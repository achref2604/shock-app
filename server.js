const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const axios = require('axios');

const app = express();

// --- CONFIGURATION ---
const MONGO_URI = process.env.MONGO_URI;
const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const CALLBACK_URL = process.env.DISCORD_CALLBACK_URL;
const SESSION_SECRET = process.env.SESSION_SECRET || 'secretSuperShock';
const ALLOWED_GUILD_ID = process.env.ALLOWED_GUILD_ID;

// IDs des "Super Admins" (Fox)
const SUPER_ADMIN_USERS = ['517350911647940611']; 
const SUPER_ADMIN_ROLES = ['1313599623004160082'];

// --- BASE DE DONNÉES ---
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("✅ Connecté à MongoDB"))
    .catch(err => console.error("❌ Erreur MongoDB:", err));

// 1. Schéma de Configuration (Rôles dynamiques et Régiments)
const ConfigSchema = new mongoose.Schema({
    officerRoles: [String], // Liste des ID roles qui ont TOUT les droits
    marineRoles: [String],  // Liste des ID roles qui peuvent juste Ajouter/Modifier
    regiments: [String]     // Liste des régiments pour le menu déroulant
});
const Config = mongoose.model('Config', ConfigSchema);

// Fonction pour initialiser la config si elle n'existe pas
async function initConfig() {
    const exists = await Config.findOne();
    if (!exists) {
        await new Config({
            officerRoles: [],
            marineRoles: [],
            regiments: ['Shock', '501st', '212th', '104th'] // Valeurs par défaut
        }).save();
        console.log("⚙️ Configuration initialisée.");
    }
}
initConfig();

// 2. Schéma des Protocoles (inchangé)
const ProtocoleSchema = new mongoose.Schema({
    auteurNom: String,
    discordUser: String, // Pseudo Username
    discordNick: String, // Surnom Serveur
    discordId: String,
    cibleNom: String,
    cibleGrade: String,
    cibleRegiment: String,
    targetSteamID: String,
    protocoleType: String,
    raison: String,
    details: String,
    tempsRestant: String,
    statut: { type: String, default: 'En Attente' },
    date: { type: Date, default: Date.now }
});
const Protocole = mongoose.model('Protocole', ProtocoleSchema);

// --- MIDDLEWARES ---
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: MONGO_URI }),
    cookie: { maxAge: 1000 * 60 * 60 * 24 * 7 }
}));

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

passport.use(new DiscordStrategy({
    clientID: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    callbackURL: CALLBACK_URL,
    scope: ['identify', 'guilds', 'guilds.members.read']
}, async (accessToken, refreshToken, profile, done) => {
    try {
        if (ALLOWED_GUILD_ID) {
            // On récupère le membre pour avoir ses rôles ET son surnom (nick)
            const response = await axios.get(`https://discord.com/api/users/@me/guilds/${ALLOWED_GUILD_ID}/member`, {
                headers: { Authorization: `Bearer ${accessToken}` }
            });
            
            const member = response.data;
            profile.roles = member.roles; // On stocke les rôles
            profile.serverNick = member.nick || member.user.username; // Surnom ou Username si pas de surnom
        }
        return done(null, profile);
    } catch (error) {
        console.error("Erreur Discord:", error.message);
        return done(null, profile);
    }
}));

// --- GESTION DES PERMISSIONS ---
async function getPermissions(user) {
    if (!user || !user.roles) return { isAdmin: false, isOfficer: false, isMarine: false };

    // 1. Check Admin (Hardcodé)
    const isAdmin = SUPER_ADMIN_USERS.includes(user.id) || user.roles.some(r => SUPER_ADMIN_ROLES.includes(r));
    if (isAdmin) return { isAdmin: true, isOfficer: true, isMarine: true };

    // 2. Check DB Config pour Officer et Marine
    const config = await Config.findOne();
    const isOfficer = user.roles.some(r => config.officerRoles.includes(r));
    const isMarine = user.roles.some(r => config.marineRoles.includes(r));

    return { isAdmin: false, isOfficer: isOfficer, isMarine: isMarine }; // Officier écrase Marine plus tard
}

// Middleware de protection Admin
const checkAdmin = async (req, res, next) => {
    if (req.isAuthenticated()) {
        const perms = await getPermissions(req.user);
        if (perms.isAdmin) return next();
    }
    res.status(403).json({ message: "Réservé à 1010 Fox." });
};

// Middleware pour modifier/ajouter (Marine + Officier + Admin)
const checkEdit = async (req, res, next) => {
    if (req.isAuthenticated()) {
        const perms = await getPermissions(req.user);
        if (perms.isAdmin || perms.isOfficer || perms.isMarine) return next();
    }
    res.status(403).json({ message: "Accès refusé." });
};

// Middleware pour Valider/Restaurer (Officier + Admin SEULEMENT)
const checkValidate = async (req, res, next) => {
    if (req.isAuthenticated()) {
        const perms = await getPermissions(req.user);
        if (perms.isAdmin || perms.isOfficer) return next();
    }
    res.status(403).json({ message: "Réservé aux Officiers." });
};

// --- ROUTES AUTH ---
app.get('/auth/discord', passport.authenticate('discord'));
app.get('/auth/discord/callback', passport.authenticate('discord', { failureRedirect: '/' }), (req, res) => res.redirect('/'));
app.get('/auth/logout', (req, res, next) => {
    req.logout((err) => { if (err) return next(err); res.redirect('/'); });
});

app.get('/auth/user', async (req, res) => {
    if (req.isAuthenticated()) {
        const perms = await getPermissions(req.user);
        res.json({ 
            connecte: true, 
            username: req.user.username,
            nickname: req.user.serverNick, // Le nom sur le serveur
            avatar: `https://cdn.discordapp.com/avatars/${req.user.id}/${req.user.avatar}.png`,
            isAdmin: perms.isAdmin,
            isOfficer: perms.isOfficer,
            isMarine: perms.isMarine
        });
    } else {
        res.json({ connecte: false });
    }
});

// --- ROUTES CONFIGURATION (ADMIN) ---
app.get('/api/config', async (req, res) => {
    const config = await Config.findOne();
    res.json(config);
});

app.put('/api/config', checkAdmin, async (req, res) => {
    // req.body contient { officerRoles: [], marineRoles: [], regiments: [] }
    await Config.findOneAndUpdate({}, req.body, { upsert: true });
    res.json({ message: "Configuration mise à jour." });
});

// --- ROUTES API PROTOCOLES ---
app.get('/api/protocoles', async (req, res) => {
    const protocoles = await Protocole.find({ statut: { $ne: 'Effectué' } }).sort({ date: -1 });
    res.json(protocoles);
});
app.get('/api/historique', async (req, res) => {
    const protocoles = await Protocole.find({ statut: 'Effectué' }).sort({ date: -1 });
    res.json(protocoles);
});

app.post('/api/protocoles', checkEdit, async (req, res) => {
    try {
        const data = req.body;
        data.discordUser = req.user.username;
        data.discordNick = req.user.serverNick; // On sauvegarde le surnom
        data.discordId = req.user.id;
        const nouveauProtocole = new Protocole(data);
        await nouveauProtocole.save();
        res.json({ message: "Enregistré." });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.put('/api/protocoles/:id', checkEdit, async (req, res) => {
    await Protocole.findByIdAndUpdate(req.params.id, req.body);
    res.json({ message: "Mis à jour." });
});

app.put('/api/protocoles/:id/valider', checkValidate, async (req, res) => {
    await Protocole.findByIdAndUpdate(req.params.id, { statut: 'Effectué' });
    const historique = await Protocole.find({ statut: 'Effectué' }).sort({ date: -1 });
    if (historique.length > 30) {
        const tropVieux = historique.slice(30);
        await Protocole.deleteMany({ _id: { $in: tropVieux.map(p => p._id) } });
    }
    res.json({ message: "Validé." });
});

app.put('/api/protocoles/:id/restaurer', checkValidate, async (req, res) => {
    const { tempsRestant } = req.body;
    let updateData = { statut: 'En Attente', date: Date.now() };
    if (tempsRestant) updateData.tempsRestant = tempsRestant;
    await Protocole.findByIdAndUpdate(req.params.id, updateData);
    res.json({ message: "Restauré." });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Serveur lancé sur le port ${PORT}`));
