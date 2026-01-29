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
const ALLOWED_ROLE_IDS = (process.env.ALLOWED_ROLE_IDS || "").split(',');

// --- BASE DE DONNÉES ---
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("✅ Connecté à MongoDB"))
    .catch(err => console.error("❌ Erreur MongoDB:", err));

// NOUVEAU SCHÉMA ADAPTÉ À TES BESOINS
const ProtocoleSchema = new mongoose.Schema({
    // Officier (Juste le nom maintenant)
    auteurNom: String,
    discordUser: String,
    discordId: String,

    // Cible (Le prisonnier)
    cibleNom: String,       // Matricule + Nom
    cibleGrade: String,
    cibleRegiment: String,
    targetSteamID: String,  // Devenu Facultatif

    // Détails sanction
    protocoleType: String,  // Liste 1-8
    raison: String,
    details: String,        // Facultatif
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
            const response = await axios.get(`https://discord.com/api/users/@me/guilds/${ALLOWED_GUILD_ID}/member`, {
                headers: { Authorization: `Bearer ${accessToken}` }
            });
            const member = response.data;
            const userRoles = member.roles;
            const aLeDroit = userRoles.some(roleId => ALLOWED_ROLE_IDS.includes(roleId));
            profile.isOfficier = aLeDroit; 
        } else {
            profile.isOfficier = true; 
        }
        return done(null, profile);
    } catch (error) {
        console.error("Erreur vérification rôles:", error.response ? error.response.data : error.message);
        profile.isOfficier = false;
        return done(null, profile);
    }
}));

// --- FONCTIONS SÉCURITÉ ---
const estOfficier = (req, res, next) => {
    if (req.isAuthenticated() && req.user.isOfficier) {
        return next();
    }
    res.status(403).json({ message: "Permission refusée." });
};

// --- ROUTES AUTH ---
app.get('/auth/discord', passport.authenticate('discord'));
app.get('/auth/discord/callback', passport.authenticate('discord', { failureRedirect: '/' }), (req, res) => res.redirect('/'));
app.get('/auth/logout', (req, res, next) => {
    req.logout((err) => { if (err) return next(err); res.redirect('/'); });
});

app.get('/auth/user', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({ 
            connecte: true, 
            username: req.user.username, 
            avatar: `https://cdn.discordapp.com/avatars/${req.user.id}/${req.user.avatar}.png`,
            isOfficier: req.user.isOfficier
        });
    } else {
        res.json({ connecte: false });
    }
});

// --- ROUTES API ---
app.get('/api/protocoles', async (req, res) => {
    const protocoles = await Protocole.find({ statut: { $ne: 'Effectué' } }).sort({ date: -1 });
    res.json(protocoles);
});
app.get('/api/historique', async (req, res) => {
    const protocoles = await Protocole.find({ statut: 'Effectué' }).sort({ date: -1 });
    res.json(protocoles);
});

// AJOUT (Mise à jour avec les nouveaux champs)
app.post('/api/protocoles', estOfficier, async (req, res) => {
    try {
        const data = req.body;
        data.discordUser = req.user.username;
        data.discordId = req.user.id;
        const nouveauProtocole = new Protocole(data);
        await nouveauProtocole.save();
        res.json({ message: "Enregistré." });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.put('/api/protocoles/:id', estOfficier, async (req, res) => {
    await Protocole.findByIdAndUpdate(req.params.id, req.body);
    res.json({ message: "Mis à jour." });
});

app.put('/api/protocoles/:id/valider', estOfficier, async (req, res) => {
    await Protocole.findByIdAndUpdate(req.params.id, { statut: 'Effectué' });
    const historique = await Protocole.find({ statut: 'Effectué' }).sort({ date: -1 });
    if (historique.length > 30) {
        const tropVieux = historique.slice(30);
        await Protocole.deleteMany({ _id: { $in: tropVieux.map(p => p._id) } });
    }
    res.json({ message: "Validé." });
});

app.put('/api/protocoles/:id/restaurer', estOfficier, async (req, res) => {
    const { tempsRestant } = req.body;
    let updateData = { statut: 'En Attente', date: Date.now() };
    if (tempsRestant) updateData.tempsRestant = tempsRestant;
    await Protocole.findByIdAndUpdate(req.params.id, updateData);
    res.json({ message: "Restauré." });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Serveur lancé sur le port ${PORT}`));
