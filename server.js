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

// IDs des "Super Admins" (Fox) - SEULS EUX PEUVENT SUPPRIMER
const SUPER_ADMIN_USERS = ['517350911647940611']; 
const SUPER_ADMIN_ROLES = ['1313599623004160082'];

// --- BASE DE DONNÉES ---
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("✅ Connecté à MongoDB"))
    .catch(err => console.error("❌ Erreur MongoDB:", err));

// Schémas
const ConfigSchema = new mongoose.Schema({
    officerRoles: [String], 
    marineRoles: [String],  
    regiments: [String]     
});
const Config = mongoose.model('Config', ConfigSchema);

async function initConfig() {
    const exists = await Config.findOne();
    if (!exists) {
        await new Config({ officerRoles: [], marineRoles: [], regiments: ['Shock', '501st'] }).save();
    }
}
initConfig();

const ProtocoleSchema = new mongoose.Schema({
    auteurNom: String,
    discordUser: String,
    discordNick: String,
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
            const response = await axios.get(`https://discord.com/api/users/@me/guilds/${ALLOWED_GUILD_ID}/member`, {
                headers: { Authorization: `Bearer ${accessToken}` }
            });
            const member = response.data;
            profile.roles = member.roles;
            profile.serverNick = member.nick || member.user.username;
        }
        return done(null, profile);
    } catch (error) {
        return done(null, profile);
    }
}));

// --- PERMISSIONS ---
async function getPermissions(user) {
    if (!user || !user.roles) return { isAdmin: false, isOfficer: false, isMarine: false };
    
    // Admin (Hardcodé)
    const isAdmin = SUPER_ADMIN_USERS.includes(user.id) || user.roles.some(r => SUPER_ADMIN_ROLES.includes(r));
    if (isAdmin) return { isAdmin: true, isOfficer: true, isMarine: true };

    // DB Config
    const config = await Config.findOne();
    const isOfficer = user.roles.some(r => config.officerRoles.includes(r));
    const isMarine = user.roles.some(r => config.marineRoles.includes(r));

    return { isAdmin: false, isOfficer: isOfficer, isMarine: isMarine };
}

const checkAdmin = async (req, res, next) => {
    if (req.isAuthenticated()) {
        const perms = await getPermissions(req.user);
        if (perms.isAdmin) return next();
    }
    res.status(403).json({ message: "Réservé à 1010 Fox." });
};

const checkEdit = async (req, res, next) => {
    if (req.isAuthenticated()) {
        const perms = await getPermissions(req.user);
        if (perms.isAdmin || perms.isOfficer || perms.isMarine) return next();
    }
    res.status(403).json({ message: "Accès refusé." });
};

const checkValidate = async (req, res, next) => {
    if (req.isAuthenticated()) {
        const perms = await getPermissions(req.user);
        if (perms.isAdmin || perms.isOfficer) return next();
    }
    res.status(403).json({ message: "Réservé aux Officiers." });
};

// --- ROUTES ---
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
            nickname: req.user.serverNick,
            avatar: `https://cdn.discordapp.com/avatars/${req.user.id}/${req.user.avatar}.png`,
            isAdmin: perms.isAdmin,
            isOfficer: perms.isOfficer,
            isMarine: perms.isMarine
        });
    } else {
        res.json({ connecte: false });
    }
});

app.get('/api/config', async (req, res) => { const config = await Config.findOne(); res.json(config); });
app.put('/api/config', checkAdmin, async (req, res) => { await Config.findOneAndUpdate({}, req.body, { upsert: true }); res.json({ message: "OK" }); });

app.get('/api/protocoles', async (req, res) => { const p = await Protocole.find({ statut: { $ne: 'Effectué' } }).sort({ date: -1 }); res.json(p); });
app.get('/api/historique', async (req, res) => { const p = await Protocole.find({ statut: 'Effectué' }).sort({ date: -1 }); res.json(p); });

app.post('/api/protocoles', checkEdit, async (req, res) => {
    try {
        const data = req.body;
        data.discordUser = req.user.username;
        data.discordNick = req.user.serverNick;
        data.discordId = req.user.id;
        await new Protocole(data).save();
        res.json({ message: "Enregistré." });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.put('/api/protocoles/:id', checkEdit, async (req, res) => { await Protocole.findByIdAndUpdate(req.params.id, req.body); res.json({ message: "OK" }); });

app.put('/api/protocoles/:id/valider', checkValidate, async (req, res) => {
    await Protocole.findByIdAndUpdate(req.params.id, { statut: 'Effectué' });
    const historique = await Protocole.find({ statut: 'Effectué' }).sort({ date: -1 });
    if (historique.length > 30) {
        const tropVieux = historique.slice(30);
        await Protocole.deleteMany({ _id: { $in: tropVieux.map(p => p._id) } });
    }
    res.json({ message: "OK" });
});

app.put('/api/protocoles/:id/restaurer', checkValidate, async (req, res) => {
    const { tempsRestant } = req.body;
    let updateData = { statut: 'En Attente', date: Date.now() };
    if (tempsRestant) updateData.tempsRestant = tempsRestant;
    await Protocole.findByIdAndUpdate(req.params.id, updateData);
    res.json({ message: "OK" });
});

// NOUVELLE ROUTE : SUPPRESSION DÉFINITIVE (Admin Only)
app.delete('/api/protocoles/:id', checkAdmin, async (req, res) => {
    try {
        await Protocole.findByIdAndDelete(req.params.id);
        res.json({ message: "Protocole supprimé définitivement." });
    } catch (error) {
        res.status(500).json({ error: "Erreur serveur" });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Serveur lancé sur le port ${PORT}`));
