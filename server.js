const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const axios = require('axios');
const { google } = require('googleapis');

const app = express();

// --- CONFIGURATION PROXY ---
app.set('trust proxy', 1);

// --- CONFIGURATION ---
const MONGO_URI = process.env.MONGO_URI;
const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const CALLBACK_URL = process.env.DISCORD_CALLBACK_URL;
const SESSION_SECRET = process.env.SESSION_SECRET || 'secretSuperShock';
const ALLOWED_GUILD_ID = process.env.ALLOWED_GUILD_ID;

// WEBHOOK DISCORD LOGS
const DISCORD_WEBHOOK_URL = 'https://discord.com/api/webhooks/1313580821470249122/qe2JVdKoa0k7LF0uJ9t_qusWJgof1p_QxaPpp1yMI2k-QzAfi8gIn2gSQsTHJdlA1Hf_';
const SHOCK_LOGO_URL = 'https://cdn.discordapp.com/attachments/1066805880928088084/1466837163093004319/Logo_Shock.png?ex=697e3210&is=697ce090&hm=28787b2cd9f14aff673f044e3374b8c8c850098f51d9600893aea32e3f42cdfb&';

const SPREADSHEET_ID = '1vEQkvkcCMr6wvl0FsSj1oVdS5CUMttXsBNlt5jThXX0';
const SHEET_NAME = '👮‍♂️ Casier Actuel';

const googleAuth = new google.auth.GoogleAuth({
    credentials: {
        client_email: process.env.GOOGLE_CLIENT_EMAIL,
        private_key: process.env.GOOGLE_PRIVATE_KEY ? process.env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, '\n') : undefined,
    },
    scopes: ['https://www.googleapis.com/auth/spreadsheets'],
});

const SUPER_ADMIN_USERS = ['517350911647940611']; 
const SUPER_ADMIN_ROLES = ['1313599623004160082'];

mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("✅ Connecté à MongoDB"))
    .catch(err => console.error("❌ Erreur MongoDB:", err));

// --- SCHEMAS ---
const ConfigSchema = new mongoose.Schema({
    adminRoles: [String], adminUsers: [String], officerRoles: [String], marineRoles: [String], 
    regiments: [{ 
        name: String, 
        rappelDays: { type: Number, default: 7 }, 
        sanctionDays: { type: Number, default: 3 }, 
        sanctionText: { type: String, default: "Sanction par défaut" },
        color: { type: String, default: '#c0392b' },
        discordRoleID: { type: String, default: '' } // AJOUT: ID du rôle à pinguer
    }]     
});
const Config = mongoose.model('Config', ConfigSchema);

async function initConfig() {
    const exists = await Config.findOne();
    if (!exists) { await new Config({ adminRoles: [], adminUsers: [], officerRoles: [], marineRoles: [], regiments: [{ name: 'Shock', rappelDays: 7, sanctionDays: 3, sanctionText: 'Arrêts', color: '#c0392b', discordRoleID: '' }] }).save(); }
}
initConfig();

const ProtocoleSchema = new mongoose.Schema({
    auteurNom: String,
    discordUser: String, discordNick: String, discordId: String,
    cibleNom: String, cibleGrade: String, cibleRegiment: String, targetSteamID: String,
    protocoleType: String, raison: String, details: String, tempsRestant: String,
    validatorUser: String, validatorNick: String, validatorId: String, validatorManualName: String,
    rappelPrisEnChargeBy: String, 
    rappelDate: Date, 
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
    proxy: true,
    store: MongoStore.create({ mongoUrl: MONGO_URI }), 
    cookie: { 
        maxAge: 1000 * 60 * 60 * 24 * 7, 
        secure: true, 
        sameSite: 'none', 
        httpOnly: true
    }
}));

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

passport.use(new DiscordStrategy({
    clientID: CLIENT_ID, clientSecret: CLIENT_SECRET, callbackURL: CALLBACK_URL, scope: ['identify', 'guilds', 'guilds.members.read'],
    proxy: true 
}, async (accessToken, refreshToken, profile, done) => {
    try {
        if (ALLOWED_GUILD_ID) {
            const response = await axios.get(`https://discord.com/api/users/@me/guilds/${ALLOWED_GUILD_ID}/member`, { headers: { Authorization: `Bearer ${accessToken}` } });
            profile.roles = response.data.roles;
            profile.serverNick = response.data.nick || response.data.user.username;
        }
        return done(null, profile);
    } catch (error) { 
        console.error("Auth Error:", error);
        return done(null, profile); 
    }
}));

// --- FONCTIONS ---

async function getPermissions(user) {
    if (!user || !user.roles) return { isAdmin: false, isOfficer: false, isMarine: false };
    const isAdmin = SUPER_ADMIN_USERS.includes(user.id) || user.roles.some(r => SUPER_ADMIN_ROLES.includes(r));
    if (isAdmin) return { isAdmin: true, isOfficer: true, isMarine: true };
    const config = await Config.findOne();
    if (!config) return { isAdmin: false, isOfficer: false, isMarine: false };

    const isAdminDB = config.adminUsers.includes(user.id) || user.roles.some(r => config.adminRoles.includes(r));
    if (isAdminDB) return { isAdmin: true, isOfficer: true, isMarine: true };
    const isOfficer = user.roles.some(r => config.officerRoles.includes(r));
    const isMarine = user.roles.some(r => config.marineRoles.includes(r));
    return { isAdmin: false, isOfficer: isOfficer, isMarine: isMarine };
}

// --- ENVOI DISCORD EMBED ---
async function sendDiscordWebhook(protocole, shockName) {
    try {
        // Récupérer la config pour la couleur et le rôle
        const config = await Config.findOne();
        const regConfig = config.regiments.find(r => r.name === protocole.cibleRegiment);
        
        // Couleur par défaut rouge si non trouvée
        let colorInt = 12609835; // #c0392b
        let rolePing = "";

        if (regConfig) {
            // Conversion Hex -> Int pour Discord
            const hex = regConfig.color.replace('#', '');
            colorInt = parseInt(hex, 16);
            if (regConfig.discordRoleID) {
                rolePing = `<@&${regConfig.discordRoleID}>`;
            }
        }

        const embed = {
            title: "Signalement Protocole",
            color: colorInt,
            thumbnail: { url: SHOCK_LOGO_URL },
            fields: [
                { name: "*Identification du Shock :*", value: `**${shockName}**`, inline: false },
                { name: "*Matricule + nom du protocolé*", value: `**${protocole.cibleNom}**`, inline: false },
                { name: "*Grade*", value: `**${protocole.cibleGrade}**`, inline: false },
                { name: "*Régiment*", value: `**${protocole.cibleRegiment}**`, inline: false },
                { name: "*Protocole :*", value: `**${protocole.protocoleType.replace(/Protocole\s+/i, '')}**`, inline: false },
                { name: "*Ordonné / Demandé par :*", value: `**${protocole.auteurNom || "N/A"}**`, inline: false },
                { name: "*Raison*", value: `**${protocole.raison}**`, inline: false },
                { name: "*Détails*", value: `**${protocole.details || "Aucun"}**`, inline: false },
                { name: "*SteamID*", value: `**${protocole.targetSteamID || "Non renseigné"}**`, inline: false }
            ],
            footer: { text: new Date().toLocaleString('fr-FR') }
        };

        await axios.post(DISCORD_WEBHOOK_URL, {
            content: rolePing, // Le ping se met ici
            embeds: [embed]
        });
        console.log("✅ Webhook Discord envoyé.");

    } catch (error) {
        console.error("❌ Erreur Webhook Discord:", error.message);
    }
}

async function sendToGoogleSheet(protocole, shockName) {
    try {
        const sheets = google.sheets({ version: 'v4', auth: googleAuth });
        const result = await sheets.spreadsheets.values.get({ spreadsheetId: SPREADSHEET_ID, range: `${SHEET_NAME}!A:A` });
        const numRows = result.data.values ? result.data.values.length : 0;
        const nextRow = numRows + 1;

        const now = new Date();
        const dateStr = now.toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit', year: '2-digit', timeZone: 'Europe/Paris' }) + 
                        ' à ' + now.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', timeZone: 'Europe/Paris' });

        const protoNum = protocole.protocoleType.replace(/Protocole\s+/i, '');

        const values = [[
            dateStr, shockName, protocole.cibleRegiment, protocole.cibleGrade, protocole.cibleNom,
            protoNum, protocole.raison, protocole.auteurNom || "", protocole.details || "", protocole.targetSteamID || ""
        ]];

        await sheets.spreadsheets.values.update({
            spreadsheetId: SPREADSHEET_ID, range: `${SHEET_NAME}!A${nextRow}`, valueInputOption: 'USER_ENTERED', resource: { values }
        });
        console.log(`📝 Google Sheet updated ligne ${nextRow}`);
    } catch (error) { console.error("❌ Erreur Google Sheet:", error); }
}

// --- MIDDLEWARES SECURITE ---
const checkAdmin = async (req, res, next) => { if (req.isAuthenticated() && (await getPermissions(req.user)).isAdmin) return next(); res.status(403).json({ message: "Admin Only." }); };
const checkEdit = async (req, res, next) => { 
    if (!req.isAuthenticated()) return res.status(401).json({ message: "Non connecté" });
    const perms = await getPermissions(req.user);
    if (perms.isAdmin || perms.isOfficer || perms.isMarine) return next(); 
    res.status(403).json({ message: "Accès refusé." }); 
};
const checkValidate = async (req, res, next) => { 
    if (!req.isAuthenticated()) return res.status(401).json({ message: "Non connecté" });
    const perms = await getPermissions(req.user);
    if (perms.isAdmin || perms.isOfficer) return next(); 
    res.status(403).json({ message: "Officiers Only." }); 
};

// --- ROUTES ---
app.get('/auth/discord', passport.authenticate('discord'));
app.get('/auth/discord/callback', (req, res, next) => {
    passport.authenticate('discord', { failureRedirect: '/' }, (err, user, info) => {
        if (err) return next(err);
        if (!user) return res.redirect('/');
        req.logIn(user, (err) => {
            if (err) return next(err);
            return res.redirect('/');
        });
    })(req, res, next);
});
app.get('/auth/logout', (req, res, next) => { req.logout((err) => { if (err) return next(err); req.session.destroy(); res.redirect('/'); }); });

app.get('/auth/user', async (req, res) => {
    if (req.isAuthenticated()) {
        const perms = await getPermissions(req.user);
        res.json({ connecte: true, id: req.user.id, username: req.user.username, nickname: req.user.serverNick, avatar: `https://cdn.discordapp.com/avatars/${req.user.id}/${req.user.avatar}.png`, ...perms });
    } else { res.json({ connecte: false }); }
});

app.get('/api/config', async (req, res) => { res.json(await Config.findOne()); });
app.put('/api/config', checkAdmin, async (req, res) => { await Config.findOneAndUpdate({}, req.body, { upsert: true }); res.json({ message: "OK" }); });

app.get('/api/protocoles', async (req, res) => { res.json(await Protocole.find({ statut: { $ne: 'Effectué' } }).sort({ date: -1 })); });
app.get('/api/historique', async (req, res) => { res.json(await Protocole.find({ statut: 'Effectué' }).sort({ date: -1 })); });

app.post('/api/protocoles', checkEdit, async (req, res) => {
    try {
        const data = req.body;
        data.discordUser = req.user.username; data.discordNick = req.user.serverNick; data.discordId = req.user.id;
        await new Protocole(data).save();
        res.json({ message: "OK" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/protocoles/direct', checkValidate, async (req, res) => {
    try {
        const data = req.body;
        data.discordUser = req.user.username; data.discordNick = req.user.serverNick; data.discordId = req.user.id;
        data.statut = 'Effectué';
        data.validatorUser = req.user.username; data.validatorNick = req.user.serverNick; data.validatorId = req.user.id;
        const nouveau = new Protocole(data);
        await nouveau.save();
        
        // Google Sheet + Discord Webhook
        await sendToGoogleSheet(nouveau, data.validatorManualName);
        await sendDiscordWebhook(nouveau, data.validatorManualName);

        const historique = await Protocole.find({ statut: 'Effectué' }).sort({ date: -1 });
        if (historique.length > 30) {
            const tropVieux = historique.slice(30);
            await Protocole.deleteMany({ _id: { $in: tropVieux.map(p => p._id) } });
        }
        res.json({ message: "OK" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/protocoles/:id', checkEdit, async (req, res) => {
    try {
        const p = await Protocole.findById(req.params.id);
        const perms = await getPermissions(req.user);
        if (!perms.isAdmin && p.discordId !== req.user.id) return res.status(403).json({ message: "Non autorisé" });
        await Protocole.findByIdAndUpdate(req.params.id, req.body);
        res.json({ message: "OK" });
    } catch (e) { res.status(500).json({ error: "Erreur" }); }
});

app.put('/api/protocoles/:id/valider', checkValidate, async (req, res) => {
    const { validatorName } = req.body;
    const p = await Protocole.findById(req.params.id);
    
    // Google Sheet + Discord Webhook
    if(p && validatorName) {
        await sendToGoogleSheet(p, validatorName);
        await sendDiscordWebhook(p, validatorName);
    }

    await Protocole.findByIdAndUpdate(req.params.id, {
        statut: 'Effectué', validatorUser: req.user.username, validatorNick: req.user.serverNick, validatorId: req.user.id, validatorManualName: validatorName
    });
    const historique = await Protocole.find({ statut: 'Effectué' }).sort({ date: -1 });
    if (historique.length > 30) {
        const tropVieux = historique.slice(30);
        await Protocole.deleteMany({ _id: { $in: tropVieux.map(p => p._id) } });
    }
    res.json({ message: "OK" });
});

app.put('/api/protocoles/:id/restaurer', checkValidate, async (req, res) => {
    const { tempsRestant } = req.body;
    let updateData = { statut: 'En Attente', date: Date.now(), validatorUser: null, validatorNick: null, validatorId: null, validatorManualName: null, rappelPrisEnChargeBy: null, rappelDate: null };
    if (tempsRestant) updateData.tempsRestant = tempsRestant;
    await Protocole.findByIdAndUpdate(req.params.id, updateData);
    res.json({ message: "OK" });
});

app.put('/api/protocoles/:id/rappel', checkValidate, async (req, res) => {
    const takenBy = `${req.user.serverNick} (${req.user.username})`;
    await Protocole.findByIdAndUpdate(req.params.id, { 
        rappelPrisEnChargeBy: takenBy,
        rappelDate: Date.now() 
    });
    res.json({ message: "OK", takenBy });
});

app.delete('/api/protocoles/:id', checkAdmin, async (req, res) => {
    await Protocole.findByIdAndDelete(req.params.id);
    res.json({ message: "Supprimé." });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Serveur lancé sur le port ${PORT}`));
