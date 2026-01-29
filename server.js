const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const axios = require('axios');
const { google } = require('googleapis'); // NOUVEAU

const app = express();

// --- CONFIGURATION ---
const MONGO_URI = process.env.MONGO_URI;
const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const CALLBACK_URL = process.env.DISCORD_CALLBACK_URL;
const SESSION_SECRET = process.env.SESSION_SECRET || 'secretSuperShock';
const ALLOWED_GUILD_ID = process.env.ALLOWED_GUILD_ID;

// CONFIG GOOGLE SHEET
const SPREADSHEET_ID = '1vEQkvkcCMr6wvl0FsSj1oVdS5CUMttXsBNlt5jThXX0';
const SHEET_NAME = '👮‍♂️ Casier Actuel';

// Authentification Google
const googleAuth = new google.auth.GoogleAuth({
    credentials: {
        client_email: process.env.GOOGLE_CLIENT_EMAIL,
        // Astuce pour Render : gérer les sauts de ligne dans la clé privée
        private_key: process.env.GOOGLE_PRIVATE_KEY ? process.env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, '\n') : undefined,
    },
    scopes: ['https://www.googleapis.com/auth/spreadsheets'],
});

const SUPER_ADMIN_USERS = ['517350911647940611']; 
const SUPER_ADMIN_ROLES = ['1313599623004160082'];

// --- BASE DE DONNÉES ---
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("✅ Connecté à MongoDB"))
    .catch(err => console.error("❌ Erreur MongoDB:", err));

const ConfigSchema = new mongoose.Schema({
    adminRoles: [String], 
    adminUsers: [String],   
    officerRoles: [String], 
    marineRoles: [String],  
    regiments: [String]     
});
const Config = mongoose.model('Config', ConfigSchema);

async function initConfig() {
    const exists = await Config.findOne();
    if (!exists) {
        await new Config({ adminRoles: [], adminUsers: [], officerRoles: [], marineRoles: [], regiments: ['Shock', '501st'] }).save();
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
    validatorUser: String,
    validatorNick: String,
    validatorId: String,
    validatorManualName: String, // NOUVEAU : Nom entré manuellement
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
    const isAdmin = SUPER_ADMIN_USERS.includes(user.id) || user.roles.some(r => SUPER_ADMIN_ROLES.includes(r));
    if (isAdmin) return { isAdmin: true, isOfficer: true, isMarine: true };
    const config = await Config.findOne();
    const isAdminDB = config.adminUsers.includes(user.id) || user.roles.some(r => config.adminRoles.includes(r));
    if (isAdminDB) return { isAdmin: true, isOfficer: true, isMarine: true };
    const isOfficer = user.roles.some(r => config.officerRoles.includes(r));
    const isMarine = user.roles.some(r => config.marineRoles.includes(r));
    return { isAdmin: false, isOfficer: isOfficer, isMarine: isMarine };
}

const checkAdmin = async (req, res, next) => {
    if (req.isAuthenticated()) {
        const perms = await getPermissions(req.user);
        if (perms.isAdmin) return next();
    }
    res.status(403).json({ message: "Réservé aux Admins." });
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

// --- FONCTION ENVOI GOOGLE SHEET ---
// --- FONCTION ENVOI GOOGLE SHEET (CORRIGÉE) ---
async function sendToGoogleSheet(protocole, validatorName) {
    try {
        const sheets = google.sheets({ version: 'v4', auth: googleAuth });
        
        // 1. On lit UNIQUEMENT la colonne A pour trouver la dernière ligne remplie
        const result = await sheets.spreadsheets.values.get({
            spreadsheetId: SPREADSHEET_ID,
            range: `${SHEET_NAME}!A:A`, // On scanne la colonne A
        });

        // Si result.data.values existe, on prend sa longueur, sinon 0.
        // On ajoute +1 pour écrire sur la ligne suivante.
        const numRows = result.data.values ? result.data.values.length : 0;
        const nextRow = numRows + 1;

        // Formatage Date
        const now = new Date();
        const dateStr = now.toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit', year: '2-digit' }) + 
                        ' à ' + now.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });

        const protoNum = protocole.protocoleType.replace(/Protocole\s+/i, '');

        const values = [[
            dateStr,                    // A
            validatorName,              // B
            protocole.cibleRegiment,    // C
            protocole.cibleGrade,       // D
            protocole.cibleNom,         // E
            protoNum,                   // F
            protocole.raison,           // G
            protocole.auteurNom,        // H
            protocole.details || "",    // I
            protocole.targetSteamID || "" // J
        ]];

        // 2. On écrit (UPDATE) spécifiquement sur la ligne calculée (ex: A21)
        await sheets.spreadsheets.values.update({
            spreadsheetId: SPREADSHEET_ID,
            range: `${SHEET_NAME}!A${nextRow}`, // Cible la première ligne vide de A
            valueInputOption: 'USER_ENTERED',
            resource: { values },
        });
        
        console.log(`📝 Ligne ajoutée au Google Sheet ligne ${nextRow}.`);
    } catch (error) {
        console.error("❌ Erreur Google Sheet:", error);
    }
}

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
            id: req.user.id,
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

app.put('/api/protocoles/:id', checkEdit, async (req, res) => {
    try {
        const protocole = await Protocole.findById(req.params.id);
        const perms = await getPermissions(req.user);
        if (!perms.isAdmin && protocole.discordId !== req.user.id) {
            return res.status(403).json({ message: "Seul l'auteur ou un Admin peut modifier." });
        }
        await Protocole.findByIdAndUpdate(req.params.id, req.body);
        res.json({ message: "OK" });
    } catch (error) { res.status(500).json({ error: "Erreur" }); }
});

// ROUTE VALIDATION (MODIFIÉE POUR GOOGLE SHEET)
app.put('/api/protocoles/:id/valider', checkValidate, async (req, res) => {
    try {
        const { validatorName } = req.body; // Récupère le nom tapé dans le prompt
        
        // 1. Récupérer le protocole AVANT modif
        const protocole = await Protocole.findById(req.params.id);
        
        // 2. Envoyer au Google Sheet
        if (protocole && validatorName) {
            await sendToGoogleSheet(protocole, validatorName);
        }

        // 3. Mettre à jour en base de données
        const updateData = {
            statut: 'Effectué',
            validatorUser: req.user.username,
            validatorNick: req.user.serverNick,
            validatorId: req.user.id,
            validatorManualName: validatorName // On sauvegarde aussi ce nom manuel
        };

        await Protocole.findByIdAndUpdate(req.params.id, updateData);
        
        const historique = await Protocole.find({ statut: 'Effectué' }).sort({ date: -1 });
        if (historique.length > 30) {
            const tropVieux = historique.slice(30);
            await Protocole.deleteMany({ _id: { $in: tropVieux.map(p => p._id) } });
        }
        res.json({ message: "OK" });
    } catch(e) {
        console.error(e);
        res.status(500).json({error: "Erreur interne"});
    }
});

app.put('/api/protocoles/:id/restaurer', checkValidate, async (req, res) => {
    const { tempsRestant } = req.body;
    let updateData = { 
        statut: 'En Attente', 
        date: Date.now(),
        validatorUser: null, 
        validatorNick: null, 
        validatorId: null,
        validatorManualName: null
    };
    if (tempsRestant) updateData.tempsRestant = tempsRestant;
    await Protocole.findByIdAndUpdate(req.params.id, updateData);
    res.json({ message: "OK" });
});

app.delete('/api/protocoles/:id', checkAdmin, async (req, res) => {
    try {
        await Protocole.findByIdAndDelete(req.params.id);
        res.json({ message: "Supprimé." });
    } catch (error) { res.status(500).json({ error: "Erreur" }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Serveur lancé sur le port ${PORT}`));

