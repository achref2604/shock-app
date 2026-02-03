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

// --- PROXY RENDER ---
app.set('trust proxy', 1);

// --- CONFIGURATION ---
const MONGO_URI = process.env.MONGO_URI;
const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const CALLBACK_URL = process.env.DISCORD_CALLBACK_URL;
const SESSION_SECRET = process.env.SESSION_SECRET || 'secretSuperShock';
const ALLOWED_GUILD_ID = process.env.ALLOWED_GUILD_ID;

// WEBHOOK
const DISCORD_WEBHOOK_URL = 'https://discord.com/api/webhooks/1313625448504098887/y6DWN9qx9Se5MRCsbJLLQmim4tl34obX7Z2u0u0S5549sA2XMZ1ZXMB2Y_gVtpcnHCM5';
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
    adminRoles: [String], 
    adminUsers: [String], 
    shockOfficerUsers: { type: [String], default: [] }, 
    bannedUsers: { type: [String], default: [] },
    officerRoles: [String], 
    marineRoles: [String], 
    regiments: [{ 
        name: String, 
        rappelDays: { type: Number, default: 10 }, 
        sanctionDays: { type: Number, default: 14 }, 
        sanctionText: { type: String, default: "Sanction par défaut" },
        color: { type: String, default: '#c0392b' },
        discordRoleID: { type: String, default: '' }
    }]     
});
const Config = mongoose.model('Config', ConfigSchema);

async function initConfig() {
    const exists = await Config.findOne();
    if (!exists) { await new Config({ adminRoles: [], adminUsers: [], shockOfficerUsers: [], bannedUsers: [], officerRoles: [], marineRoles: [], regiments: [{ name: 'Shock', rappelDays: 10, sanctionDays: 14, sanctionText: 'Protocole 6', color: '#c0392b', discordRoleID: '' }] }).save(); }
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
    isSuspended: { type: Boolean, default: false },
    suspendedBy: String,
    suspendReason: String,
    
    statut: { type: String, default: 'En Attente' },
    date: { type: Date, default: Date.now }
});
const Protocole = mongoose.model('Protocole', ProtocoleSchema);

// --- FONCTIONS DE SÉCURITÉ ---

async function getPermissions(user) {
    if (!user || !user.roles) return { isAdmin: false, isShockOfficer: false, isOfficer: false, isMarine: false, isBanned: false };
    
    const config = await Config.findOne();
    if (!config) return { isAdmin: false, isShockOfficer: false, isOfficer: false, isMarine: false, isBanned: false };

    if (config.bannedUsers && config.bannedUsers.includes(user.id)) {
        return { isAdmin: false, isShockOfficer: false, isOfficer: false, isMarine: false, isBanned: true };
    }

    const isSuperAdmin = SUPER_ADMIN_USERS.includes(user.id) || user.roles.some(r => SUPER_ADMIN_ROLES.includes(r));
    if (isSuperAdmin) return { isAdmin: true, isShockOfficer: true, isOfficer: true, isMarine: true, isBanned: false };

    const isAdminDB = config.adminUsers.includes(user.id) || user.roles.some(r => config.adminRoles.includes(r));
    if (isAdminDB) return { isAdmin: true, isShockOfficer: true, isOfficer: true, isMarine: true, isBanned: false };

    const isShockOfficer = (config.shockOfficerUsers || []).includes(user.id);
    if (isShockOfficer) return { isAdmin: false, isShockOfficer: true, isOfficer: true, isMarine: true, isBanned: false };

    const isOfficer = user.roles.some(r => config.officerRoles.includes(r));
    const isMarine = user.roles.some(r => config.marineRoles.includes(r));
    return { isAdmin: false, isShockOfficer: false, isOfficer: isOfficer, isMarine: isMarine, isBanned: false };
}

const checkAdmin = async (req, res, next) => { 
    const perms = await getPermissions(req.user);
    if (req.isAuthenticated() && !perms.isBanned && perms.isAdmin) return next(); 
    res.status(403).json({ message: "Admin Only." }); 
};

const checkManage = async (req, res, next) => {
    if (!req.isAuthenticated()) return res.status(401).json({ message: "Non connecté" });
    const perms = await getPermissions(req.user);
    if (!perms.isBanned && (perms.isAdmin || perms.isShockOfficer)) return next();
    res.status(403).json({ message: "Permission refusée." });
};

const checkEdit = async (req, res, next) => { 
    if (!req.isAuthenticated()) return res.status(401).json({ message: "Non connecté" });
    const perms = await getPermissions(req.user);
    if (!perms.isBanned && (perms.isAdmin || perms.isShockOfficer || perms.isOfficer || perms.isMarine)) return next(); 
    res.status(403).json({ message: "Accès refusé." }); 
};

const checkValidate = async (req, res, next) => { 
    if (!req.isAuthenticated()) return res.status(401).json({ message: "Non connecté" });
    const perms = await getPermissions(req.user);
    if (!perms.isBanned && (perms.isAdmin || perms.isShockOfficer || perms.isOfficer)) return next(); 
    res.status(403).json({ message: "Shock Only." }); 
};

// --- WEBHOOK ---
async function sendDiscordWebhook(protocole, shockName) {
    try {
        const config = await Config.findOne();
        const regConfig = config.regiments.find(r => r.name === protocole.cibleRegiment);
        
        let colorInt = 12609835; 
        let rolePing = "";

        if (regConfig) {
            const hex = regConfig.color.replace('#', '');
            colorInt = parseInt(hex, 16);
            if (regConfig.discordRoleID) {
                const roles = regConfig.discordRoleID.split(',');
                rolePing = roles.map(id => `<@&${id.trim()}>`).join(' ');
            }
        }

        let contentArray = [];
        const pushItem = (label, value) => {
            if (value && value.toString().trim() !== "") {
                contentArray.push(`*${label}*\n**${value}**`);
            }
        };

        pushItem("Shock qui a appliqué le protocole 👮‍♂️", shockName);
        pushItem("Matricule + nom du protocolé 🏃‍♂️", protocole.cibleNom);
        pushItem("Son grade 🏅", protocole.cibleGrade);
        pushItem("Régiment 📊", protocole.cibleRegiment);
        pushItem("Protocole 📕", protocole.protocoleType.replace(/Protocole\s+/i, ''));
        pushItem("Ordonné / Demandé par 📢", protocole.auteurNom);
        pushItem("Raison ❓", protocole.raison);
        pushItem("Détails 👀", protocole.details);
        pushItem("SteamID 💻", protocole.targetSteamID);

        const descriptionBody = contentArray.join("\n\n");

        const embed = {
            title: "Signalement Protocole",
            description: descriptionBody, 
            color: colorInt,
            thumbnail: { url: SHOCK_LOGO_URL },
            timestamp: new Date().toISOString()
        };

        await axios.post(DISCORD_WEBHOOK_URL, {
            content: rolePing,
            embeds: [embed]
        });
        console.log("✅ Webhook de",protocole.cibleNom," envoyé.");

    } catch (error) {
        console.error("❌ Erreur Webhook pour ",protocole.cibleNom," : ", error.message);
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
    } catch (error) { console.error("❌ Erreur Google Sheet pour ",protocole.cibleNom," : ",error); }
}

// --- MIDDLEWARES & ROUTES ---
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

app.use(session({
    secret: SESSION_SECRET, 
    resave: false, 
    saveUninitialized: false,
    proxy: true,
    store: MongoStore.create({ mongoUrl: MONGO_URI }), 
    cookie: { maxAge: 1000 * 60 * 60 * 24 * 7, secure: true, sameSite: 'none', httpOnly: true }
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
    } catch (error) { return done(null, profile); }
}));

app.get('/auth/discord', passport.authenticate('discord'));
app.get('/auth/discord/callback', (req, res, next) => {
    passport.authenticate('discord', { failureRedirect: '/' }, (err, user, info) => {
        if (err) return next(err);
        if (!user) return res.redirect('/');
        req.logIn(user, (err) => { if (err) return next(err); return res.redirect('/'); });
    })(req, res, next);
});
app.get('/auth/logout', (req, res, next) => { req.logout((err) => { if (err) return next(err); req.session.destroy(); res.redirect('/'); }); });

app.get('/auth/user', async (req, res) => {
    if (req.isAuthenticated()) {
        const perms = await getPermissions(req.user);
        res.json({ connecte: true, id: req.user.id, username: req.user.username, nickname: req.user.serverNick, avatar: `https://cdn.discordapp.com/avatars/${req.user.id}/${req.user.avatar}.png`, ...perms });
    } else { res.json({ connecte: false }); }
});

app.get('/api/config', async (req, res) => { 
    if(req.isAuthenticated() && (await getPermissions(req.user)).isBanned) return res.status(403).json({});
    res.json(await Config.findOne()); 
});
app.put('/api/config', checkAdmin, async (req, res) => { await Config.findOneAndUpdate({}, req.body, { upsert: true }); res.json({ message: "OK" }); });

app.get('/api/protocoles', async (req, res) => { 
    if(req.isAuthenticated()) {
        const perms = await getPermissions(req.user);
        if(perms.isBanned) return res.status(403).json([]);
    }
    res.json(await Protocole.find({ statut: { $ne: 'Effectué' } }).sort({ date: -1 })); 
});
app.get('/api/historique', async (req, res) => { 
    if(req.isAuthenticated()) {
        const perms = await getPermissions(req.user);
        if(perms.isBanned) return res.status(403).json([]);
    }
    res.json(await Protocole.find({ statut: 'Effectué' }).sort({ date: -1 })); 
});

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
        if (!perms.isAdmin && !perms.isShockOfficer && p.discordId !== req.user.id) {
            return res.status(403).json({ message: "Non autorisé" });
        }
        await Protocole.findByIdAndUpdate(req.params.id, req.body);
        res.json({ message: "OK" });
    } catch (e) { res.status(500).json({ error: "Erreur" }); }
});

// --- ROUTE VALIDATION AVEC COMMENTAIRE ---
app.put('/api/protocoles/:id/valider', checkValidate, async (req, res) => {
    const { validatorName, commentaire } = req.body; 
    const p = await Protocole.findById(req.params.id);
    
    if(p.isSuspended) return res.status(403).json({ message: "Ce protocole est suspendu." });

    // AJOUT COMMENTAIRE AUX DETAILS
    let newDetails = p.details || "";
    if (commentaire && commentaire.trim() !== "") {
        // Ajout d'un saut de ligne propre
        if (newDetails.length > 0) newDetails += "\n\n";
        newDetails += `💬 Commentaire de ${validatorName} : ${commentaire}`;
    }

    // Mise à jour de l'objet temporaire (pour Webhook/Sheet)
    p.details = newDetails;

    if(p && validatorName) {
        await sendToGoogleSheet(p, validatorName);
        await sendDiscordWebhook(p, validatorName);
    }

    // Sauvegarde en base
    await Protocole.findByIdAndUpdate(req.params.id, {
        statut: 'Effectué', 
        validatorUser: req.user.username, 
        validatorNick: req.user.serverNick, 
        validatorId: req.user.id, 
        validatorManualName: validatorName,
        details: newDetails 
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

app.delete('/api/protocoles/:id', async (req, res) => {
    try {
        if (!req.isAuthenticated()) return res.status(401).json({ message: "Non connecté" });
        const perms = await getPermissions(req.user);
        const p = await Protocole.findById(req.params.id);
        if (!p) return res.status(404).json({ message: "Protocole introuvable" });
        
        if(perms.isBanned) return res.status(403).json({ message: "Banni." });

        if (perms.isAdmin || perms.isShockOfficer) {
            await Protocole.findByIdAndDelete(req.params.id);
            return res.json({ message: "Supprimé par Haut Commandement" });
        }
        if (p.discordId === req.user.id && p.statut !== 'Effectué') {
            await Protocole.findByIdAndDelete(req.params.id);
            return res.json({ message: "Supprimé par Auteur" });
        }
        res.status(403).json({ message: "Vous n'avez pas la permission de supprimer." });
    } catch (e) {
        res.status(500).json({ error: "Erreur serveur" });
    }
});

app.put('/api/protocoles/:id/suspend', checkManage, async (req, res) => {
    try {
        const { reason } = req.body;
        const p = await Protocole.findById(req.params.id);
        if (!p) return res.status(404).json({ message: "Introuvable" });

        if (p.isSuspended) {
            await Protocole.findByIdAndUpdate(req.params.id, { 
                isSuspended: false, 
                suspendedBy: null, 
                suspendReason: null 
            });
            res.json({ message: "Suspension levée" });
        } else {
            await Protocole.findByIdAndUpdate(req.params.id, { 
                isSuspended: true, 
                suspendedBy: req.user.serverNick || req.user.username, 
                suspendReason: reason 
            });
            res.json({ message: "Protocole suspendu" });
        }
    } catch(e) {
        res.status(500).json({ error: e.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Serveur lancé sur le port ${PORT}`));
