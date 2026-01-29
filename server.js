const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const axios = require('axios'); // NOUVEAU

const app = express();

// --- CONFIGURATION ---
const MONGO_URI = process.env.MONGO_URI;
const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const CALLBACK_URL = process.env.DISCORD_CALLBACK_URL;
const SESSION_SECRET = process.env.SESSION_SECRET || 'secretSuperShock';

// NOUVEAU : Configuration des accès
const ALLOWED_GUILD_ID = process.env.ALLOWED_GUILD_ID; // L'ID de ton serveur Discord
// Les rôles autorisés (séparés par des virgules dans Render)
const ALLOWED_ROLE_IDS = (process.env.ALLOWED_ROLE_IDS || "").split(',');

// --- BASE DE DONNÉES ---
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("✅ Connecté à MongoDB"))
    .catch(err => console.error("❌ Erreur MongoDB:", err));

const ProtocoleSchema = new mongoose.Schema({
    auteurNom: String,
    auteurMatricule: String,
    auteurGrade: String,
    discordUser: String,
    discordId: String,
    protocoleType: String,
    raison: String,
    targetSteamID: String,
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
    scope: ['identify', 'guilds', 'guilds.members.read'] // NOUVEAU : on demande le droit de lire les membres
}, async (accessToken, refreshToken, profile, done) => {
    try {
        // On va vérifier si l'utilisateur est dans le bon serveur ET s'il a le bon rôle
        if (ALLOWED_GUILD_ID) {
            // Appel API Discord pour récupérer le membre et ses rôles
            const response = await axios.get(`https://discord.com/api/users/@me/guilds/${ALLOWED_GUILD_ID}/member`, {
                headers: { Authorization: `Bearer ${accessToken}` }
            });
            
            const member = response.data;
            const userRoles = member.roles; // Liste des IDs de rôles de l'utilisateur

            // Vérifie si l'utilisateur possède au moins UN des rôles autorisés
            const aLeDroit = userRoles.some(roleId => ALLOWED_ROLE_IDS.includes(roleId));

            // On ajoute cette info au profil de l'utilisateur pour l'utiliser plus tard
            profile.isOfficier = aLeDroit; 
        } else {
            // Si pas d'ID serveur configuré, tout le monde est officier (mode test)
            profile.isOfficier = true; 
        }
        
        return done(null, profile);
    } catch (error) {
        console.error("Erreur vérification rôles:", error.response ? error.response.data : error.message);
        // Si erreur (ex: pas dans le serveur), on le laisse se connecter mais sans droits
        profile.isOfficier = false;
        return done(null, profile);
    }
}));

// --- FONCTIONS DE SÉCURITÉ ---

// Juste être connecté (pour voir)
const estConnecte = (req, res, next) => {
    if (req.isAuthenticated()) return next();
    res.status(401).json({ message: "Non authentifié." });
};

// Etre connecté ET avoir le grade (pour modifier)
const estOfficier = (req, res, next) => {
    if (req.isAuthenticated() && req.user.isOfficier) {
        return next();
    }
    res.status(403).json({ message: "Permission refusée. Grade insuffisant." });
};

// --- ROUTES AUTH ---
app.get('/auth/discord', passport.authenticate('discord'));
app.get('/auth/discord/callback', passport.authenticate('discord', { failureRedirect: '/' }), (req, res) => res.redirect('/'));
app.get('/auth/logout', (req, res, next) => {
    req.logout((err) => { if (err) return next(err); res.redirect('/'); });
});

// Route info user modifiée pour envoyer le statut "isOfficier" au site
app.get('/auth/user', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({ 
            connecte: true, 
            username: req.user.username, 
            avatar: `https://cdn.discordapp.com/avatars/${req.user.id}/${req.user.avatar}.png`,
            isOfficier: req.user.isOfficier // On envoie l'info au frontend
        });
    } else {
        res.json({ connecte: false });
    }
});

// --- ROUTES API ---

// Tout le monde peut voir (Public)
app.get('/api/protocoles', async (req, res) => {
    const protocoles = await Protocole.find({ statut: { $ne: 'Effectué' } }).sort({ date: -1 });
    res.json(protocoles);
});
app.get('/api/historique', async (req, res) => {
    const protocoles = await Protocole.find({ statut: 'Effectué' }).sort({ date: -1 });
    res.json(protocoles);
});

// SEULS LES OFFICIERS PEUVENT FAIRE ÇA : (J'ai remplacé estConnecte par estOfficier)
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
