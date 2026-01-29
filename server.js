const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;

const app = express();

// --- CONFIGURATION ---
// Récupération des variables d'environnement
const MONGO_URI = process.env.MONGO_URI;
const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const CALLBACK_URL = process.env.DISCORD_CALLBACK_URL; // ex: https://ton-site.onrender.com/auth/discord/callback
const SESSION_SECRET = process.env.SESSION_SECRET || 'secretSuperShock';
// Optionnel : L'ID de ton serveur Discord pour empêcher les inconnus de se connecter
const ALLOWED_GUILD_ID = process.env.ALLOWED_GUILD_ID; 

// --- BASE DE DONNÉES ---
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("✅ Connecté à MongoDB"))
    .catch(err => console.error("❌ Erreur MongoDB:", err));

const ProtocoleSchema = new mongoose.Schema({
    auteurNom: String,
    auteurMatricule: String,
    auteurGrade: String,
    discordUser: String, // Nouveau : Pseudo Discord de celui qui a fait l'action
    discordId: String,   // Nouveau : ID Discord unique
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

// Configuration de la Session (Stockée dans MongoDB)
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: MONGO_URI }),
    cookie: { maxAge: 1000 * 60 * 60 * 24 * 7 } // Reste connecté 7 jours
}));

// Initialisation Passport (Discord)
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

passport.use(new DiscordStrategy({
    clientID: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    callbackURL: CALLBACK_URL,
    scope: ['identify', 'guilds'] // On demande l'identité et la liste des serveurs
}, (accessToken, refreshToken, profile, done) => {
    // SÉCURITÉ : Vérifier si l'utilisateur est dans le bon serveur Discord
    if (ALLOWED_GUILD_ID) {
        const isMember = profile.guilds.some(g => g.id === ALLOWED_GUILD_ID);
        if (!isMember) return done(null, false, { message: "Vous n'êtes pas sur le serveur Shock Trooper." });
    }
    return done(null, profile);
}));

// Fonction de vérification (Middleware de sécurité)
const estConnecte = (req, res, next) => {
    if (req.isAuthenticated()) {
        return next();
    }
    res.status(401).json({ message: "Non authentifié. Veuillez vous connecter via Discord." });
};

// --- ROUTES AUTHENTIFICATION ---

// 1. Lancer la connexion
app.get('/auth/discord', passport.authenticate('discord'));

// 2. Retour de Discord
app.get('/auth/discord/callback', passport.authenticate('discord', {
    failureRedirect: '/' // Si ça rate, retour accueil
}), (req, res) => {
    res.redirect('/'); // Si ça marche, retour accueil
});

// 3. Info utilisateur (pour le frontend)
app.get('/auth/user', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({ 
            connecte: true, 
            username: req.user.username, 
            avatar: `https://cdn.discordapp.com/avatars/${req.user.id}/${req.user.avatar}.png`
        });
    } else {
        res.json({ connecte: false });
    }
});

// 4. Déconnexion
app.get('/auth/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) return next(err);
        res.redirect('/');
    });
});

// --- ROUTES API (PROTÉGÉES PAR DISCORD) ---

// Voir (Public ou Protégé selon ton choix, ici Public)
app.get('/api/protocoles', async (req, res) => {
    const protocoles = await Protocole.find({ statut: { $ne: 'Effectué' } }).sort({ date: -1 });
    res.json(protocoles);
});

app.get('/api/historique', async (req, res) => {
    const protocoles = await Protocole.find({ statut: 'Effectué' }).sort({ date: -1 });
    res.json(protocoles);
});

// AJOUTER (Protégé)
app.post('/api/protocoles', estConnecte, async (req, res) => {
    try {
        const data = req.body;
        // On ajoute automatiquement les infos Discord
        data.discordUser = req.user.username;
        data.discordId = req.user.id;
        
        const nouveauProtocole = new Protocole(data);
        await nouveauProtocole.save();
        res.json({ message: "Enregistré par " + req.user.username });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// MODIFIER (Protégé)
app.put('/api/protocoles/:id', estConnecte, async (req, res) => {
    try {
        await Protocole.findByIdAndUpdate(req.params.id, req.body);
        res.json({ message: "Mis à jour par " + req.user.username });
    } catch (error) { res.status(500).json({ error: "Erreur" }); }
});

// VALIDER (Protégé)
app.put('/api/protocoles/:id/valider', estConnecte, async (req, res) => {
    try {
        await Protocole.findByIdAndUpdate(req.params.id, { statut: 'Effectué' });
        
        // Nettoyage historique > 30
        const historique = await Protocole.find({ statut: 'Effectué' }).sort({ date: -1 });
        if (historique.length > 30) {
            const tropVieux = historique.slice(30);
            await Protocole.deleteMany({ _id: { $in: tropVieux.map(p => p._id) } });
        }
        res.json({ message: "Validé par " + req.user.username });
    } catch (error) { res.status(500).json({ error: "Erreur" }); }
});

// RESTAURER (Protégé)
app.put('/api/protocoles/:id/restaurer', estConnecte, async (req, res) => {
    try {
        const { tempsRestant } = req.body;
        let updateData = { statut: 'En Attente', date: Date.now() };
        if (tempsRestant) updateData.tempsRestant = tempsRestant;
        
        await Protocole.findByIdAndUpdate(req.params.id, updateData);
        res.json({ message: "Restauré par " + req.user.username });
    } catch (error) { res.status(500).json({ error: "Erreur" }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Serveur lancé sur le port ${PORT}`));
