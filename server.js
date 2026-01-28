const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// IMPORTANT : Servir le site web (Frontend)
app.use(express.static('public'));

// Connexion à la Base de Données (Via une variable secrète pour la sécurité)
const mongoURI = process.env.MONGO_URI; 
mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("Connecté à MongoDB"))
    .catch(err => console.error("Erreur de connexion MongoDB:", err));

// Schéma
const ProtocoleSchema = new mongoose.Schema({
    auteurNom: String,
    auteurMatricule: String,
    auteurGrade: String,
    auteurRegiment: String,
    protocoleType: String,
    raison: String,
    targetSteamID: String,
    details: String,
    statut: { type: String, default: 'En Attente' },
    date: { type: Date, default: Date.now }
});
const Protocole = mongoose.model('Protocole', ProtocoleSchema);

// Middleware Auth
const verifierAuth = (req, res, next) => {
    const codeAcces = req.headers['authorization'];
    // Le mot de passe sera aussi stocké dans une variable secrète
    if (codeAcces === process.env.ADMIN_PASSWORD) { 
        next();
    } else {
        res.status(403).json({ message: "Accès refusé." });
    }
};

// Routes API
app.post('/api/protocoles', verifierAuth, async (req, res) => {
    try {
        const nouveauProtocole = new Protocole(req.body);
        await nouveauProtocole.save();
        res.json({ message: "Protocole enregistré !" });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/protocoles', async (req, res) => {
    const protocoles = await Protocole.find().sort({ date: -1 });
    res.json(protocoles);
});

app.put('/api/protocoles/:id/valider', verifierAuth, async (req, res) => {
    await Protocole.findByIdAndUpdate(req.params.id, { statut: 'Effectué' });
    res.json({ message: "Validé." });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Serveur lancé sur le port ${PORT}`));