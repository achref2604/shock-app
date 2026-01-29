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
    tempsRestant: String, // <--- NOUVEAU CHAMP ICI
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

// ... (Le début de ton fichier avec les connexions ne change pas) ...

// --- ROUTES API ---

// 1. VOIR les protocoles EN ATTENTE (Pour la page principale)
app.get('/api/protocoles', async (req, res) => {
    // On ne cherche que ceux qui ne sont PAS effectués
    const protocoles = await Protocole.find({ statut: { $ne: 'Effectué' } }).sort({ date: -1 });
    res.json(protocoles);
});

// 2. VOIR L'HISTORIQUE (Les 30 derniers effectués)
app.get('/api/historique', async (req, res) => {
    // On cherche ceux qui SONT effectués
    const protocoles = await Protocole.find({ statut: 'Effectué' }).sort({ date: -1 });
    res.json(protocoles);
});

// 3. AJOUTER un protocole (Reste pareil)
app.post('/api/protocoles', verifierAuth, async (req, res) => {
    try {
        const nouveauProtocole = new Protocole(req.body);
        await nouveauProtocole.save();
        res.json({ message: "Protocole enregistré !" });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// 4. VALIDER un protocole + NETTOYAGE AUTOMATIQUE (C'est ici que la magie opère)
app.put('/api/protocoles/:id/valider', verifierAuth, async (req, res) => {
    try {
        // A. On marque le protocole comme effectué
        await Protocole.findByIdAndUpdate(req.params.id, { statut: 'Effectué' });

        // B. Logique de suppression des vieux protocoles (> 30)
        // On compte combien sont terminés
        const historique = await Protocole.find({ statut: 'Effectué' }).sort({ date: -1 }); // Du plus récent au plus vieux
        
        if (historique.length > 30) {
            // S'il y en a plus de 30, on récupère les ID de ceux qui dépassent (les plus vieux à la fin de la liste)
            const tropVieux = historique.slice(30); 
            const idsASupprimer = tropVieux.map(p => p._id);
            
            // On les supprime de la base de données
            await Protocole.deleteMany({ _id: { $in: idsASupprimer } });
            console.log(`${idsASupprimer.length} vieux protocoles supprimés.`);
        }

        res.json({ message: "Validé et historique nettoyé." });
    } catch (error) {
        res.status(500).json({ error: "Erreur lors de la validation" });
    }
});

// ... (La fin avec app.listen ne change pas)
const PORT = process.env.PORT || 3000;

// 5. MODIFIER un protocole (Mise à jour des infos)
app.put('/api/protocoles/:id', verifierAuth, async (req, res) => {
    try {
        // On met à jour tous les champs envoyés
        await Protocole.findByIdAndUpdate(req.params.id, req.body);
        res.json({ message: "Protocole mis à jour avec succès." });
    } catch (error) {
        res.status(500).json({ error: "Erreur lors de la modification" });
    }
});

// 6. RESTAURER un protocole (Sortir des archives -> Vers En cours)
app.put('/api/protocoles/:id/restaurer', verifierAuth, async (req, res) => {
    try {
        const { tempsRestant } = req.body;
        
        // On prépare la mise à jour : on change le statut ET le temps restant si fourni
        let updateData = { statut: 'En Attente', date: Date.now() }; // On met à jour la date pour qu'il remonte en haut
        if (tempsRestant) {
            updateData.tempsRestant = tempsRestant;
        }

        await Protocole.findByIdAndUpdate(req.params.id, updateData);
        res.json({ message: "Protocole restauré." });
    } catch (error) {
        res.status(500).json({ error: "Erreur lors de la restauration" });
    }
});

app.listen(PORT, () => console.log(`Serveur lancé sur le port ${PORT}`));


