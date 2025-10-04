# Guide d'Utilisation - Ghost Cyber Universe Key Generator

## ✅ État Actuel

Le serveur est **OPÉRATIONNEL** et fonctionne sur : **http://localhost:8000**

---

## 🚀 Accès à l'Application

### Pages Disponibles

1. **Page d'Accueil** : http://localhost:8000
2. **Générateur de Clés** : http://localhost:8000/generate ⭐
3. **Sécurité** : http://localhost:8000/security
4. **À Propos** : http://localhost:8000/about
5. **Documentation API** : http://localhost:8000/api/docs

---

## 📋 Comment Utiliser la Page Generate

### Étape 1 : Accéder à la Page
Ouvrez votre navigateur et allez sur : **http://localhost:8000/generate**

### Étape 2 : Configurer la Clé

1. **Type de Clé** : Choisissez parmi :
   - 🔒 Clés Symétriques (AES-256/ChaCha20)
   - 🔑 RSA (3072-4096 bits)
   - 🔄 ECC (P-256/P-384/P-521)
   - ⚡ Ed25519 (Signatures rapides)
   - 🔀 X25519 (Échange de clés ECDH)
   - 🖥️ Clés SSH
   - 📜 Certificats TLS/SSL
   - 💰 BIP39 Mnémonique (24 mots)
   - 🌐 JWT/API Tokens
   - 📝 HMAC
   - 🔢 TOTP/OTP (2FA)
   - 🔄 KDF (Dérivation)
   - 🛡️ Post-Quantique (ML-KEM/ML-DSA)

2. **Algorithme** : Sélectionné automatiquement selon le type choisi

3. **Taille de la Clé** : Ajustez avec la glissière (128-8192 bits)

4. **Format de Sortie** : 
   - PEM, DER, PKCS#8, PKCS#12
   - JWK, Base64, Hexadécimal
   - OpenSSH, BIP39 Mnemonic

5. **Protection par Mot de Passe** (optionnel) :
   - Cochez la case
   - Entrez un mot de passe fort (12+ caractères)
   - Utilisez le bouton "Générer" pour créer un mot de passe sécurisé

### Étape 3 : Générer la Clé

Cliquez sur **"Générer Clé Sécurisée"** (le bouton s'active quand tous les champs requis sont remplis)

### Étape 4 : Récupérer la Clé

1. **Copier** : Cliquez sur l'icône de copie 📋
2. **Télécharger** : Cliquez sur l'icône de téléchargement 💾

---

## 🔐 Fonctionnalités Avancées

### Certificats TLS
Lorsque vous sélectionnez "Certificats TLS", des champs supplémentaires apparaissent :
- Nom Commun (CN)
- Organisation
- Pays (ISO 3166)
- Email
- Durée de validité (max 825 jours)

### KDF (Key Derivation Function)
Pour les clés dérivées, configurez :
- Nombre d'itérations (min 100,000)
- Longueur du salt (16-64 octets)

---

## 🧪 Test de l'API

### Avec PowerShell

```powershell
# Test de santé
Invoke-WebRequest -Uri "http://localhost:8000/api/health"

# Générer une clé AES-256
$body = @{
    key_type = "symmetric"
    algorithm = "AES-256"
    key_size = 256
    output_format = "base64"
    password_protected = $false
} | ConvertTo-Json

Invoke-WebRequest -Uri "http://localhost:8000/api/generate-key" -Method POST -Body $body -ContentType "application/json"
```

### Avec cURL

```bash
# Test de santé
curl http://localhost:8000/api/health

# Générer une clé
curl -X POST "http://localhost:8000/api/generate-key" \
  -H "Content-Type: application/json" \
  -d '{
    "key_type": "symmetric",
    "algorithm": "AES-256",
    "key_size": 256,
    "output_format": "base64",
    "password_protected": false
  }'
```

---

## 🛠️ Commandes Utiles

### Démarrer le Serveur (si arrêté)
```powershell
cd "c:\Users\Acer\Downloads\Projet\CyberSec\Ghost_Cyber_Universe—Capstone_v1\key-generator"
python run.py
```

### Vérifier si le Serveur est Actif
```powershell
Invoke-WebRequest -Uri "http://localhost:8000/api/health"
```

### Installer les Dépendances (si nécessaire)
```powershell
pip install -r requirements.txt
```

---

## 📊 Endpoints API Disponibles

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/` | GET | Page d'accueil |
| `/generate` | GET | Page de génération de clés |
| `/api/health` | GET | Vérification de santé |
| `/api/key-types` | GET | Liste des types de clés |
| `/api/output-formats` | GET | Liste des formats de sortie |
| `/api/generate-key` | POST | Génération de clé |
| `/api/validate-password` | POST | Validation de mot de passe |
| `/api/generate-password` | POST | Génération de mot de passe |
| `/api/docs` | GET | Documentation interactive Swagger |
| `/api/redoc` | GET | Documentation ReDoc |

---

## 🔒 Sécurité et Bonnes Pratiques

### Recommandations 2025
- ✅ **AES-256** ou **ChaCha20-Poly1305** pour le chiffrement symétrique
- ✅ **RSA-3072+** pour les nouvelles applications (ou migrez vers ECC/Post-Q)
- ✅ **ECDSA P-256** ou **Ed25519** pour les signatures
- ✅ **BIP39 24 mots** pour les wallets crypto
- ✅ **Argon2id** pour la dérivation de clés depuis un mot de passe

### Avertissements
- ⚠️ RSA-2048 sera déprécié en 2030
- ⚠️ Ne partagez JAMAIS vos clés privées
- ⚠️ Stockez les clés dans un HSM/Vault en production
- ⚠️ Activez la rotation régulière des clés (tous les 2 ans max)
- ⚠️ Les clés BIP39 doivent être stockées OFFLINE uniquement

---

## 🐛 Dépannage

### Le serveur ne démarre pas
```powershell
# Vérifier les dépendances
pip list | Select-String -Pattern "fastapi|uvicorn|cryptography"

# Réinstaller si nécessaire
pip install -r requirements.txt
```

### Erreur de port 8000 déjà utilisé
```powershell
# Trouver le processus utilisant le port
netstat -ano | findstr :8000

# Tuer le processus (remplacer PID)
taskkill /F /PID <PID>
```

### Erreur 404 sur les fichiers statiques
Vérifier que les dossiers existent :
- `static/css/ghost-dark.css`
- `static/js/generate.js`
- `static/js/complete-key-types.js`
- `static/js/cyber-animations.js`

---

## 📝 Notes Importantes

1. **Progression** : Le formulaire affiche une barre de progression (0-5 étapes)
2. **Validation** : Le bouton "Générer" s'active quand toutes les étapes sont complètes
3. **Force du mot de passe** : Utilisez zxcvbn pour une évaluation précise (score 3+/4 requis)
4. **Rate limiting** : Limite de requêtes appliquée pour éviter les abus
5. **Logs d'audit** : Toutes les générations sont enregistrées dans `key_generator_security.log`

---

## 🎯 Prochaines Étapes

1. ✅ Serveur démarré et opérationnel
2. ✅ Interface web accessible
3. ✅ API fonctionnelle
4. 📝 Testez la génération de différents types de clés
5. 📝 Consultez la documentation API : http://localhost:8000/api/docs
6. 📝 Personnalisez le CSS si nécessaire dans `static/css/ghost-dark.css`

---

## 📞 Support

- **Documentation API** : http://localhost:8000/api/docs
- **Logs** : Consultez `key_generator_security.log` pour les détails
- **Code source** : Vérifiez `api.py`, `core.py`, et `security.py`

---

**Date de création** : 2025-10-04  
**Version** : 1.0.0  
**Statut** : ✅ Opérationnel
