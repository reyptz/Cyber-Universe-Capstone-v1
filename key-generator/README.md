# 🔐 Générateur de Clés Cryptographiques - Ghost Cyber Universe

Un générateur complet de clés cryptographiques avec toutes les bonnes pratiques de sécurité, développé dans le cadre du projet Ghost Cyber Universe.

## ✨ Fonctionnalités

### 🔑 Types de Clés Supportés

#### Clés Symétriques
- **AES** (AES-128, AES-192, AES-256)
- **ChaCha20-Poly1305**
- Usage : Chiffrement de données, clés de session, HMAC

#### Clés Asymétriques
- **RSA** (2048, 3072, 4096 bits)
- **ECC** (secp256r1, secp384r1, secp521r1, secp256k1)
- **Ed25519** (Signatures modernes)
- **X25519** (Échange de clés)
- **Ed448/X448** (Courbes étendues)

#### Certificats et PKI
- **Certificats TLS** (X.509)
- **CSR** (Certificate Signing Request)
- **Auto-signature** et envoi à CA
- **PKCS#12/PFX** avec protection par mot de passe

#### Clés SSH
- **RSA, ECDSA, Ed25519**
- **Format OpenSSH** et PEM
- **Passphrase** optionnelle

#### Crypto-monnaie
- **BIP39** mnémoniques (12/24 mots)
- **Seeds** dérivés
- **Avertissements de sécurité** renforcés

#### JWT et API
- **HS256/HS512** (HMAC)
- **RS256/RS512** (RSA)
- **ES256/ES512** (ECC)
- **EdDSA**
- **Format JWK** pour intégration facile

#### Authentification
- **TOTP/OTP** secrets
- **HMAC** (SHA256, SHA512)
- **KDF** (PBKDF2, scrypt, Argon2id)

### 📤 Formats de Sortie

- **PEM** (Recommandé pour la plupart des usages)
- **DER** (Binaire)
- **PKCS#8** (Format moderne)
- **PKCS#12/PFX** (Bundle protégé)
- **JWK** (JSON Web Key)
- **Base64/Hex/Raw**
- **BIP39 Mnemonic**
- **OpenSSH**

## 🛡️ Sécurité

### Bonnes Pratiques Implémentées

- **CSPRNG** : Générateur de nombres aléatoires cryptographiquement sûr
- **Protection des clés privées** : Chiffrement avec mots de passe forts
- **Validation des entrées** : Vérification de tous les paramètres
- **Rate limiting** : Protection contre les abus
- **Audit et logs** : Traçabilité complète des opérations
- **Avertissements de sécurité** : Alertes contextuelles
- **Conformité** : FIPS, PCI-DSS, GDPR

### Fonctionnalités de Sécurité

- **Validation de force des mots de passe**
- **Génération de mots de passe sécurisés**
- **Chiffrement des données sensibles**
- **Rotation automatique des clés**
- **Surveillance des abus**
- **Rapports de sécurité**

## 🎯 Interface Web Complète

L'application dispose maintenant d'une interface web moderne et complète avec un thème cyber futuriste :

### Pages Disponibles

- **Page d'accueil** (`/`) : Présentation des fonctionnalités et navigation
- **Génération de clés** (`/generate`) : Interface complète de génération avec formulaire dynamique
- **Sécurité** (`/security`) : Bonnes pratiques, recommandations et rapports de sécurité
- **À propos** (`/about`) : Documentation complète du projet Ghost Cyber Universe
- **API Docs** (`/api/docs`) : Documentation interactive Swagger/OpenAPI

### Fonctionnalités de l'Interface

- 🎨 **Thème Cyber Moderne** : Interface futuriste avec effets visuels (glow, animations)
- 📱 **Responsive Design** : Compatible mobile, tablette et desktop
- ⚡ **Animations Fluides** : Effets cyber, particules et transitions modernes
- 🔒 **Validation Temps Réel** : Feedback immédiat sur les paramètres de génération
- 🛡️ **Sécurité Renforcée** : Protection, validation et avertissements complets
- 🎭 **Effets Visuels** : Particules, trails de souris, animations de texte
- 📊 **Dashboard de Sécurité** : Métriques et rapports en temps réel

### Technologies Frontend

- **HTML5** avec templates Jinja2
- **Bootstrap 5** pour le layout responsive
- **CSS3** personnalisé avec thème cyber
- **JavaScript ES6+** pour l'interactivité
- **Font Awesome** pour les icônes
- **Animations CSS3** et JavaScript pour les effets visuels

## 🚀 Installation

### Prérequis

- Python 3.11+
- pip

### Installation Rapide

```bash
# Cloner le repository
git clone https://github.com/reyptz/ghost-cyber-universe.git
cd ghost-cyber-universe/key-generator

# Créer un environnement virtuel
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate     # Windows

# Installer les dépendances
pip install -r requirements.txt

# Lancer le serveur
python run.py
```

### 🐳 Installation avec Docker (Recommandé)

```bash
# Démarrer avec Docker Compose (plus simple)
docker-compose up -d

# Vérifier le statut
docker-compose ps

# Voir les logs
docker-compose logs -f
```

### Installation avec Docker manuelle

```bash
# Build de l'image
docker build -t ghost-key-generator .

# Lancement du conteneur
docker run -p 8000:8000 ghost-key-generator
```

## 📖 Utilisation

### Interface Web Complète

1. **Accédez à l'interface** : http://localhost:8000
2. **Navigation intuitive** : Utilisez le menu pour accéder aux différentes sections
3. **Page de génération** : Formulaire complet avec validation temps réel
4. **Sélection dynamique** : Types de clés et algorithmes mis à jour automatiquement
5. **Protection avancée** : Mots de passe avec indicateur de force
6. **Résultats sécurisés** : Affichage et téléchargement des clés générées
7. **Documentation intégrée** : Pages de sécurité et à propos complètes

#### Fonctionnalités de l'Interface

- 🎨 **Thème Cyber** : Interface futuriste avec effets visuels
- 📱 **Responsive** : Optimisé pour tous les appareils
- ⚡ **Animations** : Effets fluides et transitions modernes
- 🔒 **Validation** : Feedback immédiat sur les paramètres
- 🛡️ **Sécurité** : Avertissements et recommandations intégrés

### API REST

#### Générer une clé

```bash
curl -X POST "http://localhost:8000/api/generate-key" \
  -H "Content-Type: application/json" \
  -d '{
    "key_type": "rsa",
    "algorithm": "RSA-2048",
    "output_format": "pem",
    "password_protected": true,
    "password": "MonMotDePasseFort123!"
  }'
```

#### Obtenir les types de clés

```bash
curl "http://localhost:8000/api/key-types"
```

#### Valider un mot de passe

```bash
curl -X POST "http://localhost:8000/api/validate-password" \
  -H "Content-Type: application/json" \
  -d '{"password": "MonMotDePasse123!"}'
```

### Exemples d'Usage

#### Clé AES-256

```python
import requests

response = requests.post('http://localhost:8000/api/generate-key', json={
    'key_type': 'symmetric',
    'algorithm': 'AES-256',
    'output_format': 'base64'
})

key_data = response.json()['key_data']
print(f"Clé AES-256: {key_data}")
```

#### Paire de clés RSA

```python
response = requests.post('http://localhost:8000/api/generate-key', json={
    'key_type': 'rsa',
    'algorithm': 'RSA-2048',
    'output_format': 'pem',
    'password_protected': True,
    'password': 'MotDePasseSecurise123!'
})

result = response.json()
print(f"Clé privée: {result['private_key']}")
print(f"Clé publique: {result['public_key']}")
```

#### Certificat TLS

```python
response = requests.post('http://localhost:8000/api/generate-key', json={
    'key_type': 'tls_cert',
    'algorithm': 'RSA',
    'output_format': 'pem',
    'common_name': 'example.com',
    'organization': 'Mon Entreprise',
    'country': 'FR',
    'validity_days': 365
})

result = response.json()
print(f"Certificat: {result['key_data']['certificate']}")
print(f"Clé privée: {result['key_data']['private_key']}")
```

#### Mnémonique BIP39

```python
response = requests.post('http://localhost:8000/api/generate-key', json={
    'key_type': 'bip39',
    'algorithm': 'BIP39-256',
    'output_format': 'bip39_mnemonic'
})

mnemonic = response.json()['key_data']
print(f"Mnémonique: {mnemonic}")
```

## 🔧 Configuration

### Variables d'Environnement

```bash
# Configuration de sécurité
export KEY_GENERATOR_MAX_REQUESTS_PER_MINUTE=10
export KEY_GENERATOR_MAX_REQUESTS_PER_HOUR=100
export KEY_GENERATOR_MIN_PASSWORD_LENGTH=12

# Configuration de l'application
export KEY_GENERATOR_HOST=0.0.0.0
export KEY_GENERATOR_PORT=8000
export KEY_GENERATOR_DEBUG=False
```

### Configuration Avancée

```python
# Dans api.py
app = FastAPI(
    title="Ghost Cyber Universe - Générateur de Clés",
    description="Générateur complet de clés cryptographiques",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Middleware de sécurité
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://votre-domaine.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
```

## 📊 Monitoring et Audit

### Logs de Sécurité

```bash
# Consulter les logs
tail -f key_generator_security.log

# Logs d'audit
tail -f key_generator_audit.json
```

### Rapport de Sécurité

```bash
curl "http://localhost:8000/api/security-report"
```

### Nettoyage des Données

```bash
curl "http://localhost:8000/api/cleanup"
```

## 🧪 Tests

### Tests Unitaires

```bash
# Installation des dépendances de test
pip install pytest pytest-asyncio httpx

# Lancement des tests
pytest tests/
```

### Tests de Sécurité

```bash
# Test de génération de clés
python -m pytest tests/test_key_generation.py

# Test de sécurité
python -m pytest tests/test_security.py

# Test de l'API
python -m pytest tests/test_api.py
```

## 📚 Documentation API

### Documentation Interactive

- **Swagger UI** : http://localhost:8000/api/docs
- **ReDoc** : http://localhost:8000/api/redoc

### Endpoints Principaux

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/api/generate-key` | POST | Génère une clé cryptographique |
| `/api/key-types` | GET | Liste les types de clés supportés |
| `/api/output-formats` | GET | Liste les formats de sortie |
| `/api/security-warnings/{key_type}` | GET | Avertissements de sécurité |
| `/api/validate-password` | POST | Valide un mot de passe |
| `/api/generate-password` | POST | Génère un mot de passe sécurisé |
| `/api/security-report` | GET | Rapport de sécurité |

## 🔒 Sécurité et Conformité

### Standards Respectés

- **ISO 27001** : Management de la sécurité
- **NIST Cybersecurity Framework** : Cadre de cybersécurité
- **PCI-DSS** : Sécurité des données de cartes
- **GDPR** : Protection des données personnelles
- **OWASP Top 10** : Sécurité des applications web

### Bonnes Pratiques

- **Chiffrement au repos** : Toutes les clés privées sont chiffrées
- **Chiffrement en transit** : HTTPS obligatoire
- **Authentification forte** : Mots de passe complexes
- **Audit complet** : Traçabilité de toutes les opérations
- **Rate limiting** : Protection contre les abus
- **Validation d'entrée** : Vérification de tous les paramètres

## 🤝 Contribution

### Guidelines de Contribution

1. **Fork** le projet
2. **Créer** une branche feature (`git checkout -b feature/AmazingFeature`)
3. **Commit** vos changements (`git commit -m 'Add AmazingFeature'`)
4. **Push** vers la branche (`git push origin feature/AmazingFeature`)
5. **Ouvrir** une Pull Request

### Standards de Code

- Suivre **PEP 8** pour Python
- Ajouter des **tests unitaires** pour les nouvelles fonctionnalités
- Documenter le code avec **docstrings**
- Respecter les **principes de sécurité**

## 📄 Licence

Ce projet est sous licence **AGPL v3**. Voir le fichier [LICENSE](../../LICENSE) pour plus de détails.

## 👥 Équipe

**Ghost Cyber Universe Team**
- 🎓 Projet Capstone en Cybersécurité
- 📅 Année : 2025

### Contact

- 📧 **Email** : [reypotozy@gmail.com](mailto:reypotozy@gmail.com)
- 🐙 **GitHub** : [reyptz](https://github.com/reyptz)

## 🆘 Support

- 🐛 **Issues** : [GitHub Issues](https://github.com/reyptz/ghost-cyber-universe/issues)
- 💬 **Discussions** : [GitHub Discussions](https://github.com/reyptz/ghost-cyber-universe/discussions)

---

<div align="center">

**🌟 Si ce projet vous aide, n'hésitez pas à lui donner une étoile ! 🌟**

Made with ❤️ by the Ghost Cyber Universe Team

</div>
