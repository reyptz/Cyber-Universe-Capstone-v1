# 👻 Ghost Cyber Universe — Capstone v1

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)](https://fastapi.tiangolo.com)
[![Rust](https://img.shields.io/badge/Rust-1.75+-orange.svg)](https://rust-lang.org)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-AGPL%20v3-yellow.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-ISO%2027001-red.svg)](https://www.iso.org/isoiec-27001-information-security.html)
[![DevSecOps](https://img.shields.io/badge/DevSecOps-Enabled-purple.svg)](https://www.devsecops.org)

## 🚀 Description

**Ghost Cyber Universe** est un laboratoire de cybersécurité complet comprenant deux plateformes majeures :

### 🔴 Offensive Operations Suite
- **Genjutsu Engine** : Génération polymorphe de payloads avec LLVM (< 3 min)
- **Ghost Compiler** : Injection reflective in-memory sans traces (Rust no_std)
- **Hiraishin Framework** : IaC ultra-rapide (deploy/destroy < 180s, rollback < 60s)
### 🔵 Defensive Intelligence Platform
- **Shinra OSINT Agent** : Collecte automatisée (1000 pages/min) avec RAG
- **KumoShield S-IA** : Détection temps réel (< 200ms) avec eBPF, Sigma, YARA
- **Interface Web moderne** : React + TypeScript + TailwindCSS

---

## 🎯 Nouveautés — Implémentation Cahiers des Charges

### ✨ Ce qui a été ajouté

#### 🔴 Offensive Operations Suite (NOUVEAU)
```
offensive-ops/
├── genjutsu/          # LLVM Pass pour polymorphisme
├── ghost/             # Rust no_std loader
├── hiraishin/         # Go CLI + Terraform IaC
└── orchestrator/      # Python SBOM + Rekor
```

#### 🔵 Defensive Intelligence Platform (NOUVEAU)
```
defensive-ops/
├── shinra/            # FastAPI OSINT Agent
├── kumoshield/        # eBPF Sensors + Detection
├── frontend/          # React Dashboard
└── infra/             # Kubernetes manifests
```

#### 🔧 DevSecOps & CI/CD (NOUVEAU)
- GitHub Actions avec SBOM CycloneDX
- Sigstore/Cosign attestations SLSA v1.2
- Prometheus + Grafana dashboards
- Docker Compose stack complète

### 🎯 Objectifs principaux
- ✅ **Red Team** : Génération polymorphe, injection furtive, IaC < 180s
- ✅ **Blue Team** : OSINT 1000 pages/min, détection < 200ms, SLA 99.5%
- ✅ **DevSecOps** : CI/CD sécurisé, SBOM signées, monitoring temps réel
- ✅ **Conformité** : ISO 27001/27007, RGPD, SLSA v1.2

### 👥 Public Cible
- Red/Blue Teams et pentesters
- AnalystesSOC et threat hunters
- DevSecOps engineers
- Security researchers

## ✨ Fonctionnalités

### 🔐 Module Aetherium (Cryptographie)
- **🔑 Protocole GKEP** : Ghost Key Exchange Protocol propriétaire
- **🔄 Rotation Automatique** : Gestion intelligente des clés avec support blockchain
- **🛡️ Chiffrement Multi-Algorithmes** : AES-GCM, RSA, ECC, RC4
- **✍️ Signatures Numériques** : ECDSA, Ed25519, HMAC
- **🔍 Hachage Sécurisé** : SHA-2/3, PBKDF2, Argon2
- **🌐 Protocoles Réseau** : SSL/TLS/DTLS, IPsec, QUIC

### 🔧 Module DevSecOps
- **⚡ CI/CD Sécurisé** : Pipelines GitHub Actions avec scans automatisés
- **🔒 Gestion des Secrets** : Stockage, rotation et audit sécurisés
- **📋 Politiques Automatisées** : OPA/Gatekeeper, RBAC, ABAC
- **📊 Surveillance Continue** : Prometheus, Grafana, ELK Stack, Jaeger
- **🛡️ Scans de Sécurité** : SAST, DAST, SCA, IaC

### 🤖 Intelligence Artificielle
- **🧠 ML/DL** : PyTorch, TensorFlow, scikit-learn
- **💬 NLP Avancé** : Transformers, LangChain, RAG
- **📊 Vector Databases** : Pinecone, Milvus, Weaviate, FAISS
- **🔄 MLOps** : MLflow, TFX, BentoML

### 🌐 Blockchain & Web3
- **⛓️ Outils Développement** : Hardhat, Truffle, Foundry
- **🏦 Stockage Décentralisé** : IPFS, Filecoin
- **⚡ Layer 2** : Optimistic/zkRollups
- **🔮 Oracles** : Chainlink
- **🔐 ZK Proofs** : zkSNARKs, zkSTARKs, MPC

---

## 🛠️ Installation

### 📋 Prérequis Techniques

#### Obligatoires
- **Docker 24+** & **Docker Compose 2.0+**
- **Git**
- **Python 3.11+**
- **Node.js 18+**

#### Optionnels (pour Offensive Ops)
- **Rust 1.75+** (Ghost Compiler)
- **Go 1.21+** (Hiraishin CLI)
- **LLVM 17+** (Genjutsu Engine)

### 🚀 Installation Rapide (Recommandée)

```bash
# 1. Cloner le repository
git clone https://github.com/reyptz/ghost-cyber-universe.git
cd ghost-cyber-universe

# 2. Lancer l'installation automatique
chmod +x setup.sh
./setup.sh all

# OU installation sélective :
./setup.sh defensive    # Defensive Ops uniquement
./setup.sh offensive    # Offensive Ops uniquement
./setup.sh monitoring   # Monitoring uniquement
```

### 🐳 Installation avec Docker (Production)

```bash
# Démarrer tous les services
docker-compose up -d

# Vérifier le statut
docker-compose ps

# Accéder aux services
# - Grafana:    http://localhost:3000 (admin/admin)
# - API Docs:   http://localhost:8000/api/docs
# - Frontend:   http://localhost:5173
# - Prometheus: http://localhost:9090

# Voir les logs
docker-compose logs -f shinra-api
```

### 💻 Installation Locale (Développement)

#### Backend (Shinra OSINT Agent)
```bash
cd defensive-ops/shinra
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn api.main:app --reload --port 8000
```

#### Frontend
```bash
cd defensive-ops/frontend
npm install
npm run dev
```

#### Offensive Ops
```bash
# Genjutsu Engine
cd offensive-ops/genjutsu
./build.sh

# Ghost Compiler
cd ../ghost
cargo build --release

# Hiraishin CLI
cd ../hiraishin/cli
go build -o hiraishin main.go
```

---

## 🎯 Cas d'Usage

### 🔴 Red Team / Offensive Security
- **Payload Generation** : Générer des shellcodes polymorphes indétectables
- **Stealth Injection** : Injecter du code en mémoire sans traces
- **Rapid Infrastructure** : Déployer/détruire des environnements d'attaque en < 3 minutes
- **Training Labs** : Créer des labs éphémères pour exercices Red Team

### 🔵 Blue Team / Defensive Security
- **OSINT Collection** : Collecter automatiquement des données de threat intelligence
- **Real-time Detection** : Détecter des menaces avec < 200ms de latence
- **Threat Hunting** : Rechercher des IOCs avec RAG et enrichissement IA
- **SOC Automation** : Automatiser les playbooks de réponse aux incidents

### 🟣 Purple Team / DevSecOps
- **CI/CD Security** : Pipelines sécurisés avec SBOM et attestations
- **Supply Chain Security** : Traçabilité complète avec Sigstore/Rekor
- **Performance Monitoring** : Dashboards Grafana pour métriques opérationnelles
- **Compliance** : Conformité ISO 27001/27007 et RGPD

## 🤝 Contribuer

Nous accueillons chaleureusement les contributions ! Voici comment participer :

### 📝 Guidelines de Contribution

1. **Fork** le projet
2. **Créer** une branche feature (`git checkout -b feature/AmazingFeature`)
3. **Commit** vos changements (`git commit -m 'Add AmazingFeature'`)
4. **Push** vers la branche (`git push origin feature/AmazingFeature`)
5. **Ouvrir** une Pull Request

### 🔍 Standards de Code

- Suivre **PEP 8** pour Python
- Ajouter des **tests unitaires** pour les nouvelles fonctionnalités
- Documenter le code avec **docstrings**
- Respecter les **principes de sécurité**

### 📋 Pull Request Guidelines

- Décrire clairement les changements
- Inclure des tests pour les nouvelles fonctionnalités
- S'assurer que tous les tests passent
- Respecter les standards de sécurité
- Mettre à jour la documentation si nécessaire

## 📄 Licence

Ce projet est sous licence **AGPL v3**. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

## 👨‍💻 Auteur & Contact

### 🏢 Équipe de Développement
**Ghost Cyber Universe Team**
- 🎓 Projet Capstone en Cybersécurité
- 📅 Année : 2025

### 📞 Moyens de Contact

- 📧 **Email** : [reypotozy@gmail.com](mailto:reypotozy@gmail.com)
- 🐙 **GitHub** : [Votre GitHub](https://github.com/reyptz)

### 🆘 Support

- 🐛 **Issues** : [GitHub Issues](https://github.com/reyptz/ghost-cyber-universe/issues)
- 💬 **Discussions** : [GitHub Discussions](https://github.com/reyptz/ghost-cyber-universe/discussions)

---

## 🏆 Conformité & Standards

- ✅ **ISO 27001** : Management de la sécurité de l'information
- ✅ **NIST Cybersecurity Framework** : Cadre de cybersécurité
- ✅ **SOC 2** : Contrôles de sécurité organisationnels
- ✅ **GDPR** : Protection des données personnelles
- ✅ **OWASP Top 10** : Sécurité des applications web

## 📊 Statistiques du Projet

![GitHub stars](https://img.shields.io/github/stars/reyptz/ghost-cyber-universe?style=social)
![GitHub forks](https://img.shields.io/github/forks/reyptz/ghost-cyber-universe?style=social)
![GitHub issues](https://img.shields.io/github/issues/reyptz/ghost-cyber-universe)
![GitHub pull requests](https://img.shields.io/github/issues-pr/reyptz/ghost-cyber-universe)

---

<div align="center">

**🌟 Si ce projet vous aide, n'hésitez pas à lui donner une étoile ! 🌟**

Made with ❤️ by the Ghost Cyber Universe Team

</div>