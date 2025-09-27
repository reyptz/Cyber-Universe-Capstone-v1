# Projet Cybersécurité - Laboratoires Pratiques

Ce projet contient une série de laboratoires pratiques couvrant les aspects essentiels de la cybersécurité moderne.

## 🎯 Objectifs

Apprendre et expérimenter avec :
- **TLS** : Analyse et sécurisation des communications
- **Chiffrement** : Implémentation d'algorithmes cryptographiques
- **Blockchain** : Sécurité des smart contracts
- **Zero-Knowledge** : Preuves à divulgation nulle de connaissance

## 🚀 Installation et Prérequis

### Prérequis généraux
```bash
# Python 3.8+
python --version

# Node.js 16+
node --version
npm --version

# OpenSSL
openssl version

# Git
git --version
```

## 📚 Guide d'Utilisation

### 1. PKI (Infrastructure à Clés Publiques)

#### PKI Sécurisée (avec révocation)
```bash
cd tls/
# Générer PKI avec CRL/OCSP
bash generate_certs_secure.sh

# Lancer le répondeur OCSP
bash ocsp.sh
```

### 2. Analyse TLS

#### Comparaison TLS 1.2 vs 1.3
```bash
cd tls/
# Comparer les versions TLS
python compare_tls.py
```

### 3. Blockchain Security

#### Smart Contract Sécurisé
```bash
cd blockchain/
# Déployer le contrat sécurisé
npx hardhat run scripts/deploy_secure.js --network localhost

# Tenter l'attaque (qui échouera)
npx hardhat run scripts/attack.js --network localhost

# Audit avec Slither
slither contracts/SecureBank.sol
```

### 5. Zero-Knowledge Proofs

#### Vérificateur on-chain
```bash
cd zk-proof/
# Déployer le vérificateur
npx hardhat run scripts/deploy_verifier.js

# Vérifier une preuve on-chain
npx hardhat run scripts/verify_proof.js
```

### Nettoyage
```bash
# Nettoyer les fichiers générés
find . -name "*.enc" -delete
find . -name "*.pem" -delete
find . -name "build/" -type d -exec rm -rf {} +
```

## 🔒 Sécurité

⚠️ **Attention** : Ce projet est à des fins éducatives uniquement.
- Ne pas utiliser en production
- Les clés et mots de passe sont des exemples
- Respecter les lois locales sur la cryptographie

## 📚 Ressources

- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [Hardhat Documentation](https://hardhat.org/docs)
- [Circom Documentation](https://docs.circom.io/)
- [Cryptography Best Practices](https://cryptography.io/)

---

**Auteur** : Laboratoire Cybersécurité  
**Version** : 1.0  
**Dernière mise à jour** : 2025