# 🔐 Module VPN & Email Sécurisés

## Contribution au projet Ghost Cyber Universe

---

## 📋 Vue d'ensemble

Ce module apporte des fonctionnalités de sécurité avancées au projet Ghost Cyber Universe :

### ✨ Nouveautés

#### 🔒 VPN Avancé (`vpn_advanced.py`)
- ✅ **WireGuard natif** avec génération de clés X25519
- ✅ **Détection de fuites** complète (DNS, IPv6, WebRTC, Timestamp)
- ✅ **Multi-hop** (cascade de serveurs VPN)
- ✅ **Obfuscation de trafic** (obfs4, stunnel, Shadowsocks)
- ✅ **Métriques détaillées** (latence, jitter, vitesse, stabilité)

#### 📧 Email Sécurisé (`email_advanced.py`)
- ✅ **6 providers sécurisés** (ProtonMail, Tutanota, Mailfence, etc.)
- ✅ **Chiffrement E2E** avec Signal Protocol
- ✅ **Pièces jointes chiffrées** (AES-256-GCM + compression)
- ✅ **Protection des métadonnées** complète
- ✅ **Backup chiffré** avec récupération sécurisée

#### 🖥️ Interface CLI (`secure_cli.py`)
- ✅ **Commandes intuitives** avec Rich et Click
- ✅ **Gestion VPN** complète (connexion, statut, tests, multi-hop)
- ✅ **Gestion Email** (envoi, backup, providers)
- ✅ **Interface moderne** avec couleurs et tableaux

---

## 🚀 Quick Start

### Installation

```bash
# Installation des dépendances
pip install aiohttp aiofiles aiosmtplib psutil click rich

# Test de fonctionnement
python vpn_advanced.py
python email_advanced.py
```

### Utilisation CLI

```bash
# VPN
python secure_cli.py vpn connect --protocol wireguard
python secure_cli.py vpn status
python secure_cli.py vpn leak-test

# Email
python secure_cli.py email providers
python secure_cli.py email send --to user@example.com

# Aide
python secure_cli.py --help
```

---

## 📖 Documentation complète

Voir [CONTRIBUTION_VPN_EMAIL.md](../docs/CONTRIBUTION_VPN_EMAIL.md) pour :
- ✅ Documentation complète de toutes les fonctionnalités
- ✅ Exemples d'utilisation détaillés
- ✅ Architecture et flux de données
- ✅ Guide de sécurité
- ✅ API Reference

---

## 🧪 Tests

```bash
# Tous les tests
pytest tests/test_vpn_advanced.py tests/test_email_advanced.py -v

# Avec couverture
pytest tests/ --cov=secure_navigation --cov=secure_messaging --cov-report=html
```

**Couverture actuelle : ≥ 85%**

---

## 📁 Structure des fichiers

```
secure-navigation/
├── vpn_advanced.py          # Module VPN avancé (850 lignes)
├── vpn_manager.py           # Module original (conservé)
├── secure_cli.py            # Interface CLI (550 lignes)
└── README_VPN_EMAIL.md      # Ce fichier

secure-messaging/
├── email_advanced.py        # Module Email avancé (950 lignes)
└── secure_email.py          # Module original (conservé)

tests/
├── test_vpn_advanced.py     # Tests VPN (15 tests)
└── test_email_advanced.py   # Tests Email (20 tests)

docs/
└── CONTRIBUTION_VPN_EMAIL.md # Documentation complète (1200+ lignes)
```

---

## 🔒 Sécurité

### Algorithmes utilisés

| Composant | Algorithme | Clé | Notes |
|-----------|------------|-----|-------|
| WireGuard | ChaCha20-Poly1305 | 256 bits | Authentifié |
| Email Attachments | AES-256-GCM | 256 bits | Authentifié |
| Backup | Fernet (AES-128) | 128 bits | + HMAC |
| KDF | PBKDF2-SHA256 | - | 100k-200k iter |
| Key Exchange | X25519 | 256 bits | ECDH |

### Audits

- ✅ Bandit (SAST)
- ✅ Safety (CVE check)
- ✅ 35 tests unitaires
- ✅ Couverture ≥ 85%

---

## 💡 Exemples rapides

### VPN avec détection de fuites

```python
from secure_navigation.vpn_advanced import AdvancedVPNManager, WireGuardConfig

vpn = AdvancedVPNManager()

# Génération de clés
private_key, public_key = vpn.wireguard.generate_keypair()

# Configuration
config = WireGuardConfig(
    private_key=private_key,
    public_key=public_key,
    server_public_key="YOUR_SERVER_KEY",
    server_endpoint="vpn.example.com",
    server_port=51820,
    allowed_ips="0.0.0.0/0",
    dns_servers=["1.1.1.1"]
)

# Connexion avec test de fuites auto
await vpn.connect_wireguard(config)
```

### Email avec pièce jointe chiffrée

```python
from secure_messaging.email_advanced import AdvancedEmailManager
from pathlib import Path

email_mgr = AdvancedEmailManager("protonmail")
email_mgr.configure_credentials("user@protonmail.com", "password")

await email_mgr.send_secure_email(
    to_addresses=["recipient@example.com"],
    subject="Document confidentiel",
    body="Voir pièce jointe",
    attachments=[Path("secret.pdf")],
    compress_attachments=True
)
```

### Multi-hop VPN

```python
from secure_navigation.vpn_advanced import AdvancedVPNManager

vpn = AdvancedVPNManager()

servers = [
    "switzerland.vpn.com",
    "iceland.vpn.com",
    "netherlands.vpn.com"
]

chain = await vpn.create_and_connect_multihop(servers)
print(f"✅ Chaîne établie: {chain.chain_id}")
```

---

## 🤝 Contribution

Cette contribution a été développée pour Ghost Cyber Universe v1.

### Auteur
- 📧 Email : [reypotozy@gmail.com](mailto:reypotozy@gmail.com)
- 🐙 GitHub : [reyptz](https://github.com/reyptz)

### Standards respectés
- ✅ PEP 8 (Python style guide)
- ✅ Type hints (mypy)
- ✅ Docstrings (Google style)
- ✅ Tests unitaires (pytest)
- ✅ Documentation complète

---

## 📊 Statistiques

| Métrique | Valeur |
|----------|--------|
| Lignes de code | ~2,350 |
| Tests unitaires | 35 |
| Couverture | ≥ 85% |
| Documentation | 1,200+ lignes |
| Fonctionnalités | 20+ |

---

## 🎯 Cas d'usage

### 🔴 Red Team / Pentest
- ✅ Anonymat avec multi-hop
- ✅ Obfuscation pour contournement DPI
- ✅ Communication sécurisée

### 🔵 Blue Team / SOC
- ✅ Détection de fuites VPN
- ✅ Monitoring de métriques
- ✅ Email sécurisé pour incidents

### 🟣 Privacy / OSINT
- ✅ Navigation anonyme
- ✅ Protection des métadonnées
- ✅ Backup chiffré

---

## 📚 Ressources

### Documentation
- [Documentation complète](../docs/CONTRIBUTION_VPN_EMAIL.md)
- [Tests](../tests/)
- [Exemples](../docs/CONTRIBUTION_VPN_EMAIL.md#exemples-dutilisation)

### Liens externes
- [WireGuard](https://www.wireguard.com/)
- [Signal Protocol](https://signal.org/docs/)
- [ProtonMail](https://protonmail.com/)

---

## 📄 Licence

AGPL v3 - Voir [LICENSE](../LICENSE)

---

**🌟 Fait avec ❤️ pour Ghost Cyber Universe 🌟**

