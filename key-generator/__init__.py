"""
Générateur de Clés Cryptographiques - Ghost Cyber Universe
========================================================

Module complet pour la génération de clés cryptographiques de tous types :
- Clés symétriques (AES, ChaCha20-Poly1305)
- Clés asymétriques (RSA, ECC, Ed25519, X25519)
- Certificats TLS/PKI
- Clés SSH
- Seeds crypto-monnaie (BIP39)
- Clés de signature de code
- JWT/API tokens
- Clés KDF (PBKDF2, scrypt, Argon2id)
- OTP/TOTP seeds
- Clés HMAC
- Clés temporaires/éphémères
- Clés de chiffrement de clé (Key Wrapping)
- Clés de licence/produit

Formats de sortie supportés :
- PEM, DER, PKCS#8, PKCS#12/PFX
- JWK (JSON Web Key)
- Base64, Hex, Raw
- BIP39 mnemonic

Bonnes pratiques de sécurité :
- CSPRNG (Cryptographically Secure PRNG)
- Protection des clés privées
- Export protégé par mot de passe
- Rotation et révocation
- Logs et audit
- Limitation et quotas
- Avis et disclaimers
- Conformité (FIPS, PCI-DSS, GDPR)
- Transmission sécurisée (HTTPS, HSTS, CSP)
"""

__version__ = "1.0.0"
__author__ = "Ghost Cyber Universe Team"
__license__ = "AGPL v3"
