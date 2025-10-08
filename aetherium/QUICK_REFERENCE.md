# Aetherium - Guide de Référence Rapide

**Version 2.0.0** | [Documentation Complète](./DOCUMENTATION_TECHNIQUE.md) | [README](./README.md)

---

## 🎯 Commandes CLI Essentielles

### Gestion des Keystores

```bash
# Générer un nouveau keystore
python main.py keys generate --out alice.keystore

# Afficher l'empreinte d'un keystore
python main.py keys fingerprint --keystore alice.keystore
```

### Chiffrement/Déchiffrement de Fichiers

```bash
# Chiffrer pour un seul destinataire
python main.py file encrypt \
    --in document.pdf \
    --out document.sealed \
    --sender-keystore bob.keystore \
    --to-keystore alice.keystore

# Chiffrer pour plusieurs destinataires
python main.py file encrypt \
    --in secret.txt \
    --out secret.sealed \
    --sender-keystore boss.keystore \
    --to-keystore alice.keystore \
    --to-keystore bob.keystore \
    --to-keystore charlie.keystore

# Déchiffrer
python main.py file decrypt \
    --in document.sealed \
    --out document.pdf \
    --recipient-keystore alice.keystore
```

### Démonstrations

```bash
# Toutes les démos
python main.py demo all

# Démos spécifiques
python main.py demo aes    # AES-256-GCM
python main.py demo kem    # KEM Aetherium
python main.py demo pki    # PKI X.509
```

### Tests de Sécurité

```bash
# Tous les tests
python main.py test all

# Tests spécifiques
python main.py test quantum       # Résistance quantique
python main.py test side-channel  # Canaux auxiliaires
python main.py test blockchain    # Blockchain
python main.py test ai            # IA anomalies
```

---

## 💻 API Python - Exemples Courts

### 1. AES-256-GCM Simple

```python
from main import AESEnhancedGCM

aes = AESEnhancedGCM()
ct, salt, iv, tag = aes.encrypt("Message", "password")
pt = aes.decrypt(ct, "password", salt, iv, tag)
```

### 2. KEM Aetherium - Base

```python
from AetheriumCrypt import AetheriumPrivateKey, AetheriumCipher

# Générer clés
alice = AetheriumCipher(AetheriumPrivateKey())
bob = AetheriumCipher(AetheriumPrivateKey())

# Chiffrer/Déchiffrer
sealed = bob.seal(b"Message", alice.pk)
plain = alice.open(sealed, bob.pk)
```

### 3. Keystore - Sauvegarde/Chargement

```python
from main import AetheriumUltraKeyPair, AetheriumKeystore

# Sauvegarder
kp = AetheriumUltraKeyPair.generate()
AetheriumKeystore.save("alice.keystore", kp, "password")

# Charger
kp_loaded = AetheriumKeystore.load("alice.keystore", "password")

# Empreinte
fp = AetheriumKeystore.fingerprint(kp_loaded)
```

### 4. GKEP Protocol

```python
from main import GKEPProtocol, GKEPConfig

protocol = GKEPProtocol(GKEPConfig(enable_quantum_kem=True))
protocol.initialize()
handshake = protocol.start_handshake(peer_key)
protocol.establish_session(response)

enc = protocol.encrypt_message(b"Secret")
dec = protocol.decrypt_message(enc)
```

### 5. PKI X.509

```python
from main import AetheriumPKI

pki = AetheriumPKI()
pki.initialize_ca()
cert_pem, key_pem = pki.generate_certificate("client-001")
```

### 6. PQC Backend

```python
from pqc_backend import PQC

# KEM
if PQC.has_kem():
    pk, sk = PQC.kem_generate_keypair()
    ct, ss = PQC.kem_encapsulate(pk)
    ss_dec = PQC.kem_decapsulate(sk, ct)

# Signatures
pk, sk, alg = PQC.sig_generate_keypair()
sig = PQC.sig_sign(msg, sk, alg)
valid = PQC.sig_verify(msg, sig, pk, alg)
```

### 7. Dérivation de Clés

```python
from kdf_utils import derive_key, generate_salt

salt = generate_salt(32)
key, alg = derive_key("password", salt, length=32)
# alg = "argon2id" ou "scrypt"
```

### 8. Chiffrement de Bytes

```python
from secure_store import encrypt_bytes, decrypt_bytes

key = os.urandom(32)
ct_hex, salt_hex, iv_hex, tag_hex = encrypt_bytes(key, data)
data_dec = decrypt_bytes(key, ct_hex, salt_hex, iv_hex, tag_hex)
```

### 9. Audit Log

```python
from audit import append_entry

entry_hash = append_entry(
    operation="file.encrypt",
    actor_fp="fingerprint_alice",
    object_hash="sha3_of_object",
    recipients=["fingerprint_bob"]
)
```

---

## 🔑 Structure des Clés - Aide-Mémoire

### Clé Privée (SK)

```
D1: 14 blocs
├── 6 pureté (320 bits chacun)
├── 4 unicité (192 bits chacun)
└── 4 authentification (192 bits chacun)

D2: 7 lois dynamiques
├── 3 S-boxes (256 bits chacune)
├── 1 réaction chimique (256 bits)
└── 3 paramètres radio α,β,γ (128 bits chacun)

D3: 11 sceaux
└── 11 blocs (96 bits chacun)

Pipeline:
D1 → S-boxes → Réaction → Sceaux → SK_raw → SHAKE256 → SK_derived (4096 bits)
```

### Clé Publique (PK)

```
PK (158 bits) = [64 pureté] ∥ [64 Merkle] ∥ [30 checksum]

Dérivation:
h1 = blake2b(D1_pure[0], 8)
h2 = blake2b(D1_pure[1], 8)
merkle = merkle_root(Sboxes + reaction)
checksum = blake2b(h1 + h2 + merkle, 4)
pk158 = compress_gray(h1 + h2 + merkle[:8] + checksum)
```

---

## 📊 Tailles et Paramètres Clés

| Élément | Taille | Notes |
|---------|--------|-------|
| **Clé publique** | 158 bits | Compressée |
| **Clé privée brute** | Variable | ~2-3 KB |
| **Clé privée dérivée** | 4096 bits | SHAKE256 |
| **Seed ε** | 256 bits | Aléa KEM |
| **Clé de session** | 256 bits | K_s ⊕ OTP |
| **Artefact KEM** | ~3 KB | TLV complet |
| **Salt** | 256 bits | KDF |
| **IV (AES-GCM)** | 96 bits | Nonce |
| **Tag GCM (T1)** | 128 bits | MAC interne |
| **HMAC-SHA3 (T2)** | 512 bits | MAC externe |
| **Signature Dilithium3** | ~2.7 KB | PQC |
| **Preuve zk-SNARK** | 256 bits | Simplifié |
| **Ciphertext Kyber1024** | 1568 bytes | PQC KEM |

---

## 🛠️ Configuration Rapide

### Variables d'Environnement

```bash
export AETHERIUM_LOG_LEVEL=INFO
export AETHERIUM_AUDIT_PATH=./logs/audit.jsonl
export AETHERIUM_KEYSTORE_PATH=./keystores/
export AETHERIUM_ROTATION_INTERVAL=1800
export AETHERIUM_ENABLE_PQC=true
export AETHERIUM_ENABLE_FRAGMENTATION=false
```

### Configuration GKEP

```python
config = GKEPConfig(
    key_size=2048,              # RSA key size
    session_timeout=3600,       # 1 heure
    rotation_interval=1800,     # 30 minutes
    enable_quantum_kem=True     # Activer PQC
)
```

### Paramètres KDF

```python
# Argon2id (préféré)
time_cost=3
memory_cost=64*1024  # 64 MB
parallelism=1

# PBKDF2-SHA3-512 (AES Enhanced)
iterations=666_000
```

---

## 🔐 Algorithmes Utilisés

### Chiffrement Symétrique

- **AES-256-GCM** : Chiffrement authentifié
- **HMAC-SHA3-512** : MAC externe

### Chiffrement Asymétrique

- **Kyber1024** : KEM post-quantique (NIST)
- **ECDH-P256** : Fallback classique

### Signatures

- **Dilithium3** : Signature PQC (NIST)
- **ECDSA-P256** : Fallback classique
- **Ed25519** : Fallback léger

### Hachage et KDF

- **BLAKE2b** : Hachage rapide
- **SHA3-256/512** : NIST standard
- **SHAKE256** : XOF (extension variable)
- **Argon2id** : KDF résistant aux GPU
- **PBKDF2-SHA3-512** : KDF classique

### Preuves Cryptographiques

- **zk-SNARK (Groth16)** : Preuve à divulgation nulle
- **Merkle Trees** : Agrégation de hash

---

## 📝 Formats de Fichiers

### Keystore (v2)

```json
{
  "version": "aek-v2",
  "kdf_alg": "argon2id",
  "kdf_salt": "hex...",
  "ciphertext": "hex...",
  "iv": "hex...",
  "tag": "hex...",
  "created": 1699123456.789
}
```

**Contenu chiffré :**
```json
{
  "sk_raw": "hex...",
  "sk_dig": "hex...",
  "pk": "0x...",
  "auth_chunks": ["0x...", ...],
  "sboxes": ["0x...", ...],
  "reaction": "0x...",
  "radios": ["0x...", ...],
  "seals": ["0x...", ...],
  "kem_pk": "hex...",
  "kem_sk": "hex...",
  "sig_pk": "hex...",
  "sig_sk": "hex...",
  "sig_alg": "oqs:Dilithium3"
}
```

### Enveloppe Multi-Destinataires

```json
{
  "version": "gcu-envelope-v1",
  "meta": {
    "created": 1699123456.789,
    "sender_pk": "0x...",
    "sender_fp": "abc123...",
    "hash_algo": "sha3-256"
  },
  "recipients": [
    {
      "type": "oqs-kem",
      "kem_alg": "Kyber768",
      "ct": "hex...",
      "wrapped_kf": {
        "ct": "hex...",
        "salt": "hex...",
        "iv": "hex...",
        "tag": "hex..."
      },
      "fingerprint": "def456..."
    },
    {
      "type": "ultra-kem",
      "artefact": {...},
      "wrapped_kf": {...},
      "fingerprint": "ghi789..."
    }
  ],
  "cipher": {
    "alg": "AES-256-GCM",
    "ct": "hex...",
    "salt": "hex...",
    "iv": "hex...",
    "tag": "hex..."
  },
  "signature": {
    "sig_alg": "oqs:Dilithium3",
    "sig_pk": "hex...",
    "value": "hex..."
  }
}
```

### Journal d'Audit

```json
{
  "ts": 1699123456.789,
  "op": "file.encrypt",
  "actor": "fingerprint_alice",
  "object": "sha3_256_of_object",
  "recipients": ["fingerprint_bob", "fingerprint_charlie"],
  "prev": "hash_of_previous_entry",
  "entry_hash": "sha3_256_of_this_entry"
}
```

---

## 🚨 Codes d'Erreur Communs

| Code | Erreur | Solution |
|------|--------|----------|
| **ValueError: Artefact checksum mismatch** | Artefact corrompu | Retransmettre l'artefact |
| **ValueError: Signature verification failed** | Signature invalide | Vérifier les clés publiques |
| **ValueError: zk-SNARK proof invalid** | Preuve invalide | Regénérer l'encapsulation |
| **ValueError: Outer MAC verification failed** | MAC T2 invalide | Vérifier la clé de session |
| **ValueError: Sealed message too small** | Message tronqué | Vérifier la transmission |
| **RuntimeError: OQS not available** | Librairie PQC manquante | Installer liboqs + pip install oqs |
| **FileNotFoundError: keystore** | Keystore introuvable | Vérifier le chemin |
| **InvalidToken: decryption** | Mot de passe incorrect | Vérifier le mot de passe |

---

## 🧪 Tests et Validation

### Test de Base

```python
# main.py ou AetheriumCrypt.py
if __name__ == "__main__":
    # Auto-test intégré
    pass
```

### Test CLI

```bash
# Test complet
python main.py test all

# Test spécifique
python main.py test quantum
```

### Vérification Manuelle

```python
import os
from AetheriumCrypt import AetheriumCipher, AetheriumPrivateKey

alice = AetheriumCipher(AetheriumPrivateKey())
bob = AetheriumCipher(AetheriumPrivateKey())

msg = os.urandom(1024)  # 1 KB aléatoire
sealed = bob.seal(msg, alice.pk)
dec = alice.open(sealed, bob.pk)

assert dec == msg, "Échec du test !"
print("✅ Test réussi")
```

---

## 📦 Installation Minimale

```bash
# Dépendances core uniquement
pip install cryptography>=41.0.0

# Dépendances complètes
pip install -r requirements.txt

# PQC optionnel
sudo apt-get install liboqs-dev  # ou brew install liboqs
pip install oqs

# Tests
pip install pytest pytest-cov pytest-benchmark
```

---

## 🔗 Liens Utiles

- **Documentation Complète** : [DOCUMENTATION_TECHNIQUE.md](./DOCUMENTATION_TECHNIQUE.md)
- **README Principal** : [README.md](./README.md)
- **NIST PQC** : https://csrc.nist.gov/projects/post-quantum-cryptography
- **Open Quantum Safe** : https://openquantumsafe.org/
- **CRYSTALS-Kyber** : https://pq-crystals.org/kyber/
- **CRYSTALS-Dilithium** : https://pq-crystals.org/dilithium/

---

## 📞 Support Rapide

**En cas de problème :**

1. Vérifier les logs : `cat logs/audit.jsonl`
2. Tester avec les démos : `python main.py demo all`
3. Consulter la FAQ : [DOCUMENTATION_TECHNIQUE.md § 10.4](./DOCUMENTATION_TECHNIQUE.md#104-faq)
4. Ouvrir une issue : GitHub Issues

---

**Version :** 2.0.0 | **Dernière mise à jour :** Octobre 2024

---

*Pour démarrer rapidement : `python main.py demo all`*

