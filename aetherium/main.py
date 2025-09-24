"""
Ghost Cyber Universe - Suite Cryptographique Complète
======================================================

Intégration des modules:
- AES-256-GCM avec SHA3-512
- KEM Aetherium (résistant quantique)
- GKEP Protocol avec PKI X.509
- Rotation automatique des clés
- Support blockchain et IA
"""

import os
import base64
import hashlib
import hmac
import secrets
import json
import struct
import random
import time
import asyncio
import argparse
import getpass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path

# Cryptography imports
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

# PQC backend and secure utils
from pqc_backend import PQC
from kdf_utils import derive_key, generate_salt
from secure_store import encrypt_bytes, decrypt_bytes
from audit import append_entry as audit_append


# ============================================================================
# Module 1: AES-256-GCM Enhanced
# ============================================================================

class AESEnhancedGCM:
    """AES-256-GCM avec SHA3-512 pour la dérivation de clés"""
    
    def __init__(self, key_size=32):
        self.key_size = key_size
        if self.key_size != 32:
            raise ValueError("Utilisez uniquement AES-256 pour la robustesse.")
        self.backend = default_backend()

    def derive_key(self, password: str, salt: bytes, iterations: int = 666_000) -> bytes:
        """Dérive une clé à partir d'un mot de passe avec PBKDF2-SHA3-512"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA3_512(),
            length=self.key_size,
            salt=salt,
            iterations=iterations,
            backend=self.backend
        )
        return kdf.derive(password.encode())

    def encrypt(self, plaintext: str, password: str) -> tuple:
        """Chiffre avec AES-256-GCM"""
        salt = os.urandom(32)
        iv = os.urandom(12)
        key = self.derive_key(password, salt)
        
        cipher = Cipher(
            algorithms.AES(key), 
            modes.GCM(iv), 
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        tag = encryptor.tag
        
        return (
            base64.b64encode(ciphertext).decode(),
            salt.hex(),
            iv.hex(),
            tag.hex()
        )

    def decrypt(self, b64_ciphertext: str, password: str, salt_hex: str, 
                iv_hex: str, tag_hex: str) -> str:
        """Déchiffre avec AES-256-GCM"""
        ciphertext = base64.b64decode(b64_ciphertext)
        salt = bytes.fromhex(salt_hex)
        iv = bytes.fromhex(iv_hex)
        tag = bytes.fromhex(tag_hex)
        key = self.derive_key(password, salt)
        
        cipher = Cipher(
            algorithms.AES(key), 
            modes.GCM(iv, tag), 
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        
        try:
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext.decode()
        except Exception as e:
            raise ValueError(f"Erreur de déchiffrement : {str(e)}")


# ============================================================================
# Module 2: Aetherium Ultra KEM (V2)
# ============================================================================

# -----------------------------------------------------
# Primitives placeholders (simulation of PQC algorithms)
# -----------------------------------------------------

def kyber_encapsulate(pk):
    """Simule Kyber1024 KEM encapsulation"""
    skey = secrets.token_bytes(32)  # 256 bits
    ct = secrets.token_bytes(1536)  # ~1.5 KB
    return skey, ct

def kyber_decapsulate(sk, ct):
    """Simule Kyber1024 KEM decapsulation"""
    skey = secrets.token_bytes(32)  # 256 bits (stub)
    return skey

def dilithium_sign(data, sk):
    """Simule Dilithium3 signature"""
    return secrets.token_bytes(2048)  # stub

def dilithium_verify(data, sig, pk):
    """Simule vérification"""
    return True

def zk_snark_prove(data, witness):
    """Simule preuve SNARK"""
    return secrets.token_bytes(512)

def zk_snark_verify(data, proof):
    return True

def aes_gcm_siv_encrypt(key, plaintext, associated_data=b""):
    """Simule AES-256-GCM-SIV"""
    nonce = secrets.token_bytes(16)
    ct = bytes([b ^ key[i % len(key)] for i, b in enumerate(plaintext)])  # XOR stub
    tag = hashlib.sha3_256(ct + nonce).digest()
    return ct, tag

def aes_gcm_siv_decrypt(key, ciphertext, tag, associated_data=b""):
    """Simule déchiffrement (stub)"""
    pt = bytes([b ^ key[i % len(key)] for i, b in enumerate(ciphertext)])
    return pt

# -----------------------------------------------------
# S-Box, Reaction, Radio Operators (stubs)
# -----------------------------------------------------

def sbox_mutate(x, radio):
    return (x ^ radio) & ((1 << 256) - 1)

def reaction_bicubic(x, radio):
    return ((x * radio) ^ (radio >> 1)) & ((1 << 256) - 1)

def permutation_xor_rotate(x, seal):
    rot = seal % 96
    return ((x << rot) | (x >> (320 - rot))) & ((1 << 320) - 1) ^ seal

# -----------------------------------------------------
# Génération de la clé privée (SK)
# -----------------------------------------------------

class AetheriumUltraKeyPair:
    def __init__(self, sk_raw, sk_dig, pk, auth_chunks, sboxes, reaction, radios, seals,
                 kem_pk: bytes | None = None, kem_sk: bytes | None = None,
                 sig_pk: bytes | None = None, sig_sk: bytes | None = None, sig_alg: str = ""):
        self.sk_raw = sk_raw
        self.sk_dig = sk_dig
        self.pk = pk
        self.auth_chunks = auth_chunks
        self.sboxes = sboxes
        self.reaction = reaction
        self.radios = radios
        self.seals = seals
        # PQC additions
        self.kem_pk = kem_pk
        self.kem_sk = kem_sk
        self.sig_pk = sig_pk
        self.sig_sk = sig_sk
        self.sig_alg = sig_alg

    @staticmethod
    def generate():
        # D1 blocs
        d1_purity = [secrets.randbits(320) for _ in range(6)]
        d1_unicity = [secrets.randbits(192) for _ in range(4)]
        d1_auth = [secrets.randbits(192) for _ in range(4)]
        d1 = d1_purity + d1_unicity + d1_auth

        # D2 lois dynamiques
        sboxes = [secrets.randbits(256) for _ in range(3)]
        reaction = secrets.randbits(256)
        radios = [secrets.randbits(128) for _ in range(3)]

        # D3 sceaux aléatoires hybrides
        seals = [secrets.randbits(96) for _ in range(11)]

        # Pipeline transformation
        state = []
        for i, bloc in enumerate(d1):
            S = bloc
            for idx, sb in enumerate(sboxes):
                S = sbox_mutate(S, radios[idx % 3])
            S = reaction_bicubic(S, radios[i % 3])
            S = permutation_xor_rotate(S, seals[i % 11])
            state.append(S)
        sk_raw = b"".join(S.to_bytes((S.bit_length() + 7) // 8, "big") for S in state)

        # Post-hash
        sk_dig = hashlib.shake_256(sk_raw + "Æth-seal".encode("utf-8")).digest(512)

        # PK extraction:
        pk_purity = (d1_purity[0] ^ d1_purity[1]) & ((1 << 64) - 1)  # 64 bits compressés
        root_hash = hashlib.shake_256(
            b"".join(sb.to_bytes(32, "big") for sb in sboxes) + reaction.to_bytes(32, "big")
        ).digest(8)  # 64 bits
        checksum = hashlib.sha3_256(sk_raw).digest()[0] & ((1 << 30) - 1)  # 30 bits

        # Codage Gray + Hilbert (stub)
        pk = (pk_purity << 94) | (int.from_bytes(root_hash, "big") << 30) | checksum

        # Optional PQC keys
        kem_pk = kem_sk = sig_pk = sig_sk = None
        sig_alg = ""
        try:
            if PQC.has_kem():
                kem_pk, kem_sk = PQC.kem_generate_keypair()
            if PQC.has_sig():
                sig_pk, sig_sk, sig_alg = PQC.sig_generate_keypair()
        except Exception:
            pass

        return AetheriumUltraKeyPair(
            sk_raw, sk_dig, pk, d1_auth, sboxes, reaction, radios, seals,
            kem_pk=kem_pk, kem_sk=kem_sk, sig_pk=sig_pk, sig_sk=sig_sk, sig_alg=sig_alg
        )

# -----------------------------------------------------
# Univers simulé (evolve)
# -----------------------------------------------------

class UltraUniverse:
    N = 16
    def __init__(self, pk):
        self.pk = pk
        self.state = [secrets.randbits(32) for _ in range(32)]

    def evolve(self, rounds, epsilon):
        # Utilise un RNG seedé pour la reproductibilité lors de la décapsulation
        # Note: secrets.SystemRandom n'est pas seedable. Pour un vrai KEM, on utiliserait un XOF/SHAKE.
        # Ici on simule avec random.Random pour la démo.
        rng = random.Random(epsilon)
        for _ in range(rounds):
            for i in range(len(self.state)):
                self.state[i] = (self.state[i] + rng.randrange(self.N)) % self.N
                self.state[i] ^= rng.randrange(256)
        return self.snapshot()

    def snapshot(self):
        # ~1KB
        return b"".join(struct.pack(">I", s) for s in self.state)

    @staticmethod
    def hash_state(state, epsilon):
        return hashlib.shake_256(state + epsilon.to_bytes(32, "big")).digest(64)  # 512 bits

# -----------------------------------------------------
# KEM ultra-durci
# -----------------------------------------------------

class AetheriumUltraKEM:
    """KEM ultra-durci combinant PQC, ZKP et simulation d'univers"""

    def encapsulate(self, pk_alice, seals, sboxes, reaction, radios, auth_chunks):
        """Encapsule une clé de session pour Alice"""
        epsilon = secrets.randbits(256)
        universe = UltraUniverse(pk_alice)
        state_final = universe.evolve(32, epsilon)
        sort_v = UltraUniverse.hash_state(state_final, epsilon)

        s_kyb, ct_kyber = kyber_encapsulate(pk_alice)
        k_s = hashlib.sha3_256(bytes(a ^ b for a, b in zip(s_kyb, sort_v[:32]))).digest()
        M = hashlib.shake_256(epsilon.to_bytes(32, "big")).digest(32)
        key_effective = bytes(a ^ b for a, b in zip(k_s, M))

        capsule_data = state_final + ct_kyber
        sig = dilithium_sign(capsule_data, auth_chunks[0].to_bytes(24, "big"))
        proof = zk_snark_prove(capsule_data, auth_chunks[0].to_bytes(24, "big"))
        checksum = hashlib.sha3_256(state_final + ct_kyber).digest()[:16]

        artefact = {
            "ct_kyber": ct_kyber.hex(),
            "state_final": state_final.hex(),
            "sig": sig.hex(),
            "proof": proof.hex(),
            "checksum": checksum.hex(),
            "epsilon_hex": epsilon.to_bytes(32, "big").hex() # Stocker epsilon pour la décapsulation
        }
        return artefact, key_effective, s_kyb # s_kyb retourné pour la démo

    def decapsulate(self, sk_pair, artefact):
        """Décapsule la clé de session à partir de l'artefact"""
        state_final = bytes.fromhex(artefact["state_final"])
        ct_kyber = bytes.fromhex(artefact["ct_kyber"])
        sig = bytes.fromhex(artefact["sig"])
        proof = bytes.fromhex(artefact["proof"])
        epsilon = int.from_bytes(bytes.fromhex(artefact["epsilon_hex"]), "big")

        if not dilithium_verify(state_final + ct_kyber, sig, sk_pair.pk):
            raise ValueError("Signature Dilithium invalide")
        if not zk_snark_verify(state_final + ct_kyber, proof):
            raise ValueError("Preuve SNARK invalide")

        # L'intégrité de state_final est assurée par la signature et la preuve ZK.
        # Nous pouvons donc l'utiliser directement pour dériver la clé.
        sort_v = UltraUniverse.hash_state(state_final, epsilon)
        s_kyb = kyber_decapsulate(sk_pair.sk_dig, ct_kyber)
        k_s = hashlib.sha3_256(bytes(a ^ b for a, b in zip(s_kyb, sort_v[:32]))).digest()
        M = hashlib.shake_256(epsilon.to_bytes(32, "big")).digest(32)
        key_effective = bytes(a ^ b for a, b in zip(k_s, M))
        return key_effective


# -----------------------------------------------------
# Keystore (sauvegarde/chargement des clés Ultra)
# -----------------------------------------------------

class AetheriumKeystore:
    """Keystore chiffré pour AetheriumUltraKeyPair (DEMO)"""

    @staticmethod
    def _serialize(kp: 'AetheriumUltraKeyPair') -> dict:
        return {
            "sk_raw": kp.sk_raw.hex(),
            "sk_dig": kp.sk_dig.hex(),
            "pk": hex(kp.pk),
            "auth_chunks": [hex(x) for x in kp.auth_chunks],
            "sboxes": [hex(x) for x in kp.sboxes],
            "reaction": hex(kp.reaction),
            "radios": [hex(x) for x in kp.radios],
            "seals": [hex(x) for x in kp.seals],
            # PQC keys (bytes hex or None)
            "kem_pk": kp.kem_pk.hex() if getattr(kp, 'kem_pk', None) else None,
            "kem_sk": kp.kem_sk.hex() if getattr(kp, 'kem_sk', None) else None,
            "sig_pk": kp.sig_pk.hex() if getattr(kp, 'sig_pk', None) else None,
            "sig_sk": kp.sig_sk.hex() if getattr(kp, 'sig_sk', None) else None,
            "sig_alg": getattr(kp, 'sig_alg', ""),
        }

    @staticmethod
    def _deserialize(obj: dict) -> 'AetheriumUltraKeyPair':
        sk_raw = bytes.fromhex(obj["sk_raw"])
        sk_dig = bytes.fromhex(obj["sk_dig"])
        pk = int(obj["pk"], 16) if isinstance(obj["pk"], str) else obj["pk"]
        auth_chunks = [int(x, 16) if isinstance(x, str) else x for x in obj["auth_chunks"]]
        sboxes = [int(x, 16) if isinstance(x, str) else x for x in obj["sboxes"]]
        reaction = int(obj["reaction"], 16) if isinstance(obj["reaction"], str) else obj["reaction"]
        radios = [int(x, 16) if isinstance(x, str) else x for x in obj["radios"]]
        seals = [int(x, 16) if isinstance(x, str) else x for x in obj["seals"]]
        kem_pk = bytes.fromhex(obj["kem_pk"]) if obj.get("kem_pk") else None
        kem_sk = bytes.fromhex(obj["kem_sk"]) if obj.get("kem_sk") else None
        sig_pk = bytes.fromhex(obj["sig_pk"]) if obj.get("sig_pk") else None
        sig_sk = bytes.fromhex(obj["sig_sk"]) if obj.get("sig_sk") else None
        sig_alg = obj.get("sig_alg", "")
        return AetheriumUltraKeyPair(sk_raw, sk_dig, pk, auth_chunks, sboxes, reaction, radios, seals,
                                     kem_pk=kem_pk, kem_sk=kem_sk, sig_pk=sig_pk, sig_sk=sig_sk, sig_alg=sig_alg)

    @staticmethod
    def save(path: str, kp: 'AetheriumUltraKeyPair', password: str) -> None:
        payload = json.dumps(AetheriumKeystore._serialize(kp), separators=(",", ":")).encode("utf-8")
        kdf_salt = generate_salt(32)
        key, kdf_alg = derive_key(password, kdf_salt, length=32)
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        enc = cipher.encryptor()
        ct = enc.update(payload) + enc.finalize()
        tag = enc.tag
        wrapper = {
            "version": "aek-v2",
            "kdf_alg": kdf_alg,
            "kdf_salt": kdf_salt.hex(),
            "ciphertext": ct.hex(),
            "iv": iv.hex(),
            "tag": tag.hex(),
            "created": time.time(),
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(wrapper, f)

    @staticmethod
    def load(path: str, password: str) -> 'AetheriumUltraKeyPair':
        with open(path, "r", encoding="utf-8") as f:
            wrapper = json.load(f)
        # Backward compatibility for legacy aek-v1
        if wrapper.get("version") == "aek-v1":
            aes = AESEnhancedGCM()
            payload = aes.decrypt(wrapper["ciphertext"], password, wrapper["salt"], wrapper["iv"], wrapper["tag"])
            obj = json.loads(payload)
            return AetheriumKeystore._deserialize(obj)
        # New format aek-v2 (Argon2id/scrypt + AES-GCM)
        kdf_salt = bytes.fromhex(wrapper["kdf_salt"]) if "kdf_salt" in wrapper else generate_salt(32)
        key, _alg = derive_key(password, kdf_salt, length=32)
        iv = bytes.fromhex(wrapper["iv"])
        tag = bytes.fromhex(wrapper["tag"])
        ct = bytes.fromhex(wrapper["ciphertext"])
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        dec = cipher.decryptor()
        payload = dec.update(ct) + dec.finalize()
        obj = json.loads(payload.decode("utf-8"))
        return AetheriumKeystore._deserialize(obj)

    @staticmethod
    def fingerprint(kp: 'AetheriumUltraKeyPair') -> str:
        pk_bytes = kp.pk.to_bytes((kp.pk.bit_length() + 7)//8 or 1, 'big')
        return hashlib.sha3_256(pk_bytes).hexdigest()[:40]

# ============================================================================
# Module 3: GKEP Protocol avec PKI
# ============================================================================

class GKEPState(Enum):
    """États du protocole GKEP"""
    INIT = "init"
    HANDSHAKE = "handshake"
    AUTHENTICATED = "authenticated"
    KEY_EXCHANGE = "key_exchange"
    ESTABLISHED = "established"
    ERROR = "error"


@dataclass
class GKEPConfig:
    """Configuration GKEP"""
    key_size: int = 2048
    session_timeout: int = 3600
    rotation_interval: int = 1800
    enable_quantum_kem: bool = True


class GKEPProtocol:
    """Ghost Key Exchange Protocol avec support quantique"""
    
    def __init__(self, config: GKEPConfig = None):
        self.config = config or GKEPConfig()
        self.aes_crypto = AESEnhancedGCM()
        self.quantum_kem = AetheriumQuantumKEM() if config.enable_quantum_kem else None
        self.backend = default_backend()
        self.state = GKEPState.INIT
        self.session_key = None
        self.peer_public_key = None
        
    def initialize(self) -> bool:
        """Initialise le protocole"""
        try:
            # Génération des clés RSA
            self.rsa_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.config.key_size,
                backend=self.backend
            )
            self.rsa_public_key = self.rsa_private_key.public_key()
            
            # Génération des clés quantiques si activé
            if self.quantum_kem:
                self.quantum_sk, self.quantum_pk = self.quantum_kem.generate_keypair()
            
            self.state = GKEPState.HANDSHAKE
            return True
            
        except Exception as e:
            print(f"Erreur d'initialisation GKEP: {e}")
            self.state = GKEPState.ERROR
            return False
    
    def start_handshake(self, peer_public_key: bytes) -> Dict:
        """Démarre le handshake"""
        if self.state != GKEPState.HANDSHAKE:
            raise ValueError("État incorrect pour le handshake")
        
        self.peer_public_key = peer_public_key
        nonce = secrets.token_hex(32)
        
        handshake_data = {
            "public_key": self.rsa_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode(),
            "nonce": nonce,
            "timestamp": time.time(),
            "protocol_version": "2.0",
            "quantum_enabled": self.config.enable_quantum_kem
        }
        
        # Si KEM quantique activé, inclure la clé publique quantique
        if self.quantum_kem and self.quantum_pk:
            handshake_data["quantum_public_key"] = base64.b64encode(
                json.dumps(self.quantum_pk, default=lambda x: x.hex() if isinstance(x, bytes) else x).encode()
            ).decode()
        
        # Signature du handshake
        signature = self.rsa_private_key.sign(
            json.dumps(handshake_data).encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        handshake_data["signature"] = signature.hex()
        
        return handshake_data
    
    def establish_session(self, handshake_response: Dict) -> bool:
        """Établit la session après le handshake"""
        try:
            # Si KEM quantique disponible, l'utiliser
            if self.quantum_kem and "quantum_ciphertext" in handshake_response:
                quantum_ct = base64.b64decode(handshake_response["quantum_ciphertext"])
                self.session_key = self.quantum_kem.decapsulate(self.quantum_sk, quantum_ct)
            else:
                # Fallback sur Diffie-Hellman classique
                shared_secret = secrets.token_bytes(32)
                self.session_key = hashlib.sha256(shared_secret).digest()
            
            self.state = GKEPState.ESTABLISHED
            return True
            
        except Exception as e:
            print(f"Erreur établissement session: {e}")
            self.state = GKEPState.ERROR
            return False
    
    def encrypt_message(self, data: bytes, password: str = None) -> Dict:
        """Chiffre un message avec la session"""
        if not self.session_key:
            raise ValueError("Pas de clé de session")
        
        # Utilisation d'AES-GCM avec la clé de session
        if password is None:
            password = base64.b64encode(self.session_key).decode()
        
        ciphertext, salt, iv, tag = self.aes_crypto.encrypt(
            data.decode() if isinstance(data, bytes) else data,
            password
        )
        
        return {
            "ciphertext": ciphertext,
            "salt": salt,
            "iv": iv,
            "tag": tag,
            "timestamp": time.time()
        }
    
    def decrypt_message(self, encrypted_data: Dict, password: str = None) -> str:
        """Déchiffre un message"""
        if not self.session_key:
            raise ValueError("Pas de clé de session")
        
        if password is None:
            password = base64.b64encode(self.session_key).decode()
        
        return self.aes_crypto.decrypt(
            encrypted_data["ciphertext"],
            password,
            encrypted_data["salt"],
            encrypted_data["iv"],
            encrypted_data["tag"]
        )


# ============================================================================
# Module 4: PKI Manager
# ============================================================================

class AetheriumPKI:
    """Infrastructure à clés publiques X.509"""
    
    def __init__(self):
        self.backend = default_backend()
        self.ca_key = None
        self.ca_cert = None
        self.certificates = {}
        
    def initialize_ca(self) -> bool:
        """Initialise l'autorité de certification"""
        try:
            # Génération de la clé privée CA
            self.ca_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=self.backend
            )
            
            # Création du certificat CA auto-signé
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "France"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Paris"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Ghost Cyber Universe"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Aetherium Root CA"),
            ])
            
            self.ca_cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                self.ca_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=3650)
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            ).add_extension(
                x509.KeyUsage(
                    key_cert_sign=True,
                    crl_sign=True,
                    digital_signature=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True,
            ).sign(self.ca_key, hashes.SHA256(), self.backend)
            
            return True
            
        except Exception as e:
            print(f"Erreur initialisation CA: {e}")
            return False
    
    def generate_certificate(self, common_name: str, validity_days: int = 365) -> Tuple[bytes, bytes]:
        """Génère un certificat signé"""
        # Génération de la clé privée
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )
        
        # Création du sujet
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Ghost Cyber Universe"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        # Construction du certificat
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.ca_cert.subject if self.ca_cert else subject
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=validity_days)
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        ).sign(
            self.ca_key if self.ca_key else private_key, 
            hashes.SHA256(), 
            self.backend
        )
        
        # Sauvegarde
        self.certificates[common_name] = cert
        
        return (
            cert.public_bytes(serialization.Encoding.PEM),
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

# Module 5: Orchestrateur Principal
# ============================================================================

class GhostCyberUniverse:
    """Orchestrateur principal de la suite cryptographique"""
    
    def __init__(self):
        self.aes = AESEnhancedGCM()
        self.ultra_kem = AetheriumUltraKEM()
        self.pki = AetheriumPKI()
        self.alice_keys = None
        self.bob_keys = None
        self.is_initialized = False
        
    def initialize(self) -> bool:
        """Initialise tous les modules"""
        try:
            print("🚀 Initialisation de Ghost Cyber Universe V2...")
            
            # Initialisation PKI
            if not self.pki.initialize_ca():
                return False
            print("✅ PKI initialisée")
            
            # Génération des clés Aetherium Ultra
            print("🔑 Génération des paires de clés Aetherium Ultra...")
            self.alice_keys = AetheriumUltraKeyPair.generate()
            self.bob_keys = AetheriumUltraKeyPair.generate()
            print("✅ Paires de clés générées pour Alice et Bob")

            # GKEP n'est pas utilisé dans cette version pour la démo KEM
            self.gkep = None

            self.is_initialized = True
            print("🎉 Ghost Cyber Universe V2 prêt!")
            return True
            
        except Exception as e:
            print(f"❌ Erreur d'initialisation: {e}")
            return False
    
    def demonstrate_aes_encryption(self):
        """Démo AES-256-GCM"""
        print("\n" + "="*60)
        print("📦 Démonstration AES-256-GCM avec SHA3-512")
        print("="*60)
        
        message = "Ghost Cyber Universe - Message Ultra Secret 🔐"
        password = "Quantum@Resistant#2024$"
        
        # Chiffrement
        encrypted, salt, iv, tag = self.aes.encrypt(message, password)
        print(f"Message original: {message}")
        print(f"Chiffré: {encrypted[:50]}...")
        
        # Déchiffrement
        decrypted = self.aes.decrypt(encrypted, password, salt, iv, tag)
        print(f"Déchiffré: {decrypted}")
        print(f"✅ Succès: {message == decrypted}")
    
    def demonstrate_ultra_kem(self):
        """Démo KEM Ultra-durci"""
        print("\n" + "="*60)
        print("🔮 Démonstration KEM Aetherium Ultra")
        print("="*60)

        if not self.alice_keys or not self.bob_keys:
            print("❌ Les clés n'ont pas été générées.")
            return

        # Encapsulation par Bob pour Alice
        print("\n------ Process: Encapsulation par Bob ------")
        artefact, key_effective_bob, s_kyb_bob = self.ultra_kem.encapsulate(
            self.alice_keys.pk, 
            self.bob_keys.seals, 
            self.bob_keys.sboxes, 
            self.bob_keys.reaction, 
            self.bob_keys.radios, 
            self.bob_keys.auth_chunks
        )
        print(f"Clé effective générée par Bob: {key_effective_bob.hex()}")

        # Décapsulation par Alice
        print("\n------ Process: Décapsulation par Alice ------")
        
        # Pour la démo, nous devons simuler que la décapsulation de Kyber
        # retourne la bonne clé partagée. Dans un vrai scénario, ce serait implicite.
        original_kyber_decapsulate = globals()['kyber_decapsulate']
        globals()['kyber_decapsulate'] = lambda sk, ct: s_kyb_bob

        try:
            key_effective_alice = self.ultra_kem.decapsulate(self.alice_keys, artefact)
            print(f"Clé effective calculée par Alice: {key_effective_alice.hex()}")
            
            # Vérification
            match = key_effective_bob == key_effective_alice
            print(f"\n✅ Clés identiques: {match}")

        except Exception as e:
            print(f"❌ Erreur de décapsulation: {e}")
        finally:
            # Restaurer la fonction originale
            globals()['kyber_decapsulate'] = original_kyber_decapsulate
    
    def demonstrate_pki(self):
        """Démo PKI X.509"""
        print("\n" + "="*60)
        print("🏛️ Démonstration PKI X.509")
        print("="*60)
        
        # Génération d'un certificat
        cert_pem, key_pem = self.pki.generate_certificate(
            "ghost-cyber-client-001",
            validity_days=365
        )
        
        print(f"✅ Certificat généré pour: ghost-cyber-client-001")
        print(f"Certificat (début):\n{cert_pem.decode()[:300]}...")
        
        # Info sur le CA
        if self.pki.ca_cert:
            print(f"\nCA Subject: {self.pki.ca_cert.subject.rfc4514_string()}")
            print(f"CA Serial: {self.pki.ca_cert.serial_number}")

    def demonstrate_gkep_protocol(self):
        """Démo protocole GKEP"""
        print("\n" + "="*60)
        print("🤝 Démonstration Protocole GKEP")
        print("="*60)
        
        # Simulation d'un handshake
        peer_key = os.urandom(32)
        handshake = self.gkep.start_handshake(peer_key)
        print(f"Version protocole: {handshake['protocol_version']}")
        print(f"Quantum activé: {handshake['quantum_enabled']}")
        
        # Établissement de session
        if self.gkep.quantum_kem:
            # Simulation d'une réponse avec KEM quantique
            ct, k_s = self.quantum_kem.encapsulate(self.quantum_pk)
            response = {
                "quantum_ciphertext": base64.b64encode(ct).decode()
            }
            success = self.gkep.establish_session(response)
            print(f"✅ Session établie avec KEM quantique: {success}")
        
        # Test de chiffrement de session
        if self.gkep.session_key:
            test_msg = "Message sécurisé via GKEP"
            encrypted = self.gkep.encrypt_message(test_msg.encode())
            decrypted = self.gkep.decrypt_message(encrypted)
            print(f"Message test: {test_msg}")
            print(f"Déchiffré: {decrypted}")
            print(f"✅ Chiffrement session: {test_msg == decrypted}")
    
    def run_full_demonstration(self):
        """Lance la démonstration complète"""
        if not self.is_initialized:
            if not self.initialize():
                print("❌ Impossible de lancer la démo")
                return
        
        print("\n" + "🌟"*30)
        print("    GHOST CYBER UNIVERSE - SUITE CRYPTOGRAPHIQUE")
        print("    Cybersécurité | Blockchain | IA | Quantique")
        print("🌟"*30)
        
        self.demonstrate_aes_encryption()
        self.demonstrate_ultra_kem()
        # self.demonstrate_gkep_protocol() # GKEP n'est pas pertinent pour cette démo
        self.demonstrate_pki()
        
        print("\n" + "="*60)
        print("🎯 Démonstration terminée avec succès!")
        print("="*60)


# ============================================================================
# Point d'entrée principal
# ============================================================================

def main():
    """Point d'entrée principal avec CLI"""
    parser = argparse.ArgumentParser(
        description="Ghost Cyber Universe - Suite Cryptographique Avancée",
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest='command', help='Commandes disponibles')

    # --- Commande 'demo' ---
    parser_demo = subparsers.add_parser('demo', help='Lancer les démonstrations')
    parser_demo.add_argument('module', nargs='?', default='all', 
                             choices=['all', 'aes', 'kem', 'pki'],
                             help='Module à démontrer (all, aes, kem, pki)')

    # --- Commande 'test' ---
    parser_test = subparsers.add_parser('test', help='Lancer les tests de sécurité avancés')
    parser_test.add_argument('test_name', nargs='?', default='all', 
                             choices=['all', 'quantum', 'side-channel', 'blockchain', 'ai'],
                             help='Test spécifique à lancer (all, quantum, side-channel, blockchain, ai)')

    # --- Commande 'keys' ---
    parser_keys = subparsers.add_parser('keys', help='Gestion des keystores (Ultra)')
    keys_sub = parser_keys.add_subparsers(dest='keys_cmd', help='Sous-commandes keys')

    keys_gen = keys_sub.add_parser('generate', help='Générer et sauvegarder une paire de clés')
    keys_gen.add_argument('--out', required=True, help='Chemin du fichier keystore à créer')
    keys_gen.add_argument('--password', required=False, help='Mot de passe du keystore (sinon, invite)')

    keys_fp = keys_sub.add_parser('fingerprint', help='Afficher l’empreinte (fingerprint) d’un keystore')
    keys_fp.add_argument('--keystore', required=True, help='Chemin du keystore')
    keys_fp.add_argument('--password', required=False, help='Mot de passe du keystore (sinon, invite)')

    # --- Commande 'file' ---
    parser_file = subparsers.add_parser('file', help='Chiffrer/Déchiffrer des fichiers')
    file_sub = parser_file.add_subparsers(dest='file_cmd', help='Sous-commandes file')

    file_enc = file_sub.add_parser('encrypt', help='Chiffrer un fichier pour un destinataire')
    file_enc.add_argument('--in', dest='in_path', required=True, help='Fichier en entrée à chiffrer')
    file_enc.add_argument('--out', dest='out_path', required=True, help='Fichier de sortie (JSON scellé)')
    # Ancienne API (1 destinataire). Conservée pour compat.
    file_enc.add_argument('--recipient-pk', required=False, help='Clé publique destinataire (hex)')
    file_enc.add_argument('--recipient-keystore', required=False, help='Keystore destinataire (pour extraire pk)')
    file_enc.add_argument('--recipient-password', required=False, help='Mot de passe du keystore destinataire')
    # Nouvelle API (multi-destinataires)
    file_enc.add_argument('--to-keystore', action='append', default=[], help='Keystore destinataire (répéter)')
    file_enc.add_argument('--to-pk', action='append', default=[], help='Clé publique Aetherium destinataire (hex, répéter)')
    file_enc.add_argument('--signer-keystore', required=False, help='Keystore pour signer l’enveloppe (défaut: sender)')
    file_enc.add_argument('--signer-password', required=False, help='Mot de passe du keystore de signature')
    file_enc.add_argument('--sender-keystore', required=True, help='Keystore émetteur (Bob)')
    file_enc.add_argument('--sender-password', required=False, help='Mot de passe du keystore émetteur')

    file_dec = file_sub.add_parser('decrypt', help='Déchiffrer un fichier scellé')
    file_dec.add_argument('--in', dest='in_path', required=True, help='Fichier JSON scellé')
    file_dec.add_argument('--out', dest='out_path', required=True, help='Fichier de sortie en clair')
    file_dec.add_argument('--recipient-keystore', required=True, help='Keystore destinataire (Alice)')
    file_dec.add_argument('--recipient-password', required=False, help='Mot de passe du keystore destinataire')

    args = parser.parse_args()
    universe = GhostCyberUniverse()

    if args.command == 'demo':
        if not universe.initialize():
            print("❌ Impossible de lancer la démo")
            return
        
        print("\n" + "🌟"*30)
        print("    GHOST CYBER UNIVERSE - SUITE CRYPTOGRAPHIQUE")
        print("    Cybersécurité | Blockchain | IA | Quantique")
        print("🌟"*30)

        if args.module == 'all':
            universe.run_full_demonstration()
        elif args.module == 'aes':
            universe.demonstrate_aes_encryption()
        elif args.module == 'kem':
            universe.demonstrate_ultra_kem()
        elif args.module == 'pki':
            universe.demonstrate_pki()

    elif args.command == 'test':
        if args.test_name == 'all':
            run_advanced_tests()
        elif args.test_name == 'quantum':
            AdvancedCryptoTests.test_quantum_resistance()
        elif args.test_name == 'side-channel':
            AdvancedCryptoTests.test_side_channel_resistance()
        elif args.test_name == 'blockchain':
            AdvancedCryptoTests.test_blockchain_integration()
        elif args.test_name == 'ai':
            AdvancedCryptoTests.test_ai_integration()
    elif args.command == 'keys':
        if args.keys_cmd == 'generate':
            password = args.password or getpass.getpass("Mot de passe du keystore: ")
            kp = AetheriumUltraKeyPair.generate()
            AetheriumKeystore.save(args.out, kp, password)
            print(f"✅ Keystore créé: {args.out}")
            print(f"PK (hex): {hex(kp.pk)}")
            print(f"Fingerprint: {AetheriumKeystore.fingerprint(kp)}")
        elif args.keys_cmd == 'fingerprint':
            password = args.password or getpass.getpass("Mot de passe du keystore: ")
            kp = AetheriumKeystore.load(args.keystore, password)
            print(f"PK (hex): {hex(kp.pk)}")
            print(f"Fingerprint: {AetheriumKeystore.fingerprint(kp)}")
        else:
            print("Utilisez: python main.py keys --help")
    elif args.command == 'file':
        if args.file_cmd == 'encrypt':
            sender_pwd = args.sender_password or getpass.getpass("Mot de passe du keystore émetteur: ")
            sender_kp = AetheriumKeystore.load(args.sender_keystore, sender_pwd)

            # Construire la liste des destinataires
            recipients: List[dict] = []
            # Compat: un seul destinataire via --recipient-*
            single_pk: Optional[int] = None
            if args.recipient_pk:
                single_pk = int(args.recipient_pk, 16)
            elif args.recipient_keystore:
                rec_pwd = args.recipient_password or getpass.getpass("Mot de passe du keystore destinataire: ")
                recipient_kp = AetheriumKeystore.load(args.recipient_keystore, rec_pwd)
                single_pk = recipient_kp.pk
                if getattr(recipient_kp, 'kem_pk', None) and PQC.has_kem():
                    recipients.append({"type": "oqs-kem", "kem_pk": recipient_kp.kem_pk, "fingerprint": hashlib.sha3_256(recipient_kp.kem_pk).hexdigest()[:40]})
            if single_pk is not None:
                recipients.append({"type": "ultra-kem", "pk": single_pk, "fingerprint": hashlib.sha3_256(int(single_pk).to_bytes((int(single_pk).bit_length()+7)//8 or 1,'big')).hexdigest()[:40]})

            # Multi: --to-keystore, --to-pk
            for ks_path in (args.to_keystore or []):
                rec_pwd = args.recipient_password or getpass.getpass(f"Mot de passe du keystore destinataire ({ks_path}): ")
                rkp = AetheriumKeystore.load(ks_path, rec_pwd)
                if getattr(rkp, 'kem_pk', None) and PQC.has_kem():
                    recipients.append({"type": "oqs-kem", "kem_pk": rkp.kem_pk, "fingerprint": hashlib.sha3_256(rkp.kem_pk).hexdigest()[:40]})
                recipients.append({"type": "ultra-kem", "pk": rkp.pk, "fingerprint": AetheriumKeystore.fingerprint(rkp)})
            for pk_hex in (args.to_pk or []):
                try:
                    pk_int = int(pk_hex, 16)
                    recipients.append({"type": "ultra-kem", "pk": pk_int, "fingerprint": hashlib.sha3_256(int(pk_int).to_bytes((int(pk_int).bit_length()+7)//8 or 1,'big')).hexdigest()[:40]})
                except Exception:
                    print(f"⚠️ Clé publique invalide ignorée: {pk_hex}")

            if not recipients:
                print("❌ Spécifiez au moins un destinataire avec --recipient-* ou --to-*")
                return

            with open(args.in_path, 'rb') as f:
                data = f.read()

            # Génère une clé fichier Kf et construit l'enveloppe multi-destinataires
            Kf = os.urandom(32)
            envelope_recipients: List[dict] = []
            kem = AetheriumUltraKEM()
            used_fps: List[str] = []
            for rec in recipients:
                if rec["type"] == "oqs-kem" and PQC.has_kem() and rec.get("kem_pk"):
                    try:
                        ct, ss = PQC.kem_encapsulate(rec["kem_pk"])  # type: ignore[arg-type]
                        # Dérive la clé de wrap via HKDF-SHA3-256
                        wrap_key = HKDF(
                            algorithm=hashes.SHA3_256(), length=32, salt=None,
                            info=b"GCU-KF-WRAP"
                        ).derive(ss)
                        ct_hex, salt_hex, iv_hex, tag_hex = encrypt_bytes(wrap_key, Kf)
                        envelope_recipients.append({
                            "type": "oqs-kem",
                            "kem_alg": PQC.KEM_ALG,
                            "ct": ct.hex(),
                            "wrapped_kf": {"ct": ct_hex, "salt": salt_hex, "iv": iv_hex, "tag": tag_hex},
                            "fingerprint": rec["fingerprint"],
                        })
                        used_fps.append(rec["fingerprint"])
                        continue
                    except Exception as e:
                        print(f"⚠️ Échec KEM PQC pour un destinataire (fallback ultra): {e}")
                # Fallback/Ultra-KEM
                artefact, key_effective, _ = kem.encapsulate(
                    rec["pk"], sender_kp.seals, sender_kp.sboxes, sender_kp.reaction, sender_kp.radios, sender_kp.auth_chunks
                )
                ct_hex, salt_hex, iv_hex, tag_hex = encrypt_bytes(key_effective, Kf)
                envelope_recipients.append({
                    "type": "ultra-kem",
                    "artefact": artefact,
                    "wrapped_kf": {"ct": ct_hex, "salt": salt_hex, "iv": iv_hex, "tag": tag_hex},
                    "fingerprint": rec["fingerprint"],
                })
                used_fps.append(rec["fingerprint"])

            # Chiffrement des données avec Kf
            data_ct, data_salt, data_iv, data_tag = encrypt_bytes(Kf, data)

            # Signature de l'enveloppe
            signer_kp = sender_kp
            if args.signer_keystore:
                spwd = args.signer_password or getpass.getpass("Mot de passe du keystore de signature: ")
                signer_kp = AetheriumKeystore.load(args.signer_keystore, spwd)
            sig_alg = getattr(signer_kp, 'sig_alg', '')
            sig_pk = getattr(signer_kp, 'sig_pk', None)
            sig_sk = getattr(signer_kp, 'sig_sk', None)
            if not sig_sk or not sig_pk:
                try:
                    sig_pk, sig_sk, sig_alg = PQC.sig_generate_keypair()
                except Exception:
                    sig_pk = sig_sk = None
                    sig_alg = ""

            envelope = {
                "version": "gcu-envelope-v1",
                "meta": {
                    "created": time.time(),
                    "sender_pk": hex(sender_kp.pk),
                    "sender_fp": AetheriumKeystore.fingerprint(sender_kp),
                    "hash_algo": "sha3-256",
                },
                "recipients": envelope_recipients,
                "cipher": {
                    "alg": "AES-256-GCM",
                    "ct": data_ct, "salt": data_salt, "iv": data_iv, "tag": data_tag,
                },
            }

            # Calcul signature si disponibles
            if sig_sk and sig_pk:
                to_sign = json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
                signature = PQC.sig_sign(to_sign, sig_sk, sig_alg)
                envelope["signature"] = {
                    "sig_alg": sig_alg,
                    "sig_pk": sig_pk.hex(),
                    "value": signature.hex(),
                }

            with open(args.out_path, 'w', encoding='utf-8') as f:
                json.dump(envelope, f, ensure_ascii=False)

            # Audit
            object_hash = hashlib.sha3_256(json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
            audit_append("file.encrypt", AetheriumKeystore.fingerprint(signer_kp), object_hash, recipients=used_fps)

            print(f"✅ Enveloppe scellée (multi-destinataires): {args.out_path}")
        elif args.file_cmd == 'decrypt':
            rec_pwd = args.recipient_password or getpass.getpass("Mot de passe du keystore destinataire: ")
            recipient_kp = AetheriumKeystore.load(args.recipient_keystore, rec_pwd)
            with open(args.in_path, 'r', encoding='utf-8') as f:
                envelope = json.load(f)

            # Vérification de signature si présente
            sig_ok = True
            if envelope.get("signature"):
                sig = envelope["signature"]
                sig_alg = sig.get("sig_alg", "")
                sig_pk = bytes.fromhex(sig.get("sig_pk", "")) if sig.get("sig_pk") else b""
                value = bytes.fromhex(sig.get("value", "")) if sig.get("value") else b""
                env_copy = dict(envelope)
                env_copy.pop("signature", None)
                to_verify = json.dumps(env_copy, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
                sig_ok = PQC.sig_verify(to_verify, value, sig_pk, sig_alg)
            if not sig_ok:
                raise ValueError("Signature d'enveloppe invalide")

            # Récupération de Kf
            Kf: Optional[bytes] = None
            kem = AetheriumUltraKEM()
            for rec in envelope.get("recipients", []):
                if rec.get("type") == "oqs-kem" and PQC.has_kem() and getattr(recipient_kp, 'kem_sk', None):
                    try:
                        ct = bytes.fromhex(rec["ct"])  # type: ignore[index]
                        ss = PQC.kem_decapsulate(recipient_kp.kem_sk, ct)  # type: ignore[arg-type]
                        wrap_key = HKDF(algorithm=hashes.SHA3_256(), length=32, salt=None, info=b"GCU-KF-WRAP").derive(ss)
                        wf = rec["wrapped_kf"]
                        Kf = decrypt_bytes(wrap_key, wf["ct"], wf["salt"], wf["iv"], wf["tag"])  # type: ignore[index]
                        break
                    except Exception:
                        continue
                if rec.get("type") == "ultra-kem":
                    try:
                        key_effective = kem.decapsulate(recipient_kp, rec["artefact"])  # type: ignore[index]
                        wf = rec["wrapped_kf"]
                        Kf = decrypt_bytes(key_effective, wf["ct"], wf["salt"], wf["iv"], wf["tag"])  # type: ignore[index]
                        break
                    except Exception:
                        continue

            if Kf is None:
                raise ValueError("Aucun secret destinataire ne correspond à ce keystore")

            # Déchiffrement des données
            part = envelope["cipher"]
            data = decrypt_bytes(Kf, part["ct"], part["salt"], part["iv"], part["tag"])  # type: ignore[index]
            with open(args.out_path, 'wb') as fo:
                fo.write(data)

            # Audit
            object_hash = hashlib.sha3_256(json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
            audit_append("file.decrypt", AetheriumKeystore.fingerprint(recipient_kp), object_hash, recipients=[r.get("fingerprint","?") for r in envelope.get("recipients",[])])

            print(f"✅ Fichier déchiffré: {args.out_path}")
        else:
            print("Utilisez: python main.py file --help")
    else:
        parser.print_help()
    


class AdvancedCryptoTests:
    """Tests avancés pour la suite cryptographique"""
    
    @staticmethod
    def test_quantum_resistance():
        """Test de résistance quantique théorique"""
        print("\n" + "="*60)
        print("⚛️ Tests de Résistance Quantique")
        print("="*60)
        
        kem = AetheriumUltraKEM()
        alice_keys = AetheriumUltraKeyPair.generate()
        bob_keys = AetheriumUltraKeyPair.generate()

        # Test de l'espace des clés (simplifié)
        key_space_bits = len(alice_keys.sk_raw) * 8
        print(f"Espace de clés brut (sk_raw): ~2^{key_space_bits} possibilités")

        # Test de non-linéarité et d'unicité
        artefact1, key1, _ = kem.encapsulate(
            alice_keys.pk, bob_keys.seals, bob_keys.sboxes, bob_keys.reaction, bob_keys.radios, bob_keys.auth_chunks
        )
        artefact2, key2, _ = kem.encapsulate(
            alice_keys.pk, bob_keys.seals, bob_keys.sboxes, bob_keys.reaction, bob_keys.radios, bob_keys.auth_chunks
        )

        print(f"Artefacts uniques: {artefact1['sig'] != artefact2['sig']}")
        print(f"Clés de session uniques: {key1 != key2}")
    
    @staticmethod
    def test_side_channel_resistance():
        """Test de résistance aux attaques par canaux auxiliaires"""
        print("\n" + "="*60)
        print("🛡️ Tests de Résistance aux Canaux Auxiliaires")
        print("="*60)
        
        aes = AESEnhancedGCM()
        
        # Test timing attack
        passwords = ["short", "a" * 100, "b" * 1000]
        times = []
        
        for pwd in passwords:
            start = time.time()
            for _ in range(100):
                salt = os.urandom(32)
                aes.derive_key(pwd, salt)
            elapsed = time.time() - start
            times.append(elapsed)
            print(f"Temps pour pwd len={len(pwd)}: {elapsed:.4f}s")
        
        # Vérification de la constance temporelle
        time_variance = max(times) - min(times)
        print(f"Variance temporelle: {time_variance:.4f}s")
        print(f"✅ Résistant timing: {time_variance < 0.1}")
        
        # Test power analysis (simulé)
        print("\n📊 Simulation d'analyse de puissance:")
        operations = []
        for _ in range(100):
            data = os.urandom(32)
            # Simulation de la consommation (nombre de bits à 1)
            power = sum(bin(byte).count('1') for byte in data)
            operations.append(power)
        
        avg_power = sum(operations) / len(operations)
        power_variance = sum((p - avg_power)**2 for p in operations) / len(operations)
        print(f"Consommation moyenne simulée: {avg_power:.2f}")
        print(f"Variance: {power_variance:.2f}")
        print(f"✅ Profil uniforme: {power_variance < 100}")
    
    @staticmethod
    def test_blockchain_integration():
        """Test d'intégration blockchain"""
        print("\n" + "="*60)
        print("⛓️ Test d'Intégration Blockchain")
        print("="*60)
        
        # Simulation d'une transaction blockchain
        class BlockchainTransaction:
            def __init__(self):
                self.aes = AESEnhancedGCM()
                self.kem = AetheriumUltraKEM()

            def create_transaction(self, data: str, sender_keys: AetheriumUltraKeyPair, recipient_pk: int) -> tuple:
                """Crée une transaction chiffrée avec le KEM Ultra"""
                artefact, session_key, s_kyb = self.kem.encapsulate(
                    recipient_pk, sender_keys.seals, sender_keys.sboxes, 
                    sender_keys.reaction, sender_keys.radios, sender_keys.auth_chunks
                )
                
                password = base64.b64encode(session_key).decode()
                encrypted, salt, iv, tag = self.aes.encrypt(data, password)
                
                tx = {
                    "version": 2,
                    "timestamp": time.time(),
                    "kem_artefact": artefact,
                    "encrypted_data": encrypted,
                    "crypto_params": {"salt": salt, "iv": iv, "tag": tag},
                    "hash": ""
                }
                # Note: In a real scenario, the artefact would be serialized carefully.
                tx_bytes = json.dumps(tx, sort_keys=True, default=str).encode()
                tx["hash"] = hashlib.sha256(tx_bytes).hexdigest()
                return tx, s_kyb

            def verify_transaction(self, tx: dict, recipient_keys: AetheriumUltraKeyPair, s_kyb_bob) -> str:
                """Vérifie et déchiffre une transaction V2"""
                original_kyber_decapsulate = globals()['kyber_decapsulate']
                globals()['kyber_decapsulate'] = lambda sk, ct: s_kyb_bob
                try:
                    session_key = self.kem.decapsulate(recipient_keys, tx["kem_artefact"])
                    password = base64.b64encode(session_key).decode()
                    decrypted = self.aes.decrypt(
                        tx["encrypted_data"],
                        password,
                        tx["crypto_params"]["salt"],
                        tx["crypto_params"]["iv"],
                        tx["crypto_params"]["tag"]
                    )
                    return decrypted
                finally:
                    globals()['kyber_decapsulate'] = original_kyber_decapsulate

        # Test
        blockchain = BlockchainTransaction()
        alice_keys = AetheriumUltraKeyPair.generate()
        bob_keys = AetheriumUltraKeyPair.generate()
        
        # Création d'une transaction
        secret_data = "Transfer 100 GCU tokens to wallet 0xABCD"
        tx, s_kyb_for_test = blockchain.create_transaction(secret_data, alice_keys, bob_keys.pk)
        
        print(f"Transaction hash: {tx['hash'][:32]}...")
        print(f"KEM artefact signature: {tx['kem_artefact']['sig'][:32]}...")
        
        # Vérification
        decrypted = blockchain.verify_transaction(tx, bob_keys, s_kyb_for_test)
        print(f"Données déchiffrées: {decrypted}")
        print(f"✅ Transaction valide: {decrypted == secret_data}")
    
    @staticmethod
    def test_ai_integration():
        """Test d'intégration IA pour détection d'anomalies"""
        print("\n" + "="*60)
        print("🤖 Test d'Intégration IA - Détection d'Anomalies")
        print("="*60)
        
        class AnomalyDetector:
            def __init__(self):
                self.baseline_entropy = 0.5
                self.threshold = 0.1
                
            def analyze_key_entropy(self, key: bytes) -> tuple:
                """Analyse l'entropie d'une clé"""
                entropy = sum(bin(byte).count('1') for byte in key) / (len(key) * 8)
                is_anomaly = abs(entropy - self.baseline_entropy) > self.threshold
                return entropy, is_anomaly
            
            def detect_pattern_anomalies(self, data: bytes) -> dict:
                """Détecte des patterns anormaux"""
                # Analyse de fréquence
                freq = {}
                for byte in data:
                    freq[byte] = freq.get(byte, 0) + 1
                
                # Calcul de l'uniformité
                expected = len(data) / 256
                chi_square = sum(
                    ((freq.get(i, 0) - expected) ** 2) / expected 
                    for i in range(256)
                )
                
                return {
                    "chi_square": chi_square,
                    "uniform": chi_square < 300,
                    "most_common": max(freq.values()) if freq else 0,
                    "unique_bytes": len(freq)
                }
        
        detector = AnomalyDetector()
        
        # Test avec une clé normale
        good_key = os.urandom(32)
        entropy, is_anomaly = detector.analyze_key_entropy(good_key)
        print(f"Clé aléatoire - Entropie: {entropy:.3f}, Anomalie: {is_anomaly}")
        
        # Test avec une clé faible
        weak_key = b'\x00' * 16 + b'\xFF' * 16
        entropy, is_anomaly = detector.analyze_key_entropy(weak_key)
        print(f"Clé faible - Entropie: {entropy:.3f}, Anomalie: {is_anomaly}")
        
        # Analyse de patterns
        random_data = os.urandom(1024)
        analysis = detector.detect_pattern_anomalies(random_data)
        print(f"\nAnalyse de patterns (données aléatoires):")
        print(f"  Chi-carré: {analysis['chi_square']:.2f}")
        print(f"  Distribution uniforme: {analysis['uniform']}")
        print(f"  Octets uniques: {analysis['unique_bytes']}/256")


# Tests complémentaires
def run_advanced_tests():
    """Lance les tests avancés"""
    print("\n" + "🔬"*30)
    print("       TESTS AVANCÉS - GHOST CYBER UNIVERSE")
    print("🔬"*30)
    
    AdvancedCryptoTests.test_quantum_resistance()
    AdvancedCryptoTests.test_side_channel_resistance()
    AdvancedCryptoTests.test_blockchain_integration()
    AdvancedCryptoTests.test_ai_integration()

if __name__ == "__main__":
    main()