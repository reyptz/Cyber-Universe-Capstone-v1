"""
Module principal pour la génération de clés cryptographiques
===========================================================

Ce module implémente tous les types de génération de clés selon les spécifications
du projet Ghost Cyber Universe.
"""

import os
import secrets
import base64
import hashlib
import hmac
import json
import time
import struct
import random
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path

# Cryptography imports
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec, ed25519, x25519
from cryptography.hazmat.primitives.asymmetric import ed448, x448
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives.serialization import pkcs12

# BIP39 pour les mnémoniques
try:
    from mnemonic import Mnemonic
    BIP39_AVAILABLE = True
except ImportError:
    BIP39_AVAILABLE = False

# TOTP/OTP
try:
    import pyotp
    TOTP_AVAILABLE = True
except ImportError:
    TOTP_AVAILABLE = False


class KeyType(Enum):
    """Types de clés supportés"""
    SYMMETRIC = "symmetric"
    RSA = "rsa"
    ECC = "ecc"
    ED25519 = "ed25519"
    X25519 = "x25519"
    ED448 = "ed448"
    X448 = "x448"
    SSH = "ssh"
    TLS_CERT = "tls_cert"
    BIP39 = "bip39"
    JWT = "jwt"
    HMAC = "hmac"
    TOTP = "totp"
    KDF = "kdf"
    TEMPORARY = "temporary"
    KEY_WRAPPING = "key_wrapping"
    LICENSE = "license"


class OutputFormat(Enum):
    """Formats de sortie supportés"""
    PEM = "pem"
    DER = "der"
    PKCS8 = "pkcs8"
    PKCS12 = "pkcs12"
    JWK = "jwk"
    BASE64 = "base64"
    HEX = "hex"
    RAW = "raw"
    BIP39_MNEMONIC = "bip39_mnemonic"
    OPENSSH = "openssh"


@dataclass
class KeyGenerationConfig:
    """Configuration pour la génération de clés"""
    key_type: KeyType
    key_size: int = 256
    algorithm: str = "AES-256"
    curve: str = "secp256r1"
    rsa_key_size: int = 2048
    output_format: OutputFormat = OutputFormat.PEM
    password_protected: bool = True
    password: Optional[str] = None
    iterations: int = 100000
    salt_length: int = 32
    validity_days: int = 365
    common_name: str = "Ghost Cyber Universe"
    organization: str = "Ghost Cyber Universe"
    country: str = "FR"
    email: Optional[str] = None
    usage_flags: List[str] = None
    metadata: Dict[str, Any] = None


@dataclass
class GeneratedKey:
    """Clé générée avec métadonnées"""
    key_type: KeyType
    algorithm: str
    key_data: Union[str, bytes, Dict[str, Any]]
    public_key: Optional[Union[str, bytes, Dict[str, Any]]] = None
    private_key: Optional[Union[str, bytes, Dict[str, Any]]] = None
    fingerprint: Optional[str] = None
    created_at: datetime = None
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = None
    security_warnings: List[str] = None


class CryptographicKeyGenerator:
    """Générateur principal de clés cryptographiques"""
    
    def __init__(self):
        self.backend = default_backend()
        self.security_warnings = []
        
    def generate_key(self, config: KeyGenerationConfig) -> GeneratedKey:
        """Génère une clé selon la configuration"""
        self.security_warnings = []
        
        if config.key_type == KeyType.SYMMETRIC:
            return self._generate_symmetric_key(config)
        elif config.key_type == KeyType.RSA:
            return self._generate_rsa_key(config)
        elif config.key_type == KeyType.ECC:
            return self._generate_ecc_key(config)
        elif config.key_type == KeyType.ED25519:
            return self._generate_ed25519_key(config)
        elif config.key_type == KeyType.X25519:
            return self._generate_x25519_key(config)
        elif config.key_type == KeyType.ED448:
            return self._generate_ed448_key(config)
        elif config.key_type == KeyType.X448:
            return self._generate_x448_key(config)
        elif config.key_type == KeyType.SSH:
            return self._generate_ssh_key(config)
        elif config.key_type == KeyType.TLS_CERT:
            return self._generate_tls_certificate(config)
        elif config.key_type == KeyType.BIP39:
            return self._generate_bip39_seed(config)
        elif config.key_type == KeyType.JWT:
            return self._generate_jwt_key(config)
        elif config.key_type == KeyType.HMAC:
            return self._generate_hmac_key(config)
        elif config.key_type == KeyType.TOTP:
            return self._generate_totp_secret(config)
        elif config.key_type == KeyType.KDF:
            return self._generate_kdf_key(config)
        elif config.key_type == KeyType.TEMPORARY:
            return self._generate_temporary_key(config)
        elif config.key_type == KeyType.KEY_WRAPPING:
            return self._generate_key_wrapping_key(config)
        elif config.key_type == KeyType.LICENSE:
            return self._generate_license_key(config)
        else:
            raise ValueError(f"Type de clé non supporté: {config.key_type}")
    
    def _generate_symmetric_key(self, config: KeyGenerationConfig) -> GeneratedKey:
        """Génère une clé symétrique (AES, ChaCha20)"""
        if config.algorithm == "AES-128":
            key_size = 16
        elif config.algorithm == "AES-192":
            key_size = 24
        elif config.algorithm == "AES-256":
            key_size = 32
        elif config.algorithm == "ChaCha20-Poly1305":
            key_size = 32
        else:
            key_size = config.key_size // 8
        
        # Génération avec CSPRNG
        key_bytes = secrets.token_bytes(key_size)
        
        # Formats de sortie
        if config.output_format == OutputFormat.BASE64:
            key_data = base64.b64encode(key_bytes).decode()
        elif config.output_format == OutputFormat.HEX:
            key_data = key_bytes.hex()
        elif config.output_format == OutputFormat.RAW:
            key_data = key_bytes
        else:
            key_data = base64.b64encode(key_bytes).decode()
        
        fingerprint = hashlib.sha256(key_bytes).hexdigest()[:16]
        
        return GeneratedKey(
            key_type=config.key_type,
            algorithm=config.algorithm,
            key_data=key_data,
            fingerprint=fingerprint,
            created_at=datetime.utcnow(),
            metadata={
                "key_size_bits": key_size * 8,
                "algorithm": config.algorithm,
                "format": config.output_format.value
            },
            security_warnings=self.security_warnings
        )
    
    def _generate_rsa_key(self, config: KeyGenerationConfig) -> GeneratedKey:
        """Génère une paire de clés RSA"""
        if config.rsa_key_size < 2048:
            self.security_warnings.append("⚠️ RSA < 2048 bits n'est plus recommandé pour la sécurité")
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=config.rsa_key_size,
            backend=self.backend
        )
        public_key = private_key.public_key()
        
        # Sérialisation
        if config.password_protected and config.password:
            encryption_algorithm = serialization.BestAvailableEncryption(config.password.encode())
        else:
            encryption_algorithm = serialization.NoEncryption()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Formats de sortie
        if config.output_format == OutputFormat.PEM:
            key_data = private_pem.decode()
            public_key_data = public_pem.decode()
        elif config.output_format == OutputFormat.DER:
            key_data = private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            )
            public_key_data = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        elif config.output_format == OutputFormat.JWK:
            # Conversion en JWK
            public_numbers = public_key.public_numbers()
            key_data = {
                "kty": "RSA",
                "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')).decode().rstrip('='),
                "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')).decode().rstrip('='),
                "alg": "RS256",
                "use": "sig"
            }
            public_key_data = key_data.copy()
        else:
            key_data = private_pem.decode()
            public_key_data = public_pem.decode()
        
        fingerprint = hashlib.sha256(public_pem).hexdigest()[:16]
        
        return GeneratedKey(
            key_type=config.key_type,
            algorithm=f"RSA-{config.rsa_key_size}",
            key_data=key_data,
            public_key=public_key_data,
            private_key=key_data,
            fingerprint=fingerprint,
            created_at=datetime.utcnow(),
            metadata={
                "key_size_bits": config.rsa_key_size,
                "public_exponent": 65537,
                "format": config.output_format.value
            },
            security_warnings=self.security_warnings
        )
    
    def _generate_ecc_key(self, config: KeyGenerationConfig) -> GeneratedKey:
        """Génère une paire de clés ECC"""
        # Sélection de la courbe
        curve_map = {
            "secp256r1": ec.SECP256R1(),
            "secp384r1": ec.SECP384R1(),
            "secp521r1": ec.SECP521R1(),
            "secp256k1": ec.SECP256K1(),
        }
        
        curve = curve_map.get(config.curve, ec.SECP256R1())
        
        private_key = ec.generate_private_key(curve, backend=self.backend)
        public_key = private_key.public_key()
        
        # Sérialisation
        if config.password_protected and config.password:
            encryption_algorithm = serialization.BestAvailableEncryption(config.password.encode())
        else:
            encryption_algorithm = serialization.NoEncryption()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Formats de sortie
        if config.output_format == OutputFormat.PEM:
            key_data = private_pem.decode()
            public_key_data = public_pem.decode()
        elif config.output_format == OutputFormat.JWK:
            # Conversion en JWK pour ECC
            public_numbers = public_key.public_numbers()
            x = public_numbers.x.to_bytes((public_numbers.x.bit_length() + 7) // 8, 'big')
            y = public_numbers.y.to_bytes((public_numbers.y.bit_length() + 7) // 8, 'big')
            
            key_data = {
                "kty": "EC",
                "crv": config.curve,
                "x": base64.urlsafe_b64encode(x).decode().rstrip('='),
                "y": base64.urlsafe_b64encode(y).decode().rstrip('='),
                "alg": "ES256",
                "use": "sig"
            }
            public_key_data = key_data.copy()
        else:
            key_data = private_pem.decode()
            public_key_data = public_pem.decode()
        
        fingerprint = hashlib.sha256(public_pem).hexdigest()[:16]
        
        return GeneratedKey(
            key_type=config.key_type,
            algorithm=f"ECC-{config.curve}",
            key_data=key_data,
            public_key=public_key_data,
            private_key=key_data,
            fingerprint=fingerprint,
            created_at=datetime.utcnow(),
            metadata={
                "curve": config.curve,
                "format": config.output_format.value
            },
            security_warnings=self.security_warnings
        )
    
    def _generate_ed25519_key(self, config: KeyGenerationConfig) -> GeneratedKey:
        """Génère une paire de clés Ed25519"""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        # Sérialisation
        if config.password_protected and config.password:
            encryption_algorithm = serialization.BestAvailableEncryption(config.password.encode())
        else:
            encryption_algorithm = serialization.NoEncryption()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Formats de sortie
        if config.output_format == OutputFormat.PEM:
            key_data = private_pem.decode()
            public_key_data = public_pem.decode()
        elif config.output_format == OutputFormat.JWK:
            # Conversion en JWK pour Ed25519
            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            
            key_data = {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": base64.urlsafe_b64encode(public_bytes).decode().rstrip('='),
                "alg": "EdDSA",
                "use": "sig"
            }
            public_key_data = key_data.copy()
        else:
            key_data = private_pem.decode()
            public_key_data = public_pem.decode()
        
        fingerprint = hashlib.sha256(public_pem).hexdigest()[:16]
        
        return GeneratedKey(
            key_type=config.key_type,
            algorithm="Ed25519",
            key_data=key_data,
            public_key=public_key_data,
            private_key=key_data,
            fingerprint=fingerprint,
            created_at=datetime.utcnow(),
            metadata={
                "curve": "Ed25519",
                "format": config.output_format.value
            },
            security_warnings=self.security_warnings
        )
    
    def _generate_x25519_key(self, config: KeyGenerationConfig) -> GeneratedKey:
        """Génère une paire de clés X25519 pour l'échange de clés"""
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        # Sérialisation
        if config.password_protected and config.password:
            encryption_algorithm = serialization.BestAvailableEncryption(config.password.encode())
        else:
            encryption_algorithm = serialization.NoEncryption()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Formats de sortie
        if config.output_format == OutputFormat.PEM:
            key_data = private_pem.decode()
            public_key_data = public_pem.decode()
        elif config.output_format == OutputFormat.JWK:
            # Conversion en JWK pour X25519
            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            
            key_data = {
                "kty": "OKP",
                "crv": "X25519",
                "x": base64.urlsafe_b64encode(public_bytes).decode().rstrip('='),
                "alg": "ECDH-ES",
                "use": "enc"
            }
            public_key_data = key_data.copy()
        else:
            key_data = private_pem.decode()
            public_key_data = public_pem.decode()
        
        fingerprint = hashlib.sha256(public_pem).hexdigest()[:16]
        
        return GeneratedKey(
            key_type=config.key_type,
            algorithm="X25519",
            key_data=key_data,
            public_key=public_key_data,
            private_key=key_data,
            fingerprint=fingerprint,
            created_at=datetime.utcnow(),
            metadata={
                "curve": "X25519",
                "format": config.output_format.value
            },
            security_warnings=self.security_warnings
        )
    
    def _generate_ed448_key(self, config: KeyGenerationConfig) -> GeneratedKey:
        """Génère une paire de clés Ed448"""
        private_key = ed448.Ed448PrivateKey.generate()
        public_key = private_key.public_key()
        
        # Sérialisation
        if config.password_protected and config.password:
            encryption_algorithm = serialization.BestAvailableEncryption(config.password.encode())
        else:
            encryption_algorithm = serialization.NoEncryption()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        fingerprint = hashlib.sha256(public_pem).hexdigest()[:16]
        
        return GeneratedKey(
            key_type=config.key_type,
            algorithm="Ed448",
            key_data=private_pem.decode(),
            public_key=public_pem.decode(),
            private_key=private_pem.decode(),
            fingerprint=fingerprint,
            created_at=datetime.utcnow(),
            metadata={
                "curve": "Ed448",
                "format": config.output_format.value
            },
            security_warnings=self.security_warnings
        )
    
    def _generate_x448_key(self, config: KeyGenerationConfig) -> GeneratedKey:
        """Génère une paire de clés X448"""
        private_key = x448.X448PrivateKey.generate()
        public_key = private_key.public_key()
        
        # Sérialisation
        if config.password_protected and config.password:
            encryption_algorithm = serialization.BestAvailableEncryption(config.password.encode())
        else:
            encryption_algorithm = serialization.NoEncryption()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        fingerprint = hashlib.sha256(public_pem).hexdigest()[:16]
        
        return GeneratedKey(
            key_type=config.key_type,
            algorithm="X448",
            key_data=private_pem.decode(),
            public_key=public_pem.decode(),
            private_key=private_pem.decode(),
            fingerprint=fingerprint,
            created_at=datetime.utcnow(),
            metadata={
                "curve": "X448",
                "format": config.output_format.value
            },
            security_warnings=self.security_warnings
        )
    
    def _generate_ssh_key(self, config: KeyGenerationConfig) -> GeneratedKey:
        """Génère une clé SSH (RSA, ECDSA, Ed25519)"""
        try:
            if config.algorithm == "RSA":
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=config.rsa_key_size,
                    backend=self.backend
                )
            elif config.algorithm == "ECDSA":
                curve_map = {
                    "secp256r1": ec.SECP256R1(),
                    "secp384r1": ec.SECP384R1(),
                    "secp521r1": ec.SECP521R1(),
                }
                curve = curve_map.get(config.curve, ec.SECP256R1())
                private_key = ec.generate_private_key(curve, backend=self.backend)
            elif config.algorithm == "Ed25519":
                private_key = ed25519.Ed25519PrivateKey.generate()
            else:
                raise ValueError(f"Algorithme SSH non supporté: {config.algorithm}")
            
            public_key = private_key.public_key()
            
            # Format OpenSSH
            if config.output_format == OutputFormat.OPENSSH:
                # Format OpenSSH public key
                if config.algorithm == "RSA":
                    public_openssh = f"ssh-rsa {base64.b64encode(public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)).decode()}"
                elif config.algorithm == "ECDSA":
                    public_openssh = f"ecdsa-sha2-{config.curve} {base64.b64encode(public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()}"
                elif config.algorithm == "Ed25519":
                    # Fix for Ed25519 key format
                    public_bytes = public_key.public_bytes(
                        encoding=serialization.Encoding.OpenSSH,
                        format=serialization.PublicFormat.OpenSSH
                    )
                    public_openssh = public_bytes.decode()
                
                # Clé privée au format OpenSSH
                encryption_algorithm = serialization.NoEncryption()
                if config.password_protected and config.password:
                    encryption_algorithm = serialization.BestAvailableEncryption(config.password.encode())
                
                private_openssh = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.OpenSSH,
                    encryption_algorithm=encryption_algorithm
                )
                
                key_data = private_openssh.decode()
                public_key_data = public_openssh
            else:
                # Format PEM standard
                encryption_algorithm = serialization.NoEncryption()
                if config.password_protected and config.password:
                    encryption_algorithm = serialization.BestAvailableEncryption(config.password.encode())
                
                private_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=encryption_algorithm
                )
                
                public_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                
                key_data = private_pem.decode()
                public_key_data = public_pem.decode()
            
            fingerprint = hashlib.sha256(public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()[:16]
        except Exception as e:
            self.security_warnings.append(f"Erreur lors de la génération de clé SSH: {str(e)}")
            raise
        
        return GeneratedKey(
            key_type=config.key_type,
            algorithm=f"SSH-{config.algorithm}",
            key_data=key_data,
            public_key=public_key_data,
            private_key=key_data,
            fingerprint=fingerprint,
            created_at=datetime.utcnow(),
            metadata={
                "ssh_algorithm": config.algorithm,
                "format": config.output_format.value
            },
            security_warnings=self.security_warnings
        )
    
    def _generate_tls_certificate(self, config: KeyGenerationConfig) -> GeneratedKey:
        """Génère un certificat TLS avec CSR"""
        try:
            # Génération de la clé privée
            if config.algorithm == "RSA":
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=config.rsa_key_size,
                    backend=self.backend
                )
            elif config.algorithm == "ECDSA":
                curve_map = {
                    "secp256r1": ec.SECP256R1(),
                    "secp384r1": ec.SECP384R1(),
                    "secp521r1": ec.SECP521R1(),
                }
                curve = curve_map.get(config.curve, ec.SECP256R1())
                private_key = ec.generate_private_key(curve, backend=self.backend)
            elif config.algorithm == "Ed25519":
                private_key = ed25519.Ed25519PrivateKey.generate()
            else:
                raise ValueError(f"Algorithme TLS non supporté: {config.algorithm}")
            
            public_key = private_key.public_key()
            
            # Création du CSR
            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, config.country),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, config.organization),
                x509.NameAttribute(NameOID.COMMON_NAME, config.common_name),
            ])
            
            if config.email:
                subject = subject.add(x509.NameAttribute(NameOID.EMAIL_ADDRESS, config.email))
            
            csr = x509.CertificateSigningRequestBuilder().subject_name(
                subject
            ).sign(private_key, hashes.SHA256(), self.backend)
            
            # Auto-signature du certificat (pour démo)
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                subject  # Auto-signé
            ).public_key(
                public_key
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=config.validity_days)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(config.common_name),
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256(), self.backend)
            
            # Formats de sortie
            if config.output_format == OutputFormat.PEM:
                # Définir l'algorithme de chiffrement
                encryption_algorithm = serialization.NoEncryption()
                if config.password_protected and config.password:
                    encryption_algorithm = serialization.BestAvailableEncryption(config.password.encode())
                
                cert_pem = cert.public_bytes(serialization.Encoding.PEM)
                key_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=encryption_algorithm
                )
                csr_pem = csr.public_bytes(serialization.Encoding.PEM)
                
                key_data = {
                    "certificate": cert_pem.decode(),
                    "private_key": key_pem.decode(),
                    "csr": csr_pem.decode()
                }
            elif config.output_format == OutputFormat.PKCS12:
                # Format PKCS#12 (PFX)
                # Définir l'algorithme de chiffrement
                encryption_algorithm = serialization.NoEncryption()
                if config.password_protected and config.password:
                    encryption_algorithm = serialization.BestAvailableEncryption(config.password.encode())
                
                pfx_data = pkcs12.serialize_key_and_certificates(
                    name=b"Ghost Cyber Universe",
                    key=private_key,
                    cert=cert,
                    cas=None,
                    encryption_algorithm=encryption_algorithm
                )
                
                key_data = {
                    "pfx": base64.b64encode(pfx_data).decode(),
                    "csr": csr.public_bytes(serialization.Encoding.PEM).decode()
                }
            else:
                cert_pem = cert.public_bytes(serialization.Encoding.PEM)
                key_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(config.password.encode()) if config.password_protected and config.password else serialization.NoEncryption()
                )
                csr_pem = csr.public_bytes(serialization.Encoding.PEM)
                
                key_data = {
                    "certificate": cert_pem.decode(),
                    "private_key": key_pem.decode(),
                    "csr": csr_pem.decode()
                }
            
            fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()[:16]
        except Exception as e:
            self.security_warnings.append(f"Erreur lors de la génération du certificat TLS: {str(e)}")
            raise
        
        return GeneratedKey(
            key_type=config.key_type,
            algorithm=f"TLS-{config.algorithm}",
            key_data=key_data,
            fingerprint=fingerprint,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=config.validity_days),
            metadata={
                "subject": config.common_name,
                "validity_days": config.validity_days,
                "format": config.output_format.value
            },
            security_warnings=self.security_warnings
        )
    
    def _generate_bip39_seed(self, config: KeyGenerationConfig) -> GeneratedKey:
        """Génère un seed BIP39 (mnémonique)"""
        if not BIP39_AVAILABLE:
            raise ImportError("Le module mnemonic n'est pas installé. Installez-le avec: pip install mnemonic")
        
        # Génération du mnémonique
        mnemo = Mnemonic("english")
        
        if config.key_size == 128:
            entropy_bits = 128
            word_count = 12
        elif config.key_size == 160:
            entropy_bits = 160
            word_count = 15
        elif config.key_size == 192:
            entropy_bits = 192
            word_count = 18
        elif config.key_size == 224:
            entropy_bits = 224
            word_count = 21
        elif config.key_size == 256:
            entropy_bits = 256
            word_count = 24
        else:
            entropy_bits = 256
            word_count = 24
        
        # Génération de l'entropie
        entropy = secrets.token_bytes(entropy_bits // 8)
        mnemonic_phrase = mnemo.to_mnemonic(entropy)
        
        # Dérivation du seed
        seed = mnemo.to_seed(mnemonic_phrase)
        
        if config.output_format == OutputFormat.BIP39_MNEMONIC:
            key_data = mnemonic_phrase
        elif config.output_format == OutputFormat.HEX:
            key_data = seed.hex()
        elif config.output_format == OutputFormat.BASE64:
            key_data = base64.b64encode(seed).decode()
        else:
            key_data = {
                "mnemonic": mnemonic_phrase,
                "seed": seed.hex(),
                "entropy": entropy.hex()
            }
        
        fingerprint = hashlib.sha256(seed).hexdigest()[:16]
        
        # Avertissements de sécurité
        self.security_warnings.extend([
            "⚠️ GARDEZ CE MNÉMONIQUE SECRET - Ne le partagez jamais",
            "⚠️ Stockez-le hors-ligne dans un endroit sûr",
            "⚠️ Perdre ce mnémonique = perte définitive des fonds",
            "⚠️ Ne le tapez jamais sur un ordinateur connecté à Internet"
        ])
        
        return GeneratedKey(
            key_type=config.key_type,
            algorithm="BIP39",
            key_data=key_data,
            fingerprint=fingerprint,
            created_at=datetime.utcnow(),
            metadata={
                "word_count": word_count,
                "entropy_bits": entropy_bits,
                "format": config.output_format.value
            },
            security_warnings=self.security_warnings
        )
    
    def _generate_jwt_key(self, config: KeyGenerationConfig) -> GeneratedKey:
        """Génère une clé pour JWT (HMAC ou RSA/ECC)"""
        if config.algorithm.startswith("HS"):
            # Clé HMAC pour JWT
            key_bytes = secrets.token_bytes(config.key_size // 8)
            
            if config.output_format == OutputFormat.BASE64:
                key_data = base64.b64encode(key_bytes).decode()
            elif config.output_format == OutputFormat.HEX:
                key_data = key_bytes.hex()
            else:
                key_data = base64.b64encode(key_bytes).decode()
            
            fingerprint = hashlib.sha256(key_bytes).hexdigest()[:16]
            
            return GeneratedKey(
                key_type=config.key_type,
                algorithm=config.algorithm,
                key_data=key_data,
                fingerprint=fingerprint,
                created_at=datetime.utcnow(),
                metadata={
                    "jwt_algorithm": config.algorithm,
                    "key_size_bits": config.key_size,
                    "format": config.output_format.value
                },
                security_warnings=self.security_warnings
            )
        else:
            # Clé asymétrique pour JWT (RSA/ECC)
            if config.algorithm.startswith("RS"):
                return self._generate_rsa_key(config)
            elif config.algorithm.startswith("ES"):
                return self._generate_ecc_key(config)
            elif config.algorithm.startswith("Ed"):
                return self._generate_ed25519_key(config)
            else:
                raise ValueError(f"Algorithme JWT non supporté: {config.algorithm}")
    
    def _generate_hmac_key(self, config: KeyGenerationConfig) -> GeneratedKey:
        """Génère une clé HMAC"""
        key_bytes = secrets.token_bytes(config.key_size // 8)
        
        if config.output_format == OutputFormat.BASE64:
            key_data = base64.b64encode(key_bytes).decode()
        elif config.output_format == OutputFormat.HEX:
            key_data = key_bytes.hex()
        else:
            key_data = base64.b64encode(key_bytes).decode()
        
        fingerprint = hashlib.sha256(key_bytes).hexdigest()[:16]
        
        return GeneratedKey(
            key_type=config.key_type,
            algorithm=f"HMAC-{config.algorithm}",
            key_data=key_data,
            fingerprint=fingerprint,
            created_at=datetime.utcnow(),
            metadata={
                "hmac_algorithm": config.algorithm,
                "key_size_bits": config.key_size,
                "format": config.output_format.value
            },
            security_warnings=self.security_warnings
        )
    
    def _generate_totp_secret(self, config: KeyGenerationConfig) -> GeneratedKey:
        """Génère un secret TOTP/OTP"""
        if not TOTP_AVAILABLE:
            raise ImportError("Le module pyotp n'est pas installé. Installez-le avec: pip install pyotp")
        
        # Génération du secret base32
        secret_bytes = secrets.token_bytes(20)  # 160 bits
        secret_b32 = base64.b32encode(secret_bytes).decode().rstrip('=')
        
        # Génération de l'URI TOTP
        totp = pyotp.TOTP(secret_b32)
        totp_uri = totp.provisioning_uri(
            name=config.common_name,
            issuer_name=config.organization
        )
        
        if config.output_format == OutputFormat.BASE64:
            key_data = secret_b32
        else:
            key_data = {
                "secret": secret_b32,
                "uri": totp_uri,
                "qr_code_data": totp_uri
            }
        
        fingerprint = hashlib.sha256(secret_bytes).hexdigest()[:16]
        
        return GeneratedKey(
            key_type=config.key_type,
            algorithm="TOTP",
            key_data=key_data,
            fingerprint=fingerprint,
            created_at=datetime.utcnow(),
            metadata={
                "secret_length": len(secret_b32),
                "format": config.output_format.value
            },
            security_warnings=self.security_warnings
        )
    
    def _generate_kdf_key(self, config: KeyGenerationConfig) -> GeneratedKey:
        """Génère une clé dérivée avec KDF"""
        # Génération du salt
        salt = secrets.token_bytes(config.salt_length)
        
        # Mot de passe de démonstration (en production, fourni par l'utilisateur)
        password = config.password or "GhostCyberUniverse2024!"
        
        if config.algorithm == "PBKDF2":
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=config.key_size // 8,
                salt=salt,
                iterations=config.iterations,
                backend=self.backend
            )
            derived_key = kdf.derive(password.encode())
        elif config.algorithm == "scrypt":
            kdf = Scrypt(
                salt=salt,
                length=config.key_size // 8,
                n=2**14,  # CPU/memory cost
                r=8,      # block size
                p=1,      # parallelization
                backend=self.backend
            )
            derived_key = kdf.derive(password.encode())
        elif config.algorithm == "Argon2id":
            # Simulation d'Argon2id (nécessite argon2-cffi)
            try:
                from argon2 import PasswordHasher
                ph = PasswordHasher()
                derived_key = ph.hash(password.encode()).encode()
            except ImportError:
                # Fallback sur PBKDF2
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=config.key_size // 8,
                    salt=salt,
                    iterations=config.iterations,
                    backend=self.backend
                )
                derived_key = kdf.derive(password.encode())
        else:
            raise ValueError(f"Algorithme KDF non supporté: {config.algorithm}")
        
        if config.output_format == OutputFormat.BASE64:
            key_data = base64.b64encode(derived_key).decode()
        elif config.output_format == OutputFormat.HEX:
            key_data = derived_key.hex()
        else:
            key_data = {
                "derived_key": base64.b64encode(derived_key).decode(),
                "salt": salt.hex(),
                "iterations": config.iterations,
                "algorithm": config.algorithm
            }
        
        fingerprint = hashlib.sha256(derived_key).hexdigest()[:16]
        
        return GeneratedKey(
            key_type=config.key_type,
            algorithm=config.algorithm,
            key_data=key_data,
            fingerprint=fingerprint,
            created_at=datetime.utcnow(),
            metadata={
                "kdf_algorithm": config.algorithm,
                "iterations": config.iterations,
                "salt_length": config.salt_length,
                "format": config.output_format.value
            },
            security_warnings=self.security_warnings
        )
    
    def _generate_temporary_key(self, config: KeyGenerationConfig) -> GeneratedKey:
        """Génère une clé temporaire/éphémère"""
        key_bytes = secrets.token_bytes(config.key_size // 8)
        
        if config.output_format == OutputFormat.BASE64:
            key_data = base64.b64encode(key_bytes).decode()
        elif config.output_format == OutputFormat.HEX:
            key_data = key_bytes.hex()
        else:
            key_data = base64.b64encode(key_bytes).decode()
        
        fingerprint = hashlib.sha256(key_bytes).hexdigest()[:16]
        
        # Clé temporaire avec expiration
        expires_at = datetime.utcnow() + timedelta(hours=24)  # 24h par défaut
        
        return GeneratedKey(
            key_type=config.key_type,
            algorithm="Temporary",
            key_data=key_data,
            fingerprint=fingerprint,
            created_at=datetime.utcnow(),
            expires_at=expires_at,
            metadata={
                "key_size_bits": config.key_size,
                "expires_in_hours": 24,
                "format": config.output_format.value
            },
            security_warnings=self.security_warnings
        )
    
    def _generate_key_wrapping_key(self, config: KeyGenerationConfig) -> GeneratedKey:
        """Génère une clé de chiffrement de clé (KEK)"""
        key_bytes = secrets.token_bytes(config.key_size // 8)
        
        if config.output_format == OutputFormat.BASE64:
            key_data = base64.b64encode(key_bytes).decode()
        elif config.output_format == OutputFormat.HEX:
            key_data = key_bytes.hex()
        else:
            key_data = base64.b64encode(key_bytes).decode()
        
        fingerprint = hashlib.sha256(key_bytes).hexdigest()[:16]
        
        return GeneratedKey(
            key_type=config.key_type,
            algorithm="Key-Wrapping",
            key_data=key_data,
            fingerprint=fingerprint,
            created_at=datetime.utcnow(),
            metadata={
                "key_size_bits": config.key_size,
                "usage": "key_encryption",
                "format": config.output_format.value
            },
            security_warnings=self.security_warnings
        )
    
    def _generate_license_key(self, config: KeyGenerationConfig) -> GeneratedKey:
        """Génère une clé de licence/produit"""
        # Génération d'une clé de licence formatée
        license_data = {
            "product": "Ghost Cyber Universe",
            "version": "1.0.0",
            "issued": datetime.utcnow().isoformat(),
            "expires": (datetime.utcnow() + timedelta(days=365)).isoformat(),
            "features": ["crypto", "blockchain", "ai", "devsecops"],
            "user_id": secrets.token_hex(8),
            "license_id": secrets.token_hex(16)
        }
        
        # Signature de la licence
        license_json = json.dumps(license_data, sort_keys=True)
        license_hash = hashlib.sha256(license_json.encode()).hexdigest()
        
        # Clé de signature (simulation)
        signature_key = secrets.token_bytes(32)
        signature = hmac.new(signature_key, license_json.encode(), hashlib.sha256).hexdigest()
        
        key_data = {
            "license": license_data,
            "signature": signature,
            "hash": license_hash,
            "license_key": f"GCU-{secrets.token_hex(8).upper()}-{secrets.token_hex(8).upper()}-{secrets.token_hex(8).upper()}"
        }
        
        fingerprint = hashlib.sha256(license_json.encode()).hexdigest()[:16]
        
        return GeneratedKey(
            key_type=config.key_type,
            algorithm="License-Key",
            key_data=key_data,
            fingerprint=fingerprint,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=365),
            metadata={
                "license_type": "commercial",
                "features": license_data["features"],
                "format": config.output_format.value
            },
            security_warnings=self.security_warnings
        )

"""
Types de clés étendus pour tous les domaines IT
==============================================

Ce module étend le système de génération de clés pour couvrir tous les domaines
informatiques nécessitant des clés cryptographiques.
"""

from enum import Enum
from typing import Dict, List, Any
import json
from pathlib import Path

class ExtendedKeyType(Enum):
    """Types de clés étendus couvrant tous les domaines IT"""
    
    # === CLÉS SYMÉTRIQUES ===
    SYMMETRIC = "symmetric"
    BLOCK_CIPHER = "block_cipher"
    STREAM_CIPHER = "stream_cipher"
    
    # === CLÉS ASYMÉTRIQUES ===
    ASYMMETRIC = "asymmetric"
    RSA = "rsa"
    ECC = "ecc"
    EDWARDS_CURVE = "edwards_curve"
    
    # === CRYPTOGRAPHIE POST-QUANTUM ===
    POST_QUANTUM = "post_quantum"
    LATTICE_BASED = "lattice_based"
    CODE_BASED = "code_based"
    HASH_BASED = "hash_based"
    ISOGENY_BASED = "isogeny_based"
    
    # === CERTIFICATS TLS/SSL ===
    TLS_CERT = "tls_cert"
    SERVER_CERT = "server_cert"
    CLIENT_CERT = "client_cert"
    INTERMEDIATE_CA = "intermediate_ca"
    ROOT_CA = "root_ca"
    CODE_SIGNING_CERT = "code_signing_cert"
    EMAIL_CERT = "email_cert"
    
    # === CLÉS SSH ===
    SSH_KEY = "ssh_key"
    SSH_RSA = "ssh_rsa"
    SSH_ECDSA = "ssh_ecdsa"
    SSH_ED25519 = "ssh_ed25519"
    
    # === PORTEFEUILLES CRYPTOGRAPHIQUES ===
    CRYPTO_WALLET = "crypto_wallet"
    BIP39 = "bip39"
    BIP32 = "bip32"
    BIP44 = "bip44"
    BIP49 = "bip49"
    BIP84 = "bip84"
    
    # === JWT ET API ===
    JWT_TOKEN = "jwt_token"
    API_KEY = "api_key"
    OAUTH_KEY = "oauth_key"
    
    # === SÉCURITÉ DES BASES DE DONNÉES ===
    DATABASE_ENCRYPTION = "database_encryption"
    TDE = "tde"
    COLUMN_ENCRYPTION = "column_encryption"
    FIELD_ENCRYPTION = "field_encryption"
    
    # === BLOCKCHAIN ===
    BLOCKCHAIN = "blockchain"
    BITCOIN = "bitcoin"
    ETHEREUM = "ethereum"
    MONERO = "monero"
    LITECOIN = "litecoin"
    RIPPLE = "ripple"
    CARDANO = "cardano"
    POLKADOT = "polkadot"
    
    # === IoT ET CAPTEURS ===
    IOT_SECURITY = "iot_security"
    DEVICE_KEY = "device_key"
    SENSOR_KEY = "sensor_key"
    GATEWAY_KEY = "gateway_key"
    EDGE_KEY = "edge_key"
    
    # === SÉCURITÉ CLOUD ===
    CLOUD_SECURITY = "cloud_security"
    AWS_KMS = "aws_kms"
    AZURE_KEY_VAULT = "azure_key_vault"
    GOOGLE_CLOUD_KMS = "google_cloud_kms"
    IBM_CLOUD_HSM = "ibm_cloud_hsm"
    ORACLE_CLOUD_VAULT = "oracle_cloud_vault"
    
    # === SÉCURITÉ MOBILE ===
    MOBILE_SECURITY = "mobile_security"
    ANDROID = "android"
    IOS = "ios"
    WINDOWS_MOBILE = "windows_mobile"
    
    # === OTP/TOTP ===
    OTP = "otp"
    TOTP = "totp"
    HOTP = "hotp"
    SMS_OTP = "sms_otp"
    EMAIL_OTP = "email_otp"
    
    # === SIGNATURES NUMÉRIQUES ===
    DIGITAL_SIGNATURE = "digital_signature"
    DOCUMENT_SIGNING = "document_signing"
    CODE_SIGNING = "code_signing"
    PDF_SIGNING = "pdf_signing"
    XML_SIGNING = "xml_signing"
    
    # === SÉCURITÉ EMAIL ===
    EMAIL_SECURITY = "email_security"
    PGP = "pgp"
    SMIME = "smime"
    DKIM = "dkim"
    SPF = "spf"
    DMARC = "dmarc"
    
    # === VPN ===
    VPN_KEY = "vpn_key"
    OPENVPN = "openvpn"
    WIREGUARD = "wireguard"
    IPSEC = "ipsec"
    L2TP = "l2tp"
    PPTP = "pptp"
    
    # === SÉCURITÉ DES CONTENEURS ===
    CONTAINER_SECURITY = "container_security"
    DOCKER = "docker"
    KUBERNETES = "kubernetes"
    PODMAN = "podman"
    CONTAINERD = "containerd"
    
    # === MICROSERVICES ===
    MICROSERVICES = "microservices"
    SERVICE_MESH = "service_mesh"
    API_GATEWAY = "api_gateway"
    SERVICE_DISCOVERY = "service_discovery"
    
    # === DEVOPS ===
    DEVOPS_SECURITY = "devops_security"
    CI_CD = "ci_cd"
    SECRETS_MANAGEMENT = "secrets_management"
    INFRASTRUCTURE_AS_CODE = "infrastructure_as_code"
    
    # === SÉCURITÉ RÉSEAU ===
    NETWORK_SECURITY = "network_security"
    WIFI_SECURITY = "wifi_security"
    BLUETOOTH_SECURITY = "bluetooth_security"
    ZIGBEE_SECURITY = "zigbee_security"
    
    # === SÉCURITÉ APPLICATIVE ===
    APPLICATION_SECURITY = "application_security"
    WEB_APPLICATION = "web_application"
    DESKTOP_APPLICATION = "desktop_application"
    EMBEDDED_APPLICATION = "embedded_application"
    
    # === SÉCURITÉ SYSTÈME ===
    SYSTEM_SECURITY = "system_security"
    BOOT_SECURITY = "boot_security"
    DISK_ENCRYPTION = "disk_encryption"
    FILE_ENCRYPTION = "file_encryption"
    
    # === SÉCURITÉ MÉDICALE ===
    MEDICAL_SECURITY = "medical_security"
    HIPAA_COMPLIANCE = "hipaa_compliance"
    MEDICAL_DEVICE = "medical_device"
    PATIENT_DATA = "patient_data"
    
    # === SÉCURITÉ FINANCIÈRE ===
    FINANCIAL_SECURITY = "financial_security"
    PCI_DSS = "pci_dss"
    BANKING = "banking"
    PAYMENT_PROCESSING = "payment_processing"
    
    # === SÉCURITÉ GOUVERNEMENTALE ===
    GOVERNMENT_SECURITY = "government_security"
    MILITARY_GRADE = "military_grade"
    CLASSIFIED_DATA = "classified_data"
    NATIONAL_SECURITY = "national_security"
    
    # === SÉCURITÉ AUTOMOTIVE ===
    AUTOMOTIVE_SECURITY = "automotive_security"
    VEHICLE_KEY = "vehicle_key"
    ECU_SECURITY = "ecu_security"
    TELEMATICS = "telematics"
    
    # === SÉCURITÉ AÉRONAUTIQUE ===
    AEROSPACE_SECURITY = "aerospace_security"
    AIRCRAFT_KEY = "aircraft_key"
    SATELLITE_KEY = "satellite_key"
    AVIONICS = "avionics"

class AlgorithmCategory(Enum):
    """Catégories d'algorithmes cryptographiques"""
    SYMMETRIC = "symmetric"
    ASYMMETRIC = "asymmetric"
    HASH = "hash"
    MAC = "mac"
    KDF = "kdf"
    POST_QUANTUM = "post_quantum"
    HYBRID = "hybrid"

class SecurityLevel(Enum):
    """Niveaux de sécurité"""
    LOW = "low"           # 80 bits de sécurité
    MEDIUM = "medium"     # 112 bits de sécurité
    HIGH = "high"         # 128 bits de sécurité
    VERY_HIGH = "very_high"  # 192 bits de sécurité
    ULTRA_HIGH = "ultra_high"  # 256 bits de sécurité
    QUANTUM_SAFE = "quantum_safe"  # Résistant aux ordinateurs quantiques

class ComplianceStandard(Enum):
    """Standards de conformité"""
    FIPS_140_2 = "fips_140_2"
    FIPS_140_3 = "fips_140_3"
    COMMON_CRITERIA = "common_criteria"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    SOX = "sox"
    GDPR = "gdpr"
    ISO_27001 = "iso_27001"
    NIST = "nist"
    CNSA = "cnsa"

def load_complete_key_types() -> Dict[str, Any]:
    """Charge la configuration complète des types de clés"""
    config_path = Path(__file__).parent / "complete_key_types.json"
    with open(config_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def get_key_types_by_domain(domain: str) -> List[Dict[str, Any]]:
    """Retourne les types de clés pour un domaine spécifique"""
    config = load_complete_key_types()
    return config.get(domain, {})

def get_all_domains() -> List[str]:
    """Retourne tous les domaines supportés"""
    config = load_complete_key_types()
    return list(config.keys())

def get_algorithms_for_key_type(key_type: str) -> List[Dict[str, Any]]:
    """Retourne les algorithmes disponibles pour un type de clé"""
    config = load_complete_key_types()
    
    # Recherche récursive dans la configuration
    def find_algorithms(obj, target_type):
        if isinstance(obj, dict):
            if target_type in obj:
                return obj[target_type]
            for value in obj.values():
                result = find_algorithms(value, target_type)
                if result:
                    return result
        return None
    
    return find_algorithms(config, key_type) or {}

def get_security_recommendations(key_type: str, use_case: str) -> Dict[str, Any]:
    """Retourne les recommandations de sécurité pour un type de clé et cas d'usage"""
    recommendations = {
        "symmetric": {
            "general": {
                "recommended_algorithm": "AES-256",
                "minimum_key_size": 128,
                "recommended_key_size": 256,
                "security_level": SecurityLevel.HIGH.value
            },
            "database": {
                "recommended_algorithm": "AES-256",
                "key_rotation": "90 days",
                "security_level": SecurityLevel.HIGH.value
            },
            "iot": {
                "recommended_algorithm": "AES-128",
                "minimum_key_size": 128,
                "security_level": SecurityLevel.MEDIUM.value
            }
        },
        "asymmetric": {
            "general": {
                "recommended_algorithm": "RSA-3072",
                "minimum_key_size": 2048,
                "recommended_key_size": 3072,
                "security_level": SecurityLevel.HIGH.value
            },
            "tls": {
                "recommended_algorithm": "ECDSA-P256",
                "minimum_key_size": 256,
                "security_level": SecurityLevel.HIGH.value
            },
            "ssh": {
                "recommended_algorithm": "Ed25519",
                "minimum_key_size": 256,
                "security_level": SecurityLevel.HIGH.value
            }
        },
        "post_quantum": {
            "general": {
                "recommended_algorithm": "CRYSTALS-Kyber",
                "security_level": SecurityLevel.QUANTUM_SAFE.value,
                "note": "Résistant aux attaques quantiques"
            }
        }
    }
    
    return recommendations.get(key_type, {}).get(use_case, {})

def get_compliance_requirements(standard: ComplianceStandard) -> Dict[str, Any]:
    """Retourne les exigences de conformité pour un standard"""
    requirements = {
        ComplianceStandard.FIPS_140_2: {
            "approved_algorithms": ["AES", "RSA", "ECDSA", "SHA-256", "SHA-384", "SHA-512"],
            "minimum_key_sizes": {
                "AES": 128,
                "RSA": 2048,
                "ECDSA": 224
            },
            "key_management": "Hardware Security Module (HSM) recommended"
        },
        ComplianceStandard.PCI_DSS: {
            "approved_algorithms": ["AES", "RSA", "ECDSA"],
            "minimum_key_sizes": {
                "AES": 128,
                "RSA": 2048,
                "ECDSA": 224
            },
            "key_rotation": "Annual or when compromised"
        },
        ComplianceStandard.HIPAA: {
            "approved_algorithms": ["AES", "RSA", "ECDSA"],
            "minimum_key_sizes": {
                "AES": 128,
                "RSA": 2048,
                "ECDSA": 224
            },
            "encryption_required": "At rest and in transit"
        }
    }
    
    return requirements.get(standard, {})

# Mapping des domaines IT aux types de clés
IT_DOMAINS_MAPPING = {
    "Infrastructure": [
        "TLS_CERT", "SSH_KEY", "VPN_KEY", "NETWORK_SECURITY"
    ],
    "Application": [
        "JWT_TOKEN", "API_KEY", "DIGITAL_SIGNATURE", "APPLICATION_SECURITY"
    ],
    "Database": [
        "DATABASE_ENCRYPTION", "TDE", "COLUMN_ENCRYPTION"
    ],
    "Cloud": [
        "CLOUD_SECURITY", "AWS_KMS", "AZURE_KEY_VAULT", "GOOGLE_CLOUD_KMS"
    ],
    "Mobile": [
        "MOBILE_SECURITY", "ANDROID", "IOS"
    ],
    "IoT": [
        "IOT_SECURITY", "DEVICE_KEY", "SENSOR_KEY"
    ],
    "Blockchain": [
        "BLOCKCHAIN", "BITCOIN", "ETHEREUM", "CRYPTO_WALLET"
    ],
    "DevOps": [
        "DEVOPS_SECURITY", "CI_CD", "SECRETS_MANAGEMENT", "CONTAINER_SECURITY"
    ],
    "Security": [
        "POST_QUANTUM", "SYMMETRIC", "ASYMMETRIC", "OTP"
    ],
    "Compliance": [
        "FIPS_140_2", "PCI_DSS", "HIPAA", "GOVERNMENT_SECURITY"
    ]
}

def get_domain_key_types(domain: str) -> List[str]:
    """Retourne les types de clés pour un domaine IT spécifique"""
    return IT_DOMAINS_MAPPING.get(domain, [])

def get_all_it_domains() -> List[str]:
    """Retourne tous les domaines IT supportés"""
    return list(IT_DOMAINS_MAPPING.keys())
