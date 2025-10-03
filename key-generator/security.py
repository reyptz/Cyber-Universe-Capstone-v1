"""
Module de sécurité pour le générateur de clés
============================================

Implémente les bonnes pratiques de sécurité :
- CSPRNG (Cryptographically Secure PRNG)
- Protection des clés privées
- Validation des entrées
- Audit et logging
- Rate limiting
- Avertissements de sécurité
"""

import os
import time
import hashlib
import hmac
import secrets
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import json

# Cryptography imports
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class SecurityLevel(Enum):
    """Niveaux de sécurité"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecurityAudit:
    """Enregistrement d'audit de sécurité"""
    timestamp: datetime
    operation: str
    key_type: str
    algorithm: str
    fingerprint: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    success: bool = True
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = None


class SecurityManager:
    """Gestionnaire de sécurité pour le générateur de clés"""
    
    def __init__(self):
        self.audit_log = []
        self.rate_limits = {}
        self.security_warnings = []
        self.backend = default_backend()
        
        # Configuration de sécurité
        self.max_requests_per_minute = 10
        self.max_requests_per_hour = 100
        self.min_password_length = 12
        self.require_strong_password = True
        
        # Initialisation du logging
        self._setup_logging()
    
    def _setup_logging(self):
        """Configure le système de logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('key_generator_security.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('KeyGenerator.Security')
    
    def validate_password_strength(self, password: str) -> Tuple[bool, List[str]]:
        """Valide la force d'un mot de passe"""
        warnings = []
        
        if len(password) < self.min_password_length:
            warnings.append(f"⚠️ Mot de passe trop court (minimum {self.min_password_length} caractères)")
        
        if not any(c.isupper() for c in password):
            warnings.append("⚠️ Ajoutez des majuscules")
        
        if not any(c.islower() for c in password):
            warnings.append("⚠️ Ajoutez des minuscules")
        
        if not any(c.isdigit() for c in password):
            warnings.append("⚠️ Ajoutez des chiffres")
        
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            warnings.append("⚠️ Ajoutez des caractères spéciaux")
        
        # Vérification des patterns communs
        common_patterns = [
            "password", "123456", "qwerty", "admin", "user",
            "ghost", "cyber", "universe", "key", "secret"
        ]
        
        for pattern in common_patterns:
            if pattern.lower() in password.lower():
                warnings.append(f"⚠️ Évitez les mots communs comme '{pattern}'")
        
        is_strong = len(warnings) == 0
        return is_strong, warnings
    
    def check_rate_limit(self, ip_address: str) -> Tuple[bool, str]:
        """Vérifie les limites de taux"""
        now = time.time()
        
        if ip_address not in self.rate_limits:
            self.rate_limits[ip_address] = {
                'requests': [],
                'hourly_requests': []
            }
        
        rate_data = self.rate_limits[ip_address]
        
        # Nettoyage des anciennes requêtes
        rate_data['requests'] = [req_time for req_time in rate_data['requests'] if now - req_time < 60]
        rate_data['hourly_requests'] = [req_time for req_time in rate_data['hourly_requests'] if now - req_time < 3600]
        
        # Vérification des limites
        if len(rate_data['requests']) >= self.max_requests_per_minute:
            return False, f"Trop de requêtes (limite: {self.max_requests_per_minute}/minute)"
        
        if len(rate_data['hourly_requests']) >= self.max_requests_per_hour:
            return False, f"Trop de requêtes (limite: {self.max_requests_per_hour}/heure)"
        
        # Enregistrement de la requête
        rate_data['requests'].append(now)
        rate_data['hourly_requests'].append(now)
        
        return True, "OK"
    
    def generate_secure_random(self, length: int) -> bytes:
        """Génère des données aléatoires cryptographiquement sûres"""
        return secrets.token_bytes(length)
    
    def generate_secure_password(self, length: int = 16) -> str:
        """Génère un mot de passe sécurisé"""
        # Caractères autorisés
        uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        lowercase = "abcdefghijklmnopqrstuvwxyz"
        digits = "0123456789"
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Au moins un caractère de chaque type
        password = [
            secrets.choice(uppercase),
            secrets.choice(lowercase),
            secrets.choice(digits),
            secrets.choice(symbols)
        ]
        
        # Remplissage avec des caractères aléatoires
        all_chars = uppercase + lowercase + digits + symbols
        for _ in range(length - 4):
            password.append(secrets.choice(all_chars))
        
        # Mélange
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)
    
    def encrypt_sensitive_data(self, data: bytes, password: str) -> Dict[str, str]:
        """Chiffre des données sensibles"""
        # Génération du salt et de l'IV
        salt = self.generate_secure_random(32)
        iv = self.generate_secure_random(16)
        
        # Dérivation de la clé
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        key = kdf.derive(password.encode())
        
        # Chiffrement AES-256-CBC
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        
        # Padding PKCS7
        padding_length = 16 - (len(data) % 16)
        padded_data = data + bytes([padding_length] * padding_length)
        
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        return {
            "ciphertext": ciphertext.hex(),
            "salt": salt.hex(),
            "iv": iv.hex(),
            "algorithm": "AES-256-CBC",
            "kdf": "PBKDF2-SHA256",
            "iterations": 100000
        }
    
    def decrypt_sensitive_data(self, encrypted_data: Dict[str, str], password: str) -> bytes:
        """Déchiffre des données sensibles"""
        ciphertext = bytes.fromhex(encrypted_data["ciphertext"])
        salt = bytes.fromhex(encrypted_data["salt"])
        iv = bytes.fromhex(encrypted_data["iv"])
        
        # Dérivation de la clé
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        key = kdf.derive(password.encode())
        
        # Déchiffrement AES-256-CBC
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Suppression du padding PKCS7
        padding_length = padded_data[-1]
        data = padded_data[:-padding_length]
        
        return data
    
    def log_audit_event(self, operation: str, key_type: str, algorithm: str, 
                       fingerprint: str, ip_address: str = None, 
                       user_agent: str = None, success: bool = True, 
                       error_message: str = None, metadata: Dict[str, Any] = None):
        """Enregistre un événement d'audit"""
        audit = SecurityAudit(
            timestamp=datetime.utcnow(),
            operation=operation,
            key_type=key_type,
            algorithm=algorithm,
            fingerprint=fingerprint,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            error_message=error_message,
            metadata=metadata or {}
        )
        
        self.audit_log.append(audit)
        
        # Logging
        log_level = logging.INFO if success else logging.ERROR
        self.logger.log(
            log_level,
            f"Audit: {operation} | {key_type} | {algorithm} | {fingerprint} | Success: {success}"
        )
        
        # Sauvegarde dans un fichier d'audit
        self._save_audit_to_file(audit)
    
    def _save_audit_to_file(self, audit: SecurityAudit):
        """Sauvegarde l'audit dans un fichier"""
        audit_file = "key_generator_audit.json"
        audit_data = {
            "timestamp": audit.timestamp.isoformat(),
            "operation": audit.operation,
            "key_type": audit.key_type,
            "algorithm": audit.algorithm,
            "fingerprint": audit.fingerprint,
            "ip_address": audit.ip_address,
            "user_agent": audit.user_agent,
            "success": audit.success,
            "error_message": audit.error_message,
            "metadata": audit.metadata
        }
        
        try:
            with open(audit_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(audit_data) + "\n")
        except Exception as e:
            self.logger.error(f"Erreur sauvegarde audit: {e}")
    
    def get_security_warnings(self, key_type: str, algorithm: str) -> List[str]:
        """Retourne les avertissements de sécurité appropriés"""
        warnings = []
        
        # Avertissements généraux
        warnings.extend([
            "🔐 GARDEZ VOS CLÉS PRIVÉES SECRÈTES",
            "🔐 Ne partagez jamais vos clés privées",
            "🔐 Stockez vos clés dans un endroit sûr",
            "🔐 Utilisez un mot de passe fort pour protéger vos clés"
        ])
        
        # Avertissements spécifiques par type de clé
        if key_type == "BIP39":
            warnings.extend([
                "⚠️ GARDEZ CE MNÉMONIQUE SECRET",
                "⚠️ Ne le tapez jamais sur un ordinateur connecté à Internet",
                "⚠️ Perdre ce mnémonique = perte définitive des fonds",
                "⚠️ Stockez-le hors-ligne dans un endroit sûr"
            ])
        
        elif key_type == "TLS_CERT":
            warnings.extend([
                "🔒 Vérifiez la validité de votre certificat",
                "🔒 Configurez la rotation automatique",
                "🔒 Surveillez l'expiration"
            ])
        
        elif key_type == "SSH":
            warnings.extend([
                "🔑 Ajoutez votre clé publique à ~/.ssh/authorized_keys",
                "🔑 Protégez votre clé privée avec une passphrase",
                "🔑 Désactivez l'authentification par mot de passe"
            ])
        
        elif algorithm.startswith("RSA") and "1024" in algorithm:
            warnings.append("⚠️ RSA 1024 bits n'est plus sécurisé, utilisez au minimum 2048 bits")
        
        elif algorithm.startswith("AES") and "128" in algorithm:
            warnings.append("⚠️ AES-128 est acceptable mais AES-256 est recommandé")
        
        return warnings
    
    def validate_key_parameters(self, key_type: str, algorithm: str, key_size: int) -> Tuple[bool, List[str]]:
        """Valide les paramètres de génération de clé"""
        warnings = []
        
        # Validation des tailles de clés
        if key_type == "RSA":
            if key_size < 2048:
                warnings.append("⚠️ RSA < 2048 bits n'est plus recommandé")
            if key_size < 1024:
                return False, ["❌ RSA < 1024 bits est interdit"]
        
        elif key_type == "ECC":
            if key_size < 256:
                warnings.append("⚠️ ECC < 256 bits n'est pas recommandé")
        
        elif key_type == "AES":
            if key_size < 128:
                return False, ["❌ AES < 128 bits est interdit"]
            if key_size < 256:
                warnings.append("⚠️ AES-256 est recommandé pour la sécurité")
        
        # Validation des algorithmes
        deprecated_algorithms = ["MD5", "SHA1", "DES", "3DES"]
        for deprecated in deprecated_algorithms:
            if deprecated in algorithm:
                warnings.append(f"⚠️ {deprecated} est déprécié et non sécurisé")
        
        return True, warnings
    
    def generate_security_report(self) -> Dict[str, Any]:
        """Génère un rapport de sécurité"""
        now = datetime.utcnow()
        last_24h = now - timedelta(hours=24)
        
        # Statistiques des dernières 24h
        recent_audits = [audit for audit in self.audit_log if audit.timestamp > last_24h]
        
        total_requests = len(recent_audits)
        successful_requests = len([audit for audit in recent_audits if audit.success])
        failed_requests = total_requests - successful_requests
        
        # Types de clés générées
        key_types = {}
        for audit in recent_audits:
            key_types[audit.key_type] = key_types.get(audit.key_type, 0) + 1
        
        # Adresses IP
        ip_addresses = set(audit.ip_address for audit in recent_audits if audit.ip_address)
        
        return {
            "report_timestamp": now.isoformat(),
            "period": "24h",
            "total_requests": total_requests,
            "successful_requests": successful_requests,
            "failed_requests": failed_requests,
            "success_rate": (successful_requests / total_requests * 100) if total_requests > 0 else 0,
            "key_types_generated": key_types,
            "unique_ip_addresses": len(ip_addresses),
            "rate_limits_active": len(self.rate_limits),
            "security_warnings_count": len(self.security_warnings)
        }
    
    def cleanup_old_audits(self, days_to_keep: int = 30):
        """Nettoie les anciens audits"""
        cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
        self.audit_log = [audit for audit in self.audit_log if audit.timestamp > cutoff_date]
        
        # Nettoyage des rate limits
        now = time.time()
        for ip_address in list(self.rate_limits.keys()):
            rate_data = self.rate_limits[ip_address]
            rate_data['requests'] = [req_time for req_time in rate_data['requests'] if now - req_time < 3600]
            rate_data['hourly_requests'] = [req_time for req_time in rate_data['hourly_requests'] if now - req_time < 86400]
            
            # Suppression si pas d'activité récente
            if not rate_data['requests'] and not rate_data['hourly_requests']:
                del self.rate_limits[ip_address]
    
    def get_security_recommendations(self) -> List[str]:
        """Retourne les recommandations de sécurité"""
        return [
            "🔐 Utilisez des mots de passe forts (minimum 12 caractères)",
            "🔐 Activez l'authentification à deux facteurs (2FA)",
            "🔐 Chiffrez vos clés privées avec un mot de passe",
            "🔐 Stockez vos clés dans un coffre-fort numérique (HSM)",
            "🔐 Implémentez la rotation automatique des clés",
            "🔐 Surveillez l'utilisation de vos clés",
            "🔐 Sauvegardez vos clés de manière sécurisée",
            "🔐 Utilisez des canaux sécurisés pour transmettre les clés",
            "🔐 Révoquez immédiatement les clés compromises",
            "🔐 Respectez les bonnes pratiques de votre organisation"
        ]


class SecurityValidator:
    """Validateur de sécurité pour les entrées utilisateur"""
    
    @staticmethod
    def validate_common_name(common_name: str) -> Tuple[bool, str]:
        """Valide un nom commun pour certificat"""
        if not common_name or len(common_name.strip()) == 0:
            return False, "Le nom commun ne peut pas être vide"
        
        if len(common_name) > 64:
            return False, "Le nom commun ne peut pas dépasser 64 caractères"
        
        # Caractères interdits
        forbidden_chars = ['<', '>', '"', "'", '&', ';', '(', ')', '|', '`', '$']
        for char in forbidden_chars:
            if char in common_name:
                return False, f"Caractère interdit dans le nom commun: {char}"
        
        return True, "OK"
    
    @staticmethod
    def validate_email(email: str) -> Tuple[bool, str]:
        """Valide une adresse email"""
        if not email:
            return True, "OK"  # Email optionnel
        
        import re
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not re.match(email_pattern, email):
            return False, "Format d'email invalide"
        
        if len(email) > 254:
            return False, "Email trop long"
        
        return True, "OK"
    
    @staticmethod
    def validate_key_size(key_type: str, key_size: int) -> Tuple[bool, str]:
        """Valide la taille d'une clé"""
        if key_type == "RSA":
            if key_size < 1024:
                return False, "RSA < 1024 bits est interdit"
            if key_size < 2048:
                return False, "RSA < 2048 bits n'est pas recommandé"
            if key_size > 8192:
                return False, "RSA > 8192 bits peut causer des problèmes de performance"
        
        elif key_type == "ECC":
            if key_size < 224:
                return False, "ECC < 224 bits n'est pas sécurisé"
            if key_size > 521:
                return False, "ECC > 521 bits n'est pas supporté"
        
        elif key_type == "AES":
            if key_size not in [128, 192, 256]:
                return False, "AES ne supporte que 128, 192 ou 256 bits"
        
        return True, "OK"
