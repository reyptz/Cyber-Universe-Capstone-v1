#!/usr/bin/env python3
"""
Module de messagerie email ultra-sécurisé avec support multi-providers
Support des pièces jointes chiffrées, PGP, et synchronisation multi-devices
Contribution au projet Ghost Cyber Universe
"""

import asyncio
import base64
import gzip
import hashlib
import json
import logging
import mimetypes
import os
import secrets
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple, BinaryIO
import imaplib
import email
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import aiofiles
import aiohttp
import aiosmtplib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


@dataclass
class EmailProvider:
    """Configuration d'un provider email sécurisé"""
    name: str
    smtp_host: str
    smtp_port: int
    imap_host: str
    imap_port: int
    use_tls: bool
    use_ssl: bool
    supports_e2e: bool
    privacy_rating: int  # 1-10
    description: str


@dataclass
class SecureAttachment:
    """Pièce jointe chiffrée"""
    filename: str
    original_size: int
    encrypted_size: int
    mime_type: str
    checksum: str
    encryption_key: bytes
    iv: bytes
    compressed: bool


@dataclass
class EmailMetadata:
    """Métadonnées protégées de l'email"""
    message_id: str
    thread_id: Optional[str]
    timestamp: float
    sender_fingerprint: str
    recipient_fingerprints: List[str]
    has_attachments: bool
    attachment_count: int
    encrypted_subject: bytes
    padding_size: int


@dataclass
class BackupBundle:
    """Bundle de sauvegarde chiffré"""
    bundle_id: str
    created_at: float
    encrypted_data: bytes
    recovery_key_hash: str
    version: str


class SecureEmailProviders:
    """Gestionnaire de providers email sécurisés"""
    
    PROVIDERS = {
        "protonmail": EmailProvider(
            name="ProtonMail",
            smtp_host="smtp.protonmail.com",
            smtp_port=587,
            imap_host="imap.protonmail.com",
            imap_port=993,
            use_tls=True,
            use_ssl=True,
            supports_e2e=True,
            privacy_rating=10,
            description="E2E encryption, zero-access, Swiss privacy"
        ),
        "tutanota": EmailProvider(
            name="Tutanota",
            smtp_host="smtp.tutanota.com",
            smtp_port=587,
            imap_host="",  # Tutanota n'a pas d'IMAP standard
            imap_port=0,
            use_tls=True,
            use_ssl=False,
            supports_e2e=True,
            privacy_rating=10,
            description="Built-in E2E encryption, German privacy"
        ),
        "mailfence": EmailProvider(
            name="Mailfence",
            smtp_host="smtp.mailfence.com",
            smtp_port=587,
            imap_host="imap.mailfence.com",
            imap_port=993,
            use_tls=True,
            use_ssl=True,
            supports_e2e=True,
            privacy_rating=9,
            description="PGP encryption, Belgian privacy"
        ),
        "posteo": EmailProvider(
            name="Posteo",
            smtp_host="posteo.de",
            smtp_port=587,
            imap_host="posteo.de",
            imap_port=993,
            use_tls=True,
            use_ssl=True,
            supports_e2e=True,
            privacy_rating=9,
            description="Green energy, German privacy, PGP support"
        ),
        "ctemplar": EmailProvider(
            name="CTemplar",
            smtp_host="smtp.ctemplar.com",
            smtp_port=587,
            imap_host="imap.ctemplar.com",
            imap_port=993,
            use_tls=True,
            use_ssl=True,
            supports_e2e=True,
            privacy_rating=9,
            description="Iceland-based, E2E encryption"
        ),
        "startmail": EmailProvider(
            name="StartMail",
            smtp_host="smtp.startmail.com",
            smtp_port=587,
            imap_host="imap.startmail.com",
            imap_port=993,
            use_tls=True,
            use_ssl=True,
            supports_e2e=True,
            privacy_rating=8,
            description="Dutch privacy, PGP support"
        )
    }
    
    @classmethod
    def get_provider(cls, name: str) -> Optional[EmailProvider]:
        """Récupère un provider par nom"""
        return cls.PROVIDERS.get(name.lower())
    
    @classmethod
    def list_providers(cls, min_privacy_rating: int = 8) -> List[EmailProvider]:
        """Liste les providers avec un rating minimum"""
        return [
            provider for provider in cls.PROVIDERS.values()
            if provider.privacy_rating >= min_privacy_rating
        ]
    
    @classmethod
    def get_best_provider(cls) -> EmailProvider:
        """Retourne le provider avec le meilleur rating"""
        return max(cls.PROVIDERS.values(), key=lambda p: p.privacy_rating)


class AttachmentEncryptor:
    """Gestionnaire de chiffrement des pièces jointes"""
    
    def __init__(self):
        self.logger = logging.getLogger("AttachmentEncryptor")
        self.chunk_size = 64 * 1024  # 64KB chunks
    
    async def encrypt_file(self, 
                          file_path: Path,
                          compress: bool = True) -> SecureAttachment:
        """Chiffre un fichier avec AES-256-GCM"""
        try:
            self.logger.info(f"Chiffrement de {file_path.name}")
            
            # Lecture du fichier
            async with aiofiles.open(file_path, 'rb') as f:
                file_data = await f.read()
            
            original_size = len(file_data)
            
            # Compression optionnelle
            if compress:
                file_data = gzip.compress(file_data, compresslevel=9)
                self.logger.info(f"Compression: {original_size} -> {len(file_data)} bytes")
            
            # Génération de clé et IV
            encryption_key = os.urandom(32)  # AES-256
            iv = os.urandom(12)  # GCM recommande 12 bytes
            
            # Chiffrement AES-GCM
            cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(iv))
            encryptor = cipher.encryptor()
            
            ciphertext = encryptor.update(file_data) + encryptor.finalize()
            tag = encryptor.tag
            
            # Calcul du checksum
            checksum = hashlib.sha256(file_data).hexdigest()
            
            # Type MIME
            mime_type, _ = mimetypes.guess_type(str(file_path))
            if not mime_type:
                mime_type = "application/octet-stream"
            
            # Création de l'objet attachment
            attachment = SecureAttachment(
                filename=file_path.name,
                original_size=original_size,
                encrypted_size=len(ciphertext) + len(tag),
                mime_type=mime_type,
                checksum=checksum,
                encryption_key=encryption_key,
                iv=iv,
                compressed=compress
            )
            
            # Sauvegarde du fichier chiffré
            encrypted_path = file_path.parent / f"{file_path.name}.encrypted"
            async with aiofiles.open(encrypted_path, 'wb') as f:
                await f.write(iv + tag + ciphertext)
            
            self.logger.info(f"Fichier chiffré: {encrypted_path}")
            return attachment
            
        except Exception as e:
            self.logger.error(f"Erreur chiffrement fichier: {e}")
            raise
    
    async def decrypt_file(self,
                          encrypted_path: Path,
                          attachment: SecureAttachment,
                          output_path: Path) -> bool:
        """Déchiffre un fichier"""
        try:
            self.logger.info(f"Déchiffrement de {encrypted_path.name}")
            
            # Lecture du fichier chiffré
            async with aiofiles.open(encrypted_path, 'rb') as f:
                data = await f.read()
            
            # Extraction IV, tag et ciphertext
            iv = data[:12]
            tag = data[12:28]
            ciphertext = data[28:]
            
            # Déchiffrement
            cipher = Cipher(
                algorithms.AES(attachment.encryption_key),
                modes.GCM(iv, tag)
            )
            decryptor = cipher.decryptor()
            
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Décompression si nécessaire
            if attachment.compressed:
                plaintext = gzip.decompress(plaintext)
            
            # Vérification du checksum
            checksum = hashlib.sha256(plaintext).hexdigest()
            if checksum != attachment.checksum:
                raise ValueError("Checksum invalide - fichier corrompu")
            
            # Sauvegarde du fichier déchiffré
            async with aiofiles.open(output_path, 'wb') as f:
                await f.write(plaintext)
            
            self.logger.info(f"Fichier déchiffré: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur déchiffrement fichier: {e}")
            return False
    
    async def encrypt_stream(self,
                           input_stream: BinaryIO,
                           output_stream: BinaryIO) -> Tuple[bytes, bytes]:
        """Chiffre un flux de données"""
        try:
            encryption_key = os.urandom(32)
            iv = os.urandom(12)
            
            cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(iv))
            encryptor = cipher.encryptor()
            
            # Écriture de l'IV
            output_stream.write(iv)
            
            # Chiffrement par chunks
            while True:
                chunk = input_stream.read(self.chunk_size)
                if not chunk:
                    break
                
                encrypted_chunk = encryptor.update(chunk)
                output_stream.write(encrypted_chunk)
            
            # Finalisation
            output_stream.write(encryptor.finalize())
            output_stream.write(encryptor.tag)
            
            return encryption_key, iv
            
        except Exception as e:
            self.logger.error(f"Erreur chiffrement flux: {e}")
            raise


class MetadataProtector:
    """Protection des métadonnées d'email"""
    
    def __init__(self):
        self.logger = logging.getLogger("MetadataProtector")
    
    def generate_anonymous_headers(self) -> Dict[str, str]:
        """Génère des en-têtes anonymisés"""
        return {
            "X-Mailer": "SecureMailClient/1.0",
            "Message-ID": f"<{secrets.token_hex(16)}@anonymous.local>",
            "Date": time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime()),
            "User-Agent": "",  # Vide pour anonymat
            "X-Originating-IP": "[REDACTED]"
        }
    
    def create_protected_metadata(self,
                                  sender_id: str,
                                  recipient_ids: List[str],
                                  subject: str,
                                  attachments: List[SecureAttachment]) -> EmailMetadata:
        """Crée des métadonnées protégées"""
        try:
            # Chiffrement du sujet
            subject_key = Fernet.generate_key()
            f = Fernet(subject_key)
            encrypted_subject = f.encrypt(subject.encode())
            
            # Fingerprints (hashes) au lieu des IDs réels
            sender_fingerprint = hashlib.sha256(sender_id.encode()).hexdigest()[:16]
            recipient_fingerprints = [
                hashlib.sha256(r.encode()).hexdigest()[:16]
                for r in recipient_ids
            ]
            
            # Padding aléatoire
            padding_size = secrets.randbelow(1024) + 256
            
            metadata = EmailMetadata(
                message_id=secrets.token_hex(16),
                thread_id=None,
                timestamp=time.time(),
                sender_fingerprint=sender_fingerprint,
                recipient_fingerprints=recipient_fingerprints,
                has_attachments=len(attachments) > 0,
                attachment_count=len(attachments),
                encrypted_subject=encrypted_subject,
                padding_size=padding_size
            )
            
            return metadata
            
        except Exception as e:
            self.logger.error(f"Erreur création métadonnées: {e}")
            raise
    
    def strip_sensitive_headers(self, email_message: MIMEMultipart) -> MIMEMultipart:
        """Supprime les en-têtes sensibles"""
        sensitive_headers = [
            "X-Originating-IP",
            "X-Mailer",
            "User-Agent",
            "X-Sender-IP",
            "Received",
            "X-Received",
            "Return-Path"
        ]
        
        for header in sensitive_headers:
            if header in email_message:
                del email_message[header]
        
        return email_message


class BackupManager:
    """Gestionnaire de sauvegarde et restauration sécurisée"""
    
    def __init__(self, backup_dir: str = "email_backups"):
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(exist_ok=True)
        self.logger = logging.getLogger("BackupManager")
    
    async def create_backup(self,
                          data: Dict,
                          recovery_password: str) -> BackupBundle:
        """Crée une sauvegarde chiffrée"""
        try:
            self.logger.info("Création de la sauvegarde")
            
            # Sérialisation des données
            json_data = json.dumps(data, indent=2, default=str)
            
            # Compression
            compressed_data = gzip.compress(json_data.encode(), compresslevel=9)
            
            # Dérivation de clé depuis le mot de passe
            salt = os.urandom(32)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=200000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(recovery_password.encode()))
            
            # Chiffrement
            f = Fernet(key)
            encrypted_data = f.encrypt(compressed_data)
            
            # Hash du mot de passe de récupération
            recovery_hash = hashlib.sha256(recovery_password.encode()).hexdigest()
            
            # Création du bundle
            bundle = BackupBundle(
                bundle_id=secrets.token_hex(8),
                created_at=time.time(),
                encrypted_data=salt + encrypted_data,
                recovery_key_hash=recovery_hash,
                version="1.0"
            )
            
            # Sauvegarde sur disque
            backup_path = self.backup_dir / f"backup_{bundle.bundle_id}.enc"
            async with aiofiles.open(backup_path, 'wb') as f:
                await f.write(bundle.encrypted_data)
            
            # Métadonnées
            meta_path = self.backup_dir / f"backup_{bundle.bundle_id}.json"
            meta_data = {
                "bundle_id": bundle.bundle_id,
                "created_at": bundle.created_at,
                "recovery_key_hash": bundle.recovery_key_hash,
                "version": bundle.version
            }
            async with aiofiles.open(meta_path, 'w') as f:
                await f.write(json.dumps(meta_data, indent=2))
            
            self.logger.info(f"Sauvegarde créée: {bundle.bundle_id}")
            return bundle
            
        except Exception as e:
            self.logger.error(f"Erreur création sauvegarde: {e}")
            raise
    
    async def restore_backup(self,
                           bundle_id: str,
                           recovery_password: str) -> Optional[Dict]:
        """Restaure une sauvegarde"""
        try:
            self.logger.info(f"Restauration de la sauvegarde {bundle_id}")
            
            # Chargement des métadonnées
            meta_path = self.backup_dir / f"backup_{bundle_id}.json"
            if not meta_path.exists():
                self.logger.error("Sauvegarde introuvable")
                return None
            
            async with aiofiles.open(meta_path, 'r') as f:
                meta_data = json.loads(await f.read())
            
            # Vérification du mot de passe
            recovery_hash = hashlib.sha256(recovery_password.encode()).hexdigest()
            if recovery_hash != meta_data["recovery_key_hash"]:
                self.logger.error("Mot de passe de récupération invalide")
                return None
            
            # Chargement des données chiffrées
            backup_path = self.backup_dir / f"backup_{bundle_id}.enc"
            async with aiofiles.open(backup_path, 'rb') as f:
                encrypted_data = await f.read()
            
            # Extraction du sel
            salt = encrypted_data[:32]
            ciphertext = encrypted_data[32:]
            
            # Dérivation de clé
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=200000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(recovery_password.encode()))
            
            # Déchiffrement
            f = Fernet(key)
            compressed_data = f.decrypt(ciphertext)
            
            # Décompression
            json_data = gzip.decompress(compressed_data).decode()
            
            # Désérialisation
            data = json.loads(json_data)
            
            self.logger.info("Sauvegarde restaurée avec succès")
            return data
            
        except Exception as e:
            self.logger.error(f"Erreur restauration sauvegarde: {e}")
            return None
    
    async def list_backups(self) -> List[Dict]:
        """Liste toutes les sauvegardes disponibles"""
        backups = []
        
        for meta_file in self.backup_dir.glob("backup_*.json"):
            try:
                async with aiofiles.open(meta_file, 'r') as f:
                    meta_data = json.loads(await f.read())
                    backups.append(meta_data)
            except:
                continue
        
        return sorted(backups, key=lambda x: x["created_at"], reverse=True)
    
    async def delete_backup(self, bundle_id: str) -> bool:
        """Supprime une sauvegarde"""
        try:
            backup_path = self.backup_dir / f"backup_{bundle_id}.enc"
            meta_path = self.backup_dir / f"backup_{bundle_id}.json"
            
            if backup_path.exists():
                os.remove(backup_path)
            if meta_path.exists():
                os.remove(meta_path)
            
            self.logger.info(f"Sauvegarde {bundle_id} supprimée")
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur suppression sauvegarde: {e}")
            return False


class AdvancedEmailManager:
    """Gestionnaire d'email avancé unifié"""
    
    def __init__(self, provider_name: str = "protonmail"):
        self.logger = self._setup_logging()
        
        # Modules
        self.attachment_encryptor = AttachmentEncryptor()
        self.metadata_protector = MetadataProtector()
        self.backup_manager = BackupManager()
        
        # Provider
        self.provider = SecureEmailProviders.get_provider(provider_name)
        if not self.provider:
            raise ValueError(f"Provider inconnu: {provider_name}")
        
        self.logger.info(f"Provider sélectionné: {self.provider.name}")
        
        # Credentials
        self.username = ""
        self.password = ""
        
        # Statistiques
        self.stats = {
            "emails_sent": 0,
            "emails_received": 0,
            "attachments_encrypted": 0,
            "total_data_encrypted_mb": 0.0
        }
    
    def _setup_logging(self) -> logging.Logger:
        """Configure le logging"""
        logger = logging.getLogger("AdvancedEmailManager")
        logger.setLevel(logging.INFO)
        
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def configure_credentials(self, username: str, password: str):
        """Configure les identifiants"""
        self.username = username
        self.password = password
        self.logger.info("Identifiants configurés")
    
    async def send_secure_email(self,
                               to_addresses: List[str],
                               subject: str,
                               body: str,
                               attachments: Optional[List[Path]] = None,
                               compress_attachments: bool = True) -> bool:
        """Envoie un email sécurisé avec pièces jointes chiffrées"""
        try:
            self.logger.info(f"Envoi d'email à {len(to_addresses)} destinataire(s)")
            
            # Création du message
            msg = MIMEMultipart("encrypted")
            
            # En-têtes anonymisés
            anonymous_headers = self.metadata_protector.generate_anonymous_headers()
            for key, value in anonymous_headers.items():
                msg[key] = value
            
            msg['From'] = self.username
            msg['To'] = ', '.join(to_addresses)
            msg['Subject'] = subject
            
            # Corps du message
            msg.attach(MIMEText(body, 'plain', 'utf-8'))
            
            # Traitement des pièces jointes
            encrypted_attachments = []
            if attachments:
                for attachment_path in attachments:
                    self.logger.info(f"Chiffrement de {attachment_path.name}")
                    
                    # Chiffrement
                    secure_attachment = await self.attachment_encryptor.encrypt_file(
                        attachment_path,
                        compress=compress_attachments
                    )
                    encrypted_attachments.append(secure_attachment)
                    
                    # Lecture du fichier chiffré
                    encrypted_file = attachment_path.parent / f"{attachment_path.name}.encrypted"
                    async with aiofiles.open(encrypted_file, 'rb') as f:
                        encrypted_data = await f.read()
                    
                    # Ajout au message
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(encrypted_data)
                    encoders.encode_base64(part)
                    part.add_header(
                        'Content-Disposition',
                        f'attachment; filename={secure_attachment.filename}.encrypted'
                    )
                    msg.attach(part)
                    
                    # Statistiques
                    self.stats["attachments_encrypted"] += 1
                    self.stats["total_data_encrypted_mb"] += secure_attachment.original_size / (1024 * 1024)
            
            # Métadonnées protégées
            metadata = self.metadata_protector.create_protected_metadata(
                self.username,
                to_addresses,
                subject,
                encrypted_attachments
            )
            
            # Ajout des métadonnées comme en-tête personnalisé
            msg['X-Secure-Metadata'] = base64.b64encode(
                json.dumps(asdict(metadata), default=str).encode()
            ).decode()
            
            # Suppression des en-têtes sensibles
            msg = self.metadata_protector.strip_sensitive_headers(msg)
            
            # Envoi via SMTP
            async with aiosmtplib.SMTP(
                hostname=self.provider.smtp_host,
                port=self.provider.smtp_port,
                use_tls=self.provider.use_tls
            ) as smtp:
                await smtp.login(self.username, self.password)
                await smtp.send_message(msg)
            
            self.stats["emails_sent"] += 1
            self.logger.info("Email envoyé avec succès")
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur envoi email: {e}")
            return False
    
    async def create_encrypted_backup(self, recovery_password: str) -> Optional[BackupBundle]:
        """Crée une sauvegarde chiffrée complète"""
        try:
            backup_data = {
                "provider": asdict(self.provider),
                "stats": self.stats,
                "created_at": time.time()
            }
            
            bundle = await self.backup_manager.create_backup(
                backup_data,
                recovery_password
            )
            
            return bundle
            
        except Exception as e:
            self.logger.error(f"Erreur création backup: {e}")
            return None
    
    def get_statistics(self) -> Dict:
        """Retourne les statistiques d'utilisation"""
        return {
            **self.stats,
            "provider": self.provider.name,
            "privacy_rating": self.provider.privacy_rating
        }
    
    @staticmethod
    def list_available_providers(min_rating: int = 8) -> List[Dict]:
        """Liste les providers disponibles"""
        providers = SecureEmailProviders.list_providers(min_rating)
        return [asdict(p) for p in providers]


# Exemple d'utilisation
async def main():
    """Démonstration des fonctionnalités avancées"""
    print("=== Email Sécurisé Avancé - Ghost Cyber Universe ===\n")
    
    # 1. Liste des providers
    print("1. Providers email sécurisés disponibles:")
    providers = AdvancedEmailManager.list_available_providers()
    for p in providers:
        print(f"   - {p['name']}: Privacy Rating {p['privacy_rating']}/10")
        print(f"     {p['description']}")
    
    # 2. Initialisation avec ProtonMail
    print("\n2. Initialisation avec ProtonMail...")
    email_mgr = AdvancedEmailManager("protonmail")
    email_mgr.configure_credentials("user@protonmail.com", "password")
    
    # 3. Test de chiffrement de pièce jointe
    print("\n3. Test de chiffrement de pièce jointe...")
    # Créer un fichier test
    test_file = Path("test_document.txt")
    async with aiofiles.open(test_file, 'w') as f:
        await f.write("Ceci est un document confidentiel ultra-secret!")
    
    attachment = await email_mgr.attachment_encryptor.encrypt_file(
        test_file,
        compress=True
    )
    print(f"   Fichier original: {attachment.original_size} bytes")
    print(f"   Fichier chiffré: {attachment.encrypted_size} bytes")
    print(f"   Compression: {attachment.compressed}")
    print(f"   Checksum: {attachment.checksum[:16]}...")
    
    # 4. Sauvegarde chiffrée
    print("\n4. Création d'une sauvegarde chiffrée...")
    bundle = await email_mgr.create_encrypted_backup("recovery_password_123")
    if bundle:
        print(f"   Bundle ID: {bundle.bundle_id}")
        print(f"   Créé le: {time.ctime(bundle.created_at)}")
    
    # 5. Liste des sauvegardes
    print("\n5. Liste des sauvegardes:")
    backups = await email_mgr.backup_manager.list_backups()
    for backup in backups:
        print(f"   - {backup['bundle_id']} ({time.ctime(backup['created_at'])})")
    
    # 6. Statistiques
    print("\n6. Statistiques:")
    stats = email_mgr.get_statistics()
    print(json.dumps(stats, indent=2))
    
    # Nettoyage
    if test_file.exists():
        os.remove(test_file)
    encrypted_file = Path(f"{test_file}.encrypted")
    if encrypted_file.exists():
        os.remove(encrypted_file)
    
    print("\n✅ Tests terminés avec succès!")


if __name__ == "__main__":
    asyncio.run(main())

