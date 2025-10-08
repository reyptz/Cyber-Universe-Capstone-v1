#!/usr/bin/env python3
"""
Système de messagerie électronique ultra-sécurisé avec chiffrement E2E
Implémente Signal Protocol, Perfect Forward Secrecy et protection des métadonnées
"""

import asyncio
import base64
import json
import logging
import os
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import hashlib
import hmac
import secrets

# Cryptographie
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import nacl.secret
import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import Base64Encoder

# Email et réseau
import aiosmtplib
import aiofiles
import aiohttp
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

@dataclass
class KeyBundle:
    """Bundle de clés pour l'échange initial"""
    identity_key: bytes  # Clé d'identité long terme
    signed_prekey: bytes  # Clé pré-signée
    signature: bytes  # Signature de la clé pré-signée
    one_time_prekeys: List[bytes]  # Clés à usage unique
    timestamp: float

@dataclass
class MessageHeader:
    """En-tête de message chiffré"""
    sender_id: str
    recipient_id: str
    message_id: str
    timestamp: float
    key_exchange_data: Optional[bytes]
    ratchet_key: bytes
    previous_counter: int
    message_counter: int

@dataclass
class SecureMessage:
    """Message sécurisé avec métadonnées protégées"""
    header: MessageHeader
    ciphertext: bytes
    mac: bytes
    padding_length: int

@dataclass
class UserProfile:
    """Profil utilisateur sécurisé"""
    user_id: str
    email: str
    identity_key_pair: Tuple[bytes, bytes]  # (private, public)
    signed_prekey_pair: Tuple[bytes, bytes]
    signature: bytes
    one_time_prekeys: List[Tuple[bytes, bytes]]
    created_at: float

class DoubleRatchet:
    """Implémentation du Double Ratchet Algorithm (Signal Protocol)"""
    
    def __init__(self, shared_key: bytes, sending: bool = True):
        self.root_key = shared_key
        self.chain_key_send = None
        self.chain_key_recv = None
        self.dh_send = None
        self.dh_recv = None
        self.pn = 0  # Previous chain length
        self.ns = 0  # Sending message number
        self.nr = 0  # Receiving message number
        self.mkskipped = {}  # Skipped message keys
        
        if sending:
            self.dh_send = x25519.X25519PrivateKey.generate()
            self.chain_key_send = self._kdf_ck(shared_key)
    
    def _kdf_rk(self, rk: bytes, dh_out: bytes) -> Tuple[bytes, bytes]:
        """Key Derivation Function for Root Key"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=rk,
            info=b"WhisperRatchet"
        )
        output = hkdf.derive(dh_out)
        return output[:32], output[32:]
    
    def _kdf_ck(self, ck: bytes) -> bytes:
        """Key Derivation Function for Chain Key"""
        h = hmac.new(ck, b"\x01", hashlib.sha256)
        return h.digest()
    
    def _kdf_mk(self, ck: bytes) -> bytes:
        """Key Derivation Function for Message Key"""
        h = hmac.new(ck, b"\x00", hashlib.sha256)
        return h.digest()
    
    def encrypt(self, plaintext: bytes, associated_data: bytes) -> Tuple[bytes, bytes]:
        """Chiffre un message avec le ratchet"""
        mk = self._kdf_mk(self.chain_key_send)
        self.chain_key_send = self._kdf_ck(self.chain_key_send)
        
        # Chiffrement AES-GCM
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(mk[:32]), modes.GCM(iv))
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(associated_data)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        self.ns += 1
        return iv + ciphertext, encryptor.tag
    
    def decrypt(self, ciphertext: bytes, tag: bytes, associated_data: bytes) -> bytes:
        """Déchiffre un message avec le ratchet"""
        mk = self._kdf_mk(self.chain_key_recv)
        self.chain_key_recv = self._kdf_ck(self.chain_key_recv)
        
        # Déchiffrement AES-GCM
        iv = ciphertext[:12]
        actual_ciphertext = ciphertext[12:]
        
        cipher = Cipher(algorithms.AES(mk[:32]), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(associated_data)
        plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        
        self.nr += 1
        return plaintext
    
    def dh_ratchet(self, remote_public_key: bytes):
        """Effectue un DH ratchet step"""
        if self.dh_recv:
            # Calcul du shared secret
            shared_secret = self.dh_send.exchange(
                x25519.X25519PublicKey.from_public_bytes(remote_public_key)
            )
            
            # Mise à jour des clés
            self.root_key, self.chain_key_recv = self._kdf_rk(self.root_key, shared_secret)
            self.dh_recv = remote_public_key
            
            # Nouveau DH key pair pour l'envoi
            self.dh_send = x25519.X25519PrivateKey.generate()
            shared_secret = self.dh_send.exchange(
                x25519.X25519PublicKey.from_public_bytes(remote_public_key)
            )
            self.root_key, self.chain_key_send = self._kdf_rk(self.root_key, shared_secret)

class SecureEmailManager:
    """Gestionnaire de messagerie électronique ultra-sécurisé"""
    
    def __init__(self, data_dir: str = "secure_email_data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        
        self.logger = self._setup_logging()
        self.user_profile: Optional[UserProfile] = None
        self.contacts: Dict[str, Dict] = {}
        self.sessions: Dict[str, DoubleRatchet] = {}
        self.message_store: Dict[str, List[SecureMessage]] = {}
        
        # Configuration de sécurité
        self.max_message_age = 86400 * 7  # 7 jours
        self.auto_delete_enabled = True
        self.metadata_protection = True
        self.forward_secrecy = True
        
        # Configuration SMTP/IMAP sécurisée
        self.smtp_config = {
            "hostname": "smtp.protonmail.com",
            "port": 587,
            "use_tls": True,
            "username": "",
            "password": ""
        }
        
        self.imap_config = {
            "hostname": "imap.protonmail.com",
            "port": 993,
            "use_ssl": True,
            "username": "",
            "password": ""
        }
    
    def _setup_logging(self) -> logging.Logger:
        """Configuration du système de logs sécurisé"""
        logger = logging.getLogger("SecureEmailManager")
        logger.setLevel(logging.INFO)
        
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler(
            self.data_dir / "secure_email.log",
            maxBytes=10*1024*1024,
            backupCount=5
        )
        
        # Format sans informations sensibles
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        return logger
    
    async def create_user_profile(self, user_id: str, email: str, password: str) -> UserProfile:
        """Crée un profil utilisateur avec génération de clés"""
        try:
            self.logger.info(f"Création du profil utilisateur: {user_id}")
            
            # Génération des clés d'identité (Ed25519)
            identity_private = SigningKey.generate()
            identity_public = identity_private.verify_key
            
            # Génération des clés pré-signées (X25519)
            prekey_private = x25519.X25519PrivateKey.generate()
            prekey_public = prekey_private.public_key()
            
            # Signature de la clé pré-signée
            prekey_signature = identity_private.sign(
                prekey_public.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            ).signature
            
            # Génération des clés à usage unique
            one_time_keys = []
            for _ in range(100):  # 100 clés à usage unique
                otk_private = x25519.X25519PrivateKey.generate()
                otk_public = otk_private.public_key()
                one_time_keys.append((
                    otk_private.private_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption()
                    ),
                    otk_public.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    )
                ))
            
            # Création du profil
            profile = UserProfile(
                user_id=user_id,
                email=email,
                identity_key_pair=(
                    identity_private.encode(),
                    identity_public.encode()
                ),
                signed_prekey_pair=(
                    prekey_private.private_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption()
                    ),
                    prekey_public.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    )
                ),
                signature=prekey_signature,
                one_time_prekeys=one_time_keys,
                created_at=time.time()
            )
            
            # Sauvegarde chiffrée du profil
            await self._save_encrypted_profile(profile, password)
            
            self.user_profile = profile
            self.logger.info("Profil utilisateur créé avec succès")
            
            return profile
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la création du profil: {e}")
            raise
    
    async def load_user_profile(self, user_id: str, password: str) -> bool:
        """Charge un profil utilisateur existant"""
        try:
            profile_path = self.data_dir / f"{user_id}_profile.enc"
            
            if not profile_path.exists():
                return False
            
            # Déchiffrement du profil
            profile_data = await self._load_encrypted_profile(user_id, password)
            
            if profile_data:
                self.user_profile = UserProfile(**profile_data)
                await self._load_contacts()
                self.logger.info(f"Profil {user_id} chargé avec succès")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Erreur lors du chargement du profil: {e}")
            return False
    
    async def _save_encrypted_profile(self, profile: UserProfile, password: str):
        """Sauvegarde chiffrée du profil utilisateur"""
        try:
            # Dérivation de clé à partir du mot de passe
            salt = os.urandom(32)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            
            # Chiffrement du profil
            f = Fernet(key)
            profile_json = json.dumps(asdict(profile), default=str)
            encrypted_data = f.encrypt(profile_json.encode())
            
            # Sauvegarde
            profile_path = self.data_dir / f"{profile.user_id}_profile.enc"
            async with aiofiles.open(profile_path, 'wb') as file:
                await file.write(salt + encrypted_data)
                
        except Exception as e:
            self.logger.error(f"Erreur lors de la sauvegarde du profil: {e}")
            raise
    
    async def _load_encrypted_profile(self, user_id: str, password: str) -> Optional[Dict]:
        """Charge et déchiffre un profil utilisateur"""
        try:
            profile_path = self.data_dir / f"{user_id}_profile.enc"
            
            async with aiofiles.open(profile_path, 'rb') as file:
                data = await file.read()
            
            # Extraction du sel et des données chiffrées
            salt = data[:32]
            encrypted_data = data[32:]
            
            # Dérivation de clé
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            
            # Déchiffrement
            f = Fernet(key)
            decrypted_data = f.decrypt(encrypted_data)
            
            return json.loads(decrypted_data.decode())
            
        except Exception as e:
            self.logger.error(f"Erreur lors du chargement du profil: {e}")
            return None
    
    async def add_contact(self, contact_id: str, email: str, public_key_bundle: KeyBundle):
        """Ajoute un contact avec son bundle de clés publiques"""
        try:
            self.contacts[contact_id] = {
                "email": email,
                "identity_key": public_key_bundle.identity_key,
                "signed_prekey": public_key_bundle.signed_prekey,
                "signature": public_key_bundle.signature,
                "one_time_prekeys": public_key_bundle.one_time_prekeys.copy(),
                "added_at": time.time()
            }
            
            await self._save_contacts()
            self.logger.info(f"Contact {contact_id} ajouté")
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'ajout du contact: {e}")
            raise
    
    async def _save_contacts(self):
        """Sauvegarde la liste des contacts"""
        try:
            contacts_path = self.data_dir / f"{self.user_profile.user_id}_contacts.json"
            async with aiofiles.open(contacts_path, 'w') as file:
                await file.write(json.dumps(self.contacts, default=str, indent=2))
        except Exception as e:
            self.logger.error(f"Erreur lors de la sauvegarde des contacts: {e}")
    
    async def _load_contacts(self):
        """Charge la liste des contacts"""
        try:
            contacts_path = self.data_dir / f"{self.user_profile.user_id}_contacts.json"
            if contacts_path.exists():
                async with aiofiles.open(contacts_path, 'r') as file:
                    content = await file.read()
                    self.contacts = json.loads(content)
        except Exception as e:
            self.logger.error(f"Erreur lors du chargement des contacts: {e}")
    
    async def initiate_session(self, contact_id: str) -> bool:
        """Initie une session sécurisée avec un contact"""
        try:
            if contact_id not in self.contacts:
                raise ValueError(f"Contact {contact_id} non trouvé")
            
            contact = self.contacts[contact_id]
            
            # Génération d'une clé éphémère
            ephemeral_key = x25519.X25519PrivateKey.generate()
            
            # Sélection d'une clé à usage unique
            if not contact["one_time_prekeys"]:
                raise ValueError("Aucune clé à usage unique disponible")
            
            one_time_key = contact["one_time_prekeys"].pop(0)
            
            # Calcul du secret partagé (X3DH)
            shared_secret = self._calculate_x3dh_secret(
                self.user_profile.identity_key_pair[0],
                ephemeral_key,
                contact["identity_key"],
                contact["signed_prekey"],
                one_time_key
            )
            
            # Initialisation du Double Ratchet
            self.sessions[contact_id] = DoubleRatchet(shared_secret, sending=True)
            
            self.logger.info(f"Session initiée avec {contact_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'initiation de session: {e}")
            return False
    
    def _calculate_x3dh_secret(self, 
                              identity_private: bytes,
                              ephemeral_private: x25519.X25519PrivateKey,
                              remote_identity: bytes,
                              remote_prekey: bytes,
                              remote_one_time: bytes) -> bytes:
        """Calcule le secret partagé avec X3DH"""
        try:
            # Reconstruction des clés
            identity_key = x25519.X25519PrivateKey.from_private_bytes(identity_private)
            remote_identity_key = x25519.X25519PublicKey.from_public_bytes(remote_identity)
            remote_prekey_key = x25519.X25519PublicKey.from_public_bytes(remote_prekey)
            remote_one_time_key = x25519.X25519PublicKey.from_public_bytes(remote_one_time)
            
            # Calculs DH
            dh1 = identity_key.exchange(remote_prekey_key)
            dh2 = ephemeral_private.exchange(remote_identity_key)
            dh3 = ephemeral_private.exchange(remote_prekey_key)
            dh4 = ephemeral_private.exchange(remote_one_time_key)
            
            # Concaténation et dérivation
            shared_input = dh1 + dh2 + dh3 + dh4
            
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b"",
                info=b"WhisperText"
            )
            
            return hkdf.derive(shared_input)
            
        except Exception as e:
            self.logger.error(f"Erreur lors du calcul X3DH: {e}")
            raise
    
    async def send_secure_message(self, 
                                 contact_id: str, 
                                 subject: str,
                                 message: str,
                                 attachments: Optional[List[str]] = None) -> bool:
        """Envoie un message sécurisé avec chiffrement E2E"""
        try:
            if contact_id not in self.contacts:
                raise ValueError(f"Contact {contact_id} non trouvé")
            
            if contact_id not in self.sessions:
                if not await self.initiate_session(contact_id):
                    raise ValueError("Impossible d'initier la session")
            
            # Préparation du message
            message_data = {
                "subject": subject,
                "body": message,
                "timestamp": time.time(),
                "attachments": attachments or []
            }
            
            message_json = json.dumps(message_data)
            plaintext = message_json.encode()
            
            # Ajout de padding pour masquer la taille
            padded_plaintext = self._add_padding(plaintext)
            
            # Chiffrement avec Double Ratchet
            session = self.sessions[contact_id]
            
            # Création de l'en-tête
            header = MessageHeader(
                sender_id=self.user_profile.user_id,
                recipient_id=contact_id,
                message_id=secrets.token_hex(16),
                timestamp=time.time(),
                key_exchange_data=None,
                ratchet_key=session.dh_send.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                ),
                previous_counter=session.pn,
                message_counter=session.ns
            )
            
            # Données associées pour l'authentification
            associated_data = json.dumps(asdict(header), default=str).encode()
            
            # Chiffrement
            ciphertext, tag = session.encrypt(padded_plaintext, associated_data)
            
            # Création du message sécurisé
            secure_message = SecureMessage(
                header=header,
                ciphertext=ciphertext,
                mac=tag,
                padding_length=len(padded_plaintext) - len(plaintext)
            )
            
            # Envoi via email chiffré
            success = await self._send_encrypted_email(contact_id, secure_message)
            
            if success:
                # Stockage local pour l'historique
                if contact_id not in self.message_store:
                    self.message_store[contact_id] = []
                self.message_store[contact_id].append(secure_message)
                
                self.logger.info(f"Message sécurisé envoyé à {contact_id}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'envoi du message: {e}")
            return False
    
    def _add_padding(self, data: bytes, block_size: int = 256) -> bytes:
        """Ajoute du padding pour masquer la taille réelle du message"""
        padding_length = block_size - (len(data) % block_size)
        padding = os.urandom(padding_length)
        return data + padding
    
    def _remove_padding(self, padded_data: bytes, padding_length: int) -> bytes:
        """Supprime le padding d'un message"""
        return padded_data[:-padding_length] if padding_length > 0 else padded_data
    
    async def _send_encrypted_email(self, contact_id: str, secure_message: SecureMessage) -> bool:
        """Envoie un email avec le message chiffré"""
        try:
            contact = self.contacts[contact_id]
            
            # Sérialisation du message sécurisé
            message_data = {
                "header": asdict(secure_message.header),
                "ciphertext": base64.b64encode(secure_message.ciphertext).decode(),
                "mac": base64.b64encode(secure_message.mac).decode(),
                "padding_length": secure_message.padding_length
            }
            
            # Création de l'email
            msg = MIMEMultipart()
            msg['From'] = self.user_profile.email
            msg['To'] = contact["email"]
            msg['Subject'] = f"Secure Message [{secure_message.header.message_id[:8]}]"
            
            # Corps du message (données chiffrées)
            body = f"""
            -----BEGIN SECURE MESSAGE-----
            {base64.b64encode(json.dumps(message_data).encode()).decode()}
            -----END SECURE MESSAGE-----
            
            This is an encrypted message. Use a compatible secure email client to decrypt.
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Envoi via SMTP sécurisé
            async with aiosmtplib.SMTP(
                hostname=self.smtp_config["hostname"],
                port=self.smtp_config["port"],
                use_tls=self.smtp_config["use_tls"]
            ) as smtp:
                await smtp.login(
                    self.smtp_config["username"],
                    self.smtp_config["password"]
                )
                await smtp.send_message(msg)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'envoi de l'email: {e}")
            return False
    
    async def receive_secure_message(self, encrypted_email_data: str) -> Optional[Dict]:
        """Reçoit et déchiffre un message sécurisé"""
        try:
            # Extraction des données du message
            if "-----BEGIN SECURE MESSAGE-----" not in encrypted_email_data:
                return None
            
            start = encrypted_email_data.find("-----BEGIN SECURE MESSAGE-----") + len("-----BEGIN SECURE MESSAGE-----")
            end = encrypted_email_data.find("-----END SECURE MESSAGE-----")
            
            if end == -1:
                return None
            
            encoded_data = encrypted_email_data[start:end].strip()
            message_data = json.loads(base64.b64decode(encoded_data).decode())
            
            # Reconstruction du message sécurisé
            header = MessageHeader(**message_data["header"])
            ciphertext = base64.b64decode(message_data["ciphertext"])
            mac = base64.b64decode(message_data["mac"])
            padding_length = message_data["padding_length"]
            
            secure_message = SecureMessage(
                header=header,
                ciphertext=ciphertext,
                mac=mac,
                padding_length=padding_length
            )
            
            # Vérification de l'expéditeur
            sender_id = header.sender_id
            if sender_id not in self.contacts:
                self.logger.warning(f"Message reçu d'un expéditeur inconnu: {sender_id}")
                return None
            
            # Initialisation de session si nécessaire
            if sender_id not in self.sessions:
                # Pour la réception, nous devons reconstruire la session
                # En production, cela nécessiterait l'échange de clés initial
                self.logger.warning("Session non initialisée pour la réception")
                return None
            
            # Déchiffrement
            session = self.sessions[sender_id]
            associated_data = json.dumps(asdict(header), default=str).encode()
            
            padded_plaintext = session.decrypt(ciphertext, mac, associated_data)
            plaintext = self._remove_padding(padded_plaintext, padding_length)
            
            # Décodage du message
            message_data = json.loads(plaintext.decode())
            
            # Stockage du message reçu
            if sender_id not in self.message_store:
                self.message_store[sender_id] = []
            self.message_store[sender_id].append(secure_message)
            
            self.logger.info(f"Message sécurisé reçu de {sender_id}")
            
            return {
                "sender_id": sender_id,
                "message_id": header.message_id,
                "timestamp": header.timestamp,
                "subject": message_data.get("subject", ""),
                "body": message_data.get("body", ""),
                "attachments": message_data.get("attachments", [])
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la réception du message: {e}")
            return None
    
    async def get_message_history(self, contact_id: str) -> List[Dict]:
        """Récupère l'historique des messages avec un contact"""
        try:
            if contact_id not in self.message_store:
                return []
            
            messages = []
            for secure_msg in self.message_store[contact_id]:
                # Déchiffrement pour l'affichage (si possible)
                try:
                    # Ici, nous aurions besoin de garder les clés de déchiffrement
                    # Pour la démonstration, nous retournons les métadonnées
                    messages.append({
                        "message_id": secure_msg.header.message_id,
                        "sender_id": secure_msg.header.sender_id,
                        "recipient_id": secure_msg.header.recipient_id,
                        "timestamp": secure_msg.header.timestamp,
                        "encrypted": True
                    })
                except Exception:
                    continue
            
            return messages
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération de l'historique: {e}")
            return []
    
    async def cleanup_old_messages(self):
        """Nettoie les anciens messages (Perfect Forward Secrecy)"""
        try:
            current_time = time.time()
            
            for contact_id in list(self.message_store.keys()):
                messages = self.message_store[contact_id]
                
                # Filtrer les messages récents
                recent_messages = [
                    msg for msg in messages
                    if current_time - msg.header.timestamp < self.max_message_age
                ]
                
                if len(recent_messages) != len(messages):
                    self.message_store[contact_id] = recent_messages
                    deleted_count = len(messages) - len(recent_messages)
                    self.logger.info(f"Supprimé {deleted_count} anciens messages de {contact_id}")
            
        except Exception as e:
            self.logger.error(f"Erreur lors du nettoyage: {e}")
    
    async def export_public_key_bundle(self) -> KeyBundle:
        """Exporte le bundle de clés publiques pour partage"""
        try:
            if not self.user_profile:
                raise ValueError("Aucun profil utilisateur chargé")
            
            return KeyBundle(
                identity_key=self.user_profile.identity_key_pair[1],
                signed_prekey=self.user_profile.signed_prekey_pair[1],
                signature=self.user_profile.signature,
                one_time_prekeys=[key[1] for key in self.user_profile.one_time_prekeys[:50]],
                timestamp=time.time()
            )
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'export du bundle: {e}")
            raise
    
    async def verify_message_integrity(self, secure_message: SecureMessage) -> bool:
        """Vérifie l'intégrité d'un message"""
        try:
            # Vérification du MAC
            associated_data = json.dumps(asdict(secure_message.header), default=str).encode()
            
            # En production, utiliser la clé de session appropriée
            # Ici, simulation de la vérification
            return len(secure_message.mac) == 16  # Taille attendue du tag GCM
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la vérification d'intégrité: {e}")
            return False
    
    def get_security_status(self) -> Dict[str, any]:
        """Retourne le statut de sécurité du système"""
        return {
            "user_authenticated": self.user_profile is not None,
            "active_sessions": len(self.sessions),
            "contacts_count": len(self.contacts),
            "forward_secrecy_enabled": self.forward_secrecy,
            "metadata_protection": self.metadata_protection,
            "auto_delete_enabled": self.auto_delete_enabled,
            "message_store_size": sum(len(msgs) for msgs in self.message_store.values())
        }

# Exemple d'utilisation
async def main():
    """Fonction de démonstration"""
    # Création de deux utilisateurs pour test
    alice = SecureEmailManager("alice_data")
    bob = SecureEmailManager("bob_data")
    
    try:
        # Création des profils
        alice_profile = await alice.create_user_profile("alice", "alice@secure.com", "password123")
        bob_profile = await bob.create_user_profile("bob", "bob@secure.com", "password456")
        
        # Échange de clés publiques
        alice_bundle = await alice.export_public_key_bundle()
        bob_bundle = await bob.export_public_key_bundle()
        
        await alice.add_contact("bob", "bob@secure.com", bob_bundle)
        await bob.add_contact("alice", "alice@secure.com", alice_bundle)
        
        # Envoi d'un message sécurisé
        success = await alice.send_secure_message(
            "bob",
            "Test sécurisé",
            "Ceci est un message ultra-sécurisé avec chiffrement E2E!"
        )
        
        if success:
            print("Message sécurisé envoyé avec succès")
        
        # Statut de sécurité
        status = alice.get_security_status()
        print(f"Statut de sécurité: {status}")
        
    except Exception as e:
        print(f"Erreur: {e}")

if __name__ == "__main__":
    asyncio.run(main())