#!/usr/bin/env python3
"""
Tests unitaires pour le module Email avancé
Ghost Cyber Universe
"""

import asyncio
import os
import pytest
import sys
from pathlib import Path

# Ajout du chemin parent
sys.path.append(str(Path(__file__).parent.parent))

from secure_messaging.email_advanced import (
    SecureEmailProviders,
    AttachmentEncryptor,
    MetadataProtector,
    BackupManager,
    AdvancedEmailManager,
    EmailProvider,
    SecureAttachment
)


class TestSecureEmailProviders:
    """Tests pour SecureEmailProviders"""
    
    def test_get_provider_protonmail(self):
        """Test de récupération ProtonMail"""
        provider = SecureEmailProviders.get_provider("protonmail")
        
        assert provider is not None
        assert provider.name == "ProtonMail"
        assert provider.privacy_rating == 10
        assert provider.supports_e2e == True
    
    def test_get_provider_case_insensitive(self):
        """Test insensible à la casse"""
        provider1 = SecureEmailProviders.get_provider("ProtonMail")
        provider2 = SecureEmailProviders.get_provider("protonmail")
        
        assert provider1 == provider2
    
    def test_get_provider_unknown(self):
        """Test avec provider inconnu"""
        provider = SecureEmailProviders.get_provider("unknown_provider")
        assert provider is None
    
    def test_list_providers(self):
        """Test de liste des providers"""
        providers = SecureEmailProviders.list_providers(min_privacy_rating=8)
        
        assert len(providers) > 0
        assert all(p.privacy_rating >= 8 for p in providers)
    
    def test_list_providers_high_rating(self):
        """Test avec rating élevé"""
        providers = SecureEmailProviders.list_providers(min_privacy_rating=10)
        
        assert len(providers) >= 2  # ProtonMail et Tutanota
        assert all(p.privacy_rating == 10 for p in providers)
    
    def test_get_best_provider(self):
        """Test du meilleur provider"""
        provider = SecureEmailProviders.get_best_provider()
        
        assert provider is not None
        assert provider.privacy_rating == 10


class TestAttachmentEncryptor:
    """Tests pour AttachmentEncryptor"""
    
    @pytest.fixture
    async def test_file(self, tmp_path):
        """Crée un fichier de test"""
        file_path = tmp_path / "test_document.txt"
        async with pytest.importorskip("aiofiles").open(file_path, 'w') as f:
            await f.write("Ceci est un document confidentiel de test!")
        return file_path
    
    def test_init(self):
        """Test d'initialisation"""
        encryptor = AttachmentEncryptor()
        assert encryptor.chunk_size == 64 * 1024
    
    @pytest.mark.asyncio
    async def test_encrypt_file(self, tmp_path):
        """Test de chiffrement de fichier"""
        # Création d'un fichier test
        test_file = tmp_path / "test.txt"
        content = b"Contenu secret de test!"
        
        import aiofiles
        async with aiofiles.open(test_file, 'wb') as f:
            await f.write(content)
        
        encryptor = AttachmentEncryptor()
        
        # Chiffrement
        attachment = await encryptor.encrypt_file(test_file, compress=True)
        
        assert attachment is not None
        assert attachment.filename == "test.txt"
        assert attachment.original_size == len(content)
        assert attachment.encrypted_size > 0
        assert attachment.compressed == True
        assert len(attachment.checksum) == 64  # SHA256 hex
        
        # Vérification du fichier chiffré
        encrypted_file = tmp_path / "test.txt.encrypted"
        assert encrypted_file.exists()
    
    @pytest.mark.asyncio
    async def test_encrypt_decrypt_roundtrip(self, tmp_path):
        """Test de chiffrement/déchiffrement complet"""
        # Fichier original
        original_file = tmp_path / "original.txt"
        original_content = b"Contenu ultra-secret!"
        
        import aiofiles
        async with aiofiles.open(original_file, 'wb') as f:
            await f.write(original_content)
        
        encryptor = AttachmentEncryptor()
        
        # Chiffrement
        attachment = await encryptor.encrypt_file(original_file, compress=True)
        encrypted_file = tmp_path / "original.txt.encrypted"
        
        # Déchiffrement
        decrypted_file = tmp_path / "decrypted.txt"
        success = await encryptor.decrypt_file(
            encrypted_file,
            attachment,
            decrypted_file
        )
        
        assert success == True
        assert decrypted_file.exists()
        
        # Vérification du contenu
        async with aiofiles.open(decrypted_file, 'rb') as f:
            decrypted_content = await f.read()
        
        assert decrypted_content == original_content


class TestMetadataProtector:
    """Tests pour MetadataProtector"""
    
    def test_init(self):
        """Test d'initialisation"""
        protector = MetadataProtector()
        assert protector is not None
    
    def test_generate_anonymous_headers(self):
        """Test de génération d'en-têtes anonymes"""
        protector = MetadataProtector()
        headers = protector.generate_anonymous_headers()
        
        assert isinstance(headers, dict)
        assert "X-Mailer" in headers
        assert "Message-ID" in headers
        assert "Date" in headers
        assert headers["User-Agent"] == ""
        assert headers["X-Originating-IP"] == "[REDACTED]"
    
    def test_create_protected_metadata(self):
        """Test de création de métadonnées protégées"""
        protector = MetadataProtector()
        
        metadata = protector.create_protected_metadata(
            sender_id="alice@example.com",
            recipient_ids=["bob@example.com", "charlie@example.com"],
            subject="Sujet confidentiel",
            attachments=[]
        )
        
        assert metadata is not None
        assert metadata.message_id is not None
        assert len(metadata.sender_fingerprint) == 16
        assert len(metadata.recipient_fingerprints) == 2
        assert metadata.has_attachments == False
        assert metadata.attachment_count == 0
        assert metadata.encrypted_subject is not None
        assert metadata.padding_size >= 256


class TestBackupManager:
    """Tests pour BackupManager"""
    
    @pytest.fixture
    def backup_mgr(self, tmp_path):
        """Crée un BackupManager avec répertoire temporaire"""
        return BackupManager(str(tmp_path / "backups"))
    
    def test_init(self, tmp_path):
        """Test d'initialisation"""
        backup_dir = tmp_path / "backups"
        mgr = BackupManager(str(backup_dir))
        
        assert mgr.backup_dir.exists()
        assert mgr.backup_dir == backup_dir
    
    @pytest.mark.asyncio
    async def test_create_backup(self, backup_mgr):
        """Test de création de sauvegarde"""
        data = {
            "user": "alice",
            "emails": ["email1", "email2"],
            "config": {"setting1": "value1"}
        }
        
        bundle = await backup_mgr.create_backup(data, "recovery_password_123")
        
        assert bundle is not None
        assert bundle.bundle_id is not None
        assert len(bundle.bundle_id) == 16  # 8 bytes en hex
        assert bundle.created_at > 0
        assert bundle.encrypted_data is not None
        assert len(bundle.recovery_key_hash) == 64  # SHA256
    
    @pytest.mark.asyncio
    async def test_restore_backup(self, backup_mgr):
        """Test de restauration de sauvegarde"""
        original_data = {
            "user": "alice",
            "emails": ["email1", "email2"]
        }
        
        # Création
        bundle = await backup_mgr.create_backup(original_data, "password123")
        
        # Restauration
        restored_data = await backup_mgr.restore_backup(
            bundle.bundle_id,
            "password123"
        )
        
        assert restored_data is not None
        assert restored_data["user"] == "alice"
        assert restored_data["emails"] == ["email1", "email2"]
    
    @pytest.mark.asyncio
    async def test_restore_backup_wrong_password(self, backup_mgr):
        """Test avec mauvais mot de passe"""
        data = {"test": "data"}
        
        bundle = await backup_mgr.create_backup(data, "correct_password")
        
        restored = await backup_mgr.restore_backup(
            bundle.bundle_id,
            "wrong_password"
        )
        
        assert restored is None
    
    @pytest.mark.asyncio
    async def test_list_backups(self, backup_mgr):
        """Test de liste des sauvegardes"""
        # Création de plusieurs sauvegardes
        await backup_mgr.create_backup({"data": 1}, "pass1")
        await backup_mgr.create_backup({"data": 2}, "pass2")
        
        backups = await backup_mgr.list_backups()
        
        assert len(backups) >= 2
        assert all("bundle_id" in b for b in backups)
        assert all("created_at" in b for b in backups)
    
    @pytest.mark.asyncio
    async def test_delete_backup(self, backup_mgr):
        """Test de suppression de sauvegarde"""
        data = {"test": "data"}
        bundle = await backup_mgr.create_backup(data, "password")
        
        # Suppression
        result = await backup_mgr.delete_backup(bundle.bundle_id)
        assert result == True
        
        # Vérification
        backups = await backup_mgr.list_backups()
        assert not any(b["bundle_id"] == bundle.bundle_id for b in backups)


class TestAdvancedEmailManager:
    """Tests pour AdvancedEmailManager"""
    
    def test_init_default_provider(self):
        """Test d'initialisation avec provider par défaut"""
        mgr = AdvancedEmailManager()
        
        assert mgr.provider is not None
        assert mgr.provider.name == "ProtonMail"
        assert mgr.attachment_encryptor is not None
        assert mgr.metadata_protector is not None
        assert mgr.backup_manager is not None
    
    def test_init_custom_provider(self):
        """Test avec provider personnalisé"""
        mgr = AdvancedEmailManager("tutanota")
        
        assert mgr.provider.name == "Tutanota"
    
    def test_init_unknown_provider(self):
        """Test avec provider inconnu"""
        with pytest.raises(ValueError):
            AdvancedEmailManager("unknown_provider")
    
    def test_configure_credentials(self):
        """Test de configuration des identifiants"""
        mgr = AdvancedEmailManager()
        mgr.configure_credentials("user@example.com", "password123")
        
        assert mgr.username == "user@example.com"
        assert mgr.password == "password123"
    
    def test_get_statistics(self):
        """Test de récupération des statistiques"""
        mgr = AdvancedEmailManager()
        stats = mgr.get_statistics()
        
        assert isinstance(stats, dict)
        assert "emails_sent" in stats
        assert "emails_received" in stats
        assert "attachments_encrypted" in stats
        assert "total_data_encrypted_mb" in stats
        assert "provider" in stats
        assert "privacy_rating" in stats
    
    def test_list_available_providers(self):
        """Test de liste des providers"""
        providers = AdvancedEmailManager.list_available_providers(min_rating=8)
        
        assert isinstance(providers, list)
        assert len(providers) > 0
        assert all(isinstance(p, dict) for p in providers)
        assert all("name" in p for p in providers)
        assert all("privacy_rating" in p for p in providers)


# Tests d'intégration

@pytest.mark.asyncio
async def test_full_email_workflow(tmp_path):
    """Test du workflow complet email"""
    # 1. Initialisation
    mgr = AdvancedEmailManager("protonmail")
    mgr.configure_credentials("user@example.com", "password")
    
    # 2. Création d'un fichier test
    test_file = tmp_path / "secret.txt"
    import aiofiles
    async with aiofiles.open(test_file, 'w') as f:
        await f.write("Document ultra-confidentiel!")
    
    # 3. Chiffrement de pièce jointe
    attachment = await mgr.attachment_encryptor.encrypt_file(test_file)
    assert attachment.original_size > 0
    
    # 4. Métadonnées protégées
    metadata = mgr.metadata_protector.create_protected_metadata(
        "alice@example.com",
        ["bob@example.com"],
        "Sujet secret",
        [attachment]
    )
    assert metadata.has_attachments == True
    
    # 5. Backup
    backup_data = {"test": "data"}
    bundle = await mgr.create_encrypted_backup("recovery_pass")
    assert bundle is not None
    
    # 6. Restauration
    restored = await mgr.backup_manager.restore_backup(
        bundle.bundle_id,
        "recovery_pass"
    )
    assert restored is not None
    
    # 7. Statistiques
    stats = mgr.get_statistics()
    assert stats["attachments_encrypted"] > 0


@pytest.mark.asyncio
async def test_encryption_security(tmp_path):
    """Test de sécurité du chiffrement"""
    encryptor = AttachmentEncryptor()
    
    # Fichier avec contenu sensible
    sensitive_file = tmp_path / "sensitive.txt"
    import aiofiles
    async with aiofiles.open(sensitive_file, 'w') as f:
        await f.write("Données ultra-secrètes: mot de passe = secret123")
    
    # Chiffrement
    attachment = await encryptor.encrypt_file(sensitive_file, compress=True)
    encrypted_file = tmp_path / "sensitive.txt.encrypted"
    
    # Vérification que le contenu chiffré ne contient pas le texte original
    async with aiofiles.open(encrypted_file, 'rb') as f:
        encrypted_content = await f.read()
    
    assert b"secret123" not in encrypted_content
    assert b"mot de passe" not in encrypted_content
    
    # Vérification du checksum
    import hashlib
    async with aiofiles.open(sensitive_file, 'rb') as f:
        original_content = await f.read()
    
    expected_checksum = hashlib.sha256(original_content).hexdigest()
    assert attachment.checksum == expected_checksum


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

