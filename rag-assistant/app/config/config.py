"""
Configuration de sécurité pour le système RAG
"""
import os
from typing import List, Dict, Any
from pydantic import BaseSettings, Field
from cryptography.fernet import Fernet

class SecurityConfig(BaseSettings):
    """Configuration de sécurité centralisée"""
    
    # Clés de chiffrement
    ENCRYPTION_KEY: str = Field(default_factory=lambda: Fernet.generate_key().decode())
    JWT_SECRET_KEY: str = Field(default_factory=lambda: os.urandom(32).hex())
    
    # Configuration PII
    PII_ENTITIES: List[str] = [
        "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", 
        "CREDIT_CARD", "IBAN_CODE", "IP_ADDRESS",
        "LOCATION", "DATE_TIME", "NRP", "MEDICAL_LICENSE",
        "US_SSN", "US_PASSPORT", "US_DRIVER_LICENSE"
    ]
    
    # Règles de confidentialité
    PRIVACY_RULES: Dict[str, Any] = {
        "max_retention_days": 30,
        "auto_anonymize": True,
        "log_pii_access": True,
        "require_consent": True
    }
    
    # Configuration de modération
    CONTENT_MODERATION: Dict[str, Any] = {
        "toxicity_threshold": 0.7,
        "hate_speech_threshold": 0.8,
        "violence_threshold": 0.6,
        "sexual_content_threshold": 0.7
    }
    
    # Configuration des signatures d'embeddings
    EMBEDDING_SIGNATURES: Dict[str, Any] = {
        "algorithm": "HMAC-SHA256",
        "verify_integrity": True,
        "cache_signed_embeddings": True
    }
    
    # Configuration de détection d'injection
    INJECTION_DETECTION: Dict[str, Any] = {
        "prompt_injection_threshold": 0.8,
        "jailbreak_threshold": 0.9,
        "max_prompt_length": 4000,
        "suspicious_patterns": [
            r"ignore\s+previous\s+instructions",
            r"forget\s+everything",
            r"you\s+are\s+now\s+a\s+different",
            r"pretend\s+to\s+be",
            r"act\s+as\s+if",
            r"roleplay\s+as"
        ]
    }
    
    # Configuration de détection de secrets
    SECRETS_DETECTION: Dict[str, Any] = {
        "patterns": [
            r"api[_-]?key\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}['\"]?",
            r"password\s*[:=]\s*['\"]?[^\s]{8,}['\"]?",
            r"secret\s*[:=]\s*['\"]?[a-zA-Z0-9]{16,}['\"]?",
            r"token\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}['\"]?",
            r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"
        ],
        "confidence_threshold": 0.8
    }
    
    # Configuration de la chaîne d'approvisionnement
    SUPPLY_CHAIN: Dict[str, Any] = {
        "verify_model_hashes": True,
        "check_sbom": True,
        "sandbox_execution": True,
        "network_policies": {
            "allow_outbound": False,
            "allowed_domains": ["api.openai.com", "api.anthropic.com"]
        }
    }
    
    # Configuration de détection adversarial
    ADVERSARIAL_DETECTION: Dict[str, Any] = {
        "perplexity_threshold": 2.0,
        "toxicity_threshold": 0.7,
        "leakage_indicators": [
            "internal", "confidential", "secret", "private",
            "proprietary", "restricted", "classified"
        ],
        "quarantine_threshold": 0.8
    }
    
    # Configuration de gouvernance
    GOVERNANCE: Dict[str, Any] = {
        "risk_categories": [
            "prompt_injection", "jailbreak", "pii_leakage",
            "secrets_exposure", "toxic_content", "adversarial_attack"
        ],
        "severity_levels": ["low", "medium", "high", "critical"],
        "mttd_target": 300,  # 5 minutes
        "mttr_target": 1800  # 30 minutes
    }

    class Config:
        env_file = ".env"
        case_sensitive = True

# Instance globale de configuration
security_config = SecurityConfig()
