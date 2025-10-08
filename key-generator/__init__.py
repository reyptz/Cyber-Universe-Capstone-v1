"""
Ghost Cyber Universe - Générateur de Clés Cryptographiques
==========================================================

Un générateur complet de clés cryptographiques avec toutes les bonnes pratiques de sécurité.

Modules:
- core: Générateur principal de clés cryptographiques
- api: Interface FastAPI pour l'API REST
- security: Gestionnaire de sécurité et audit
- extended_key_types: Types de clés étendus pour tous les domaines IT

Version: 1.0.0
Auteur: Ghost Cyber Universe Team
"""

__version__ = "1.0.0"
__author__ = "Ghost Cyber Universe Team"
__email__ = "reypotozy@gmail.com"
__description__ = "Générateur de clés cryptographiques sécurisé"

# Imports principaux
from .core import CryptographicKeyGenerator, KeyType, OutputFormat
from .security import SecurityManager, SecurityValidator
from .extended_key_types import ExtendedKeyType, get_all_domains

__all__ = [
    "CryptographicKeyGenerator",
    "KeyType", 
    "OutputFormat",
    "SecurityManager",
    "SecurityValidator",
    "ExtendedKeyType",
    "get_all_domains"
]