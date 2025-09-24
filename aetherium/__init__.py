"""
Aetherium - Protocole cryptographique Ghost Key Exchange Protocol (GKEP)

Ce module implémente le protocole Aetherium v1 pour l'échange sécurisé de clés
avec support pour la rotation automatique et la détection d'intrusion.
"""

__version__ = "1.0.0"
__author__ = "Ghost Cyber Universe Team"

from .gkep import GKEPProtocol
from .crypto import AetheriumCrypto
from .pki import AetheriumPKI
from .rotation import KeyRotationManager

__all__ = [
    "GKEPProtocol",
    "AetheriumCrypto", 
    "AetheriumPKI",
    "KeyRotationManager"
]
