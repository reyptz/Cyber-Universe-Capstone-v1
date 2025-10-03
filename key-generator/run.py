#!/usr/bin/env python3
"""
Script de lancement pour le générateur de clés cryptographiques
Ghost Cyber Universe
"""

import os
import sys
import uvicorn
from pathlib import Path

# Ajouter le répertoire parent au path pour les imports
sys.path.insert(0, str(Path(__file__).parent.parent))

def main():
    """Point d'entrée principal"""
    print("🚀 Ghost Cyber Universe - Générateur de Clés Cryptographiques")
    print("=" * 60)
    
    # Vérification des dépendances
    try:
        import fastapi
        import cryptography
        print("✅ Dépendances principales installées")
    except ImportError as e:
        print(f"❌ Dépendance manquante: {e}")
        print("💡 Installez les dépendances avec: pip install -r requirements.txt")
        sys.exit(1)
    
    # Création des répertoires nécessaires
    os.makedirs("key-generator/templates", exist_ok=True)
    os.makedirs("key-generator/static/css", exist_ok=True)
    os.makedirs("key-generator/static/js", exist_ok=True)
    
    print("📁 Répertoires créés")
    print("🌐 Interface web: http://localhost:8000")
    print("📚 Documentation API: http://localhost:8000/api/docs")
    print("🔧 Redoc: http://localhost:8000/api/redoc")
    print("=" * 60)
    
    # Configuration du serveur
    config = {
        "app": "key-generator.api:app",
        "host": "0.0.0.0",
        "port": 8000,
        "reload": True,
        "log_level": "info",
        "access_log": True
    }
    
    # Variables d'environnement
    host = os.getenv("KEY_GENERATOR_HOST", "0.0.0.0")
    port = int(os.getenv("KEY_GENERATOR_PORT", "8000"))
    debug = os.getenv("KEY_GENERATOR_DEBUG", "False").lower() == "true"
    
    config.update({
        "host": host,
        "port": port,
        "reload": debug
    })
    
    print(f"🔧 Configuration:")
    print(f"   Host: {config['host']}")
    print(f"   Port: {config['port']}")
    print(f"   Debug: {debug}")
    print("=" * 60)
    
    try:
        # Lancement du serveur
        uvicorn.run(**config)
    except KeyboardInterrupt:
        print("\n🛑 Arrêt du serveur")
    except Exception as e:
        print(f"❌ Erreur lors du lancement: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
