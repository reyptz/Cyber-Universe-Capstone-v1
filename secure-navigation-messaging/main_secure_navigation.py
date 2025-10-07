#!/usr/bin/env python3
"""
Ghost Cyber Universe - Navigation Sécurisée
Point d'entrée principal pour le système de navigation sécurisée

Ce module lance l'interface utilisateur intégrée combinant:
- VPN avec rotation automatique des serveurs
- Tor avec gestion des circuits multiples  
- Messagerie ultra-sécurisée avec chiffrement E2E
- Tests de sécurité et détection de fuites
"""

import sys
import os
import logging
import asyncio
from pathlib import Path

# Ajouter le répertoire du projet au path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

try:
    from secure_navigation.secure_ui import SecureNavigationUI
except ImportError as e:
    print(f"Erreur d'importation: {e}")
    print("Assurez-vous que tous les modules sont présents et que les dépendances sont installées.")
    print("Exécutez: pip install -r requirements.txt")
    sys.exit(1)

def setup_logging():
    """Configure le système de logging"""
    log_dir = project_root / "logs"
    log_dir.mkdir(exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / "secure_navigation.log"),
            logging.StreamHandler(sys.stdout)
        ]
    )

def check_dependencies():
    """Vérifie que les dépendances critiques sont installées"""
    required_modules = [
        'tkinter',
        'matplotlib',
        'numpy',
        'cryptography',
        'stem',
        'requests'
    ]
    
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        print("Modules manquants:")
        for module in missing_modules:
            print(f"  - {module}")
        print("\nInstallez les dépendances avec: pip install -r requirements.txt")
        return False
    
    return True

def check_system_requirements():
    """Vérifie les prérequis système"""
    import platform
    
    system = platform.system()
    print(f"Système détecté: {system}")
    
    # Vérifications spécifiques selon l'OS
    if system == "Windows":
        print("Configuration Windows détectée")
        # Vérifier si Tor est disponible
        tor_paths = [
            "C:\\Program Files\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe",
            "C:\\Users\\%USERNAME%\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe",
            "tor.exe"  # Dans le PATH
        ]
        
        tor_found = False
        for path in tor_paths:
            if os.path.exists(path.replace('%USERNAME%', os.getenv('USERNAME', ''))):
                tor_found = True
                print(f"Tor trouvé: {path}")
                break
        
        if not tor_found:
            print("ATTENTION: Tor non trouvé. Téléchargez Tor Browser depuis https://www.torproject.org/")
    
    elif system == "Linux":
        print("Configuration Linux détectée")
        # Vérifier si Tor est installé
        if os.system("which tor > /dev/null 2>&1") == 0:
            print("Tor trouvé dans le système")
        else:
            print("ATTENTION: Tor non trouvé. Installez avec: sudo apt install tor")
    
    elif system == "Darwin":  # macOS
        print("Configuration macOS détectée")
        if os.system("which tor > /dev/null 2>&1") == 0:
            print("Tor trouvé dans le système")
        else:
            print("ATTENTION: Tor non trouvé. Installez avec: brew install tor")
    
    return True

def create_directories():
    """Crée les répertoires nécessaires"""
    directories = [
        "logs",
        "config",
        "data",
        "profiles",
        "keys"
    ]
    
    for directory in directories:
        dir_path = project_root / directory
        dir_path.mkdir(exist_ok=True)
        print(f"Répertoire créé/vérifié: {dir_path}")

def main():
    """Fonction principale"""
    print("=" * 60)
    print("Ghost Cyber Universe - Navigation Sécurisée")
    print("Version 1.0")
    print("=" * 60)
    
    # Configuration du logging
    setup_logging()
    logger = logging.getLogger(__name__)
    
    try:
        # Vérifications préliminaires
        print("\n1. Vérification des dépendances...")
        if not check_dependencies():
            sys.exit(1)
        print("✓ Toutes les dépendances sont installées")
        
        print("\n2. Vérification des prérequis système...")
        check_system_requirements()
        print("✓ Vérifications système terminées")
        
        print("\n3. Création des répertoires...")
        create_directories()
        print("✓ Structure des répertoires créée")
        
        print("\n4. Lancement de l'interface utilisateur...")
        logger.info("Démarrage de l'application de navigation sécurisée")
        
        # Lancement de l'interface
        app = SecureNavigationUI()
        
        print("✓ Interface utilisateur initialisée")
        print("\nL'application est prête à l'utilisation!")
        print("Fermez cette fenêtre pour arrêter l'application.")
        
        # Démarrage de l'interface
        app.run()
        
    except KeyboardInterrupt:
        print("\n\nArrêt demandé par l'utilisateur")
        logger.info("Application arrêtée par l'utilisateur")
        
    except Exception as e:
        print(f"\nErreur fatale: {e}")
        logger.error(f"Erreur fatale: {e}", exc_info=True)
        sys.exit(1)
    
    finally:
        print("\nFermeture de l'application...")
        logger.info("Application fermée")

if __name__ == "__main__":
    main()