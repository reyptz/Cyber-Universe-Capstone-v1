#!/usr/bin/env python3
"""
Script de démarrage rapide pour l'assistant RAG sécurisé
"""
import os
import sys
import subprocess
import time
import logging
from pathlib import Path

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def check_python_version():
    """Vérifie la version de Python"""
    if sys.version_info < (3, 8):
        logger.error("Python 3.8 ou supérieur est requis")
        sys.exit(1)
    logger.info(f"✅ Python {sys.version.split()[0]} détecté")

def check_dependencies():
    """Vérifie les dépendances principales"""
    required_packages = [
        'fastapi', 'uvicorn', 'langchain', 'transformers', 
        'spacy', 'presidio-analyzer', 'cryptography'
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
            logger.info(f"✅ {package} installé")
        except ImportError:
            missing_packages.append(package)
            logger.warning(f"❌ {package} manquant")
    
    if missing_packages:
        logger.error(f"Packages manquants: {', '.join(missing_packages)}")
        logger.info("Exécutez: pip install -r requirements.txt")
        return False
    
    return True

def install_spacy_models():
    """Installe les modèles spaCy nécessaires"""
    models = ['fr_core_news_sm', 'en_core_web_sm']
    
    for model in models:
        try:
            import spacy
            spacy.load(model)
            logger.info(f"✅ Modèle spaCy {model} installé")
        except OSError:
            logger.info(f"📥 Installation du modèle spaCy {model}...")
            try:
                subprocess.run([sys.executable, '-m', 'spacy', 'download', model], 
                             check=True, capture_output=True)
                logger.info(f"✅ Modèle spaCy {model} installé")
            except subprocess.CalledProcessError as e:
                logger.error(f"❌ Erreur lors de l'installation de {model}: {e}")
                return False
    
    return True

def create_directories():
    """Crée les répertoires nécessaires"""
    directories = ['logs', 'chroma_db', 'security_cache', 'monitoring']
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        logger.info(f"✅ Répertoire créé: {directory}")

def create_env_file():
    """Crée le fichier .env s'il n'existe pas"""
    env_file = Path('.env')
    if not env_file.exists():
        logger.info("📝 Création du fichier .env...")
        with open(env_file, 'w') as f:
            f.write("# Configuration d'environnement pour l'assistant RAG sécurisé\n")
            f.write("OPENAI_API_KEY=your_openai_api_key_here\n")
            f.write("ENCRYPTION_KEY=your_encryption_key_here\n")
            f.write("JWT_SECRET_KEY=your_jwt_secret_key_here\n")
            f.write("LOG_LEVEL=INFO\n")
            f.write("API_HOST=0.0.0.0\n")
            f.write("API_PORT=8000\n")
        logger.info("✅ Fichier .env créé")
        logger.warning("⚠️ Veuillez configurer vos clés API dans le fichier .env")
    else:
        logger.info("✅ Fichier .env existant")

def run_security_tests():
    """Exécute les tests de sécurité"""
    logger.info("🧪 Exécution des tests de sécurité...")
    try:
        result = subprocess.run([sys.executable, 'test_security.py'], 
                              capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            logger.info("✅ Tests de sécurité réussis")
            return True
        else:
            logger.warning("⚠️ Certains tests de sécurité ont échoué")
            logger.warning(f"Sortie: {result.stdout}")
            return False
    except subprocess.TimeoutExpired:
        logger.warning("⚠️ Tests de sécurité interrompus (timeout)")
        return False
    except Exception as e:
        logger.error(f"❌ Erreur lors des tests de sécurité: {e}")
        return False

def start_server():
    """Démarre le serveur"""
    logger.info("🚀 Démarrage du serveur...")
    try:
        # Vérifier si le serveur est déjà en cours d'exécution
        import requests
        try:
            response = requests.get("http://localhost:8000/health", timeout=5)
            if response.status_code == 200:
                logger.info("✅ Serveur déjà en cours d'exécution")
                return True
        except:
            pass
        
        # Démarrer le serveur
        logger.info("🌐 Serveur démarré sur http://localhost:8000")
        logger.info("📚 Documentation API: http://localhost:8000/docs")
        logger.info("🔍 Tests d'API: test_main.http")
        logger.info("⏹️ Appuyez sur Ctrl+C pour arrêter")
        
        subprocess.run([sys.executable, 'main.py'])
        
    except KeyboardInterrupt:
        logger.info("⏹️ Serveur arrêté par l'utilisateur")
    except Exception as e:
        logger.error(f"❌ Erreur lors du démarrage du serveur: {e}")
        return False
    
    return True

def show_help():
    """Affiche l'aide"""
    print("""
🛡️ Assistant RAG Sécurisé - PME Mali
=====================================

Usage: python quick_start.py [COMMAND]

Commands:
  install     Installe les dépendances et configure l'environnement
  test        Exécute les tests de sécurité
  start       Démarre le serveur
  full        Installation complète + tests + démarrage
  help        Affiche cette aide

Exemples:
  python quick_start.py install    # Installation des dépendances
  python quick_start.py test       # Tests de sécurité
  python quick_start.py start      # Démarrage du serveur
  python quick_start.py full       # Installation complète

Fonctionnalités de sécurité:
  ✅ Filtrage PII et anonymisation
  ✅ Modération de contenu
  ✅ Détection d'injection de prompts
  ✅ Détection de secrets
  ✅ Sécurité des embeddings
  ✅ Surveillance adversarial
  ✅ Gouvernance des risques
  ✅ Tests de sécurité automatisés

Pour plus d'informations, consultez le README.md
""")

def main():
    """Fonction principale"""
    if len(sys.argv) < 2:
        show_help()
        return
    
    command = sys.argv[1].lower()
    
    if command == "help" or command == "-h" or command == "--help":
        show_help()
        return
    
    logger.info("🛡️ Assistant RAG Sécurisé - PME Mali")
    logger.info("=" * 50)
    
    if command == "install":
        logger.info("📦 Installation des dépendances...")
        check_python_version()
        if not check_dependencies():
            logger.error("❌ Installation échouée")
            sys.exit(1)
        if not install_spacy_models():
            logger.error("❌ Installation des modèles spaCy échouée")
            sys.exit(1)
        create_directories()
        create_env_file()
        logger.info("✅ Installation terminée")
    
    elif command == "test":
        logger.info("🧪 Exécution des tests de sécurité...")
        if not run_security_tests():
            logger.warning("⚠️ Tests terminés avec des avertissements")
    
    elif command == "start":
        logger.info("🚀 Démarrage du serveur...")
        if not start_server():
            logger.error("❌ Démarrage échoué")
            sys.exit(1)
    
    elif command == "full":
        logger.info("🔄 Installation complète...")
        check_python_version()
        if not check_dependencies():
            logger.error("❌ Installation échouée")
            sys.exit(1)
        if not install_spacy_models():
            logger.error("❌ Installation des modèles spaCy échouée")
            sys.exit(1)
        create_directories()
        create_env_file()
        
        logger.info("🧪 Exécution des tests de sécurité...")
        run_security_tests()
        
        logger.info("🚀 Démarrage du serveur...")
        start_server()
    
    else:
        logger.error(f"❌ Commande inconnue: {command}")
        show_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
