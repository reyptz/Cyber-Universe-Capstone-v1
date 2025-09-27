#!/usr/bin/env python3
"""
Script de démarrage pour l'assistant RAG sécurisé
"""
import os
import sys
import logging
import subprocess
from pathlib import Path

def setup_logging():
    """Configure le logging"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('rag_assistant.log')
        ]
    )

def check_dependencies():
    """Vérifie les dépendances requises"""
    logger = logging.getLogger(__name__)
    
    try:
        import fastapi
        import langchain
        import transformers
        import spacy
        import presidio_analyzer
        logger.info("✅ Toutes les dépendances principales sont installées")
        return True
    except ImportError as e:
        logger.error(f"❌ Dépendance manquante: {e}")
        logger.error("Veuillez installer les dépendances avec: pip install -r requirements.txt")
        return False

def check_spacy_models():
    """Vérifie les modèles spaCy"""
    logger = logging.getLogger(__name__)
    
    try:
        import spacy
        
        # Vérifier le modèle français
        try:
            spacy.load("fr_core_news_sm")
            logger.info("✅ Modèle spaCy français installé")
        except OSError:
            logger.warning("⚠️ Modèle spaCy français non trouvé")
            logger.info("Installation: python -m spacy download fr_core_news_sm")
        
        # Vérifier le modèle anglais
        try:
            spacy.load("en_core_web_sm")
            logger.info("✅ Modèle spaCy anglais installé")
        except OSError:
            logger.warning("⚠️ Modèle spaCy anglais non trouvé")
            logger.info("Installation: python -m spacy download en_core_web_sm")
        
        return True
    except Exception as e:
        logger.error(f"❌ Erreur lors de la vérification des modèles spaCy: {e}")
        return False

def check_environment():
    """Vérifie la configuration de l'environnement"""
    logger = logging.getLogger(__name__)
    
    # Vérifier les variables d'environnement importantes
    openai_key = os.getenv("OPENAI_API_KEY")
    if openai_key:
        logger.info("✅ Clé API OpenAI configurée")
    else:
        logger.warning("⚠️ Clé API OpenAI non configurée (optionnelle)")
    
    # Vérifier les fichiers de configuration
    config_files = ["config.py", "main.py", "rag_chain.py"]
    for file in config_files:
        if Path(file).exists():
            logger.info(f"✅ Fichier de configuration trouvé: {file}")
        else:
            logger.error(f"❌ Fichier de configuration manquant: {file}")
            return False
    
    return True

def create_directories():
    """Crée les répertoires nécessaires"""
    logger = logging.getLogger(__name__)
    
    directories = ["logs", "chroma_db", "security_cache"]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        logger.info(f"✅ Répertoire créé/vérifié: {directory}")

def run_security_tests():
    """Exécute les tests de sécurité"""
    logger = logging.getLogger(__name__)
    
    logger.info("🧪 Exécution des tests de sécurité...")
    
    try:
        # Import et exécution des tests
        from .test.test_security import run_all_tests
        results = run_all_tests()
        
        # Vérifier les résultats
        passed = sum(1 for success in results.values() if success)
        total = len(results)
        
        if passed == total:
            logger.info("✅ Tous les tests de sécurité sont passés")
            return True
        else:
            logger.warning(f"⚠️ {total - passed} test(s) ont échoué")
            return False
            
    except Exception as e:
        logger.error(f"❌ Erreur lors de l'exécution des tests: {e}")
        return False

def start_server():
    """Démarre le serveur FastAPI"""
    logger = logging.getLogger(__name__)
    
    logger.info("🚀 Démarrage du serveur FastAPI...")
    
    try:
        import uvicorn
        from .app.api.main import app
        
        # Configuration du serveur
        host = os.getenv("API_HOST", "0.0.0.0")
        port = int(os.getenv("API_PORT", "8000"))
        workers = int(os.getenv("API_WORKERS", "1"))
        
        logger.info(f"🌐 Serveur démarré sur http://{host}:{port}")
        logger.info("📚 Documentation API disponible sur http://localhost:8000/docs")
        logger.info("🔍 Tests d'API disponibles dans test_main.http")
        
        # Démarrage du serveur
        uvicorn.run(
            app,
            host=host,
            port=port,
            workers=workers,
            log_level="info"
        )
        
    except Exception as e:
        logger.error(f"❌ Erreur lors du démarrage du serveur: {e}")
        return False

def main():
    """Fonction principale"""
    setup_logging()
    logger = logging.getLogger(__name__)
    
    logger.info("🛡️ Assistant RAG Sécurisé - PME Mali")
    logger.info("=" * 50)
    
    # Vérifications préliminaires
    logger.info("🔍 Vérification des prérequis...")
    
    if not check_dependencies():
        sys.exit(1)
    
    if not check_spacy_models():
        logger.warning("⚠️ Certains modèles spaCy sont manquants, mais le système peut fonctionner")
    
    if not check_environment():
        sys.exit(1)
    
    # Création des répertoires
    create_directories()
    
    # Tests de sécurité (optionnels)
    run_tests = os.getenv("RUN_SECURITY_TESTS", "true").lower() == "true"
    if run_tests:
        if not run_security_tests():
            logger.warning("⚠️ Certains tests de sécurité ont échoué, mais le serveur peut démarrer")
    else:
        logger.info("⏭️ Tests de sécurité ignorés")
    
    # Démarrage du serveur
    logger.info("🎯 Toutes les vérifications sont terminées")
    start_server()

if __name__ == "__main__":
    main()
