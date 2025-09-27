# Dockerfile pour l'assistant RAG sécurisé
FROM python:3.9-slim

# Métadonnées
LABEL maintainer="PME Mali Security Team"
LABEL description="Assistant RAG sécurisé avec toutes les fonctionnalités de sécurité"
LABEL version="1.0.0"

# Variables d'environnement
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PIP_NO_CACHE_DIR=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

# Installation des dépendances système
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Création du répertoire de travail
WORKDIR /app

# Copie des fichiers de dépendances
COPY requirements.txt .

# Installation des dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Installation des modèles spaCy
RUN python -m spacy download fr_core_news_sm
RUN python -m spacy download en_core_web_sm

# Copie du code source
COPY . .

# Création des répertoires nécessaires
RUN mkdir -p logs chroma_db security_cache

# Configuration des permissions
RUN chmod +x start_server.py

# Exposition du port
EXPOSE 8000

# Variables d'environnement par défaut
ENV API_HOST=0.0.0.0
ENV API_PORT=8000
ENV LOG_LEVEL=INFO
ENV RUN_SECURITY_TESTS=false

# Point d'entrée
CMD ["python", "start_server.py"]

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1
