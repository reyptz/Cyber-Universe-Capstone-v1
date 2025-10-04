# Ghost Cyber Universe - Générateur de Clés Cryptographiques
# Dockerfile pour le déploiement

FROM python:3.11-slim

# Métadonnées
LABEL maintainer="Ghost Cyber Universe Team"
LABEL description="Générateur de clés cryptographiques sécurisé"
LABEL version="1.0.0"

# Variables d'environnement
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV KEY_GENERATOR_HOST=0.0.0.0
ENV KEY_GENERATOR_PORT=8000
ENV KEY_GENERATOR_DEBUG=False

# Créer un utilisateur non-root
RUN groupadd -r ghost && useradd -r -g ghost ghost

# Installer les dépendances système
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Définir le répertoire de travail
WORKDIR /app

# Copier les fichiers de dépendances
COPY requirements.txt .

# Installer les dépendances Python
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copier le code source
COPY . .

# Créer les répertoires nécessaires
RUN mkdir -p templates static/css static/js && \
    chown -R ghost:ghost /app

# Changer vers l'utilisateur non-root
USER ghost

# Exposer le port
EXPOSE 8000

# Point d'entrée
CMD ["python", "run.py"]