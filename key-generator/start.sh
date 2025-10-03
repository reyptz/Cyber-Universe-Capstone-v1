#!/bin/bash

echo "========================================"
echo "Ghost Cyber Universe - Générateur de Clés"
echo "========================================"
echo

# Vérification de Python
if ! command -v python3 &> /dev/null; then
    echo "Python 3 n'est pas installé"
    echo "Installez Python 3.11+ avec votre gestionnaire de paquets"
    exit 1
fi

# Vérification de pip
if ! command -v pip3 &> /dev/null; then
    echo "pip3 n'est pas installé"
    echo "Installez pip3 avec votre gestionnaire de paquets"
    exit 1
fi

echo "Python détecté"
echo

# Installation des dépendances
echo "Installation des dépendances..."
pip3 install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "Erreur lors de l'installation des dépendances"
    exit 1
fi

echo "Dépendances installées"
echo

# Création des répertoires
echo "Création des répertoires..."
mkdir -p templates static/css static/js logs audit

echo "Répertoires créés"
echo

# Lancement du serveur
echo "Lancement du serveur..."
echo
echo "Interface web: http://localhost:8000"
echo "Documentation API: http://localhost:8000/api/docs"
echo "Redoc: http://localhost:8000/api/redoc"
echo
echo "Appuyez sur Ctrl+C pour arrêter le serveur"
echo

python3 run.py

