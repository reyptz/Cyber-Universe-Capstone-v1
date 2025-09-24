# Ghost Cyber Universe - Manuel d'Utilisation

## Table des Matières
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Gestion des Clés](#gestion-des-clés)
4. [Chiffrement de Fichiers](#chiffrement-de-fichiers)
5. [Déchiffrement de Fichiers](#déchiffrement-de-fichiers)
6. [Journal d'Audit](#journal-daudit)
7. [Bonnes Pratiques](#bonnes-pratiques)
8. [Dépannage](#dépannage)

## Introduction
Ghost Cyber Universe (GCU) est une suite cryptographique avancée offrant un chiffrement post-quantique, une gestion sécurisée des clés et une traçabilité complète des opérations.

## Installation

### Prérequis
- Python 3.8+
- pip (gestionnaire de paquets Python)

### Installation des dépendances
```bash
# Installer les dépendances de base
pip install -r requirements.txt

# Pour le support PQC (optionnel mais recommandé)
pip install oqs
```

## Gestion des Clés

### Générer un nouveau keystore
```bash
python main.py keys generate --out mon_keystore.json
```

### Afficher l'empreinte d'un keystore
```bash
python main.py keys fingerprint --keystore mon_keystore.json
```

## Chiffrement de Fichiers

### Chiffrement simple (1 destinataire)
```bash
python main.py file encrypt --in document.txt --out document.gcu --sender-keystore alice.keystore.json --to-keystore bob.keystore.json
```

### Chiffrement multi-destinataires
```bash
python main.py file encrypt --in rapport_confidentiel.pdf --out rapport.gcu --sender-keystore alice.keystore.json --to-keystore bob.keystore.json --to-keystore charlie.keystore.json --to-pk 1a2b3c4d...  # Clé publique supplémentaire
```

### Options avancées
- `--signer-keystore` : Spécifier un keystore différent pour la signature
- `--sender-password` : Fournir le mot de passe en ligne de commande (non sécurisé)

## Déchiffrement de Fichiers

### Déchiffrement de base
```bash
python main.py file decrypt --in document.gcu --out document_decrypte.txt --recipient-keystore bob.keystore.json
```

## Journal d'Audit

### Emplacement
Le journal d'audit est stocké dans : `./logs/audit.jsonl`

### Format des entrées
Chaque ligne est un objet JSON contenant :
- `timestamp` : Horodatage de l'opération
- `operation` : Type d'opération
- `actor` : Empreinte du keystore initiateur
- `object_hash` : Empreinte de l'objet concerné
- `recipients` : Liste des empreintes des destinataires

### Vérification d'intégrité
```bash
# Vérifier l'intégrité du journal
python -c "from audit import verify_audit_log; verify_audit_log()"
```

## Bonnes Pratiques

### Sécurité des mots de passe
- Ne jamais stocker les mots de passe en clair
- Utiliser un gestionnaire de mots de passe
- Ne pas utiliser `--sender-password` en production

### Gestion des clés
- Sauvegarder régulièrement les keystores
- Utiliser des mots de passe forts (minimum 16 caractères)
- Régénérer périodiquement les paires de clés

### Chiffrement
- Vérifier l'empreinte des destinataires avant envoi
- Signer systématiquement les enveloppes
- Conserver une copie du journal d'audit

## Dépannage

### Erreurs courantes

#### "Signature d'enveloppe invalide"
- Vérifier que le keystore du signataire est valide
- S'assurer que le fichier n'a pas été altéré

#### "Aucun secret destinataire ne correspond"
- Vérifier que le keystore correspond à un destinataire autorisé
- S'assurer que la version de GCU est à jour

#### "Format de keystore non reconnu"
- Vérifier que le fichier n'est pas corrompu
- Utiliser la commande `fingerprint` pour valider le keystore

### Support
Pour toute question ou problème, veuillez ouvrir une issue sur notre dépôt GitHub.

---

*Documentation mise à jour le 24/09/2025*
