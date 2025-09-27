# ZK-SNARK Laboratory

Laboratoire d'expérimentation avec les preuves à divulgation nulle de connaissance (Zero-Knowledge Proofs).

## Objectif

Démontrer la possession d'un mot de passe sans jamais le révéler, en utilisant ZK-SNARK avec Circom.

## Installation

### Prérequis
- Node.js (v16+)
- Circom compiler
- snarkjs

### Setup
```bash
# Installer les dépendances
npm install

# Compiler le circuit et générer les clés
npm run setup
```

## Utilisation

### Génération de Preuve
```bash
# Générer et vérifier une preuve
npm run prove
```

### Test Complet
```bash
# Setup + Preuve
npm test
```

## Fonctionnalités

- **Circuit Circom** : Vérification de mot de passe avec hash Poseidon
- **ZK-SNARK Groth16** : Génération de preuves cryptographiques
- **Vérification** : Validation sans révélation du secret
- **Setup automatisé** : Configuration des paramètres de confiance

## Sécurité

- ✅ **Zero-Knowledge** : Le mot de passe n'est jamais révélé
- ✅ **Soundness** : Impossible de tricher sans connaître le secret
- ✅ **Completeness** : Une preuve valide est toujours acceptée
- ✅ **Trusted Setup** : Utilise des paramètres Powers of Tau publics

## Exemple de Sortie

```
🎯 Démonstration ZK-SNARK - Preuve de Mot de Passe

=== Génération de Preuve ZK-SNARK ===
Mot de passe (secret): cybersec2024
Hash attendu (public): 12345...

✅ Témoin généré
✅ Preuve générée
✅ Preuve sauvegardée

=== Vérification de la Preuve ===
✅ PREUVE VALIDE - Le mot de passe est correct!
🔒 Le secret n'a jamais été révélé
```