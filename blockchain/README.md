# SecureBank - Smart Contract Sécurisé

## Description
Version sécurisée d'un smart contract bancaire implémentant les bonnes pratiques de sécurité blockchain.

## Sécurités Implémentées
- ✅ **Pattern Checks-Effects-Interactions**
- ✅ **Mutex anti-reentrancy** 
- ✅ **Circuit breaker** (arrêt d'urgence)
- ✅ **Pull pattern** pour retraits
- ✅ **Limite de gas** pour transferts
- ✅ **Contrôle d'accès** (owner)

## Installation
```bash
npm install
```

## Compilation
```bash
npx hardhat compile
```

## Tests d'audit
```bash
npx hardhat run scripts/audit.js
```

## Audit avec outils externes
```bash
# Slither (analyse statique)
npm run audit:slither

# Mythril (analyse symbolique)
npm run audit:mythril
```

## Contrat Principal
- `contracts/SecureBank.sol` - Contrat bancaire sécurisé

## Scripts
- `scripts/audit.js` - Script d'audit de sécurité