const fs = require('fs');
const path = require('path');
const snarkjs = require('snarkjs');

// Fonction pour convertir une chaîne en nombre pour Poseidon
function stringToFieldElement(str) {
    const bytes = Buffer.from(str, 'utf8');
    let result = BigInt(0);
    for (let i = 0; i < Math.min(bytes.length, 31); i++) {
        result = result * BigInt(256) + BigInt(bytes[i]);
    }
    return result.toString();
}

// Fonction pour calculer le hash Poseidon d'un mot de passe
async function calculatePoseidonHash(password) {
    const passwordField = stringToFieldElement(password);
    const hash = await snarkjs.poseidon([passwordField]);
    return hash.toString();
}

async function generateHashForPassword(password = 'cybersec2024') {
    console.log(`🔐 Génération du hash Poseidon pour: "${password}"`);
    
    try {
        const passwordField = stringToFieldElement(password);
        const hash = await calculatePoseidonHash(password);
        
        console.log(`📊 Résultats:`);
        console.log(`   - Mot de passe: ${password}`);
        console.log(`   - Field element: ${passwordField}`);
        console.log(`   - Hash Poseidon: ${hash}`);
        
        // Mettre à jour le fichier input.json
        const inputPath = path.join(__dirname, '..', 'input.json');
        const inputData = {
            password: passwordField,
            expectedHash: hash
        };
        
        fs.writeFileSync(inputPath, JSON.stringify(inputData, null, 2));
        console.log(`✅ Fichier ${path.relative(process.cwd(), inputPath)} mis à jour`);
        
        return { passwordField, hash };
        
    } catch (error) {
        console.error('❌ Erreur lors de la génération du hash:', error.message);
        process.exit(1);
    }
}

// Exécuter si appelé directement
if (require.main === module) {
    const password = process.argv[2] || 'cybersec2024';
    generateHashForPassword(password);
}

module.exports = { generateHashForPassword, calculatePoseidonHash, stringToFieldElement };