const fs = require('fs');
const path = require('path');
const snarkjs = require('snarkjs');

// Fonction pour convertir une chaîne en nombre pour Poseidon
function stringToFieldElement(str) {
    // Convertir la chaîne en bytes puis en nombre
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

async function generateAndVerifyProof() {
    console.log('🎯 Démonstration ZK-SNARK - Preuve de Mot de Passe\\n');
    
    try {
        // Paramètres de démonstration
        const password = 'cybersec2024';
        console.log('=== Génération de Preuve ZK-SNARK ===');
        console.log(`Mot de passe (secret): ${password}`);
        
        // Calculer le hash attendu
        const expectedHash = await calculatePoseidonHash(password);
        console.log(`Hash attendu (public): ${expectedHash.substring(0, 5)}...\\n`);
        
        // Préparer les entrées du circuit
        const input = {
            password: stringToFieldElement(password),
            expectedHash: expectedHash
        };
        
        // Chemins des fichiers
        const buildDir = path.join(__dirname, '..', 'build');
        const wasmPath = path.join(buildDir, 'password_verification_js', 'password_verification.wasm');
        const zkeyPath = path.join(buildDir, 'password_verification_final.zkey');
        const vkeyPath = path.join(buildDir, 'verification_key.json');
        
        // Vérifier que les fichiers existent
        if (!fs.existsSync(wasmPath)) {
            throw new Error('Fichier WASM non trouvé. Exécutez d\'abord \'npm run setup\'');
        }
        
        // Étape 1: Générer le témoin
        console.log('⚙️  Génération du témoin...');
        const { witness } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);
        console.log('✅ Témoin généré');
        
        // Étape 2: Générer la preuve
        console.log('🔐 Génération de la preuve ZK-SNARK...');
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);
        console.log('✅ Preuve générée');
        
        // Sauvegarder la preuve
        const proofPath = path.join(__dirname, '..', 'proof.json');
        const publicPath = path.join(__dirname, '..', 'public.json');
        
        fs.writeFileSync(proofPath, JSON.stringify(proof, null, 2));
        fs.writeFileSync(publicPath, JSON.stringify(publicSignals, null, 2));
        console.log('✅ Preuve sauvegardée\\n');
        
        // Étape 3: Vérifier la preuve
        console.log('=== Vérification de la Preuve ===');
        
        // Charger la clé de vérification
        const vKey = JSON.parse(fs.readFileSync(vkeyPath));
        
        // Vérifier la preuve
        const isValid = await snarkjs.groth16.verify(vKey, publicSignals, proof);
        
        if (isValid) {
            console.log('✅ PREUVE VALIDE - Le mot de passe est correct!');
            console.log('🔒 Le secret n\'a jamais été révélé');
        } else {
            console.log('❌ PREUVE INVALIDE - Le mot de passe est incorrect!');
        }
        
        console.log('\\n📊 Détails de la preuve:');
        console.log(`   - Signal public (isValid): ${publicSignals[0]}`);
        console.log(`   - Taille de la preuve: ${JSON.stringify(proof).length} bytes`);
        console.log(`   - Hash utilisé: ${expectedHash}`);
        
        return isValid;
        
    } catch (error) {
        console.error('❌ Erreur lors de la génération/vérification:', error.message);
        process.exit(1);
    }
}

// Fonction pour tester avec un mauvais mot de passe
async function testInvalidPassword() {
    console.log('\\n🧪 Test avec un mot de passe incorrect...');
    
    try {
        const wrongPassword = 'wrongpassword';
        const correctHash = await calculatePoseidonHash('cybersec2024');
        
        const input = {
            password: stringToFieldElement(wrongPassword),
            expectedHash: correctHash
        };
        
        const buildDir = path.join(__dirname, '..', 'build');
        const wasmPath = path.join(buildDir, 'password_verification_js', 'password_verification.wasm');
        const zkeyPath = path.join(buildDir, 'password_verification_final.zkey');
        const vkeyPath = path.join(buildDir, 'verification_key.json');
        
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);
        const vKey = JSON.parse(fs.readFileSync(vkeyPath));
        const isValid = await snarkjs.groth16.verify(vKey, publicSignals, proof);
        
        console.log(`Signal de sortie: ${publicSignals[0]} (0 = invalide, 1 = valide)`);
        console.log(isValid ? '✅ Preuve techniquement valide mais mot de passe incorrect' : '❌ Preuve invalide');
        
    } catch (error) {
        console.error('Erreur lors du test:', error.message);
    }
}

// Exécuter la démonstration si ce script est appelé directement
if (require.main === module) {
    generateAndVerifyProof()
        .then(() => testInvalidPassword())
        .catch(console.error);
}

module.exports = { generateAndVerifyProof, calculatePoseidonHash };