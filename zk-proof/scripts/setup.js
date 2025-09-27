const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const util = require('util');

const execAsync = util.promisify(exec);

async function setup() {
    console.log('🚀 Démarrage du setup ZK-SNARK...\n');
    
    try {
        // Créer le dossier build s'il n'existe pas
        const buildDir = path.join(__dirname, '..', 'build');
        if (!fs.existsSync(buildDir)) {
            fs.mkdirSync(buildDir, { recursive: true });
            console.log('📁 Dossier build créé');
        }
        
        // Étape 1: Compiler le circuit Circom
        console.log('⚙️  Compilation du circuit Circom...');
        const circuitPath = path.join(__dirname, '..', 'circuits', 'password_verification.circom');
        const buildPath = path.join(__dirname, '..', 'build');
        
        await execAsync(`circom "${circuitPath}" --r1cs --wasm --sym -o "${buildPath}"`);
        console.log('✅ Circuit compilé avec succès');
        
        // Étape 2: Télécharger les paramètres Powers of Tau (si pas déjà présents)
        const ptauPath = path.join(buildPath, 'powersOfTau28_hez_final_10.ptau');
        if (!fs.existsSync(ptauPath)) {
            console.log('📥 Téléchargement des paramètres Powers of Tau...');
            await execAsync(`curl -o "${ptauPath}" https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_10.ptau`);
            console.log('✅ Paramètres Powers of Tau téléchargés');
        } else {
            console.log('✅ Paramètres Powers of Tau déjà présents');
        }
        
        // Étape 3: Générer la clé de vérification
        console.log('🔑 Génération de la clé de vérification...');
        const r1csPath = path.join(buildPath, 'password_verification.r1cs');
        const zkeyPath = path.join(buildPath, 'password_verification_final.zkey');
        
        // Setup initial
        await execAsync(`snarkjs groth16 setup "${r1csPath}" "${ptauPath}" "${zkeyPath}"`);
        console.log('✅ Clé de vérification générée');
        
        // Étape 4: Exporter la clé de vérification
        console.log('📤 Export de la clé de vérification...');
        const vkeyPath = path.join(buildPath, 'verification_key.json');
        await execAsync(`snarkjs zkey export verificationkey "${zkeyPath}" "${vkeyPath}"`);
        console.log('✅ Clé de vérification exportée');
        
        console.log('\n🎉 Setup terminé avec succès!');
        console.log('📋 Fichiers générés:');
        console.log(`   - ${path.relative(process.cwd(), r1csPath)}`);
        console.log(`   - ${path.relative(process.cwd(), zkeyPath)}`);
        console.log(`   - ${path.relative(process.cwd(), vkeyPath)}`);
        console.log(`   - ${path.relative(process.cwd(), path.join(buildPath, 'password_verification_js'))}`);
        
    } catch (error) {
        console.error('❌ Erreur lors du setup:', error.message);
        process.exit(1);
    }
}

// Exécuter le setup si ce script est appelé directement
if (require.main === module) {
    setup();
}

module.exports = { setup };