const fs = require('fs');
const path = require('path');

async function runDemo() {
    console.log('🎯 Démonstration ZK-SNARK - Laboratoire CyberSec\n');
    
    // Vérifier si le setup a été fait
    const buildDir = path.join(__dirname, 'build');
    const zkeyPath = path.join(buildDir, 'password_verification_final.zkey');
    
    if (!fs.existsSync(zkeyPath)) {
        console.log('⚠️  Setup requis. Exécution automatique...\n');
        
        try {
            const { setup } = require('./scripts/setup.js');
            await setup();
            console.log('\n');
        } catch (error) {
            console.error('❌ Erreur lors du setup:', error.message);
            console.log('\n💡 Essayez manuellement: npm run setup');
            return;
        }
    }
    
    // Exécuter la démonstration de preuve
    try {
        const { generateAndVerifyProof } = require('./scripts/prove.js');
        await generateAndVerifyProof();
        
        console.log('\n🎉 Démonstration terminée avec succès!');
        console.log('\n📋 Fichiers générés:');
        console.log('   - proof.json (preuve ZK-SNARK)');
        console.log('   - public.json (signaux publics)');
        console.log('   - build/ (circuit compilé et clés)');
        
    } catch (error) {
        console.error('❌ Erreur lors de la démonstration:', error.message);
    }
}

// Exécuter la démonstration si ce script est appelé directement
if (require.main === module) {
    runDemo().catch(console.error);
}

module.exports = { runDemo };