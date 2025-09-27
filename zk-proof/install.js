const { exec } = require('child_process');
const util = require('util');
const fs = require('fs');
const path = require('path');

const execAsync = util.promisify(exec);

async function checkPrerequisites() {
    console.log('🔍 Vérification des prérequis...\n');
    
    const checks = [
        { name: 'Node.js', command: 'node --version', minVersion: '16.0.0' },
        { name: 'npm', command: 'npm --version' },
        { name: 'Circom', command: 'circom --version' },
        { name: 'curl', command: 'curl --version' }
    ];
    
    for (const check of checks) {
        try {
            const { stdout } = await execAsync(check.command);
            const version = stdout.trim().split('\n')[0];
            console.log(`✅ ${check.name}: ${version}`);
        } catch (error) {
            console.log(`❌ ${check.name}: Non installé ou non accessible`);
            
            if (check.name === 'Circom') {
                console.log('   💡 Installation: npm install -g circom');
            }
            if (check.name === 'curl') {
                console.log('   💡 curl est requis pour télécharger les paramètres Powers of Tau');
            }
        }
    }
    console.log('');
}

async function installDependencies() {
    console.log('📦 Installation des dépendances npm...');
    
    try {
        await execAsync('npm install');
        console.log('✅ Dépendances installées avec succès\n');
    } catch (error) {
        console.error('❌ Erreur lors de l\'installation des dépendances:', error.message);
        process.exit(1);
    }
}

async function createDirectories() {
    console.log('📁 Création des dossiers nécessaires...');
    
    const dirs = ['build', 'scripts'];
    
    for (const dir of dirs) {
        const dirPath = path.join(__dirname, dir);
        if (!fs.existsSync(dirPath)) {
            fs.mkdirSync(dirPath, { recursive: true });
            console.log(`   ✅ ${dir}/`);
        } else {
            console.log(`   ✅ ${dir}/ (existe déjà)`);
        }
    }
    console.log('');
}

async function displayInstructions() {
    console.log('🎯 Installation terminée! Prochaines étapes:\n');
    console.log('1. Compiler le circuit et générer les clés:');
    console.log('   npm run setup\n');
    console.log('2. Générer et vérifier une preuve:');
    console.log('   npm run prove\n');
    console.log('3. Exécuter le test complet:');
    console.log('   npm test\n');
    console.log('📚 Consultez le README.md pour plus d\'informations.');
}

async function install() {
    console.log('🚀 Installation du laboratoire ZK-SNARK\n');
    
    await checkPrerequisites();
    await createDirectories();
    await installDependencies();
    await displayInstructions();
}

// Exécuter l'installation si ce script est appelé directement
if (require.main === module) {
    install().catch(console.error);
}

module.exports = { install };