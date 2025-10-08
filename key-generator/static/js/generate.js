/**
 * Générateur de clés cryptographiques - Interface utilisateur
 * ========================================================
 * 
 * Interface moderne et accessible pour la génération de clés.
 * Compatible avec les standards 2025 et optimisé pour l'UX.
 */

// Configuration des formats de sortie
const OUTPUT_FORMATS = {
    'pem': { name: 'PEM', description: 'Format standard ASCII' },
    'der': { name: 'DER', description: 'Format binaire' },
    'pkcs8': { name: 'PKCS#8', description: 'Standard PKCS#8' },
    'pkcs12': { name: 'PKCS#12', description: 'Archive avec certificat' },
    'jwk': { name: 'JWK', description: 'JSON Web Key' },
    'base64': { name: 'Base64', description: 'Encodage Base64' },
    'hex': { name: 'Hexadécimal', description: 'Format hexadécimal' },
    'raw': { name: 'Binaire', description: 'Données brutes' },
    'bip39_mnemonic': { name: 'BIP39 Mnémonique', description: 'Phrase mnémonique' },
    'openssh': { name: 'OpenSSH', description: 'Format OpenSSH' }
};

// Configuration des types de clés avec formats recommandés
const KEY_TYPES_CONFIG = {
    'symmetric': { 
        default_format: 'base64',
        formats: ['base64', 'hex', 'raw']
    },
    'rsa': { 
        default_format: 'pem',
        formats: ['pem', 'der', 'pkcs8', 'jwk']
    },
    'ecc': { 
        default_format: 'pem',
        formats: ['pem', 'der', 'pkcs8', 'jwk']
    },
    'ed25519': { 
        default_format: 'pem',
        formats: ['pem', 'der', 'pkcs8', 'jwk']
    },
    'x25519': { 
        default_format: 'pem',
        formats: ['pem', 'der', 'pkcs8', 'jwk']
    },
    'ssh': { 
        default_format: 'openssh',
        formats: ['openssh', 'pem']
    },
    'tls_cert': { 
        default_format: 'pem',
        formats: ['pem', 'pkcs12', 'der']
    },
    'bip39': { 
        default_format: 'bip39_mnemonic',
        formats: ['bip39_mnemonic', 'hex']
    },
    'jwt': { 
        default_format: 'jwk',
        formats: ['jwk', 'base64']
    },
    'hmac': { 
        default_format: 'base64',
        formats: ['base64', 'hex']
    },
    'totp': { 
        default_format: 'base64',
        formats: ['base64', 'hex']
    },
    'kdf': { 
        default_format: 'base64',
        formats: ['base64', 'hex']
    },
    'post_quantum': { 
        default_format: 'pem',
        formats: ['pem', 'jwk']
    }
};

// Gestionnaire des types de clés
class KeyTypesManager {
    static getKeySizeForAlgorithm(algorithm) {
        const algorithmSizes = {
            'aes256': 256, 'aes192': 192, 'aes128': 128,
            'chacha20poly1305': 256, 'camellia256': 256,
            'rsa2048': 2048, 'rsa3072': 3072, 'rsa4096': 4096,
            'secp256r1': 256, 'secp384r1': 384, 'secp521r1': 521,
            'secp256k1': 256, 'ed25519': 256, 'x25519': 256,
            'ecdsap256': 256, 'ecdsap384': 384, 'ecdsap521': 521,
            'hmacsha256': 256, 'hmacsha384': 384, 'hmacsha512': 512,
            'totpsha256': 256, 'totpsha512': 512,
            'argon2id': 256, 'pbkdf2': 256, 'scrypt': 256,
            'mlkem768': 1184, 'mldsa65': 1952, 'hqc192': 3328,
            'slhdsasha2192f': 48
        };
        return algorithmSizes[algorithm] || 256;
    }

    static getRecommendedFormatsForKeyType(keyType) {
        return KEY_TYPES_CONFIG[keyType]?.formats || ['pem', 'base64'];
    }

    static validateKeyConfiguration(keyType, algorithm, keySize) {
        if (!keyType) return { valid: false, message: 'Type de clé requis' };
        if (!algorithm) return { valid: false, message: 'Algorithme requis' };
        if (keySize < 128) return { valid: false, message: 'Taille minimale: 128 bits' };
        
        // Validation spécifique 2025
        if (keyType === 'rsa' && keySize < 3072) {
            return { valid: false, message: 'RSA: minimum 3072 bits (standard 2025)' };
        }
        
        return { valid: true };
    }

    static getSecurityWarnings(keyType) {
        const warnings = [];
        
        if (keyType === 'rsa') {
            warnings.push('RSA: Considérez Ed25519 pour de meilleures performances');
        }
        if (keyType === 'bip39') {
            warnings.push('BIP39: Stockez la phrase mnémonique de manière sécurisée');
        }
        if (keyType === 'post_quantum') {
            warnings.push('Post-Quantum: Technologie émergente, testez la compatibilité');
        }
        
        return warnings;
    }
}

class KeyGenerator {
    constructor() {
        this.keyTypes = null;
        this.initializeEventListeners();
        this.loadKeyTypes();
        this.setupPasswordValidation();
    }

    /**
     * Initialise tous les écouteurs d'événements
     */
    initializeEventListeners() {
        // Type de clé
        const keyTypeSelect = document.getElementById('keyType');
        if (keyTypeSelect) {
            keyTypeSelect.addEventListener('change', (e) => {
                const keyType = e.target.value;
                this.updateAlgorithms(keyType);
                this.updateKeySize(keyType);
                this.updateOutputFormats(keyType);
                this.toggleSpecialParams(keyType);
                this.updateProgress();
            });
        }

        // Algorithme
        const algorithmSelect = document.getElementById('algorithm');
        if (algorithmSelect) {
            algorithmSelect.addEventListener('change', (e) => {
                this.updateKeySizeForAlgorithm(e.target.value);
                this.updateProgress();
            });
        }

        // Protection par mot de passe
        const passwordProtectedCheckbox = document.getElementById('passwordProtected');
        if (passwordProtectedCheckbox) {
            passwordProtectedCheckbox.addEventListener('change', (e) => {
                this.togglePasswordSection(e.target.checked);
                this.updateProgress();
            });
        }

        // Génération de mot de passe
        const generatePasswordBtn = document.getElementById('generatePassword');
        if (generatePasswordBtn) {
            generatePasswordBtn.addEventListener('click', () => this.generateSecurePassword());
        }

        // Visibilité du mot de passe
        const togglePasswordBtn = document.getElementById('togglePassword');
        if (togglePasswordBtn) {
            togglePasswordBtn.addEventListener('click', () => this.togglePasswordVisibility());
        }

        // Validation en temps réel du mot de passe
        const passwordInput = document.getElementById('password');
        if (passwordInput) {
            passwordInput.addEventListener('input', (e) => {
                this.validatePasswordStrength(e.target.value);
                this.updateProgress();
            });
        }

        // Soumission du formulaire
        const form = document.getElementById('keyGenerationForm');
        if (form) {
            form.addEventListener('submit', (e) => {
                e.preventDefault();
                this.generateKey();
            });
        }

        // Synchronisation taille de clé
        const keySizeRange = document.getElementById('keySizeRange');
        const keySizeInput = document.getElementById('keySize');
        
        if (keySizeRange && keySizeInput) {
            keySizeRange.addEventListener('input', (e) => {
                keySizeInput.value = e.target.value;
                this.updateProgress();
            });
            
            keySizeInput.addEventListener('input', (e) => {
                keySizeRange.value = e.target.value;
                this.updateProgress();
            });
        }
    }

    /**
     * Charge les types de clés depuis l'API
     */
    async loadKeyTypes() {
        try {
            const response = await fetch('/api/key-types');
            if (response.ok) {
                this.keyTypes = await response.json();
                this.populateKeyTypes();
            } else {
                console.warn('API non disponible, utilisation de la configuration locale');
                this.loadFallbackKeyTypes();
            } 
        } catch (error) {
            console.warn('Erreur API, utilisation de la configuration locale:', error);
            this.loadFallbackKeyTypes();
        }
    }

    /**
     * Configuration locale de fallback pour les types de clés
     */
    loadFallbackKeyTypes() {
        this.keyTypes = {
            'symmetric': { name: 'Clés Symétriques', algorithms: ['AES-256', 'ChaCha20-Poly1305'] },
            'rsa': { name: 'RSA', algorithms: ['RSA-3072', 'RSA-4096'] },
            'ecc': { name: 'ECC', algorithms: ['secp256r1', 'secp384r1'] },
            'ed25519': { name: 'Ed25519', algorithms: ['Ed25519'] },
            'x25519': { name: 'X25519', algorithms: ['X25519'] },
            'ssh': { name: 'Clés SSH', algorithms: ['Ed25519', 'ECDSA', 'RSA'] },
            'tls_cert': { name: 'Certificats TLS', algorithms: ['ECDSA', 'RSA', 'Ed25519'] },
            'bip39': { name: 'BIP39', algorithms: ['BIP39-256', 'BIP39-192'] },
            'jwt': { name: 'JWT', algorithms: ['ES256', 'HS512', 'EdDSA'] },
            'hmac': { name: 'HMAC', algorithms: ['HMAC-SHA256', 'HMAC-SHA512'] },
            'totp': { name: 'TOTP', algorithms: ['TOTP'] },
            'kdf': { name: 'KDF', algorithms: ['Argon2id', 'PBKDF2', 'scrypt'] },
            'post_quantum': { name: 'Post-Quantum', algorithms: ['ML-KEM-768', 'ML-DSA-65'] }
        };
        this.populateKeyTypes();
    }

    /**
     * Remplit la liste des types de clés
     */
    populateKeyTypes() {
        const keyTypeSelect = document.getElementById('keyType');
        if (!keyTypeSelect || !this.keyTypes) return;

        // Vider les options existantes sauf la première
        keyTypeSelect.innerHTML = '<option value="">Sélectionnez un type de clé</option>';

        Object.entries(this.keyTypes).forEach(([key, value]) => {
            const option = document.createElement('option');
            option.value = key;
            option.textContent = value.name;
            option.title = value.description || '';
            keyTypeSelect.appendChild(option);
        });
    }

    /**
     * Met à jour les algorithmes disponibles selon le type de clé
     */
    updateAlgorithms(keyType) {
        const algorithmSelect = document.getElementById('algorithm');
        if (!algorithmSelect) return;
        
        algorithmSelect.innerHTML = '<option value="">Sélectionnez un algorithme</option>';
        algorithmSelect.disabled = true;

        if (!keyType || !this.keyTypes) return;

        const algorithms = this.keyTypes[keyType]?.algorithms || [];
        
        algorithms.forEach(algorithm => {
            const option = document.createElement('option');
            option.value = algorithm.toLowerCase().replace(/[^a-z0-9]/g, '');
            option.textContent = algorithm;
            option.title = `Algorithme ${algorithm}`;
            algorithmSelect.appendChild(option);
        });

        if (algorithms.length > 0) {
            algorithmSelect.disabled = false;
            // Sélectionner le premier algorithme par défaut
            if (algorithms[0]) {
                algorithmSelect.value = algorithms[0].toLowerCase().replace(/[^a-z0-9]/g, '');
                this.updateKeySizeForAlgorithm(algorithmSelect.value);
            }
        }
    }

    /**
     * Met à jour la taille de clé par défaut selon le type de clé
     */
    updateKeySize(keyType) {
        const keySizeInput = document.getElementById('keySize');
        const rangeInput = document.getElementById('keySizeRange');
        
        if (!keySizeInput || !rangeInput) return;
        
        const defaultSizes = {
            'symmetric': 256,
            'rsa': 3072,
            'ecc': 256,
            'ed25519': 256,
            'x25519': 256,
            'ssh': 256,
            'tls_cert': 256,
            'bip39': 256,
            'jwt': 256,
            'hmac': 512,
            'totp': 256,
            'kdf': 256,
            'post_quantum': 1184
        };

        const size = defaultSizes[keyType] || 256;
        keySizeInput.value = size;
        rangeInput.value = size;
        rangeInput.min = Math.min(128, size / 2);
        rangeInput.max = Math.max(8192, size * 2);
        
        // Announce for screen readers
        this.announceLiveRegion(`Taille mise à jour: ${size} bits`);
    }

    /**
     * Met à jour la taille de clé selon l'algorithme sélectionné
     */
    updateKeySizeForAlgorithm(algorithm) {
        const keySizeInput = document.getElementById('keySize');
        const rangeInput = document.getElementById('keySizeRange');
        
        if (!keySizeInput || !rangeInput) return;
        
        const size = KeyTypesManager.getKeySizeForAlgorithm(algorithm);
        keySizeInput.value = size;
        rangeInput.value = size;
        rangeInput.min = Math.min(128, size / 2);
        rangeInput.max = Math.max(8192, size * 2);
        
        // Announce for screen readers
        this.announceLiveRegion(`Taille mise à jour: ${size} bits`);
    }

    /**
     * Met à jour les formats de sortie disponibles
     */
    updateOutputFormats(keyType) {
        const outputFormatSelect = document.getElementById('outputFormat');
        if (!outputFormatSelect) return;
        
        const formats = KeyTypesManager.getRecommendedFormatsForKeyType(keyType);
        
        outputFormatSelect.innerHTML = '';
        formats.forEach(format => {
            const option = document.createElement('option');
            option.value = format;
            option.textContent = OUTPUT_FORMATS[format]?.name || format;
            option.title = OUTPUT_FORMATS[format]?.description || '';
            outputFormatSelect.appendChild(option);
        });

        // Sélectionner le format par défaut
        const defaultFormat = KEY_TYPES_CONFIG[keyType]?.default_format || 'pem';
        if (formats.includes(defaultFormat)) {
            outputFormatSelect.value = defaultFormat;
        }
    }

    /**
     * Affiche/masque les paramètres spéciaux selon le type de clé
     */
    toggleSpecialParams(keyType) {
        const tlsParams = document.getElementById('tlsParams');
        const kdfParams = document.getElementById('kdfParams');
        
        if (!tlsParams || !kdfParams) return;
        
        // Masquer tous
        tlsParams.style.display = 'none';
        kdfParams.style.display = 'none';
        
        if (keyType === 'tls_cert') {
            tlsParams.style.display = 'block';
            this.announceLiveRegion('Paramètres TLS affichés');
        } else if (keyType === 'kdf') {
            kdfParams.style.display = 'block';
            this.announceLiveRegion('Paramètres KDF affichés');
        }
    }

    /**
     * Affiche/masque la section mot de passe
     */
    togglePasswordSection(enabled) {
        const passwordSection = document.getElementById('passwordSection');
        if (!passwordSection) return;
        
        passwordSection.style.display = enabled ? 'block' : 'none';
        
        if (!enabled) {
            const passwordInput = document.getElementById('password');
            if (passwordInput) passwordInput.value = '';
            this.clearPasswordStrength();
            this.announceLiveRegion('Section mot de passe masquée');
        } else {
            this.announceLiveRegion('Section mot de passe activée');
        }
    }

    /**
     * Génère un mot de passe sécurisé (2025: Argon2-like strength)
     */
    async generateSecurePassword() {
        try {
            const response = await fetch('/api/generate-password?length=20&strength=4', {
                method: 'POST'
            });
            const data = await response.json();
            
            if (data.password) {
                document.getElementById('password').value = data.password;
                this.validatePasswordStrength(data.password);
                this.announceLiveRegion('Mot de passe généré (force excellente)');
                this.showSuccess('Mot de passe sécurisé généré !');
            } else {
                this.generateFallbackPassword();
            }
        } catch (error) {
            console.error('Erreur API:', error);
            this.generateFallbackPassword();
        }
    }

    generateFallbackPassword() {
        // Fallback client-side
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
        let pwd = '';
        for (let i = 0; i < 20; i++) pwd += chars[Math.floor(Math.random() * chars.length)];
        
        const passwordInput = document.getElementById('password');
        if (passwordInput) {
            passwordInput.value = pwd;
            this.validatePasswordStrength(pwd);
            this.showWarning('Mot de passe généré localement (recommandé API pour entropie)');
        }
    }

    /**
     * Toggle la visibilité du mot de passe
     */
    togglePasswordVisibility() {
        const passwordInput = document.getElementById('password');
        const toggleBtn = document.getElementById('togglePassword');
        
        if (!passwordInput || !toggleBtn) return;
        
        const icon = toggleBtn.querySelector('i');
        
        passwordInput.type = passwordInput.type === 'password' ? 'text' : 'password';
        if (icon) {
            icon.className = passwordInput.type === 'password' ? 'fas fa-eye' : 'fas fa-eye-slash';
        }
        this.announceLiveRegion(passwordInput.type === 'text' ? 'Mot de passe visible' : 'Mot de passe masqué');
    }

    /**
     * Valide la force du mot de passe (2025: zxcvbn + OWASP)
     */
    async validatePasswordStrength(password) {
        if (!password) {
            this.clearPasswordStrength();
            return;
        }

        // Client-side zxcvbn si disponible
        let strength = { score: 0, feedback: { warning: 'Mot de passe faible' } };
        if (typeof zxcvbn !== 'undefined') {
            strength = zxcvbn(password);
        }
        
        try {
            const response = await fetch('/api/validate-password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: password })
            });
            const data = await response.json();
            
            const score = Math.max(strength.score, data.score || 0);
            this.updatePasswordStrengthIndicator(score, data.warnings || [strength.feedback.warning]);
            this.announceLiveRegion(`Force: ${['Faible', 'Moyen', 'Bon', 'Excellent'][score]}`);
        } catch (error) {
            // Fallback zxcvbn
            this.updatePasswordStrengthIndicator(strength.score, [strength.feedback.warning || 'Améliorez la complexité']);
        }
    }

    /**
     * Met à jour l'indicateur de force du mot de passe
     */
    updatePasswordStrengthIndicator(score, warnings) {
        const strengthIndicator = document.getElementById('passwordStrength');
        const strengthBar = document.getElementById('strengthBar');
        const strengthText = document.getElementById('strengthText');
        
        if (!strengthBar || !strengthText) return;
        
        const colors = ['danger', 'warning', 'info', 'success'];
        const labels = ['Faible', 'Moyen', 'Bon', 'Excellent'];
        
        strengthBar.style.width = `${(score / 4) * 100}%`;
        strengthBar.className = `progress-bar bg-${colors[score] || 'danger'}`;
        strengthText.textContent = labels[score] || 'Faible';
        
        if (strengthIndicator) {
            strengthIndicator.title = warnings ? warnings.join('; ') : 'Mot de passe fort';
            strengthIndicator.setAttribute('aria-valuenow', score);
            strengthIndicator.setAttribute('aria-label', `Force du mot de passe: ${strengthText.textContent}`);
        }
    }

    /**
     * Efface l'indicateur de force du mot de passe
     */
    clearPasswordStrength() {
        const strengthBar = document.getElementById('strengthBar');
        const strengthText = document.getElementById('strengthText');
        const strengthIndicator = document.getElementById('passwordStrength');
        
        if (strengthBar) {
            strengthBar.style.width = '0%';
            strengthBar.className = 'progress-bar bg-secondary';
        }
        if (strengthText) {
            strengthText.textContent = 'Aucune';
        }
        if (strengthIndicator) {
            strengthIndicator.title = '';
            strengthIndicator.setAttribute('aria-valuenow', 0);
        }
    }

    /**
     * Configure la validation du mot de passe
     */
    setupPasswordValidation() {
        const passwordInput = document.getElementById('password');
        if (!passwordInput) return;
        
        passwordInput.addEventListener('blur', () => {
            if (passwordInput.value && passwordInput.value.length < 12) {
                this.showWarning('Minimum 12 caractères (OWASP 2025)');
                passwordInput.classList.add('is-invalid');
            } else {
                passwordInput.classList.remove('is-invalid');
            }
        });
    }

    /**
     * Génère une clé cryptographique avec validation 2025
     */
    async generateKey() {
        const form = document.getElementById('keyGenerationForm');
        if (!form) return;
        
        const formData = new FormData(form);
        
        // Validation avancée
        const validation = KeyTypesManager.validateKeyConfiguration(
            formData.get('key_type'),
            formData.get('algorithm'),
            parseInt(formData.get('key_size'))
        );
        if (!validation.valid) {
            this.showError(validation.message);
            return;
        }

        // Préparer données
        const requestData = {
            key_type: formData.get('key_type'),
            algorithm: formData.get('algorithm'),
            key_size: parseInt(formData.get('key_size')),
            output_format: formData.get('output_format'),
            password_protected: formData.get('password_protected') === 'on',
            password: formData.get('password') || null
        };

        // Params spéciaux
        if (requestData.key_type === 'tls_cert') {
            Object.assign(requestData, {
                common_name: formData.get('common_name'),
                organization: formData.get('organization'),
                country: formData.get('country'),
                email: formData.get('email'),
                validity_days: parseInt(formData.get('validity_days'))
            });
        } else if (requestData.key_type === 'kdf') {
            Object.assign(requestData, {
                iterations: parseInt(formData.get('iterations')),
                salt_length: parseInt(formData.get('salt_length'))
            });
        }

        this.showLoading(true);
        this.announceLiveRegion('Génération en cours...');

        try {
            const response = await fetch('/api/generate-key', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(requestData)
            });

            const result = await response.json();

            if (response.ok) {
                this.displayResult(result);
                const warnings = KeyTypesManager.getSecurityWarnings(requestData.key_type);
                if (warnings.length > 0) {
                    this.showSecurityWarnings(warnings);
                }
                this.announceLiveRegion('Clé générée avec succès');
            } else {
                this.showError(result.detail || 'Erreur génération (vérifiez sécurité)');
            }
        } catch (error) {
            console.error('Génération échouée:', error);
            this.showError('Erreur réseau. Vérifiez connexion et réessayez.');
        } finally {
            this.showLoading(false);
        }
    }

    /**
     * Affiche le résultat de la génération avec copier/télécharger
     */
    displayResult(result) {
        const resultContainer = document.getElementById('resultContainer');
        const noResultContainer = document.getElementById('noResultContainer');
        const resultContent = document.getElementById('resultContent');

        if (!resultContainer || !resultContent) return;

        if (noResultContainer) noResultContainer.style.display = 'none';
        resultContainer.classList.remove('d-none');

        let content = `
            <div class="mb-4 p-3 bg-tertiary rounded" role="status">
                <h5 class="text-gradient mb-2">
                    <i class="fas fa-key me-2" aria-hidden="true"></i>
                    ${result.key_type.toUpperCase()} - ${result.format.toUpperCase()}
                </h5>
                <div class="row small text-ghost-secondary">
                    <div class="col-md-6">
                        <p><strong>Algorithme:</strong> ${result.algorithm}</p>
                        <p><strong>Taille:</strong> ${result.key_size} bits</p>
                        <p><strong>Fingerprint:</strong> ${result.fingerprint || 'N/A'}</p>
                    </div>
                    <div class="col-md-6">
                        <p><strong>Créé:</strong> ${new Date(result.created_at).toLocaleString('fr-FR')}</p>
                        ${result.expires_at ? `<p><strong>Expire:</strong> ${new Date(result.expires_at).toLocaleString('fr-FR')}</p>` : ''}
                        <p><strong>UUID:</strong> ${result.uuid?.slice(0,8)}...</p>
                    </div>
                </div>
            </div>
        `;

        // Clé principale
        if (result.key_data) {
            const keyData = typeof result.key_data === 'string' ? result.key_data : JSON.stringify(result.key_data, null, 2);
            content += `
                <div class="code-block-ghost position-relative mb-4" id="keyDataBlock">
                    <pre class="mb-0">${keyData}</pre>
                    <button class="btn btn-sm btn-outline-light position-absolute top-0 end-0 m-2" onclick="copyKeyData()" aria-label="Copier la clé">
                        <i class="fas fa-copy" aria-hidden="true"></i>
                    </button>
                    <button class="btn btn-sm btn-outline-success position-absolute top-0 start-0 m-2" onclick="downloadKeyFile()" aria-label="Télécharger">
                        <i class="fas fa-download" aria-hidden="true"></i>
                    </button>
                </div>
            `;
        }

        // Clé publique si disponible
        if (result.public_key) {
            content += `
                <div class="code-block-ghost position-relative mb-4">
                    <h6 class="text-white mb-2">Clé Publique</h6>
                    <pre class="mb-0">${result.public_key}</pre>
                    <button class="btn btn-sm btn-outline-light position-absolute top-0 end-0 m-2" onclick="copyToClipboard('${result.public_key.replace(/'/g, "\\'")}')">
                        <i class="fas fa-copy"></i>
                    </button>
                </div>
            `;
        }

        // Métadonnées
        if (result.metadata) {
            content += `
                <details class="mb-4">
                    <summary class="text-gradient cursor-pointer">Métadonnées Détaillées <i class="fas fa-chevron-down ms-1"></i></summary>
                    <div class="code-block-ghost mt-2">
                        <pre class="mb-0">${JSON.stringify(result.metadata, null, 2)}</pre>
                    </div>
                </details>
            `;
        }

        resultContent.innerHTML = content;
        resultContainer.scrollIntoView({ behavior: 'smooth' });
        resultContainer.focus();
    }

    /**
     * Affiche les avertissements de sécurité
     */
    showSecurityWarnings(warnings) {
        const resultContent = document.getElementById('resultContent');
        if (!resultContent || !warnings.length) return;
        
        let alertHtml = `
            <div class="alert-ghost alert-ghost-warning mb-4" role="alert">
                <h6 class="alert-heading text-warning mb-2">
                    <i class="fas fa-exclamation-triangle me-2"></i>Avertissements Sécurité
                </h6>
                <ul class="mb-0 list-unstyled">
        `;
        warnings.forEach(w => {
            alertHtml += `<li class="small">${w}</li>`;
        });
        alertHtml += `
                </ul>
            </div>
        `;
        resultContent.insertAdjacentHTML('afterbegin', alertHtml);
    }

    /**
     * Met à jour la progression (5 étapes)
     */
    updateProgress() {
        const keyTypeValue = document.getElementById('keyType')?.value;
        const algorithmValue = document.getElementById('algorithm')?.value;
        const keySizeValue = parseInt(document.getElementById('keySize')?.value || 0);
        const outputFormatValue = document.getElementById('outputFormat')?.value;
        const passwordProtected = document.getElementById('passwordProtected')?.checked;
        const passwordValue = document.getElementById('password')?.value || '';

        const steps = [
            !!keyTypeValue,
            !!algorithmValue,
            keySizeValue >= 128,
            !!outputFormatValue,
            !passwordProtected || (passwordValue.length >= 12 && this.getPasswordScore(passwordValue) >= 3)
        ].filter(Boolean).length;

        const progress = document.getElementById('configProgress');
        const generateBtn = document.getElementById('generateBtn');
        
        if (progress) {
            progress.style.width = `${(steps / 5) * 100}%`;
        }
        
        if (generateBtn) {
            generateBtn.disabled = steps < 4; // Au moins 4/5 étapes
        }
    }

    getPasswordScore(password) {
        if (typeof zxcvbn !== 'undefined') {
            return zxcvbn(password).score;
        }
        // Fallback simple
        if (password.length < 8) return 0;
        if (password.length < 12) return 1;
        if (!/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/[0-9]/.test(password)) return 2;
        return 3;
    }

    /**
     * Annonce pour région live (accessibilité)
     */
    announceLiveRegion(message) {
        const liveRegion = document.getElementById('liveRegion') || (() => {
            const region = document.createElement('div');
            region.id = 'liveRegion';
            region.className = 'sr-only';
            region.setAttribute('aria-live', 'polite');
            region.setAttribute('aria-atomic', 'true');
            document.body.appendChild(region);
            return region;
        })();
        liveRegion.textContent = message;
    }

    /**
     * Affiche/masque le loading
     */
    showLoading(show) {
        const generateBtn = document.getElementById('generateBtn');
        const generateBtnText = document.getElementById('generateBtnText');
        const loadingSpinner = document.getElementById('loadingSpinner');

        if (show) {
            if (generateBtn) generateBtn.disabled = true;
            if (generateBtnText) generateBtnText.style.display = 'none';
            if (loadingSpinner) loadingSpinner.classList.remove('d-none');
            this.announceLiveRegion('Génération en cours...');
        } else {
            if (generateBtn) generateBtn.disabled = false;
            if (generateBtnText) generateBtnText.style.display = 'inline';
            if (loadingSpinner) loadingSpinner.classList.add('d-none');
            this.announceLiveRegion('Génération terminée');
        }
    }

    /**
     * Affiche un message de succès
     */
    showSuccess(message) {
        this.showAlert(message, 'success');
    }

    /**
     * Affiche un message d'erreur
     */
    showError(message) {
        this.showAlert(message, 'danger');
        this.announceLiveRegion(message);
    }

    /**
     * Affiche un message d'avertissement
     */
    showWarning(message) {
        this.showAlert(message, 'warning');
        this.announceLiveRegion(message);
    }

    /**
     * Affiche une alerte toast
     */
    showAlert(message, type) {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert-ghost alert-ghost-${type} alert-dismissible fade show position-fixed top-0 end-0 m-3`;
        alertDiv.style.maxWidth = '400px';
        alertDiv.style.zIndex = '9999';
        alertDiv.setAttribute('role', 'alert');
        
        const iconMap = {
            'success': 'check-circle',
            'warning': 'exclamation-triangle',
            'danger': 'times-circle',
            'info': 'info-circle'
        };
        
        alertDiv.innerHTML = `
            <i class="fas fa-${iconMap[type] || 'info-circle'} me-2 text-${type}"></i>
            ${message}
            <button type="button" class="btn-close btn-close-white ms-2" data-bs-dismiss="alert" aria-label="Fermer"></button>
        `;

        document.body.appendChild(alertDiv);

        // Auto-remove
        setTimeout(() => {
            if (alertDiv.parentNode) alertDiv.remove();
        }, 5000);

        // Bootstrap dismiss si disponible
        if (typeof bootstrap !== 'undefined' && bootstrap.Alert) {
            new bootstrap.Alert(alertDiv);
        }
    }
}

/**
 * Fonctions utilitaires globales
 */
function copyKeyData() {
    const block = document.getElementById('keyDataBlock');
    if (!block) return;
    
    const pre = block.querySelector('pre');
    const text = pre.textContent;
    
    navigator.clipboard.writeText(text).then(() => {
        const btn = block.querySelector('button[onclick="copyKeyData()"] i');
        if (btn) {
            const original = btn.className;
            btn.className = 'fas fa-check';
            setTimeout(() => btn.className = original, 2000);
        }
        showCopySuccess('Clé copiée dans le presse-papiers !');
    }).catch(() => showCopyError());
}

function downloadKeyFile() {
    const block = document.getElementById('keyDataBlock');
    if (!block) return;
    
    const pre = block.querySelector('pre');
    const content = pre.textContent;
    const blob = new Blob([content], { type: 'application/x-pem-file' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ghost-key-${Date.now()}.pem`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showCopySuccess('Fichier téléchargé ! Sécurisez-le.');
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showCopySuccess('Copié dans le presse-papiers !');
    }).catch(() => showCopyError());
}

function showCopySuccess(message = 'Copié dans le presse-papiers !') {
    if (window.KeyGeneratorInstance) {
        window.KeyGeneratorInstance.showSuccess(message);
    } else {
        console.log(message);
    }
}

function showCopyError() {
    if (window.KeyGeneratorInstance) {
        window.KeyGeneratorInstance.showError('Erreur de copie');
    } else {
        console.error('Erreur de copie');
    }
}

// Initialisation automatique
document.addEventListener('DOMContentLoaded', () => {
    window.KeyGeneratorInstance = new KeyGenerator();
    console.log('Générateur de clés initialisé avec succès');
});