/**
 * JavaScript pour le générateur de clés cryptographiques
 * Ghost Cyber Universe
 */

class KeyGenerator {
    constructor() {
        this.form = document.getElementById('keyGenerationForm');
        this.keyTypeSelect = document.getElementById('keyType');
        this.algorithmSelect = document.getElementById('algorithm');
        this.passwordInput = document.getElementById('password');
        this.passwordToggle = document.getElementById('togglePassword');
        this.generateButton = document.getElementById('generateButton');
        this.resultsCard = document.getElementById('resultsCard');
        this.securityWarnings = document.getElementById('securityWarnings');
        
        this.initializeEventListeners();
        this.loadKeyTypes();
    }

    initializeEventListeners() {
        // Changement de type de clé
        this.keyTypeSelect.addEventListener('change', () => {
            this.updateAlgorithmOptions();
            this.updateSpecificParams();
            this.updateOutputFormats();
        });

        // Toggle mot de passe
        this.passwordToggle.addEventListener('click', () => {
            this.togglePasswordVisibility();
        });

        // Génération de mot de passe
        document.getElementById('generatePassword').addEventListener('click', () => {
            this.generateSecurePassword();
        });

        // Validation de mot de passe
        document.getElementById('validatePassword').addEventListener('click', () => {
            this.validatePasswordStrength();
        });

        // Changement de mot de passe
        this.passwordInput.addEventListener('input', () => {
            this.updatePasswordStrength();
        });

        // Protection par mot de passe
        document.getElementById('passwordProtected').addEventListener('change', (e) => {
            this.togglePasswordSection(e.target.checked);
        });

        // Reset formulaire
        document.getElementById('resetForm').addEventListener('click', () => {
            this.resetForm();
        });

        // Soumission du formulaire
        this.form.addEventListener('submit', (e) => {
            e.preventDefault();
            this.generateKey();
        });
    }

    async loadKeyTypes() {
        try {
            const response = await fetch('/api/key-types');
            const keyTypes = await response.json();
            this.keyTypes = keyTypes;
        } catch (error) {
            console.error('Erreur lors du chargement des types de clés:', error);
        }
    }

    updateAlgorithmOptions() {
        const keyType = this.keyTypeSelect.value;
        const algorithmSelect = this.algorithmSelect;
        
        // Vider les options existantes
        algorithmSelect.innerHTML = '';

        if (!keyType) {
            algorithmSelect.innerHTML = '<option value="">Sélectionnez d\'abord un type...</option>';
            return;
        }

        const algorithms = this.getAlgorithmsForKeyType(keyType);
        
        algorithms.forEach(algorithm => {
            const option = document.createElement('option');
            option.value = algorithm.value;
            option.textContent = algorithm.label;
            algorithmSelect.appendChild(option);
        });
    }

    getAlgorithmsForKeyType(keyType) {
        const algorithms = {
            'symmetric': [
                { value: 'AES-128', label: 'AES-128' },
                { value: 'AES-192', label: 'AES-192' },
                { value: 'AES-256', label: 'AES-256 (Recommandé)' },
                { value: 'ChaCha20-Poly1305', label: 'ChaCha20-Poly1305' }
            ],
            'rsa': [
                { value: 'RSA-2048', label: 'RSA-2048' },
                { value: 'RSA-3072', label: 'RSA-3072' },
                { value: 'RSA-4096', label: 'RSA-4096' }
            ],
            'ecc': [
                { value: 'secp256r1', label: 'secp256r1 (P-256)' },
                { value: 'secp384r1', label: 'secp384r1 (P-384)' },
                { value: 'secp521r1', label: 'secp521r1 (P-521)' },
                { value: 'secp256k1', label: 'secp256k1 (Bitcoin)' }
            ],
            'ed25519': [
                { value: 'Ed25519', label: 'Ed25519' }
            ],
            'x25519': [
                { value: 'X25519', label: 'X25519' }
            ],
            'ssh': [
                { value: 'RSA', label: 'RSA' },
                { value: 'ECDSA', label: 'ECDSA' },
                { value: 'Ed25519', label: 'Ed25519 (Recommandé)' }
            ],
            'tls_cert': [
                { value: 'RSA', label: 'RSA' },
                { value: 'ECDSA', label: 'ECDSA' },
                { value: 'Ed25519', label: 'Ed25519' }
            ],
            'bip39': [
                { value: 'BIP39-128', label: 'BIP39-128 (12 mots)' },
                { value: 'BIP39-160', label: 'BIP39-160 (15 mots)' },
                { value: 'BIP39-192', label: 'BIP39-192 (18 mots)' },
                { value: 'BIP39-224', label: 'BIP39-224 (21 mots)' },
                { value: 'BIP39-256', label: 'BIP39-256 (24 mots)' }
            ],
            'jwt': [
                { value: 'HS256', label: 'HS256 (HMAC-SHA256)' },
                { value: 'HS512', label: 'HS512 (HMAC-SHA512)' },
                { value: 'RS256', label: 'RS256 (RSA-SHA256)' },
                { value: 'RS512', label: 'RS512 (RSA-SHA512)' },
                { value: 'ES256', label: 'ES256 (ECDSA-SHA256)' },
                { value: 'ES512', label: 'ES512 (ECDSA-SHA512)' },
                { value: 'EdDSA', label: 'EdDSA' }
            ],
            'hmac': [
                { value: 'HMAC-SHA256', label: 'HMAC-SHA256' },
                { value: 'HMAC-SHA512', label: 'HMAC-SHA512' }
            ],
            'totp': [
                { value: 'TOTP', label: 'TOTP' }
            ],
            'kdf': [
                { value: 'PBKDF2', label: 'PBKDF2' },
                { value: 'scrypt', label: 'scrypt' },
                { value: 'Argon2id', label: 'Argon2id (Recommandé)' }
            ]
        };

        return algorithms[keyType] || [];
    }

    updateSpecificParams() {
        const keyType = this.keyTypeSelect.value;
        
        // Masquer tous les paramètres spécifiques
        document.getElementById('rsaParams').style.display = 'none';
        document.getElementById('eccParams').style.display = 'none';
        document.getElementById('genericKeySize').style.display = 'none';
        document.getElementById('bip39Params').style.display = 'none';
        document.getElementById('certificateInfo').style.display = 'none';

        // Afficher les paramètres appropriés
        switch (keyType) {
            case 'rsa':
                document.getElementById('rsaParams').style.display = 'block';
                break;
            case 'ecc':
                document.getElementById('eccParams').style.display = 'block';
                break;
            case 'symmetric':
            case 'jwt':
            case 'hmac':
            case 'kdf':
                document.getElementById('genericKeySize').style.display = 'block';
                break;
            case 'bip39':
                document.getElementById('bip39Params').style.display = 'block';
                break;
            case 'tls_cert':
                document.getElementById('certificateInfo').style.display = 'block';
                break;
        }
    }

    updateOutputFormats() {
        const keyType = this.keyTypeSelect.value;
        const outputFormatSelect = document.getElementById('outputFormat');
        
        // Formats disponibles selon le type de clé
        const formats = {
            'symmetric': ['base64', 'hex', 'raw'],
            'rsa': ['pem', 'der', 'pkcs8', 'jwk'],
            'ecc': ['pem', 'der', 'pkcs8', 'jwk'],
            'ed25519': ['pem', 'der', 'pkcs8', 'jwk'],
            'x25519': ['pem', 'der', 'pkcs8', 'jwk'],
            'ssh': ['pem', 'openssh'],
            'tls_cert': ['pem', 'der', 'pkcs12'],
            'bip39': ['bip39_mnemonic', 'hex', 'base64'],
            'jwt': ['jwk', 'pem', 'der'],
            'hmac': ['base64', 'hex', 'raw'],
            'totp': ['base64', 'hex'],
            'kdf': ['base64', 'hex', 'raw']
        };

        const availableFormats = formats[keyType] || ['pem'];
        
        // Mettre à jour les options
        outputFormatSelect.innerHTML = '';
        availableFormats.forEach(format => {
            const option = document.createElement('option');
            option.value = format;
            option.textContent = this.getFormatLabel(format);
            if (format === 'pem' || format === 'base64') {
                option.selected = true;
            }
            outputFormatSelect.appendChild(option);
        });
    }

    getFormatLabel(format) {
        const labels = {
            'pem': 'PEM (Recommandé)',
            'der': 'DER (Binaire)',
            'pkcs8': 'PKCS#8',
            'pkcs12': 'PKCS#12/PFX',
            'jwk': 'JWK (JSON Web Key)',
            'base64': 'Base64',
            'hex': 'Hexadécimal',
            'raw': 'Raw/Binaire',
            'bip39_mnemonic': 'BIP39 Mnemonic',
            'openssh': 'OpenSSH'
        };
        return labels[format] || format;
    }

    togglePasswordVisibility() {
        const type = this.passwordInput.type === 'password' ? 'text' : 'password';
        this.passwordInput.type = type;
        
        const icon = this.passwordToggle.querySelector('i');
        icon.className = type === 'password' ? 'fas fa-eye' : 'fas fa-eye-slash';
    }

    togglePasswordSection(enabled) {
        const passwordSection = document.getElementById('passwordSection');
        passwordSection.style.display = enabled ? 'block' : 'none';
        
        if (!enabled) {
            this.passwordInput.value = '';
        }
    }

    async generateSecurePassword() {
        try {
            const response = await fetch('/api/generate-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ length: 16 })
            });
            
            const data = await response.json();
            this.passwordInput.value = data.password;
            this.updatePasswordStrength();
        } catch (error) {
            console.error('Erreur lors de la génération du mot de passe:', error);
            this.showAlert('Erreur lors de la génération du mot de passe', 'danger');
        }
    }

    async validatePasswordStrength() {
        const password = this.passwordInput.value;
        if (!password) {
            this.showAlert('Veuillez entrer un mot de passe', 'warning');
            return;
        }

        try {
            const response = await fetch('/api/validate-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ password })
            });
            
            const data = await response.json();
            
            if (data.is_strong) {
                this.showAlert('✅ Mot de passe fort!', 'success');
            } else {
                this.showAlert('⚠️ Mot de passe faible: ' + data.warnings.join(', '), 'warning');
            }
        } catch (error) {
            console.error('Erreur lors de la validation du mot de passe:', error);
        }
    }

    updatePasswordStrength() {
        const password = this.passwordInput.value;
        const strengthIndicator = document.getElementById('passwordStrength');
        
        if (!password) {
            strengthIndicator.textContent = '';
            return;
        }

        let strength = 'weak';
        let message = 'Faible';

        if (password.length >= 12 && /[A-Z]/.test(password) && /[a-z]/.test(password) && /\d/.test(password) && /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password)) {
            strength = 'strong';
            message = 'Très fort';
        } else if (password.length >= 8 && /[A-Z]/.test(password) && /[a-z]/.test(password) && /\d/.test(password)) {
            strength = 'good';
            message = 'Bon';
        } else if (password.length >= 6) {
            strength = 'fair';
            message = 'Moyen';
        }

        strengthIndicator.textContent = `Force: ${message}`;
        strengthIndicator.className = `text-${strength === 'strong' ? 'success' : strength === 'good' ? 'info' : strength === 'fair' ? 'warning' : 'danger'}`;
    }

    async generateKey() {
        const formData = new FormData(this.form);
        const requestData = Object.fromEntries(formData.entries());
        
        // Conversion des types
        requestData.key_size = parseInt(requestData.key_size) || 256;
        requestData.rsa_key_size = parseInt(requestData.rsa_key_size) || 2048;
        requestData.validity_days = parseInt(requestData.validity_days) || 365;
        requestData.iterations = parseInt(requestData.iterations) || 100000;
        requestData.salt_length = parseInt(requestData.salt_length) || 32;
        requestData.password_protected = document.getElementById('passwordProtected').checked;

        // Validation
        if (!requestData.key_type) {
            this.showAlert('Veuillez sélectionner un type de clé', 'warning');
            return;
        }

        if (requestData.password_protected && !requestData.password) {
            this.showAlert('Veuillez entrer un mot de passe', 'warning');
            return;
        }

        // Afficher le loading
        this.generateButton.innerHTML = '<span class="loading-spinner"></span> Génération...';
        this.generateButton.disabled = true;

        try {
            const response = await fetch('/api/generate-key', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(requestData)
            });

            const data = await response.json();

            if (data.success) {
                this.displayResults(data);
                this.loadSecurityWarnings(requestData.key_type);
            } else {
                this.showAlert('Erreur lors de la génération de la clé', 'danger');
            }
        } catch (error) {
            console.error('Erreur lors de la génération:', error);
            this.showAlert('Erreur lors de la génération de la clé', 'danger');
        } finally {
            this.generateButton.innerHTML = '<i class="fas fa-magic me-2"></i>Générer la Clé';
            this.generateButton.disabled = false;
        }
    }

    displayResults(data) {
        const resultsContent = document.getElementById('resultsContent');
        
        let html = `
            <div class="row mb-3">
                <div class="col-md-6">
                    <div class="result-item">
                        <h6><i class="fas fa-fingerprint me-2"></i>Empreinte</h6>
                        <code>${data.fingerprint}</code>
                        <button class="btn btn-sm btn-outline-primary copy-btn ms-2" onclick="copyToClipboard('${data.fingerprint}')">
                            <i class="fas fa-copy"></i>
                        </button>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="result-item">
                        <h6><i class="fas fa-cogs me-2"></i>Algorithme</h6>
                        <code>${data.algorithm}</code>
                    </div>
                </div>
            </div>
        `;

        // Clé principale
        if (data.key_data) {
            html += `
                <div class="result-item">
                    <h6><i class="fas fa-key me-2"></i>Clé ${typeof data.key_data === 'object' ? 'Principale' : ''}</h6>
                    <pre class="code-block">${this.formatKeyData(data.key_data)}</pre>
                    <button class="btn btn-sm btn-outline-primary copy-btn" onclick="copyToClipboard(\`${this.formatKeyData(data.key_data)}\`)">
                        <i class="fas fa-copy"></i> Copier
                    </button>
                </div>
            `;
        }

        // Clé publique
        if (data.public_key) {
            html += `
                <div class="result-item">
                    <h6><i class="fas fa-unlock me-2"></i>Clé Publique</h6>
                    <pre class="code-block">${this.formatKeyData(data.public_key)}</pre>
                    <button class="btn btn-sm btn-outline-success copy-btn" onclick="copyToClipboard(\`${this.formatKeyData(data.public_key)}\`)">
                        <i class="fas fa-copy"></i> Copier
                    </button>
                </div>
            `;
        }

        // Clé privée
        if (data.private_key) {
            html += `
                <div class="result-item">
                    <h6><i class="fas fa-lock me-2"></i>Clé Privée</h6>
                    <pre class="code-block">${this.formatKeyData(data.private_key)}</pre>
                    <button class="btn btn-sm btn-outline-danger copy-btn" onclick="copyToClipboard(\`${this.formatKeyData(data.private_key)}\`)">
                        <i class="fas fa-copy"></i> Copier
                    </button>
                </div>
            `;
        }

        // Métadonnées
        if (data.metadata && Object.keys(data.metadata).length > 0) {
            html += `
                <div class="result-item">
                    <h6><i class="fas fa-info-circle me-2"></i>Métadonnées</h6>
                    <pre class="code-block">${JSON.stringify(data.metadata, null, 2)}</pre>
                </div>
            `;
        }

        resultsContent.innerHTML = html;
        this.resultsCard.style.display = 'block';
        this.resultsCard.scrollIntoView({ behavior: 'smooth' });
    }

    formatKeyData(data) {
        if (typeof data === 'object') {
            return JSON.stringify(data, null, 2);
        }
        return data;
    }

    async loadSecurityWarnings(keyType) {
        try {
            const response = await fetch(`/api/security-warnings/${keyType}`);
            const data = await response.json();
            
            if (data.warnings && data.warnings.length > 0) {
                const warningsList = document.getElementById('warningsList');
                warningsList.innerHTML = '';
                
                data.warnings.forEach(warning => {
                    const li = document.createElement('li');
                    li.textContent = warning;
                    warningsList.appendChild(li);
                });
                
                this.securityWarnings.style.display = 'block';
            }
        } catch (error) {
            console.error('Erreur lors du chargement des avertissements:', error);
        }
    }

    resetForm() {
        this.form.reset();
        this.resultsCard.style.display = 'none';
        this.securityWarnings.style.display = 'none';
        document.getElementById('passwordSection').style.display = 'block';
        this.updateAlgorithmOptions();
        this.updateSpecificParams();
        this.updateOutputFormats();
    }

    showAlert(message, type) {
        // Supprimer les alertes existantes
        const existingAlerts = document.querySelectorAll('.alert');
        existingAlerts.forEach(alert => alert.remove());

        // Créer une nouvelle alerte
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;

        // Insérer l'alerte en haut du formulaire
        this.form.parentNode.insertBefore(alertDiv, this.form);
    }
}

// Fonction globale pour copier dans le presse-papiers
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        // Afficher un feedback visuel
        const button = event.target.closest('.copy-btn');
        button.classList.add('copied');
        setTimeout(() => {
            button.classList.remove('copied');
        }, 2000);
    }).catch(err => {
        console.error('Erreur lors de la copie:', err);
        // Fallback pour les navigateurs plus anciens
        const textArea = document.createElement('textarea');
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
    });
}

// Initialisation quand le DOM est chargé
document.addEventListener('DOMContentLoaded', () => {
    new KeyGenerator();
});
