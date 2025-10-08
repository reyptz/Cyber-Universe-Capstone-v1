/**
 * Black Hat Ghost Cyber Security - Animations Cyber
 * Système d'animations et d'effets visuels black hat cyber
 */

class CyberAnimations {
    constructor() {
        this.init();
        this.setupIntersectionObserver();
        this.setupParticleSystem();
        this.setupGlitchEffects();
        this.setupHologramEffects();
    }

    /**
     * Initialise les animations cyber
     */
    init() {
        // Ajouter les classes d'animation aux éléments
        this.addAnimationClasses();
        
        // Démarrer les animations de fond
        this.startBackgroundAnimations();
        
        // Configurer les effets de survol
        this.setupHoverEffects();
        
        // Démarrer les animations de texte
        this.startTextAnimations();
    }

    /**
     * Ajoute les classes d'animation aux éléments
     */
    addAnimationClasses() {
        // Animation des titres
        const titles = document.querySelectorAll('h1, h2, h3');
        titles.forEach((title, index) => {
            title.classList.add('animate-fade-in-down');
            title.style.animationDelay = `${index * 0.1}s`;
        });

        // Animation des cartes
        const cards = document.querySelectorAll('.card, .card-cyber');
        cards.forEach((card, index) => {
            card.classList.add('animate-fade-in-up');
            card.style.animationDelay = `${index * 0.2}s`;
        });

        // Animation des boutons
        const buttons = document.querySelectorAll('.btn, .btn-cyber');
        buttons.forEach((button, index) => {
            button.classList.add('animate-fade-in-up');
            button.style.animationDelay = `${index * 0.1}s`;
        });

        // Animation des icônes
        const icons = document.querySelectorAll('.fas, .fab');
        icons.forEach((icon, index) => {
            icon.classList.add('animate-float');
            icon.style.animationDelay = `${index * 0.05}s`;
            icon.style.animationDuration = `${2 + Math.random() * 2}s`;
        });
    }

    /**
     * Configure l'Intersection Observer pour les animations
     */
    setupIntersectionObserver() {
        const observerOptions = {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        };

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('animate-visible');
                    
                    // Effet de glitch pour les titres
                    if (entry.target.tagName === 'H1' || entry.target.tagName === 'H2') {
                        this.triggerGlitchEffect(entry.target);
                    }
                    
                    // Effet hologramme pour les cartes
                    if (entry.target.classList.contains('card-cyber')) {
                        this.triggerHologramEffect(entry.target);
                    }
                }
            });
        }, observerOptions);

        // Observer tous les éléments animables
        const animatedElements = document.querySelectorAll('.animate-fade-in-down, .animate-fade-in-up, .animate-fade-in-left, .animate-fade-in-right, .card-cyber');
        animatedElements.forEach(el => observer.observe(el));
    }

    /**
     * Démarre les animations de fond
     */
    startBackgroundAnimations() {
        // Grille cyber animée
        this.createCyberGrid();
        
        // Particules flottantes
        this.createFloatingParticles();
        
        // Effet de scan
        this.createScanEffect();
    }

    /**
     * Crée la grille cyber animée
     */
    createCyberGrid() {
        const grid = document.createElement('div');
        grid.className = 'cyber-grid-bg';
        grid.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: -1;
            opacity: 0.1;
            background-image: 
                linear-gradient(rgba(255, 0, 0, 0.1) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255, 0, 0, 0.1) 1px, transparent 1px);
            background-size: 20px 20px;
            animation: cyber-grid-move 20s linear infinite;
        `;

        // Ajouter l'animation CSS
        const style = document.createElement('style');
        style.textContent = `
            @keyframes cyber-grid-move {
                0% { transform: translate(0, 0); }
                100% { transform: translate(20px, 20px); }
            }
        `;
        document.head.appendChild(style);
        document.body.appendChild(grid);
    }

    /**
     * Crée les particules flottantes
     */
    createFloatingParticles() {
        const particleContainer = document.createElement('div');
        particleContainer.className = 'particle-container';
        particleContainer.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: -1;
        `;

        // Créer des particules
        for (let i = 0; i < 50; i++) {
            const particle = document.createElement('div');
            particle.className = 'cyber-particle';
            particle.style.cssText = `
                position: absolute;
                width: 2px;
                height: 2px;
                background: rgba(255, 0, 0, 0.6);
                border-radius: 50%;
                left: ${Math.random() * 100}%;
                top: ${Math.random() * 100}%;
                animation: particle-float ${5 + Math.random() * 10}s linear infinite;
                animation-delay: ${Math.random() * 5}s;
            `;
            particleContainer.appendChild(particle);
        }

        // Ajouter l'animation CSS
        const style = document.createElement('style');
        style.textContent = `
            @keyframes particle-float {
                0% { 
                    transform: translateY(100vh) translateX(0);
                    opacity: 0;
                }
                10% {
                    opacity: 1;
                }
                90% {
                    opacity: 1;
                }
                100% { 
                    transform: translateY(-100px) translateX(${Math.random() * 100}px);
                    opacity: 0;
                }
            }
        `;
        document.head.appendChild(style);
        document.body.appendChild(particleContainer);
    }

    /**
     * Crée l'effet de scan
     */
    createScanEffect() {
        const scanLine = document.createElement('div');
        scanLine.className = 'scan-line';
        scanLine.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 2px;
            background: linear-gradient(90deg, transparent, #ff0000, transparent);
            z-index: 1000;
            pointer-events: none;
            animation: scan-move 8s linear infinite;
            box-shadow: 0 0 10px #ff0000;
        `;

        // Ajouter l'animation CSS
        const style = document.createElement('style');
        style.textContent = `
            @keyframes scan-move {
                0% { 
                    top: 0;
                    opacity: 0;
                }
                5% {
                    opacity: 1;
                }
                95% {
                    opacity: 1;
                }
                100% { 
                    top: 100vh;
                    opacity: 0;
                }
            }
        `;
        document.head.appendChild(style);
        document.body.appendChild(scanLine);
    }

    /**
     * Configure les effets de survol
     */
    setupHoverEffects() {
        // Effet de survol pour les cartes
        const cards = document.querySelectorAll('.card-cyber');
        cards.forEach(card => {
            card.addEventListener('mouseenter', () => {
                this.triggerHologramEffect(card);
                this.addGlowEffect(card);
            });
            
            card.addEventListener('mouseleave', () => {
                this.removeGlowEffect(card);
            });
        });

        // Effet de survol pour les boutons
        const buttons = document.querySelectorAll('.btn-cyber');
        buttons.forEach(button => {
            button.addEventListener('mouseenter', () => {
                this.addButtonSparkle(button);
            });
        });

        // Effet de survol pour les icônes
        const icons = document.querySelectorAll('.fas, .fab');
        icons.forEach(icon => {
            icon.addEventListener('mouseenter', () => {
                this.addIconGlow(icon);
            });
            
            icon.addEventListener('mouseleave', () => {
                this.removeIconGlow(icon);
            });
        });
    }

    /**
     * Démarre les animations de texte
     */
    startTextAnimations() {
        // Animation de frappe pour les titres
        const titles = document.querySelectorAll('.glitch-effect');
        titles.forEach(title => {
            this.startTypingAnimation(title);
        });

        // Animation de scintillement pour le texte cyber
        const cyberTexts = document.querySelectorAll('.text-glow');
        cyberTexts.forEach(text => {
            this.startGlowAnimation(text);
        });
    }

    /**
     * Animation de frappe
     */
    startTypingAnimation(element) {
        const text = element.textContent;
        element.textContent = '';
        element.style.borderRight = '2px solid #ff0000';
        
        let i = 0;
        const typeWriter = () => {
            if (i < text.length) {
            element.textContent += text.charAt(i);
            i++;
                setTimeout(typeWriter, 50 + Math.random() * 100);
            } else {
                element.style.borderRight = 'none';
            }
        };
        
        // Démarrer après un délai
        setTimeout(typeWriter, 1000);
    }

    /**
     * Animation de scintillement
     */
    startGlowAnimation(element) {
        setInterval(() => {
            element.style.textShadow = `
                0 0 5px currentColor,
                0 0 10px currentColor,
                0 0 15px currentColor,
                0 0 20px #ff0000
            `;
            
            setTimeout(() => {
                element.style.textShadow = '0 0 10px currentColor';
            }, 200);
        }, 3000 + Math.random() * 2000);
    }

    /**
     * Déclenche l'effet de glitch
     */
    triggerGlitchEffect(element) {
        const originalText = element.textContent;
        const glitchChars = '!@#$%^&*()_+-=[]{}|;:,.<>?';
        
        element.classList.add('glitch-active');
        
        // Animation de glitch
        let glitchCount = 0;
        const glitchInterval = setInterval(() => {
            let glitchedText = '';
            for (let i = 0; i < originalText.length; i++) {
                if (Math.random() < 0.1) {
                    glitchedText += glitchChars[Math.floor(Math.random() * glitchChars.length)];
                } else {
                    glitchedText += originalText[i];
                }
            }
            element.textContent = glitchedText;
            
            glitchCount++;
            if (glitchCount > 10) {
                clearInterval(glitchInterval);
                element.textContent = originalText;
                element.classList.remove('glitch-active');
            }
        }, 50);
    }

    /**
     * Déclenche l'effet hologramme
     */
    triggerHologramEffect(element) {
        element.classList.add('hologram-active');

        setTimeout(() => {
            element.classList.remove('hologram-active');
        }, 1000);
    }

    /**
     * Ajoute l'effet de lueur
     */
    addGlowEffect(element) {
        element.style.boxShadow = '0 0 20px rgba(255, 0, 0, 0.5)';
        element.style.transform = 'translateY(-5px)';
    }

    /**
     * Supprime l'effet de lueur
     */
    removeGlowEffect(element) {
        element.style.boxShadow = '';
        element.style.transform = '';
    }

    /**
     * Ajoute des étincelles au bouton
     */
    addButtonSparkle(button) {
        const sparkle = document.createElement('div');
        sparkle.className = 'sparkle-effect';
        sparkle.style.cssText = `
            position: absolute;
            width: 4px;
            height: 4px;
            background: #ff0000;
            border-radius: 50%;
            left: ${Math.random() * 100}%;
            top: ${Math.random() * 100}%;
            animation: sparkle-pop 0.5s ease-out;
            pointer-events: none;
        `;
        
        button.style.position = 'relative';
        button.appendChild(sparkle);
        
        setTimeout(() => {
            sparkle.remove();
        }, 500);
    }

    /**
     * Ajoute la lueur à l'icône
     */
    addIconGlow(icon) {
        icon.style.textShadow = '0 0 10px currentColor, 0 0 20px currentColor, 0 0 30px #ff0000';
        icon.style.transform = 'scale(1.2)';
    }

    /**
     * Supprime la lueur de l'icône
     */
    removeIconGlow(icon) {
        icon.style.textShadow = '';
        icon.style.transform = '';
    }

    /**
     * Configure le système de particules
     */
    setupParticleSystem() {
        // Particules pour les interactions
        document.addEventListener('mousemove', (e) => {
            if (Math.random() < 0.1) {
                this.createMouseParticle(e.clientX, e.clientY);
            }
        });

        // Particules pour les clics
        document.addEventListener('click', (e) => {
            this.createClickParticle(e.clientX, e.clientY);
        });
    }

    /**
     * Crée une particule de souris
     */
    createMouseParticle(x, y) {
        const particle = document.createElement('div');
        particle.className = 'mouse-particle';
        particle.style.cssText = `
            position: fixed;
            width: 2px;
            height: 2px;
            background: rgba(255, 0, 0, 0.8);
            border-radius: 50%;
            left: ${x}px;
            top: ${y}px;
            pointer-events: none;
            z-index: 9999;
            animation: mouse-particle-fade 1s ease-out forwards;
        `;
        
        document.body.appendChild(particle);
        
        setTimeout(() => {
            particle.remove();
        }, 1000);
    }

    /**
     * Crée une particule de clic
     */
    createClickParticle(x, y) {
        for (let i = 0; i < 5; i++) {
            const particle = document.createElement('div');
            particle.className = 'click-particle';
            particle.style.cssText = `
                position: fixed;
                width: 4px;
                height: 4px;
                background: #ff0000;
                border-radius: 50%;
                left: ${x}px;
                top: ${y}px;
                pointer-events: none;
                z-index: 9999;
                animation: click-particle-explode 0.5s ease-out forwards;
                transform: translate(${(Math.random() - 0.5) * 50}px, ${(Math.random() - 0.5) * 50}px);
            `;
            
            document.body.appendChild(particle);
            
            setTimeout(() => {
                particle.remove();
            }, 500);
        }
    }

    /**
     * Configure les effets de glitch
     */
    setupGlitchEffects() {
        // Effet de glitch aléatoire
        setInterval(() => {
            const elements = document.querySelectorAll('.glitch-effect');
            if (elements.length > 0) {
                const randomElement = elements[Math.floor(Math.random() * elements.length)];
                this.triggerGlitchEffect(randomElement);
            }
        }, 10000);
    }

    /**
     * Configure les effets d'hologramme
     */
    setupHologramEffects() {
        // Effet d'hologramme aléatoire
        setInterval(() => {
            const elements = document.querySelectorAll('.hologram-effect');
            if (elements.length > 0) {
                const randomElement = elements[Math.floor(Math.random() * elements.length)];
                this.triggerHologramEffect(randomElement);
            }
        }, 15000);
    }

    /**
     * Animation de chargement cyber
     */
    createCyberLoader(element) {
        const loader = document.createElement('div');
        loader.className = 'cyber-loader';
        loader.innerHTML = `
            <div class="loader-ring"></div>
            <div class="loader-text">BREACHING...</div>
        `;
        
        loader.style.cssText = `
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
            z-index: 1000;
        `;
        
        const style = document.createElement('style');
        style.textContent = `
            .loader-ring {
                width: 60px;
                height: 60px;
                border: 3px solid rgba(255, 0, 0, 0.3);
                border-top: 3px solid #ff0000;
                border-radius: 50%;
                animation: cyber-spin 1s linear infinite;
                margin: 0 auto 10px;
            }
            
            .loader-text {
                color: #ff0000;
                font-family: 'JetBrains Mono', monospace;
                font-size: 12px;
                letter-spacing: 2px;
                animation: cyber-text-glow 2s ease-in-out infinite alternate;
            }
            
            @keyframes cyber-spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
            
            @keyframes cyber-text-glow {
                from { text-shadow: 0 0 5px #ff0000; }
                to { text-shadow: 0 0 20px #ff0000, 0 0 30px #ff0000; }
            }
        `;
        
        document.head.appendChild(style);
        element.appendChild(loader);
        
        return loader;
    }

    /**
     * Supprime le loader cyber
     */
    removeCyberLoader(loader) {
        if (loader && loader.parentNode) {
            loader.remove();
        }
    }
}

// Ajouter les animations CSS
const cyberAnimationsCSS = `
    @keyframes mouse-particle-fade {
        0% { opacity: 1; transform: scale(1); }
        100% { opacity: 0; transform: scale(0); }
    }
    
    @keyframes click-particle-explode {
        0% { opacity: 1; transform: scale(1); }
        100% { opacity: 0; transform: scale(0); }
    }
    
    .glitch-active {
        animation: glitch-shake 0.1s ease-in-out;
    }
    
    @keyframes glitch-shake {
        0%, 100% { transform: translate(0); }
        20% { transform: translate(-2px, 2px); }
        40% { transform: translate(-2px, -2px); }
        60% { transform: translate(2px, 2px); }
        80% { transform: translate(2px, -2px); }
    }
    
    .hologram-active {
        animation: hologram-flicker 0.1s ease-in-out;
    }
    
    @keyframes hologram-flicker {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.8; }
    }
    
    .animate-visible {
        opacity: 1 !important;
        transform: translateY(0) !important;
    }
    
    .sparkle-effect {
        animation: sparkle-pop 0.5s ease-out;
    }
    
    @keyframes sparkle-pop {
        0% { transform: scale(0); opacity: 1; }
        100% { transform: scale(1); opacity: 0; }
    }
`;

// Injecter le CSS
const style = document.createElement('style');
style.textContent = cyberAnimationsCSS;
document.head.appendChild(style);

// Initialiser les animations cyber
document.addEventListener('DOMContentLoaded', () => {
    window.cyberAnimations = new CyberAnimations();
});

/**
 * Black Hat Ghost Cyber Security - Miracle Effects
 * Effets visuels avancés et animations malveillantes
 */

class MiracleEffects {
    constructor() {
        this.effects = new Map();
        this.isEnabled = true;
        this.init();
    }

    /**
     * Initialise les effets miracles
     */
    init() {
        this.setupBloodEffects();
        this.setupMatrixRain();
        this.setupNeonGlow();
        this.setupParticleExplosions();
        this.setupLightningEffects();
        this.setupHolographicProjections();
        this.setupQuantumAnimations();
        this.setupMirageEffects();
    }

    /**
     * Configure les effets de sang (remplace rainbow)
     */
    setupBloodEffects() {
        const bloodElements = document.querySelectorAll('.blood-effect');
        
        bloodElements.forEach(element => {
            this.createBloodAnimation(element);
        });

        // Effet de sang sur les boutons
        document.addEventListener('mouseover', (e) => {
            if (e.target.classList.contains('btn-cyber')) {
                this.addBloodGlow(e.target);
            }
        });

        document.addEventListener('mouseout', (e) => {
            if (e.target.classList.contains('btn-cyber')) {
                this.removeBloodGlow(e.target);
            }
        });
    }

    /**
     * Crée une animation de sang
     */
    createBloodAnimation(element) {
        const bloodCSS = `
            @keyframes blood {
                0% { filter: hue-rotate(0deg) saturate(2); }
                100% { filter: hue-rotate(360deg) saturate(2); }
            }
            
            .blood-animation {
                animation: blood 3s linear infinite;
            }
        `;
        
        this.injectCSS(bloodCSS);
        element.classList.add('blood-animation');
    }

    /**
     * Ajoute un effet de sang au survol
     */
    addBloodGlow(element) {
        element.style.background = 'linear-gradient(45deg, #8b0000, #ff0000, #8b0000, #ff0000, #4b0082, #8b0000, #4b0082)';
        element.style.backgroundSize = '400% 400%';
        element.style.animation = 'blood-gradient 2s ease infinite';
        
        const bloodGradientCSS = `
            @keyframes blood-gradient {
                0% { background-position: 0% 50%; }
                50% { background-position: 100% 50%; }
                100% { background-position: 0% 50%; }
            }
        `;
        this.injectCSS(bloodGradientCSS);
    }

    /**
     * Supprime l'effet de sang
     */
    removeBloodGlow(element) {
        element.style.background = '';
        element.style.backgroundSize = '';
        element.style.animation = '';
    }

    /**
     * Configure la pluie Matrix
     */
    setupMatrixRain() {
        const matrixContainer = document.createElement('div');
        matrixContainer.className = 'matrix-rain-container';
        matrixContainer.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: -2;
            overflow: hidden;
        `;

        // Créer les colonnes de caractères Matrix
        for (let i = 0; i < 50; i++) {
            this.createMatrixColumn(matrixContainer, i);
        }

        document.body.appendChild(matrixContainer);
    }

    /**
     * Crée une colonne Matrix
     */
    createMatrixColumn(container, index) {
        const column = document.createElement('div');
        column.className = 'matrix-column';
        column.style.cssText = `
            position: absolute;
            left: ${index * 2}%;
            top: -100%;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            color: #006400;
            animation: matrix-fall ${3 + Math.random() * 5}s linear infinite;
            animation-delay: ${Math.random() * 5}s;
            opacity: 0.7;
        `;

        // Générer des caractères aléatoires
        const chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()_+-=[]{}|;:,.<>?';
        let content = '';
        for (let i = 0; i < 20; i++) {
            content += chars[Math.floor(Math.random() * chars.length)] + '<br>';
        }
        column.innerHTML = content;

        container.appendChild(column);
    }

    /**
     * Configure les effets néon
     */
    setupNeonGlow() {
        const neonElements = document.querySelectorAll('.neon-glow');
        neonElements.forEach(element => {
            this.addNeonEffect(element);
        });

        // Effet néon sur les éléments cyber
        document.addEventListener('mouseenter', (e) => {
            if (e.target && e.target.classList && e.target.classList.contains('text-glow')) {
                this.enhanceNeonGlow(e.target);
            }
        }, true);
    }

    /**
     * Ajoute un effet néon
     */
    addNeonEffect(element) {
        element.style.textShadow = `
            0 0 5px currentColor,
            0 0 10px currentColor,
            0 0 15px currentColor,
            0 0 20px currentColor,
            0 0 35px currentColor,
            0 0 40px currentColor
        `;
        element.style.animation = 'neon-flicker 2s infinite alternate';
    }

    /**
     * Améliore l'effet néon au survol
     */
    enhanceNeonGlow(element) {
        element.style.textShadow = `
            0 0 5px currentColor,
            0 0 10px currentColor,
            0 0 15px currentColor,
            0 0 20px currentColor,
            0 0 35px currentColor,
            0 0 40px currentColor,
            0 0 55px currentColor,
            0 0 70px currentColor
        `;
    }

    /**
     * Configure les explosions de particules
     */
    setupParticleExplosions() {
        // Explosion sur les clics
        document.addEventListener('click', (e) => {
            this.createParticleExplosion(e.clientX, e.clientY);
        });

        // Explosion sur les succès
        document.addEventListener('success', (e) => {
            this.createSuccessExplosion();
        });
    }

    /**
     * Crée une explosion de particules
     */
    createParticleExplosion(x, y) {
        const colors = ['#ff0000', '#8b0000', '#b8860b', '#006400', '#ff0000', '#4b0082'];
        
        for (let i = 0; i < 20; i++) {
            const particle = document.createElement('div');
            particle.className = 'explosion-particle';
            particle.style.cssText = `
                position: fixed;
                width: 4px;
                height: 4px;
                background: ${colors[Math.floor(Math.random() * colors.length)]};
                border-radius: 50%;
                left: ${x}px;
                top: ${y}px;
                pointer-events: none;
                z-index: 9999;
                animation: particle-explode ${0.5 + Math.random() * 0.5}s ease-out forwards;
            `;

            const angle = (Math.PI * 2 * i) / 20;
            const velocity = 50 + Math.random() * 100;
            const deltaX = Math.cos(angle) * velocity;
            const deltaY = Math.sin(angle) * velocity;

            particle.style.setProperty('--deltaX', `${deltaX}px`);
            particle.style.setProperty('--deltaY', `${deltaY}px`);

            document.body.appendChild(particle);

            setTimeout(() => {
                particle.remove();
            }, 1000);
        }
    }

    /**
     * Crée une explosion de succès
     */
    createSuccessExplosion() {
        const centerX = window.innerWidth / 2;
        const centerY = window.innerHeight / 2;
        
        for (let i = 0; i < 50; i++) {
            setTimeout(() => {
                this.createParticleExplosion(
                    centerX + (Math.random() - 0.5) * 200,
                    centerY + (Math.random() - 0.5) * 200
                );
            }, i * 50);
        }
    }

    /**
     * Configure les effets d'éclair
     */
    setupLightningEffects() {
        // Éclair aléatoire
        setInterval(() => {
            if (Math.random() < 0.1) {
                this.createLightning();
            }
        }, 10000);
    }

    /**
     * Crée un effet d'éclair
     */
    createLightning() {
        const lightning = document.createElement('div');
        lightning.className = 'lightning-effect';
        lightning.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(45deg, transparent 30%, rgba(255, 0, 0, 0.8) 50%, transparent 70%);
            pointer-events: none;
            z-index: 9998;
            animation: lightning-flash 0.1s ease-out;
        `;

        document.body.appendChild(lightning);

        setTimeout(() => {
            lightning.remove();
        }, 100);
    }

    /**
     * Configure les projections holographiques
     */
    setupHolographicProjections() {
        const hologramElements = document.querySelectorAll('.hologram-effect');
        
        hologramElements.forEach(element => {
            this.enhanceHologramEffect(element);
        });
    }

    /**
     * Améliore l'effet hologramme
     */
    enhanceHologramEffect(element) {
        element.style.position = 'relative';
        element.style.overflow = 'hidden';

        // Créer l'effet de scan holographique
        const scanLine = document.createElement('div');
        scanLine.className = 'hologram-scan';
        scanLine.style.cssText = `
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 0, 0, 0.3), transparent);
            animation: hologram-scan 3s linear infinite;
        `;

        element.appendChild(scanLine);
    }

    /**
     * Configure les animations quantiques
     */
    setupQuantumAnimations() {
        const quantumElements = document.querySelectorAll('.quantum-effect');
        
        quantumElements.forEach(element => {
            this.addQuantumEffect(element);
        });
    }

    /**
     * Ajoute un effet quantique
     */
    addQuantumEffect(element) {
        element.style.position = 'relative';
        
        // Créer des particules quantiques flottantes
        for (let i = 0; i < 5; i++) {
            const quantumParticle = document.createElement('div');
            quantumParticle.className = 'quantum-particle';
            quantumParticle.style.cssText = `
                position: absolute;
                width: 2px;
                height: 2px;
                background: #ff0000;
                border-radius: 50%;
                left: ${Math.random() * 100}%;
                top: ${Math.random() * 100}%;
                animation: quantum-float ${2 + Math.random() * 3}s ease-in-out infinite;
                animation-delay: ${Math.random() * 2}s;
            `;
            
            element.appendChild(quantumParticle);
        }
    }

    /**
     * Configure les effets de mirage
     */
    setupMirageEffects() {
        const mirageElements = document.querySelectorAll('.mirage-effect');
        
        mirageElements.forEach(element => {
            this.addMirageEffect(element);
        });
    }

    /**
     * Ajoute un effet de mirage
     */
    addMirageEffect(element) {
        element.style.animation = 'mirage-shimmer 2s ease-in-out infinite alternate';
    }

    /**
     * Crée un effet de téléportation
     */
    createTeleportationEffect(element) {
        const originalPosition = element.getBoundingClientRect();
        
        // Effet de disparition
        element.style.animation = 'teleport-out 0.5s ease-in forwards';
        
        setTimeout(() => {
            // Déplacer l'élément
            element.style.position = 'fixed';
            element.style.left = Math.random() * window.innerWidth + 'px';
            element.style.top = Math.random() * window.innerHeight + 'px';
            
            // Effet d'apparition
            element.style.animation = 'teleport-in 0.5s ease-out forwards';
        }, 500);
    }

    /**
     * Crée un effet de distorsion temporelle
     */
    createTimeDistortionEffect(element) {
        element.style.animation = 'time-distort 2s ease-in-out infinite';
    }

    /**
     * Crée un effet de vortex
     */
    createVortexEffect(x, y) {
        const vortex = document.createElement('div');
        vortex.className = 'vortex-effect';
        vortex.style.cssText = `
            position: fixed;
            left: ${x - 50}px;
            top: ${y - 50}px;
            width: 100px;
            height: 100px;
            border: 2px solid #ff0000;
            border-radius: 50%;
            pointer-events: none;
            z-index: 9999;
            animation: vortex-spin 2s ease-in-out forwards;
        `;

        document.body.appendChild(vortex);

        setTimeout(() => {
            vortex.remove();
        }, 2000);
    }

    /**
     * Crée un effet de transformation
     */
    createTransformationEffect(element, newClass) {
        element.style.animation = 'transform-out 0.5s ease-in forwards';
        
        setTimeout(() => {
            element.className = newClass;
            element.style.animation = 'transform-in 0.5s ease-out forwards';
        }, 500);
    }

    /**
     * Injecte du CSS personnalisé
     */
    injectCSS(css) {
        const style = document.createElement('style');
        style.textContent = css;
        document.head.appendChild(style);
    }

    /**
     * Active/désactive les effets
     */
    toggleEffects() {
        this.isEnabled = !this.isEnabled;
        
        if (this.isEnabled) {
            document.body.classList.remove('effects-disabled');
        } else {
            document.body.classList.add('effects-disabled');
        }
    }

    /**
     * Nettoie tous les effets
     */
    cleanup() {
        // Supprimer tous les éléments d'effets
        document.querySelectorAll('.matrix-rain-container, .explosion-particle, .lightning-effect, .vortex-effect').forEach(el => {
            el.remove();
        });
        
        // Réinitialiser les styles
        document.querySelectorAll('[style*="animation"]').forEach(el => {
            el.style.animation = '';
        });
    }
}

// CSS pour tous les effets miracles
const miracleEffectsCSS = `
    @keyframes matrix-fall {
        0% { top: -100%; opacity: 0; }
        10% { opacity: 1; }
        90% { opacity: 1; }
        100% { top: 100vh; opacity: 0; }
    }
    
    @keyframes neon-flicker {
        0%, 100% { 
            text-shadow: 
                0 0 5px currentColor,
                0 0 10px currentColor,
                0 0 15px currentColor,
                0 0 20px currentColor;
        }
        50% { 
            text-shadow: 
                0 0 2px currentColor,
                0 0 5px currentColor,
                0 0 8px currentColor,
                0 0 12px currentColor;
        }
    }
    
    @keyframes particle-explode {
        0% { 
            transform: translate(0, 0) scale(1);
            opacity: 1;
        }
        100% { 
            transform: translate(var(--deltaX), var(--deltaY)) scale(0);
            opacity: 0;
        }
    }
    
    @keyframes lightning-flash {
        0% { opacity: 0; }
        50% { opacity: 1; }
        100% { opacity: 0; }
    }
    
    @keyframes hologram-scan {
        0% { left: -100%; }
        100% { left: 100%; }
    }
    
    @keyframes quantum-float {
        0%, 100% { 
            transform: translateY(0) rotate(0deg);
            opacity: 0.7;
        }
        50% { 
            transform: translateY(-20px) rotate(180deg);
            opacity: 1;
        }
    }
    
    @keyframes mirage-shimmer {
        0% { 
            filter: hue-rotate(0deg) brightness(1);
            transform: skewX(0deg);
        }
        100% { 
            filter: hue-rotate(10deg) brightness(1.2);
            transform: skewX(2deg);
        }
    }
    
    @keyframes teleport-out {
        0% { 
            transform: scale(1) rotate(0deg);
            opacity: 1;
        }
        100% { 
            transform: scale(0) rotate(360deg);
            opacity: 0;
        }
    }
    
    @keyframes teleport-in {
        0% { 
            transform: scale(0) rotate(-360deg);
            opacity: 0;
        }
        100% { 
            transform: scale(1) rotate(0deg);
            opacity: 1;
        }
    }
    
    @keyframes time-distort {
        0%, 100% { 
            transform: scale(1);
            filter: blur(0px);
        }
        50% { 
            transform: scale(1.1);
            filter: blur(1px);
        }
    }
    
    @keyframes vortex-spin {
        0% { 
            transform: rotate(0deg) scale(0);
            opacity: 0;
        }
        50% { 
            transform: rotate(180deg) scale(1);
            opacity: 1;
        }
        100% { 
            transform: rotate(360deg) scale(0);
            opacity: 0;
        }
    }
    
    @keyframes transform-out {
        0% { 
            transform: scale(1) rotate(0deg);
            opacity: 1;
        }
        100% { 
            transform: scale(0.8) rotate(180deg);
            opacity: 0;
        }
    }
    
    @keyframes transform-in {
        0% { 
            transform: scale(0.8) rotate(-180deg);
            opacity: 0;
        }
        100% { 
            transform: scale(1) rotate(0deg);
            opacity: 1;
        }
    }
    
    .effects-disabled * {
        animation: none !important;
        transition: none !important;
    }
`;

// Injecter le CSS
const miracleStyle = document.createElement('style');
miracleStyle.textContent = miracleEffectsCSS;
document.head.appendChild(miracleStyle);

// Initialiser les effets miracles
document.addEventListener('DOMContentLoaded', () => {
    window.miracleEffects = new MiracleEffects();
    
    // Créer un bouton de contrôle pour les effets
    const controlButton = document.createElement('button');
    controlButton.innerHTML = '💀';
    controlButton.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        width: 50px;
        height: 50px;
        border-radius: 50%;
        background: linear-gradient(45deg, #ff0000, #8b0000);
        border: none;
        color: white;
        font-size: 20px;
        cursor: pointer;
        z-index: 10000;
        box-shadow: 0 0 20px rgba(255, 0, 0, 0.5);
        transition: all 0.3s ease;
    `;
    
    controlButton.addEventListener('click', () => {
        window.miracleEffects.toggleEffects();
    });
    
    controlButton.addEventListener('mouseenter', () => {
        controlButton.style.transform = 'scale(1.1)';
        controlButton.style.boxShadow = '0 0 30px rgba(255, 0, 0, 0.8)';
    });
    
    controlButton.addEventListener('mouseleave', () => {
        controlButton.style.transform = 'scale(1)';
        controlButton.style.boxShadow = '0 0 20px rgba(255, 0, 0, 0.5)';
    });
    
    document.body.appendChild(controlButton);
});