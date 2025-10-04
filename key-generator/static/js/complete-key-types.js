/**
 * Ghost Cyber Universe - Configuration Complète des Types de Clés (2025)
 * Configuration JavaScript pour tous les types de clés cryptographiques
 * Mise à jour avec NIST SP 800-57 (Rev. 6, 2025), standards post-quantiques NIST (HQC, ML-KEM, etc.),
 * et meilleures pratiques OWASP pour le stockage cryptographique.
 */

const COMPLETE_KEY_TYPES = {
    "symmetric_keys": {
      "block_ciphers": {
        "AES": {
          "AES-128": {"key_size": 128, "description": "AES 128-bit - Standard NIST FIPS 197 (minimum, éviter pour nouveaux systèmes)"},
          "AES-192": {"key_size": 192, "description": "AES 192-bit - Standard NIST FIPS 197"},
          "AES-256": {"key_size": 256, "description": "AES 256-bit - Standard NIST FIPS 197 (recommandé pour 2025)"}
        },
        "ChaCha20": {
          "ChaCha20": {"key_size": 256, "description": "ChaCha20 - Chiffrement de flux moderne, RFC 7539"},
          "ChaCha20-Poly1305": {"key_size": 256, "description": "ChaCha20-Poly1305 - Chiffrement authentifié, recommandé pour mobile/IoT"}
        },
        "Blowfish": {
          "Blowfish": {"key_size": 448, "description": "Blowfish - Algorithme legacy (éviter pour nouveaux usages, OWASP)"}
        },
        "Twofish": {
          "Twofish": {"key_size": 256, "description": "Twofish - Successeur de Blowfish (non recommandé pour production 2025)"}
        },
        "Serpent": {
          "Serpent": {"key_size": 256, "description": "Serpent - AES finaliste, AES-like"}
        },
        "Camellia": {
          "Camellia-128": {"key_size": 128, "description": "Camellia 128-bit - Standard ISO/IEC 18033-3"},
          "Camellia-192": {"key_size": 192, "description": "Camellia 192-bit - Standard ISO/IEC 18033-3"},
          "Camellia-256": {"key_size": 256, "description": "Camellia 256-bit - Standard ISO/IEC 18033-3 (équivalent AES)"}
        }
      },
      "stream_ciphers": {
        "RC4": {
          "RC4": {"key_size": 2048, "description": "RC4 - Chiffrement de flux (déprécié, interdit par NIST/OWASP 2025)"}
        },
        "Salsa20": {
          "Salsa20": {"key_size": 256, "description": "Salsa20 - Chiffrement de flux (précurseur ChaCha)"}
        }
      },
      "kdf": {  // Ajouté pour clarté, aligné OWASP
        "PBKDF2": {"key_size": 256, "description": "PBKDF2-HMAC-SHA256 - NIST SP 800-132, min 100k itérations"},
        "Argon2id": {"key_size": 256, "description": "Argon2id - Gagnant Password Hashing Competition, recommandé OWASP 2025"},
        "scrypt": {"key_size": 256, "description": "scrypt - Résistant à l'ASIC, RFC 7914"}
      }
    },
    "asymmetric_keys": {
      "rsa": {
        "RSA-1024": {"key_size": 1024, "description": "RSA 1024-bit (déprécié - non sécurisé post-2025, NIST)"},
        "RSA-2048": {"key_size": 2048, "description": "RSA 2048-bit - Minimum acceptable jusqu'en 2030 (NIST SP 800-57)"},
        "RSA-3072": {"key_size": 3072, "description": "RSA 3072-bit - Recommandé pour signatures jusqu'en 2035"},
        "RSA-4096": {"key_size": 4096, "description": "RSA 4096-bit - Haute sécurité pour long terme"},
        "RSA-8192": {"key_size": 8192, "description": "RSA 8192-bit - Sécurité maximale (performances dégradées)"}
      },
      "elliptic_curve": {
        "secp192r1": {"key_size": 192, "description": "NIST P-192 - Obsolète 2025 (éviter)"},
        "secp224r1": {"key_size": 224, "description": "NIST P-224 - Phase-out recommandé"},
        "secp256r1": {"key_size": 256, "description": "NIST P-256 - Recommandé, équivalent RSA 3072 (NIST 2025)"},
        "secp384r1": {"key_size": 384, "description": "NIST P-384 - Équivalent RSA 7680"},
        "secp521r1": {"key_size": 521, "description": "NIST P-521 - Équivalent RSA 15360"},
        "secp256k1": {"key_size": 256, "description": "secp256k1 - Bitcoin/Ethereum, non NIST mais sécurisé"},
        "brainpoolP256r1": {"key_size": 256, "description": "Brainpool P-256r1 - BSI Allemagne, alternative NIST"},
        "brainpoolP384r1": {"key_size": 384, "description": "Brainpool P-384r1 - BSI Allemagne"},
        "brainpoolP512r1": {"key_size": 512, "description": "Brainpool P-512r1 - BSI Allemagne"},
        "Curve25519": {"key_size": 256, "description": "Curve25519 - X25519 pour ECDH (recommandé)"},
        "Curve448": {"key_size": 448, "description": "Curve448 - X448 pour ECDH haute sécurité"}
      },
      "edwards_curve": {
        "Ed25519": {"key_size": 256, "description": "Ed25519 - Signature Edwards (recommandé, équivalent RSA 4096)"},
        "Ed448": {"key_size": 448, "description": "Ed448 - Signature Edwards haute sécurité"}
      }
    },
    "post_quantum_cryptography": {
      "lattice_based": {
        "ML-KEM-512": {"key_size": 800, "description": "ML-KEM (Kyber) 512 - NIST FIPS 203, KEM standard 2024"},
        "ML-KEM-768": {"key_size": 1184, "description": "ML-KEM (Kyber) 768 - NIST FIPS 203, sécurité moyenne"},
        "ML-KEM-1024": {"key_size": 1568, "description": "ML-KEM (Kyber) 1024 - NIST FIPS 203, haute sécurité"},
        "ML-DSA-44": {"key_size": 1312, "description": "ML-DSA (Dilithium) 44 - NIST FIPS 204, signature niveau 2"},
        "ML-DSA-65": {"key_size": 1952, "description": "ML-DSA (Dilithium) 65 - NIST FIPS 204, niveau 3"},
        "ML-DSA-87": {"key_size": 2592, "description": "ML-DSA (Dilithium) 87 - NIST FIPS 204, niveau 5"},
        "FALCON-512": {"key_size": 897, "description": "FALCON-512 - Signature lattice, NIST round 4"},
        "FALCON-1024": {"key_size": 1793, "description": "FALCON-1024 - Signature lattice haute sécurité"},
        "HQC-128": {"key_size": 2240, "description": "HQC-128 - Code-based KEM, NIST sélection 2025"},
        "HQC-192": {"key_size": 3328, "description": "HQC-192 - Code-based KEM sécurité moyenne"},
        "HQC-256": {"key_size": 4864, "description": "HQC-256 - Code-based KEM haute sécurité"}
      },
      "code_based": {
        "Classic-McEliece-348864": {"key_size": 261120, "description": "Classic McEliece m=348864 - KEM code-based NIST round 4"},
        "Classic-McEliece-6688128": {"key_size": 1359360, "description": "Classic McEliece m=6688128 - Haute sécurité"},
        "BIKE-1": {"key_size": 12352, "description": "BIKE-1 - KEM code-based"},
        "BIKE-2": {"key_size": 24704, "description": "BIKE-2 - Sécurité moyenne"},
        "BIKE-3": {"key_size": 49280, "description": "BIKE-3 - Haute sécurité"}
      },
      "hash_based": {
        "SLH-DSA-SHA2-128f": {"key_size": 32, "description": "SLH-DSA-SHA2-128f - NIST FIPS 205, niveau 1"},
        "SLH-DSA-SHA2-128s": {"key_size": 32, "description": "SLH-DSA-SHA2-128s - NIST FIPS 205, compact niveau 1"},
        "SLH-DSA-SHA2-192f": {"key_size": 32, "description": "SLH-DSA-SHA2-192f - Niveau 2"},
        "SLH-DSA-SHA2-192s": {"key_size": 32, "description": "SLH-DSA-SHA2-192s - Compact niveau 2"},
        "SLH-DSA-SHA2-256f": {"key_size": 32, "description": "SLH-DSA-SHA2-256f - Niveau 3"},
        "SLH-DSA-SHA2-256s": {"key_size": 32, "description": "SLH-DSA-SHA2-256s - Compact niveau 3"},
        "XMSS": {"key_size": 32, "description": "XMSS - eXtended Merkle Signature Scheme (legacy)"},
        "LMS": {"key_size": 32, "description": "Lehmer Merkle Signature (RFC 8554)"}
      },
      "isogeny_based": {
        "CSIDH": {"key_size": 512, "description": "CSIDH - Isogeny-based (expérimental, non NIST 2025)"},
        "SIDH": {"key_size": 434, "description": "SIDH - Supersingular Isogeny (cassé 2022, éviter)"},
        "SIKE": {"key_size": 434, "description": "SIKE - Isogeny-based (cassé 2022, déprécié)"}
      },
      "multivariate": {
        "Rainbow": {"key_size": 1024, "description": "Rainbow - Multivariate (cassé, non recommandé)"},
        "GeMSS": {"key_size": 1024, "description": "GeMSS - Multivariate signature"}
      }
    },
    "tls_certificates": {
      "server_certificates": {
        "RSA-2048": {"key_size": 2048, "description": "Certificat serveur RSA 2048-bit (min 2030)"},
        "RSA-3072": {"key_size": 3072, "description": "Certificat serveur RSA 3072-bit (recommandé)"},
        "RSA-4096": {"key_size": 4096, "description": "Certificat serveur RSA 4096-bit (haute sécurité)"},
        "ECDSA-P256": {"key_size": 256, "description": "Certificat serveur ECDSA P-256 (recommandé)"},
        "ECDSA-P384": {"key_size": 384, "description": "Certificat serveur ECDSA P-384"},
        "Ed25519": {"key_size": 256, "description": "Certificat serveur Ed25519 (moderne)"},
        "ML-KEM-768": {"key_size": 1184, "description": "Certificat post-quantum ML-KEM 768"}
      },
      "client_certificates": {
        "RSA-2048": {"key_size": 2048, "description": "Certificat client RSA 2048-bit"},
        "ECDSA-P256": {"key_size": 256, "description": "Certificat client ECDSA P-256"},
        "Ed25519": {"key_size": 256, "description": "Certificat client Ed25519"}
      },
      "intermediate_ca": {
        "RSA-3072": {"key_size": 3072, "description": "CA intermédiaire RSA 3072-bit"},
        "ECDSA-P384": {"key_size": 384, "description": "CA intermédiaire ECDSA P-384"},
        "ML-DSA-65": {"key_size": 1952, "description": "CA intermédiaire post-quantum ML-DSA 65"}
      },
      "root_ca": {
        "RSA-4096": {"key_size": 4096, "description": "CA racine RSA 4096-bit (recommandé)"},
        "ECDSA-P521": {"key_size": 521, "description": "CA racine ECDSA P-521"},
        "SLH-DSA-SHA2-256f": {"key_size": 32, "description": "CA racine post-quantum SLH-DSA 256f"}
      }
    },
    "ssh_keys": {
      "rsa": {
        "RSA-2048": {"key_size": 2048, "description": "Clé SSH RSA 2048-bit (legacy)"},
        "RSA-3072": {"key_size": 3072, "description": "Clé SSH RSA 3072-bit"},
        "RSA-4096": {"key_size": 4096, "description": "Clé SSH RSA 4096-bit"}
      },
      "ecdsa": {
        "ECDSA-P256": {"key_size": 256, "description": "Clé SSH ECDSA P-256"},
        "ECDSA-P384": {"key_size": 384, "description": "Clé SSH ECDSA P-384"},
        "ECDSA-P521": {"key_size": 521, "description": "Clé SSH ECDSA P-521"}
      },
      "ed25519": {
        "Ed25519": {"key_size": 256, "description": "Clé SSH Ed25519 (recommandé 2025)"}
      },
      "sk": {
        "Ed25519-sk": {"key_size": 256, "description": "Ed25519-sk - SSH avec FIDO/U2F"},
        "ECDSA-sk": {"key_size": 256, "description": "ECDSA-sk - SSH avec FIDO/U2F"}
      }
    },
    "crypto_wallets": {
      "bip39": {
        "BIP39-12": {"key_size": 128, "description": "Mnémonique BIP39 12 mots (sécurité faible, éviter 2025)"},
        "BIP39-15": {"key_size": 160, "description": "Mnémonique BIP39 15 mots"},
        "BIP39-18": {"key_size": 192, "description": "Mnémonique BIP39 18 mots"},
        "BIP39-21": {"key_size": 224, "description": "Mnémonique BIP39 21 mots"},
        "BIP39-24": {"key_size": 256, "description": "Mnémonique BIP39 24 mots (recommandé)"}
      },
      "bip32": {
        "BIP32": {"key_size": 256, "description": "Clé maître BIP32 HD Wallet"}
      },
      "bip44": {
        "BIP44": {"key_size": 256, "description": "Clé dérivée BIP44 multi-account"}
      },
      "bip84": {
        "BIP84": {"key_size": 256, "description": "BIP84 Native SegWit (Bech32)"}
      },
      "bip86": {
        "BIP86": {"key_size": 256, "description": "BIP86 SLIP-0173 Bech32m"}
      }
    },
    "jwt_tokens": {
      "hmac": {
        "HS256": {"key_size": 256, "description": "HMAC SHA-256 pour JWT (min 256 bits)"},
        "HS384": {"key_size": 384, "description": "HMAC SHA-384 pour JWT"},
        "HS512": {"key_size": 512, "description": "HMAC SHA-512 pour JWT (recommandé pour haute sécurité)"}
      },
      "rsa": {
        "RS256": {"key_size": 2048, "description": "RSA SHA-256 pour JWT (min 2048)"},
        "RS384": {"key_size": 3072, "description": "RSA SHA-384 pour JWT"},
        "RS512": {"key_size": 4096, "description": "RSA SHA-512 pour JWT"}
      },
      "ecdsa": {
        "ES256": {"key_size": 256, "description": "ECDSA P-256 SHA-256 pour JWT"},
        "ES384": {"key_size": 384, "description": "ECDSA P-384 SHA-384 pour JWT"},
        "ES512": {"key_size": 521, "description": "ECDSA P-521 SHA-512 pour JWT"}
      },
      "eddsa": {
        "EdDSA": {"key_size": 256, "description": "EdDSA (Ed25519) pour JWT"}
      },
      "psa": {  // Post-quantum
        "PS256": {"key_size": 1312, "description": "ML-DSA-44 SHA-256 pour JWT post-quantum"},
        "PS512": {"key_size": 2592, "description": "ML-DSA-87 SHA-512 pour JWT post-quantum"}
      }
    },
    "api_keys": {
      "random": {
        "API-128": {"key_size": 128, "description": "Clé API 128-bit (faible, éviter)"},
        "API-256": {"key_size": 256, "description": "Clé API 256-bit (standard)"},
        "API-512": {"key_size": 512, "description": "Clé API 512-bit (haute sécurité)"}
      },
      "uuid": {
        "UUID-v4": {"key_size": 128, "description": "Clé API UUID v4 (RFC 4122)"},
        "UUID-v5": {"key_size": 128, "description": "Clé API UUID v5 SHA-1"}
      },
      "ed25519": {
        "API-Ed25519": {"key_size": 256, "description": "Clé API Ed25519 pour signatures"}
      }
    },
    "database_encryption": {
      "transparent_data_encryption": {
        "TDE-AES-128": {"key_size": 128, "description": "TDE AES 128-bit (SQL Server/Oracle)"},
        "TDE-AES-256": {"key_size": 256, "description": "TDE AES 256-bit (recommandé)"}
      },
      "column_encryption": {
        "CE-AES-128-GCM": {"key_size": 128, "description": "Chiffrement colonne AES-GCM 128-bit"},
        "CE-AES-256-GCM": {"key_size": 256, "description": "Chiffrement colonne AES-GCM 256-bit (recommandé OWASP)"}
      }
    },
    "blockchain": {
      "bitcoin": {
        "secp256k1": {"key_size": 256, "description": "Clé Bitcoin/Ethereum secp256k1 (BIP32)"}
      },
      "ethereum": {
        "secp256k1": {"key_size": 256, "description": "Clé Ethereum secp256k1 (EIP-155)"}
      },
      "monero": {
        "Ed25519": {"key_size": 256, "description": "Clé Monero Ed25519 (RingCT)"},
        "Curve25519": {"key_size": 256, "description": "Clé Monero Curve25519 (échange)"}
      },
      "solana": {
        "Ed25519": {"key_size": 256, "description": "Clé Solana Ed25519"}
      },
      "cardano": {
        "Ed25519": {"key_size": 256, "description": "Clé Cardano Ed25519 (BIP32)"}
      }
    },
    "iot_security": {
      "device_keys": {
        "IoT-AES-128": {"key_size": 128, "description": "Clé IoT AES 128-bit (contraintes ressources)"},
        "IoT-AES-256": {"key_size": 256, "description": "Clé IoT AES 256-bit (recommandé)"},
        "IoT-ECDSA-P256": {"key_size": 256, "description": "Clé IoT ECDSA P-256 (signatures légères)"},
        "IoT-Ed25519": {"key_size": 256, "description": "Clé IoT Ed25519 (rapide)"}
      },
      "sensor_keys": {
        "Sensor-AES-128": {"key_size": 128, "description": "Clé capteur AES 128-bit (basse puissance)"},
        "Sensor-ChaCha20": {"key_size": 256, "description": "Clé capteur ChaCha20 (mobile)"}
      },
      "fido": {
        "FIDO-ECDSA-P256": {"key_size": 256, "description": "Clé FIDO/U2F ECDSA P-256"},
        "FIDO-Ed25519": {"key_size": 256, "description": "Clé FIDO Ed25519"}
      }
    },
    "cloud_security": {
      "aws_kms": {
        "AWS-AES-256": {"key_size": 256, "description": "Clé AWS KMS AES 256-bit (symétrique)"},
        "AWS-RSA-2048": {"key_size": 2048, "description": "Clé AWS KMS RSA 2048-bit (asymétrique)"},
        "AWS-ECDSA-P256": {"key_size": 256, "description": "Clé AWS KMS ECDSA P-256"},
        "AWS-ML-KEM-768": {"key_size": 1184, "description": "Clé AWS KMS ML-KEM 768 (post-quantum)"}
      },
      "azure_key_vault": {
        "Azure-AES-256": {"key_size": 256, "description": "Clé Azure Key Vault AES 256-bit"},
        "Azure-RSA-2048": {"key_size": 2048, "description": "Clé Azure Key Vault RSA 2048-bit"},
        "Azure-ECDSA-P256": {"key_size": 256, "description": "Clé Azure Key Vault ECDSA P-256"}
      },
      "google_cloud_kms": {
        "GCP-AES-256": {"key_size": 256, "description": "Clé Google Cloud KMS AES 256-bit"},
        "GCP-RSA-3072": {"key_size": 3072, "description": "Clé Google Cloud KMS RSA 3072-bit (recommandé)"},
        "GCP-Ed25519": {"key_size": 256, "description": "Clé Google Cloud KMS Ed25519"}
      }
    },
    "mobile_security": {
      "android": {
        "Android-AES-256-GCM": {"key_size": 256, "description": "Clé Android AES-256-GCM (Jetpack Security)"},
        "Android-RSA-2048": {"key_size": 2048, "description": "Clé Android RSA 2048-bit (Keystore)"},
        "Android-ECDSA-P256": {"key_size": 256, "description": "Clé Android ECDSA P-256"}
      },
      "ios": {
        "iOS-AES-256": {"key_size": 256, "description": "Clé iOS AES 256-bit (Secure Enclave)"},
        "iOS-ECDSA-P256": {"key_size": 256, "description": "Clé iOS ECDSA P-256 (Secure Enclave)"},
        "iOS-Ed25519": {"key_size": 256, "description": "Clé iOS Ed25519 (iOS 13+)"}
      }
    },
    "otp_totp": {
      "hotp": {
        "HOTP-SHA1": {"key_size": 160, "description": "HOTP SHA-1 (RFC 4226, déprécié)"},
        "HOTP-SHA256": {"key_size": 256, "description": "HOTP SHA-256 (extension sécurisée)"}
      },
      "totp": {
        "TOTP-SHA1": {"key_size": 160, "description": "TOTP SHA-1 (RFC 6238, standard)"},
        "TOTP-SHA256": {"key_size": 256, "description": "TOTP SHA-256 (recommandé 2025)"},
        "TOTP-SHA512": {"key_size": 512, "description": "TOTP SHA-512 (haute sécurité)"}
      }
    },
    "digital_signatures": {
      "document_signing": {
        "RSA-3072-PSS": {"key_size": 3072, "description": "Signature document RSA-PSS 3072-bit (PDF/Adobe)"},
        "ECDSA-P384": {"key_size": 384, "description": "Signature document ECDSA P-384"},
        "Ed25519": {"key_size": 256, "description": "Signature document Ed25519 (rapide)"},
        "ML-DSA-65": {"key_size": 1952, "description": "Signature document post-quantum ML-DSA 65"}
      },
      "code_signing": {
        "RSA-4096": {"key_size": 4096, "description": "Signature code RSA 4096-bit (Apple/Microsoft)"},
        "ECDSA-P256": {"key_size": 256, "description": "Signature code ECDSA P-256 (Android)"},
        "Ed25519": {"key_size": 256, "description": "Signature code Ed25519 (expérimental)"}
      }
    },
    "email_security": {
      "pgp": {
        "PGP-RSA-3072": {"key_size": 3072, "description": "Clé PGP RSA 3072-bit (GnuPG recommandé)"},
        "PGP-RSA-4096": {"key_size": 4096, "description": "Clé PGP RSA 4096-bit (haute sécurité)"},
        "PGP-ECDSA-P256": {"key_size": 256, "description": "Clé PGP ECDSA P-256"},
        "PGP-Ed25519": {"key_size": 256, "description": "Clé PGP Ed25519 (GnuPG 2.1+)"}
      },
      "smime": {
        "S/MIME-RSA-2048": {"key_size": 2048, "description": "Clé S/MIME RSA 2048-bit (Outlook)"},
        "S/MIME-RSA-3072": {"key_size": 3072, "description": "Clé S/MIME RSA 3072-bit (recommandé)"},
        "S/MIME-ECDSA-P256": {"key_size": 256, "description": "Clé S/MIME ECDSA P-256"}
      }
    },
    "vpn_keys": {
      "openvpn": {
        "OpenVPN-RSA-3072": {"key_size": 3072, "description": "Clé OpenVPN RSA 3072-bit"},
        "OpenVPN-ECDSA-P384": {"key_size": 384, "description": "Clé OpenVPN ECDSA P-384"},
        "OpenVPN-Ed25519": {"key_size": 256, "description": "Clé OpenVPN Ed25519"}
      },
      "wireguard": {
        "WireGuard-Curve25519": {"key_size": 256, "description": "Clé WireGuard Curve25519 (standard)"}
      },
      "ipsec": {
        "IPSec-RSA-3072": {"key_size": 3072, "description": "Clé IPSec RSA 3072-bit (IKEv2)"},
        "IPSec-ECDSA-P256": {"key_size": 256, "description": "Clé IPSec ECDSA P-256"},
        "IPSec-Ed25519": {"key_size": 256, "description": "Clé IPSec Ed25519 (expérimental)"}
      }
    },
    "container_security": {
      "docker": {
        "Docker-RSA-3072": {"key_size": 3072, "description": "Clé Docker RSA 3072-bit (content trust)"},
        "Docker-ECDSA-P256": {"key_size": 256, "description": "Clé Docker ECDSA P-256"},
        "Docker-Ed25519": {"key_size": 256, "description": "Clé Docker Ed25519"}
      },
      "kubernetes": {
        "K8s-RSA-3072": {"key_size": 3072, "description": "Clé Kubernetes RSA 3072-bit (cert-manager)"},
        "K8s-ECDSA-P256": {"key_size": 256, "description": "Clé Kubernetes ECDSA P-256"},
        "K8s-Ed25519": {"key_size": 256, "description": "Clé Kubernetes Ed25519"}
      }
    },
    "microservices": {
      "service_mesh": {
        "Istio-RSA-3072": {"key_size": 3072, "description": "Clé Istio RSA 3072-bit (mTLS)"},
        "Istio-ECDSA-P256": {"key_size": 256, "description": "Clé Istio ECDSA P-256 (mTLS recommandé)"},
        "Linkerd-Ed25519": {"key_size": 256, "description": "Clé Linkerd Ed25519 (mTLS)"}
      },
      "api_gateway": {
        "Gateway-RSA-3072": {"key_size": 3072, "description": "Clé API Gateway RSA 3072-bit (Kong/NGINX)"},
        "Gateway-ECDSA-P256": {"key_size": 256, "description": "Clé API Gateway ECDSA P-256"}
      }
    },
    "devops_security": {
      "ci_cd": {
        "CI-CD-RSA-3072": {"key_size": 3072, "description": "Clé CI/CD RSA 3072-bit (Jenkins/GitHub)"},
        "CI-CD-ECDSA-P256": {"key_size": 256, "description": "Clé CI/CD ECDSA P-256 (rapide)"},
        "CI-CD-Ed25519": {"key_size": 256, "description": "Clé CI/CD Ed25519 (recommandé)"}
      },
      "secrets_management": {
        "Vault-AES-256": {"key_size": 256, "description": "Clé HashiCorp Vault AES 256-bit (transit)"},
        "Vault-RSA-3072": {"key_size": 3072, "description": "Clé HashiCorp Vault RSA 3072-bit"},
        "Consul-AES-256": {"key_size": 256, "description": "Clé Consul AES 256-bit (encrypt)"}
      }
    }
  };
  
  /**
   * Configuration simplifiée pour l'interface utilisateur (2025)
   * Alignée avec NIST et OWASP pour UX optimale
   */
  const KEY_TYPES_CONFIG = {
      "symmetric": {
          "name": "Clés Symétriques",
          "algorithms": ["AES-256", "ChaCha20-Poly1305", "Camellia-256"],
          "description": "Chiffrement rapide pour données/sessions (AES-256 recommandé NIST)",
          "icon": "fas fa-lock",
          "color": "primary",
          "default_algorithm": "AES-256",
          "default_key_size": 256,
          "default_format": "base64",
          "warnings": ["Utilisez AES-256 ou ChaCha20 pour 2025 (OWASP)"]
      },
      "rsa": {
          "name": "RSA (Legacy)",
          "algorithms": ["RSA-3072", "RSA-4096"],
          "description": "Asymétrique pour signatures/chiffrement (3072+ recommandé NIST 2025)",
          "icon": "fas fa-exchange-alt",
          "color": "success",
          "default_algorithm": "RSA-3072",
          "default_key_size": 3072,
          "default_format": "pem",
          "warnings": ["Évitez RSA<3072; migrez vers ECC/Post-Q (NIST SP 800-57)"]
      },
      "ecc": {
          "name": "ECC (Courbes Elliptiques)",
          "algorithms": ["secp256r1", "secp384r1", "secp521r1"],
          "description": "Efficace et sécurisé (P-256 équiv. RSA 3072, NIST 2025)",
          "icon": "fas fa-circle",
          "color": "info",
          "default_algorithm": "secp256r1",
          "default_key_size": 256,
          "default_format": "pem",
          "warnings": ["Utilisez courbes NIST/Brainpool vérifiées"]
      },
      "ed25519": {
          "name": "Ed25519",
          "algorithms": ["Ed25519"],
          "description": "Signatures rapides/sécurisées (équiv. RSA 4096, recommandé 2025)",
          "icon": "fas fa-signature",
          "color": "warning",
          "default_algorithm": "Ed25519",
          "default_key_size": 256,
          "default_format": "pem",
          "warnings": ["Idéal pour SSH/JWT (OpenSSH 8.0+)"]
      },
      "x25519": {
          "name": "X25519",
          "algorithms": ["X25519"],
          "description": "Échange de clés ECDH moderne (RFC 7748)",
          "icon": "fas fa-handshake",
          "color": "secondary",
          "default_algorithm": "X25519",
          "default_key_size": 256,
          "default_format": "pem",
          "warnings": ["Préféré pour TLS 1.3 (IETF)"]
      },
      "ssh": {
          "name": "Clés SSH",
          "algorithms": ["Ed25519", "ECDSA-P256", "RSA-3072"],
          "description": "Authentification serveur (Ed25519 recommandé 2025)",
          "icon": "fas fa-terminal",
          "color": "dark",
          "default_algorithm": "Ed25519",
          "default_key_size": 256,
          "default_format": "openssh",
          "warnings": ["Désactivez password auth; utilisez FIDO2 si possible"]
      },
      "tls_cert": {
          "name": "Certificats TLS",
          "algorithms": ["ECDSA-P256", "RSA-3072", "Ed25519"],
          "description": "X.509 pour HTTPS (P-256 recommandé CA/B Forum 2025)",
          "icon": "fas fa-certificate",
          "color": "info",
          "default_algorithm": "ECDSA-P256",
          "default_key_size": 256,
          "default_format": "pem",
          "requires_special_params": true,
          "warnings": ["Validité max 398 jours (CA/B 2025); surveillez expiration"]
      },
      "bip39": {
          "name": "BIP39 (Crypto-monnaie)",
          "algorithms": ["BIP39-24"],
          "description": "Mnémoniques HD wallets (24 mots recommandé 2025)",
          "icon": "fab fa-bitcoin",
          "color": "warning",
          "default_algorithm": "BIP39-24",
          "default_key_size": 256,
          "default_format": "bip39_mnemonic",
          "security_warning": true,
          "warnings": ["Hors-ligne uniquement; pas de photos; hardware wallet (Ledger/Trezor)"]
      },
      "jwt": {
          "name": "JWT/API Tokens",
          "algorithms": ["HS512", "ES256", "PS256", "EdDSA"],
          "description": "Tokens signés (HS512 pour sym, ES256 asym 2025 OWASP)",
          "icon": "fas fa-code",
          "color": "primary",
          "default_algorithm": "ES256",
          "default_key_size": 256,
          "default_format": "jwk",
          "warnings": ["Rotation 24h; validez claims; évitez HS256 faible"]
      },
      "hmac": {
          "name": "HMAC",
          "algorithms": ["HMAC-SHA512"],
          "description": "Intégrité messages (SHA-512 recommandé NIST)",
          "icon": "fas fa-shield-alt",
          "color": "success",
          "default_algorithm": "HMAC-SHA512",
          "default_key_size": 512,
          "default_format": "base64",
          "warnings": ["Clé min 256 bits; ne réutilisez pas pour chiffrement"]
      },
      "totp": {
          "name": "TOTP/OTP",
          "algorithms": ["TOTP-SHA256"],
          "description": "2FA time-based (SHA-256 recommandé 2025)",
          "icon": "fas fa-mobile-alt",
          "color": "info",
          "default_algorithm": "TOTP-SHA256",
          "default_key_size": 256,
          "default_format": "base64",
          "warnings": ["Backup QR; changez périodiquement; utilisez app authenticator"]
      },
      "kdf": {
          "name": "KDF (Dérivation)",
          "algorithms": ["Argon2id"],
          "description": "De password à clé (Argon2id gagnant PHC, OWASP 2025)",
          "icon": "fas fa-key",
          "color": "secondary",
          "default_algorithm": "Argon2id",
          "default_key_size": 256,
          "default_format": "base64",
          "requires_special_params": true,
          "warnings": ["Min 100k itérations PBKDF2; salt unique; mémoire 64MB Argon2"]
      },
      "post_quantum": {  // Nouveau type pour 2025
          "name": "Post-Quantique",
          "algorithms": ["ML-KEM-768", "ML-DSA-65", "HQC-192", "SLH-DSA-SHA2-192f"],
          "description": "Résistant aux ordinateurs quantiques (NIST FIPS 203-205, 2025)",
          "icon": "fas fa-atom",
          "color": "danger",
          "default_algorithm": "ML-KEM-768",
          "default_key_size": 1184,
          "default_format": "pem",
          "warnings": ["Transition hybride recommandé; performances impactées"]
      }
  };
  
  /**
   * Formats de sortie disponibles (2025)
   */
  const OUTPUT_FORMATS = {
      "pem": {
          "name": "PEM",
          "description": "RFC 7468 - Texte base64 armé (-----BEGIN-----)",
          "use_cases": ["TLS", "SSH", "PGP"],
          "icon": "fas fa-file-code",
          "color": "primary"
      },
      "der": {
          "name": "DER",
          "description": "ASN.1 binaire (RFC 7468)",
          "use_cases": ["Java Keystore", "Windows Cert"],
          "icon": "fas fa-file-binary",
          "color": "success"
      },
      "pkcs8": {
          "name": "PKCS#8",
          "description": "RFC 5958 - Clés privées modernes",
          "use_cases": ["OpenSSL", "Crypto libs"],
          "icon": "fas fa-key",
          "color": "warning"
      },
      "pkcs12": {
          "name": "PKCS#12/PFX",
          "description": "RFC 7292 - Bundle chiffré (clé+cert)",
          "use_cases": ["Windows", "Java", "Browsers"],
          "icon": "fas fa-archive",
          "color": "info"
      },
      "jwk": {
          "name": "JWK",
          "description": "RFC 7517 - JSON pour APIs/JWT",
          "use_cases": ["OAuth2", "JWKS", "Cloud APIs"],
          "icon": "fas fa-code",
          "color": "secondary"
      },
      "base64": {
          "name": "Base64",
          "description": "RFC 4648 - Encodage texte sûr",
          "use_cases": ["API", "Config files"],
          "icon": "fas fa-file-alt",
          "color": "dark"
      },
      "hex": {
          "name": "Hexadécimal",
          "description": "Encodage hex lisible",
          "use_cases": ["Debug", "Seeds"],
          "icon": "fas fa-hashtag",
          "color": "primary"
      },
      "raw": {
          "name": "Raw/Binaire",
          "description": "Données brutes (fichiers .bin)",
          "use_cases": ["Embeds", "Hardware"],
          "icon": "fas fa-file-binary",
          "color": "dark"
      },
      "bip39_mnemonic": {
          "name": "BIP39 Mnemonic",
          "description": "BIP-39 - 12-24 mots (RFC N/A)",
          "use_cases": ["Wallets", "Recovery"],
          "icon": "fas fa-list",
          "color": "warning",
          "warnings": ["Hors-ligne; pas photos; hardware only (2025 best practices)"]
      },
      "openssh": {
          "name": "OpenSSH",
          "description": "Format OpenSSH (RFC 4716)",
          "use_cases": ["SSH", "Git"],
          "icon": "fas fa-terminal",
          "color": "info"
      },
      "jose": {  // Nouveau pour 2025
          "name": "JOSE",
          "description": "RFC 7515 - JSON Object Signing/Encryption",
          "use_cases": ["JWT hybride", "Post-Q"],
          "icon": "fas fa-object-group",
          "color": "secondary"
      }
  };
  
  /**
   * Avertissements de sécurité par type de clé (2025)
   */
  const SECURITY_WARNINGS = {
      "symmetric": [
          "🔐 AES-256 ou ChaCha20-Poly1305 recommandé (NIST SP 800-57 Rev. 6)",
          "🔐 Évitez RC4/Blowfish (dépréciés OWASP 2025)",
          "🔐 Rotation clés tous 2 ans max; utilisez KDF pour dérivés"
      ],
      "rsa": [
          "⚠️ RSA-2048 phase-out 2030; migrez ECC/Post-Q (NIST 2025)",
          "⚠️ Utilisez PSS/OAEP padding; min 3072 bits nouveaux",
          "⚠️ Vulnérable à Shor's quantum; planifiez migration"
      ],
      "ecc": [
          "✅ P-256 équiv. RSA 3072; P-384 pour long terme (NIST)",
          "✅ Évitez Dual_EC_DRBG curves; utilisez NIST/Brainpool vérifiées",
          "✅ Performances 10x RSA pour même sécurité"
      ],
      "ed25519": [
          "🚀 Équiv. RSA 4096; rapide pour signatures (OpenSSH recommandé)",
          "🚀 Résistant side-channel; idéal SSH/JWT 2025",
          "🚀 Support natif browsers (Chrome 73+)"
      ],
      "ssh": [
          "🔑 Ed25519 ou ECDSA-P256; évitez RSA<3072 (OpenSSH 9.0+)",
          "🔑 Désactivez password auth; utilisez CA pour scaling",
          "🔑 FIDO2/sk pour phishing resistance"
      ],
      "tls_cert": [
          "🔒 Validité max 398 jours (CA/B Forum 2025); OCSP stapling",
          "🔒 Hybride ECC/Post-Q pour forward secrecy",
          "🔒 Surveillez CT logs; utilisez HSTS preload"
      ],
      "bip39": [
          "⚠️ 24 mots recommandé; stockez offline, pas digital (2025 best practices)",
          "⚠️ Jamais entrer en ligne; utilisez air-gapped/hardware (Ledger/Trezor)",
          "⚠️ Perte = fonds perdus; backup multi-sites physiques séparés",
          "⚠️ Évitez photos/scans; considérez passphrase BIP39 additionnelle"
      ],
      "jwt": [
          "🔐 ES256/EdDSA recommandé; HS512 pour sym (OWASP 2025)",
          "🔐 Rotation 24h; validez audience/issuer; short expiry",
          "🔐 Utilisez JWE pour chiffrement; migrez post-Q (ML-DSA)"
      ],
      "hmac": [
          "🔐 SHA-512 recommandé; clé min 256 bits (NIST)",
          "🔐 Ne réutilisez pas pour chiffrement (OWASP)",
          "🔐 Vérifiez timing attacks avec HMAC constant-time"
      ],
      "totp": [
          "📱 SHA-256 recommandé; backup QR sécurisé (2025)",
          "📱 Changez secret tous 90 jours; utilisez app authenticator",
          "📱 Résistant replay avec time sync NTP"
      ],
      "kdf": [
          "🔐 Argon2id gagnant (PHC); PBKDF2 min 310k itérations (OWASP 2025)",
          "🔐 Salt unique/random 16+ bytes; mémoire 64MB Argon2",
          "🔐 Évitez MD5/SHA1; testez contre GPU attacks"
      ],
      "post_quantum": [
          "🛡️ ML-KEM/ML-DSA/SLH-DSA/HQC NIST FIPS 203-205 (2024-2025)",
          "🛡️ Hybride classical+PQ pour transition; testez interop",
          "🛡️ Performances: +20-50% taille; migrez TLS 1.4 draft"
      ]
  };
  
  /**
   * Utilitaires pour la gestion des types de clés (Amélioré 2025)
   */
  class KeyTypesManager {
      /**
       * Obtient la configuration d'un type de clé
       */
      static getKeyTypeConfig(keyType) {
          return KEY_TYPES_CONFIG[keyType] || null;
      }
  
      /**
       * Obtient les algorithmes pour un type de clé
       */
      static getAlgorithmsForKeyType(keyType) {
          const config = this.getKeyTypeConfig(keyType);
          return config ? config.algorithms : [];
      }
  
      /**
       * Obtient les formats de sortie recommandés pour un type de clé
       */
      static getRecommendedFormatsForKeyType(keyType) {
          const config = this.getKeyTypeConfig(keyType);
          if (!config) return Object.keys(OUTPUT_FORMATS);
  
          const formatMap = {
              "symmetric": ["base64", "hex", "raw"],
              "rsa": ["pem", "der", "pkcs8", "jwk"],
              "ecc": ["pem", "der", "pkcs8", "jwk"],
              "ed25519": ["pem", "der", "pkcs8", "jwk"],
              "x25519": ["pem", "der", "pkcs8", "jwk"],
              "ssh": ["openssh", "pem"],
              "tls_cert": ["pem", "pkcs12", "der"],
              "bip39": ["bip39_mnemonic", "hex", "base64"],
              "jwt": ["jwk", "base64", "jose"],
              "hmac": ["base64", "hex"],
              "totp": ["base64", "hex"],
              "kdf": ["base64", "hex"],
              "post_quantum": ["pem", "jwk", "jose"]
          };
  
          return formatMap[keyType] || ["pem", "base64"];
      }
  
      /**
       * Obtient les avertissements de sécurité pour un type de clé
       */
      static getSecurityWarnings(keyType) {
          return SECURITY_WARNINGS[keyType] || [
              "🔐 Suivez NIST SP 800-57 Rev. 6 (2025) pour la gestion des clés",
              "🔐 Ne partagez jamais vos clés privées ou secrets",
              "🔐 Stockez dans HSM/Vault; migrez vers post-quantique"
          ];
      }
  
      /**
       * Obtient la taille de clé par défaut pour un algorithme (2025)
       */
      static getKeySizeForAlgorithm(algorithm) {
          // Recherche dans la configuration complète
          for (const category of Object.values(COMPLETE_KEY_TYPES)) {
              for (const subcategory of Object.values(category)) {
                  if (subcategory[algorithm]) {
                      return subcategory[algorithm].key_size;
                  }
              }
          }
  
          // Tailles par défaut mises à jour 2025
          if (algorithm.includes('AES-128')) return 128;
          if (algorithm.includes('AES-192')) return 192;
          if (algorithm.includes('AES-256')) return 256;
          if (algorithm.includes('RSA-2048')) return 2048;
          if (algorithm.includes('RSA-3072')) return 3072;
          if (algorithm.includes('RSA-4096')) return 4096;
          if (algorithm.includes('P-256') || algorithm.includes('secp256')) return 256;
          if (algorithm.includes('P-384') || algorithm.includes('secp384')) return 384;
          if (algorithm.includes('P-521') || algorithm.includes('secp521')) return 521;
          if (algorithm.includes('Ed25519') || algorithm.includes('X25519')) return 256;
          if (algorithm.includes('TOTP') || algorithm.includes('HOTP')) return 256;  // SHA-256
          if (algorithm.includes('ML-KEM-768')) return 1184;
          if (algorithm.includes('ML-DSA-65')) return 1952;
          if (algorithm.includes('HQC-192')) return 3328;
          if (algorithm.includes('SLH-DSA-SHA2-192f')) return 48;  // Hash-based small
  
          return 256; // Taille par défaut
      }
  
      /**
       * Vérifie si un type de clé nécessite des paramètres spéciaux
       */
      static requiresSpecialParams(keyType) {
          const config = this.getKeyTypeConfig(keyType);
          return config && config.requires_special_params;
      }
  
      /**
       * Obtient tous les types de clés disponibles (filtrés 2025)
       */
      static getAllKeyTypes() {
          return Object.keys(KEY_TYPES_CONFIG).filter(type => !type.includes('legacy'));  // Exclure obsolètes
      }
  
      /**
       * Obtient tous les formats de sortie disponibles
       */
      static getAllOutputFormats() {
          return Object.keys(OUTPUT_FORMATS);
      }
  
      /**
       * Valide une combinaison type/algorithme/taille (2025)
       */
      static validateKeyConfiguration(keyType, algorithm, keySize) {
          const config = this.getKeyTypeConfig(keyType);
          if (!config) {
              return { valid: false, message: "Type de clé invalide ou déprécié (2025)" };
          }
  
          if (!config.algorithms.includes(algorithm)) {
              return { valid: false, message: "Algorithme non supporté ou déprécié pour ce type" };
          }
  
          const expectedSize = this.getKeySizeForAlgorithm(algorithm);
          if (expectedSize && keySize !== expectedSize) {
              return { 
                  valid: false, 
                  message: `Taille incorrecte. Attendu: ${expectedSize} bits (NIST 2025), reçu: ${keySize}` 
              };
          }
  
          // Vérifications supplémentaires 2025
          if (keyType === 'rsa' && keySize < 3072) {
              return { valid: false, message: "RSA <3072 non recommandé pour nouveaux systèmes (NIST)" };
          }
          if (keyType === 'bip39' && keySize < 256) {
              return { valid: false, message: "BIP39 24 mots (256 bits) recommandé pour sécurité" };
          }
          return { valid: true, message: "Configuration valide et conforme 2025" };
      }
  }
  
  // Export pour utilisation dans d'autres modules
  if (typeof module !== 'undefined' && module.exports) {
      module.exports = {
          COMPLETE_KEY_TYPES,
          KEY_TYPES_CONFIG,
          OUTPUT_FORMATS,
          SECURITY_WARNINGS,
          KeyTypesManager
      };
  }
  
  // Exposer globalement pour le navigateur
  if (typeof window !== 'undefined') {
      window.KeyTypesManager = KeyTypesManager;
      window.KEY_TYPES_CONFIG = KEY_TYPES_CONFIG;
      window.OUTPUT_FORMATS = OUTPUT_FORMATS;
      window.SECURITY_WARNINGS = SECURITY_WARNINGS;
      window.COMPLETE_KEY_TYPES = COMPLETE_KEY_TYPES;
  }