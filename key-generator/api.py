"""
API FastAPI pour le générateur de clés cryptographiques
======================================================

Interface web moderne avec FastAPI pour la génération de clés.
"""

from fastapi import FastAPI, HTTPException, Request, Depends, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import uvicorn
import os
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from pathlib import Path

# Imports locaux
from core import (
    CryptographicKeyGenerator, KeyGenerationConfig, KeyType, 
    OutputFormat, GeneratedKey
)
from security import SecurityManager, SecurityValidator


# Configuration de l'application
app = FastAPI(
    title="Ghost Cyber Universe - Générateur de Clés Cryptographiques",
    description="Générateur complet de clés cryptographiques avec toutes les bonnes pratiques de sécurité",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Middleware de sécurité
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # En production, spécifiez les domaines autorisés
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"]  # En production, spécifiez les hôtes autorisés
)

# Configuration des templates et fichiers statiques
templates = Jinja2Templates(directory="./templates")
app.mount("/static", StaticFiles(directory="./static"), name="static")

# Instances globales
key_generator = CryptographicKeyGenerator()
security_manager = SecurityManager()
security = HTTPBearer(auto_error=False)


# Modèles de données
from pydantic import BaseModel, Field

class KeyGenerationRequest(BaseModel):
    """Modèle de requête pour la génération de clés"""
    key_type: str
    algorithm: str = "AES-256"
    key_size: int = 256
    curve: str = "secp256r1"
    rsa_key_size: int = 2048
    output_format: str = "pem"
    password_protected: bool = True
    password: Optional[str] = None
    validity_days: int = 365
    common_name: str = "Ghost Cyber Universe"
    organization: str = "Ghost Cyber Universe"
    country: str = "FR"
    email: Optional[str] = None
    iterations: int = 100000
    salt_length: int = 32


class KeyGenerationResponse(BaseModel):
    """Modèle de réponse pour la génération de clés"""
    success: bool
    key_data: Union[str, Dict[str, Any]]
    public_key: Optional[Union[str, Dict[str, Any]]] = None
    private_key: Optional[Union[str, Dict[str, Any]]] = None
    fingerprint: Optional[str] = None
    algorithm: str
    key_type: str
    created_at: str
    expires_at: Optional[str] = None
    security_warnings: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


# Dépendances
async def get_client_info(request: Request) -> Dict[str, str]:
    """Extrait les informations du client"""
    return {
        "ip_address": request.client.host if request.client else "unknown",
        "user_agent": request.headers.get("user-agent", "unknown")
    }


async def check_rate_limit(request: Request) -> bool:
    """Vérifie les limites de taux"""
    client_info = await get_client_info(request)
    ip_address = client_info["ip_address"]
    
    allowed, message = security_manager.check_rate_limit(ip_address)
    if not allowed:
        raise HTTPException(status_code=429, detail=message)
    
    return True


# Routes principales
@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Page d'accueil"""
    return templates.TemplateResponse("index.html", {
        "request": request,
        "title": "Ghost Cyber Universe - Générateur de Clés"
    })


@app.get("/api/health")
async def health_check():
    """Vérification de santé de l'API"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }


@app.get("/api/key-types")
async def get_key_types():
    """Retourne les types de clés supportés"""
    return {
        "symmetric": {
            "name": "Clés Symétriques",
            "algorithms": ["AES-128", "AES-192", "AES-256", "ChaCha20-Poly1305"],
            "description": "Chiffrement/déchiffrement de données, clés de session"
        },
        "rsa": {
            "name": "RSA",
            "algorithms": ["RSA-2048", "RSA-3072", "RSA-4096"],
            "description": "Chiffrement asymétrique et signatures (compatibilité large)"
        },
        "ecc": {
            "name": "ECC (Courbes Elliptiques)",
            "algorithms": ["secp256r1", "secp384r1", "secp521r1", "secp256k1"],
            "description": "Plus petites et plus rapides que RSA"
        },
        "ed25519": {
            "name": "Ed25519",
            "algorithms": ["Ed25519"],
            "description": "Signatures modernes, très rapides"
        },
        "x25519": {
            "name": "X25519",
            "algorithms": ["X25519"],
            "description": "Échange de clés moderne"
        },
        "ssh": {
            "name": "Clés SSH",
            "algorithms": ["RSA", "ECDSA", "Ed25519"],
            "description": "Authentification SSH"
        },
        "tls_cert": {
            "name": "Certificats TLS",
            "algorithms": ["RSA", "ECDSA", "Ed25519"],
            "description": "Certificats X.509 pour HTTPS/TLS"
        },
        "bip39": {
            "name": "BIP39 (Crypto-monnaie)",
            "algorithms": ["BIP39-128", "BIP39-160", "BIP39-192", "BIP39-224", "BIP39-256"],
            "description": "Mnémoniques pour wallets crypto"
        },
        "jwt": {
            "name": "JWT/API Tokens",
            "algorithms": ["HS256", "HS512", "RS256", "RS512", "ES256", "ES512", "EdDSA"],
            "description": "Clés pour JSON Web Tokens"
        },
        "hmac": {
            "name": "HMAC",
            "algorithms": ["HMAC-SHA256", "HMAC-SHA512"],
            "description": "Authentification d'intégrité des messages"
        },
        "totp": {
            "name": "TOTP/OTP",
            "algorithms": ["TOTP"],
            "description": "Secrets pour authentification à deux facteurs"
        },
        "kdf": {
            "name": "KDF (Key Derivation)",
            "algorithms": ["PBKDF2", "scrypt", "Argon2id"],
            "description": "Dérivation de clés depuis un mot de passe"
        }
    }


@app.get("/api/output-formats")
async def get_output_formats():
    """Retourne les formats de sortie supportés"""
    return {
        "pem": {
            "name": "PEM",
            "description": "Format texte base64 encadré (-----BEGIN PRIVATE KEY-----)",
            "use_cases": ["Certificats", "Clés privées", "CSR"]
        },
        "der": {
            "name": "DER",
            "description": "Format binaire",
            "use_cases": ["Certificats", "Clés privées"]
        },
        "pkcs8": {
            "name": "PKCS#8",
            "description": "Format moderne pour clés privées",
            "use_cases": ["Clés privées"]
        },
        "pkcs12": {
            "name": "PKCS#12/PFX",
            "description": "Bundle (clé privée + certificat) protégé par mot de passe",
            "use_cases": ["Certificats", "Clés privées"]
        },
        "jwk": {
            "name": "JWK (JSON Web Key)",
            "description": "Format JSON pour APIs/OAuth/JWKS",
            "use_cases": ["JWT", "OAuth", "APIs"]
        },
        "base64": {
            "name": "Base64",
            "description": "Encodage base64",
            "use_cases": ["Clés symétriques", "Seeds"]
        },
        "hex": {
            "name": "Hexadécimal",
            "description": "Encodage hexadécimal",
            "use_cases": ["Clés symétriques", "Seeds"]
        },
        "raw": {
            "name": "Raw/Binaire",
            "description": "Données binaires brutes",
            "use_cases": ["Clés symétriques", "Seeds"]
        },
        "bip39_mnemonic": {
            "name": "BIP39 Mnemonic",
            "description": "12/24 mots pour wallets crypto",
            "use_cases": ["Crypto-monnaie", "Wallets"]
        },
        "openssh": {
            "name": "OpenSSH",
            "description": "Format OpenSSH pour clés SSH",
            "use_cases": ["SSH", "Authentification"]
        }
    }


@app.post("/api/generate-key", response_model=KeyGenerationResponse)
async def generate_key(
    request: KeyGenerationRequest,
    background_tasks: BackgroundTasks,
    client_info: Dict[str, str] = Depends(get_client_info),
    rate_limited: bool = Depends(check_rate_limit)
):
    """Génère une clé cryptographique"""
    try:
        # Validation des paramètres
        key_type_enum = KeyType(request.key_type)
        output_format_enum = OutputFormat(request.output_format)
        
        # Validation de sécurité
        is_valid, warnings = security_manager.validate_key_parameters(
            request.key_type, request.algorithm, request.key_size
        )
        if not is_valid:
            raise HTTPException(status_code=400, detail=warnings[0])
        
        # Validation des paramètres spécifiques
        if request.key_type == "tls_cert":
            is_valid, message = SecurityValidator.validate_common_name(request.common_name)
            if not is_valid:
                raise HTTPException(status_code=400, detail=message)
        
        if request.email:
            is_valid, message = SecurityValidator.validate_email(request.email)
            if not is_valid:
                raise HTTPException(status_code=400, detail=message)
        
        # Validation de la taille de clé
        is_valid, message = SecurityValidator.validate_key_size(
            request.key_type, request.key_size
        )
        if not is_valid:
            raise HTTPException(status_code=400, detail=message)
        
        # Configuration de génération
        config = KeyGenerationConfig(
            key_type=key_type_enum,
            algorithm=request.algorithm,
            key_size=request.key_size,
            curve=request.curve,
            rsa_key_size=request.rsa_key_size,
            output_format=output_format_enum,
            password_protected=request.password_protected,
            password=request.password,
            validity_days=request.validity_days,
            common_name=request.common_name,
            organization=request.organization,
            country=request.country,
            email=request.email,
            iterations=request.iterations,
            salt_length=request.salt_length
        )
        
        # Génération de la clé
        generated_key = key_generator.generate_key(config)
        
        # Enregistrement de l'audit
        background_tasks.add_task(
            security_manager.log_audit_event,
            operation="generate_key",
            key_type=request.key_type,
            algorithm=request.algorithm,
            fingerprint=generated_key.fingerprint,
            ip_address=client_info["ip_address"],
            user_agent=client_info["user_agent"],
            success=True,
            metadata={
                "output_format": request.output_format,
                "password_protected": request.password_protected
            }
        )
        
        # Préparation de la réponse
        response = KeyGenerationResponse(
            success=True,
            key_data=generated_key.key_data,
            public_key=generated_key.public_key,
            private_key=generated_key.private_key,
            fingerprint=generated_key.fingerprint,
            algorithm=generated_key.algorithm,
            key_type=generated_key.key_type.value,
            created_at=generated_key.created_at.isoformat() if generated_key.created_at else None,
            expires_at=generated_key.expires_at.isoformat() if generated_key.expires_at else None,
            security_warnings=generated_key.security_warnings or [],
            metadata=generated_key.metadata or {}
        )
        
        return response
        
    except ValueError as e:
        # Enregistrement de l'erreur
        security_manager.log_audit_event(
            operation="generate_key",
            key_type=request.key_type,
            algorithm=request.algorithm,
            fingerprint="error",
            ip_address=client_info["ip_address"],
            user_agent=client_info["user_agent"],
            success=False,
            error_message=str(e)
        )
        raise HTTPException(status_code=400, detail=str(e))
    
    except Exception as e:
        # Enregistrement de l'erreur
        security_manager.log_audit_event(
            operation="generate_key",
            key_type=request.key_type,
            algorithm=request.algorithm,
            fingerprint="error",
            ip_address=client_info["ip_address"],
            user_agent=client_info["user_agent"],
            success=False,
            error_message=str(e)
        )
        raise HTTPException(status_code=500, detail=f"Erreur interne: {str(e)}")


@app.get("/api/security-warnings/{key_type}")
async def get_security_warnings(key_type: str):
    """Retourne les avertissements de sécurité pour un type de clé"""
    warnings = security_manager.get_security_warnings(key_type, "")
    return {"warnings": warnings}


@app.get("/api/security-recommendations")
async def get_security_recommendations():
    """Retourne les recommandations de sécurité"""
    recommendations = security_manager.get_security_recommendations()
    return {"recommendations": recommendations}


@app.get("/api/security-report")
async def get_security_report():
    """Retourne le rapport de sécurité"""
    report = security_manager.generate_security_report()
    return report


@app.post("/api/validate-password")
async def validate_password(password: str):
    """Valide la force d'un mot de passe"""
    is_strong, warnings = security_manager.validate_password_strength(password)
    return {
        "is_strong": is_strong,
        "warnings": warnings
    }


@app.post("/api/generate-password")
async def generate_password(length: int = 16):
    """Génère un mot de passe sécurisé"""
    if length < 8 or length > 128:
        raise HTTPException(status_code=400, detail="Longueur de mot de passe invalide (8-128 caractères)")
    
    password = security_manager.generate_secure_password(length)
    return {"password": password}


@app.get("/api/download/{fingerprint}")
async def download_key(fingerprint: str, format: str = "json"):
    """Télécharge une clé générée (simulation)"""
    # En production, ceci devrait récupérer la clé depuis une base de données
    # Pour la démo, nous retournons un exemple
    
    if format == "json":
        return JSONResponse(
            content={"message": "Téléchargement simulé", "fingerprint": fingerprint},
            headers={"Content-Disposition": f"attachment; filename=key_{fingerprint}.json"}
        )
    else:
        return JSONResponse(
            content={"message": "Format non supporté"},
            status_code=400
        )


# Routes pour l'interface utilisateur
@app.get("/generate", response_class=HTMLResponse)
async def generate_page(request: Request):
    """Page de génération de clés"""
    return templates.TemplateResponse("generate.html", {
        "request": request,
        "title": "Générer une Clé - Ghost Cyber Universe"
    })


@app.get("/security", response_class=HTMLResponse)
async def security_page(request: Request):
    """Page de sécurité"""
    return templates.TemplateResponse("security.html", {
        "request": request,
        "title": "Sécurité - Ghost Cyber Universe"
    })


@app.get("/about", response_class=HTMLResponse)
async def about_page(request: Request):
    """Page à propos"""
    return templates.TemplateResponse("about.html", {
        "request": request,
        "title": "À Propos - Ghost Cyber Universe"
    })


# Tâches de maintenance
@app.on_event("startup")
async def startup_event():
    """Événements de démarrage"""
    print("🚀 Ghost Cyber Universe - Générateur de Clés démarré")
    print("📊 Interface disponible sur: http://localhost:8000")
    print("📚 Documentation API: http://localhost:8000/api/docs")


@app.on_event("shutdown")
async def shutdown_event():
    """Événements d'arrêt"""
    print("🛑 Arrêt du générateur de clés")


# Tâche de nettoyage périodique
@app.get("/api/cleanup")
async def cleanup_old_data():
    """Nettoie les anciennes données d'audit"""
    security_manager.cleanup_old_audits(days_to_keep=30)
    return {"message": "Nettoyage terminé"}


if __name__ == "__main__":
    # Création des répertoires nécessaires
    os.makedirs("key-generator/templates", exist_ok=True)
    os.makedirs("key-generator/static", exist_ok=True)
    
    # Démarrage du serveur
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8080,
        log_level="info"
    )
