#!/usr/bin/env python3
"""
Validateur de protocoles de sécurité
Module spécialisé pour valider les protocoles cryptographiques et de communication
"""

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
import socket
import ssl
import struct
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Union
from enum import Enum

# Imports cryptographiques
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate

class ProtocolType(Enum):
    """Types de protocoles supportés"""
    TLS = "tls"
    SIGNAL = "signal"
    DOUBLE_RATCHET = "double_ratchet"
    X3DH = "x3dh"
    NOISE = "noise"
    OPENVPN = "openvpn"
    WIREGUARD = "wireguard"
    TOR = "tor"

class ValidationLevel(Enum):
    """Niveaux de validation"""
    BASIC = "basic"
    STANDARD = "standard"
    STRICT = "strict"
    PARANOID = "paranoid"

class ProtocolValidationResult:
    """Résultat de validation d'un protocole"""
    
    def __init__(self, protocol: ProtocolType, passed: bool, 
                 score: float, details: Dict[str, Any],
                 vulnerabilities: List[str] = None,
                 recommendations: List[str] = None):
        self.protocol = protocol
        self.passed = passed
        self.score = score  # Score de 0 à 100
        self.details = details
        self.vulnerabilities = vulnerabilities or []
        self.recommendations = recommendations or []
        self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convertit en dictionnaire"""
        return {
            "protocol": self.protocol.value,
            "passed": self.passed,
            "score": self.score,
            "details": self.details,
            "vulnerabilities": self.vulnerabilities,
            "recommendations": self.recommendations,
            "timestamp": self.timestamp.isoformat()
        }

class CryptographicValidator:
    """Validateur pour les primitives cryptographiques"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def validate_encryption_algorithm(self, algorithm: str, key_size: int) -> Tuple[bool, float, str]:
        """Valide un algorithme de chiffrement"""
        
        # Algorithmes approuvés et leurs scores
        approved_algorithms = {
            "AES": {
                128: (True, 70, "AES-128 acceptable mais AES-256 recommandé"),
                192: (True, 85, "AES-192 bon niveau de sécurité"),
                256: (True, 95, "AES-256 excellent niveau de sécurité")
            },
            "ChaCha20": {
                256: (True, 95, "ChaCha20 excellent algorithme moderne")
            },
            "Salsa20": {
                256: (True, 80, "Salsa20 bon mais ChaCha20 préférable")
            }
        }
        
        # Algorithmes dépréciés
        deprecated_algorithms = {
            "DES": (False, 0, "DES complètement obsolète"),
            "3DES": (False, 20, "3DES obsolète, utiliser AES"),
            "RC4": (False, 0, "RC4 complètement cassé"),
            "Blowfish": (False, 30, "Blowfish obsolète")
        }
        
        if algorithm in deprecated_algorithms:
            return deprecated_algorithms[algorithm]
        
        if algorithm in approved_algorithms:
            if key_size in approved_algorithms[algorithm]:
                return approved_algorithms[algorithm][key_size]
            else:
                return (False, 40, f"Taille de clé {key_size} non recommandée pour {algorithm}")
        
        return (False, 0, f"Algorithme {algorithm} non reconnu")
    
    def validate_hash_algorithm(self, algorithm: str) -> Tuple[bool, float, str]:
        """Valide un algorithme de hachage"""
        
        hash_scores = {
            "SHA-256": (True, 90, "SHA-256 excellent"),
            "SHA-384": (True, 95, "SHA-384 excellent"),
            "SHA-512": (True, 95, "SHA-512 excellent"),
            "SHA3-256": (True, 95, "SHA3-256 excellent"),
            "SHA3-512": (True, 95, "SHA3-512 excellent"),
            "BLAKE2b": (True, 90, "BLAKE2b excellent"),
            "BLAKE2s": (True, 85, "BLAKE2s bon"),
            "SHA-1": (False, 30, "SHA-1 obsolète, vulnérable aux collisions"),
            "MD5": (False, 0, "MD5 complètement cassé")
        }
        
        return hash_scores.get(algorithm, (False, 0, f"Algorithme {algorithm} non reconnu"))
    
    def validate_key_exchange(self, method: str, parameters: Dict[str, Any]) -> Tuple[bool, float, str]:
        """Valide une méthode d'échange de clés"""
        
        if method == "ECDH":
            curve = parameters.get("curve", "")
            
            curve_scores = {
                "P-256": (True, 80, "P-256 acceptable"),
                "P-384": (True, 90, "P-384 recommandé"),
                "P-521": (True, 95, "P-521 excellent"),
                "Curve25519": (True, 95, "Curve25519 excellent"),
                "Curve448": (True, 95, "Curve448 excellent")
            }
            
            return curve_scores.get(curve, (False, 40, f"Courbe {curve} non recommandée"))
        
        elif method == "DH":
            key_size = parameters.get("key_size", 0)
            
            if key_size >= 3072:
                return (True, 85, f"DH-{key_size} bon niveau")
            elif key_size >= 2048:
                return (True, 70, f"DH-{key_size} acceptable mais 3072+ recommandé")
            else:
                return (False, 30, f"DH-{key_size} trop faible")
        
        elif method == "RSA":
            key_size = parameters.get("key_size", 0)
            
            if key_size >= 4096:
                return (True, 80, f"RSA-{key_size} bon pour l'échange de clés")
            elif key_size >= 2048:
                return (True, 60, f"RSA-{key_size} acceptable mais ECDH préférable")
            else:
                return (False, 20, f"RSA-{key_size} trop faible")
        
        return (False, 0, f"Méthode {method} non reconnue")

class TLSValidator:
    """Validateur pour le protocole TLS"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.crypto_validator = CryptographicValidator()
    
    async def validate_tls_connection(self, hostname: str, port: int = 443) -> ProtocolValidationResult:
        """Valide une connexion TLS"""
        
        details = {}
        vulnerabilities = []
        recommendations = []
        score = 0
        
        try:
            # Création du contexte SSL
            context = ssl.create_default_context()
            
            # Connexion et récupération du certificat
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    
                    # Version TLS
                    tls_version = ssock.version()
                    details["tls_version"] = tls_version
                    
                    if tls_version in ["TLSv1.3"]:
                        score += 30
                        details["version_score"] = "Excellent"
                    elif tls_version in ["TLSv1.2"]:
                        score += 25
                        details["version_score"] = "Bon"
                    else:
                        vulnerabilities.append(f"Version TLS obsolète: {tls_version}")
                        recommendations.append("Mettre à jour vers TLS 1.3")
                        details["version_score"] = "Obsolète"
                    
                    # Cipher suite
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name, tls_ver, key_bits = cipher
                        details["cipher_suite"] = cipher_name
                        details["key_bits"] = key_bits
                        
                        # Validation du cipher
                        if "AES" in cipher_name and "GCM" in cipher_name:
                            score += 25
                        elif "ChaCha20" in cipher_name:
                            score += 25
                        elif "CBC" in cipher_name:
                            score += 15
                            recommendations.append("Préférer les modes AEAD (GCM)")
                        else:
                            vulnerabilities.append(f"Cipher faible: {cipher_name}")
                    
                    # Certificat
                    cert_der = ssock.getpeercert_chain()[0]
                    cert = ssl.DER_cert_to_PEM_cert(cert_der)
                    
                    # Validation du certificat
                    cert_score = self._validate_certificate(cert)
                    score += cert_score
                    details["certificate_score"] = cert_score
                    
                    # Perfect Forward Secrecy
                    if "ECDHE" in cipher_name or "DHE" in cipher_name:
                        score += 20
                        details["perfect_forward_secrecy"] = True
                    else:
                        vulnerabilities.append("Pas de Perfect Forward Secrecy")
                        details["perfect_forward_secrecy"] = False
            
            # Score final
            passed = score >= 70 and len(vulnerabilities) == 0
            
            return ProtocolValidationResult(
                ProtocolType.TLS,
                passed,
                min(score, 100),
                details,
                vulnerabilities,
                recommendations
            )
            
        except Exception as e:
            return ProtocolValidationResult(
                ProtocolType.TLS,
                False,
                0,
                {"error": str(e)},
                [f"Erreur de connexion TLS: {e}"],
                ["Vérifier la connectivité et la configuration"]
            )
    
    def _validate_certificate(self, cert_pem: str) -> float:
        """Valide un certificat X.509"""
        try:
            cert = load_pem_x509_certificate(cert_pem.encode(), default_backend())
            
            score = 0
            
            # Algorithme de signature
            sig_algo = cert.signature_algorithm_oid._name
            if "sha256" in sig_algo.lower():
                score += 15
            elif "sha1" in sig_algo.lower():
                score += 5  # Obsolète mais encore accepté
            
            # Taille de clé
            public_key = cert.public_key()
            if hasattr(public_key, 'key_size'):
                key_size = public_key.key_size
                if key_size >= 2048:
                    score += 10
            
            # Validité
            now = datetime.now()
            if cert.not_valid_before <= now <= cert.not_valid_after:
                score += 10
            
            return score
            
        except Exception:
            return 0

class SignalProtocolValidator:
    """Validateur pour le protocole Signal"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.crypto_validator = CryptographicValidator()
    
    def validate_signal_implementation(self, config: Dict[str, Any]) -> ProtocolValidationResult:
        """Valide une implémentation du protocole Signal"""
        
        details = {}
        vulnerabilities = []
        recommendations = []
        score = 0
        
        # Validation X3DH
        x3dh_score = self._validate_x3dh(config.get("x3dh", {}))
        score += x3dh_score
        details["x3dh_score"] = x3dh_score
        
        # Validation Double Ratchet
        dr_score = self._validate_double_ratchet(config.get("double_ratchet", {}))
        score += dr_score
        details["double_ratchet_score"] = dr_score
        
        # Validation des clés
        key_score = self._validate_key_management(config.get("key_management", {}))
        score += key_score
        details["key_management_score"] = key_score
        
        # Perfect Forward Secrecy
        if config.get("perfect_forward_secrecy", False):
            score += 20
            details["perfect_forward_secrecy"] = True
        else:
            vulnerabilities.append("Perfect Forward Secrecy non implémenté")
            recommendations.append("Implémenter la rotation automatique des clés")
        
        # Future Secrecy
        if config.get("future_secrecy", False):
            score += 15
            details["future_secrecy"] = True
        else:
            recommendations.append("Implémenter la Future Secrecy")
        
        # Deniability
        if config.get("deniability", False):
            score += 10
            details["deniability"] = True
        
        passed = score >= 80
        
        return ProtocolValidationResult(
            ProtocolType.SIGNAL,
            passed,
            min(score, 100),
            details,
            vulnerabilities,
            recommendations
        )
    
    def _validate_x3dh(self, config: Dict[str, Any]) -> float:
        """Valide l'implémentation X3DH"""
        score = 0
        
        # Courbe elliptique
        curve = config.get("curve", "")
        if curve in ["Curve25519", "P-384"]:
            score += 15
        elif curve == "P-256":
            score += 10
        
        # Clés d'identité
        if config.get("identity_keys", False):
            score += 10
        
        # Clés signées
        if config.get("signed_prekeys", False):
            score += 10
        
        # One-time prekeys
        if config.get("onetime_prekeys", False):
            score += 5
        
        return score
    
    def _validate_double_ratchet(self, config: Dict[str, Any]) -> float:
        """Valide l'implémentation Double Ratchet"""
        score = 0
        
        # Root chain
        if config.get("root_chain", False):
            score += 10
        
        # Sending chain
        if config.get("sending_chain", False):
            score += 10
        
        # Receiving chain
        if config.get("receiving_chain", False):
            score += 10
        
        # Key derivation
        kdf = config.get("kdf", "")
        if kdf == "HKDF-SHA256":
            score += 10
        elif "HKDF" in kdf:
            score += 8
        
        return score
    
    def _validate_key_management(self, config: Dict[str, Any]) -> float:
        """Valide la gestion des clés"""
        score = 0
        
        # Stockage sécurisé
        if config.get("secure_storage", False):
            score += 10
        
        # Rotation des clés
        if config.get("key_rotation", False):
            score += 10
        
        # Suppression sécurisée
        if config.get("secure_deletion", False):
            score += 5
        
        return score

class VPNProtocolValidator:
    """Validateur pour les protocoles VPN"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.crypto_validator = CryptographicValidator()
    
    def validate_openvpn(self, config: Dict[str, Any]) -> ProtocolValidationResult:
        """Valide une configuration OpenVPN"""
        
        details = {}
        vulnerabilities = []
        recommendations = []
        score = 0
        
        # Chiffrement
        cipher = config.get("cipher", "")
        if cipher:
            key_size = config.get("key_size", 0)
            passed, cipher_score, message = self.crypto_validator.validate_encryption_algorithm(
                cipher.split("-")[0], key_size
            )
            score += cipher_score * 0.3
            details["cipher_validation"] = message
            
            if not passed:
                vulnerabilities.append(f"Chiffrement faible: {cipher}")
        
        # Authentification
        auth = config.get("auth", "")
        if auth:
            passed, auth_score, message = self.crypto_validator.validate_hash_algorithm(auth)
            score += auth_score * 0.2
            details["auth_validation"] = message
        
        # Perfect Forward Secrecy
        if config.get("tls_auth", False) or config.get("tls_crypt", False):
            score += 20
            details["perfect_forward_secrecy"] = True
        else:
            recommendations.append("Activer tls-auth ou tls-crypt")
        
        # Compression
        if config.get("compress", False):
            vulnerabilities.append("Compression activée (vulnérable à CRIME/BREACH)")
            recommendations.append("Désactiver la compression")
        else:
            score += 10
        
        # Protocole
        proto = config.get("proto", "")
        if proto == "udp":
            score += 5
            details["protocol"] = "UDP (recommandé)"
        elif proto == "tcp":
            details["protocol"] = "TCP (acceptable)"
        
        passed = score >= 70 and len(vulnerabilities) == 0
        
        return ProtocolValidationResult(
            ProtocolType.OPENVPN,
            passed,
            min(score, 100),
            details,
            vulnerabilities,
            recommendations
        )
    
    def validate_wireguard(self, config: Dict[str, Any]) -> ProtocolValidationResult:
        """Valide une configuration WireGuard"""
        
        details = {}
        vulnerabilities = []
        recommendations = []
        score = 80  # WireGuard a une base solide
        
        # Clés
        if config.get("private_key") and config.get("public_key"):
            score += 10
            details["key_pair"] = "Présent"
        else:
            vulnerabilities.append("Clés manquantes")
        
        # Peers
        peers = config.get("peers", [])
        if peers:
            score += 10
            details["peers_count"] = len(peers)
        
        # Endpoint
        if config.get("endpoint"):
            details["endpoint"] = "Configuré"
        
        # Cryptographie (WireGuard utilise des primitives modernes)
        details["encryption"] = "ChaCha20-Poly1305"
        details["key_exchange"] = "Curve25519"
        details["hash"] = "BLAKE2s"
        
        passed = score >= 80 and len(vulnerabilities) == 0
        
        return ProtocolValidationResult(
            ProtocolType.WIREGUARD,
            passed,
            min(score, 100),
            details,
            vulnerabilities,
            recommendations
        )

class TorProtocolValidator:
    """Validateur pour le protocole Tor"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def validate_tor_configuration(self, config: Dict[str, Any]) -> ProtocolValidationResult:
        """Valide une configuration Tor"""
        
        details = {}
        vulnerabilities = []
        recommendations = []
        score = 0
        
        # Circuits
        circuit_length = config.get("circuit_length", 3)
        if circuit_length >= 3:
            score += 25
            details["circuit_length"] = f"{circuit_length} (bon)"
        else:
            vulnerabilities.append(f"Circuit trop court: {circuit_length}")
            recommendations.append("Utiliser au moins 3 relais")
        
        # Nodes de sortie
        exit_nodes = config.get("exit_nodes", [])
        if exit_nodes:
            details["exit_nodes"] = f"{len(exit_nodes)} configurés"
            score += 10
        
        # Nodes exclus
        exclude_nodes = config.get("exclude_nodes", [])
        if exclude_nodes:
            details["exclude_nodes"] = f"{len(exclude_nodes)} exclus"
            score += 5
        
        # Strict nodes
        if config.get("strict_nodes", False):
            score += 10
            details["strict_nodes"] = True
        else:
            recommendations.append("Activer StrictNodes pour plus de sécurité")
        
        # SOCKS proxy
        socks_port = config.get("socks_port", 9050)
        if socks_port:
            score += 15
            details["socks_port"] = socks_port
        
        # Control port
        control_port = config.get("control_port")
        if control_port:
            score += 10
            details["control_port"] = control_port
            
            # Authentification du port de contrôle
            if config.get("control_auth", False):
                score += 10
            else:
                vulnerabilities.append("Port de contrôle non authentifié")
                recommendations.append("Configurer l'authentification du port de contrôle")
        
        # Bridges
        if config.get("use_bridges", False):
            score += 15
            details["bridges"] = "Activés"
        
        # DNS
        if config.get("dns_port"):
            score += 5
            details["dns_port"] = config["dns_port"]
        
        passed = score >= 70 and len(vulnerabilities) <= 1
        
        return ProtocolValidationResult(
            ProtocolType.TOR,
            passed,
            min(score, 100),
            details,
            vulnerabilities,
            recommendations
        )

class ProtocolValidator:
    """Validateur principal pour tous les protocoles"""
    
    def __init__(self, validation_level: ValidationLevel = ValidationLevel.STANDARD):
        self.validation_level = validation_level
        self.logger = logging.getLogger(__name__)
        
        # Validateurs spécialisés
        self.tls_validator = TLSValidator()
        self.signal_validator = SignalProtocolValidator()
        self.vpn_validator = VPNProtocolValidator()
        self.tor_validator = TorProtocolValidator()
        
        self.results: List[ProtocolValidationResult] = []
    
    async def validate_all_protocols(self, configurations: Dict[str, Any]) -> List[ProtocolValidationResult]:
        """Valide tous les protocoles configurés"""
        
        self.logger.info("Démarrage de la validation des protocoles")
        self.results.clear()
        
        # Validation TLS
        if "tls" in configurations:
            tls_config = configurations["tls"]
            hostname = tls_config.get("hostname", "www.google.com")
            port = tls_config.get("port", 443)
            
            result = await self.tls_validator.validate_tls_connection(hostname, port)
            self.results.append(result)
        
        # Validation Signal
        if "signal" in configurations:
            result = self.signal_validator.validate_signal_implementation(
                configurations["signal"]
            )
            self.results.append(result)
        
        # Validation OpenVPN
        if "openvpn" in configurations:
            result = self.vpn_validator.validate_openvpn(configurations["openvpn"])
            self.results.append(result)
        
        # Validation WireGuard
        if "wireguard" in configurations:
            result = self.vpn_validator.validate_wireguard(configurations["wireguard"])
            self.results.append(result)
        
        # Validation Tor
        if "tor" in configurations:
            result = self.tor_validator.validate_tor_configuration(configurations["tor"])
            self.results.append(result)
        
        self.logger.info(f"Validation terminée: {len(self.results)} protocoles validés")
        return self.results
    
    def generate_compliance_report(self) -> Dict[str, Any]:
        """Génère un rapport de conformité"""
        
        if not self.results:
            return {"error": "Aucun résultat de validation"}
        
        total_score = sum(r.score for r in self.results) / len(self.results)
        passed_count = sum(1 for r in self.results if r.passed)
        
        # Classification de sécurité
        if total_score >= 90:
            security_level = "EXCELLENT"
        elif total_score >= 80:
            security_level = "BON"
        elif total_score >= 70:
            security_level = "ACCEPTABLE"
        elif total_score >= 50:
            security_level = "FAIBLE"
        else:
            security_level = "CRITIQUE"
        
        # Vulnérabilités critiques
        critical_vulns = []
        for result in self.results:
            if result.score < 50:
                critical_vulns.extend(result.vulnerabilities)
        
        # Recommandations prioritaires
        priority_recommendations = []
        for result in self.results:
            if not result.passed:
                priority_recommendations.extend(result.recommendations[:2])
        
        return {
            "timestamp": datetime.now().isoformat(),
            "validation_level": self.validation_level.value,
            "overall_score": round(total_score, 2),
            "security_level": security_level,
            "protocols_tested": len(self.results),
            "protocols_passed": passed_count,
            "protocols_failed": len(self.results) - passed_count,
            "critical_vulnerabilities": critical_vulns,
            "priority_recommendations": priority_recommendations,
            "detailed_results": [r.to_dict() for r in self.results]
        }
    
    def export_report(self, filename: str = None) -> str:
        """Exporte le rapport de validation"""
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"protocol_validation_{timestamp}.json"
        
        report = self.generate_compliance_report()
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return filename

async def main():
    """Fonction principale de test"""
    
    # Configuration d'exemple
    test_configurations = {
        "tls": {
            "hostname": "www.google.com",
            "port": 443
        },
        "signal": {
            "x3dh": {
                "curve": "Curve25519",
                "identity_keys": True,
                "signed_prekeys": True,
                "onetime_prekeys": True
            },
            "double_ratchet": {
                "root_chain": True,
                "sending_chain": True,
                "receiving_chain": True,
                "kdf": "HKDF-SHA256"
            },
            "key_management": {
                "secure_storage": True,
                "key_rotation": True,
                "secure_deletion": True
            },
            "perfect_forward_secrecy": True,
            "future_secrecy": True,
            "deniability": True
        },
        "openvpn": {
            "cipher": "AES-256-GCM",
            "key_size": 256,
            "auth": "SHA-256",
            "tls_auth": True,
            "compress": False,
            "proto": "udp"
        },
        "wireguard": {
            "private_key": "present",
            "public_key": "present",
            "peers": [{"endpoint": "vpn.example.com:51820"}],
            "endpoint": "vpn.example.com:51820"
        },
        "tor": {
            "circuit_length": 3,
            "exit_nodes": ["ExitNode1", "ExitNode2"],
            "exclude_nodes": ["BadNode1"],
            "strict_nodes": True,
            "socks_port": 9050,
            "control_port": 9051,
            "control_auth": True,
            "use_bridges": False,
            "dns_port": 9053
        }
    }
    
    # Validation
    validator = ProtocolValidator(ValidationLevel.STRICT)
    results = await validator.validate_all_protocols(test_configurations)
    
    # Rapport
    report = validator.generate_compliance_report()
    
    print("=" * 60)
    print("RAPPORT DE VALIDATION DES PROTOCOLES")
    print("=" * 60)
    print(f"Niveau de sécurité global: {report['security_level']}")
    print(f"Score moyen: {report['overall_score']}/100")
    print(f"Protocoles testés: {report['protocols_tested']}")
    print(f"Protocoles validés: {report['protocols_passed']}")
    
    if report['critical_vulnerabilities']:
        print("\nVulnérabilités critiques:")
        for vuln in report['critical_vulnerabilities']:
            print(f"  - {vuln}")
    
    if report['priority_recommendations']:
        print("\nRecommandations prioritaires:")
        for rec in report['priority_recommendations']:
            print(f"  - {rec}")
    
    # Export
    filename = validator.export_report()
    print(f"\nRapport détaillé exporté: {filename}")

if __name__ == "__main__":
    asyncio.run(main())