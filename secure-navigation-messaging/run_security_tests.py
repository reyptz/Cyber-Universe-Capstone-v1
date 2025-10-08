#!/usr/bin/env python3
"""
Script principal pour exécuter tous les tests de sécurité
Combine les tests de sécurité et la validation des protocoles
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from typing import Dict, List, Any

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_tests.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

# Imports des modules de test
try:
    from security_tests import SecurityTester
    from protocol_validator import ProtocolValidator, ValidationLevel
except ImportError as e:
    print(f"Erreur d'import: {e}")
    print("Assurez-vous que tous les modules sont présents")
    sys.exit(1)

class ComprehensiveSecurityTester:
    """Testeur de sécurité complet"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.security_tester = SecurityTester()
        self.protocol_validator = ProtocolValidator(ValidationLevel.STRICT)
        
        # Résultats
        self.security_results = []
        self.protocol_results = []
        
    async def run_comprehensive_tests(self) -> Dict[str, Any]:
        """Exécute tous les tests de sécurité"""
        
        self.logger.info("Démarrage des tests de sécurité complets")
        
        # Phase 1: Tests de sécurité de base
        self.logger.info("Phase 1: Tests de sécurité de base")
        self.security_results = await self.security_tester.run_all_tests()
        
        # Phase 2: Validation des protocoles
        self.logger.info("Phase 2: Validation des protocoles")
        protocol_configs = self._get_protocol_configurations()
        self.protocol_results = await self.protocol_validator.validate_all_protocols(protocol_configs)
        
        # Phase 3: Analyse combinée
        self.logger.info("Phase 3: Analyse des résultats")
        combined_report = self._generate_combined_report()
        
        return combined_report
    
    def _get_protocol_configurations(self) -> Dict[str, Any]:
        """Récupère les configurations des protocoles à tester"""
        
        return {
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
    
    def _generate_combined_report(self) -> Dict[str, Any]:
        """Génère un rapport combiné de tous les tests"""
        
        # Statistiques des tests de sécurité
        security_passed = sum(1 for r in self.security_results if r.passed)
        security_failed = len(self.security_results) - security_passed
        
        # Statistiques des protocoles
        protocol_passed = sum(1 for r in self.protocol_results if r.passed)
        protocol_failed = len(self.protocol_results) - protocol_passed
        
        # Score global
        if self.security_results:
            security_score = (security_passed / len(self.security_results)) * 100
        else:
            security_score = 0
            
        if self.protocol_results:
            protocol_score = sum(r.score for r in self.protocol_results) / len(self.protocol_results)
        else:
            protocol_score = 0
        
        overall_score = (security_score + protocol_score) / 2
        
        # Niveau de sécurité global
        if overall_score >= 90:
            security_level = "EXCELLENT"
            risk_level = "TRÈS FAIBLE"
        elif overall_score >= 80:
            security_level = "BON"
            risk_level = "FAIBLE"
        elif overall_score >= 70:
            security_level = "ACCEPTABLE"
            risk_level = "MOYEN"
        elif overall_score >= 50:
            security_level = "INSUFFISANT"
            risk_level = "ÉLEVÉ"
        else:
            security_level = "CRITIQUE"
            risk_level = "CRITIQUE"
        
        # Vulnérabilités critiques
        critical_issues = []
        
        # Issues des tests de sécurité
        for result in self.security_results:
            if not result.passed and result.risk_level in ["high", "critical"]:
                critical_issues.append({
                    "type": "security",
                    "test": result.test_name,
                    "issue": result.details,
                    "risk": result.risk_level,
                    "recommendations": result.recommendations
                })
        
        # Issues des protocoles
        for result in self.protocol_results:
            if not result.passed or result.score < 70:
                critical_issues.append({
                    "type": "protocol",
                    "protocol": result.protocol.value,
                    "score": result.score,
                    "vulnerabilities": result.vulnerabilities,
                    "recommendations": result.recommendations
                })
        
        # Recommandations prioritaires
        priority_actions = []
        
        # Actions critiques
        if any(issue["risk"] == "critical" for issue in critical_issues if "risk" in issue):
            priority_actions.append("ARRÊTER IMMÉDIATEMENT toute activité sensible")
            priority_actions.append("Corriger les vulnérabilités critiques avant de continuer")
        
        # Actions par catégorie
        if security_failed > 0:
            priority_actions.append(f"Corriger {security_failed} tests de sécurité échoués")
        
        if protocol_failed > 0:
            priority_actions.append(f"Reconfigurer {protocol_failed} protocoles non conformes")
        
        # Recommandations générales
        general_recommendations = [
            "Effectuer des tests réguliers (hebdomadaires)",
            "Maintenir les logiciels à jour",
            "Surveiller les logs de sécurité",
            "Former les utilisateurs aux bonnes pratiques",
            "Implémenter une surveillance continue"
        ]
        
        return {
            "timestamp": datetime.now().isoformat(),
            "test_summary": {
                "security_tests": {
                    "total": len(self.security_results),
                    "passed": security_passed,
                    "failed": security_failed,
                    "score": round(security_score, 2)
                },
                "protocol_validation": {
                    "total": len(self.protocol_results),
                    "passed": protocol_passed,
                    "failed": protocol_failed,
                    "score": round(protocol_score, 2)
                }
            },
            "overall_assessment": {
                "score": round(overall_score, 2),
                "security_level": security_level,
                "risk_level": risk_level,
                "critical_issues_count": len(critical_issues)
            },
            "critical_issues": critical_issues,
            "priority_actions": priority_actions,
            "general_recommendations": general_recommendations,
            "detailed_results": {
                "security_tests": [
                    {
                        "test_name": r.test_name,
                        "passed": r.passed,
                        "details": r.details,
                        "risk_level": r.risk_level,
                        "recommendations": r.recommendations
                    } for r in self.security_results
                ],
                "protocol_validation": [r.to_dict() for r in self.protocol_results]
            }
        }
    
    def print_summary_report(self, report: Dict[str, Any]):
        """Affiche un résumé du rapport"""
        
        print("\n" + "=" * 80)
        print("GHOST CYBER UNIVERSE - RAPPORT DE SÉCURITÉ COMPLET")
        print("=" * 80)
        
        # En-tête
        print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Score global: {report['overall_assessment']['score']}/100")
        print(f"Niveau de sécurité: {report['overall_assessment']['security_level']}")
        print(f"Niveau de risque: {report['overall_assessment']['risk_level']}")
        
        # Statistiques
        print("\n" + "-" * 40)
        print("STATISTIQUES DES TESTS")
        print("-" * 40)
        
        sec_stats = report['test_summary']['security_tests']
        print(f"Tests de sécurité: {sec_stats['passed']}/{sec_stats['total']} réussis ({sec_stats['score']:.1f}%)")
        
        proto_stats = report['test_summary']['protocol_validation']
        print(f"Validation protocoles: {proto_stats['passed']}/{proto_stats['total']} conformes ({proto_stats['score']:.1f}%)")
        
        # Issues critiques
        critical_count = report['overall_assessment']['critical_issues_count']
        if critical_count > 0:
            print(f"\n⚠️  ATTENTION: {critical_count} problèmes critiques détectés!")
            
            print("\n" + "-" * 40)
            print("PROBLÈMES CRITIQUES")
            print("-" * 40)
            
            for i, issue in enumerate(report['critical_issues'][:5], 1):  # Top 5
                if issue['type'] == 'security':
                    print(f"{i}. [SÉCURITÉ] {issue['test']}")
                    print(f"   Problème: {issue['issue']}")
                    print(f"   Risque: {issue['risk'].upper()}")
                else:
                    print(f"{i}. [PROTOCOLE] {issue['protocol'].upper()}")
                    print(f"   Score: {issue['score']}/100")
                    if issue['vulnerabilities']:
                        print(f"   Vulnérabilités: {', '.join(issue['vulnerabilities'][:2])}")
                print()
        
        # Actions prioritaires
        if report['priority_actions']:
            print("-" * 40)
            print("ACTIONS PRIORITAIRES")
            print("-" * 40)
            
            for i, action in enumerate(report['priority_actions'][:5], 1):
                print(f"{i}. {action}")
            print()
        
        # Recommandations
        print("-" * 40)
        print("RECOMMANDATIONS GÉNÉRALES")
        print("-" * 40)
        
        for i, rec in enumerate(report['general_recommendations'], 1):
            print(f"{i}. {rec}")
        
        print("\n" + "=" * 80)
        
        # Alerte finale
        if report['overall_assessment']['risk_level'] in ['CRITIQUE', 'ÉLEVÉ']:
            print("🚨 ALERTE SÉCURITÉ: Intervention immédiate requise!")
        elif report['overall_assessment']['risk_level'] == 'MOYEN':
            print("⚠️  ATTENTION: Améliorations de sécurité recommandées")
        else:
            print("✅ Niveau de sécurité satisfaisant")
        
        print("=" * 80)
    
    def export_full_report(self, report: Dict[str, Any], filename: str = None) -> str:
        """Exporte le rapport complet"""
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"ghost_cyber_security_report_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return filename

async def main():
    """Fonction principale"""
    
    print("Initialisation du système de test Ghost Cyber Universe...")
    
    # Vérification des dépendances
    try:
        import requests
        import dns.resolver
        import psutil
        from cryptography.hazmat.primitives import hashes
        print("✅ Toutes les dépendances sont disponibles")
    except ImportError as e:
        print(f"❌ Dépendance manquante: {e}")
        print("Installez les dépendances avec: pip install -r requirements.txt")
        return
    
    # Création du testeur
    tester = ComprehensiveSecurityTester()
    
    try:
        # Exécution des tests
        print("\nDémarrage des tests de sécurité complets...")
        report = await tester.run_comprehensive_tests()
        
        # Affichage du résumé
        tester.print_summary_report(report)
        
        # Export du rapport
        filename = tester.export_full_report(report)
        print(f"\n📄 Rapport détaillé exporté: {filename}")
        
        # Codes de sortie
        overall_score = report['overall_assessment']['score']
        if overall_score >= 80:
            print("\n✅ Tests terminés avec succès")
            return 0
        elif overall_score >= 60:
            print("\n⚠️  Tests terminés avec des avertissements")
            return 1
        else:
            print("\n❌ Tests terminés avec des erreurs critiques")
            return 2
            
    except Exception as e:
        print(f"\n❌ Erreur lors des tests: {e}")
        tester.logger.error(f"Erreur critique: {e}", exc_info=True)
        return 3

if __name__ == "__main__":
    exit_code = asyncio.run(main())