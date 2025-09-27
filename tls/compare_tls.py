#!/usr/bin/env python3
"""
Comparaison détaillée TLS 1.2 vs TLS 1.3
"""

import ssl
import socket
import json
import time
from datetime import datetime
import subprocess
import os

class TLSComparator:
    def __init__(self):
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'tls_12_tests': [],
            'tls_13_tests': [],
            'comparison': {},
            'security_analysis': {}
        }
    
    def test_tls_connection(self, hostname, port=443, tls_version=None):
        """Teste une connexion TLS avec une version spécifique"""
        try:
            # Créer le contexte SSL
            context = ssl.create_default_context()
            
            # Configurer la version TLS si spécifiée
            if tls_version == 'TLSv1_2':
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.maximum_version = ssl.TLSVersion.TLSv1_2
            elif tls_version == 'TLSv1_3':
                context.minimum_version = ssl.TLSVersion.TLSv1_3
                context.maximum_version = ssl.TLSVersion.TLSv1_3
            
            start_time = time.time()
            
            # Établir la connexion
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    handshake_time = time.time() - start_time
                    
                    # Récupérer les informations de la connexion
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Envoyer une requête HTTP simple pour tester la performance
                    request = f"GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
                    ssock.send(request.encode())
                    
                    response_start = time.time()
                    response = ssock.recv(1024)
                    response_time = time.time() - response_start
                    
                    return {
                        'success': True,
                        'hostname': hostname,
                        'tls_version': version,
                        'cipher_suite': cipher[0] if cipher else None,
                        'cipher_strength': cipher[2] if cipher else None,
                        'handshake_time': round(handshake_time * 1000, 2),  # en ms
                        'response_time': round(response_time * 1000, 2),    # en ms
                        'certificate_subject': cert.get('subject', []) if cert else [],
                        'certificate_issuer': cert.get('issuer', []) if cert else [],
                        'certificate_version': cert.get('version', None) if cert else None,
                        'error': None
                    }
                    
        except Exception as e:
            return {
                'success': False,
                'hostname': hostname,
                'tls_version': tls_version,
                'error': str(e),
                'handshake_time': None,
                'response_time': None
            }
    
    def test_multiple_sites(self, sites, tls_version):
        """Teste plusieurs sites avec une version TLS spécifique"""
        results = []
        
        print(f"\nTest des sites avec {tls_version}:")
        
        for hostname in sites:
            print(f"  Testing {hostname}...", end=" ")
            result = self.test_tls_connection(hostname, tls_version=tls_version)
            
            if result['success']:
                print(f"✓ {result['tls_version']} ({result['handshake_time']}ms)")
            else:
                print(f"✗ {result['error'][:50]}...")
            
            results.append(result)
            time.sleep(0.5)  # Pause entre les tests
        
        return results
    
    def run_comparison_tests(self):
        """Exécute les tests de comparaison TLS"""
        print("=== COMPARAISON TLS 1.2 vs TLS 1.3 ===")
        
        # Sites de test (qui supportent TLS 1.3)
        test_sites = [
            'www.google.com',
            'www.cloudflare.com',
            'www.github.com',
            'www.mozilla.org',
            'www.microsoft.com'
        ]
        
        # Tester TLS 1.2
        print("\n🔒 Phase 1: Tests TLS 1.2")
        self.results['tls_12_tests'] = self.test_multiple_sites(test_sites, 'TLSv1_2')
        
        # Tester TLS 1.3
        print("\n🔒 Phase 2: Tests TLS 1.3")
        self.results['tls_13_tests'] = self.test_multiple_sites(test_sites, 'TLSv1_3')
        
        # Analyser les résultats
        self.analyze_results()
    
    def analyze_results(self):
        """Analyse et compare les résultats"""
        print("\n📊 Analyse des résultats...")
        
        # Statistiques TLS 1.2
        tls12_successful = [r for r in self.results['tls_12_tests'] if r['success']]
        tls12_handshake_times = [r['handshake_time'] for r in tls12_successful if r['handshake_time']]
        tls12_response_times = [r['response_time'] for r in tls12_successful if r['response_time']]
        
        # Statistiques TLS 1.3
        tls13_successful = [r for r in self.results['tls_13_tests'] if r['success']]
        tls13_handshake_times = [r['handshake_time'] for r in tls13_successful if r['handshake_time']]
        tls13_response_times = [r['response_time'] for r in tls13_successful if r['response_time']]
        
        # Calculer les moyennes
        comparison = {
            'tls_12': {
                'success_rate': len(tls12_successful) / len(self.results['tls_12_tests']) * 100,
                'avg_handshake_time': sum(tls12_handshake_times) / len(tls12_handshake_times) if tls12_handshake_times else 0,
                'avg_response_time': sum(tls12_response_times) / len(tls12_response_times) if tls12_response_times else 0,
                'cipher_suites': list(set([r['cipher_suite'] for r in tls12_successful if r['cipher_suite']]))
            },
            'tls_13': {
                'success_rate': len(tls13_successful) / len(self.results['tls_13_tests']) * 100,
                'avg_handshake_time': sum(tls13_handshake_times) / len(tls13_handshake_times) if tls13_handshake_times else 0,
                'avg_response_time': sum(tls13_response_times) / len(tls13_response_times) if tls13_response_times else 0,
                'cipher_suites': list(set([r['cipher_suite'] for r in tls13_successful if r['cipher_suite']]))
            }
        }
        
        # Calculer les améliorations
        if comparison['tls_12']['avg_handshake_time'] > 0 and comparison['tls_13']['avg_handshake_time'] > 0:
            handshake_improvement = ((comparison['tls_12']['avg_handshake_time'] - comparison['tls_13']['avg_handshake_time']) / comparison['tls_12']['avg_handshake_time']) * 100
        else:
            handshake_improvement = 0
        
        comparison['performance_improvement'] = {
            'handshake_time_reduction': round(handshake_improvement, 2),
            'tls_13_faster': handshake_improvement > 0
        }
        
        self.results['comparison'] = comparison
        
        # Analyse de sécurité
        self.security_analysis()
    
    def security_analysis(self):
        """Analyse de sécurité comparative"""
        security_analysis = {
            'tls_12_features': {
                'handshake_rounds': '2-RTT (Round Trip Time)',
                'key_exchange': 'RSA, DHE, ECDHE',
                'cipher_modes': 'CBC, GCM, CCM',
                'hash_algorithms': 'SHA-1, SHA-256, SHA-384',
                'vulnerabilities': [
                    'BEAST (CBC mode)',
                    'CRIME (compression)',
                    'BREACH (compression)',
                    'POODLE (CBC padding)',
                    'Lucky13 (CBC timing)'
                ],
                'deprecated_features': [
                    'RC4 cipher',
                    'MD5 hash',
                    'SHA-1 signatures',
                    'Static RSA key exchange'
                ]
            },
            'tls_13_features': {
                'handshake_rounds': '1-RTT (0-RTT possible)',
                'key_exchange': 'ECDHE, DHE (Perfect Forward Secrecy obligatoire)',
                'cipher_modes': 'AEAD uniquement (GCM, CCM, ChaCha20-Poly1305)',
                'hash_algorithms': 'SHA-256, SHA-384 minimum',
                'security_improvements': [
                    'Perfect Forward Secrecy obligatoire',
                    'Suppression des modes CBC vulnérables',
                    'Chiffrement de plus de métadonnées handshake',
                    'Résistance aux attaques de downgrade',
                    'Suppression de la compression',
                    'Algorithmes cryptographiques plus forts'
                ],
                'removed_vulnerabilities': [
                    'Attaques CBC (BEAST, POODLE, Lucky13)',
                    'Attaques de compression (CRIME, BREACH)',
                    'Attaques RSA statique',
                    'Attaques de renegotiation'
                ]
            },
            'key_differences': {
                'handshake_efficiency': 'TLS 1.3 réduit la latence avec 1-RTT vs 2-RTT',
                'forward_secrecy': 'TLS 1.3 impose PFS, TLS 1.2 optionnel',
                'cipher_security': 'TLS 1.3 utilise uniquement AEAD, élimine CBC',
                'metadata_protection': 'TLS 1.3 chiffre plus de métadonnées handshake',
                'algorithm_agility': 'TLS 1.3 simplifie et renforce les algorithmes'
            }
        }
        
        self.results['security_analysis'] = security_analysis
    
    def generate_detailed_report(self):
        """Génère un rapport détaillé de comparaison"""
        print("\n" + "="*80)
        print("RAPPORT DÉTAILLÉ: TLS 1.2 vs TLS 1.3")
        print("="*80)
        
        # Résultats de performance
        comp = self.results['comparison']
        
        print("\n📈 PERFORMANCE:")
        print(f"  TLS 1.2 - Taux de succès: {comp['tls_12']['success_rate']:.1f}%")
        print(f"  TLS 1.2 - Temps handshake moyen: {comp['tls_12']['avg_handshake_time']:.2f}ms")
        print(f"  TLS 1.3 - Taux de succès: {comp['tls_13']['success_rate']:.1f}%")
        print(f"  TLS 1.3 - Temps handshake moyen: {comp['tls_13']['avg_handshake_time']:.2f}ms")
        
        if comp['performance_improvement']['tls_13_faster']:
            print(f"  ✓ TLS 1.3 est {comp['performance_improvement']['handshake_time_reduction']:.1f}% plus rapide")
        else:
            print(f"  ⚠ TLS 1.2 semble plus rapide dans ce test")
        
        # Cipher suites
        print("\n🔐 CIPHER SUITES:")
        print("  TLS 1.2:")
        for cipher in comp['tls_12']['cipher_suites'][:5]:
            print(f"    • {cipher}")
        
        print("  TLS 1.3:")
        for cipher in comp['tls_13']['cipher_suites'][:5]:
            print(f"    • {cipher}")
        
        # Analyse de sécurité
        sec = self.results['security_analysis']
        
        print("\n🛡️ ANALYSE DE SÉCURITÉ:")
        
        print("\n  TLS 1.2 - Vulnérabilités connues:")
        for vuln in sec['tls_12_features']['vulnerabilities']:
            print(f"    ✗ {vuln}")
        
        print("\n  TLS 1.3 - Améliorations de sécurité:")
        for improvement in sec['tls_13_features']['security_improvements']:
            print(f"    ✓ {improvement}")
        
        print("\n  TLS 1.3 - Vulnérabilités supprimées:")
        for removed in sec['tls_13_features']['removed_vulnerabilities']:
            print(f"    ✓ {removed}")
        
        print("\n🔍 DIFFÉRENCES CLÉS:")
        for key, diff in sec['key_differences'].items():
            print(f"  • {key.replace('_', ' ').title()}: {diff}")
        
        # Recommandations
        print("\n💡 RECOMMANDATIONS:")
        print("  ✓ Migrer vers TLS 1.3 pour une sécurité et performance optimales")
        print("  ✓ Désactiver TLS 1.0 et TLS 1.1 (obsolètes)")
        print("  ✓ Configurer Perfect Forward Secrecy (PFS)")
        print("  ✓ Utiliser uniquement des cipher suites AEAD")
        print("  ✓ Implémenter HSTS (HTTP Strict Transport Security)")
        print("  ✓ Surveiller les nouvelles vulnérabilités TLS")
    
    def save_results(self, filename="tls_comparison_report.json"):
        """Sauvegarde les résultats en JSON"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"\n✓ Rapport sauvegardé: {filename}")
        except Exception as e:
            print(f"\n✗ Erreur sauvegarde: {e}")
    
    def create_wireshark_filter_guide(self):
        """Crée un guide des filtres Wireshark pour l'analyse TLS"""
        filters = {
            'basic_tls': 'tls',
            'tls_handshake': 'tls.handshake',
            'client_hello': 'tls.handshake.type == 1',
            'server_hello': 'tls.handshake.type == 2',
            'certificate': 'tls.handshake.type == 11',
            'server_key_exchange': 'tls.handshake.type == 12',
            'client_key_exchange': 'tls.handshake.type == 16',
            'finished': 'tls.handshake.type == 20',
            'tls_12_only': 'tls.record.version == 0x0303',
            'tls_13_only': 'tls.record.version == 0x0304',
            'cipher_suites': 'tls.handshake.ciphersuite',
            'certificates_x509': 'x509',
            'tls_alerts': 'tls.alert',
            'tls_errors': 'tls.alert.level == 2'
        }
        
        print("\n" + "="*60)
        print("GUIDE DES FILTRES WIRESHARK POUR ANALYSE TLS")
        print("="*60)
        
        for name, filter_expr in filters.items():
            print(f"  {name.replace('_', ' ').title():<25}: {filter_expr}")
        
        print("\n📋 ÉTAPES D'ANALYSE RECOMMANDÉES:")
        print("  1. Capturer avec: port 443")
        print("  2. Filtrer handshakes: tls.handshake")
        print("  3. Analyser Client Hello: tls.handshake.type == 1")
        print("  4. Vérifier versions: tls.record.version")
        print("  5. Examiner cipher suites: tls.handshake.ciphersuite")
        print("  6. Analyser certificats: x509")
        print("  7. Détecter erreurs: tls.alert.level == 2")

def main():
    print("=== COMPARAISON AVANCÉE TLS 1.2 vs TLS 1.3 ===")
    
    comparator = TLSComparator()
    
    # Exécuter les tests de comparaison
    comparator.run_comparison_tests()
    
    # Générer le rapport détaillé
    comparator.generate_detailed_report()
    
    # Créer le guide Wireshark
    comparator.create_wireshark_filter_guide()
    
    # Sauvegarder les résultats
    comparator.save_results()
    
    print("\n" + "="*80)
    print("✓ ANALYSE TLS TERMINÉE")
    print("\nFichiers générés:")
    print("  • tls_comparison_report.json (résultats détaillés)")
    print("\nPour une analyse plus poussée:")
    print("  • Utilisez Wireshark avec les filtres fournis")
    print("  • Capturez le trafic pendant l'exécution de ce script")
    print("  • Analysez les différences de handshake entre TLS 1.2 et 1.3")

if __name__ == "__main__":
    main()