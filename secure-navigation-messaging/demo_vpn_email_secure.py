#!/usr/bin/env python3
"""
Script de démonstration des modules VPN & Email sécurisés
Ghost Cyber Universe — Capstone v1

Ce script démontre toutes les fonctionnalités ajoutées :
- VPN avancé avec WireGuard
- Détection de fuites complète
- Obfuscation de trafic
- Multi-hop VPN
- Email sécurisé avec multi-providers
- Chiffrement de pièces jointes
- Backup chiffré
"""

import asyncio
import json
import os
import sys
from pathlib import Path
import time

# Ajout du chemin
sys.path.append(str(Path(__file__).parent))

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import print as rprint
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
except ImportError:
    print("⚠️  Rich non installé. Installez-le : pip install rich")
    print("Le script continuera sans Rich...\n")
    Console = None

console = Console() if Console else None


def print_section(title: str, emoji: str = "📋"):
    """Affiche une section"""
    if console:
        console.print(f"\n{emoji} [bold cyan]{title}[/bold cyan]")
        console.print("=" * 60)
    else:
        print(f"\n{emoji} {title}")
        print("=" * 60)


def print_success(message: str):
    """Affiche un message de succès"""
    if console:
        console.print(f"✅ [green]{message}[/green]")
    else:
        print(f"✅ {message}")


def print_info(message: str):
    """Affiche une info"""
    if console:
        console.print(f"ℹ️  [blue]{message}[/blue]")
    else:
        print(f"ℹ️  {message}")


def print_warning(message: str):
    """Affiche un avertissement"""
    if console:
        console.print(f"⚠️  [yellow]{message}[/yellow]")
    else:
        print(f"⚠️  {message}")


def print_error(message: str):
    """Affiche une erreur"""
    if console:
        console.print(f"❌ [red]{message}[/red]")
    else:
        print(f"❌ {message}")


async def demo_vpn_wireguard():
    """Démo VPN WireGuard"""
    print_section("Démonstration VPN WireGuard", "🔒")
    
    try:
        from secure_navigation.vpn_advanced import AdvancedVPNManager, WireGuardConfig
        
        print_info("Initialisation du gestionnaire VPN...")
        vpn = AdvancedVPNManager()
        
        # Génération de clés
        print_info("Génération de clés WireGuard (X25519)...")
        private_key, public_key = vpn.wireguard.generate_keypair()
        
        print_success(f"Clé publique générée : {public_key[:30]}...")
        print_success(f"Clé privée générée : {private_key[:30]}...")
        
        # Configuration
        print_info("Création de la configuration WireGuard...")
        config = WireGuardConfig(
            private_key=private_key,
            public_key=public_key,
            server_public_key="DEMO_SERVER_PUBLIC_KEY",
            server_endpoint="demo.vpn.example.com",
            server_port=51820,
            allowed_ips="0.0.0.0/0",
            dns_servers=["1.1.1.1", "1.0.0.1"],
            mtu=1420,
            persistent_keepalive=25
        )
        
        print_success("Configuration créée avec succès")
        print(f"  • Serveur: {config.server_endpoint}:{config.server_port}")
        print(f"  • DNS: {', '.join(config.dns_servers)}")
        print(f"  • MTU: {config.mtu}")
        
        return vpn
        
    except Exception as e:
        print_error(f"Erreur lors de la démo VPN: {e}")
        return None


async def demo_leak_detection():
    """Démo détection de fuites"""
    print_section("Détection de Fuites VPN", "🔍")
    
    try:
        from secure_navigation.vpn_advanced import LeakDetector
        
        print_info("Initialisation du détecteur de fuites...")
        detector = LeakDetector()
        
        # IP de test
        test_ip = "203.0.113.1"
        print_info(f"Test avec IP VPN simulée: {test_ip}")
        
        # Test complet
        print_info("Exécution des tests de fuites...")
        print("  • Test DNS...")
        await asyncio.sleep(0.5)
        print("  • Test IPv6...")
        await asyncio.sleep(0.5)
        print("  • Test WebRTC...")
        await asyncio.sleep(0.5)
        print("  • Test Timestamp...")
        await asyncio.sleep(0.5)
        
        result = await detector.perform_full_leak_test(test_ip)
        
        # Affichage des résultats
        print("\n📊 Résultats des tests:")
        print(f"  • Sévérité: {result.leak_severity.upper()}")
        
        tests = [
            ("DNS Leak", result.dns_leak),
            ("IPv6 Leak", result.ipv6_leak),
            ("WebRTC Leak", result.webrtc_leak),
            ("Timestamp Leak", result.timestamp_leak)
        ]
        
        for test_name, leaked in tests:
            status = "❌ FUITE" if leaked else "✅ OK"
            print(f"  • {test_name}: {status}")
        
        if result.leak_severity == "none":
            print_success("Aucune fuite détectée ! VPN sécurisé.")
        else:
            print_warning(f"Fuites détectées avec sévérité: {result.leak_severity}")
        
        return result
        
    except Exception as e:
        print_error(f"Erreur lors du test de fuites: {e}")
        return None


async def demo_vpn_metrics():
    """Démo métriques de performance"""
    print_section("Métriques de Performance VPN", "📊")
    
    try:
        from secure_navigation.vpn_advanced import AdvancedVPNManager
        
        print_info("Collecte des métriques de performance...")
        vpn = AdvancedVPNManager()
        
        # Collecte des métriques
        metrics = await vpn.collect_performance_metrics()
        
        # Affichage
        if console:
            table = Table(title="📈 Métriques VPN")
            table.add_column("Métrique", style="cyan")
            table.add_column("Valeur", style="green")
            
            table.add_row("Latence", f"{metrics.latency_ms:.2f} ms")
            table.add_row("Jitter", f"{metrics.jitter_ms:.2f} ms")
            table.add_row("Perte de paquets", f"{metrics.packet_loss_percent:.1f}%")
            table.add_row("Vitesse Download", f"{metrics.download_speed_mbps:.2f} Mbps")
            table.add_row("Vitesse Upload", f"{metrics.upload_speed_mbps:.2f} Mbps")
            table.add_row("Stabilité", f"{metrics.connection_stability:.1f}%")
            table.add_row("Overhead", f"{metrics.encryption_overhead_percent:.1f}%")
            
            console.print(table)
        else:
            print("\n📈 Métriques VPN:")
            print(f"  • Latence: {metrics.latency_ms:.2f} ms")
            print(f"  • Jitter: {metrics.jitter_ms:.2f} ms")
            print(f"  • Perte de paquets: {metrics.packet_loss_percent:.1f}%")
            print(f"  • Vitesse Download: {metrics.download_speed_mbps:.2f} Mbps")
            print(f"  • Vitesse Upload: {metrics.upload_speed_mbps:.2f} Mbps")
            print(f"  • Stabilité: {metrics.connection_stability:.1f}%")
            print(f"  • Overhead: {metrics.encryption_overhead_percent:.1f}%")
        
        return metrics
        
    except Exception as e:
        print_error(f"Erreur lors de la collecte de métriques: {e}")
        return None


async def demo_multihop_vpn():
    """Démo VPN multi-hop"""
    print_section("VPN Multi-Hop (Cascade)", "🔗")
    
    try:
        from secure_navigation.vpn_advanced import MultiHopVPN
        
        print_info("Initialisation du gestionnaire multi-hop...")
        multihop = MultiHopVPN()
        
        # Serveurs de démonstration
        servers = [
            "switzerland.vpn.example.com",
            "iceland.vpn.example.com",
            "netherlands.vpn.example.com"
        ]
        
        print_info(f"Création d'une chaîne avec {len(servers)} serveurs...")
        for i, server in enumerate(servers, 1):
            print(f"  {i}. {server}")
        
        # Création de la chaîne
        chain = await multihop.create_vpn_chain(
            servers=servers,
            protocol="wireguard",
            obfuscation=True
        )
        
        print_success(f"Chaîne créée avec ID: {chain.chain_id}")
        print(f"  • Protocole: {chain.protocol}")
        print(f"  • Obfuscation: {'✅' if chain.obfuscation_enabled else '❌'}")
        print(f"  • Nombre de sauts: {len(chain.servers)}")
        
        print_info("Simulation de connexion à la chaîne...")
        success = await multihop.connect_chain(chain)
        
        if success:
            print_success("Connexion multi-hop établie !")
            print_info("Anonymat renforcé : chaque saut ne connaît que le précédent/suivant")
        
        return chain
        
    except Exception as e:
        print_error(f"Erreur lors de la démo multi-hop: {e}")
        return None


async def demo_email_providers():
    """Démo providers email"""
    print_section("Providers Email Sécurisés", "📧")
    
    try:
        from secure_messaging.email_advanced import SecureEmailProviders
        
        print_info("Liste des providers email sécurisés...")
        
        providers = SecureEmailProviders.list_providers(min_privacy_rating=8)
        
        if console:
            table = Table(title="📧 Providers Sécurisés")
            table.add_column("Provider", style="cyan")
            table.add_column("Privacy", style="green")
            table.add_column("E2E", style="yellow")
            table.add_column("Description", style="white", width=40)
            
            for provider in providers:
                e2e = "✅" if provider.supports_e2e else "❌"
                rating = "⭐" * provider.privacy_rating
                
                table.add_row(
                    provider.name,
                    rating,
                    e2e,
                    provider.description[:40] + "..."
                )
            
            console.print(table)
        else:
            print("\n📧 Providers disponibles:")
            for provider in providers:
                e2e = "✅" if provider.supports_e2e else "❌"
                rating = "⭐" * provider.privacy_rating
                print(f"\n  • {provider.name}")
                print(f"    Privacy: {rating} ({provider.privacy_rating}/10)")
                print(f"    E2E: {e2e}")
                print(f"    {provider.description}")
        
        # Meilleur provider
        best = SecureEmailProviders.get_best_provider()
        print_success(f"\nMeilleur provider recommandé: {best.name} ({best.privacy_rating}/10)")
        
        return providers
        
    except Exception as e:
        print_error(f"Erreur lors de la démo providers: {e}")
        return None


async def demo_attachment_encryption():
    """Démo chiffrement de pièce jointe"""
    print_section("Chiffrement de Pièces Jointes", "🔐")
    
    try:
        from secure_messaging.email_advanced import AttachmentEncryptor
        
        print_info("Création d'un fichier de test...")
        test_file = Path("demo_document_secret.txt")
        test_content = "Ceci est un document ultra-confidentiel contenant des informations sensibles!"
        
        import aiofiles
        async with aiofiles.open(test_file, 'w') as f:
            await f.write(test_content)
        
        print_success(f"Fichier créé: {test_file.name} ({len(test_content)} bytes)")
        
        # Chiffrement
        print_info("Chiffrement avec AES-256-GCM + compression...")
        encryptor = AttachmentEncryptor()
        
        attachment = await encryptor.encrypt_file(test_file, compress=True)
        
        print_success("Chiffrement terminé !")
        print(f"  • Fichier: {attachment.filename}")
        print(f"  • Taille originale: {attachment.original_size} bytes")
        print(f"  • Taille chiffrée: {attachment.encrypted_size} bytes")
        print(f"  • Compression: {'✅' if attachment.compressed else '❌'}")
        print(f"  • Type MIME: {attachment.mime_type}")
        print(f"  • Checksum: {attachment.checksum[:32]}...")
        
        # Déchiffrement
        print_info("Test de déchiffrement...")
        encrypted_file = Path(f"{test_file}.encrypted")
        decrypted_file = Path("demo_document_decrypted.txt")
        
        success = await encryptor.decrypt_file(
            encrypted_file,
            attachment,
            decrypted_file
        )
        
        if success:
            print_success("Déchiffrement réussi !")
            
            # Vérification
            async with aiofiles.open(decrypted_file, 'r') as f:
                decrypted_content = await f.read()
            
            if decrypted_content == test_content:
                print_success("Intégrité vérifiée : contenu identique ✓")
            else:
                print_error("Erreur : contenu différent !")
        
        # Nettoyage
        print_info("Nettoyage des fichiers de test...")
        for f in [test_file, encrypted_file, decrypted_file]:
            if f.exists():
                os.remove(f)
        
        return attachment
        
    except Exception as e:
        print_error(f"Erreur lors du chiffrement: {e}")
        return None


async def demo_email_backup():
    """Démo backup email"""
    print_section("Backup Chiffré", "💾")
    
    try:
        from secure_messaging.email_advanced import BackupManager
        
        print_info("Initialisation du gestionnaire de backup...")
        backup_mgr = BackupManager("demo_backups")
        
        # Données de test
        test_data = {
            "user": "alice@protonmail.com",
            "emails_sent": 42,
            "contacts": ["bob@example.com", "charlie@example.com"],
            "settings": {
                "encryption": "AES-256-GCM",
                "auto_delete": True,
                "backup_frequency": "daily"
            }
        }
        
        print_info("Création d'un backup chiffré...")
        recovery_password = "demo_ultra_secure_password_123"
        
        bundle = await backup_mgr.create_backup(test_data, recovery_password)
        
        print_success("Backup créé !")
        print(f"  • Bundle ID: {bundle.bundle_id}")
        print(f"  • Date: {time.ctime(bundle.created_at)}")
        print(f"  • Hash clé: {bundle.recovery_key_hash[:32]}...")
        print(f"  • Version: {bundle.version}")
        
        # Test de restauration
        print_info("Test de restauration...")
        restored_data = await backup_mgr.restore_backup(
            bundle.bundle_id,
            recovery_password
        )
        
        if restored_data:
            print_success("Restauration réussie !")
            print(f"  • User: {restored_data['user']}")
            print(f"  • Emails: {restored_data['emails_sent']}")
            print(f"  • Contacts: {len(restored_data['contacts'])}")
        
        # Nettoyage
        print_info("Suppression du backup de test...")
        await backup_mgr.delete_backup(bundle.bundle_id)
        
        return bundle
        
    except Exception as e:
        print_error(f"Erreur lors du backup: {e}")
        return None


async def demo_full_workflow():
    """Démo complète du workflow"""
    print_section("Workflow Complet", "🎯")
    
    try:
        from secure_navigation.vpn_advanced import AdvancedVPNManager
        from secure_messaging.email_advanced import AdvancedEmailManager
        
        print_info("Scénario : Envoi d'un email confidentiel via VPN sécurisé")
        print()
        
        # Étape 1 : VPN
        print("📍 Étape 1 : Connexion VPN sécurisée")
        vpn = AdvancedVPNManager()
        private_key, public_key = vpn.wireguard.generate_keypair()
        print_success("VPN initialisé")
        
        # Étape 2 : Test de fuites
        print("\n📍 Étape 2 : Vérification des fuites")
        leak_result = await vpn.leak_detector.perform_full_leak_test("203.0.113.1")
        if leak_result.leak_severity == "none":
            print_success("Aucune fuite : connexion sécurisée")
        else:
            print_warning(f"Fuites détectées : {leak_result.leak_severity}")
        
        # Étape 3 : Email
        print("\n📍 Étape 3 : Préparation de l'email sécurisé")
        email_mgr = AdvancedEmailManager("protonmail")
        print_success("Email manager configuré avec ProtonMail")
        
        # Étape 4 : Statistiques
        print("\n📍 Étape 4 : Statistiques")
        stats = email_mgr.get_statistics()
        print(f"  • Provider: {stats['provider']}")
        print(f"  • Privacy Rating: {stats['privacy_rating']}/10")
        
        print_success("\n✅ Workflow complet démontré avec succès !")
        
    except Exception as e:
        print_error(f"Erreur lors du workflow: {e}")


async def main():
    """Fonction principale"""
    
    # Header
    if console:
        header = """
[bold cyan]╔═══════════════════════════════════════════════════════════╗
║  Ghost Cyber Universe — VPN & Email Sécurisés Demo       ║
║  Capstone v1 — Contribution 2025                          ║
╚═══════════════════════════════════════════════════════════╝[/bold cyan]
        """
        console.print(header)
    else:
        print("""
╔═══════════════════════════════════════════════════════════╗
║  Ghost Cyber Universe — VPN & Email Sécurisés Demo       ║
║  Capstone v1 — Contribution 2025                          ║
╚═══════════════════════════════════════════════════════════╝
        """)
    
    print_info("Démonstration de toutes les fonctionnalités ajoutées\n")
    
    try:
        # Menu
        demos = [
            ("VPN WireGuard", demo_vpn_wireguard),
            ("Détection de Fuites", demo_leak_detection),
            ("Métriques VPN", demo_vpn_metrics),
            ("Multi-Hop VPN", demo_multihop_vpn),
            ("Providers Email", demo_email_providers),
            ("Chiffrement de Pièces Jointes", demo_attachment_encryption),
            ("Backup Chiffré", demo_email_backup),
            ("Workflow Complet", demo_full_workflow)
        ]
        
        print("📋 Démonstrations disponibles:\n")
        for i, (name, _) in enumerate(demos, 1):
            print(f"  {i}. {name}")
        
        print("\n  0. Exécuter toutes les démos")
        print("  q. Quitter")
        
        choice = input("\n➤ Choisissez une option (0-8, q): ").strip()
        
        if choice.lower() == 'q':
            print_info("Fermeture de la démo...")
            return
        
        if choice == '0':
            # Toutes les démos
            for name, demo_func in demos:
                await demo_func()
                print()
        else:
            # Démo spécifique
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(demos):
                    name, demo_func = demos[idx]
                    await demo_func()
                else:
                    print_error("Choix invalide!")
            except ValueError:
                print_error("Entrée invalide!")
        
        # Footer
        print_section("Démo terminée", "✅")
        print_info("Pour plus d'informations, consultez:")
        print("  • docs/CONTRIBUTION_VPN_EMAIL.md")
        print("  • secure-navigation/README_VPN_EMAIL.md")
        print("  • CONTRIBUTION_SUMMARY.md")
        
    except KeyboardInterrupt:
        print_info("\n\nDémo interrompue par l'utilisateur")
    except Exception as e:
        print_error(f"Erreur inattendue: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())

