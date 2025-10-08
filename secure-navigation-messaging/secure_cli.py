#!/usr/bin/env python3
"""
Interface CLI unifiée pour la gestion VPN et Email sécurisés
Ghost Cyber Universe - Contribution
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

try:
    import click
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import print as rprint
except ImportError:
    print("❌ Dépendances manquantes. Installez: pip install click rich")
    sys.exit(1)

# Imports relatifs
sys.path.append(str(Path(__file__).parent.parent))
from secure_navigation.vpn_advanced import (
    AdvancedVPNManager, WireGuardConfig, LeakDetector
)
from secure_messaging.email_advanced import (
    AdvancedEmailManager, SecureEmailProviders
)

console = Console()


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """
    🔐 Ghost Cyber Universe - Gestionnaire VPN & Email Sécurisé
    
    Interface CLI pour la gestion avancée de VPN et email sécurisés.
    """
    pass


# ============= Commandes VPN =============

@cli.group()
def vpn():
    """🔒 Gestion du VPN sécurisé"""
    pass


@vpn.command()
@click.option('--protocol', type=click.Choice(['wireguard', 'openvpn']), 
              default='wireguard', help='Protocole VPN')
@click.option('--server', help='Serveur VPN cible')
@click.option('--obfuscation/--no-obfuscation', default=False,
              help='Activer l\'obfuscation du trafic')
def connect(protocol, server, obfuscation):
    """Connexion au VPN"""
    asyncio.run(_vpn_connect(protocol, server, obfuscation))


async def _vpn_connect(protocol: str, server: Optional[str], obfuscation: bool):
    """Logique de connexion VPN"""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("🔌 Connexion au VPN...", total=None)
        
        try:
            vpn_manager = AdvancedVPNManager()
            
            if protocol == "wireguard":
                # Génération de configuration WireGuard
                progress.update(task, description="🔑 Génération des clés WireGuard...")
                private_key, public_key = vpn_manager.wireguard.generate_keypair()
                
                # Configuration exemple
                config = WireGuardConfig(
                    private_key=private_key,
                    public_key=public_key,
                    server_public_key="SERVER_PUBLIC_KEY_HERE",
                    server_endpoint=server or "vpn.example.com",
                    server_port=51820,
                    allowed_ips="0.0.0.0/0",
                    dns_servers=["1.1.1.1", "1.0.0.1"]
                )
                
                progress.update(task, description="🌐 Connexion WireGuard...")
                success = await vpn_manager.connect_wireguard(config)
            else:
                console.print("⚠️  OpenVPN non encore implémenté dans cette démo", style="yellow")
                return
            
            if success:
                console.print("\n✅ [green bold]VPN connecté avec succès![/green bold]")
                
                if obfuscation:
                    progress.update(task, description="🎭 Activation de l'obfuscation...")
                    await vpn_manager.enable_stealth_mode()
                    console.print("✅ [green]Obfuscation activée[/green]")
                
                # Affichage du statut
                status = vpn_manager.get_status_report()
                _display_vpn_status(status)
            else:
                console.print("❌ [red]Échec de la connexion VPN[/red]")
                
        except Exception as e:
            console.print(f"❌ [red]Erreur: {e}[/red]")


@vpn.command()
def status():
    """Affiche le statut du VPN"""
    asyncio.run(_vpn_status())


async def _vpn_status():
    """Affiche le statut détaillé du VPN"""
    try:
        vpn_manager = AdvancedVPNManager()
        
        # Test de connexion
        current_ip = await vpn_manager._get_current_ip()
        
        # Collecte des métriques
        with console.status("[bold green]Collecte des métriques..."):
            metrics = await vpn_manager.collect_performance_metrics()
        
        # Affichage
        table = Table(title="📊 État du VPN", show_header=True)
        table.add_column("Métrique", style="cyan")
        table.add_column("Valeur", style="green")
        
        table.add_row("IP Publique", current_ip or "Non connecté")
        table.add_row("Protocole", vpn_manager.current_protocol or "Aucun")
        table.add_row("Latence", f"{metrics.latency_ms:.2f} ms")
        table.add_row("Jitter", f"{metrics.jitter_ms:.2f} ms")
        table.add_row("Perte de paquets", f"{metrics.packet_loss_percent:.1f}%")
        table.add_row("Vitesse Download", f"{metrics.download_speed_mbps:.2f} Mbps")
        table.add_row("Vitesse Upload", f"{metrics.upload_speed_mbps:.2f} Mbps")
        table.add_row("Stabilité", f"{metrics.connection_stability:.1f}%")
        table.add_row("Overhead", f"{metrics.encryption_overhead_percent:.1f}%")
        
        console.print(table)
        
    except Exception as e:
        console.print(f"❌ [red]Erreur: {e}[/red]")


@vpn.command()
def leak_test():
    """Effectue un test de fuites complet"""
    asyncio.run(_vpn_leak_test())


async def _vpn_leak_test():
    """Test de fuites VPN"""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("🔍 Test de fuites en cours...", total=None)
        
        try:
            detector = LeakDetector()
            
            # Récupération de l'IP VPN
            vpn_manager = AdvancedVPNManager()
            vpn_ip = await vpn_manager._get_current_ip()
            
            progress.update(task, description="🔍 Test DNS...")
            await asyncio.sleep(1)
            
            progress.update(task, description="🔍 Test IPv6...")
            await asyncio.sleep(1)
            
            progress.update(task, description="🔍 Test WebRTC...")
            await asyncio.sleep(1)
            
            # Test complet
            result = await detector.perform_full_leak_test(vpn_ip)
            
            # Affichage des résultats
            console.print("\n" + "="*50)
            console.print("[bold]🔍 Résultats du test de fuites[/bold]")
            console.print("="*50 + "\n")
            
            severity_colors = {
                "none": "green",
                "low": "yellow",
                "medium": "orange1",
                "high": "red",
                "critical": "red bold"
            }
            
            color = severity_colors.get(result.leak_severity, "white")
            console.print(f"Sévérité: [{color}]{result.leak_severity.upper()}[/{color}]\n")
            
            # Détails des fuites
            tests = [
                ("DNS Leak", result.dns_leak, result.dns_servers_detected),
                ("IPv6 Leak", result.ipv6_leak, result.ipv6_addresses_detected),
                ("WebRTC Leak", result.webrtc_leak, [result.real_ip_detected] if result.real_ip_detected else []),
                ("Timestamp Leak", result.timestamp_leak, [])
            ]
            
            for test_name, leaked, details in tests:
                status = "❌ FUITE DÉTECTÉE" if leaked else "✅ Sécurisé"
                style = "red" if leaked else "green"
                console.print(f"{test_name}: [{style}]{status}[/{style}]")
                
                if leaked and details:
                    for detail in details[:3]:  # Max 3 détails
                        console.print(f"  └─ {detail}", style="dim")
            
            console.print("\n" + "="*50)
            
        except Exception as e:
            console.print(f"❌ [red]Erreur: {e}[/red]")


@vpn.command()
@click.argument('servers', nargs=-1, required=True)
def multihop(servers):
    """Connexion VPN multi-hop (cascade)"""
    asyncio.run(_vpn_multihop(list(servers)))


async def _vpn_multihop(servers: list):
    """Connexion multi-hop"""
    if len(servers) < 2:
        console.print("❌ [red]Minimum 2 serveurs requis pour multi-hop[/red]")
        return
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("🔗 Configuration multi-hop...", total=None)
        
        try:
            vpn_manager = AdvancedVPNManager()
            
            # Création de la chaîne
            progress.update(task, description="🔗 Création de la chaîne VPN...")
            chain = await vpn_manager.create_and_connect_multihop(servers)
            
            if chain:
                console.print("\n✅ [green bold]Chaîne VPN multi-hop établie![/green bold]")
                console.print(f"\n📋 Chain ID: [cyan]{chain.chain_id}[/cyan]")
                console.print(f"🔗 Nombre de sauts: [yellow]{len(chain.servers)}[/yellow]")
                console.print(f"🛡️  Protocole: [blue]{chain.protocol}[/blue]")
                console.print(f"🎭 Obfuscation: [magenta]{'✅ Activée' if chain.obfuscation_enabled else '❌ Désactivée'}[/magenta]")
                
                # Liste des serveurs
                console.print("\n[bold]Serveurs dans la chaîne:[/bold]")
                for i, server in enumerate(chain.servers, 1):
                    console.print(f"  {i}. {server}")
            else:
                console.print("❌ [red]Échec de la création de la chaîne[/red]")
                
        except Exception as e:
            console.print(f"❌ [red]Erreur: {e}[/red]")


# ============= Commandes Email =============

@cli.group()
def email():
    """📧 Gestion de l'email sécurisé"""
    pass


@email.command()
def providers():
    """Liste les providers email sécurisés"""
    try:
        providers_list = AdvancedEmailManager.list_available_providers(min_rating=8)
        
        table = Table(title="📧 Providers Email Sécurisés", show_header=True)
        table.add_column("Provider", style="cyan", width=15)
        table.add_column("Privacy", justify="center", style="green", width=10)
        table.add_column("E2E", justify="center", style="yellow", width=8)
        table.add_column("Description", style="white", width=50)
        
        for provider in providers_list:
            e2e_icon = "✅" if provider['supports_e2e'] else "❌"
            privacy_bar = "⭐" * provider['privacy_rating']
            
            table.add_row(
                provider['name'],
                privacy_bar,
                e2e_icon,
                provider['description']
            )
        
        console.print(table)
        
    except Exception as e:
        console.print(f"❌ [red]Erreur: {e}[/red]")


@email.command()
@click.option('--provider', default='protonmail', 
              help='Provider email (protonmail, tutanota, mailfence, etc.)')
@click.option('--username', prompt=True, help='Adresse email')
@click.option('--password', prompt=True, hide_input=True, help='Mot de passe')
@click.option('--to', multiple=True, required=True, help='Destinataires')
@click.option('--subject', prompt=True, help='Sujet')
@click.option('--body', prompt=True, help='Corps du message')
@click.option('--attach', multiple=True, type=click.Path(exists=True),
              help='Pièces jointes à chiffrer')
def send(provider, username, password, to, subject, body, attach):
    """Envoie un email sécurisé avec pièces jointes chiffrées"""
    asyncio.run(_email_send(provider, username, password, to, subject, body, attach))


async def _email_send(provider, username, password, to, subject, body, attachments):
    """Logique d'envoi d'email"""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("📧 Préparation de l'email...", total=None)
        
        try:
            # Initialisation
            email_mgr = AdvancedEmailManager(provider)
            email_mgr.configure_credentials(username, password)
            
            # Conversion des pièces jointes
            attachment_paths = [Path(a) for a in attachments] if attachments else None
            
            if attachment_paths:
                progress.update(task, description=f"🔐 Chiffrement de {len(attachment_paths)} pièce(s) jointe(s)...")
                await asyncio.sleep(1)
            
            progress.update(task, description="📨 Envoi de l'email...")
            
            # Envoi
            success = await email_mgr.send_secure_email(
                to_addresses=list(to),
                subject=subject,
                body=body,
                attachments=attachment_paths,
                compress_attachments=True
            )
            
            if success:
                console.print("\n✅ [green bold]Email envoyé avec succès![/green bold]")
                
                # Statistiques
                stats = email_mgr.get_statistics()
                console.print(f"\n📊 [cyan]Statistiques:[/cyan]")
                console.print(f"  • Emails envoyés: {stats['emails_sent']}")
                console.print(f"  • Pièces jointes chiffrées: {stats['attachments_encrypted']}")
                console.print(f"  • Données chiffrées: {stats['total_data_encrypted_mb']:.2f} MB")
            else:
                console.print("❌ [red]Échec de l'envoi[/red]")
                
        except Exception as e:
            console.print(f"❌ [red]Erreur: {e}[/red]")


@email.command()
@click.option('--provider', default='protonmail', help='Provider email')
@click.option('--username', prompt=True, help='Adresse email')
@click.option('--password', prompt=True, hide_input=True, help='Mot de passe')
@click.option('--recovery-password', prompt=True, hide_input=True, 
              help='Mot de passe de récupération pour le backup')
def backup(provider, username, password, recovery_password):
    """Crée une sauvegarde chiffrée"""
    asyncio.run(_email_backup(provider, username, password, recovery_password))


async def _email_backup(provider, username, password, recovery_password):
    """Création de backup"""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("💾 Création de la sauvegarde...", total=None)
        
        try:
            email_mgr = AdvancedEmailManager(provider)
            email_mgr.configure_credentials(username, password)
            
            progress.update(task, description="🔐 Chiffrement des données...")
            bundle = await email_mgr.create_encrypted_backup(recovery_password)
            
            if bundle:
                console.print("\n✅ [green bold]Sauvegarde créée avec succès![/green bold]")
                console.print(f"\n📋 Bundle ID: [cyan]{bundle.bundle_id}[/cyan]")
                console.print(f"📅 Date: [yellow]{bundle.created_at}[/yellow]")
                console.print(f"🔑 Hash clé récup: [dim]{bundle.recovery_key_hash[:16]}...[/dim]")
                
                console.print("\n⚠️  [yellow]Conservez précieusement votre mot de passe de récupération ![/yellow]")
            else:
                console.print("❌ [red]Échec de la création de la sauvegarde[/red]")
                
        except Exception as e:
            console.print(f"❌ [red]Erreur: {e}[/red]")


# ============= Commandes Générales =============

@cli.command()
def info():
    """Affiche les informations système"""
    
    panel_content = """
[bold cyan]Ghost Cyber Universe - Sécurité Avancée[/bold cyan]

[yellow]Modules disponibles:[/yellow]
  🔒 VPN Avancé
     • WireGuard natif
     • Multi-hop (cascade)
     • Détection de fuites (DNS, IPv6, WebRTC)
     • Obfuscation du trafic
     • Métriques de performance

  📧 Email Sécurisé
     • Support multi-providers (ProtonMail, Tutanota, etc.)
     • Chiffrement E2E avec Signal Protocol
     • Pièces jointes chiffrées avec compression
     • Protection des métadonnées
     • Sauvegarde chiffrée

[green]Contribution à Ghost Cyber Universe v1[/green]
[dim]Développé avec Python, cryptographie avancée et amour de la vie privée ❤️[/dim]
    """
    
    console.print(Panel(panel_content, title="ℹ️  Information", border_style="blue"))


def _display_vpn_status(status: dict):
    """Affiche le statut VPN formaté"""
    table = Table(show_header=False, box=None)
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Protocole", status.get("protocol", "N/A"))
    table.add_row("WireGuard", "✅ Connecté" if status.get("wireguard_connected") else "❌ Déconnecté")
    table.add_row("Chaînes multi-hop", str(status.get("active_multihop_chains", 0)))
    
    console.print("\n")
    console.print(table)


if __name__ == "__main__":
    cli()

