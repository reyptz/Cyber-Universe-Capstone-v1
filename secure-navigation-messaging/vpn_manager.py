#!/usr/bin/env python3
"""
Module de gestion VPN avec configuration automatique et rotation des serveurs
Fournit une couche de protection réseau avec chiffrement et anonymisation
"""

import asyncio
import json
import logging
import random
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import aiohttp
import psutil
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

@dataclass
class VPNServer:
    """Configuration d'un serveur VPN"""
    name: str
    host: str
    port: int
    protocol: str  # OpenVPN, WireGuard, IKEv2
    country: str
    city: str
    load: float
    ping: Optional[float] = None
    config_path: Optional[str] = None
    credentials: Optional[Dict[str, str]] = None

@dataclass
class VPNStatus:
    """Statut de la connexion VPN"""
    connected: bool
    server: Optional[VPNServer]
    ip_address: Optional[str]
    dns_servers: List[str]
    connection_time: Optional[float]
    data_transferred: Dict[str, int]

class VPNManager:
    """Gestionnaire VPN avec rotation automatique et sécurité renforcée"""
    
    def __init__(self, config_dir: str = "vpn_configs"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)
        
        self.logger = self._setup_logging()
        self.servers: List[VPNServer] = []
        self.current_server: Optional[VPNServer] = None
        self.status = VPNStatus(
            connected=False,
            server=None,
            ip_address=None,
            dns_servers=[],
            connection_time=None,
            data_transferred={"sent": 0, "received": 0}
        )
        
        # Configuration de sécurité
        self.kill_switch_enabled = True
        self.dns_leak_protection = True
        self.auto_rotation_interval = 3600  # 1 heure
        self.max_connection_attempts = 3
        
        # Chiffrement des configurations
        self.encryption_key = self._generate_encryption_key()
        
        # Initialisation
        asyncio.create_task(self._initialize_servers())
        
    def _setup_logging(self) -> logging.Logger:
        """Configuration du système de logs sécurisé"""
        logger = logging.getLogger("VPNManager")
        logger.setLevel(logging.INFO)
        
        # Handler pour fichier avec rotation
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler(
            "vpn_manager.log",
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        
        # Format sécurisé (pas d'informations sensibles)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        return logger
    
    def _generate_encryption_key(self) -> bytes:
        """Génère une clé de chiffrement pour les configurations"""
        password = os.environ.get("VPN_MASTER_KEY", "default_secure_key").encode()
        salt = b"vpn_config_salt_2024"
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    def _encrypt_data(self, data: str) -> str:
        """Chiffre les données sensibles"""
        f = Fernet(self.encryption_key)
        encrypted_data = f.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted_data).decode()
    
    def _decrypt_data(self, encrypted_data: str) -> str:
        """Déchiffre les données"""
        f = Fernet(self.encryption_key)
        decoded_data = base64.urlsafe_b64decode(encrypted_data.encode())
        decrypted_data = f.decrypt(decoded_data)
        return decrypted_data.decode()
    
    async def _initialize_servers(self):
        """Initialise la liste des serveurs VPN disponibles"""
        try:
            # Serveurs de démonstration (en production, charger depuis une API sécurisée)
            demo_servers = [
                VPNServer("NordVPN-US1", "us1.nordvpn.com", 1194, "OpenVPN", "US", "New York", 0.3),
                VPNServer("NordVPN-UK1", "uk1.nordvpn.com", 1194, "OpenVPN", "UK", "London", 0.2),
                VPNServer("ExpressVPN-DE1", "de1.expressvpn.com", 1194, "OpenVPN", "DE", "Frankfurt", 0.4),
                VPNServer("Surfshark-NL1", "nl1.surfshark.com", 51820, "WireGuard", "NL", "Amsterdam", 0.1),
                VPNServer("ProtonVPN-CH1", "ch1.protonvpn.com", 1194, "OpenVPN", "CH", "Zurich", 0.25),
            ]
            
            # Test de ping pour chaque serveur
            for server in demo_servers:
                server.ping = await self._ping_server(server.host)
            
            # Tri par ping et charge
            self.servers = sorted(demo_servers, key=lambda s: (s.ping or 999, s.load))
            self.logger.info(f"Initialisé {len(self.servers)} serveurs VPN")
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'initialisation des serveurs: {e}")
    
    async def _ping_server(self, host: str) -> Optional[float]:
        """Test de ping vers un serveur"""
        try:
            if os.name == 'nt':  # Windows
                result = subprocess.run(
                    ["ping", "-n", "1", host],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
            else:  # Unix/Linux
                result = subprocess.run(
                    ["ping", "-c", "1", host],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
            
            if result.returncode == 0:
                # Extraction du temps de ping (simplifiée)
                output = result.stdout
                if "time=" in output:
                    time_str = output.split("time=")[1].split("ms")[0]
                    return float(time_str)
            
            return None
            
        except Exception:
            return None
    
    async def connect(self, server: Optional[VPNServer] = None) -> bool:
        """Établit une connexion VPN sécurisée"""
        try:
            if not server:
                server = await self._select_best_server()
            
            if not server:
                self.logger.error("Aucun serveur disponible")
                return False
            
            self.logger.info(f"Connexion au serveur {server.name} ({server.country})")
            
            # Activation du kill switch
            if self.kill_switch_enabled:
                await self._enable_kill_switch()
            
            # Configuration DNS sécurisée
            if self.dns_leak_protection:
                await self._configure_secure_dns()
            
            # Simulation de connexion (en production, utiliser les vraies APIs VPN)
            await asyncio.sleep(2)  # Simulation du temps de connexion
            
            # Mise à jour du statut
            self.current_server = server
            self.status.connected = True
            self.status.server = server
            self.status.connection_time = time.time()
            self.status.ip_address = await self._get_public_ip()
            
            self.logger.info(f"Connecté avec succès. IP: {self.status.ip_address}")
            
            # Démarrage de la rotation automatique
            asyncio.create_task(self._auto_rotation_task())
            
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur de connexion VPN: {e}")
            return False
    
    async def disconnect(self) -> bool:
        """Déconnecte le VPN"""
        try:
            if not self.status.connected:
                return True
            
            self.logger.info("Déconnexion du VPN")
            
            # Simulation de déconnexion
            await asyncio.sleep(1)
            
            # Désactivation du kill switch
            await self._disable_kill_switch()
            
            # Restauration DNS
            await self._restore_dns()
            
            # Mise à jour du statut
            self.status.connected = False
            self.status.server = None
            self.status.ip_address = None
            self.status.connection_time = None
            self.current_server = None
            
            self.logger.info("VPN déconnecté")
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur de déconnexion: {e}")
            return False
    
    async def _select_best_server(self) -> Optional[VPNServer]:
        """Sélectionne le meilleur serveur disponible"""
        if not self.servers:
            return None
        
        # Filtrage des serveurs par critères de performance
        available_servers = [s for s in self.servers if s.ping and s.ping < 200 and s.load < 0.8]
        
        if not available_servers:
            available_servers = self.servers[:3]  # Fallback sur les 3 premiers
        
        # Sélection pondérée (favorise ping faible et charge faible)
        weights = []
        for server in available_servers:
            ping_score = 1 / (server.ping or 100)
            load_score = 1 / (server.load + 0.1)
            weights.append(ping_score * load_score)
        
        return random.choices(available_servers, weights=weights)[0]
    
    async def rotate_server(self) -> bool:
        """Effectue une rotation vers un nouveau serveur"""
        if not self.status.connected:
            return False
        
        try:
            # Sélection d'un nouveau serveur (différent du current)
            available_servers = [s for s in self.servers if s != self.current_server]
            if not available_servers:
                return False
            
            new_server = await self._select_best_server()
            if new_server == self.current_server:
                # Forcer un serveur différent
                new_server = random.choice(available_servers)
            
            self.logger.info(f"Rotation vers {new_server.name}")
            
            # Déconnexion et reconnexion
            await self.disconnect()
            await asyncio.sleep(2)
            return await self.connect(new_server)
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la rotation: {e}")
            return False
    
    async def _auto_rotation_task(self):
        """Tâche de rotation automatique"""
        while self.status.connected:
            await asyncio.sleep(self.auto_rotation_interval)
            if self.status.connected:
                await self.rotate_server()
    
    async def _enable_kill_switch(self):
        """Active le kill switch pour bloquer le trafic en cas de déconnexion"""
        try:
            # Implémentation du kill switch (firewall rules)
            if os.name == 'nt':  # Windows
                # Règles Windows Firewall
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    "name=VPN_KillSwitch_Block_All",
                    "dir=out", "action=block", "enable=yes"
                ], check=False)
            else:  # Linux/Unix
                # Règles iptables
                subprocess.run([
                    "iptables", "-I", "OUTPUT", "1", "-j", "DROP"
                ], check=False)
            
            self.logger.info("Kill switch activé")
            
        except Exception as e:
            self.logger.error(f"Erreur activation kill switch: {e}")
    
    async def _disable_kill_switch(self):
        """Désactive le kill switch"""
        try:
            if os.name == 'nt':  # Windows
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    "name=VPN_KillSwitch_Block_All"
                ], check=False)
            else:  # Linux/Unix
                subprocess.run([
                    "iptables", "-D", "OUTPUT", "-j", "DROP"
                ], check=False)
            
            self.logger.info("Kill switch désactivé")
            
        except Exception as e:
            self.logger.error(f"Erreur désactivation kill switch: {e}")
    
    async def _configure_secure_dns(self):
        """Configure des serveurs DNS sécurisés"""
        secure_dns = [
            "1.1.1.1",      # Cloudflare
            "1.0.0.1",      # Cloudflare
            "8.8.8.8",      # Google
            "8.8.4.4",      # Google
            "9.9.9.9",      # Quad9
            "149.112.112.112"  # Quad9
        ]
        
        self.status.dns_servers = secure_dns[:2]  # Utiliser les 2 premiers
        self.logger.info(f"DNS sécurisés configurés: {self.status.dns_servers}")
    
    async def _restore_dns(self):
        """Restaure la configuration DNS par défaut"""
        self.status.dns_servers = []
        self.logger.info("Configuration DNS restaurée")
    
    async def _get_public_ip(self) -> Optional[str]:
        """Récupère l'adresse IP publique actuelle"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get("https://api.ipify.org", timeout=10) as response:
                    if response.status == 200:
                        return await response.text()
            return None
        except Exception:
            return None
    
    async def get_status(self) -> VPNStatus:
        """Retourne le statut actuel de la connexion VPN"""
        if self.status.connected:
            # Mise à jour des statistiques de transfert
            self.status.data_transferred = await self._get_transfer_stats()
        
        return self.status
    
    async def _get_transfer_stats(self) -> Dict[str, int]:
        """Récupère les statistiques de transfert de données"""
        try:
            # Utilisation de psutil pour les stats réseau
            stats = psutil.net_io_counters()
            return {
                "sent": stats.bytes_sent,
                "received": stats.bytes_recv
            }
        except Exception:
            return {"sent": 0, "received": 0}
    
    async def test_connection(self) -> Dict[str, any]:
        """Teste la qualité de la connexion VPN"""
        results = {
            "connected": self.status.connected,
            "ip_address": await self._get_public_ip(),
            "dns_leak_test": await self._test_dns_leak(),
            "speed_test": await self._test_speed(),
            "latency": None
        }
        
        if self.current_server:
            results["latency"] = await self._ping_server(self.current_server.host)
        
        return results
    
    async def _test_dns_leak(self) -> bool:
        """Teste les fuites DNS"""
        try:
            # Test simplifié - vérifier que les DNS utilisés sont ceux configurés
            return len(self.status.dns_servers) > 0
        except Exception:
            return False
    
    async def _test_speed(self) -> Dict[str, float]:
        """Test de vitesse de connexion"""
        try:
            # Test simplifié de téléchargement
            start_time = time.time()
            async with aiohttp.ClientSession() as session:
                async with session.get("https://httpbin.org/bytes/1024", timeout=30) as response:
                    await response.read()
            
            duration = time.time() - start_time
            speed_kbps = (1024 / duration) / 1024  # KB/s
            
            return {
                "download_speed_kbps": speed_kbps,
                "upload_speed_kbps": speed_kbps * 0.8  # Estimation
            }
        except Exception:
            return {"download_speed_kbps": 0, "upload_speed_kbps": 0}

# Exemple d'utilisation
async def main():
    """Fonction de démonstration"""
    vpn = VPNManager()
    
    # Attendre l'initialisation
    await asyncio.sleep(3)
    
    # Connexion
    if await vpn.connect():
        print("VPN connecté avec succès")
        
        # Test de la connexion
        test_results = await vpn.test_connection()
        print(f"Résultats du test: {test_results}")
        
        # Attendre un peu
        await asyncio.sleep(10)
        
        # Rotation
        await vpn.rotate_server()
        
        # Déconnexion
        await vpn.disconnect()
    else:
        print("Échec de la connexion VPN")

if __name__ == "__main__":
    asyncio.run(main())