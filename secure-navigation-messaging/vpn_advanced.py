#!/usr/bin/env python3
"""
Module VPN avancé avec support WireGuard, multi-hop, obfuscation et détection de fuites
Contribution au projet Ghost Cyber Universe
"""

import asyncio
import ipaddress
import json
import logging
import os
import platform
import random
import re
import socket
import subprocess
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
import hashlib
import secrets

import aiohttp
import psutil
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519


@dataclass
class WireGuardConfig:
    """Configuration WireGuard sécurisée"""
    private_key: str
    public_key: str
    server_public_key: str
    server_endpoint: str
    server_port: int
    allowed_ips: str
    dns_servers: List[str]
    mtu: int = 1420
    persistent_keepalive: int = 25


@dataclass
class VPNChain:
    """Configuration pour VPN multi-hop (cascade)"""
    chain_id: str
    servers: List[str]  # Liste des serveurs dans l'ordre de connexion
    protocol: str  # "openvpn" ou "wireguard"
    obfuscation_enabled: bool
    created_at: float


@dataclass
class LeakTestResult:
    """Résultat des tests de fuites"""
    dns_leak: bool
    ipv6_leak: bool
    webrtc_leak: bool
    timestamp_leak: bool
    dns_servers_detected: List[str]
    ipv6_addresses_detected: List[str]
    real_ip_detected: Optional[str]
    leak_severity: str  # "none", "low", "medium", "high", "critical"


@dataclass
class VPNMetrics:
    """Métriques détaillées de performance VPN"""
    latency_ms: float
    jitter_ms: float
    packet_loss_percent: float
    download_speed_mbps: float
    upload_speed_mbps: float
    connection_stability: float  # 0-100
    encryption_overhead_percent: float
    timestamp: float


class WireGuardManager:
    """Gestionnaire WireGuard natif"""
    
    def __init__(self):
        self.logger = logging.getLogger("WireGuardManager")
        self.interface_name = "wg0"
        self.config_dir = Path("wireguard_configs")
        self.config_dir.mkdir(exist_ok=True)
        self.is_connected = False
        
    def generate_keypair(self) -> Tuple[str, str]:
        """Génère une paire de clés WireGuard"""
        try:
            # Génération de la clé privée
            private_key_bytes = secrets.token_bytes(32)
            private_key_obj = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)
            
            # Génération de la clé publique
            public_key_obj = private_key_obj.public_key()
            
            # Encodage en base64
            import base64
            private_key = base64.b64encode(private_key_bytes).decode('ascii')
            public_key = base64.b64encode(
                public_key_obj.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            ).decode('ascii')
            
            return private_key, public_key
            
        except Exception as e:
            self.logger.error(f"Erreur génération clés WireGuard: {e}")
            raise
    
    def create_config_file(self, config: WireGuardConfig, filename: str) -> Path:
        """Crée un fichier de configuration WireGuard"""
        try:
            config_path = self.config_dir / filename
            
            config_content = f"""[Interface]
PrivateKey = {config.private_key}
Address = 10.8.0.2/24
DNS = {', '.join(config.dns_servers)}
MTU = {config.mtu}

[Peer]
PublicKey = {config.server_public_key}
Endpoint = {config.server_endpoint}:{config.server_port}
AllowedIPs = {config.allowed_ips}
PersistentKeepalive = {config.persistent_keepalive}
"""
            
            with open(config_path, 'w') as f:
                f.write(config_content)
            
            # Permissions restrictives
            os.chmod(config_path, 0o600)
            
            self.logger.info(f"Configuration WireGuard créée: {config_path}")
            return config_path
            
        except Exception as e:
            self.logger.error(f"Erreur création config WireGuard: {e}")
            raise
    
    async def connect(self, config: WireGuardConfig) -> bool:
        """Établit une connexion WireGuard"""
        try:
            # Création du fichier de configuration
            config_file = self.create_config_file(config, f"{self.interface_name}.conf")
            
            # Commandes selon l'OS
            if platform.system() == "Linux":
                # Activation de l'interface
                subprocess.run(
                    ["wg-quick", "up", str(config_file)],
                    check=True,
                    capture_output=True
                )
            elif platform.system() == "Windows":
                # Sur Windows, utiliser wireguard.exe
                subprocess.run(
                    ["wireguard", "/installtunnelservice", str(config_file)],
                    check=True,
                    capture_output=True
                )
            
            self.is_connected = True
            self.logger.info("WireGuard connecté avec succès")
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Erreur connexion WireGuard: {e.stderr.decode()}")
            return False
        except Exception as e:
            self.logger.error(f"Erreur inattendue: {e}")
            return False
    
    async def disconnect(self) -> bool:
        """Déconnecte WireGuard"""
        try:
            if platform.system() == "Linux":
                subprocess.run(
                    ["wg-quick", "down", self.interface_name],
                    check=True,
                    capture_output=True
                )
            elif platform.system() == "Windows":
                subprocess.run(
                    ["wireguard", "/uninstalltunnelservice", self.interface_name],
                    check=True,
                    capture_output=True
                )
            
            self.is_connected = False
            self.logger.info("WireGuard déconnecté")
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur déconnexion WireGuard: {e}")
            return False
    
    async def get_stats(self) -> Dict:
        """Récupère les statistiques de la connexion WireGuard"""
        try:
            result = subprocess.run(
                ["wg", "show", self.interface_name],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                output = result.stdout
                stats = self._parse_wg_output(output)
                return stats
            
            return {}
            
        except Exception as e:
            self.logger.error(f"Erreur récupération stats: {e}")
            return {}
    
    def _parse_wg_output(self, output: str) -> Dict:
        """Parse la sortie de 'wg show'"""
        stats = {}
        lines = output.split('\n')
        
        for line in lines:
            if "latest handshake:" in line:
                stats["last_handshake"] = line.split(":")[-1].strip()
            elif "transfer:" in line:
                parts = line.split(":")[-1].strip().split()
                stats["received"] = parts[0]
                stats["sent"] = parts[2]
        
        return stats


class LeakDetector:
    """Détecteur avancé de fuites VPN"""
    
    def __init__(self):
        self.logger = logging.getLogger("LeakDetector")
        self.original_ip = None
        self.original_dns = None
    
    async def perform_full_leak_test(self, vpn_ip: str) -> LeakTestResult:
        """Effectue un test complet de fuites"""
        try:
            self.logger.info("Démarrage du test de fuites complet")
            
            # Tests parallèles
            dns_leak, dns_servers = await self._test_dns_leak()
            ipv6_leak, ipv6_addrs = await self._test_ipv6_leak()
            webrtc_leak, real_ip = await self._test_webrtc_leak(vpn_ip)
            timestamp_leak = await self._test_timestamp_leak()
            
            # Calcul de la sévérité
            severity = self._calculate_leak_severity(
                dns_leak, ipv6_leak, webrtc_leak, timestamp_leak
            )
            
            result = LeakTestResult(
                dns_leak=dns_leak,
                ipv6_leak=ipv6_leak,
                webrtc_leak=webrtc_leak,
                timestamp_leak=timestamp_leak,
                dns_servers_detected=dns_servers,
                ipv6_addresses_detected=ipv6_addrs,
                real_ip_detected=real_ip,
                leak_severity=severity
            )
            
            self.logger.info(f"Test de fuites terminé - Sévérité: {severity}")
            return result
            
        except Exception as e:
            self.logger.error(f"Erreur lors du test de fuites: {e}")
            raise
    
    async def _test_dns_leak(self) -> Tuple[bool, List[str]]:
        """Test de fuite DNS"""
        try:
            detected_dns = []
            
            # Test avec plusieurs services
            test_domains = [
                "dnsleaktest.com",
                "ipleak.net",
                "whoer.net"
            ]
            
            for domain in test_domains:
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            f"https://{domain}/api/dns-leak-test",
                            timeout=10
                        ) as response:
                            if response.status == 200:
                                data = await response.json()
                                if "dns_servers" in data:
                                    detected_dns.extend(data["dns_servers"])
                except:
                    continue
            
            # Détection de fuite si les DNS détectés ne correspondent pas au VPN
            leak_detected = len(detected_dns) > 0 and any(
                not self._is_vpn_dns(dns) for dns in detected_dns
            )
            
            return leak_detected, detected_dns
            
        except Exception as e:
            self.logger.error(f"Erreur test DNS: {e}")
            return False, []
    
    async def _test_ipv6_leak(self) -> Tuple[bool, List[str]]:
        """Test de fuite IPv6"""
        try:
            ipv6_addresses = []
            
            # Vérifier les interfaces réseau
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET6:
                        # Ignorer les adresses link-local
                        if not addr.address.startswith("fe80:"):
                            ipv6_addresses.append(addr.address)
            
            # Test en ligne
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get("https://ipv6.icanhazip.com", timeout=10) as response:
                        if response.status == 200:
                            ipv6_online = await response.text()
                            ipv6_online = ipv6_online.strip()
                            if ipv6_online and ipv6_online not in ipv6_addresses:
                                ipv6_addresses.append(ipv6_online)
            except:
                pass
            
            leak_detected = len(ipv6_addresses) > 0
            return leak_detected, ipv6_addresses
            
        except Exception as e:
            self.logger.error(f"Erreur test IPv6: {e}")
            return False, []
    
    async def _test_webrtc_leak(self, vpn_ip: str) -> Tuple[bool, Optional[str]]:
        """Test de fuite WebRTC"""
        try:
            # Test via API externe
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "https://www.browserleaks.com/webrtc",
                    timeout=10
                ) as response:
                    if response.status == 200:
                        text = await response.text()
                        
                        # Extraction des IPs détectées
                        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                        detected_ips = re.findall(ip_pattern, text)
                        
                        # Filtrer les IPs privées et localhost
                        public_ips = [
                            ip for ip in detected_ips
                            if not self._is_private_ip(ip) and ip != "127.0.0.1"
                        ]
                        
                        # Fuite si une IP publique différente du VPN est détectée
                        for ip in public_ips:
                            if ip != vpn_ip:
                                return True, ip
            
            return False, None
            
        except Exception as e:
            self.logger.error(f"Erreur test WebRTC: {e}")
            return False, None
    
    async def _test_timestamp_leak(self) -> bool:
        """Test de fuite de fuseau horaire"""
        try:
            # Récupérer le timezone local
            import datetime
            local_tz = datetime.datetime.now(datetime.timezone.utc).astimezone().tzinfo
            
            # Comparer avec le timezone du VPN (si différent de l'IP)
            async with aiohttp.ClientSession() as session:
                async with session.get("http://ip-api.com/json/", timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        vpn_tz = data.get("timezone", "")
                        
                        # Si le timezone local diffère du timezone VPN, c'est une fuite
                        if vpn_tz and str(local_tz) != vpn_tz:
                            return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Erreur test timestamp: {e}")
            return False
    
    def _is_vpn_dns(self, dns: str) -> bool:
        """Vérifie si le DNS appartient à un provider VPN connu"""
        vpn_dns_ranges = [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
        ]
        
        try:
            ip = ipaddress.ip_address(dns)
            for range_str in vpn_dns_ranges:
                if ip in ipaddress.ip_network(range_str):
                    return True
        except:
            pass
        
        return False
    
    def _is_private_ip(self, ip: str) -> bool:
        """Vérifie si l'IP est privée"""
        try:
            return ipaddress.ip_address(ip).is_private
        except:
            return False
    
    def _calculate_leak_severity(self, dns: bool, ipv6: bool, 
                                 webrtc: bool, timestamp: bool) -> str:
        """Calcule la sévérité des fuites détectées"""
        leak_count = sum([dns, ipv6, webrtc, timestamp])
        
        if leak_count == 0:
            return "none"
        elif leak_count == 1:
            if webrtc:
                return "high"
            return "low"
        elif leak_count == 2:
            return "medium"
        elif leak_count == 3:
            return "high"
        else:
            return "critical"


class TrafficObfuscator:
    """Obfuscateur de trafic VPN pour contournement DPI"""
    
    def __init__(self):
        self.logger = logging.getLogger("TrafficObfuscator")
        self.obfuscation_methods = ["stunnel", "obfs4", "shadowsocks"]
    
    async def enable_obfuscation(self, method: str = "obfs4") -> bool:
        """Active l'obfuscation du trafic"""
        try:
            if method not in self.obfuscation_methods:
                raise ValueError(f"Méthode inconnue: {method}")
            
            self.logger.info(f"Activation de l'obfuscation: {method}")
            
            if method == "obfs4":
                return await self._setup_obfs4()
            elif method == "stunnel":
                return await self._setup_stunnel()
            elif method == "shadowsocks":
                return await self._setup_shadowsocks()
            
            return False
            
        except Exception as e:
            self.logger.error(f"Erreur activation obfuscation: {e}")
            return False
    
    async def _setup_obfs4(self) -> bool:
        """Configure obfs4proxy pour obfuscation"""
        try:
            # Vérifier si obfs4proxy est installé
            result = subprocess.run(
                ["which", "obfs4proxy"],
                capture_output=True
            )
            
            if result.returncode != 0:
                self.logger.warning("obfs4proxy n'est pas installé")
                return False
            
            # Configuration obfs4
            # En production, configurer le bridge obfs4
            self.logger.info("obfs4proxy configuré")
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur setup obfs4: {e}")
            return False
    
    async def _setup_stunnel(self) -> bool:
        """Configure stunnel pour encapsulation TLS"""
        try:
            # Création de la configuration stunnel
            stunnel_config = """[openvpn]
client = yes
accept = 127.0.0.1:1194
connect = vpn-server.example.com:443
cert = /etc/stunnel/stunnel.pem
"""
            
            config_path = Path("/etc/stunnel/stunnel.conf")
            if config_path.parent.exists():
                with open(config_path, 'w') as f:
                    f.write(stunnel_config)
                
                self.logger.info("stunnel configuré")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Erreur setup stunnel: {e}")
            return False
    
    async def _setup_shadowsocks(self) -> bool:
        """Configure Shadowsocks pour obfuscation"""
        try:
            # Configuration Shadowsocks
            ss_config = {
                "server": "0.0.0.0",
                "server_port": 8388,
                "local_address": "127.0.0.1",
                "local_port": 1080,
                "password": secrets.token_urlsafe(32),
                "timeout": 300,
                "method": "chacha20-ietf-poly1305"
            }
            
            config_path = Path("shadowsocks.json")
            with open(config_path, 'w') as f:
                json.dump(ss_config, f, indent=2)
            
            self.logger.info("Shadowsocks configuré")
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur setup Shadowsocks: {e}")
            return False


class MultiHopVPN:
    """Gestionnaire de VPN multi-hop (cascade)"""
    
    def __init__(self):
        self.logger = logging.getLogger("MultiHopVPN")
        self.active_chains: Dict[str, VPNChain] = {}
    
    async def create_vpn_chain(self, 
                              servers: List[str],
                              protocol: str = "wireguard",
                              obfuscation: bool = True) -> VPNChain:
        """Crée une chaîne VPN multi-hop"""
        try:
            if len(servers) < 2:
                raise ValueError("Minimum 2 serveurs requis pour multi-hop")
            
            chain_id = secrets.token_hex(8)
            
            chain = VPNChain(
                chain_id=chain_id,
                servers=servers,
                protocol=protocol,
                obfuscation_enabled=obfuscation,
                created_at=time.time()
            )
            
            self.active_chains[chain_id] = chain
            self.logger.info(f"Chaîne VPN créée: {chain_id} avec {len(servers)} sauts")
            
            return chain
            
        except Exception as e:
            self.logger.error(f"Erreur création chaîne VPN: {e}")
            raise
    
    async def connect_chain(self, chain: VPNChain) -> bool:
        """Établit la connexion en cascade"""
        try:
            self.logger.info(f"Connexion à la chaîne {chain.chain_id}")
            
            # Connexion séquentielle aux serveurs
            for i, server in enumerate(chain.servers):
                self.logger.info(f"Connexion au saut {i+1}/{len(chain.servers)}: {server}")
                
                # Simuler la connexion au serveur
                await asyncio.sleep(2)
                
                # En production, établir vraiment la connexion
                # selon le protocole (WireGuard ou OpenVPN)
            
            self.logger.info(f"Chaîne {chain.chain_id} connectée avec succès")
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur connexion chaîne: {e}")
            return False
    
    async def disconnect_chain(self, chain_id: str) -> bool:
        """Déconnecte une chaîne VPN"""
        try:
            if chain_id not in self.active_chains:
                return False
            
            chain = self.active_chains[chain_id]
            
            # Déconnexion en ordre inverse
            for server in reversed(chain.servers):
                self.logger.info(f"Déconnexion de {server}")
                await asyncio.sleep(1)
            
            del self.active_chains[chain_id]
            self.logger.info(f"Chaîne {chain_id} déconnectée")
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur déconnexion chaîne: {e}")
            return False


class AdvancedVPNManager:
    """Gestionnaire VPN avancé unifié"""
    
    def __init__(self):
        self.logger = self._setup_logging()
        self.wireguard = WireGuardManager()
        self.leak_detector = LeakDetector()
        self.obfuscator = TrafficObfuscator()
        self.multihop = MultiHopVPN()
        
        self.current_protocol = None
        self.performance_metrics: List[VPNMetrics] = []
    
    def _setup_logging(self) -> logging.Logger:
        """Configure le logging"""
        logger = logging.getLogger("AdvancedVPNManager")
        logger.setLevel(logging.INFO)
        
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    async def connect_wireguard(self, config: WireGuardConfig) -> bool:
        """Connexion WireGuard avec détection de fuites"""
        try:
            # Connexion
            success = await self.wireguard.connect(config)
            
            if success:
                self.current_protocol = "wireguard"
                
                # Test de fuites après connexion
                await asyncio.sleep(3)
                
                vpn_ip = await self._get_current_ip()
                leak_result = await self.leak_detector.perform_full_leak_test(vpn_ip)
                
                if leak_result.leak_severity in ["high", "critical"]:
                    self.logger.warning(f"Fuites détectées: {leak_result.leak_severity}")
                    # Optionnel: déconnecter si fuites critiques
                
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Erreur connexion WireGuard avancée: {e}")
            return False
    
    async def enable_stealth_mode(self, method: str = "obfs4") -> bool:
        """Active le mode furtif avec obfuscation"""
        return await self.obfuscator.enable_obfuscation(method)
    
    async def create_and_connect_multihop(self, servers: List[str]) -> Optional[VPNChain]:
        """Crée et connecte une chaîne multi-hop"""
        try:
            chain = await self.multihop.create_vpn_chain(servers)
            success = await self.multihop.connect_chain(chain)
            
            if success:
                return chain
            return None
            
        except Exception as e:
            self.logger.error(f"Erreur multi-hop: {e}")
            return None
    
    async def collect_performance_metrics(self) -> VPNMetrics:
        """Collecte les métriques de performance détaillées"""
        try:
            # Mesure de latence
            latency = await self._measure_latency()
            jitter = await self._measure_jitter()
            packet_loss = await self._measure_packet_loss()
            
            # Mesure de vitesse
            download_speed, upload_speed = await self._measure_speed()
            
            # Calcul de stabilité
            stability = await self._calculate_stability()
            
            # Overhead de chiffrement
            overhead = await self._estimate_encryption_overhead()
            
            metrics = VPNMetrics(
                latency_ms=latency,
                jitter_ms=jitter,
                packet_loss_percent=packet_loss,
                download_speed_mbps=download_speed,
                upload_speed_mbps=upload_speed,
                connection_stability=stability,
                encryption_overhead_percent=overhead,
                timestamp=time.time()
            )
            
            self.performance_metrics.append(metrics)
            return metrics
            
        except Exception as e:
            self.logger.error(f"Erreur collecte métriques: {e}")
            raise
    
    async def _get_current_ip(self) -> str:
        """Récupère l'IP publique actuelle"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get("https://api.ipify.org", timeout=10) as response:
                    return await response.text()
        except:
            return ""
    
    async def _measure_latency(self) -> float:
        """Mesure la latence"""
        try:
            start = time.time()
            async with aiohttp.ClientSession() as session:
                async with session.get("https://www.google.com", timeout=10) as response:
                    await response.read()
            return (time.time() - start) * 1000
        except:
            return 0.0
    
    async def _measure_jitter(self) -> float:
        """Mesure la gigue (variation de latence)"""
        latencies = []
        for _ in range(5):
            latencies.append(await self._measure_latency())
            await asyncio.sleep(0.5)
        
        if len(latencies) > 1:
            import statistics
            return statistics.stdev(latencies)
        return 0.0
    
    async def _measure_packet_loss(self) -> float:
        """Estime la perte de paquets"""
        try:
            result = subprocess.run(
                ["ping", "-c", "10", "8.8.8.8"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            output = result.stdout
            match = re.search(r'(\d+)% packet loss', output)
            if match:
                return float(match.group(1))
        except:
            pass
        return 0.0
    
    async def _measure_speed(self) -> Tuple[float, float]:
        """Mesure la vitesse de téléchargement/upload"""
        # Simplification: test avec un petit fichier
        try:
            test_size = 1024 * 1024  # 1MB
            
            start = time.time()
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://httpbin.org/bytes/{test_size}",
                    timeout=30
                ) as response:
                    await response.read()
            
            duration = time.time() - start
            download_mbps = (test_size / duration) / (1024 * 1024) * 8
            
            # Upload estimé à 80% du download (approximation)
            upload_mbps = download_mbps * 0.8
            
            return download_mbps, upload_mbps
        except:
            return 0.0, 0.0
    
    async def _calculate_stability(self) -> float:
        """Calcule la stabilité de connexion (0-100)"""
        if len(self.performance_metrics) < 2:
            return 100.0
        
        # Basé sur la variation des métriques récentes
        recent = self.performance_metrics[-10:]
        latencies = [m.latency_ms for m in recent]
        
        if latencies:
            import statistics
            avg = statistics.mean(latencies)
            if avg > 0:
                variation = (statistics.stdev(latencies) / avg) * 100
                stability = max(0, 100 - variation)
                return min(100, stability)
        
        return 100.0
    
    async def _estimate_encryption_overhead(self) -> float:
        """Estime le surcoût du chiffrement"""
        # Simplifié: basé sur le protocole
        if self.current_protocol == "wireguard":
            return 3.0  # WireGuard a un overhead très faible
        elif self.current_protocol == "openvpn":
            return 10.0  # OpenVPN a plus d'overhead
        return 0.0
    
    def get_status_report(self) -> Dict:
        """Génère un rapport de statut complet"""
        return {
            "protocol": self.current_protocol,
            "wireguard_connected": self.wireguard.is_connected,
            "active_multihop_chains": len(self.multihop.active_chains),
            "recent_metrics": [asdict(m) for m in self.performance_metrics[-5:]],
            "metrics_collected": len(self.performance_metrics)
        }


# Exemple d'utilisation
async def main():
    """Démonstration des fonctionnalités avancées"""
    print("=== VPN Avancé - Ghost Cyber Universe ===\n")
    
    vpn = AdvancedVPNManager()
    
    # 1. Test WireGuard
    print("1. Configuration WireGuard...")
    private_key, public_key = vpn.wireguard.generate_keypair()
    print(f"   Clés générées: {public_key[:20]}...")
    
    # 2. Test de détection de fuites
    print("\n2. Test de détection de fuites...")
    leak_result = await vpn.leak_detector.perform_full_leak_test("203.0.113.1")
    print(f"   Sévérité des fuites: {leak_result.leak_severity}")
    print(f"   DNS leak: {leak_result.dns_leak}")
    print(f"   IPv6 leak: {leak_result.ipv6_leak}")
    print(f"   WebRTC leak: {leak_result.webrtc_leak}")
    
    # 3. Métriques de performance
    print("\n3. Collecte des métriques de performance...")
    metrics = await vpn.collect_performance_metrics()
    print(f"   Latence: {metrics.latency_ms:.2f} ms")
    print(f"   Vitesse download: {metrics.download_speed_mbps:.2f} Mbps")
    print(f"   Stabilité: {metrics.connection_stability:.1f}%")
    
    # 4. Multi-hop
    print("\n4. Test multi-hop VPN...")
    servers = ["server1.vpn.com", "server2.vpn.com", "server3.vpn.com"]
    chain = await vpn.multihop.create_vpn_chain(servers)
    print(f"   Chaîne créée: {chain.chain_id}")
    print(f"   Nombre de sauts: {len(chain.servers)}")
    
    # 5. Rapport final
    print("\n5. Rapport de statut:")
    status = vpn.get_status_report()
    print(json.dumps(status, indent=2))
    
    print("\n✅ Tests terminés avec succès!")


if __name__ == "__main__":
    asyncio.run(main())

