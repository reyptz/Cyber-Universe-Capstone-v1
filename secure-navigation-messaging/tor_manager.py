#!/usr/bin/env python3
"""
Module d'intégration Tor avec proxy SOCKS5 et circuits multiples
Fournit un anonymat renforcé avec rotation automatique des circuits
"""

import asyncio
import json
import logging
import random
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import aiohttp
import aiofiles
import stem
from stem import Signal
from stem.control import Controller
from stem.process import launch_tor_with_config
import socks
import requests

@dataclass
class TorCircuit:
    """Représente un circuit Tor"""
    circuit_id: str
    path: List[str]  # Liste des relais
    purpose: str
    status: str
    created_time: float
    country_sequence: List[str]

@dataclass
class TorStatus:
    """Statut de la connexion Tor"""
    connected: bool
    circuits_count: int
    active_circuit: Optional[TorCircuit]
    exit_ip: Optional[str]
    exit_country: Optional[str]
    bootstrap_progress: int
    control_port: int
    socks_port: int

class TorManager:
    """Gestionnaire Tor avec circuits multiples et anonymat renforcé"""
    
    def __init__(self, 
                 socks_port: int = 9050,
                 control_port: int = 9051,
                 data_dir: Optional[str] = None):
        
        self.socks_port = socks_port
        self.control_port = control_port
        self.data_dir = Path(data_dir) if data_dir else Path(tempfile.mkdtemp(prefix="tor_"))
        self.data_dir.mkdir(exist_ok=True)
        
        self.logger = self._setup_logging()
        self.tor_process = None
        self.controller: Optional[Controller] = None
        self.circuits: Dict[str, TorCircuit] = {}
        
        self.status = TorStatus(
            connected=False,
            circuits_count=0,
            active_circuit=None,
            exit_ip=None,
            exit_country=None,
            bootstrap_progress=0,
            control_port=control_port,
            socks_port=socks_port
        )
        
        # Configuration de sécurité
        self.circuit_rotation_interval = 600  # 10 minutes
        self.max_circuits = 5
        self.excluded_countries = ['CN', 'RU', 'IR', 'KP']  # Pays à éviter
        self.preferred_countries = ['CH', 'SE', 'NL', 'DE', 'IS']  # Pays préférés
        
        # Configuration Tor
        self.tor_config = self._generate_tor_config()
        
    def _setup_logging(self) -> logging.Logger:
        """Configuration du système de logs sécurisé"""
        logger = logging.getLogger("TorManager")
        logger.setLevel(logging.INFO)
        
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler(
            "tor_manager.log",
            maxBytes=10*1024*1024,
            backupCount=5
        )
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        return logger
    
    def _generate_tor_config(self) -> Dict[str, Union[str, int, List[str]]]:
        """Génère la configuration Tor sécurisée"""
        return {
            'SocksPort': str(self.socks_port),
            'ControlPort': str(self.control_port),
            'DataDirectory': str(self.data_dir),
            'CookieAuthentication': '1',
            'HashedControlPassword': '',
            
            # Sécurité renforcée
            'ExitNodes': '{' + ','.join(self.preferred_countries) + '}',
            'ExcludeNodes': '{' + ','.join(self.excluded_countries) + '}',
            'StrictNodes': '1',
            
            # Circuits et chemins
            'CircuitBuildTimeout': '30',
            'NewCircuitPeriod': '30',
            'MaxCircuitDirtiness': '600',
            'EnforceDistinctSubnets': '1',
            
            # Protection contre les attaques
            'SafeLogging': '1',
            'WarnUnsafeSocks': '1',
            'ClientRejectInternalAddresses': '1',
            'ClientUseIPv6': '0',  # Désactiver IPv6 pour éviter les fuites
            
            # Optimisations
            'KeepalivePeriod': '60',
            'CircuitStreamTimeout': '20',
            'CircuitIdleTimeout': '1800',
            
            # Logs (minimal pour sécurité)
            'Log': ['notice stdout', 'info file tor.log'],
        }
    
    async def start(self) -> bool:
        """Démarre le processus Tor avec configuration sécurisée"""
        try:
            self.logger.info("Démarrage de Tor...")
            
            # Vérifier si Tor est déjà en cours d'exécution
            if await self._is_tor_running():
                self.logger.info("Tor est déjà en cours d'exécution")
                return await self._connect_to_existing_tor()
            
            # Lancement de Tor avec configuration personnalisée
            self.tor_process = launch_tor_with_config(
                config=self.tor_config,
                timeout=60
            )
            
            # Attendre que Tor soit prêt
            await self._wait_for_bootstrap()
            
            # Connexion au contrôleur
            await self._connect_controller()
            
            # Initialisation des circuits
            await self._initialize_circuits()
            
            self.status.connected = True
            self.logger.info("Tor démarré avec succès")
            
            # Démarrage des tâches de maintenance
            asyncio.create_task(self._circuit_rotation_task())
            asyncio.create_task(self._monitor_circuits())
            
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur lors du démarrage de Tor: {e}")
            return False
    
    async def stop(self) -> bool:
        """Arrête Tor et nettoie les ressources"""
        try:
            self.logger.info("Arrêt de Tor...")
            
            # Fermeture du contrôleur
            if self.controller:
                self.controller.close()
                self.controller = None
            
            # Arrêt du processus Tor
            if self.tor_process:
                self.tor_process.terminate()
                self.tor_process = None
            
            # Nettoyage des circuits
            self.circuits.clear()
            
            # Mise à jour du statut
            self.status.connected = False
            self.status.circuits_count = 0
            self.status.active_circuit = None
            self.status.bootstrap_progress = 0
            
            self.logger.info("Tor arrêté")
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'arrêt de Tor: {e}")
            return False
    
    async def _is_tor_running(self) -> bool:
        """Vérifie si Tor est déjà en cours d'exécution"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex(('127.0.0.1', self.control_port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    async def _connect_to_existing_tor(self) -> bool:
        """Se connecte à une instance Tor existante"""
        try:
            await self._connect_controller()
            await self._update_circuits_info()
            self.status.connected = True
            return True
        except Exception as e:
            self.logger.error(f"Impossible de se connecter à Tor existant: {e}")
            return False
    
    async def _wait_for_bootstrap(self, timeout: int = 60):
        """Attend que Tor termine son bootstrap"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                # Tentative de connexion au port de contrôle
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('127.0.0.1', self.control_port))
                sock.close()
                
                if result == 0:
                    # Vérifier le statut du bootstrap
                    try:
                        with Controller.from_port(port=self.control_port) as controller:
                            controller.authenticate()
                            bootstrap_status = controller.get_info("status/bootstrap-phase")
                            
                            if "PROGRESS=100" in bootstrap_status:
                                self.status.bootstrap_progress = 100
                                return
                            else:
                                # Extraire le pourcentage de progression
                                if "PROGRESS=" in bootstrap_status:
                                    progress_str = bootstrap_status.split("PROGRESS=")[1].split()[0]
                                    self.status.bootstrap_progress = int(progress_str)
                    except Exception:
                        pass
                
                await asyncio.sleep(1)
                
            except Exception:
                await asyncio.sleep(1)
        
        raise TimeoutError("Timeout lors du bootstrap de Tor")
    
    async def _connect_controller(self):
        """Établit la connexion avec le contrôleur Tor"""
        try:
            self.controller = Controller.from_port(port=self.control_port)
            self.controller.authenticate()
            self.logger.info("Connexion au contrôleur Tor établie")
        except Exception as e:
            raise Exception(f"Impossible de se connecter au contrôleur Tor: {e}")
    
    async def _initialize_circuits(self):
        """Initialise les circuits Tor"""
        try:
            # Créer plusieurs circuits pour différents usages
            await self._create_circuit("general")
            await self._create_circuit("secure")
            await self._create_circuit("fast")
            
            await self._update_circuits_info()
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'initialisation des circuits: {e}")
    
    async def _create_circuit(self, purpose: str = "general") -> Optional[str]:
        """Crée un nouveau circuit Tor"""
        try:
            if not self.controller:
                return None
            
            # Sélection des relais selon le purpose
            if purpose == "secure":
                # Circuit avec relais dans des pays sûrs uniquement
                path = await self._select_secure_path()
            elif purpose == "fast":
                # Circuit optimisé pour la vitesse
                path = await self._select_fast_path()
            else:
                # Circuit général
                path = None  # Laisser Tor choisir
            
            # Création du circuit
            if path:
                circuit_id = self.controller.new_circuit(path)
            else:
                circuit_id = self.controller.new_circuit()
            
            self.logger.info(f"Circuit {circuit_id} créé pour {purpose}")
            return circuit_id
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la création du circuit: {e}")
            return None
    
    async def _select_secure_path(self) -> List[str]:
        """Sélectionne un chemin sécurisé pour le circuit"""
        # En production, utiliser l'API Tor pour obtenir les relais disponibles
        # Ici, simulation avec des relais connus sûrs
        secure_relays = [
            "9695DFC35FFEB861329B9F1AB04C46397020CE31",  # Exemple de relais suisse
            "87562B2F0B2C8E0E6F7F8A8B9C0D1E2F3A4B5C6D",  # Exemple de relais suédois
            "1234567890ABCDEF1234567890ABCDEF12345678"   # Exemple de relais néerlandais
        ]
        
        return random.sample(secure_relays, min(3, len(secure_relays)))
    
    async def _select_fast_path(self) -> List[str]:
        """Sélectionne un chemin optimisé pour la vitesse"""
        # Sélection basée sur la bande passante et la latence
        fast_relays = [
            "ABCDEF1234567890ABCDEF1234567890ABCDEF12",
            "1234567890ABCDEF1234567890ABCDEF12345678",
            "FEDCBA0987654321FEDCBA0987654321FEDCBA09"
        ]
        
        return random.sample(fast_relays, min(3, len(fast_relays)))
    
    async def _update_circuits_info(self):
        """Met à jour les informations sur les circuits"""
        try:
            if not self.controller:
                return
            
            circuits = self.controller.get_circuits()
            self.circuits.clear()
            
            for circuit in circuits:
                if circuit.status == "BUILT":
                    tor_circuit = TorCircuit(
                        circuit_id=circuit.id,
                        path=[relay[0] for relay in circuit.path],
                        purpose=circuit.purpose or "general",
                        status=circuit.status,
                        created_time=time.time(),  # Approximation
                        country_sequence=await self._get_circuit_countries(circuit)
                    )
                    
                    self.circuits[circuit.id] = tor_circuit
            
            self.status.circuits_count = len(self.circuits)
            
            # Sélectionner un circuit actif
            if self.circuits and not self.status.active_circuit:
                self.status.active_circuit = list(self.circuits.values())[0]
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la mise à jour des circuits: {e}")
    
    async def _get_circuit_countries(self, circuit) -> List[str]:
        """Obtient la séquence de pays pour un circuit"""
        try:
            countries = []
            for relay_fingerprint, _ in circuit.path:
                # En production, utiliser l'API Tor pour obtenir les infos du relais
                # Ici, simulation
                country = random.choice(['CH', 'SE', 'NL', 'DE', 'NO', 'DK'])
                countries.append(country)
            return countries
        except Exception:
            return []
    
    async def new_identity(self) -> bool:
        """Demande une nouvelle identité (nouveau circuit)"""
        try:
            if not self.controller:
                return False
            
            self.logger.info("Demande d'une nouvelle identité")
            
            # Signal pour nouvelle identité
            self.controller.signal(Signal.NEWNYM)
            
            # Attendre un peu pour que le nouveau circuit soit établi
            await asyncio.sleep(5)
            
            # Mettre à jour les informations
            await self._update_circuits_info()
            await self._update_exit_info()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la demande de nouvelle identité: {e}")
            return False
    
    async def rotate_circuit(self) -> bool:
        """Effectue une rotation manuelle des circuits"""
        try:
            # Créer un nouveau circuit
            new_circuit_id = await self._create_circuit()
            
            if new_circuit_id:
                # Attendre que le circuit soit construit
                await asyncio.sleep(3)
                
                # Mettre à jour les informations
                await self._update_circuits_info()
                
                # Nettoyer les anciens circuits si nécessaire
                await self._cleanup_old_circuits()
                
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la rotation des circuits: {e}")
            return False
    
    async def _cleanup_old_circuits(self):
        """Nettoie les anciens circuits pour maintenir la limite"""
        try:
            if len(self.circuits) > self.max_circuits:
                # Trier par âge et fermer les plus anciens
                sorted_circuits = sorted(
                    self.circuits.values(),
                    key=lambda c: c.created_time
                )
                
                circuits_to_close = sorted_circuits[:-self.max_circuits]
                
                for circuit in circuits_to_close:
                    try:
                        self.controller.close_circuit(circuit.circuit_id)
                        del self.circuits[circuit.circuit_id]
                    except Exception:
                        pass
                        
        except Exception as e:
            self.logger.error(f"Erreur lors du nettoyage des circuits: {e}")
    
    async def _circuit_rotation_task(self):
        """Tâche de rotation automatique des circuits"""
        while self.status.connected:
            await asyncio.sleep(self.circuit_rotation_interval)
            if self.status.connected:
                await self.rotate_circuit()
    
    async def _monitor_circuits(self):
        """Surveillance continue des circuits"""
        while self.status.connected:
            try:
                await self._update_circuits_info()
                await self._update_exit_info()
                await asyncio.sleep(30)  # Vérification toutes les 30 secondes
            except Exception as e:
                self.logger.error(f"Erreur lors de la surveillance: {e}")
                await asyncio.sleep(60)
    
    async def _update_exit_info(self):
        """Met à jour les informations sur le nœud de sortie"""
        try:
            # Obtenir l'IP de sortie via un service externe
            exit_ip = await self._get_exit_ip()
            if exit_ip:
                self.status.exit_ip = exit_ip
                self.status.exit_country = await self._get_ip_country(exit_ip)
                
        except Exception as e:
            self.logger.error(f"Erreur lors de la mise à jour des infos de sortie: {e}")
    
    async def _get_exit_ip(self) -> Optional[str]:
        """Récupère l'adresse IP de sortie via Tor"""
        try:
            # Configuration du proxy SOCKS5
            session = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(
                    resolver=aiohttp.resolver.AsyncResolver(),
                    family=socket.AF_INET
                ),
                timeout=aiohttp.ClientTimeout(total=30)
            )
            
            # Utilisation du proxy SOCKS5 de Tor
            proxy_url = f"socks5://127.0.0.1:{self.socks_port}"
            
            async with session.get(
                "https://check.torproject.org/api/ip",
                proxy=proxy_url
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("IP")
            
            await session.close()
            return None
            
        except Exception:
            return None
    
    async def _get_ip_country(self, ip: str) -> Optional[str]:
        """Obtient le pays d'une adresse IP"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://ip-api.com/json/{ip}") as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get("countryCode")
            return None
        except Exception:
            return None
    
    def get_socks_proxy(self) -> Dict[str, str]:
        """Retourne la configuration du proxy SOCKS5"""
        return {
            "http": f"socks5://127.0.0.1:{self.socks_port}",
            "https": f"socks5://127.0.0.1:{self.socks_port}"
        }
    
    async def test_connection(self) -> Dict[str, any]:
        """Teste la connexion Tor"""
        results = {
            "connected": self.status.connected,
            "circuits_count": self.status.circuits_count,
            "exit_ip": self.status.exit_ip,
            "exit_country": self.status.exit_country,
            "tor_check": await self._test_tor_connectivity(),
            "anonymity_test": await self._test_anonymity()
        }
        
        return results
    
    async def _test_tor_connectivity(self) -> bool:
        """Teste la connectivité via Tor"""
        try:
            proxy_url = f"socks5://127.0.0.1:{self.socks_port}"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "https://check.torproject.org/",
                    proxy=proxy_url,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        text = await response.text()
                        return "Congratulations" in text
            
            return False
            
        except Exception:
            return False
    
    async def _test_anonymity(self) -> Dict[str, any]:
        """Teste le niveau d'anonymat"""
        try:
            proxy_url = f"socks5://127.0.0.1:{self.socks_port}"
            
            # Test des headers et empreinte
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "https://httpbin.org/headers",
                    proxy=proxy_url,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        headers = data.get("headers", {})
                        
                        return {
                            "user_agent_anonymized": "Tor" in headers.get("User-Agent", ""),
                            "no_real_ip_leaked": "X-Real-Ip" not in headers,
                            "headers_count": len(headers)
                        }
            
            return {"error": "Test failed"}
            
        except Exception as e:
            return {"error": str(e)}
    
    async def get_status(self) -> TorStatus:
        """Retourne le statut actuel de Tor"""
        return self.status

# Exemple d'utilisation
async def main():
    """Fonction de démonstration"""
    tor = TorManager()
    
    try:
        # Démarrage de Tor
        if await tor.start():
            print("Tor démarré avec succès")
            
            # Test de la connexion
            test_results = await tor.test_connection()
            print(f"Résultats du test: {test_results}")
            
            # Nouvelle identité
            await tor.new_identity()
            print("Nouvelle identité obtenue")
            
            # Attendre un peu
            await asyncio.sleep(10)
            
            # Arrêt
            await tor.stop()
        else:
            print("Échec du démarrage de Tor")
            
    except KeyboardInterrupt:
        await tor.stop()

if __name__ == "__main__":
    asyncio.run(main())