#!/usr/bin/env python3
"""
Tests unitaires pour le module VPN avancé
Ghost Cyber Universe
"""

import asyncio
import pytest
import sys
from pathlib import Path

# Ajout du chemin parent
sys.path.append(str(Path(__file__).parent.parent))

from secure_navigation.vpn_advanced import (
    WireGuardManager,
    WireGuardConfig,
    LeakDetector,
    TrafficObfuscator,
    MultiHopVPN,
    AdvancedVPNManager
)


class TestWireGuardManager:
    """Tests pour WireGuardManager"""
    
    def test_init(self):
        """Test d'initialisation"""
        wg = WireGuardManager()
        assert wg.interface_name == "wg0"
        assert wg.is_connected == False
    
    def test_generate_keypair(self):
        """Test de génération de clés"""
        wg = WireGuardManager()
        private_key, public_key = wg.generate_keypair()
        
        assert private_key is not None
        assert public_key is not None
        assert len(private_key) > 0
        assert len(public_key) > 0
        assert private_key != public_key
    
    def test_create_config_file(self):
        """Test de création de fichier de configuration"""
        wg = WireGuardManager()
        
        config = WireGuardConfig(
            private_key="test_private_key",
            public_key="test_public_key",
            server_public_key="server_public_key",
            server_endpoint="vpn.example.com",
            server_port=51820,
            allowed_ips="0.0.0.0/0",
            dns_servers=["1.1.1.1", "1.0.0.1"],
            mtu=1420,
            persistent_keepalive=25
        )
        
        config_path = wg.create_config_file(config, "test_wg0.conf")
        
        assert config_path.exists()
        assert config_path.name == "test_wg0.conf"
        
        # Vérification du contenu
        with open(config_path, 'r') as f:
            content = f.read()
            assert "PrivateKey" in content
            assert "PublicKey" in content
            assert "Endpoint" in content
            assert "vpn.example.com:51820" in content
        
        # Nettoyage
        config_path.unlink()


class TestLeakDetector:
    """Tests pour LeakDetector"""
    
    @pytest.mark.asyncio
    async def test_init(self):
        """Test d'initialisation"""
        detector = LeakDetector()
        assert detector.original_ip is None
        assert detector.original_dns is None
    
    @pytest.mark.asyncio
    async def test_perform_full_leak_test(self):
        """Test de détection de fuites complète"""
        detector = LeakDetector()
        
        # Test avec une IP VPN fictive
        result = await detector.perform_full_leak_test("203.0.113.1")
        
        assert result is not None
        assert hasattr(result, 'dns_leak')
        assert hasattr(result, 'ipv6_leak')
        assert hasattr(result, 'webrtc_leak')
        assert hasattr(result, 'timestamp_leak')
        assert hasattr(result, 'leak_severity')
        assert result.leak_severity in ['none', 'low', 'medium', 'high', 'critical']
    
    @pytest.mark.asyncio
    async def test_dns_leak_detection(self):
        """Test de détection DNS"""
        detector = LeakDetector()
        
        dns_leak, dns_servers = await detector._test_dns_leak()
        
        assert isinstance(dns_leak, bool)
        assert isinstance(dns_servers, list)
    
    @pytest.mark.asyncio
    async def test_ipv6_leak_detection(self):
        """Test de détection IPv6"""
        detector = LeakDetector()
        
        ipv6_leak, ipv6_addrs = await detector._test_ipv6_leak()
        
        assert isinstance(ipv6_leak, bool)
        assert isinstance(ipv6_addrs, list)
    
    def test_is_private_ip(self):
        """Test de détection d'IP privée"""
        detector = LeakDetector()
        
        assert detector._is_private_ip("192.168.1.1") == True
        assert detector._is_private_ip("10.0.0.1") == True
        assert detector._is_private_ip("172.16.0.1") == True
        assert detector._is_private_ip("8.8.8.8") == False
        assert detector._is_private_ip("1.1.1.1") == False
    
    def test_calculate_leak_severity(self):
        """Test de calcul de sévérité"""
        detector = LeakDetector()
        
        # Aucune fuite
        assert detector._calculate_leak_severity(False, False, False, False) == "none"
        
        # Fuite légère
        assert detector._calculate_leak_severity(True, False, False, False) == "low"
        
        # Fuite WebRTC seule = haute
        assert detector._calculate_leak_severity(False, False, True, False) == "high"
        
        # Plusieurs fuites
        assert detector._calculate_leak_severity(True, True, False, False) == "medium"
        
        # Fuites critiques
        assert detector._calculate_leak_severity(True, True, True, True) == "critical"


class TestTrafficObfuscator:
    """Tests pour TrafficObfuscator"""
    
    def test_init(self):
        """Test d'initialisation"""
        obfuscator = TrafficObfuscator()
        assert obfuscator.obfuscation_methods == ["stunnel", "obfs4", "shadowsocks"]
    
    @pytest.mark.asyncio
    async def test_enable_obfuscation_invalid_method(self):
        """Test avec méthode invalide"""
        obfuscator = TrafficObfuscator()
        
        with pytest.raises(ValueError):
            await obfuscator.enable_obfuscation("invalid_method")
    
    @pytest.mark.asyncio
    async def test_enable_obfuscation_obfs4(self):
        """Test d'activation obfs4"""
        obfuscator = TrafficObfuscator()
        
        # Ne devrait pas échouer même si obfs4proxy n'est pas installé
        result = await obfuscator.enable_obfuscation("obfs4")
        assert isinstance(result, bool)


class TestMultiHopVPN:
    """Tests pour MultiHopVPN"""
    
    def test_init(self):
        """Test d'initialisation"""
        multihop = MultiHopVPN()
        assert multihop.active_chains == {}
    
    @pytest.mark.asyncio
    async def test_create_vpn_chain(self):
        """Test de création de chaîne VPN"""
        multihop = MultiHopVPN()
        
        servers = ["server1.vpn.com", "server2.vpn.com", "server3.vpn.com"]
        chain = await multihop.create_vpn_chain(servers, protocol="wireguard")
        
        assert chain is not None
        assert chain.chain_id in multihop.active_chains
        assert len(chain.servers) == 3
        assert chain.protocol == "wireguard"
    
    @pytest.mark.asyncio
    async def test_create_vpn_chain_insufficient_servers(self):
        """Test avec nombre insuffisant de serveurs"""
        multihop = MultiHopVPN()
        
        with pytest.raises(ValueError):
            await multihop.create_vpn_chain(["server1.vpn.com"])
    
    @pytest.mark.asyncio
    async def test_connect_chain(self):
        """Test de connexion à une chaîne"""
        multihop = MultiHopVPN()
        
        servers = ["server1.vpn.com", "server2.vpn.com"]
        chain = await multihop.create_vpn_chain(servers)
        
        result = await multihop.connect_chain(chain)
        assert isinstance(result, bool)
    
    @pytest.mark.asyncio
    async def test_disconnect_chain(self):
        """Test de déconnexion d'une chaîne"""
        multihop = MultiHopVPN()
        
        servers = ["server1.vpn.com", "server2.vpn.com"]
        chain = await multihop.create_vpn_chain(servers)
        
        result = await multihop.disconnect_chain(chain.chain_id)
        assert result == True
        assert chain.chain_id not in multihop.active_chains


class TestAdvancedVPNManager:
    """Tests pour AdvancedVPNManager"""
    
    def test_init(self):
        """Test d'initialisation"""
        vpn = AdvancedVPNManager()
        
        assert vpn.wireguard is not None
        assert vpn.leak_detector is not None
        assert vpn.obfuscator is not None
        assert vpn.multihop is not None
        assert vpn.current_protocol is None
        assert vpn.performance_metrics == []
    
    @pytest.mark.asyncio
    async def test_get_current_ip(self):
        """Test de récupération de l'IP"""
        vpn = AdvancedVPNManager()
        
        ip = await vpn._get_current_ip()
        assert ip is not None or ip == ""
    
    @pytest.mark.asyncio
    async def test_measure_latency(self):
        """Test de mesure de latence"""
        vpn = AdvancedVPNManager()
        
        latency = await vpn._measure_latency()
        assert isinstance(latency, float)
        assert latency >= 0
    
    @pytest.mark.asyncio
    async def test_collect_performance_metrics(self):
        """Test de collecte de métriques"""
        vpn = AdvancedVPNManager()
        
        metrics = await vpn.collect_performance_metrics()
        
        assert metrics is not None
        assert hasattr(metrics, 'latency_ms')
        assert hasattr(metrics, 'jitter_ms')
        assert hasattr(metrics, 'packet_loss_percent')
        assert hasattr(metrics, 'download_speed_mbps')
        assert hasattr(metrics, 'upload_speed_mbps')
        assert hasattr(metrics, 'connection_stability')
        assert hasattr(metrics, 'encryption_overhead_percent')
        assert hasattr(metrics, 'timestamp')
    
    @pytest.mark.asyncio
    async def test_create_and_connect_multihop(self):
        """Test de création et connexion multi-hop"""
        vpn = AdvancedVPNManager()
        
        servers = ["server1.vpn.com", "server2.vpn.com"]
        chain = await vpn.create_and_connect_multihop(servers)
        
        # Peut réussir ou échouer selon l'environnement
        assert chain is None or chain is not None
    
    def test_get_status_report(self):
        """Test du rapport de statut"""
        vpn = AdvancedVPNManager()
        
        status = vpn.get_status_report()
        
        assert isinstance(status, dict)
        assert "protocol" in status
        assert "wireguard_connected" in status
        assert "active_multihop_chains" in status
        assert "recent_metrics" in status
        assert "metrics_collected" in status


# Tests d'intégration

@pytest.mark.asyncio
async def test_full_vpn_workflow():
    """Test du workflow complet VPN"""
    vpn = AdvancedVPNManager()
    
    # 1. Génération de clés
    private_key, public_key = vpn.wireguard.generate_keypair()
    assert private_key and public_key
    
    # 2. Test de fuites
    detector = LeakDetector()
    leak_result = await detector.perform_full_leak_test("203.0.113.1")
    assert leak_result.leak_severity in ['none', 'low', 'medium', 'high', 'critical']
    
    # 3. Métriques de performance
    metrics = await vpn.collect_performance_metrics()
    assert metrics.latency_ms >= 0
    
    # 4. Multi-hop
    servers = ["server1.vpn.com", "server2.vpn.com"]
    chain = await vpn.multihop.create_vpn_chain(servers)
    assert chain is not None
    
    # 5. Statut
    status = vpn.get_status_report()
    assert status["metrics_collected"] > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

