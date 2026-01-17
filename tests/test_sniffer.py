#!/usr/bin/env python3
"""
Unit tests for sniffer module
"""

import unittest
import sys
import os
import time
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.sniffer import NetworkSniffer, PacketInfo, TrafficStats
from unittest.mock import patch, MagicMock

class TestPacketInfo(unittest.TestCase):
    """Test cases for PacketInfo dataclass"""
    
    def test_packet_info_creation(self):
        """Test PacketInfo creation"""
        packet = PacketInfo(
            timestamp="12:00:00.000",
            source_ip="192.168.1.1",
            destination_ip="192.168.1.2",
            protocol="TCP",
            source_port=80,
            destination_port=12345,
            packet_size=1500,
            flags="SYN ACK",
            info="TCP 80 -> 12345",
            ttl=64,
            checksum=12345
        )
        
        self.assertEqual(packet.timestamp, "12:00:00.000")
        self.assertEqual(packet.source_ip, "192.168.1.1")
        self.assertEqual(packet.destination_ip, "192.168.1.2")
        self.assertEqual(packet.protocol, "TCP")
        self.assertEqual(packet.source_port, 80)
        self.assertEqual(packet.destination_port, 12345)
        self.assertEqual(packet.packet_size, 1500)
        self.assertEqual(packet.flags, "SYN ACK")
        self.assertEqual(packet.info, "TCP 80 -> 12345")
        self.assertEqual(packet.ttl, 64)
        self.assertEqual(packet.checksum, 12345)
    
    def test_packet_info_defaults(self):
        """Test PacketInfo with defaults"""
        packet = PacketInfo(
            timestamp="12:00:00.000",
            source_ip="192.168.1.1",
            destination_ip="192.168.1.2",
            protocol="TCP",
            source_port=None,
            destination_port=None,
            packet_size=100,
            flags=None,
            info="Test"
        )
        
        self.assertIsNone(packet.source_port)
        self.assertIsNone(packet.destination_port)
        self.assertIsNone(packet.flags)
        self.assertIsNone(packet.raw_data)

class TestTrafficStats(unittest.TestCase):
    """Test cases for TrafficStats"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.stats = TrafficStats()
    
    def test_initial_state(self):
        """Test initial state of TrafficStats"""
        self.assertEqual(self.stats.total_packets, 0)
        self.assertEqual(self.stats.total_bytes, 0)
        self.assertEqual(self.stats.tcp_packets, 0)
        self.assertEqual(self.stats.udp_packets, 0)
        self.assertEqual(self.stats.icmp_packets, 0)
        self.assertEqual(self.stats.arp_packets, 0)
        self.assertEqual(self.stats.other_packets, 0)
        
        # Check sets are initialized
        self.assertIsNotNone(self.stats.unique_source_ips)
        self.assertIsNotNone(self.stats.unique_destination_ips)
        self.assertEqual(len(self.stats.unique_source_ips), 0)
        self.assertEqual(len(self.stats.unique_destination_ips), 0)
    
    def test_update_stats(self):
        """Test updating statistics"""
        packet = PacketInfo(
            timestamp="12:00:00.000",
            source_ip="192.168.1.1",
            destination_ip="192.168.1.2",
            protocol="TCP",
            source_port=80,
            destination_port=12345,
            packet_size=1500,
            flags="SYN",
            info="TCP 80 -> 12345"
        )
        
        self.stats.update(packet)
        
        self.assertEqual(self.stats.total_packets, 1)
        self.assertEqual(self.stats.total_bytes, 1500)
        self.assertEqual(self.stats.tcp_packets, 1)
        self.assertEqual(len(self.stats.unique_source_ips), 1)
        self.assertEqual(len(self.stats.unique_destination_ips), 1)
        
        # Update with different protocol
        packet2 = PacketInfo(
            timestamp="12:00:00.001",
            source_ip="192.168.1.3",
            destination_ip="192.168.1.4",
            protocol="UDP",
            source_port=53,
            destination_port=12345,
            packet_size=500,
            flags=None,
            info="UDP 53 -> 12345"
        )
        
        self.stats.update(packet2)
        
        self.assertEqual(self.stats.total_packets, 2)
        self.assertEqual(self.stats.total_bytes, 2000)
        self.assertEqual(self.stats.tcp_packets, 1)
        self.assertEqual(self.stats.udp_packets, 1)
        self.assertEqual(len(self.stats.unique_source_ips), 2)
        self.assertEqual(len(self.stats.unique_destination_ips), 2)
    
    def test_get_summary(self):
        """Test get_summary method"""
        # Add some packets
        for i in range(5):
            packet = PacketInfo(
                timestamp="12:00:00.000",
                source_ip=f"192.168.1.{i}",
                destination_ip="192.168.1.100",
                protocol="TCP",
                source_port=80 + i,
                destination_port=12345,
                packet_size=100 * (i + 1),
                flags="ACK",
                info=f"TCP {80 + i} -> 12345"
            )
            self.stats.update(packet)
        
        self.stats.start_time = time.time() - 10  # 10 seconds ago
        self.stats.end_time = time.time()
        
        summary = self.stats.get_summary()
        
        self.assertIn('duration_seconds', summary)
        self.assertIn('total_packets', summary)
        self.assertIn('total_bytes', summary)
        self.assertIn('packets_per_second', summary)
        self.assertIn('bytes_per_second', summary)
        self.assertIn('unique_source_ips', summary)
        self.assertIn('unique_destination_ips', summary)
        self.assertIn('protocol_distribution', summary)
        
        self.assertEqual(summary['total_packets'], 5)
        self.assertEqual(summary['unique_source_ips'], 5)
        self.assertEqual(summary['unique_destination_ips'], 1)
        self.assertGreater(summary['duration_seconds'], 0)

class TestNetworkSniffer(unittest.TestCase):
    """Test cases for NetworkSniffer"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.sniffer = NetworkSniffer(verbose=False)
    
    def test_initial_state(self):
        """Test initial state of NetworkSniffer"""
        self.assertEqual(len(self.sniffer.captured_packets), 0)
        self.assertIsInstance(self.sniffer.traffic_stats, TrafficStats)
        self.assertFalse(self.sniffer.is_sniffing)
        self.assertIsNone(self.sniffer.sniff_thread)
        self.assertIsNone(self.sniffer.ip_filter)
        self.assertIsNone(self.sniffer.port_filter)
        self.assertIsNone(self.sniffer.protocol_filter)
    
    def test_build_bpf_filter(self):
        """Test BPF filter building"""
        # Test with no filters
        filter_str = self.sniffer._build_bpf_filter()
        self.assertEqual(filter_str, '')
        
        # Test with IP filter
        self.sniffer.ip_filter = "192.168.1.1"
        filter_str = self.sniffer._build_bpf_filter()
        self.assertEqual(filter_str, "host 192.168.1.1")
        
        # Test with IP and port filter
        self.sniffer.port_filter = "80"
        filter_str = self.sniffer._build_bpf_filter()
        self.assertEqual(filter_str, "host 192.168.1.1 and port 80")
        
        # Test with IP, port, and protocol filter
        self.sniffer.protocol_filter = "tcp"
        filter_str = self.sniffer._build_bpf_filter()
        self.assertEqual(filter_str, "host 192.168.1.1 and port 80 and tcp")
        
        # Reset filters
        self.sniffer.ip_filter = None
        self.sniffer.port_filter = None
        self.sniffer.protocol_filter = None
    
    def test_set_filter(self):
        """Test set_filter method"""
        self.sniffer.set_filter(ip="192.168.1.1", port=80, protocol="tcp")
        
        self.assertEqual(self.sniffer.ip_filter, "192.168.1.1")
        self.assertEqual(self.sniffer.port_filter, 80)
        self.assertEqual(self.sniffer.protocol_filter, "tcp")
    
    @patch('src.sniffer.sniff')
    def test_start_sniffing(self, mock_sniff):
        """Test start_sniffing method (mocked)"""
        # Mock sniff to do nothing
        mock_sniff.return_value = None
        
        # Test with count parameter
        packets = self.sniffer.start_sniffing(packet_count=10)
        
        # Verify sniff was called
        mock_sniff.assert_called_once()
        
        # Check call arguments
        call_args = mock_sniff.call_args[1]
        self.assertEqual(call_args.get('count'), 10)
        self.assertEqual(call_args.get('store'), 0)
        
        # Should return empty list (since we mocked sniff)
        self.assertEqual(packets, [])
    
    def test_parse_packet(self):
        """Test packet parsing (basic functionality)"""
        # Create a mock scapy packet
        mock_packet = MagicMock()
        
        # Mock Ethernet layer
        mock_ether = MagicMock()
        mock_packet.__contains__.return_value = True
        mock_packet.__getitem__.side_effect = lambda x: {
            'Ether': mock_ether,
            'IP': MagicMock(src="192.168.1.1", dst="192.168.1.2", ttl=64, chksum=12345),
            'TCP': MagicMock(sport=80, dport=12345, flags=0x12),  # SYN-ACK
            'Raw': MagicMock(load=b'HTTP/1.1 200 OK')
        }.get(x, MagicMock())
        
        # Mock haslayer
        mock_packet.haslayer.return_value = True
        
        # Mock len
        mock_packet.__len__.return_value = 1500
        
        # Parse packet
        packet_info = self.sniffer._parse_packet(mock_packet)
        
        # Should return PacketInfo object
        self.assertIsNotNone(packet_info)
        self.assertIsInstance(packet_info, PacketInfo)
        
        # Check fields
        self.assertEqual(packet_info.source_ip, "192.168.1.1")
        self.assertEqual(packet_info.destination_ip, "192.168.1.2")
        self.assertEqual(packet_info.protocol, "TCP")
        self.assertEqual(packet_info.source_port, 80)
        self.assertEqual(packet_info.destination_port, 12345)
        self.assertEqual(packet_info.packet_size, 1500)
        self.assertIn("SYN", packet_info.flags)
        self.assertIn("ACK", packet_info.flags)
        self.assertEqual(packet_info.ttl, 64)
        self.assertEqual(packet_info.checksum, 12345)
    
    def test_display_packet(self):
        """Test packet display (should not crash)"""
        packet = PacketInfo(
            timestamp="12:00:00.000",
            source_ip="192.168.1.1",
            destination_ip="192.168.1.2",
            protocol="TCP",
            source_port=80,
            destination_port=12345,
            packet_size=1500,
            flags="SYN ACK",
            info="TCP 80 -> 12345"
        )
        
        # Just test that it doesn't crash
        try:
            self.sniffer._display_packet(packet)
            success = True
        except Exception:
            success = False
        
        self.assertTrue(success)
    
    def test_traffic_statistics(self):
        """Test traffic statistics collection"""
        # Add some packets
        packets = [
            PacketInfo(
                timestamp="12:00:00.000",
                source_ip="192.168.1.1",
                destination_ip="192.168.1.2",
                protocol="TCP",
                source_port=80,
                destination_port=12345,
                packet_size=1000,
                flags="SYN",
                info="TCP 80 -> 12345"
            ),
            PacketInfo(
                timestamp="12:00:00.001",
                source_ip="192.168.1.2",
                destination_ip="192.168.1.1",
                protocol="TCP",
                source_port=12345,
                destination_port=80,
                packet_size=500,
                flags="ACK",
                info="TCP 12345 -> 80"
            ),
            PacketInfo(
                timestamp="12:00:00.002",
                source_ip="192.168.1.3",
                destination_ip="192.168.1.4",
                protocol="UDP",
                source_port=53,
                destination_port=12345,
                packet_size=200,
                flags=None,
                info="UDP 53 -> 12345"
            )
        ]
        
        # Process packets
        for packet in packets:
            self.sniffer.captured_packets.append(packet)
            self.sniffer.traffic_stats.update(packet)
        
        # Check statistics
        self.assertEqual(self.sniffer.traffic_stats.total_packets, 3)
        self.assertEqual(self.sniffer.traffic_stats.total_bytes, 1700)
        self.assertEqual(self.sniffer.traffic_stats.tcp_packets, 2)
        self.assertEqual(self.sniffer.traffic_stats.udp_packets, 1)
        self.assertEqual(len(self.sniffer.traffic_stats.unique_source_ips), 3)
        self.assertEqual(len(self.sniffer.traffic_stats.unique_destination_ips), 3)
    
    def test_get_top_talkers(self):
        """Test top talkers calculation"""
        # Add packets from different sources
        sources = ["192.168.1.1", "192.168.1.2", "192.168.1.1", "192.168.1.3", "192.168.1.1"]
        
        for i, src in enumerate(sources):
            packet = PacketInfo(
                timestamp=f"12:00:00.{i:03d}",
                source_ip=src,
                destination_ip="192.168.1.100",
                protocol="TCP",
                source_port=80 + i,
                destination_port=12345,
                packet_size=100,
                flags="ACK",
                info=f"TCP {80 + i} -> 12345"
            )
            self.sniffer.captured_packets.append(packet)
        
        # Get top talkers
        top_talkers = self.sniffer.get_top_talkers(limit=2)
        
        self.assertEqual(len(top_talkers), 2)
        
        # 192.168.1.1 should be first (3 packets)
        self.assertEqual(top_talkers[0][0], "192.168.1.1")
        self.assertEqual(top_talkers[0][1], 3)
        
        # 192.168.1.2 and 192.168.1.3 should tie for second (1 packet each)
        self.assertEqual(top_talkers[1][1], 1)

if __name__ == '__main__':
    unittest.main()