#!/usr/bin/env python3
"""
Unit tests for detector module
"""

import unittest
import sys
import os
import time
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.detector import AttackDetector, SecurityAlert
from unittest.mock import patch, MagicMock

class TestSecurityAlert(unittest.TestCase):
    """Test cases for SecurityAlert"""
    
    def test_security_alert_creation(self):
        """Test SecurityAlert creation"""
        alert = SecurityAlert(
            alert_id="ALERT-001",
            alert_type="Port Scanning",
            severity="Medium",
            source_ip="192.168.1.100",
            destination_ip="192.168.1.1",
            description="Port scanning activity detected",
            timestamp="2024-01-15T12:00:00",
            evidence=["Scanned 15 different ports"],
            recommendation="Monitor source IP"
        )
        
        self.assertEqual(alert.alert_id, "ALERT-001")
        self.assertEqual(alert.alert_type, "Port Scanning")
        self.assertEqual(alert.severity, "Medium")
        self.assertEqual(alert.source_ip, "192.168.1.100")
        self.assertEqual(alert.destination_ip, "192.168.1.1")
        self.assertEqual(alert.description, "Port scanning activity detected")
        self.assertEqual(alert.timestamp, "2024-01-15T12:00:00")
        self.assertEqual(alert.evidence, ["Scanned 15 different ports"])
        self.assertEqual(alert.recommendation, "Monitor source IP")
    
    def test_to_dict_method(self):
        """Test to_dict method"""
        alert = SecurityAlert(
            alert_id="ALERT-001",
            alert_type="Test Alert",
            severity="Low",
            source_ip="192.168.1.1",
            destination_ip=None,
            description="Test description",
            timestamp="2024-01-15T12:00:00",
            evidence=["Evidence 1", "Evidence 2"],
            recommendation="Test recommendation"
        )
        
        alert_dict = alert.to_dict()
        
        self.assertIsInstance(alert_dict, dict)
        self.assertEqual(alert_dict['alert_id'], "ALERT-001")
        self.assertEqual(alert_dict['alert_type'], "Test Alert")
        self.assertEqual(alert_dict['severity'], "Low")
        self.assertEqual(alert_dict['source_ip'], "192.168.1.1")
        self.assertIsNone(alert_dict['destination_ip'])
        self.assertEqual(alert_dict['description'], "Test description")
        self.assertEqual(alert_dict['timestamp'], "2024-01-15T12:00:00")
        self.assertEqual(alert_dict['evidence'], ["Evidence 1", "Evidence 2"])
        self.assertEqual(alert_dict['recommendation'], "Test recommendation")

class TestAttackDetector(unittest.TestCase):
    """Test cases for AttackDetector"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.detector = AttackDetector()
    
    def test_initial_state(self):
        """Test initial state of AttackDetector"""
        self.assertEqual(len(self.detector.alerts), 0)
        self.assertEqual(len(self.detector.alert_counters), 0)
        
        # Check detection windows
        self.assertIn('syn_flood', self.detector.window_sizes)
        self.assertIn('port_scan', self.detector.window_sizes)
        self.assertIn('ddos', self.detector.window_sizes)
        self.assertIn('brute_force', self.detector.window_sizes)
        
        # Check thresholds
        self.assertIn('syn_flood', self.detector.thresholds)
        self.assertIn('port_scan', self.detector.thresholds)
        self.assertIn('ddos_packets', self.detector.thresholds)
        self.assertIn('ddos_sources', self.detector.thresholds)
        self.assertIn('brute_force', self.detector.thresholds)
        
        # Check data structures
        self.assertIsInstance(self.detector.syn_counter, collections.Counter)
        self.assertIsInstance(self.detector.port_scan_data, collections.defaultdict)
        self.assertIsInstance(self.detector.ddos_data, collections.defaultdict)
        self.assertIsInstance(self.detector.brute_force_data, collections.defaultdict)
        
        # Check signatures
        self.assertIn('sql_injection', self.detector.signatures)
        self.assertIn('xss', self.detector.signatures)
        self.assertIn('directory_traversal', self.detector.signatures)
    
    def test_detect_syn_flood(self):
        """Test SYN flood detection"""
        current_time = time.time()
        
        # Simulate SYN flood
        for i in range(60):  # 60 SYN packets in 10 seconds (threshold is 50)
            self.detector._detect_syn_flood(
                source_ip="192.168.1.100",
                protocol="TCP",
                flags="SYN",
                timestamp=current_time + (i * 0.1)  # 0.1 seconds apart
            )
        
        # Should generate an alert
        self.assertGreater(len(self.detector.alerts), 0)
        
        alert = self.detector.alerts[0]
        self.assertEqual(alert.alert_type, "SYN Flood Attack")
        self.assertEqual(alert.severity, "High")
        self.assertEqual(alert.source_ip, "192.168.1.100")
        self.assertIn("SYN flood", alert.description)
        self.assertIn("Detected 60 SYN packets", alert.description)
    
    def test_detect_port_scan(self):
        """Test port scan detection"""
        current_time = time.time()
        source_ip = "192.168.1.150"
        
        # Simulate port scanning (scanning 20 different ports)
        for port in range(1000, 1020):  # 20 different ports
            self.detector._detect_port_scan(
                source_ip=source_ip,
                dst_port=port,
                timestamp=current_time
            )
        
        # Should generate an alert (threshold is 15 ports)
        self.assertGreater(len(self.detector.alerts), 0)
        
        alert = self.detector.alerts[0]
        self.assertEqual(alert.alert_type, "Port Scanning")
        self.assertEqual(alert.severity, "Medium")
        self.assertEqual(alert.source_ip, source_ip)
        self.assertIn("Port scanning", alert.description)
        self.assertIn("Scanned 20 different ports", alert.description)
    
    def test_detect_ddos(self):
        """Test DDoS detection"""
        current_time = time.time()
        target_ip = "192.168.1.1"
        
        # Simulate DDoS attack
        for i in range(25):  # 25 different sources
            source_ip = f"10.0.0.{i}"
            
            # Each source sends 50 packets
            for j in range(50):
                self.detector._detect_ddos(
                    dest_ip=target_ip,
                    source_ip=source_ip,
                    timestamp=current_time
                )
        
        # Should generate an alert
        # Thresholds: ddos_packets=1000, ddos_sources=20
        # We have: 25 sources * 50 packets = 1250 packets from 25 sources
        
        alerts = [a for a in self.detector.alerts if a.alert_type == "DDoS Attack"]
        self.assertGreater(len(alerts), 0)
        
        alert = alerts[0]
        self.assertEqual(alert.alert_type, "DDoS Attack")
        self.assertEqual(alert.severity, "Critical")
        self.assertEqual(alert.destination_ip, target_ip)
        self.assertIn("DDoS", alert.description)
        self.assertIn("25 sources", alert.description)
    
    def test_detect_malicious_payload(self):
        """Test malicious payload detection"""
        # Test SQL injection
        sql_payload = b"SELECT * FROM users WHERE username = 'admin' OR '1'='1'"
        
        self.detector._detect_malicious_payload(
            raw_data=sql_payload,
            source_ip="192.168.1.100",
            dest_ip="192.168.1.1"
        )
        
        # Should generate an alert
        sql_alerts = [a for a in self.detector.alerts if "SQL" in a.alert_type]
        self.assertGreater(len(sql_alerts), 0)
        
        alert = sql_alerts[0]
        self.assertIn("SQL", alert.alert_type)
        self.assertEqual(alert.severity, "High")
        self.assertEqual(alert.source_ip, "192.168.1.100")
        
        # Test XSS
        xss_payload = b"<script>alert('XSS')</script>"
        
        self.detector._detect_malicious_payload(
            raw_data=xss_payload,
            source_ip="192.168.1.101",
            dest_ip="192.168.1.1"
        )
        
        xss_alerts = [a for a in self.detector.alerts if "XSS" in a.alert_type]
        self.assertGreater(len(xss_alerts), 0)
    
    def test_analyze_vulnerabilities(self):
        """Test vulnerability analysis"""
        # Create mock open ports data
        open_ports = {
            "192.168.1.1": [
                {"port": 21, "service": "ftp"},
                {"port": 23, "service": "telnet"},  # Critical vulnerability
                {"port": 80, "service": "http"},
                {"port": 445, "service": "microsoft-ds"},  # Critical vulnerability
                {"port": 3389, "service": "ms-wbt-server"}  # High vulnerability
            ]
        }
        
        alerts = self.detector.analyze_vulnerabilities(open_ports)
        
        # Should find vulnerabilities for ports 23, 445, and 3389
        self.assertGreaterEqual(len(alerts), 3)
        
        # Check for specific vulnerabilities
        telnet_alerts = [a for a in alerts if "Telnet" in a.description]
        smb_alerts = [a for a in alerts if "SMB" in a.description or "EternalBlue" in a.description]
        rdp_alerts = [a for a in alerts if "RDP" in a.description]
        
        self.assertGreater(len(telnet_alerts), 0)
        self.assertGreater(len(smb_alerts), 0)
        self.assertGreater(len(rdp_alerts), 0)
        
        # Check severities
        for alert in telnet_alerts:
            self.assertEqual(alert.severity, "Critical")
        
        for alert in smb_alerts:
            self.assertEqual(alert.severity, "Critical")
    
    def test_generate_security_report(self):
        """Test security report generation"""
        # Create some test alerts
        alerts = [
            SecurityAlert(
                alert_id="ALERT-001",
                alert_type="Test Alert 1",
                severity="High",
                source_ip="192.168.1.100",
                destination_ip="192.168.1.1",
                description="Test description 1",
                timestamp="2024-01-15T12:00:00",
                evidence=["Evidence 1"],
                recommendation="Recommendation 1"
            ),
            SecurityAlert(
                alert_id="ALERT-002",
                alert_type="Test Alert 2",
                severity="Medium",
                source_ip="192.168.1.101",
                destination_ip=None,
                description="Test description 2",
                timestamp="2024-01-15T12:01:00",
                evidence=["Evidence 2"],
                recommendation="Recommendation 2"
            )
        ]
        
        report = self.detector.generate_security_report(alerts)
        
        # Check report structure
        self.assertIn('generated_at', report)
        self.assertIn('total_alerts', report)
        self.assertIn('alert_summary', report)
        self.assertIn('severity_summary', report)
        self.assertIn('top_source_ips', report)
        self.assertIn('alerts', report)
        
        self.assertEqual(report['total_alerts'], 2)
        self.assertEqual(report['alert_summary']['Test Alert 1'], 1)
        self.assertEqual(report['alert_summary']['Test Alert 2'], 1)
        self.assertEqual(report['severity_summary']['High'], 1)
        self.assertEqual(report['severity_summary']['Medium'], 1)
        self.assertEqual(len(report['alerts']), 2)
    
    def test_get_recommendations(self):
        """Test security recommendations"""
        # Add some alerts to trigger recommendations
        current_time = time.time()
        
        # Add SYN flood alert
        for i in range(60):
            self.detector._detect_syn_flood(
                source_ip="192.168.1.100",
                protocol="TCP",
                flags="SYN",
                timestamp=current_time + (i * 0.1)
            )
        
        # Add port scan alert
        for port in range(1000, 1020):
            self.detector._detect_port_scan(
                source_ip="192.168.1.150",
                dst_port=port,
                timestamp=current_time
            )
        
        # Get recommendations
        recommendations = self.detector.get_recommendations()
        
        self.assertGreater(len(recommendations), 0)
        
        # Check for specific recommendations
        syn_recs = [r for r in recommendations if "SYN" in r]
        port_scan_recs = [r for r in recommendations if "port scan" in r.lower()]
        
        self.assertGreater(len(syn_recs), 0)
        self.assertGreater(len(port_scan_recs), 0)
        
        # Check general recommendations are included
        general_recs = [r for r in recommendations if "update" in r.lower() or "patch" in r.lower()]
        self.assertGreater(len(general_recs), 0)
    
    def test_display_alerts(self):
        """Test alert display (should not crash)"""
        # Create test alerts
        alerts = [
            SecurityAlert(
                alert_id="ALERT-001",
                alert_type="Critical Alert",
                severity="Critical",
                source_ip="192.168.1.100",
                destination_ip="192.168.1.1",
                description="Critical security issue",
                timestamp="2024-01-15T12:00:00",
                evidence=["Evidence"],
                recommendation="Fix immediately"
            ),
            SecurityAlert(
                alert_id="ALERT-002",
                alert_type="Medium Alert",
                severity="Medium",
                source_ip="192.168.1.101",
                destination_ip=None,
                description="Medium security issue",
                timestamp="2024-01-15T12:01:00",
                evidence=["Evidence"],
                recommendation="Fix soon"
            )
        ]
        
        # Test that display doesn't crash
        try:
            self.detector.display_alerts(alerts)
            success = True
        except Exception as e:
            print(f"Display error: {e}")
            success = False
        
        self.assertTrue(success)

class TestIntegration(unittest.TestCase):
    """Integration tests for detector"""
    
    def test_analyze_packets_integration(self):
        """Test packet analysis integration"""
        detector = AttackDetector()
        
        # Create mock packets
        packets = []
        current_time = time.time()
        
        # Add SYN packets for SYN flood detection
        for i in range(60):
            packets.append({
                'source_ip': '192.168.1.100',
                'destination_ip': '192.168.1.1',
                'protocol': 'TCP',
                'source_port': 12345 + i,
                'destination_port': 80,
                'flags': 'SYN',
                'info': f'TCP {12345 + i} -> 80 [SYN]',
                'raw_data': b''
            })
        
        # Add port scan packets
        for port in range(1000, 1020):
            packets.append({
                'source_ip': '192.168.1.150',
                'destination_ip': '192.168.1.1',
                'protocol': 'TCP',
                'source_port': 54321,
                'destination_port': port,
                'flags': 'SYN',
                'info': f'TCP 54321 -> {port} [SYN]',
                'raw_data': b''
            })
        
        # Analyze packets
        alerts = detector.analyze_packets(packets)
        
        # Should find at least SYN flood and port scan alerts
        self.assertGreater(len(alerts), 0)
        
        alert_types = [a.alert_type for a in alerts]
        self.assertIn("SYN Flood Attack", alert_types)
        self.assertIn("Port Scanning", alert_types)

if __name__ == '__main__':
    unittest.main()