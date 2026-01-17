#!/usr/bin/env python3
"""
Unit tests for scanner module
"""

import unittest
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.scanner import AdvancedPortScanner, PortResult
from unittest.mock import patch, MagicMock

class TestPortScanner(unittest.TestCase):
    """Test cases for PortScanner"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.scanner = AdvancedPortScanner(max_threads=10, timeout=0.1)
    
    def test_port_result_creation(self):
        """Test PortResult dataclass"""
        result = PortResult(
            port=80,
            protocol='tcp',
            state='open',
            service='http',
            banner='Apache/2.4.41'
        )
        
        self.assertEqual(result.port, 80)
        self.assertEqual(result.protocol, 'tcp')
        self.assertEqual(result.state, 'open')
        self.assertEqual(result.service, 'http')
        self.assertEqual(result.banner, 'Apache/2.4.41')
    
    def test_service_database_loading(self):
        """Test service database loading"""
        self.assertIn(22, self.scanner.service_db)
        self.assertEqual(self.scanner.service_db[22]['name'], 'ssh')
    
    @patch('socket.socket')
    def test_tcp_connect_scan_open_port(self, mock_socket):
        """Test TCP connect scan with open port"""
        # Mock socket behavior
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0  # Port open
        mock_socket.return_value = mock_sock
        
        # Mock banner grabbing
        with patch.object(self.scanner, '_grab_banner', return_value='Test Banner'):
            with patch.object(self.scanner, '_identify_service', return_value='test-service'):
                results = self.scanner.tcp_connect_scan('127.0.0.1', [80])
        
        self.assertIn(80, results)
        self.assertEqual(results[80].state, 'open')
        self.assertEqual(results[80].service, 'test-service')
    
    @patch('socket.socket')
    def test_tcp_connect_scan_closed_port(self, mock_socket):
        """Test TCP connect scan with closed port"""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 1  # Port closed
        mock_socket.return_value = mock_sock
        
        results = self.scanner.tcp_connect_scan('127.0.0.1', [9999])
        
        self.assertIn(9999, results)
        self.assertEqual(results[9999].state, 'closed')
    
    def test_identify_service(self):
        """Test service identification"""
        # Test known ports
        self.assertEqual(self.scanner._identify_service(22), 'ssh')
        self.assertEqual(self.scanner._identify_service(80), 'http')
        self.assertEqual(self.scanner._identify_service(443), 'https')
        
        # Test unknown port
        self.assertEqual(self.scanner._identify_service(99999), 'unknown')
    
    def test_grab_banner(self):
        """Test banner grabbing"""
        # This is a basic test - actual banner grabbing requires network
        # We'll test the method exists and returns appropriate types
        result = self.scanner._grab_banner('127.0.0.1', 80)
        
        # Result should be either None or a string
        self.assertTrue(result is None or isinstance(result, str))
    
    def test_common_ports_list(self):
        """Test common ports list"""
        self.assertIsInstance(self.scanner.common_ports, dict)
        self.assertIn('tcp', self.scanner.common_ports)
        self.assertIn('udp', self.scanner.common_ports)
        
        # Check some common ports are in the list
        self.assertIn(22, self.scanner.common_ports['tcp'])
        self.assertIn(80, self.scanner.common_ports['tcp'])
        self.assertIn(443, self.scanner.common_ports['tcp'])
        self.assertIn(53, self.scanner.common_ports['udp'])
    
    def test_scan_stats(self):
        """Test scan statistics"""
        # Initial stats should be zero
        self.assertEqual(self.scanner.scan_stats['total_ports'], 0)
        self.assertEqual(self.scanner.scan_stats['open_ports'], 0)
        
        # After a scan, stats should be updated
        # (We'll mock a simple scan)
        with patch.object(self.scanner, 'tcp_connect_scan') as mock_scan:
            mock_scan.return_value = {80: PortResult(80, 'tcp', 'open', 'http')}
            
            results = self.scanner.comprehensive_scan('127.0.0.1', '80-80')
            
            # Stats should be updated
            self.assertGreater(self.scanner.scan_stats['total_ports'], 0)
            self.assertGreater(self.scanner.scan_stats['open_ports'], 0)
    
    def test_report_generation(self):
        """Test report generation"""
        # Create mock results
        results = {
            80: PortResult(80, 'tcp', 'open', 'http', 'Apache/2.4'),
            22: PortResult(22, 'tcp', 'open', 'ssh', 'OpenSSH_7.9')
        }
        
        report = self.scanner.generate_report('127.0.0.1', results)
        
        # Check report structure
        self.assertIn('target', report)
        self.assertIn('timestamp', report)
        self.assertIn('scan_stats', report)
        self.assertIn('open_ports', report)
        
        self.assertEqual(report['target'], '127.0.0.1')
        self.assertEqual(len(report['open_ports']), 2)

class TestIntegration(unittest.TestCase):
    """Integration tests for scanner"""
    
    def test_localhost_scan(self):
        """Test scanning localhost (basic functionality test)"""
        scanner = AdvancedPortScanner(max_threads=5, timeout=0.5)
        
        # Scan a few common ports on localhost
        # This test verifies the scanner can run without errors
        try:
            results = scanner.tcp_connect_scan('127.0.0.1', [80, 443, 8080])
            
            # Should return results (even if all ports are closed)
            self.assertIsInstance(results, dict)
            
            # Each port should have a PortResult
            for port, result in results.items():
                self.assertIsInstance(result, PortResult)
                self.assertIn(result.state, ['open', 'closed', 'filtered'])
                
        except Exception as e:
            self.fail(f"Scanner raised exception: {e}")

if __name__ == '__main__':
    unittest.main()