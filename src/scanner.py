#!/usr/bin/env python3
"""
Port Scanner Module
Advanced port scanning with multithreading and service detection
"""

import socket
import threading
import concurrent.futures
import ipaddress
import time
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
import json
from colorama import Fore, Style
import nmap
import subprocess
import sys

@dataclass
class PortResult:
    """Data class for port scan results"""
    port: int
    protocol: str
    state: str  # open, closed, filtered
    service: str
    banner: Optional[str] = None
    version: Optional[str] = None
    cpe: Optional[str] = None
    vulnerability: Optional[str] = None

class AdvancedPortScanner:
    """Advanced port scanner with multiple scanning techniques"""
    
    def __init__(self, max_threads: int = 100, timeout: float = 1.0):
        self.max_threads = max_threads
        self.timeout = timeout
        self.results = {}
        self.scan_stats = {
            'total_ports': 0,
            'open_ports': 0,
            'closed_ports': 0,
            'filtered_ports': 0,
            'scan_duration': 0
        }
        
        # Common ports for quick scanning
        self.common_ports = {
            'tcp': [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 
                   445, 993, 995, 1723, 3306, 3389, 5900, 5985, 5986, 8080, 8443],
            'udp': [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1900, 4500]
        }
        
        # Service database
        self.service_db = self._load_service_database()
    
    def _load_service_database(self) -> Dict:
        """Load service database from file or create default"""
        services = {
            21: {'name': 'ftp', 'vulnerabilities': ['Anonymous login', 'Brute force']},
            22: {'name': 'ssh', 'vulnerabilities': ['Weak passwords', 'Outdated versions']},
            23: {'name': 'telnet', 'vulnerabilities': ['Cleartext authentication']},
            25: {'name': 'smtp', 'vulnerabilities': ['Open relay', 'Spam']},
            53: {'name': 'dns', 'vulnerabilities': ['DNS poisoning', 'Zone transfer']},
            80: {'name': 'http', 'vulnerabilities': ['Web vulnerabilities', 'Directory traversal']},
            110: {'name': 'pop3', 'vulnerabilities': ['Cleartext authentication']},
            135: {'name': 'msrpc', 'vulnerabilities': ['DCE/RPC vulnerabilities']},
            139: {'name': 'netbios-ssn', 'vulnerabilities': ['SMB vulnerabilities']},
            143: {'name': 'imap', 'vulnerabilities': ['Cleartext authentication']},
            443: {'name': 'https', 'vulnerabilities': ['SSL/TLS vulnerabilities']},
            445: {'name': 'microsoft-ds', 'vulnerabilities': ['EternalBlue', 'SMB vulnerabilities']},
            3306: {'name': 'mysql', 'vulnerabilities': ['Weak authentication', 'SQL injection']},
            3389: {'name': 'ms-wbt-server', 'vulnerabilities': ['BlueKeep', 'RDP vulnerabilities']},
            5900: {'name': 'vnc', 'vulnerabilities': ['Weak authentication']},
            8080: {'name': 'http-proxy', 'vulnerabilities': ['Proxy vulnerabilities']}
        }
        return services
    
    def tcp_connect_scan(self, target: str, ports: List[int]) -> Dict[int, PortResult]:
        """TCP Connect scan - most reliable but easily detected"""
        start_time = time.time()
        open_ports = {}
        
        def scan_port(port: int):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((target, port))
                
                if result == 0:
                    # Port is open
                    banner = self._grab_banner(target, port)
                    service = self._identify_service(port)
                    
                    result_obj = PortResult(
                        port=port,
                        protocol='tcp',
                        state='open',
                        service=service,
                        banner=banner
                    )
                    
                    # Check for vulnerabilities
                    if port in self.service_db:
                        result_obj.vulnerability = ', '.join(self.service_db[port]['vulnerabilities'])
                    
                    return port, result_obj
                else:
                    # Port is closed or filtered
                    return port, PortResult(
                        port=port,
                        protocol='tcp',
                        state='closed',
                        service='unknown'
                    )
            except socket.timeout:
                return port, PortResult(
                    port=port,
                    protocol='tcp',
                    state='filtered',
                    service='unknown'
                )
            except Exception as e:
                return port, None
            finally:
                try:
                    sock.close()
                except:
                    pass
        
        # Multithreaded scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(scan_port, port): port for port in ports}
            
            for future in concurrent.futures.as_completed(futures):
                port, result = future.result()
                if result:
                    open_ports[port] = result
        
        self.scan_stats['scan_duration'] = time.time() - start_time
        self.scan_stats['total_ports'] = len(ports)
        self.scan_stats['open_ports'] = len([p for p in open_ports.values() if p.state == 'open'])
        
        return open_ports
    
    def syn_scan(self, target: str, ports: List[int]) -> Dict[int, PortResult]:
        """SYN scan (half-open scan) - stealthier"""
        try:
            # This requires raw socket access (root/admin privileges)
            import struct
            
            results = {}
            
            def create_syn_packet(dst_ip: str, dst_port: int):
                """Create SYN packet"""
                # Implementation depends on OS
                pass
            
            print(f"{Fore.YELLOW}[*] SYN scan requires root/admin privileges")
            print(f"{Fore.YELLOW}[*] Falling back to TCP connect scan")
            
            # Fallback to TCP connect scan
            return self.tcp_connect_scan(target, ports)
            
        except ImportError:
            return self.tcp_connect_scan(target, ports)
    
    def udp_scan(self, target: str, ports: List[int]) -> Dict[int, PortResult]:
        """UDP port scanning"""
        results = {}
        
        def scan_udp_port(port: int):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                
                # Send empty packet
                sock.sendto(b'', (target, port))
                
                try:
                    data, addr = sock.recvfrom(1024)
                    # Received response - port is open
                    service = socket.getservbyport(port, 'udp') if port <= 65535 else 'unknown'
                    
                    return port, PortResult(
                        port=port,
                        protocol='udp',
                        state='open',
                        service=service,
                        banner=data.decode('utf-8', errors='ignore')[:100] if data else None
                    )
                except socket.timeout:
                    # No response - port might be open or filtered
                    return port, PortResult(
                        port=port,
                        protocol='udp',
                        state='open|filtered',
                        service='unknown'
                    )
            except Exception:
                return port, None
            finally:
                try:
                    sock.close()
                except:
                    pass
        
        # Limited threading for UDP (ICMP rate limiting)
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(scan_udp_port, port): port for port in ports}
            
            for future in concurrent.futures.as_completed(futures):
                port, result = future.result()
                if result:
                    results[port] = result
        
        return results
    
    def nmap_scan(self, target: str, arguments: str = "-sS -sV -O") -> Dict:
        """Integrate with nmap for advanced scanning"""
        try:
            nm = nmap.PortScanner()
            print(f"{Fore.CYAN}[*] Starting nmap scan: {arguments}")
            
            nm.scan(target, arguments=arguments)
            
            results = {}
            if target in nm.all_hosts():
                for proto in nm[target].all_protocols():
                    for port in nm[target][proto].keys():
                        port_info = nm[target][proto][port]
                        
                        result = PortResult(
                            port=port,
                            protocol=proto,
                            state=port_info['state'],
                            service=port_info['name'],
                            version=port_info.get('version', ''),
                            cpe=port_info.get('cpe', '')
                        )
                        results[port] = result
            
            return results
        except Exception as e:
            print(f"{Fore.RED}[-] Nmap scan failed: {e}")
            return {}
    
    def comprehensive_scan(self, target: str, port_range: str = "1-1000") -> Dict:
        """Comprehensive scan combining multiple techniques"""
        print(f"{Fore.CYAN}[*] Starting comprehensive scan on {target}")
        
        all_results = {}
        
        # Parse port range
        if '-' in port_range:
            start, end = map(int, port_range.split('-'))
            ports = list(range(start, end + 1))
        elif ',' in port_range:
            ports = list(map(int, port_range.split(',')))
        else:
            ports = [int(port_range)]
        
        # Step 1: Quick scan of common ports
        print(f"{Fore.YELLOW}[*] Step 1: Scanning common ports")
        common_results = self.tcp_connect_scan(target, self.common_ports['tcp'])
        all_results.update(common_results)
        
        # Step 2: Full TCP scan
        print(f"{Fore.YELLOW}[*] Step 2: Full TCP port scan")
        tcp_results = self.tcp_connect_scan(target, ports)
        all_results.update(tcp_results)
        
        # Step 3: UDP scan on common UDP ports
        print(f"{Fore.YELLOW}[*] Step 3: UDP port scan")
        udp_results = self.udp_scan(target, self.common_ports['udp'])
        all_results.update(udp_results)
        
        # Step 4: Service version detection
        print(f"{Fore.YELLOW}[*] Step 4: Service version detection")
        self._detect_service_versions(target, all_results)
        
        return all_results
    
    def _grab_banner(self, target: str, port: int, timeout: float = 2.0) -> Optional[str]:
        """Attempt to grab banner from open port"""
        try:
            socket.setdefaulttimeout(timeout)
            sock = socket.socket()
            sock.connect((target, port))
            
            # Try different banner grabbing techniques
            banners = []
            
            # HTTP banner
            if port in [80, 443, 8080, 8443]:
                try:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        banners.append(f"HTTP: {banner.split('\\r\\n')[0]}")
                except:
                    pass
            
            # SSH banner
            elif port == 22:
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        banners.append(f"SSH: {banner}")
                except:
                    pass
            
            # FTP banner
            elif port == 21:
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        banners.append(f"FTP: {banner}")
                except:
                    pass
            
            # SMTP banner
            elif port == 25:
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        banners.append(f"SMTP: {banner}")
                except:
                    pass
            
            # Generic banner grab
            if not banners:
                try:
                    sock.send(b'\r\n\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner and len(banner) > 3:
                        banners.append(f"Generic: {banner[:100]}")
                except:
                    pass
            
            sock.close()
            
            return ' | '.join(banners) if banners else None
            
        except Exception:
            return None
    
    def _identify_service(self, port: int) -> str:
        """Identify service based on port number"""
        try:
            return socket.getservbyport(port)
        except:
            # Common port mappings
            common_services = {
                21: 'ftp',
                22: 'ssh',
                23: 'telnet',
                25: 'smtp',
                53: 'dns',
                80: 'http',
                110: 'pop3',
                143: 'imap',
                443: 'https',
                445: 'microsoft-ds',
                3306: 'mysql',
                3389: 'rdp',
                5900: 'vnc',
                8080: 'http-proxy'
            }
            return common_services.get(port, 'unknown')
    
    def _detect_service_versions(self, target: str, results: Dict):
        """Detect service versions for open ports"""
        for port, result in results.items():
            if result.state == 'open':
                try:
                    # Simple version detection
                    if result.service == 'http' or result.service == 'https':
                        # Already done in banner grab
                        pass
                    elif result.service == 'ssh':
                        # SSH version detection
                        pass
                except:
                    continue
    
    def generate_report(self, target: str, results: Dict, output_file: str = None):
        """Generate scan report"""
        report = {
            'target': target,
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
            'scan_stats': self.scan_stats,
            'open_ports': [],
            'vulnerabilities': []
        }
        
        for port, result in results.items():
            if result.state == 'open':
                port_info = {
                    'port': result.port,
                    'protocol': result.protocol,
                    'service': result.service,
                    'banner': result.banner,
                    'version': result.version
                }
                report['open_ports'].append(port_info)
                
                if result.vulnerability:
                    report['vulnerabilities'].append({
                        'port': result.port,
                        'service': result.service,
                        'vulnerability': result.vulnerability
                    })
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"{Fore.GREEN}[+] Report saved to {output_file}")
        
        return report
    
    def display_results(self, results: Dict):
        """Display scan results in formatted table"""
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"{Fore.YELLOW}PORT SCAN RESULTS")
        print(f"{Fore.CYAN}{'='*80}")
        
        open_ports = [r for r in results.values() if r.state == 'open']
        filtered_ports = [r for r in results.values() if r.state == 'filtered']
        
        print(f"\n{Fore.GREEN}Open Ports ({len(open_ports)}):")
        print(f"{Fore.WHITE}{'-'*80}")
        
        for result in sorted(open_ports, key=lambda x: x.port):
            color = Fore.GREEN if result.state == 'open' else Fore.YELLOW
            print(f"{color}Port {result.port:5}/{result.protocol:4} - {result.service:20} ", end='')
            if result.banner:
                print(f"Banner: {result.banner[:50]}...")
            else:
                print()
            
            if result.vulnerability:
                print(f"{Fore.RED}      Vulnerabilities: {result.vulnerability}")
        
        if filtered_ports:
            print(f"\n{Fore.YELLOW}Filtered Ports ({len(filtered_ports)}):")
            print(f"{Fore.WHITE}{'-'*80}")
            for result in filtered_ports[:10]:  # Show only first 10
                print(f"{Fore.YELLOW}Port {result.port:5}/{result.protocol:4} - Filtered")
        
        print(f"\n{Fore.CYAN}Scan Statistics:")
        print(f"{Fore.WHITE}{'-'*80}")
        print(f"Total ports scanned: {self.scan_stats['total_ports']}")
        print(f"Open ports found: {self.scan_stats['open_ports']}")
        print(f"Scan duration: {self.scan_stats['scan_duration']:.2f} seconds")
        print(f"{Fore.CYAN}{'='*80}")

# CLI interface for scanner module
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Advanced Port Scanner")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", default="1-1000", help="Port range (e.g., 1-1000, 22,80,443)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads")
    parser.add_argument("-o", "--output", help="Output file for report")
    parser.add_argument("-m", "--mode", default="comprehensive", 
                       choices=["tcp", "udp", "syn", "comprehensive"],
                       help="Scanning mode")
    
    args = parser.parse_args()
    
    scanner = AdvancedPortScanner(max_threads=args.threads)
    
    if args.mode == "tcp":
        # Parse ports
        if '-' in args.ports:
            start, end = map(int, args.ports.split('-'))
            ports = list(range(start, end + 1))
        else:
            ports = list(map(int, args.ports.split(',')))
        
        results = scanner.tcp_connect_scan(args.target, ports)
    elif args.mode == "comprehensive":
        results = scanner.comprehensive_scan(args.target, args.ports)
    else:
        print(f"{Fore.RED}[-] Mode {args.mode} not implemented yet")
        sys.exit(1)
    
    scanner.display_results(results)
    
    if args.output:
        scanner.generate_report(args.target, results, args.output)