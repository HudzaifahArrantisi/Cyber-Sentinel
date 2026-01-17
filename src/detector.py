#!/usr/bin/env python3
"""
Attack Detector Module
Detect network attacks and security threats
"""

import time
import collections
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, asdict
import json
import statistics
from colorama import Fore, Style
import ipaddress

@dataclass
class SecurityAlert:
    """Security alert container"""
    alert_id: str
    alert_type: str
    severity: str  # low, medium, high, critical
    source_ip: str
    destination_ip: Optional[str]
    description: str
    timestamp: str
    evidence: List[str]
    recommendation: str
    
    def to_dict(self):
        return asdict(self)

class AttackDetector:
    """Advanced network attack detector"""
    
    def __init__(self):
        self.alerts = []
        self.alert_counters = collections.Counter()
        
        # Detection windows (seconds)
        self.window_sizes = {
            'syn_flood': 10,      # 10-second window for SYN flood
            'port_scan': 60,      # 60-second window for port scans
            'ddos': 30,           # 30-second window for DDoS
            'brute_force': 300,   # 5-minute window for brute force
        }
        
        # Detection thresholds
        self.thresholds = {
            'syn_flood': 50,      # SYN packets per second per source
            'port_scan': 15,      # Different ports per source per minute
            'ddos_packets': 1000, # Packets per second to single target
            'ddos_sources': 20,   # Unique sources for DDoS
            'brute_force': 10,    # Failed auth attempts per minute
        }
        
        # Data structures for detection
        self.syn_counter = collections.Counter()
        self.port_scan_data = collections.defaultdict(set)
        self.ddos_data = collections.defaultdict(lambda: {'packets': 0, 'sources': set()})
        self.brute_force_data = collections.defaultdict(int)
        
        # Time windows
        self.time_windows = {
            'syn_flood': collections.deque(maxlen=1000),
            'port_scan': collections.deque(maxlen=1000),
            'ddos': collections.deque(maxlen=10000),
            'brute_force': collections.deque(maxlen=1000),
        }
        
        # Attack signatures
        self.signatures = self._load_attack_signatures()
    
    def _load_attack_signatures(self) -> Dict:
        """Load attack signatures"""
        return {
            'sql_injection': [
                "' OR '1'='1", "UNION SELECT", "DROP TABLE", "--", 
                "EXEC xp_cmdshell", "WAITFOR DELAY", "BENCHMARK",
                "SLEEP(", "PG_SLEEP(", "' OR 'a'='a"
            ],
            'xss': [
                "<script>", "javascript:", "onload=", "onerror=",
                "alert(", "document.cookie", "<iframe", "<img src=",
                "eval(", "fromCharCode"
            ],
            'directory_traversal': [
                "../", "..\\", "/etc/passwd", "C:\\Windows\\",
                "../../", "..//", "/bin/sh", "\\..\\"
            ],
            'command_injection': [
                "; ls", "| cat /etc/passwd", "`id`", "$(whoami)",
                "&& dir", "|| ping", "; rm -rf", "| net user"
            ],
            'buffer_overflow': [
                "A" * 1000, "\x90" * 500,  # NOP sled patterns
            ]
        }
    
    def analyze_packets(self, packets: List) -> List[SecurityAlert]:
        """Analyze packets for security threats"""
        print(f"{Fore.YELLOW}[*] Analyzing {len(packets)} packets for security threats...")
        
        # Reset previous analysis
        self.alerts = []
        current_time = time.time()
        
        # Clean old data from windows
        self._clean_old_data(current_time)
        
        # Process each packet
        for packet in packets:
            # Extract packet information
            # Assuming packet is a dict with specific fields
            source_ip = packet.get('source_ip', '')
            dest_ip = packet.get('destination_ip', '')
            protocol = packet.get('protocol', '')
            src_port = packet.get('source_port')
            dst_port = packet.get('destination_port')
            flags = packet.get('flags', '')
            info = packet.get('info', '')
            raw_data = packet.get('raw_data', b'')
            
            # Run detection algorithms
            self._detect_syn_flood(source_ip, protocol, flags, current_time)
            self._detect_port_scan(source_ip, dst_port, current_time)
            self._detect_ddos(dest_ip, source_ip, current_time)
            self._detect_brute_force(source_ip, dest_ip, dst_port, info, current_time)
            self._detect_malicious_payload(raw_data, source_ip, dest_ip)
            self._detect_arp_spoofing(packet)
        
        # Generate alerts from collected data
        self._generate_alerts(current_time)
        
        print(f"{Fore.GREEN}[+] Analysis complete. Found {len(self.alerts)} security alerts")
        return self.alerts
    
    def _clean_old_data(self, current_time: float):
        """Clean old data from detection windows"""
        # Clean SYN flood data
        while (self.time_windows['syn_flood'] and 
               current_time - self.time_windows['syn_flood'][0][0] > self.window_sizes['syn_flood']):
            self.time_windows['syn_flood'].popleft()
        
        # Clean port scan data
        cutoff_time = current_time - self.window_sizes['port_scan']
        old_keys = [k for k, t in self.port_scan_data.items() if t < cutoff_time]
        for key in old_keys:
            if key in self.port_scan_data:
                del self.port_scan_data[key]
        
        # Clean DDoS data
        cutoff_time = current_time - self.window_sizes['ddos']
        old_ddos = []
        for target, data in self.ddos_data.items():
            if current_time - data.get('timestamp', 0) > cutoff_time:
                old_ddos.append(target)
        for target in old_ddos:
            if target in self.ddos_data:
                del self.ddos_data[target]
    
    def _detect_syn_flood(self, source_ip: str, protocol: str, flags: str, timestamp: float):
        """Detect SYN flood attacks"""
        if protocol == 'TCP' and 'SYN' in flags and 'ACK' not in flags:
            # Add to time window
            self.time_windows['syn_flood'].append((timestamp, source_ip))
            
            # Count SYN packets from this source in the window
            window_start = timestamp - self.window_sizes['syn_flood']
            syn_count = sum(1 for t, ip in self.time_windows['syn_flood'] 
                          if ip == source_ip and t >= window_start)
            
            # Check threshold
            if syn_count > self.thresholds['syn_flood']:
                alert_id = f"SYN_FLOOD_{source_ip}_{int(timestamp)}"
                
                # Check if alert already exists
                existing = [a for a in self.alerts if a.alert_id == alert_id]
                if not existing:
                    alert = SecurityAlert(
                        alert_id=alert_id,
                        alert_type="SYN Flood Attack",
                        severity="High",
                        source_ip=source_ip,
                        destination_ip=None,
                        description=f"Potential SYN flood attack from {source_ip}. "
                                  f"Detected {syn_count} SYN packets in {self.window_sizes['syn_flood']} seconds.",
                        timestamp=datetime.fromtimestamp(timestamp).isoformat(),
                        evidence=[f"SYN packets: {syn_count}", 
                                 f"Time window: {self.window_sizes['syn_flood']}s",
                                 f"Threshold: {self.thresholds['syn_flood']}"],
                        recommendation="Enable SYN cookies, implement rate limiting, "
                                     "configure firewall rules to block source IP."
                    )
                    self.alerts.append(alert)
                    self.alert_counters['syn_flood'] += 1
    
    def _detect_port_scan(self, source_ip: str, dst_port: int, timestamp: float):
        """Detect port scanning activity"""
        if dst_port:
            key = f"{source_ip}_{int(timestamp / self.window_sizes['port_scan'])}"
            
            # Add port to scan data
            if key not in self.port_scan_data:
                self.port_scan_data[key] = set()
            
            self.port_scan_data[key].add(dst_port)
            
            # Check if scanning threshold exceeded
            unique_ports = len(self.port_scan_data[key])
            
            if unique_ports > self.thresholds['port_scan']:
                alert_id = f"PORT_SCAN_{source_ip}_{int(timestamp)}"
                
                existing = [a for a in self.alerts if a.alert_id == alert_id]
                if not existing:
                    alert = SecurityAlert(
                        alert_id=alert_id,
                        alert_type="Port Scanning",
                        severity="Medium",
                        source_ip=source_ip,
                        destination_ip=None,
                        description=f"Port scanning activity detected from {source_ip}. "
                                  f"Scanned {unique_ports} different ports in {self.window_sizes['port_scan']} seconds.",
                        timestamp=datetime.fromtimestamp(timestamp).isoformat(),
                        evidence=[f"Unique ports scanned: {unique_ports}",
                                 f"Ports: {sorted(list(self.port_scan_data[key]))[:10]}..." 
                                 if len(self.port_scan_data[key]) > 10 else 
                                 f"Ports: {sorted(list(self.port_scan_data[key]))}"],
                        recommendation="Monitor source IP, consider blocking if unauthorized. "
                                     "Implement port scan detection in IDS/IPS."
                    )
                    self.alerts.append(alert)
                    self.alert_counters['port_scan'] += 1
    
    def _detect_ddos(self, dest_ip: str, source_ip: str, timestamp: float):
        """Detect DDoS attacks"""
        if dest_ip:
            if dest_ip not in self.ddos_data:
                self.ddos_data[dest_ip] = {
                    'packets': 0,
                    'sources': set(),
                    'timestamp': timestamp
                }
            
            # Update DDoS data
            self.ddos_data[dest_ip]['packets'] += 1
            self.ddos_data[dest_ip]['sources'].add(source_ip)
            self.ddos_data[dest_ip]['timestamp'] = timestamp
            
            # Check DDoS thresholds
            data = self.ddos_data[dest_ip]
            packet_rate = data['packets'] / self.window_sizes['ddos']
            unique_sources = len(data['sources'])
            
            if (packet_rate > self.thresholds['ddos_packets'] and 
                unique_sources > self.thresholds['ddos_sources']):
                
                alert_id = f"DDOS_{dest_ip}_{int(timestamp)}"
                
                existing = [a for a in self.alerts if a.alert_id == alert_id]
                if not existing:
                    alert = SecurityAlert(
                        alert_id=alert_id,
                        alert_type="DDoS Attack",
                        severity="Critical",
                        source_ip="Multiple",
                        destination_ip=dest_ip,
                        description=f"Potential DDoS attack targeting {dest_ip}. "
                                  f"{data['packets']} packets from {unique_sources} sources "
                                  f"in {self.window_sizes['ddos']} seconds.",
                        timestamp=datetime.fromtimestamp(timestamp).isoformat(),
                        evidence=[f"Target: {dest_ip}",
                                 f"Packet rate: {packet_rate:.1f}/s",
                                 f"Unique sources: {unique_sources}",
                                 f"Sample sources: {list(data['sources'])[:5]}"],
                        recommendation="Activate DDoS protection measures, contact ISP, "
                                     "implement rate limiting, use CDN protection."
                    )
                    self.alerts.append(alert)
                    self.alert_counters['ddos'] += 1
    
    def _detect_brute_force(self, source_ip: str, dest_ip: str, dst_port: int, info: str, timestamp: float):
        """Detect brute force attacks"""
        # Common brute force indicators
        brute_force_ports = [22, 23, 3389, 5900]  # SSH, Telnet, RDP, VNC
        failure_indicators = ['Failed password', 'Invalid credentials', 'Login failed', 
                             'Authentication failed', 'Access denied']
        
        if dst_port in brute_force_ports:
            key = f"{source_ip}_{dest_ip}_{dst_port}"
            
            # Check for failure indicators
            if any(indicator.lower() in info.lower() for indicator in failure_indicators):
                self.brute_force_data[key] += 1
                
                # Check time window
                window_start = timestamp - self.window_sizes['brute_force']
                # Simplified: just check count
                if self.brute_force_data[key] > self.thresholds['brute_force']:
                    alert_id = f"BRUTE_FORCE_{source_ip}_{dest_ip}_{int(timestamp)}"
                    
                    existing = [a for a in self.alerts if a.alert_id == alert_id]
                    if not existing:
                        service = {22: 'SSH', 23: 'Telnet', 3389: 'RDP', 5900: 'VNC'}.get(dst_port, f'Port {dst_port}')
                        
                        alert = SecurityAlert(
                            alert_id=alert_id,
                            alert_type="Brute Force Attack",
                            severity="High",
                            source_ip=source_ip,
                            destination_ip=dest_ip,
                            description=f"Potential brute force attack on {service} at {dest_ip} from {source_ip}. "
                                      f"{self.brute_force_data[key]} failed attempts detected.",
                            timestamp=datetime.fromtimestamp(timestamp).isoformat(),
                            evidence=[f"Target service: {service}",
                                     f"Target: {dest_ip}:{dst_port}",
                                     f"Failed attempts: {self.brute_force_data[key]}",
                                     f"Attack indicator: {info}"],
                            recommendation="Implement account lockout policy, use strong passwords, "
                                         "enable two-factor authentication, whitelist allowed IPs."
                        )
                        self.alerts.append(alert)
                        self.alert_counters['brute_force'] += 1
    
    def _detect_malicious_payload(self, raw_data: bytes, source_ip: str, dest_ip: str):
        """Detect malicious payloads in packet data"""
        if not raw_data:
            return
        
        try:
            data_str = raw_data.decode('utf-8', errors='ignore').lower()
            
            for attack_type, signatures in self.signatures.items():
                for signature in signatures:
                    if signature.lower() in data_str:
                        alert_id = f"MALICIOUS_{attack_type}_{source_ip}_{int(time.time())}"
                        
                        existing = [a for a in self.alerts if a.alert_id == alert_id]
                        if not existing:
                            # Extract context around the signature
                            idx = data_str.find(signature.lower())
                            start = max(0, idx - 50)
                            end = min(len(data_str), idx + len(signature) + 50)
                            context = data_str[start:end]
                            
                            alert = SecurityAlert(
                                alert_id=alert_id,
                                alert_type=f"{attack_type.upper()} Attempt",
                                severity="High",
                                source_ip=source_ip,
                                destination_ip=dest_ip,
                                description=f"Potential {attack_type} attempt detected from {source_ip} to {dest_ip}",
                                timestamp=datetime.now().isoformat(),
                                evidence=[f"Signature: {signature}",
                                         f"Context: ...{context}..."],
                                recommendation=f"Block source IP, implement WAF rules for {attack_type}, "
                                             "sanitize user input, use parameterized queries."
                            )
                            self.alerts.append(alert)
                            self.alert_counters[attack_type] += 1
                        break  # Only alert once per attack type per packet
        except:
            pass
    
    def _detect_arp_spoofing(self, packet):
        """Detect ARP spoofing attacks"""
        # Simplified ARP spoofing detection
        # In real implementation, would track IP-MAC mappings
        pass
    
    def _generate_alerts(self, current_time: float):
        """Generate alerts from collected data"""
        # Additional alert generation logic can go here
        pass
    
    def analyze_vulnerabilities(self, open_ports: Dict) -> List[SecurityAlert]:
        """Analyze open ports for vulnerabilities"""
        print(f"{Fore.YELLOW}[*] Analyzing {len(open_ports)} open ports for vulnerabilities...")
        
        vulnerability_alerts = []
        
        # Common vulnerable services
        vulnerable_services = {
            21: ('FTP', 'Anonymous login enabled, weak authentication', 'High'),
            22: ('SSH', 'Outdated version or weak passwords', 'Medium'),
            23: ('Telnet', 'Cleartext authentication', 'Critical'),
            80: ('HTTP', 'Potential web vulnerabilities', 'Medium'),
            443: ('HTTPS', 'SSL/TLS vulnerabilities', 'Medium'),
            445: ('SMB', 'EternalBlue vulnerability possible', 'Critical'),
            3389: ('RDP', 'BlueKeep vulnerability possible', 'High'),
            5900: ('VNC', 'Weak or no authentication', 'High'),
            27017: ('MongoDB', 'Unauthenticated access', 'Critical'),
            9200: ('Elasticsearch', 'Unauthenticated access', 'High'),
            11211: ('Memcached', 'Unauthenticated UDP access', 'Critical'),
        }
        
        for ip, ports in open_ports.items():
            for port_info in ports:
                port = port_info.get('port')
                
                if port in vulnerable_services:
                    service, risk, severity = vulnerable_services[port]
                    
                    alert = SecurityAlert(
                        alert_id=f"VULN_{ip}_{port}_{int(time.time())}",
                        alert_type="Vulnerable Service",
                        severity=severity,
                        source_ip=ip,
                        destination_ip=None,
                        description=f"Vulnerable service detected: {service} on port {port} at {ip}",
                        timestamp=datetime.now().isoformat(),
                        evidence=[f"Service: {service} on port {port}",
                                 f"Risk: {risk}",
                                 f"IP Address: {ip}"],
                        recommendation=f"Secure {service} service, update to latest version, "
                                     "implement access controls, disable if not needed."
                    )
                    vulnerability_alerts.append(alert)
        
        return vulnerability_alerts
    
    def display_alerts(self, alerts: List[SecurityAlert] = None):
        """Display security alerts"""
        if alerts is None:
            alerts = self.alerts
        
        if not alerts:
            print(f"\n{Fore.GREEN}[+] No security alerts detected")
            return
        
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"{Fore.YELLOW}SECURITY ALERTS ({len(alerts)} found)")
        print(f"{Fore.CYAN}{'='*80}")
        
        # Group alerts by severity
        severity_groups = {'Critical': [], 'High': [], 'Medium': [], 'Low': []}
        
        for alert in alerts:
            severity_groups[alert.severity].append(alert)
        
        # Display by severity
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            group = severity_groups[severity]
            if group:
                # Color code by severity
                if severity == 'Critical':
                    color = Fore.RED + Style.BRIGHT
                elif severity == 'High':
                    color = Fore.RED
                elif severity == 'Medium':
                    color = Fore.YELLOW
                else:
                    color = Fore.BLUE
                
                print(f"\n{color}{severity} Alerts ({len(group)}):")
                print(f"{Fore.WHITE}{'-'*80}")
                
                for i, alert in enumerate(group[:5], 1):  # Show max 5 per severity
                    print(f"{color}{i}. {alert.alert_type}")
                    print(f"{Fore.WHITE}   Source: {alert.source_ip}")
                    if alert.destination_ip:
                        print(f"   Target: {alert.destination_ip}")
                    print(f"   Description: {alert.description[:100]}...")
                    
                    # Show first evidence item
                    if alert.evidence:
                        print(f"   Evidence: {alert.evidence[0]}")
                    
                    print()
                
                if len(group) > 5:
                    print(f"{Fore.YELLOW}   ... and {len(group) - 5} more {severity.lower()} alerts")
        
        print(f"{Fore.CYAN}{'='*80}")
        
        # Display alert statistics
        print(f"\n{Fore.GREEN}Alert Statistics:")
        print(f"{Fore.WHITE}{'-'*80}")
        for alert_type, count in self.alert_counters.most_common():
            print(f"{Fore.CYAN}{alert_type.replace('_', ' ').title()}: {count}")
        print(f"{Fore.WHITE}{'-'*80}")
    
    def generate_security_report(self, alerts: List[SecurityAlert], output_file: str = None):
        """Generate comprehensive security report"""
        report = {
            'generated_at': datetime.now().isoformat(),
            'total_alerts': len(alerts),
            'alert_summary': collections.Counter(a.alert_type for a in alerts),
            'severity_summary': collections.Counter(a.severity for a in alerts),
            'top_source_ips': collections.Counter(a.source_ip for a in alerts if a.source_ip).most_common(10),
            'alerts': [a.to_dict() for a in alerts]
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            print(f"{Fore.GREEN}[+] Security report saved to {output_file}")
        
        return report
    
    def get_recommendations(self) -> List[str]:
        """Get security recommendations based on detected threats"""
        recommendations = []
        
        if self.alert_counters['syn_flood'] > 0:
            recommendations.extend([
                "Enable SYN cookies on critical servers",
                "Implement rate limiting for TCP connections",
                "Configure firewall to block SYN flood sources"
            ])
        
        if self.alert_counters['port_scan'] > 0:
            recommendations.extend([
                "Implement port scan detection in IDS/IPS",
                "Use firewall rules to limit connection attempts",
                "Consider using port knocking for sensitive services"
            ])
        
        if self.alert_counters['ddos'] > 0:
            recommendations.extend([
                "Activate DDoS protection service",
                "Implement rate limiting and connection throttling",
                "Use Content Delivery Network (CDN) for web services"
            ])
        
        if self.alert_counters['brute_force'] > 0:
            recommendations.extend([
                "Implement account lockout policies",
                "Use two-factor authentication",
                "Restrict access to management interfaces by IP"
            ])
        
        # General recommendations
        recommendations.extend([
            "Regularly update and patch all systems",
            "Implement network segmentation",
            "Use encrypted protocols (SSH, HTTPS, VPN)",
            "Regular security audits and penetration testing",
            "Employee security awareness training"
        ])
        
        return list(set(recommendations))  # Remove duplicates

# CLI interface for detector module
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Network Attack Detector")
    parser.add_argument("-i", "--input", help="Input JSON file with captured packets")
    parser.add_argument("-o", "--output", help="Output file for security report")
    parser.add_argument("-p", "--ports", help="JSON file with port scan results")
    
    args = parser.parse_args()
    
    detector = AttackDetector()
    
    alerts = []
    
    # Analyze packets if input file provided
    if args.input:
        try:
            with open(args.input, 'r') as f:
                packets = json.load(f).get('packets', [])
            
            packet_alerts = detector.analyze_packets(packets)
            alerts.extend(packet_alerts)
        except Exception as e:
            print(f"{Fore.RED}[-] Error loading packet file: {e}")
    
    # Analyze vulnerabilities if ports file provided
    if args.ports:
        try:
            with open(args.ports, 'r') as f:
                port_data = json.load(f)
                open_ports = port_data.get('open_ports', {})
            
            vuln_alerts = detector.analyze_vulnerabilities(open_ports)
            alerts.extend(vuln_alerts)
        except Exception as e:
            print(f"{Fore.RED}[-] Error loading port file: {e}")
    
    # Display results
    detector.display_alerts(alerts)
    
    # Generate recommendations
    recommendations = detector.get_recommendations()
    if recommendations:
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"{Fore.YELLOW}SECURITY RECOMMENDATIONS")
        print(f"{Fore.CYAN}{'='*80}")
        for i, rec in enumerate(recommendations, 1):
            print(f"{Fore.GREEN}{i}. {rec}")
        print(f"{Fore.CYAN}{'='*80}")
    
    # Generate report
    if args.output:
        detector.generate_security_report(alerts, args.output)