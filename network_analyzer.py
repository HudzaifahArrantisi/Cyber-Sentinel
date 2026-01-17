#!/usr/bin/env python3
"""
Web Security Final Project - Advanced Network Security Analyzer
Author: Cybersecurity Student
Features: Port Scanning, Active User Detection, Network Sniffing, Attack Analysis
"""

import sys
import socket
import threading
import time
import ipaddress
import subprocess
import platform
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict, Counter
import json
from colorama import init, Fore, Style, Back
try:
    import netifaces
except ImportError:
    import netifaces_plus as netifaces
import requests
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
import psutil
import warnings
from tabulate import tabulate
from tqdm import tqdm
import itertools
import threading as thread

# Suppress Scapy warnings
warnings.filterwarnings("ignore", category=UserWarning)

init(autoreset=True)  # Initialize colorama

class NetworkSecurityAnalyzer:
    def __init__(self):
        self.open_ports = {}
        self.active_hosts = {}
        self.network_traffic = []
        self.detected_attacks = []
        self.interface = None
        self.network_range = None
        self.sniffing = False
        self.scan_stats = {
            'hosts_scanned': 0,
            'ports_scanned': 0,
            'open_ports_found': 0,
            'scan_start_time': None,
            'scan_duration': 0
        }
        
    def banner(self):
        """Display enhanced tool banner"""
        banner = f"""
{Fore.CYAN}{'═'*75}
{Fore.GREEN}
   ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ██╗███████╗████████╗
  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗████╗  ██║██╔════╝╚══██╔══╝
  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██╔██╗ ██║█████╗     ██║   
  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║╚██╗██║██╔══╝     ██║   
  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║ ╚████║███████╗   ██║   
   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   
{Fore.YELLOW}              █▀ █▀▀ █▄░█ ▀█▀ █ █▄░█ █▀▀ █░░
              ▄█ ██▄ █░▀█ ░█░ █ █░▀█ ██▄ █▄▄
{Fore.CYAN}          Advanced Network Security Analyzer v2.1 Pro
{Fore.CYAN}{'═'*75}
{Fore.MAGENTA}        🔥 Cybernet Sentinel By Candalena 🔥
{Fore.WHITE}  Author: Cybersecurity Student | Semester 3
{Fore.CYAN}  Features: {Fore.GREEN}Fast Scan {Fore.CYAN}| {Fore.GREEN}Deep Analysis {Fore.CYAN}| {Fore.GREEN}Attack Detection
{Fore.CYAN}{'═'*75}
        """
        print(banner)
    
    def get_network_interfaces(self):
        """Get available network interfaces"""
        interfaces = []
        
        if platform.system() == "Windows":
            try:
                import wmi
                c = wmi.WMI()
                for interface in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
                    if interface.IPAddress and interface.IPAddress[0] != "0.0.0.0":
                        interfaces.append({
                            'name': interface.Description,
                            'ip': interface.IPAddress[0],
                            'mac': interface.MACAddress,
                            'subnet': interface.IPSubnet[0] if interface.IPSubnet else '255.255.255.0'
                        })
            except:
                # Fallback method for Windows
                for iface in psutil.net_if_addrs():
                    for addr in psutil.net_if_addrs()[iface]:
                        if addr.family == socket.AF_INET and addr.address != '127.0.0.1':
                            interfaces.append({
                                'name': iface,
                                'ip': addr.address,
                                'mac': psutil.net_if_stats()[iface].address if iface in psutil.net_if_stats() else 'Unknown',
                                'subnet': addr.netmask
                            })
        else:
            # Linux/Unix/MacOS
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    ip_info = addrs[netifaces.AF_INET][0]
                    mac_info = addrs[netifaces.AF_LINK][0] if netifaces.AF_LINK in addrs else {'addr': 'Unknown'}
                    interfaces.append({
                        'name': iface,
                        'ip': ip_info['addr'],
                        'mac': mac_info['addr'],
                        'subnet': ip_info.get('netmask', '255.255.255.0')
                    })
        
        return interfaces
    
    def calculate_network_range(self, ip, subnet):
        """Calculate network range from IP and subnet"""
        try:
            network = ipaddress.ip_network(f"{ip}/{subnet}", strict=False)
            return str(network)
        except:
            return f"{ip}/24"
    
    def port_scanner(self, target_ip, start_port=1, end_port=1024, timeout=0.5, threads=200):
        """Ultra-fast port scanner with threading and progress bar"""
        print(f"\n{Fore.CYAN}{'─'*75}")
        print(f"{Fore.YELLOW}🔍 ADVANCED PORT SCANNER")
        print(f"{Fore.CYAN}{'─'*75}")
        print(f"{Fore.WHITE}  Target IP    : {Fore.GREEN}{target_ip}")
        print(f"{Fore.WHITE}  Port Range   : {Fore.GREEN}{start_port}-{end_port} {Fore.CYAN}({end_port-start_port+1} ports)")
        print(f"{Fore.WHITE}  Threads      : {Fore.GREEN}{threads}")
        print(f"{Fore.WHITE}  Timeout      : {Fore.GREEN}{timeout}s")
        print(f"{Fore.CYAN}{'─'*75}\n")
        
        open_ports = []
        scan_start = time.time()
        self.scan_stats['scan_start_time'] = scan_start
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target_ip, port))
                sock.close()
                
                self.scan_stats['ports_scanned'] += 1
                
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"
                    
                    # Get banner in separate thread for speed
                    banner = self.get_banner(target_ip, port)
                    
                    self.scan_stats['open_ports_found'] += 1
                    
                    return {
                        'port': port,
                        'protocol': 'TCP',
                        'service': service,
                        'banner': banner,
                        'status': 'open'
                    }
            except:
                pass
            return None
        
        # Threaded port scanning with progress bar
        print(f"{Fore.CYAN}[*] Scanning TCP ports...")
        with ThreadPoolExecutor(max_workers=threads) as executor:
            with tqdm(total=end_port-start_port+1, 
                     desc=f"{Fore.CYAN}Progress", 
                     bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]',
                     colour='green') as pbar:
                
                futures = []
                for port in range(start_port, end_port + 1):
                    future = executor.submit(scan_port, port)
                    futures.append(future)
                
                for future in futures:
                    result = future.result()
                    if result:
                        open_ports.append(result)
                        print(f"\r{Fore.GREEN}[✓] Port {result['port']:5}/TCP OPEN - {result['service']:15} {result['banner'][:40] if result['banner'] else '':40}")
                    pbar.update(1)
        
        # Quick UDP scan on common ports
        print(f"\n{Fore.CYAN}[*] Scanning common UDP ports...")
        common_udp_ports = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1900, 4500]
        
        with tqdm(common_udp_ports, desc=f"{Fore.CYAN}UDP Scan", colour='yellow') as udp_pbar:
            for port in udp_pbar:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(1)
                    sock.sendto(b'\x00', (target_ip, port))
                    try:
                        data, addr = sock.recvfrom(1024)
                        open_ports.append({
                            'port': port,
                            'protocol': 'UDP',
                            'service': socket.getservbyport(port, 'udp') if port in [53, 67, 68, 123, 161] else 'unknown',
                            'banner': '',
                            'status': 'open/filtered'
                        })
                        print(f"\r{Fore.YELLOW}[✓] Port {port:5}/UDP OPEN or FILTERED")
                    except:
                        pass
                    sock.close()
                except:
                    pass
        
        scan_duration = time.time() - scan_start
        self.scan_stats['scan_duration'] = scan_duration
        
        # Display scan summary
        print(f"\n{Fore.CYAN}{'─'*75}")
        print(f"{Fore.GREEN}✓ SCAN COMPLETE")
        print(f"{Fore.CYAN}{'─'*75}")
        print(f"{Fore.WHITE}  Total Ports Scanned : {Fore.GREEN}{self.scan_stats['ports_scanned']}")
        print(f"{Fore.WHITE}  Open Ports Found    : {Fore.GREEN}{len(open_ports)}")
        print(f"{Fore.WHITE}  Scan Duration       : {Fore.GREEN}{scan_duration:.2f}s")
        print(f"{Fore.WHITE}  Scan Rate           : {Fore.GREEN}{self.scan_stats['ports_scanned']/scan_duration:.0f} ports/sec")
        print(f"{Fore.CYAN}{'─'*75}")
        
        return open_ports
    
    def get_banner(self, ip, port):
        """Attempt to grab banner from open port"""
        try:
            socket.setdefaulttimeout(2)
            sock = socket.socket()
            sock.connect((ip, port))
            
            # Try to receive banner
            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            if banner:
                # Clean up banner
                return banner[:100] + "..." if len(banner) > 100 else banner
        except:
            pass
        return None
    
    def arp_scan(self, network_range):
        """ARP scan to discover active hosts"""
        print(f"\n{Fore.YELLOW}[*] Scanning network {network_range} for active hosts...")
        print(f"{Fore.CYAN}[*] Using ARP scan (if fails, will fallback to ping sweep)")
        
        active_hosts = []
        
        # Suppress ALL Scapy output including stderr and logging
        import sys
        import io
        import logging
        
        # Save original streams
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        old_log_level = logging.root.level
        
        try:
            # Redirect both stdout and stderr to suppress ALL output
            sys.stdout = io.StringIO()
            sys.stderr = io.StringIO()
            logging.disable(logging.CRITICAL)
            
            # Set Scapy to minimal verbosity
            conf.verb = 0
            
            try:
                # Create ARP request packet
                arp = ARP(pdst=network_range)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether/arp
                
                # Perform ARP scan
                result = srp(packet, timeout=3, verbose=0)[0]
                
                # Restore output before printing results
                sys.stdout = old_stdout
                sys.stderr = old_stderr
                logging.disable(old_log_level)
                
                for sent, received in result:
                    hostname = self.resolve_hostname(received.psrc)
                    vendor = self.get_mac_vendor(received.hwsrc)
                    
                    print(f"{Fore.GREEN}[+] Host: {received.psrc:15} | MAC: {received.hwsrc} | Hostname: {hostname} | Vendor: {vendor}")
                    
                    active_hosts.append({
                        'ip': received.psrc,
                        'mac': received.hwsrc,
                        'hostname': hostname,
                        'vendor': vendor
                    })
                    
            except Exception:
                # Restore output on error
                sys.stdout = old_stdout
                sys.stderr = old_stderr
                logging.disable(old_log_level)
                
                # Silently fall back to ping sweep
                print(f"{Fore.YELLOW}[*] ARP scan unavailable, using ping sweep...")
                active_hosts = self.ping_sweep(network_range)
                
        finally:
            # Ensure streams are always restored
            sys.stdout = old_stdout
            sys.stderr = old_stderr
            logging.disable(old_log_level)
        
        return active_hosts
    
    def ping_sweep(self, network_range):
        """Fast ping sweep with progress bar"""
        print(f"\n{Fore.CYAN}[*] Performing fast ping sweep...")
        
        active_hosts = []
        network = ipaddress.ip_network(network_range, strict=False)
        total_hosts = sum(1 for _ in network.hosts())
        
        def ping_host(ip):
            try:
                param = '-n' if platform.system().lower() == 'windows' else '-c'
                command = ['ping', param, '1', '-w', '500', str(ip)]
                
                result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0)
                
                if result.returncode == 0:
                    hostname = self.resolve_hostname(str(ip))
                    
                    return {
                        'ip': str(ip),
                        'mac': 'Unknown',
                        'hostname': hostname,
                        'vendor': 'Unknown'
                    }
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            with tqdm(total=total_hosts, desc=f"{Fore.CYAN}Ping Sweep", colour='blue') as pbar:
                futures = [executor.submit(ping_host, ip) for ip in network.hosts()]
                
                for future in futures:
                    result = future.result()
                    if result:
                        active_hosts.append(result)
                        print(f"\r{Fore.GREEN}[✓] Host {result['ip']:15} - {result['hostname']:30}")
                    pbar.update(1)
        
        return active_hosts
    
    def resolve_hostname(self, ip):
        """Resolve IP to hostname"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "Unknown"
    
    def get_mac_vendor(self, mac_address):
        """Get vendor from MAC address using OUI lookup"""
        try:
            # First 6 characters (OUI)
            oui = mac_address.replace(':', '')[:6].upper()
            
            # Try to get from online database
            try:
                response = requests.get(f"https://api.macvendors.com/{mac_address}", timeout=2)
                if response.status_code == 200:
                    return response.text
            except:
                pass
            
            # Local OUI database (sample)
            oui_db = {
                '001C14': 'Cisco',
                '001B21': 'Netgear',
                '0021B9': 'Intel',
                '001D0F': 'Apple',
                '0050F2': 'Microsoft',
                '000C29': 'VMware',
                '001E65': 'Belkin',
                '001A2B': 'Samsung',
                '00805F': 'Netgear',
                '00017F': 'ASUS'
            }
            
            # Check exact match
            if oui in oui_db:
                return oui_db[oui]
            
            # Check prefix match
            for prefix, vendor in oui_db.items():
                if oui.startswith(prefix[:4]):
                    return vendor
            
            return "Unknown"
        except:
            return "Unknown"
    
    def network_sniffer(self, interface=None, count=100, filter="ip"):
        """Packet sniffer for network analysis"""
        print(f"\n{Fore.YELLOW}[*] Starting network sniffer... (Capturing {count} packets)")
        print(f"{Fore.CYAN}[*] Press Ctrl+C to stop\n")
        
        packets = []
        
        def packet_handler(packet):
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = packet[IP].proto
                
                # Determine protocol name
                proto_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(protocol, f'IP/{protocol}')
                
                # Get packet size
                size = len(packet)
                
                # Additional info based on protocol
                info = ""
                if TCP in packet:
                    info = f"TCP {packet[TCP].sport} -> {packet[TCP].dport}"
                    if packet[TCP].flags:
                        flags = []
                        if packet[TCP].flags & 0x02: flags.append("SYN")
                        if packet[TCP].flags & 0x10: flags.append("ACK")
                        if packet[TCP].flags & 0x01: flags.append("FIN")
                        if packet[TCP].flags & 0x04: flags.append("RST")
                        if flags:
                            info += f" [Flags: {' '.join(flags)}]"
                elif UDP in packet:
                    info = f"UDP {packet[UDP].sport} -> {packet[UDP].dport}"
                elif ICMP in packet:
                    info = f"ICMP Type: {packet[ICMP].type}"
                
                print(f"{Fore.WHITE}[{timestamp}] {src_ip:15} -> {dst_ip:15} | {proto_name:6} | {size:4} bytes | {info}")
                
                packets.append({
                    'timestamp': timestamp,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'protocol': proto_name,
                    'size': size,
                    'info': info,
                    'raw': packet.summary()
                })
        
        try:
            sniff(iface=interface, prn=packet_handler, count=count, filter=filter, store=0)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Sniffing stopped by user")
        except Exception as e:
            print(f"{Fore.RED}[-] Sniffing error: {e}")
        
        return packets
    
    def detect_attacks(self, packets):
        """Detect potential network attacks from captured packets"""
        print(f"\n{Fore.YELLOW}[*] Analyzing traffic for potential attacks...")
        
        detected = []
        
        # Analyze for SYN Flood
        syn_count = Counter()
        for packet in packets:
            if 'SYN' in packet['info'] and 'ACK' not in packet['info']:
                syn_count[packet['src_ip']] += 1
        
        for ip, count in syn_count.items():
            if count > 50:  # Threshold for SYN flood
                detected.append({
                    'type': 'SYN Flood Attack',
                    'severity': 'High',
                    'source': ip,
                    'description': f'Possible SYN flood attack detected from {ip} with {count} SYN packets',
                    'recommendation': 'Implement SYN cookies, rate limiting, or firewall rules'
                })
                print(f"{Fore.RED}[!] Potential SYN Flood Attack from {ip} ({count} SYN packets)")
        
        # Analyze for Port Scanning
        port_scan_sources = defaultdict(set)
        for packet in packets:
            if 'TCP' in packet['protocol'] and 'SYN' in packet['info']:
                port_scan_sources[packet['src_ip']].add(packet['dst_ip'])
        
        for ip, targets in port_scan_sources.items():
            if len(targets) > 10:  # Scanning multiple targets
                detected.append({
                    'type': 'Port Scanning',
                    'severity': 'Medium',
                    'source': ip,
                    'description': f'Port scanning activity detected from {ip} targeting {len(targets)} hosts',
                    'recommendation': 'Monitor source IP, consider blocking if unauthorized'
                })
                print(f"{Fore.YELLOW}[!] Potential Port Scanning from {ip} ({len(targets)} targets)")
        
        # Analyze for DDoS (multiple sources to single target)
        target_counter = Counter()
        for packet in packets:
            target_counter[packet['dst_ip']] += 1
        
        for target, count in target_counter.items():
            if count > 100:  # High traffic to single target
                sources = set(p['src_ip'] for p in packets if p['dst_ip'] == target)
                if len(sources) > 20:  # Multiple sources
                    detected.append({
                        'type': 'DDoS Attack',
                        'severity': 'Critical',
                        'target': target,
                        'description': f'Possible DDoS attack targeting {target} from {len(sources)} sources',
                        'recommendation': 'Activate DDoS protection, contact ISP, implement rate limiting'
                    })
                    print(f"{Fore.RED}[!] Potential DDoS Attack targeting {target} from {len(sources)} sources")
        
        # Analyze for ARP Spoofing (duplicate IP-MAC mappings)
        arp_mappings = {}
        for packet in packets:
            if 'ARP' in packet['raw']:
                src_ip = packet['src_ip']
                src_mac = packet.get('src_mac', '')
                
                if src_ip in arp_mappings and arp_mappings[src_ip] != src_mac:
                    detected.append({
                        'type': 'ARP Spoofing',
                        'severity': 'High',
                        'ip': src_ip,
                        'description': f'Possible ARP spoofing detected: IP {src_ip} has multiple MAC addresses',
                        'recommendation': 'Enable DHCP snooping, implement ARP inspection'
                    })
                    print(f"{Fore.RED}[!] Potential ARP Spoofing for IP {src_ip}")
                else:
                    arp_mappings[src_ip] = src_mac
        
        return detected
    
    def vulnerability_assessment(self, target_ip, open_ports):
        """Basic vulnerability assessment based on open ports"""
        print(f"\n{Fore.YELLOW}[*] Performing basic vulnerability assessment...")
        
        vulnerabilities = []
        
        # Common vulnerable services
        vulnerable_services = {
            21: ('FTP', 'Anonymous login, weak authentication'),
            22: ('SSH', 'Weak passwords, outdated versions'),
            23: ('Telnet', 'Cleartext authentication'),
            80: ('HTTP', 'Web vulnerabilities, outdated software'),
            443: ('HTTPS', 'SSL/TLS vulnerabilities'),
            445: ('SMB', 'EternalBlue, weak configurations'),
            3389: ('RDP', 'BlueKeep, brute force attacks'),
            5900: ('VNC', 'Weak authentication'),
            27017: ('MongoDB', 'Unauthenticated access')
        }
        
        for port_info in open_ports:
            port = port_info['port']
            if port in vulnerable_services:
                service, risk = vulnerable_services[port]
                vulnerabilities.append({
                    'port': port,
                    'service': service,
                    'risk': risk,
                    'recommendation': f'Secure {service} service, update software, implement access controls'
                })
                print(f"{Fore.YELLOW}[!] Vulnerability: Port {port} ({service}) - {risk}")
        
        return vulnerabilities
    
    def export_results(self, filename="network_analysis_report.json"):
        """Export all results to JSON file"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'network_range': self.network_range,
            'open_ports': self.open_ports,
            'active_hosts': self.active_hosts,
            'detected_attacks': self.detected_attacks,
            'traffic_summary': {
                'total_packets': len(self.network_traffic),
                'protocols': Counter(p['protocol'] for p in self.network_traffic)
            }
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=4, default=str)
            print(f"{Fore.GREEN}[+] Report exported to {filename}")
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to export report: {e}")
    
    def export_to_txt(self, filename="network_analysis_report.txt"):
        """Export all results to readable TXT file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                # Header
                f.write("═" * 80 + "\n")
                f.write(" " * 20 + "CYBERNET SENTINEL\n")
                f.write(" " * 15 + "Network Security Analysis Report\n")
                f.write("═" * 80 + "\n\n")
                
                # Timestamp
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Network Range: {self.network_range or 'N/A'}\n")
                f.write("\n" + "═" * 80 + "\n\n")
                
                # Host Discovery Results
                if self.active_hosts:
                    f.write("[✓] HOST DISCOVERY RESULTS\n")
                    f.write("─" * 80 + "\n")
                    for i, host in enumerate(self.active_hosts, 1):
                        f.write(f"\n{i}. IP Address : {host['ip']}\n")
                        f.write(f"   Hostname   : {host.get('hostname', 'N/A')}\n")
                        f.write(f"   MAC Address: {host.get('mac', 'N/A')}\n")
                        f.write(f"   Vendor     : {host.get('vendor', 'N/A')}\n")
                    f.write(f"\nTotal Active Hosts: {len(self.active_hosts)}\n")
                    f.write("\n" + "═" * 80 + "\n\n")
                
                # Port Scan Results
                if self.open_ports:
                    f.write("[✓] PORT SCANNING RESULTS\n")
                    f.write("─" * 80 + "\n")
                    for ip, ports in self.open_ports.items():
                        f.write(f"\nTarget: {ip}\n")
                        f.write("─" * 40 + "\n")
                        for port in ports:
                            f.write(f"  Port: {port['port']}/{port['protocol']}\n")
                            f.write(f"    Service : {port['service']}\n")
                            f.write(f"    Status  : {port['status']}\n")
                            if port.get('banner'):
                                f.write(f"    Banner  : {port['banner'][:60]}\n")
                            f.write("\n")
                        f.write(f"Total Open Ports: {len(ports)}\n\n")
                    f.write("═" * 80 + "\n\n")
                
                # Security Threats
                if self.detected_attacks:
                    f.write("[!] SECURITY THREATS DETECTED\n")
                    f.write("─" * 80 + "\n")
                    for i, attack in enumerate(self.detected_attacks, 1):
                        f.write(f"\n{i}. Threat Type : {attack['type']}\n")
                        f.write(f"   Severity    : {attack['severity']}\n")
                        f.write(f"   Source      : {attack.get('source', attack.get('target', 'N/A'))}\n")
                        f.write(f"   Description : {attack['description']}\n")
                    f.write(f"\nTotal Threats: {len(self.detected_attacks)}\n")
                    f.write("\n" + "═" * 80 + "\n\n")
                
                # Traffic Statistics
                if self.network_traffic:
                    f.write("[✓] TRAFFIC STATISTICS\n")
                    f.write("─" * 80 + "\n\n")
                    protocol_counts = Counter(p['protocol'] for p in self.network_traffic)
                    total = len(self.network_traffic)
                    for proto, count in protocol_counts.most_common():
                        percentage = (count / total) * 100
                        bar = '█' * int(percentage / 2)
                        f.write(f"  {proto:10s} : {count:5d} packets ({percentage:5.1f}%) {bar}\n")
                    f.write(f"\nTotal Packets Captured: {total}\n")
                    f.write("\n" + "═" * 80 + "\n")
                
                f.write("\n" + "═" * 80 + "\n")
                f.write(" " * 25 + "End of Report\n")
                f.write("═" * 80 + "\n")
            
            print(f"{Fore.GREEN}[+] Report exported to {filename}")
            return filename
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to export report: {e}")
            return None
    
    def display_summary(self):
        """Display comprehensive analysis summary with tables"""
        print(f"\n{Fore.CYAN}{'═'*75}")
        print(f"{Fore.YELLOW}           📊 NETWORK SECURITY ANALYSIS SUMMARY")
        print(f"{Fore.CYAN}{'═'*75}\n")
        
        # Host Discovery Summary with Table
        if self.active_hosts:
            print(f"{Fore.GREEN}[✓] HOST DISCOVERY RESULTS")
            print(f"{Fore.CYAN}{'─'*75}")
            
            host_table = []
            for i, host in enumerate(self.active_hosts, 1):
                host_table.append([
                    i,
                    host['ip'],
                    host['hostname'][:25],
                    host['mac'][:17],
                    host['vendor'][:20]
                ])
            
            print(tabulate(host_table, 
                          headers=[f"{Fore.WHITE}#", "IP Address", "Hostname", "MAC Address", "Vendor"],
                          tablefmt="fancy_grid"))
            print(f"{Fore.WHITE}Total Active Hosts: {Fore.GREEN}{len(self.active_hosts)}\n")
        
        # Port Scan Summary with Table
        if self.open_ports:
            print(f"\n{Fore.GREEN}[✓] PORT SCANNING RESULTS")
            print(f"{Fore.CYAN}{'─'*75}")
            
            for ip, ports in self.open_ports.items():
                print(f"\n{Fore.YELLOW}Target: {Fore.GREEN}{ip}")
                
                port_table = []
                for port in ports:
                    status_color = Fore.GREEN if port['status'] == 'open' else Fore.YELLOW
                    port_table.append([
                        f"{port['port']}/{port['protocol']}",
                        port['service'],
                        f"{status_color}{port['status']}",
                        (port.get('banner', '') or 'N/A')[:40]
                    ])
                
                print(tabulate(port_table,
                              headers=["Port", "Service", "Status", "Banner"],
                              tablefmt="fancy_grid"))
                print(f"{Fore.WHITE}Open Ports: {Fore.GREEN}{len(ports)}")
        
        # Security Threats with Table
        if self.detected_attacks:
            print(f"\n{Fore.RED}[!] SECURITY THREATS DETECTED")
            print(f"{Fore.CYAN}{'─'*75}")
            
            threat_table = []
            for i, attack in enumerate(self.detected_attacks, 1):
                severity_color = {
                    'Critical': Fore.RED,
                    'High': Fore.MAGENTA,
                    'Medium': Fore.YELLOW,
                    'Low': Fore.BLUE
                }.get(attack['severity'], Fore.WHITE)
                
                threat_table.append([
                    i,
                    attack['type'][:25],
                    f"{severity_color}{attack['severity']}",
                    attack.get('source', attack.get('target', 'N/A'))[:20],
                    attack['description'][:40]
                ])
            
            print(tabulate(threat_table,
                          headers=["#", "Threat Type", "Severity", "Source/Target", "Description"],
                          tablefmt="fancy_grid"))
            print(f"\n{Fore.RED}⚠️  Total Threats: {len(self.detected_attacks)}")
        else:
            print(f"\n{Fore.GREEN}[✓] SECURITY STATUS")
            print(f"{Fore.CYAN}{'─'*75}")
            print(f"{Fore.GREEN}✓ No critical security threats detected")
            print(f"{Fore.GREEN}✓ Network appears to be secure")
        
        # Traffic Statistics with Table
        if self.network_traffic:
            print(f"\n{Fore.GREEN}[✓] TRAFFIC STATISTICS")
            print(f"{Fore.CYAN}{'─'*75}")
            
            protocols = Counter(p['protocol'] for p in self.network_traffic)
            total_packets = len(self.network_traffic)
            
            traffic_table = []
            for proto, count in protocols.most_common():
                percentage = (count / total_packets) * 100
                bar = '█' * int(percentage / 5)
                traffic_table.append([
                    proto,
                    count,
                    f"{percentage:.1f}%",
                    f"{Fore.GREEN}{bar}"
                ])
            
            print(tabulate(traffic_table,
                          headers=["Protocol", "Packets", "Percentage", "Graph"],
                          tablefmt="fancy_grid"))
            print(f"\n{Fore.WHITE}Total Packets Captured: {Fore.GREEN}{total_packets}")
        
        print(f"\n{Fore.CYAN}{'═'*75}")
    
    def interactive_menu(self):
        """Enhanced interactive command line interface"""
        self.banner()
        
        while True:
            print(f"\n{Fore.CYAN}{'═'*75}")
            print(f"{Fore.YELLOW}                        🎯 MAIN MENU")
            print(f"{Fore.CYAN}{'═'*75}")
            print(f"{Fore.GREEN}  [1]{Fore.WHITE} 📡 Select Network Interface      {Fore.CYAN}│ {Fore.GREEN}[6]{Fore.WHITE} 🔒 Comprehensive Audit")
            print(f"{Fore.GREEN}  [2]{Fore.WHITE} 🌐 Network Discovery             {Fore.CYAN}│ {Fore.GREEN}[7]{Fore.WHITE} 💾 Export Results")
            print(f"{Fore.GREEN}  [3]{Fore.WHITE} 🚪 Port Scanner (Fast!)          {Fore.CYAN}│ {Fore.GREEN}[8]{Fore.WHITE} 📊 Display Summary")
            print(f"{Fore.GREEN}  [4]{Fore.WHITE} 👂 Network Sniffer               {Fore.CYAN}│ {Fore.GREEN}[9]{Fore.WHITE} ❌ Exit")
            print(f"{Fore.GREEN}  [5]{Fore.WHITE} ⚠️  Attack Detection              {Fore.CYAN}│")
            print(f"{Fore.CYAN}{'═'*75}")
            
            choice = input(f"\n{Fore.GREEN}[?] Select option (1-9): {Fore.WHITE}").strip()
            
            if choice == '1':
                self.select_interface()
            elif choice == '2':
                self.network_discovery()
            elif choice == '3':
                self.scan_ports_menu()
            elif choice == '4':
                self.sniff_menu()
            elif choice == '5':
                self.attack_detection_menu()
            elif choice == '6':
                self.comprehensive_audit()
            elif choice == '7':
                print(f"\n{Fore.CYAN}{'─'*75}")
                print(f"{Fore.YELLOW}📁 Export Format:")
                print(f"{Fore.WHITE}  [1] TXT - Readable Text Report")
                print(f"{Fore.WHITE}  [2] JSON - Structured Data")
                print(f"{Fore.CYAN}{'─'*75}")
                format_choice = input(f"{Fore.GREEN}[?] Select format (1-2): {Fore.WHITE}").strip()
                
                if format_choice == '1':
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    filename = input(f"{Fore.GREEN}[?] Enter filename (default: report_{timestamp}.txt): {Fore.WHITE}") or f"report_{timestamp}.txt"
                    self.export_to_txt(filename)
                elif format_choice == '2':
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    filename = input(f"{Fore.GREEN}[?] Enter filename (default: report_{timestamp}.json): {Fore.WHITE}") or f"report_{timestamp}.json"
                    self.export_results(filename)
                else:
                    print(f"{Fore.RED}[✗] Invalid format choice!")
            elif choice == '8':
                self.display_summary()
            elif choice == '9':
                print(f"\n{Fore.CYAN}{'═'*75}")
                print(f"{Fore.YELLOW}     👋 Thank you for using CyberNet Sentinel!")
                print(f"{Fore.GREEN}     Stay safe and secure! 🛡️")
                print(f"{Fore.CYAN}{'═'*75}\n")
                break
            else:
                print(f"{Fore.RED}[✗] Invalid choice! Please select 1-9")
    
    def select_interface(self):
        """Select network interface"""
        interfaces = self.get_network_interfaces()
        
        if not interfaces:
            print(f"{Fore.RED}[-] No network interfaces found!")
            return
        
        print(f"\n{Fore.YELLOW}[*] Available Network Interfaces:")
        for i, iface in enumerate(interfaces, 1):
            print(f"{Fore.WHITE}{i}. {iface['name']:20} | IP: {iface['ip']:15} | MAC: {iface['mac']}")
        
        try:
            choice = int(input(f"\n{Fore.GREEN}[?] Select interface (1-{len(interfaces)}): "))
            if 1 <= choice <= len(interfaces):
                self.interface = interfaces[choice-1]
                self.network_range = self.calculate_network_range(
                    self.interface['ip'], 
                    self.interface['subnet']
                )
                print(f"{Fore.GREEN}[+] Selected: {self.interface['name']}")
                print(f"{Fore.GREEN}[+] Network Range: {self.network_range}")
            else:
                print(f"{Fore.RED}[-] Invalid selection!")
        except:
            print(f"{Fore.RED}[-] Invalid input!")
    
    def network_discovery(self):
        """Network host discovery"""
        if not self.network_range:
            print(f"{Fore.RED}[-] Please select network interface first! (Option 1)")
            return
        
        self.active_hosts = self.arp_scan(self.network_range)
        
        if not self.active_hosts:
            print(f"{Fore.YELLOW}[*] No hosts found, trying alternative methods...")
            self.active_hosts = self.ping_sweep(self.network_range)
        
        if self.active_hosts:
            print(f"\n{Fore.GREEN}[+] Discovery complete! Found {len(self.active_hosts)} active host(s)")
        else:
            print(f"\n{Fore.YELLOW}[*] No active hosts found in network {self.network_range}")
    
    def scan_ports_menu(self):
        """Port scanning menu"""
        if not self.active_hosts:
            print(f"{Fore.YELLOW}[*] No active hosts found from discovery.")
            print(f"{Fore.YELLOW}[*] You can still scan a specific IP address.")
        
        print(f"\n{Fore.YELLOW}[*] Select target for port scanning:")
        
        if self.active_hosts:
            for i, host in enumerate(self.active_hosts, 1):
                print(f"{Fore.WHITE}{i}. {host['ip']:15} - {host['hostname']} ({host['vendor']})")
            print(f"{Fore.WHITE}{len(self.active_hosts)+1}. Enter custom IP")
        else:
            print(f"{Fore.WHITE}1. Enter custom IP")
        
        try:
            if self.active_hosts:
                choice = int(input(f"\n{Fore.GREEN}[?] Select target (1-{len(self.active_hosts)+1}): "))
                
                if 1 <= choice <= len(self.active_hosts):
                    target_ip = self.active_hosts[choice-1]['ip']
                elif choice == len(self.active_hosts) + 1:
                    target_ip = input(f"{Fore.GREEN}[?] Enter IP address: ").strip()
                else:
                    print(f"{Fore.RED}[-] Invalid selection!")
                    return
            else:
                choice = int(input(f"\n{Fore.GREEN}[?] Select target (1): "))
                if choice == 1:
                    target_ip = input(f"{Fore.GREEN}[?] Enter IP address: ").strip()
                else:
                    print(f"{Fore.RED}[-] Invalid selection!")
                    return
            
            # Get scan parameters
            start_port = input(f"{Fore.GREEN}[?] Start port (default: 1): ").strip()
            start_port = int(start_port) if start_port else 1
            
            end_port = input(f"{Fore.GREEN}[?] End port (default: 1024): ").strip()
            end_port = int(end_port) if end_port else 1024
            
            threads = input(f"{Fore.GREEN}[?] Number of threads (default: 100): ").strip()
            threads = int(threads) if threads else 100
            
            # Run port scan
            open_ports = self.port_scanner(target_ip, start_port, end_port, threads=threads)
            self.open_ports[target_ip] = open_ports
            
            # Vulnerability assessment
            vulns = self.vulnerability_assessment(target_ip, open_ports)
            
            print(f"\n{Fore.GREEN}[+] Scan completed. Found {len(open_ports)} open ports")
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error: {e}")
    
    def sniff_menu(self):
        """Network sniffing menu"""
        iface = self.interface['name'] if self.interface else None
        
        count = input(f"{Fore.GREEN}[?] Number of packets to capture (default: 100): ").strip()
        count = int(count) if count else 100
        
        filter_exp = input(f"{Fore.GREEN}[?] BPF filter (default: 'ip'): ").strip()
        filter_exp = filter_exp if filter_exp else "ip"
        
        self.network_traffic = self.network_sniffer(iface, count, filter_exp)
        
        # Save packets to file
        try:
            with open("captured_packets.txt", "w") as f:
                for packet in self.network_traffic:
                    f.write(f"{packet['timestamp']} {packet['src_ip']} -> {packet['dst_ip']} | "
                           f"{packet['protocol']} | {packet['size']} bytes | {packet['info']}\n")
            print(f"{Fore.GREEN}[+] Packets saved to captured_packets.txt")
        except:
            pass
    
    def attack_detection_menu(self):
        """Attack detection menu"""
        if not self.network_traffic:
            print(f"{Fore.RED}[-] Please capture network traffic first!")
            return
        
        self.detected_attacks = self.detect_attacks(self.network_traffic)
        
        if self.detected_attacks:
            print(f"\n{Fore.RED}[!] Found {len(self.detected_attacks)} potential attacks!")
        else:
            print(f"\n{Fore.GREEN}[+] No attacks detected in captured traffic")
    
    def comprehensive_audit(self):
        """Run comprehensive security audit"""
        print(f"\n{Fore.YELLOW}[*] Starting comprehensive security audit...")
        
        if not self.network_range:
            self.select_interface()
        
        # Step 1: Network Discovery
        print(f"\n{Fore.CYAN}[*] STEP 1: Network Discovery")
        self.network_discovery()
        
        # Step 2: Port Scanning on all hosts
        print(f"\n{Fore.CYAN}[*] STEP 2: Port Scanning all hosts")
        self.open_ports = {}
        
        for host in self.active_hosts[:5]:  # Limit to first 5 hosts for performance
            print(f"\n{Fore.YELLOW}[*] Scanning {host['ip']}...")
            ports = self.port_scanner(host['ip'], 1, 100, threads=50)
            self.open_ports[host['ip']] = ports
        
        # Step 3: Network Sniffing
        print(f"\n{Fore.CYAN}[*] STEP 3: Network Traffic Analysis")
        self.network_traffic = self.network_sniffer(
            self.interface['name'] if self.interface else None,
            200,
            "ip"
        )
        
        # Step 4: Attack Detection
        print(f"\n{Fore.CYAN}[*] STEP 4: Security Threat Detection")
        self.detected_attacks = self.detect_attacks(self.network_traffic)
        
        # Step 5: Display Summary
        print(f"\n{Fore.CYAN}[*] STEP 5: Generating Report")
        self.display_summary()
        
        print(f"\n{Fore.GREEN}[+] Comprehensive audit completed!")
        
        # Auto-save option
        print(f"\n{Fore.CYAN}{'─'*75}")
        save = input(f"{Fore.YELLOW}[?] Save report to TXT file? (Y/n): {Fore.WHITE}").strip().lower()
        if save != 'n':
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"audit_report_{timestamp}.txt"
            saved_file = self.export_to_txt(filename)
            if saved_file:
                print(f"{Fore.GREEN}[✓] Report saved: {Fore.CYAN}{saved_file}")

def main():
    """Main function"""
    # Check for admin/root privileges
    if platform.system() == "Windows":
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                print(f"{Fore.RED}[!] Warning: Running without administrator privileges.")
                print(f"{Fore.YELLOW}[*] Some features may not work correctly.")
        except:
            pass
    
    # Check for required modules
    try:
        import scapy
    except ImportError:
        print(f"{Fore.RED}[!] Error: Scapy module not installed!")
        print(f"{Fore.YELLOW}[*] Install with: pip install scapy")
        sys.exit(1)
    
    try:
        analyzer = NetworkSecurityAnalyzer()
        analyzer.interactive_menu()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Program terminated by user")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[-] Critical error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()