#!/usr/bin/env python3
"""
Network Sniffer Module
Packet capture and analysis for network monitoring
"""

import socket
import struct
import threading
import time
import collections
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
import json
from colorama import Fore, Style
import sys
import os

# Try to import scapy, but provide fallback
try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import ARP, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print(f"{Fore.YELLOW}[!] Scapy not available. Limited functionality.")

@dataclass
class PacketInfo:
    """Packet information container"""
    timestamp: str
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: Optional[int]
    destination_port: Optional[int]
    packet_size: int
    flags: Optional[str]
    info: str
    raw_data: Optional[bytes] = None
    ttl: Optional[int] = None
    checksum: Optional[int] = None

@dataclass
class TrafficStats:
    """Traffic statistics"""
    total_packets: int = 0
    total_bytes: int = 0
    start_time: float = 0
    end_time: float = 0
    
    # Protocol counters
    tcp_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0
    arp_packets: int = 0
    other_packets: int = 0
    
    # IP counters
    unique_source_ips: set = None
    unique_destination_ips: set = None
    
    def __post_init__(self):
        self.unique_source_ips = set()
        self.unique_destination_ips = set()
    
    def update(self, packet: PacketInfo):
        """Update statistics with new packet"""
        self.total_packets += 1
        self.total_bytes += packet.packet_size
        
        if packet.protocol == 'TCP':
            self.tcp_packets += 1
        elif packet.protocol == 'UDP':
            self.udp_packets += 1
        elif packet.protocol == 'ICMP':
            self.icmp_packets += 1
        elif packet.protocol == 'ARP':
            self.arp_packets += 1
        else:
            self.other_packets += 1
        
        if packet.source_ip:
            self.unique_source_ips.add(packet.source_ip)
        if packet.destination_ip:
            self.unique_destination_ips.add(packet.destination_ip)
    
    def get_summary(self) -> Dict:
        """Get statistics summary"""
        duration = self.end_time - self.start_time if self.end_time > self.start_time else 0
        packets_per_second = self.total_packets / duration if duration > 0 else 0
        bytes_per_second = self.total_bytes / duration if duration > 0 else 0
        
        return {
            'duration_seconds': duration,
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'packets_per_second': packets_per_second,
            'bytes_per_second': bytes_per_second,
            'unique_source_ips': len(self.unique_source_ips),
            'unique_destination_ips': len(self.unique_destination_ips),
            'protocol_distribution': {
                'tcp': self.tcp_packets,
                'udp': self.udp_packets,
                'icmp': self.icmp_packets,
                'arp': self.arp_packets,
                'other': self.other_packets
            }
        }

class NetworkSniffer:
    """Advanced network packet sniffer"""
    
    def __init__(self, interface: str = None, verbose: bool = False):
        self.interface = interface
        self.verbose = verbose
        self.captured_packets = []
        self.traffic_stats = TrafficStats()
        self.is_sniffing = False
        self.sniff_thread = None
        
        # Filters
        self.ip_filter = None
        self.port_filter = None
        self.protocol_filter = None
        
        # Callbacks
        self.on_packet_callback = None
        self.on_alert_callback = None
        
        # Alert thresholds
        self.alert_thresholds = {
            'syn_flood': 50,  # SYN packets per second
            'large_packet': 1500,  # Packet size in bytes
            'port_scan': 10,  # Different ports per IP
        }
        
    def start_sniffing(self, packet_count: int = 0, timeout: int = 0) -> List[PacketInfo]:
        """Start packet sniffing"""
        if not SCAPY_AVAILABLE:
            print(f"{Fore.RED}[-] Scapy is required for packet sniffing")
            print(f"{Fore.YELLOW}[*] Install with: pip install scapy")
            return []
        
        print(f"{Fore.CYAN}[*] Starting packet capture...")
        print(f"{Fore.YELLOW}[*] Press Ctrl+C to stop\n")
        
        self.captured_packets = []
        self.traffic_stats = TrafficStats()
        self.traffic_stats.start_time = time.time()
        
        try:
            # Set sniffing parameters
            sniff_params = {
                'prn': self._process_packet,
                'store': 0,  # Don't store in scapy's memory
                'iface': self.interface,
            }
            
            if packet_count > 0:
                sniff_params['count'] = packet_count
            if timeout > 0:
                sniff_params['timeout'] = timeout
            
            # Apply filters
            bpf_filter = self._build_bpf_filter()
            if bpf_filter:
                sniff_params['filter'] = bpf_filter
            
            # Start sniffing
            sniff(**sniff_params)
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Stopping packet capture...")
        except Exception as e:
            print(f"{Fore.RED}[-] Sniffing error: {e}")
        finally:
            self.traffic_stats.end_time = time.time()
        
        return self.captured_packets
    
    def start_background_sniffing(self, packet_count: int = 0):
        """Start sniffing in background thread"""
        self.is_sniffing = True
        self.sniff_thread = threading.Thread(
            target=self._background_sniff,
            args=(packet_count,)
        )
        self.sniff_thread.daemon = True
        self.sniff_thread.start()
        
        print(f"{Fore.GREEN}[+] Background sniffing started")
        return self.sniff_thread
    
    def stop_background_sniffing(self):
        """Stop background sniffing"""
        self.is_sniffing = False
        if self.sniff_thread:
            self.sniff_thread.join(timeout=5)
            print(f"{Fore.YELLOW}[*] Background sniffing stopped")
    
    def _background_sniff(self, packet_count: int = 0):
        """Background sniffing function"""
        try:
            self.start_sniffing(packet_count=packet_count)
        except Exception as e:
            print(f"{Fore.RED}[-] Background sniffing error: {e}")
    
    def _process_packet(self, packet):
        """Process captured packet"""
        try:
            packet_info = self._parse_packet(packet)
            if packet_info:
                # Add to captured packets
                self.captured_packets.append(packet_info)
                
                # Update statistics
                self.traffic_stats.update(packet_info)
                
                # Display packet
                if self.verbose:
                    self._display_packet(packet_info)
                
                # Check for alerts
                self._check_alerts(packet_info)
                
                # Call callback if set
                if self.on_packet_callback:
                    self.on_packet_callback(packet_info)
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[!] Error processing packet: {e}")
    
    def _parse_packet(self, packet) -> Optional[PacketInfo]:
        """Parse packet into PacketInfo object"""
        try:
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            
            # Initialize variables
            source_ip = dest_ip = protocol = "Unknown"
            src_port = dst_port = None
            flags = info = ""
            ttl = checksum = None
            
            # Check for Ethernet frame
            if Ether in packet:
                # IP packet
                if IP in packet:
                    ip_layer = packet[IP]
                    source_ip = ip_layer.src
                    dest_ip = ip_layer.dst
                    ttl = ip_layer.ttl
                    checksum = ip_layer.chksum
                    
                    # TCP
                    if TCP in packet:
                        protocol = "TCP"
                        tcp_layer = packet[TCP]
                        src_port = tcp_layer.sport
                        dst_port = tcp_layer.dport
                        
                        # Extract flags
                        flag_list = []
                        if tcp_layer.flags & 0x02: flag_list.append("SYN")
                        if tcp_layer.flags & 0x10: flag_list.append("ACK")
                        if tcp_layer.flags & 0x01: flag_list.append("FIN")
                        if tcp_layer.flags & 0x04: flag_list.append("RST")
                        if tcp_layer.flags & 0x08: flag_list.append("PSH")
                        if tcp_layer.flags & 0x20: flag_list.append("URG")
                        flags = " ".join(flag_list) if flag_list else "None"
                        
                        info = f"TCP {src_port} -> {dst_port}"
                        if flags:
                            info += f" [{flags}]"
                        
                        # Check for HTTP
                        if src_port == 80 or dst_port == 80 or src_port == 443 or dst_port == 443:
                            if packet.haslayer(Raw):
                                raw_data = packet[Raw].load
                                try:
                                    http_data = raw_data.decode('utf-8', errors='ignore')
                                    if "HTTP" in http_data or "GET" in http_data or "POST" in http_data:
                                        protocol = "HTTP"
                                        first_line = http_data.split('\r\n')[0] if '\r\n' in http_data else http_data[:50]
                                        info = f"HTTP: {first_line}"
                                except:
                                    pass
                    
                    # UDP
                    elif UDP in packet:
                        protocol = "UDP"
                        udp_layer = packet[UDP]
                        src_port = udp_layer.sport
                        dst_port = udp_layer.dport
                        info = f"UDP {src_port} -> {dst_port}"
                        
                        # DNS
                        if src_port == 53 or dst_port == 53:
                            protocol = "DNS"
                            info = f"DNS Query"
                    
                    # ICMP
                    elif ICMP in packet:
                        protocol = "ICMP"
                        icmp_layer = packet[ICMP]
                        info = f"ICMP Type: {icmp_layer.type}"
                
                # ARP
                elif ARP in packet:
                    protocol = "ARP"
                    arp_layer = packet[ARP]
                    source_ip = arp_layer.psrc
                    dest_ip = arp_layer.pdst
                    info = f"ARP {source_ip} -> {dest_ip}"
            
            # Create PacketInfo object
            packet_info = PacketInfo(
                timestamp=timestamp,
                source_ip=source_ip,
                destination_ip=dest_ip,
                protocol=protocol,
                source_port=src_port,
                destination_port=dst_port,
                packet_size=len(packet),
                flags=flags,
                info=info,
                ttl=ttl,
                checksum=checksum
            )
            
            return packet_info
            
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[!] Parse error: {e}")
            return None
    
    def _display_packet(self, packet_info: PacketInfo):
        """Display packet information in console"""
        # Color coding by protocol
        color_map = {
            'TCP': Fore.CYAN,
            'UDP': Fore.MAGENTA,
            'ICMP': Fore.YELLOW,
            'HTTP': Fore.GREEN,
            'DNS': Fore.BLUE,
            'ARP': Fore.WHITE,
            'Unknown': Fore.LIGHTBLACK_EX
        }
        
        color = color_map.get(packet_info.protocol, Fore.LIGHTBLACK_EX)
        
        # Format output
        if packet_info.protocol in ['TCP', 'UDP', 'HTTP']:
            output = (f"{color}[{packet_info.timestamp}] "
                     f"{packet_info.source_ip:15}:{packet_info.source_port or '':<5} -> "
                     f"{packet_info.destination_ip:15}:{packet_info.destination_port or '':<5} "
                     f"{packet_info.protocol:5} {packet_info.packet_size:4} bytes")
            
            if packet_info.flags and packet_info.flags != "None":
                output += f" [{packet_info.flags}]"
            
            if packet_info.info and packet_info.protocol not in ['TCP', 'UDP']:
                output += f" {packet_info.info}"
            
            print(output)
        
        elif packet_info.protocol == 'ICMP':
            print(f"{color}[{packet_info.timestamp}] "
                  f"{packet_info.source_ip:15} -> {packet_info.destination_ip:15} "
                  f"ICMP     {packet_info.packet_size:4} bytes {packet_info.info}")
        
        elif packet_info.protocol == 'ARP':
            print(f"{color}[{packet_info.timestamp}] "
                  f"{packet_info.source_ip:15} -> {packet_info.destination_ip:15} "
                  f"ARP      {packet_info.packet_size:4} bytes")
        
        else:
            print(f"{color}[{packet_info.timestamp}] "
                  f"{packet_info.source_ip:15} -> {packet_info.destination_ip:15} "
                  f"{packet_info.protocol:7} {packet_info.packet_size:4} bytes")
    
    def _build_bpf_filter(self) -> str:
        """Build Berkeley Packet Filter (BPF) string"""
        filters = []
        
        if self.ip_filter:
            filters.append(f"host {self.ip_filter}")
        
        if self.port_filter:
            filters.append(f"port {self.port_filter}")
        
        if self.protocol_filter:
            if self.protocol_filter.lower() == 'tcp':
                filters.append('tcp')
            elif self.protocol_filter.lower() == 'udp':
                filters.append('udp')
            elif self.protocol_filter.lower() == 'icmp':
                filters.append('icmp')
            elif self.protocol_filter.lower() == 'arp':
                filters.append('arp')
        
        return ' and '.join(filters) if filters else ''
    
    def _check_alerts(self, packet_info: PacketInfo):
        """Check packet for security alerts"""
        alerts = []
        
        # Large packet alert
        if packet_info.packet_size > self.alert_thresholds['large_packet']:
            alerts.append(f"Large packet detected: {packet_info.packet_size} bytes")
        
        # Check for SYN flood (simplified)
        if packet_info.protocol == 'TCP' and 'SYN' in packet_info.flags and 'ACK' not in packet_info.flags:
            # In real implementation, track SYN rate per source IP
            pass
        
        # Trigger alert callback
        if alerts and self.on_alert_callback:
            for alert in alerts:
                self.on_alert_callback(alert, packet_info)
    
    def set_filter(self, ip: str = None, port: int = None, protocol: str = None):
        """Set packet capture filters"""
        self.ip_filter = ip
        self.port_filter = port
        self.protocol_filter = protocol
        
        print(f"{Fore.GREEN}[+] Filters set: IP={ip}, Port={port}, Protocol={protocol}")
    
    def save_capture(self, filename: str = "capture.pcap"):
        """Save captured packets to PCAP file"""
        if not SCAPY_AVAILABLE:
            print(f"{Fore.RED}[-] Cannot save PCAP without scapy")
            return
        
        try:
            # Create a list of scapy packets from captured packets
            # Note: This is simplified - real implementation would store raw packets
            print(f"{Fore.YELLOW}[*] Saving capture to {filename}...")
            
            # For now, save packet info to JSON
            json_file = filename.replace('.pcap', '.json')
            self.save_to_json(json_file)
            
            print(f"{Fore.GREEN}[+] Capture saved to {json_file}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error saving capture: {e}")
    
    def save_to_json(self, filename: str = "capture.json"):
        """Save captured packets to JSON file"""
        try:
            data = {
                'metadata': {
                    'interface': self.interface,
                    'capture_time': datetime.now().isoformat(),
                    'total_packets': len(self.captured_packets),
                    'statistics': self.traffic_stats.get_summary()
                },
                'packets': [asdict(p) for p in self.captured_packets]
            }
            
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            
            print(f"{Fore.GREEN}[+] Saved {len(self.captured_packets)} packets to {filename}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error saving to JSON: {e}")
    
    def display_statistics(self):
        """Display traffic statistics"""
        stats = self.traffic_stats.get_summary()
        
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"{Fore.YELLOW}TRAFFIC STATISTICS")
        print(f"{Fore.CYAN}{'='*80}")
        
        print(f"\n{Fore.GREEN}Capture Duration: {stats['duration_seconds']:.2f} seconds")
        print(f"{Fore.GREEN}Total Packets: {stats['total_packets']}")
        print(f"{Fore.GREEN}Total Bytes: {stats['total_bytes']:,}")
        print(f"{Fore.GREEN}Packets/Second: {stats['packets_per_second']:.2f}")
        print(f"{Fore.GREEN}Bytes/Second: {stats['bytes_per_second']:.2f}")
        
        print(f"\n{Fore.YELLOW}Protocol Distribution:")
        for proto, count in stats['protocol_distribution'].items():
            if count > 0:
                percentage = (count / stats['total_packets']) * 100
                print(f"  {proto.upper():6}: {count:6} packets ({percentage:5.1f}%)")
        
        print(f"\n{Fore.YELLOW}Unique IP Addresses:")
        print(f"  Source: {stats['unique_source_ips']}")
        print(f"  Destination: {stats['unique_destination_ips']}")
        
        print(f"{Fore.CYAN}{'='*80}")
    
    def get_top_talkers(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Get top talking IP addresses"""
        ip_counter = collections.Counter()
        
        for packet in self.captured_packets:
            if packet.source_ip and packet.source_ip != "Unknown":
                ip_counter[packet.source_ip] += 1
        
        return ip_counter.most_common(limit)
    
    def analyze_traffic_patterns(self):
        """Analyze traffic patterns for anomalies"""
        print(f"\n{Fore.YELLOW}[*] Analyzing traffic patterns...")
        
        # Group packets by protocol
        protocols = collections.Counter(p.protocol for p in self.captured_packets)
        
        # Analyze TCP connections
        tcp_connections = collections.Counter()
        for p in self.captured_packets:
            if p.protocol == 'TCP' and p.source_port and p.destination_port:
                conn = f"{p.source_ip}:{p.source_port} -> {p.destination_ip}:{p.destination_port}"
                tcp_connections[conn] += 1
        
        # Find most active connections
        if tcp_connections:
            print(f"\n{Fore.GREEN}Top TCP Connections:")
            for conn, count in tcp_connections.most_common(5):
                print(f"  {conn}: {count} packets")
        
        # Check for port scanning patterns
        source_ports = collections.defaultdict(set)
        for p in self.captured_packets:
            if p.source_ip and p.destination_port:
                source_ports[p.source_ip].add(p.destination_port)
        
        potential_scanners = []
        for ip, ports in source_ports.items():
            if len(ports) > self.alert_thresholds['port_scan']:
                potential_scanners.append((ip, len(ports)))
        
        if potential_scanners:
            print(f"\n{Fore.RED}[!] Potential Port Scanners Detected:")
            for ip, port_count in potential_scanners:
                print(f"  {ip}: Scanned {port_count} different ports")

# CLI interface for sniffer module
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Network Packet Sniffer")
    parser.add_argument("-i", "--interface", help="Network interface to sniff")
    parser.add_argument("-c", "--count", type=int, default=100, help="Number of packets to capture")
    parser.add_argument("-f", "--filter", help="BPF filter string")
    parser.add_argument("-o", "--output", help="Output file for capture")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if not SCAPY_AVAILABLE:
        print(f"{Fore.RED}[-] Scapy is required for packet sniffing")
        print(f"{Fore.YELLOW}[*] Install with: pip install scapy")
        sys.exit(1)
    
    sniffer = NetworkSniffer(interface=args.interface, verbose=args.verbose)
    
    if args.filter:
        # Parse filter (simple parsing)
        if 'host' in args.filter:
            parts = args.filter.split()
            ip = parts[parts.index('host') + 1] if 'host' in parts else None
            sniffer.ip_filter = ip
        
        if 'port' in args.filter:
            parts = args.filter.split()
            port = parts[parts.index('port') + 1] if 'port' in parts else None
            sniffer.port_filter = port
    
    print(f"{Fore.CYAN}[*] Starting network sniffer...")
    print(f"{Fore.YELLOW}[*] Capturing {args.count} packets")
    print(f"{Fore.YELLOW}[*] Press Ctrl+C to stop early\n")
    
    packets = sniffer.start_sniffing(packet_count=args.count)
    
    print(f"\n{Fore.GREEN}[+] Capture complete!")
    print(f"{Fore.GREEN}[+] Captured {len(packets)} packets")
    
    sniffer.display_statistics()
    
    if args.output:
        sniffer.save_capture(args.output)