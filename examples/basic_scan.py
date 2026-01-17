#!/usr/bin/env python3
"""
Basic Network Scanning Example
Example script showing how to use the scanner module
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.scanner import AdvancedPortScanner
from src.utils import print_banner, print_success, print_error, print_info
from colorama import Fore, Style

def basic_port_scan():
    """Basic port scanning example"""
    print_banner()
    
    print(f"{Fore.CYAN}[*] Basic Port Scanning Example")
    print(f"{Fore.CYAN}{'='*60}")
    
    # Get target from user
    target = input(f"{Fore.GREEN}[?] Enter target IP address: ").strip()
    
    if not target:
        print_error("No target specified")
        return
    
    # Create scanner instance
    scanner = AdvancedPortScanner(max_threads=50, timeout=2)
    
    print_info(f"Starting scan on {target}")
    
    # Scan common ports
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5900, 8080]
    
    print_info(f"Scanning {len(common_ports)} common ports...")
    
    results = scanner.tcp_connect_scan(target, common_ports)
    
    # Display results
    scanner.display_results(results)
    
    # Generate report
    report = scanner.generate_report(target, results)
    
    print_success("Scan completed!")
    
    # Save results
    save = input(f"\n{Fore.GREEN}[?] Save results to file? (y/N): ").strip().lower()
    if save == 'y':
        filename = input(f"{Fore.GREEN}[?] Enter filename (default: scan_results.json): ").strip()
        filename = filename or "scan_results.json"
        scanner.generate_report(target, results, filename)

def comprehensive_scan_example():
    """Comprehensive scanning example"""
    print_banner()
    
    print(f"{Fore.CYAN}[*] Comprehensive Network Analysis Example")
    print(f"{Fore.CYAN}{'='*60}")
    
    target = "192.168.1.1"  # Example target
    
    print_info(f"Target: {target}")
    
    scanner = AdvancedPortScanner()
    
    # Run comprehensive scan
    print_info("Starting comprehensive scan...")
    results = scanner.comprehensive_scan(target, "1-1000")
    
    # Display results
    scanner.display_results(results)
    
    # Check for vulnerabilities
    print_info("Checking for common vulnerabilities...")
    
    vulnerable_ports = []
    for port, result in results.items():
        if result.state == 'open' and result.vulnerability:
            vulnerable_ports.append((port, result.vulnerability))
    
    if vulnerable_ports:
        print(f"\n{Fore.RED}[!] Potential Vulnerabilities Found:")
        for port, vuln in vulnerable_ports:
            print(f"{Fore.RED}  Port {port}: {vuln}")
    else:
        print_success("No obvious vulnerabilities found")

def network_discovery_example():
    """Network discovery example"""
    print_banner()
    
    print(f"{Fore.CYAN}[*] Network Discovery Example")
    print(f"{Fore.CYAN}{'='*60}")
    
    from src.utils import NetworkUtils
    
    # Get local network information
    local_ip = NetworkUtils.get_local_ip()
    print_info(f"Local IP: {local_ip}")
    
    # Get network interfaces
    interfaces = NetworkUtils.get_network_interfaces()
    
    if interfaces:
        print_info(f"Found {len(interfaces)} network interfaces:")
        
        for iface in interfaces:
            print(f"{Fore.GREEN}  Interface: {iface['name']}")
            print(f"{Fore.WHITE}    IP: {iface['ip']}")
            print(f"    MAC: {iface['mac']}")
            print(f"    Subnet: {iface['subnet']}")
            print()
    
    # Ping sweep example
    print_info("Performing ping sweep on local network...")
    
    network_range = "192.168.1.0/24"  # Example network
    
    print_info(f"Scanning network: {network_range}")
    print_info("This may take a while...")
    
    # Simple ping sweep
    alive_hosts = []
    for i in range(1, 11):  # Only scan first 10 hosts for example
        ip = f"192.168.1.{i}"
        if NetworkUtils.ping_host(ip):
            hostname = NetworkUtils.resolve_hostname(ip)
            alive_hosts.append((ip, hostname))
            print_success(f"Host alive: {ip} ({hostname})")
    
    print_info(f"Found {len(alive_hosts)} alive hosts")

def main():
    """Main example menu"""
    print_banner()
    
    while True:
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}EXAMPLES MENU")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.WHITE}1. Basic Port Scan")
        print(f"{Fore.WHITE}2. Comprehensive Scan")
        print(f"{Fore.WHITE}3. Network Discovery")
        print(f"{Fore.WHITE}4. Exit")
        print(f"{Fore.CYAN}{'='*60}")
        
        choice = input(f"\n{Fore.GREEN}[?] Select example (1-4): ").strip()
        
        if choice == '1':
            basic_port_scan()
        elif choice == '2':
            comprehensive_scan_example()
        elif choice == '3':
            network_discovery_example()
        elif choice == '4':
            print_info("Exiting...")
            break
        else:
            print_error("Invalid choice!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Example stopped by user")
    except Exception as e:
        print_error(f"Error: {e}")