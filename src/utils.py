#!/usr/bin/env python3
"""
Utility Functions Module
Common utilities for network security analyzer
"""

import socket
import subprocess
import platform
import os
import sys
import ipaddress
import json
import time
import hashlib
import base64
from datetime import datetime
from typing import Optional, Dict, List, Tuple, Any
from colorama import Fore, Style, init
import netifaces
import psutil

# Initialize colorama
init(autoreset=True)

class NetworkUtils:
    """Network utility functions"""
    
    @staticmethod
    def get_local_ip() -> Optional[str]:
        """Get local IP address"""
        try:
            # Create a socket connection to get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            try:
                # Alternative method
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                return local_ip
            except:
                return "127.0.0.1"
    
    @staticmethod
    def get_network_interfaces() -> List[Dict]:
        """Get all network interfaces with details"""
        interfaces = []
        
        try:
            if platform.system() == "Windows":
                interfaces = NetworkUtils._get_windows_interfaces()
            else:
                interfaces = NetworkUtils._get_unix_interfaces()
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error getting interfaces: {e}")
            interfaces = NetworkUtils._get_fallback_interfaces()
        
        return interfaces
    
    @staticmethod
    def _get_windows_interfaces() -> List[Dict]:
        """Get network interfaces on Windows"""
        interfaces = []
        
        try:
            import wmi
            c = wmi.WMI()
            
            for interface in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
                if interface.IPAddress:
                    ip = interface.IPAddress[0]
                    if ip != "0.0.0.0":
                        interfaces.append({
                            'name': interface.Description,
                            'ip': ip,
                            'mac': interface.MACAddress,
                            'subnet': interface.IPSubnet[0] if interface.IPSubnet else '255.255.255.0',
                            'status': 'Up' if interface.IPEnabled else 'Down'
                        })
        except ImportError:
            # Fallback using psutil
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and addr.address != '127.0.0.1':
                        interfaces.append({
                            'name': iface,
                            'ip': addr.address,
                            'mac': psutil.net_if_stats()[iface].address if iface in psutil.net_if_stats() else 'Unknown',
                            'subnet': addr.netmask,
                            'status': 'Up'
                        })
        
        return interfaces
    
    @staticmethod
    def _get_unix_interfaces() -> List[Dict]:
        """Get network interfaces on Unix/Linux/MacOS"""
        interfaces = []
        
        for iface in netifaces.interfaces():
            try:
                # Skip loopback
                if iface == 'lo':
                    continue
                
                addrs = netifaces.ifaddresses(iface)
                
                if netifaces.AF_INET in addrs:
                    ip_info = addrs[netifaces.AF_INET][0]
                    
                    # Get MAC address
                    mac = 'Unknown'
                    if netifaces.AF_LINK in addrs:
                        mac_info = addrs[netifaces.AF_LINK][0]
                        mac = mac_info.get('addr', 'Unknown')
                    
                    interfaces.append({
                        'name': iface,
                        'ip': ip_info['addr'],
                        'mac': mac,
                        'subnet': ip_info.get('netmask', '255.255.255.0'),
                        'status': 'Up'
                    })
            except:
                continue
        
        return interfaces
    
    @staticmethod
    def _get_fallback_interfaces() -> List[Dict]:
        """Fallback method to get interfaces"""
        interfaces = []
        
        try:
            # Try socket method
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            
            if ip != '127.0.0.1':
                interfaces.append({
                    'name': 'default',
                    'ip': ip,
                    'mac': 'Unknown',
                    'subnet': '255.255.255.0',
                    'status': 'Up'
                })
        except:
            pass
        
        return interfaces
    
    @staticmethod
    def calculate_network_range(ip: str, subnet_mask: str) -> str:
        """Calculate network range from IP and subnet mask"""
        try:
            # Convert to CIDR notation
            cidr = NetworkUtils.subnet_mask_to_cidr(subnet_mask)
            network = ipaddress.ip_network(f"{ip}/{cidr}", strict=False)
            return str(network)
        except:
            # Default to /24 if calculation fails
            return f"{ip}/24"
    
    @staticmethod
    def subnet_mask_to_cidr(subnet_mask: str) -> int:
        """Convert subnet mask to CIDR notation"""
        try:
            # Convert subnet mask to binary
            binary_str = ''.join([bin(int(x))[2:].zfill(8) for x in subnet_mask.split('.')])
            return binary_str.count('1')
        except:
            return 24  # Default /24
    
    @staticmethod
    def resolve_hostname(ip: str) -> str:
        """Resolve IP address to hostname"""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except:
            return "Unknown"
    
    @staticmethod
    def get_mac_vendor(mac_address: str) -> str:
        """Get vendor information from MAC address"""
        try:
            # Clean MAC address
            mac = mac_address.replace(':', '').replace('-', '').upper()[:6]
            
            # Load local OUI database
            vendors = NetworkUtils._load_oui_database()
            
            if mac in vendors:
                return vendors[mac]
            
            # Try online lookup (commented out to avoid external requests)
            # return NetworkUtils._online_mac_lookup(mac_address)
            
            return "Unknown"
        except:
            return "Unknown"
    
    @staticmethod
    def _load_oui_database() -> Dict:
        """Load local OUI database"""
        # Common vendors (partial list)
        vendors = {
            '000C29': 'VMware',
            '001C14': 'Cisco',
            '001B21': 'Netgear',
            '0021B9': 'Intel',
            '001D0F': 'Apple',
            '0050F2': 'Microsoft',
            '001E65': 'Belkin',
            '001A2B': 'Samsung',
            '00805F': 'Netgear',
            '00017F': 'ASUS',
            '0016B6': 'Cisco',
            '001DE1': 'Samsung',
            '001E8C': 'Intel',
            '0022B0': 'Dell',
            '0023D6': 'Apple',
            '0024E8': 'Huawei',
            '0026C7': 'Apple',
            '002710': 'Microsoft',
            '003065': 'Apple',
            '0030BD': 'Apple',
            '0050BA': 'Dell',
            '0050E4': 'Apple',
            '0060B0': 'HP',
            '00A0C9': 'Intel',
            '00C0B0': 'Apple',
            '00E018': 'Cisco',
            '00E0FC': 'Apple',
            '080002': '3Com',
            '080009': 'HP',
            '080020': 'Sun',
            '08005A': 'IBM',
            '080069': 'Silicon Graphics',
            '080086': 'Apple',
            '08008B': 'Apple',
        }
        
        return vendors
    
    @staticmethod
    def ping_host(ip: str, timeout: int = 1) -> bool:
        """Ping a host to check if it's alive"""
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '1', '-w', str(timeout * 1000), str(ip)]
            
            # Redirect output to avoid console spam
            with open(os.devnull, 'w') as devnull:
                result = subprocess.run(command, stdout=devnull, stderr=devnull)
            
            return result.returncode == 0
        except:
            return False
    
    @staticmethod
    def traceroute(target: str, max_hops: int = 30) -> List[Dict]:
        """Perform traceroute to target"""
        results = []
        
        try:
            if platform.system() == "Windows":
                command = ['tracert', '-h', str(max_hops), '-w', '1000', target]
            else:
                command = ['traceroute', '-m', str(max_hops), '-w', '1', target]
            
            process = subprocess.run(command, capture_output=True, text=True)
            
            # Parse output (simplified)
            lines = process.stdout.split('\n')
            for line in lines[1:]:  # Skip header
                if line.strip():
                    # Parse line (this is simplified)
                    parts = line.split()
                    if len(parts) >= 2:
                        hop = {
                            'hop_number': parts[0],
                            'ip': parts[1] if parts[1] != '*' else 'Timeout',
                            'hostname': ' '.join(parts[2:]) if len(parts) > 2 else ''
                        }
                        results.append(hop)
            
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Traceroute failed: {e}")
        
        return results
    
    @staticmethod
    def get_external_ip() -> Optional[str]:
        """Get external/public IP address"""
        try:
            # Try multiple services in case one fails
            services = [
                'https://api.ipify.org',
                'https://checkip.amazonaws.com',
                'https://icanhazip.com',
                'https://ifconfig.me/ip'
            ]
            
            import requests
            
            for service in services:
                try:
                    response = requests.get(service, timeout=5)
                    if response.status_code == 200:
                        return response.text.strip()
                except:
                    continue
            
            return None
        except:
            return None

class SecurityUtils:
    """Security utility functions"""
    
    @staticmethod
    def generate_hash(data: str, algorithm: str = 'sha256') -> str:
        """Generate hash of data"""
        hash_func = getattr(hashlib, algorithm, hashlib.sha256)
        return hash_func(data.encode()).hexdigest()
    
    @staticmethod
    def encode_base64(data: str) -> str:
        """Base64 encode data"""
        return base64.b64encode(data.encode()).decode()
    
    @staticmethod
    def decode_base64(data: str) -> str:
        """Base64 decode data"""
        return base64.b64decode(data).decode()
    
    @staticmethod
    def check_weak_password(password: str) -> List[str]:
        """Check if password is weak"""
        warnings = []
        
        if len(password) < 8:
            warnings.append("Password is too short (minimum 8 characters)")
        
        if not any(c.isupper() for c in password):
            warnings.append("Password should contain uppercase letters")
        
        if not any(c.islower() for c in password):
            warnings.append("Password should contain lowercase letters")
        
        if not any(c.isdigit() for c in password):
            warnings.append("Password should contain numbers")
        
        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?`~' for c in password):
            warnings.append("Password should contain special characters")
        
        # Common weak passwords
        weak_passwords = [
            'password', '123456', 'qwerty', 'admin', 'welcome',
            'password123', 'letmein', 'monkey', 'sunshine', 'iloveyou'
        ]
        
        if password.lower() in weak_passwords:
            warnings.append("Password is too common")
        
        return warnings
    
    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except:
            return False
    
    @staticmethod
    def validate_port(port: int) -> bool:
        """Validate port number"""
        return 1 <= port <= 65535
    
    @staticmethod
    def sanitize_input(input_str: str) -> str:
        """Sanitize user input to prevent injection attacks"""
        # Remove potentially dangerous characters
        dangerous = ['<', '>', '"', "'", ';', '&', '|', '$', '`']
        sanitized = input_str
        
        for char in dangerous:
            sanitized = sanitized.replace(char, '')
        
        return sanitized.strip()

class FileUtils:
    """File utility functions"""
    
    @staticmethod
    def read_json(file_path: str) -> Optional[Dict]:
        """Read JSON file"""
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"{Fore.RED}[-] Error reading JSON file: {e}")
            return None
    
    @staticmethod
    def write_json(data: Any, file_path: str, indent: int = 2):
        """Write data to JSON file"""
        try:
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=indent, default=str)
            return True
        except Exception as e:
            print(f"{Fore.RED}[-] Error writing JSON file: {e}")
            return False
    
    @staticmethod
    def create_directory(directory: str):
        """Create directory if it doesn't exist"""
        try:
            os.makedirs(directory, exist_ok=True)
            return True
        except Exception as e:
            print(f"{Fore.RED}[-] Error creating directory: {e}")
            return False
    
    @staticmethod
    def get_file_hash(file_path: str, algorithm: str = 'sha256') -> Optional[str]:
        """Calculate file hash"""
        try:
            hash_func = getattr(hashlib, algorithm, hashlib.sha256)
            
            with open(file_path, 'rb') as f:
                file_hash = hash_func()
                chunk = f.read(8192)
                while chunk:
                    file_hash.update(chunk)
                    chunk = f.read(8192)
            
            return file_hash.hexdigest()
        except Exception as e:
            print(f"{Fore.RED}[-] Error calculating file hash: {e}")
            return None
    
    @staticmethod
    def backup_file(file_path: str):
        """Create backup of file"""
        try:
            if os.path.exists(file_path):
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_path = f"{file_path}.backup_{timestamp}"
                
                import shutil
                shutil.copy2(file_path, backup_path)
                
                print(f"{Fore.GREEN}[+] Backup created: {backup_path}")
                return backup_path
        except Exception as e:
            print(f"{Fore.RED}[-] Error creating backup: {e}")
        
        return None

class DisplayUtils:
    """Display and formatting utilities"""
    
    @staticmethod
    def print_banner():
        """Print application banner"""
        banner = f"""
{Fore.CYAN}{'='*70}
{Fore.GREEN}      ██████╗ ███████╗████████╗██╗  ██╗███████╗████████╗
      ██╔══██╗██╔════╝╚══██╔══╝██║  ██║██╔════╝╚══██╔══╝
      ██████╔╝█████╗     ██║   ███████║███████╗   ██║   
      ██╔══██╗██╔══╝     ██║   ██╔══██║╚════██║   ██║   
      ██║  ██║███████╗   ██║   ██║  ██║███████║   ██║   
      ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝   ╚═╝   
{Fore.YELLOW}         Advanced Network Security Analyzer v2.0
{Fore.CYAN}{'='*70}
{Fore.WHITE}Created by: Cybersecurity Student | Semester 3
{Fore.CYAN}{'='*70}
        """
        print(banner)
    
    @staticmethod
    def print_table(headers: List[str], rows: List[List], max_width: int = 80):
        """Print data in table format"""
        # Calculate column widths
        col_widths = []
        for i, header in enumerate(headers):
            max_len = len(header)
            for row in rows:
                if i < len(row):
                    cell_len = len(str(row[i]))
                    if cell_len > max_len:
                        max_len = cell_len
            # Limit width
            max_len = min(max_len, max_width // len(headers))
            col_widths.append(max_len)
        
        # Print header
        header_line = " | ".join(h.ljust(w) for h, w in zip(headers, col_widths))
        separator = "-+-".join('-' * w for w in col_widths)
        
        print(f"\n{Fore.CYAN}{header_line}")
        print(f"{Fore.CYAN}{separator}")
        
        # Print rows
        for row in rows:
            row_cells = []
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    cell_str = str(cell)
                    if len(cell_str) > col_widths[i]:
                        cell_str = cell_str[:col_widths[i]-3] + "..."
                    row_cells.append(cell_str.ljust(col_widths[i]))
                else:
                    row_cells.append("".ljust(col_widths[i]))
            
            print(f"{Fore.WHITE}{' | '.join(row_cells)}")
    
    @staticmethod
    def print_progress_bar(iteration: int, total: int, prefix: str = '', suffix: str = '', 
                          length: int = 50, fill: str = '█'):
        """Print progress bar"""
        percent = ("{0:.1f}").format(100 * (iteration / float(total)))
        filled_length = int(length * iteration // total)
        bar = fill * filled_length + '-' * (length - filled_length)
        
        print(f'\r{Fore.CYAN}{prefix} |{bar}| {percent}% {suffix}', end='\r')
        
        if iteration == total:
            print()
    
    @staticmethod
    def colorize_severity(severity: str) -> str:
        """Color code severity levels"""
        colors = {
            'Critical': Fore.RED + Style.BRIGHT,
            'High': Fore.RED,
            'Medium': Fore.YELLOW,
            'Low': Fore.BLUE,
            'Info': Fore.CYAN
        }
        return colors.get(severity, Fore.WHITE) + severity
    
    @staticmethod
    def print_success(message: str):
        """Print success message"""
        print(f"{Fore.GREEN}[+] {message}")
    
    @staticmethod
    def print_warning(message: str):
        """Print warning message"""
        print(f"{Fore.YELLOW}[!] {message}")
    
    @staticmethod
    def print_error(message: str):
        """Print error message"""
        print(f"{Fore.RED}[-] {message}")
    
    @staticmethod
    def print_info(message: str):
        """Print info message"""
        print(f"{Fore.CYAN}[*] {message}")

class ValidationUtils:
    """Validation utilities"""
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email address format"""
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate URL format"""
        import re
        pattern = r'^(https?://)?(www\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(/\S*)?$'
        return bool(re.match(pattern, url))
    
    @staticmethod
    def validate_mac_address(mac: str) -> bool:
        """Validate MAC address format"""
        import re
        patterns = [
            r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$',
            r'^([0-9A-Fa-f]{4}\.){2}([0-9A-Fa-f]{4})$'
        ]
        return any(bool(re.match(p, mac)) for p in patterns)

# Export commonly used functions
get_local_ip = NetworkUtils.get_local_ip
get_network_interfaces = NetworkUtils.get_network_interfaces
resolve_hostname = NetworkUtils.resolve_hostname
ping_host = NetworkUtils.ping_host
print_banner = DisplayUtils.print_banner
print_table = DisplayUtils.print_table
print_success = DisplayUtils.print_success
print_warning = DisplayUtils.print_warning
print_error = DisplayUtils.print_error
print_info = DisplayUtils.print_info

if __name__ == "__main__":
    # Test the utilities
    print_banner()
    
    # Test network utilities
    local_ip = get_local_ip()
    print_success(f"Local IP: {local_ip}")
    
    interfaces = get_network_interfaces()
    print_info(f"Found {len(interfaces)} network interfaces")
    
    # Display interfaces in table
    if interfaces:
        headers = ['Interface', 'IP Address', 'MAC Address', 'Status']
        rows = []
        for iface in interfaces[:5]:  # Show first 5
            rows.append([iface['name'], iface['ip'], iface['mac'], iface['status']])
        
        DisplayUtils.print_table(headers, rows)
    
    # Test security utilities
    test_password = "password123"
    warnings = SecurityUtils.check_weak_password(test_password)
    if warnings:
        print_warning(f"Weak password '{test_password}':")
        for warning in warnings:
            print(f"  - {warning}")
    
    # Test display utilities
    print_info("Testing progress bar:")
    for i in range(101):
        DisplayUtils.print_progress_bar(i, 100, prefix='Progress:', suffix='Complete')
        time.sleep(0.01)