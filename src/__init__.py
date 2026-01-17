"""
Network Security Analyzer - Core Modules
"""

__version__ = "2.0.0"
__author__ = "Cybersecurity Student"
__license__ = "MIT"

from .scanner import AdvancedPortScanner, PortResult
from .sniffer import NetworkSniffer, PacketInfo, TrafficStats
from .detector import AttackDetector, SecurityAlert
from .utils import (
    NetworkUtils, SecurityUtils, FileUtils, DisplayUtils, ValidationUtils,
    get_local_ip, get_network_interfaces, resolve_hostname, ping_host,
    print_banner, print_table, print_success, print_warning, print_error, print_info
)

__all__ = [
    # Scanner module
    'AdvancedPortScanner',
    'PortResult',
    
    # Sniffer module
    'NetworkSniffer',
    'PacketInfo',
    'TrafficStats',
    
    # Detector module
    'AttackDetector',
    'SecurityAlert',
    
    # Utils module
    'NetworkUtils',
    'SecurityUtils',
    'FileUtils',
    'DisplayUtils',
    'ValidationUtils',
    
    # Utility functions
    'get_local_ip',
    'get_network_interfaces',
    'resolve_hostname',
    'ping_host',
    'print_banner',
    'print_table',
    'print_success',
    'print_warning',
    'print_error',
    'print_info',
]