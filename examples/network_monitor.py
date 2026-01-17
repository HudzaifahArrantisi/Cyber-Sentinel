#!/usr/bin/env python3
"""
Network Monitoring Example
Real-time network monitoring with alerting
"""

import sys
import os
import time
import threading
from datetime import datetime
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.sniffer import NetworkSniffer
from src.detector import AttackDetector
from src.utils import print_banner, print_success, print_warning, print_error, print_info
from colorama import Fore, Style

class NetworkMonitor:
    """Network monitoring class with real-time alerting"""
    
    def __init__(self, interface=None):
        self.interface = interface
        self.sniffer = NetworkSniffer(interface=interface, verbose=True)
        self.detector = AttackDetector()
        self.monitoring = False
        self.monitor_thread = None
        
        # Statistics
        self.packet_count = 0
        self.alert_count = 0
        self.start_time = None
        
        # Alert history
        self.alert_history = []
        
        # Callbacks
        self.sniffer.on_packet_callback = self._on_packet
        self.sniffer.on_alert_callback = self._on_alert
    
    def start_monitoring(self, duration=0):
        """Start network monitoring"""
        print_banner()
        
        print(f"{Fore.CYAN}[*] Starting Network Monitor")
        print(f"{Fore.CYAN}{'='*60}")
        
        if self.interface:
            print_info(f"Interface: {self.interface}")
        else:
            print_info("Interface: Auto-detect")
        
        if duration > 0:
            print_info(f"Duration: {duration} seconds")
        else:
            print_info("Duration: Continuous (press Ctrl+C to stop)")
        
        print_info("Monitoring started at: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        print()
        
        self.monitoring = True
        self.start_time = time.time()
        self.packet_count = 0
        self.alert_count = 0
        
        # Start monitoring in separate thread
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(duration,)
        )
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        # Display statistics periodically
        self._display_stats_thread()
        
        # Wait for monitor thread
        try:
            self.monitor_thread.join()
        except KeyboardInterrupt:
            self.stop_monitoring()
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitoring = False
        self.sniffer.stop_background_sniffing()
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        print_info("Monitoring stopped")
        self._display_final_stats()
    
    def _monitor_loop(self, duration):
        """Main monitoring loop"""
        try:
            if duration > 0:
                # Capture for specified duration
                self.sniffer.start_sniffing(timeout=duration)
            else:
                # Continuous capture
                self.sniffer.start_sniffing()
        except Exception as e:
            print_error(f"Monitoring error: {e}")
        finally:
            self.monitoring = False
    
    def _on_packet(self, packet_info):
        """Callback for each captured packet"""
        self.packet_count += 1
        
        # Update display every 100 packets
        if self.packet_count % 100 == 0:
            self._update_display()
    
    def _on_alert(self, alert_message, packet_info):
        """Callback for alerts"""
        self.alert_count += 1
        
        # Create alert record
        alert_record = {
            'timestamp': datetime.now().isoformat(),
            'message': alert_message,
            'packet': {
                'source': packet_info.source_ip,
                'destination': packet_info.destination_ip,
                'protocol': packet_info.protocol,
                'info': packet_info.info
            }
        }
        
        self.alert_history.append(alert_record)
        
        # Display alert
        print(f"\n{Fore.RED}[ALERT] {alert_message}")
        print(f"{Fore.YELLOW}  Source: {packet_info.source_ip}")
        print(f"  Destination: {packet_info.destination_ip}")
        print(f"  Protocol: {packet_info.protocol}")
        print(f"  Info: {packet_info.info}")
        
        # Save alert to file
        self._save_alert(alert_record)
    
    def _update_display(self):
        """Update statistics display"""
        elapsed = time.time() - self.start_time
        packets_per_sec = self.packet_count / elapsed if elapsed > 0 else 0
        
        print(f"\r{Fore.CYAN}[*] Packets: {self.packet_count:,} | "
              f"Alerts: {self.alert_count} | "
              f"Rate: {packets_per_sec:.1f} p/s", end='')
    
    def _display_stats_thread(self):
        """Display statistics in separate thread"""
        def stats_loop():
            while self.monitoring:
                self._update_display()
                time.sleep(1)
        
        stats_thread = threading.Thread(target=stats_loop)
        stats_thread.daemon = True
        stats_thread.start()
    
    def _display_final_stats(self):
        """Display final statistics"""
        elapsed = time.time() - self.start_time
        
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}MONITORING SUMMARY")
        print(f"{Fore.CYAN}{'='*60}")
        
        print(f"{Fore.GREEN}Duration: {elapsed:.1f} seconds")
        print(f"{Fore.GREEN}Total Packets: {self.packet_count:,}")
        print(f"{Fore.GREEN}Total Alerts: {self.alert_count}")
        
        if elapsed > 0:
            packets_per_sec = self.packet_count / elapsed
            print(f"{Fore.GREEN}Average Rate: {packets_per_sec:.1f} packets/second")
        
        # Display alert summary
        if self.alert_history:
            print(f"\n{Fore.YELLOW}Recent Alerts:")
            for alert in self.alert_history[-5:]:  # Last 5 alerts
                print(f"{Fore.RED}  [{alert['timestamp'][11:19]}] {alert['message']}")
        
        print(f"{Fore.CYAN}{'='*60}")
    
    def _save_alert(self, alert_record):
        """Save alert to file"""
        try:
            import json
            alert_file = "alerts.json"
            
            # Load existing alerts
            alerts = []
            if os.path.exists(alert_file):
                with open(alert_file, 'r') as f:
                    alerts = json.load(f)
            
            # Add new alert
            alerts.append(alert_record)
            
            # Save to file
            with open(alert_file, 'w') as f:
                json.dump(alerts, f, indent=2)
            
        except Exception as e:
            print_error(f"Failed to save alert: {e}")
    
    def save_capture(self, filename="capture.pcap"):
        """Save captured packets"""
        self.sniffer.save_capture(filename)

def real_time_traffic_analysis():
    """Real-time traffic analysis example"""
    monitor = NetworkMonitor()
    
    print_info("Starting real-time traffic analysis...")
    print_info("Press Ctrl+C to stop\n")
    
    try:
        # Set filter for specific traffic (optional)
        # monitor.sniffer.set_filter(protocol="tcp", port=80)
        
        # Start monitoring
        monitor.start_monitoring(duration=0)  # 0 = continuous
        
    except KeyboardInterrupt:
        print_info("\nStopping monitor...")
        monitor.stop_monitoring()
    except Exception as e:
        print_error(f"Error: {e}")
        monitor.stop_monitoring()
    
    # Save capture
    save = input(f"\n{Fore.GREEN}[?] Save capture to file? (y/N): ").strip().lower()
    if save == 'y':
        filename = input(f"{Fore.GREEN}[?] Enter filename: ").strip()
        monitor.save_capture(filename or "monitor_capture.pcap")

def interface_selection():
    """Select network interface for monitoring"""
    from src.utils import get_network_interfaces
    
    interfaces = get_network_interfaces()
    
    if not interfaces:
        print_error("No network interfaces found!")
        return None
    
    print_info("Available network interfaces:")
    for i, iface in enumerate(interfaces, 1):
        print(f"{Fore.WHITE}{i}. {iface['name']:20} - {iface['ip']}")
    
    try:
        choice = int(input(f"\n{Fore.GREEN}[?] Select interface (1-{len(interfaces)}): "))
        if 1 <= choice <= len(interfaces):
            return interfaces[choice-1]['name']
    except:
        pass
    
    return None

def main():
    """Main monitoring menu"""
    print_banner()
    
    while True:
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}NETWORK MONITOR")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.WHITE}1. Real-time Traffic Monitoring")
        print(f"{Fore.WHITE}2. Monitor Specific Interface")
        print(f"{Fore.WHITE}3. Monitor with Filter (HTTP only)")
        print(f"{Fore.WHITE}4. View Alert History")
        print(f"{Fore.WHITE}5. Exit")
        print(f"{Fore.CYAN}{'='*60}")
        
        choice = input(f"\n{Fore.GREEN}[?] Select option (1-5): ").strip()
        
        if choice == '1':
            real_time_traffic_analysis()
        elif choice == '2':
            interface = interface_selection()
            if interface:
                monitor = NetworkMonitor(interface=interface)
                monitor.start_monitoring(duration=30)  # 30 seconds
        elif choice == '3':
            monitor = NetworkMonitor()
            monitor.sniffer.set_filter(protocol="tcp", port=80)
            monitor.start_monitoring(duration=60)  # 60 seconds
        elif choice == '4':
            view_alert_history()
        elif choice == '5':
            print_info("Exiting...")
            break
        else:
            print_error("Invalid choice!")

def view_alert_history():
    """View alert history from file"""
    import json
    
    alert_file = "alerts.json"
    
    if not os.path.exists(alert_file):
        print_error("No alert history found!")
        return
    
    try:
        with open(alert_file, 'r') as f:
            alerts = json.load(f)
        
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}ALERT HISTORY ({len(alerts)} alerts)")
        print(f"{Fore.CYAN}{'='*60}")
        
        for i, alert in enumerate(alerts[-10:], 1):  # Show last 10 alerts
            print(f"{Fore.RED}{i}. [{alert['timestamp']}]")
            print(f"{Fore.YELLOW}   Message: {alert['message']}")
            print(f"{Fore.WHITE}   Source: {alert['packet']['source']}")
            print(f"   Destination: {alert['packet']['destination']}")
            print()
        
        print(f"{Fore.CYAN}{'='*60}")
        
    except Exception as e:
        print_error(f"Error reading alert history: {e}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Monitor stopped by user")
    except Exception as e:
        print_error(f"Error: {e}")