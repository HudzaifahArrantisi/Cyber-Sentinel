# 🛡️ CyberNet Sentinel - Advanced Network Security Analyzer By Candalena

<div align="center">

```
   ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ██╗███████╗████████╗
  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗████╗  ██║██╔════╝╚══██╔══╝
  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██╔██╗ ██║█████╗     ██║   
  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║╚██╗██║██╔══╝     ██║   
  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║ ╚████║███████╗   ██║   
   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   
              █▀ █▀▀ █▄░█ ▀█▀ █ █▄░█ █▀▀ █░░
              ▄█ ██▄ █░▀█ ░█░ █ █░▀█ ██▄ █▄▄
          Advanced Network Security Analyzer v2.1 Pro By Candalena
```

![CyberNet Sentinel Banner](https://img.shields.io/badge/CyberNet-Sentinel-00ff00?style=for-the-badge&logo=security&logoColor=white)

**Professional Network Security Analysis & Monitoring Tool**

🔥 **Cybernet Sentinel By Candalena** 🔥

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square)](https://github.com)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED?style=flat-square&logo=docker&logoColor=white)](Dockerfile)

[Features](#-key-features) • [Installation](#-installation) • [Usage](#-usage) • [Docker](#-docker-deployment) • [Documentation](#-documentation) • [License](#-license)

</div>

---

## 📖 About the Project

**CyberNet Sentinel** is a network security analysis tool developed as a Final Project for Web Security Course. This tool is designed to assist security analysts, network administrators, and cybersecurity enthusiasts in performing:

- 🔍 Network reconnaissance and discovery
- 🚪 Port scanning and service enumeration  
- 👂 Network traffic monitoring and analysis
- ⚠️ Attack detection and threat intelligence
- 📊 Security vulnerability assessment
- 📝 Automated reporting and documentation

---

## ✨ Key Features

### 🔍 1. Network Discovery
Device detection and network mapping with various methods:

- **ARP Scanning** - Active device detection using ARP protocol
- **Ping Sweep** - ICMP-based host discovery with multithreading
- **Hostname Resolution** - Automatic DNS reverse lookup
- **MAC Vendor Detection** - Device vendor identification from MAC address
- **Network Mapping** - Network topology visualization

**Example Output:**
```
[+] Host: 192.168.1.1    | MAC: 00:11:22:33:44:55 | Hostname: Router.local | Vendor: Cisco
[+] Host: 192.168.1.10   | MAC: AA:BB:CC:DD:EE:FF | Hostname: PC-Admin    | Vendor: Intel
```

### 🚪 2. Port Scanner
Advanced port scanning with multiple protocol support:

- **TCP Full Connect Scan** - Reliable connection-based scanning
- **UDP Port Scanning** - Open UDP service detection
- **Banner Grabbing** - Service banner extraction for identification
- **Service Detection** - Automatic service identification
- **Multithreading Support** - Fast scanning with 200+ concurrent threads
- **Custom Port Range** - Flexible port specification

**Capabilities:**
- Scan 1-65535 ports
- Adjustable timeout and threads
- Service version detection
- Common vulnerabilities identification

### 👂 3. Network Sniffer
Real-time packet capture and analysis:

- **Packet Capture** - Capture network traffic in real-time
- **Protocol Analysis** - Deep packet inspection (TCP/UDP/ICMP/ARP)
- **Traffic Statistics** - Traffic statistical analysis
- **Packet Filtering** - BPF filter support
- **Export Capability** - Save captured packets to file
- **Live Monitoring** - Real-time traffic visualization

**Protocol Support:**
- TCP (with flag analysis)
- UDP 
- ICMP
- ARP
- HTTP/HTTPS

### ⚠️ 4. Attack Detection
Intelligent threat detection system:

- **SYN Flood Detection** - SYN flood attack detection
- **Port Scan Detection** - Port scanning activity identification
- **DDoS Detection** - Distributed denial of service detection
- **ARP Spoofing Detection** - Man-in-the-middle attack detection
- **Brute Force Detection** - Login attempt monitoring
- **Anomaly Detection** - Behavioral analysis

**Severity Levels:**
- 🔴 **Critical** - Immediate action required
- 🟠 **High** - Serious security threat
- 🟡 **Medium** - Potential security issue
- 🔵 **Low** - Informational

### 🔒 5. Vulnerability Assessment
Basic security vulnerability scanning:

- **Common Port Vulnerabilities** - Known vulnerable services
- **Weak Configuration Detection** - Misconfiguration identification
- **CVE Database Lookup** - Known vulnerability matching
- **Remediation Recommendations** - Security hardening suggestions
- **Risk Scoring** - CVSS-based risk assessment

### 📊 6. Comprehensive Reporting
Multiple output formats:

- **JSON Export** - Machine-readable format
- **TXT Report** - Human-readable text format
- **HTML Report** - Visual web-based report
- **CSV Export** - Spreadsheet compatible
- **PDF Report** - Professional documentation

---

## 🚀 Installation

### System Requirements

**Minimum Requirements:**
- Python 3.8 or higher
- 2GB RAM
- 100MB disk space
- Administrator/root privileges (for packet capture)

**Operating Systems:**
- ✅ Windows 10/11
- ✅ Ubuntu 20.04+
- ✅ Debian 11+
- ✅ macOS 11+
- ✅ Kali Linux

### 📦 Method 1: Manual Installation

#### Windows

```powershell
# Clone repository
git clone https://github.com/HudzaifahArrantisi/Cyber-Sentinel.git
cd cybernet-sentinel

# Install dependencies
pip install -r requirements.txt

# Install Npcap (Required for packet capture)
# Download from: https://npcap.com/#download

# Run as Administrator
python network_analyzer.py
```

#### Linux/Ubuntu

```bash
# Update system
sudo apt update

# Install dependencies
sudo apt install -y python3 python3-pip nmap tcpdump libpcap-dev

# Clone repository
git clone https://github.com/HudzaifahArrantisi/Cyber-Sentinel.git
cd cybernet-sentinel

# Install Python packages
pip3 install -r requirements.txt

# Run with sudo
sudo python3 network_analyzer.py
```

#### macOS

```bash
# Install Homebrew if not installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install python3 nmap libpcap

# Clone repository
git clone https://github.com/HudzaifahArrantisi/Cyber-Sentinel.git
cd cybernet-sentinel

# Install Python packages
pip3 install -r requirements.txt

# Run with sudo
sudo python3 network_analyzer.py
```

### 📦 Method 2: Script Installation

#### Windows
```powershell
# Download and run installer
.\install_windows.ps1
```

#### Linux
```bash
# Download and run installer
chmod +x install_linux.sh
sudo ./install_linux.sh
```

### 📦 Method 3: Docker (Recommended)

```bash
# Build Docker image
docker build -t cybernet-sentinel .

# Run container
docker run -it --network host --privileged cybernet-sentinel

# Or with docker-compose
docker-compose up
```

---

## 🎯 Usage

### Quick Start

```bash
# Run the program
python network_analyzer.py

# Main menu will appear
# Select options according to your needs (1-9)
```

### 📚 Complete Guide

#### 1️⃣ Select Network Interface
```
Select the network interface to be used for scanning

Steps:
1. Select option 1 from main menu
2. Choose interface from the available list
3. Interface will be set for subsequent operations
```

#### 2️⃣ Network Discovery
```
Scan network to find active hosts

Steps:
1. Ensure interface is already selected
2. Select option 2
3. Wait for scanning process to complete
4. View list of discovered hosts

Methods used:
- ARP Scan (faster for local network)
- Ping Sweep (fallback method)
```

#### 3️⃣ Port Scanner
```
Scan ports on target host

Steps:
1. Select option 3
2. Choose target from list or input IP manually
3. Specify port range (default: 1-1024)
4. Set number of threads (default: 200)
5. Wait for scanning results

Tips:
- Port 1-1024: Common ports (fast)
- Port 1-10000: Extended scan (medium)
- Port 1-65535: Full port scan (slow)
```

#### 4️⃣ Network Sniffer
```
Capture and analyze network traffic

Steps:
1. Select option 4
2. Specify number of packets to capture
3. Set BPF filter (optional)
4. Press Ctrl+C to stop

BPF Filter Examples:
- "tcp port 80"     -> HTTP traffic only
- "udp"             -> UDP packets only
- "host 192.168.1.1" -> Specific host
- "tcp and port 443" -> HTTPS traffic
```

#### 5️⃣ Attack Detection
```
Analyze traffic for attack detection

Steps:
1. Ensure traffic has been captured (option 4)
2. Select option 5
3. View threat analysis results

Available detections:
- SYN Flood
- Port Scanning
- DDoS Attack
- ARP Spoofing
```

#### 6️⃣ Comprehensive Security Audit
```
Complete security audit automatically

Steps:
1. Select option 6
2. Program will automatically:
   - Select interface
   - Network discovery
   - Port scanning (first 5 hosts)
   - Traffic capture (200 packets)
   - Attack detection
   - Generate report
3. Option to save report to TXT file
```

#### 7️⃣ Export Results
```
Export results to file

Supported formats:
- TXT (readable text report)
- JSON (structured data)
```

#### 8️⃣ Display Summary
```
Display analysis results summary in terminal
```

---

## 🐳 Docker Deployment

### Dockerfile
Dockerfile is provided for easy deployment.

### Build & Run

```bash
# Build image
docker build -t cybernet-sentinel:latest .

# Run container
docker run -it --rm \
  --network host \
  --privileged \
  --name sentinel \
  cybernet-sentinel:latest
```

### Docker Compose

```bash
# Run with compose
docker-compose up -d

# Access container
docker-compose exec sentinel bash

# Stop container
docker-compose down
```

### Docker Command Examples

```bash
# Run with volume mount
docker run -it --rm \
  --network host \
  --privileged \
  -v $(pwd)/reports:/app/reports \
  cybernet-sentinel:latest

# Run with environment variables
docker run -it --rm \
  --network host \
  --privileged \
  -e TARGET_NETWORK="192.168.1.0/24" \
  -e SCAN_PORTS="1-10000" \
  cybernet-sentinel:latest

# Run with custom command
docker run -it --rm \
  --network host \
  --privileged \
  cybernet-sentinel:latest \
  python network_analyzer.py --help
```

---

## 📚 Documentation

### API Documentation
Complete documentation available in `docs/` folder:
- [User Guide](docs/user_guide.md) - Complete user guide
- [Developer Guide](docs/developer_guide.md) - Developer guide
- [API Reference](docs/api.md) - API documentation

### Code Structure

```
cybernet-sentinel/
├── network_analyzer.py      # Main program
├── src/
│   ├── analyzer.py          # Network analysis core
│   ├── detector.py          # Attack detection engine
│   ├── reporter.py          # Report generation
│   ├── scanner.py           # Port scanning module
│   ├── sniffer.py           # Packet capture module
│   └── utils.py             # Helper functions
├── tests/
│   ├── test_scanner.py      # Scanner unit tests
│   ├── test_sniffer.py      # Sniffer unit tests
│   └── test_detector.py     # Detector unit tests
├── examples/
│   ├── basic_scan.py        # Basic usage example
│   ├── network_monitor.py   # Monitoring example
│   └── vulnerability_scan.py # Vulnerability scan example
├── docs/                    # Documentation
├── reports/                 # Generated reports
├── config.yaml              # Configuration file
├── requirements.txt         # Python dependencies
├── Dockerfile              # Docker configuration
└── docker-compose.yml      # Docker Compose config
```

### Configuration

Edit `config.yaml` for custom configuration:

```yaml
# config.yaml
network:
  interface: "auto"          # Interface name or "auto"
  timeout: 5                 # Timeout in seconds
  threads: 200              # Number of threads for scanning

scanning:
  default_port_range: "1-1024"
  scan_timeout: 0.5
  enable_udp_scan: true
  enable_banner_grab: true

sniffing:
  default_packet_count: 100
  default_filter: "ip"
  save_pcap: true

detection:
  syn_flood_threshold: 50
  port_scan_threshold: 10
  ddos_threshold: 100
  enable_alerts: true

reporting:
  format: "json"            # json, html, csv, txt
  save_path: "./reports"
  include_raw_data: false
```

---

## 🔧 Troubleshooting

### Common Issues

#### 1. Module Not Found Error
```bash
# Install missing modules
pip install -r requirements.txt

# For netifaces issue on Windows
pip install netifaces-plus
```

#### 2. Permission Denied
```bash
# Linux/Mac
sudo python3 network_analyzer.py

# Windows
# Run PowerShell/CMD as Administrator
python network_analyzer.py
```

#### 3. Packet Capture Failed
```bash
# Windows: Install Npcap
https://npcap.com/#download

# Linux: Install libpcap
sudo apt install libpcap-dev

# Check permissions
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
```

#### 4. No Network Interface Found
```bash
# List available interfaces
# Windows
ipconfig

# Linux/Mac
ifconfig
ip addr show

# Select an active and connected interface
```

---

## 🧪 Testing

### Run Unit Tests

```bash
# Run all tests
pytest

# Run specific test
pytest tests/test_scanner.py

# Run with coverage
pytest --cov=src tests/

# Generate HTML coverage report
pytest --cov=src --cov-report=html tests/
```

### Manual Testing

```bash
# Test port scanner
python examples/basic_scan.py

# Test network monitor
python examples/network_monitor.py

# Test vulnerability scanner
python examples/vulnerability_scan.py
```

---

## 🤝 Contributing

Contributions are very welcome! Here's how to contribute:

1. Fork this repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request

### Development Setup

```bash
# Clone repository
git clone https://github.com/HudzaifahArrantisi/Cyber-Sentinel.git
cd cybernet-sentinel

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install dev dependencies
pip install -r requirements.txt
pip install pytest black flake8 mypy pylint

# Run linters
black .
flake8 src/
mypy src/
pylint src/
```

---

## ⚠️ Legal Disclaimer

**IMPORTANT: Use this tool only for legal and ethical purposes!**

- ✅ **Legal Use**: Security testing on own systems or with written permission
- ✅ **Educational**: Cybersecurity learning and research
- ✅ **Authorized Testing**: Penetration testing with proper authorization

- ❌ **Illegal Use**: Unauthorized access or scanning without permission
- ❌ **Malicious Intent**: Using for malicious or criminal purposes
- ❌ **Privacy Violation**: Violating others' privacy

**User Responsibility:**
Users are fully responsible for the use of this tool. Developers are not responsible for misuse or damage caused.

---

## 📜 License

This project is licensed under MIT License - see [LICENSE](LICENSE) file for complete details.

```
MIT License

Copyright (c) 2024-2026 Candalena

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

## 👨‍💻 Author

**Candalena**
- 🎓 Semester 3 - Web Security Course
- 🏫 Final Project - Network Security Analysis Tool
- 📧 Email: [hudzaifaharrantisi@gmail.com](mailto:hudzaifaharrantisi@gmail.com)
- 🔗 GitHub: [@HudzaifahArrantisi](https://github.com/HudzaifahArrantisi)

---

## 🙏 Acknowledgments

Special thanks to:
- Scapy Project for packet manipulation library
- Python Community for amazing ecosystem
- Course instructor for guidance and support
- Open source contributors who inspired this project

---

## 📞 Support

Need help? Please:
- 📖 Read [Documentation](docs/)
- 🐛 Report bugs via [Issues](https://github.com/HudzaifahArrantisi/Cyber-Sentinel/issues)
- 💬 Discuss at [Discussions](https://github.com/HudzaifahArrantisi/Cyber-Sentinel/discussions)
- 📧 Email to [hudzaifaharrantisi@gmail.com](mailto:hudzaifaharrantisi@gmail.com)

---

## 🗺️ Roadmap

### Version 2.1 (Q1 2026)
- [ ] Web-based dashboard
- [ ] Real-time alerting system
- [ ] Database integration (PostgreSQL)
- [ ] Advanced ML-based anomaly detection
- [ ] REST API support

### Version 2.2 (Q2 2026)
- [ ] IPv6 support
- [ ] Wireless network analysis
- [ ] SSL/TLS vulnerability scanning
- [ ] SIEM tools integration
- [ ] Mobile app (Android/iOS)

### Version 3.0 (Q3 2026)
- [ ] Distributed scanning capability
- [ ] Cloud integration (AWS/Azure/GCP)
- [ ] Advanced threat intelligence feeds
- [ ] Compliance reporting (PCI-DSS, HIPAA)
- [ ] Custom plugin system

---

<div align="center">

### ⭐ Star this repository if you find it useful!

**Made with ❤️ by Candalena**

[Report Bug](https://github.com/HudzaifahArrantisi/Cyber-Sentinel/issues) • [Request Feature](https://github.com/HudzaifahArrantisi/Cyber-Sentinel/issues) • [Documentation](docs/)

---

**© 2024-2026 CyberNet Sentinel | MIT License**

</div>
