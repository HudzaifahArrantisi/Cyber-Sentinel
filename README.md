# 🛡️ CyberNet Sentinel - Advanced Network Security Analyzer

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

[Fitur](#-fitur-utama) • [Instalasi](#-instalasi) • [Penggunaan](#-penggunaan) • [Docker](#-docker-deployment) • [Dokumentasi](#-dokumentasi) • [Lisensi](#-lisensi)

</div>

---

## 📖 Tentang Proyek

**CyberNet Sentinel** adalah alat analisis keamanan jaringan yang dikembangkan untuk Final Project Mata Kuliah Web Security. Tool ini dirancang untuk membantu security analyst, network administrator, dan cybersecurity enthusiast dalam melakukan:

- 🔍 Network reconnaissance dan discovery
- 🚪 Port scanning dan service enumeration  
- 👂 Network traffic monitoring dan analysis
- ⚠️ Attack detection dan threat intelligence
- 📊 Security vulnerability assessment
- 📝 Automated reporting dan documentation

---

## ✨ Fitur Utama

### 🔍 1. Network Discovery
Deteksi dan pemetaan perangkat di jaringan dengan berbagai metode:

- **ARP Scanning** - Deteksi perangkat aktif menggunakan ARP protocol
- **Ping Sweep** - ICMP-based host discovery dengan multithreading
- **Hostname Resolution** - Automatic DNS reverse lookup
- **MAC Vendor Detection** - Identifikasi vendor perangkat dari MAC address
- **Network Mapping** - Visualisasi topologi jaringan

**Contoh Output:**
```
[+] Host: 192.168.1.1    | MAC: 00:11:22:33:44:55 | Hostname: Router.local | Vendor: Cisco
[+] Host: 192.168.1.10   | MAC: AA:BB:CC:DD:EE:FF | Hostname: PC-Admin    | Vendor: Intel
```

### 🚪 2. Port Scanner
Advanced port scanning dengan multiple protocol support:

- **TCP Full Connect Scan** - Reliable connection-based scanning
- **UDP Port Scanning** - Deteksi layanan UDP terbuka
- **Banner Grabbing** - Mengambil service banner untuk identifikasi
- **Service Detection** - Automatic service identification
- **Multithreading Support** - Fast scanning dengan 100+ concurrent threads
- **Custom Port Range** - Flexible port specification

**Kemampuan:**
- Scan 1-65535 ports
- Adjustable timeout dan threads
- Service version detection
- Common vulnerabilities identification

### 👂 3. Network Sniffer
Real-time packet capture dan analysis:

- **Packet Capture** - Menangkap traffic jaringan secara real-time
- **Protocol Analysis** - Deep packet inspection (TCP/UDP/ICMP/ARP)
- **Traffic Statistics** - Analisis statistik lalu lintas
- **Packet Filtering** - BPF filter support
- **Export Capability** - Simpan captured packets ke file
- **Live Monitoring** - Real-time traffic visualization

**Protocol Support:**
- TCP (dengan flag analysis)
- UDP 
- ICMP
- ARP
- HTTP/HTTPS

### ⚠️ 4. Attack Detection
Intelligent threat detection system:

- **SYN Flood Detection** - Deteksi serangan SYN flood
- **Port Scan Detection** - Identifikasi aktivitas port scanning
- **DDoS Detection** - Deteksi distributed denial of service
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
- **HTML Report** - Visual web-based report
- **Text Summary** - CLI-based output
- **CSV Export** - Spreadsheet compatible
- **PDF Report** - Professional documentation

---

## 🚀 Instalasi

### Prasyarat Sistem

**Minimum Requirements:**
- Python 3.8 atau lebih tinggi
- 2GB RAM
- 100MB disk space
- Administrator/root privileges (untuk packet capture)

**Sistem Operasi:**
- ✅ Windows 10/11
- ✅ Ubuntu 20.04+
- ✅ Debian 11+
- ✅ macOS 11+
- ✅ Kali Linux

### 📦 Metode 1: Instalasi Manual

#### Windows

```powershell
# Clone repository
git clone https://github.com/cybersecurity-student/cybernet-sentinel.git
cd cybernet-sentinel

# Install dependencies
pip install -r requirements.txt

# Install Npcap (Required for packet capture)
# Download dari: https://npcap.com/#download

# Jalankan sebagai Administrator
python network_analyzer.py
```

#### Linux/Ubuntu

```bash
# Update sistem
sudo apt update

# Install dependencies
sudo apt install -y python3 python3-pip nmap tcpdump libpcap-dev

# Clone repository
git clone https://github.com/cybersecurity-student/cybernet-sentinel.git
cd cybernet-sentinel

# Install Python packages
pip3 install -r requirements.txt

# Jalankan dengan sudo
sudo python3 network_analyzer.py
```

#### macOS

```bash
# Install Homebrew jika belum ada
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install python3 nmap libpcap

# Clone repository
git clone https://github.com/cybersecurity-student/cybernet-sentinel.git
cd cybernet-sentinel

# Install Python packages
pip3 install -r requirements.txt

# Jalankan dengan sudo
sudo python3 network_analyzer.py
```

### 📦 Metode 2: Instalasi via Script

#### Windows
```powershell
# Download dan jalankan installer
.\install_windows.ps1
```

#### Linux
```bash
# Download dan jalankan installer
chmod +x install_linux.sh
sudo ./install_linux.sh
```

### 📦 Metode 3: Docker (Recommended)

```bash
# Build Docker image
docker build -t cybernet-sentinel .

# Jalankan container
docker run -it --network host --privileged cybernet-sentinel

# Atau dengan docker-compose
docker-compose up
```

---

## 🎯 Penggunaan

### Quick Start

```bash
# Jalankan program
python network_analyzer.py

# Menu utama akan muncul
# Pilih opsi sesuai kebutuhan (1-9)
```

### 📚 Panduan Lengkap

#### 1️⃣ Select Network Interface
```
Pilih interface jaringan yang akan digunakan untuk scanning

Langkah:
1. Pilih option 1 dari main menu
2. Pilih interface dari daftar yang tersedia
3. Interface akan diset untuk operasi selanjutnya
```

#### 2️⃣ Network Discovery
```
Scan jaringan untuk menemukan host aktif

Langkah:
1. Pastikan interface sudah dipilih
2. Pilih option 2
3. Tunggu proses scanning selesai
4. Lihat daftar host yang ditemukan

Metode yang digunakan:
- ARP Scan (lebih cepat untuk local network)
- Ping Sweep (fallback method)
```

#### 3️⃣ Port Scanner
```
Scan port pada target host

Langkah:
1. Pilih option 3
2. Pilih target dari daftar atau input IP manual
3. Tentukan port range (default: 1-1024)
4. Atur jumlah threads (default: 100)
5. Tunggu hasil scanning

Tips:
- Port 1-1024: Common ports (cepat)
- Port 1-10000: Extended scan (medium)
- Port 1-65535: Full port scan (lambat)
```

#### 4️⃣ Network Sniffer
```
Capture dan analisis traffic jaringan

Langkah:
1. Pilih option 4
2. Tentukan jumlah packet yang akan di-capture
3. Atur BPF filter (optional)
4. Tekan Ctrl+C untuk stop

BPF Filter Examples:
- "tcp port 80"     -> HTTP traffic only
- "udp"             -> UDP packets only
- "host 192.168.1.1" -> Specific host
- "tcp and port 443" -> HTTPS traffic
```

#### 5️⃣ Attack Detection
```
Analisis traffic untuk deteksi serangan

Langkah:
1. Pastikan sudah capture traffic (option 4)
2. Pilih option 5
3. Lihat hasil analisis ancaman

Deteksi yang tersedia:
- SYN Flood
- Port Scanning
- DDoS Attack
- ARP Spoofing
```

#### 6️⃣ Comprehensive Security Audit
```
Audit keamanan lengkap secara otomatis

Langkah:
1. Pilih option 6
2. Program akan otomatis:
   - Select interface
   - Network discovery
   - Port scanning (5 host pertama)
   - Traffic capture (200 packets)
   - Attack detection
   - Generate report
```

#### 7️⃣ Export Results
```
Ekspor hasil ke file

Format yang didukung:
- JSON (default)
- HTML
- CSV
- TXT
```

#### 8️⃣ Display Summary
```
Tampilkan ringkasan hasil analisis di terminal
```

---

## 🐳 Docker Deployment

### Dockerfile
File Dockerfile sudah disediakan untuk kemudahan deployment.

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
# Jalankan dengan compose
docker-compose up -d

# Akses container
docker-compose exec sentinel bash

# Stop container
docker-compose down
```

### Docker Command Examples

```bash
# Run dengan volume mount
docker run -it --rm \
  --network host \
  --privileged \
  -v $(pwd)/reports:/app/reports \
  cybernet-sentinel:latest

# Run dengan environment variables
docker run -it --rm \
  --network host \
  --privileged \
  -e TARGET_NETWORK="192.168.1.0/24" \
  -e SCAN_PORTS="1-10000" \
  cybernet-sentinel:latest

# Run dengan custom command
docker run -it --rm \
  --network host \
  --privileged \
  cybernet-sentinel:latest \
  python network_analyzer.py --help
```

---

## 📚 Dokumentasi

### API Documentation
Dokumentasi lengkap tersedia di folder `docs/`:
- [User Guide](docs/user_guide.md) - Panduan pengguna lengkap
- [Developer Guide](docs/developer_guide.md) - Panduan developer
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

Edit `config.yaml` untuk custom configuration:

```yaml
# config.yaml
network:
  interface: "auto"          # Interface name atau "auto"
  timeout: 5                 # Timeout dalam detik
  threads: 100              # Jumlah threads untuk scanning

scanning:
  default_port_range: "1-1024"
  scan_timeout: 1
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

# Untuk netifaces issue di Windows
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

# Pilih interface yang aktif dan terhubung
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

Kontribusi sangat diterima! Berikut cara berkontribusi:

1. Fork repository ini
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request

### Development Setup

```bash
# Clone repository
git clone https://github.com/cybersecurity-student/cybernet-sentinel.git
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

**PENTING: Gunakan tool ini hanya untuk tujuan legal dan etis!**

- ✅ **Legal Use**: Pengujian keamanan pada sistem sendiri atau dengan izin tertulis
- ✅ **Educational**: Pembelajaran dan penelitian cybersecurity
- ✅ **Authorized Testing**: Penetration testing dengan proper authorization

- ❌ **Illegal Use**: Unauthorized access atau scanning tanpa izin
- ❌ **Malicious Intent**: Menggunakan untuk tujuan jahat atau kriminal
- ❌ **Privacy Violation**: Melanggar privasi orang lain

**Tanggung Jawab Pengguna:**
Pengguna bertanggung jawab penuh atas penggunaan tool ini. Developer tidak bertanggung jawab atas penyalahgunaan atau kerusakan yang ditimbulkan.

---

## 📜 Lisensi

Proyek ini dilisensikan di bawah MIT License - lihat file [LICENSE](LICENSE) untuk detail lengkap.

```
MIT License

Copyright (c) 2024-2026 Cybersecurity Student

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

**Cybersecurity Student**
- 🎓 Semester 3 - Web Security Course
- 🏫 Final Project - Network Security Analysis Tool
- 📧 Email: [your-email@example.com](mailto:your-email@example.com)
- 🔗 GitHub: [@cybersecurity-student](https://github.com/cybersecurity-student)

---

## 🙏 Acknowledgments

Terima kasih kepada:
- Scapy Project untuk packet manipulation library
- Python Community untuk ecosystem yang luar biasa
- Dosen pembimbing untuk guidance dan support
- Open source contributors yang menginspirasi project ini

---

## 📞 Support

Butuh bantuan? Silakan:
- 📖 Baca [Documentation](docs/)
- 🐛 Report bugs via [Issues](https://github.com/cybersecurity-student/cybernet-sentinel/issues)
- 💬 Diskusi di [Discussions](https://github.com/cybersecurity-student/cybernet-sentinel/discussions)
- 📧 Email ke [support@example.com](mailto:support@example.com)

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
- [ ] Integration dengan SIEM tools
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

**Made with ❤️ for the Cybersecurity Community**

[Report Bug](https://github.com/cybersecurity-student/cybernet-sentinel/issues) • [Request Feature](https://github.com/cybersecurity-student/cybernet-sentinel/issues) • [Documentation](docs/)

---

**© 2024-2026 CyberNet Sentinel | MIT License**

</div>
