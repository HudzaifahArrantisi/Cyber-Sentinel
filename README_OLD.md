# 🛡️ CyberNet Sentinel - Advanced Network Security Analyzer

<div align="center">

![CyberNet Sentinel Banner](https://img.shields.io/badge/CyberNet-Sentinel-00ff00?style=for-the-badge&logo=security&logoColor=white)

**Professional Network Security Analysis & Monitoring Tool**

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