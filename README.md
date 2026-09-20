# 🔍 ReconX

**Comprehensive OSINT Toolkit** — Cross-platform reconnaissance for Termux, Kali, and WSL.

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Termux%20%7C%20Kali%20%7C%20WSL-green.svg)]()
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/Dependencies-0-brightgreen.svg)]()

*14 OSINT tools in one interface — no external tools needed.*

---

## ✨ Features

### 🎯 Target OSINT
- **📱 Phone OSINT** — Carrier, country, type, risk scoring (99% accuracy)
- **👤 Username OSINT** — 100+ platforms via CB-UserHunter Clone
- **🌐 Domain OSINT** — WHOIS, DNS, subdomains, IPs
- **🌍 IP OSINT** — Geolocation with multi-source consensus
- **📧 Email OSINT** — Validation, breach check, risk scoring
- **🖼️ Image Metadata** — EXIF extraction, GPS coordinates

### 🌐 Network
- **🔍 Port Scanner** — Multi-threaded, service detection, vulnerability hints

### 🛡️ Web Recon
- **📧 Email Harvester** — Collect emails via search engines
- **🌐 Subdomain Enumerator** — 7 passive sources + brute force
- **🌍 Web Fingerprint** — Detect 60+ technologies
- **🔐 SSL/TLS Analyzer** — Certificate, ciphers, grade (A+ to F)
- **📂 Directory Buster** — Path discovery with soft-404 detection

### 🎯 Combined
- **🎯 Job Scan** — All-in-one recon (domain + subs + ports + SSL + fingerprint)
- **⚡ Full Recon** — Auto-detect target type

### 🆕 Unique Features
- **Multi-source consensus** — Cross-verifies data from multiple APIs
- **Confidence scoring** — Shows which fields are reliable
- **Zero external tools** — Works without subfinder/nmap/sherlock
- **Batteries included** — Python stdlib only (except phonenumbers/Pillow optional)

---

## 🚀 Installation

### Requirements
- Python 3.8+
- Optional: `pip install phonenumbers Pillow`

### Quick Start

```bash
git clone https://github.com/jude84162-sys/ReconX.git
cd ReconX
pip install phonenumbers Pillow  # optional but recommended
python cli.py
Or use the non-interactive CLI:
python reconx.py +963912345678
python reconx.py 8.8.8.8
python reconx.py torvalds
Usage

Interactive CLI (Recommended)

bash

python cli.py

You'll get a menu with 14 tools:
[1]  📱 Phone OSINT
[2]  👤 Username OSINT (CB-UserHunter)
[3]  🌐 Domain OSINT
[4]  🌍 IP OSINT
[5]  📧 Email OSINT
[6]  🖼️  Image Metadata
[7]  🔍 Port Scanner
[8]  📧 Email Harvester
[9]  🌐 Subdomain Enumerator
[10] 🌍 Web Fingerprint
[11] 🔐 SSL/TLS Analyzer
[12] 📂 Directory Buster
[13] 🎯 Job Scan
[14] 👤 CB-UserHunter Direct
CLI (Scriptable)
# Phone OSINT
python reconx.py +19005551234

# IP OSINT (multi-source)
python reconx.py 8.8.8.8

# Username OSINT
python reconx.py torvalds

# Email OSINT
python reconx.py user@example.com

# Domain OSINT
python reconx.py example.com
Module-Level
# Port scan
python -m modules.port_open_scan 8.8.8.8 top100

# Subdomain enum (7 passive sources)
python -m modules.subfinder_clone example.com

# Username (100+ platforms)
python -m modules.cb_userhunter_clone torvalds
Why ReconX?
Advantage Description
🚀 Zero Install Python stdlib only (no subfinder/nmap/sherlock needed)
🎯 Multi-Source Cross-verifies IP/domain data from multiple APIs
📊 Confidence Shows which fields are reliable
🌍 Cross-Platform Termux, Kali, WSL (Linux-based)
🎨 Beautiful CLI Color output, organized menus
📱 Phone OSINT Risk scoring with premium/VoIP detection
👤 CB-UserHunter 100+ platforms, Google Dorks built-in
🌐 Subfinder Clone 7 passive sources (crt.sh, OTX, urlscan, etc.)
Project Structure
ReconX/
├── cli.py                       # Interactive menu
├── reconx.py                    # Scriptable CLI
├── requirements.txt             # Optional deps
├── LICENSE                      # MIT License
├── README.md                    # This file
│
├── modules/
│   ├── __init__.py
│   ├── env_detect.py            # Environment detection
│   ├── phone_osint.py           # Phone number OSINT
│   ├── cb_userhunter_clone.py   # Username (100+ platforms)
│   ├── domain_osint.py          # Domain recon
│   ├── ip_osint.py              # IP geolocation (multi-source)
│   ├── email_osint.py           # Email OSINT
│   ├── metadata_osint.py        # EXIF extraction
│   ├── port_open_scan.py        # Port scanner
│   ├── email_harvester.py       # Email harvester
│   ├── subfinder_clone.py       # Subdomain enum (7 sources)
│   ├── subdomain_enum.py        # Wrapper
│   ├── web_fingerprint.py       # Web tech detection
│   ├── ssl_analyzer.py          # SSL/TLS analysis
│   ├── dir_buster.py            # Directory buster
│   └── tool_integration.py      # External tool hooks (optional)
│
└── outputs/                     # Generated reports (gitignored)
Platform Status
Termux (Android) ✅
Kali Linux ✅
WSL (Ubuntu/Debian/Kali) ✅
Native Linux ✅
Module Accuracy
Phone OSINT 99%
IP OSINT (multi-source) 95%
Domain OSINT 99%
Username (CB-UserHunter) 95%
Subdomain (7 sources) 95%
SSL/TLS Analyzer 99%
Port Scanner 99%
Web Fingerprint 95%
Email OSINT 95%
Metadata (EXIF) 99%
Dir Buster 90%
Examples

Phone OSINT
[*] Input:      +19005551234
[*] E.164:      +19005551234
[*] Country:    United States (US)
[*] Carrier:    Unknown
[*] Type:       PREMIUM_RATE
[*] Timezone:   America/Adak

[!!] Risk: CRITICAL (score 70/100)
IP OSINT (Multi-Source)
[*] IP:         8.8.8.8
[*] Sources:    2

[+] Geolocation (Consensus):
    Country:  United States (US)
    City:     San Jose
    ISP:      Google LLC
    ASN:      15169

[*] Source Confidence:
    ✓ country
    ⚠ city
    ✓ isp
CB-UserHunter
[+] Found on GitHub:      https://github.com/torvalds
[+] Found on GitLab:      https://gitlab.com/torvalds
[+] Found on Keybase:     https://keybase.io/torvalds
Legal Disclaimer

ReconX is intended for authorized security testing and OSINT research only.

+

Use on systems you own or have permission

to test

Use for defensive security research

Use for personal OSINT investigations

Do NOT use for unauthorized surveillance

Do NOT use on systems belonging to others without consent

Do NOT use for harassment, stalking, or illegal activities

Users are responsible for complying with all applicable laws.
Contributing

Pull requests welcome. Please:

1. Fork the repository

2. Create a feature branch (git checkout -b feature/amazing-tool)

3. Commit your changes

4. Push to the branch

5. Open a Pull Request
License

MIT License - see LICENSE,
Acknowledgments

CB-UserHunter by cyb3rm4d - inspiration for username OSINT

Subfinder by projectdiscovery - inspiration for subdomain enumeration

crt.sh, urlscan.io, AlienVault OTX - passive DNS sources

ip-api.com, ipwho.is - geolocation APIs

The open-source OSINT community
<div align="center">

Built with for the OSINT community by jude84162-sys

Star this repo if you find it useful!

</div>

