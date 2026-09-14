
# reconx 🔍
**reconx** is a modular Open Source Intelligence (OSINT) framework designed for fast domain reconnaissance and cross-platform username enumeration.

---

## 🚀 Features

### 🌐 Domain Intelligence (`domain.py`)
* **DNS Enumeration**: Queries `A` and `AAAA` records via standard socket resolution, with fallback to `dnspython` for retrieving `CNAME`, `NS`, `MX`, and `TXT` records.
* **WHOIS Inspection**: Fetches domain ownership details, registrar, creation/expiration dates, and authoritative name servers using `python-whois`.
* **Security Header Analysis**: Evaluates HTTP response security headers (e.g., `HSTS`, `CSP`, `X-Frame-Options`, `Referrer-Policy`) and extracts backend server banners (`Server`, `X-Powered-By`).
* **Technology Fingerprinting**: Detects up to 27 popular web frameworks, CMS platforms, and backend stacks (e.g., React, WordPress, Next.js, Django, Laravel, Nginx).
* **Multi-threaded Subdomain Brute-Forcing**: Utilizes a `ThreadPoolExecutor` with 30 concurrent workers for high-speed subdomain discovery.

### 👤 Username Enumeration (`username.py`)
* **Extensive Site Registry**: Queries a structured `SITES` catalog of target platforms using custom URL templates and HTTP status code checks.
* **Broad Category Coverage**: Searches across social networks, code repositories, gaming networks, link-in-bio platforms, academic databases, and regional sites.
* **Custom Verification Engines**: Supports dedicated checking logic for platforms requiring custom payload validation or API handling (e.g., Cloudflare-protected targets or Have I Been Pwned).

---

## 🛠️ Prerequisites & Installation

Ensure you have **Python 3.8+** installed.

1. **Clone the Repository**:
   ```bash
   git clone [https://github.com/your-username/reconx.git](https://github.com/your-username/reconx.git)
   cd reconx

 * Install Required Packages:
   pip install dnspython python-whois requests

📖 Usage
Domain Reconnaissance
Run domain enumeration and tech stack fingerprinting on a target domain:
python domain.py --target example.com

Username Search
Search for a specific handle across all configured platforms:
python username.py --username targetuser

📁 Module Structure
reconx/
├── domain.py          # Domain analysis, DNS, WHOIS, headers & subdomain brute-forcing
├── username.py        # Cross-platform username lookup registry & checker
└── README.md          # Project documentation

⚠️ Known Issues & Roadmap
 * [ ] Wildcard DNS Detection: Implement baseline checks in _subdomain_enum to prevent false positives when targets resolve arbitrary subdomains.
 * [ ] External Wordlists: Add command-line support for custom wordlist files (--wordlist path/to/list.txt).
 * [ ] Complete Site Registry: Finalize missing definitions in username.py site structures.
 * [ ] Export Options: Add JSON/CSV export formats for search results.
⚖️ Legal & Ethical Disclaimer
This tool is intended strictly for educational purposes and authorized security assessments. Do not run reconx against targets without explicit prior permission from the target system owner. The authors accept no liability for misuse or damage caused by this program.

