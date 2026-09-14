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
