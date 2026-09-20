# modules/subfinder_clone.py
"""ReconX - Subfinder Clone (no external tools needed).
Uses multiple free passive sources + optional brute force.
"""

import socket
import ssl
import json
import logging
import urllib.request
import urllib.error
import urllib.parse
import concurrent.futures
from datetime import datetime

logger = logging.getLogger("ReconX.subfinder")


# ============================================================
# Wordlist for brute force
# ============================================================

WORDLIST = [
    "www", "www1", "www2", "www3", "web", "website", "webmail",
    "mail", "mail1", "mail2", "smtp", "smtp1", "smtp2", "pop", "pop3", "imap", "mx", "mx1", "mx2",
    "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
    "dev", "development", "staging", "stage", "test", "testing", "test1", "test2",
    "demo", "sandbox", "beta", "alpha", "preview", "preprod", "uat", "qa", "prod", "production", "live",
    "api", "api1", "api2", "api-v1", "api-v2", "api-v3", "rest", "graphql", "grpc",
    "app", "apps", "mobile", "m", "v1", "v2", "v3",
    "admin", "administrator", "panel", "cpanel", "whm", "dashboard", "manage", "management", "console", "portal",
    "auth", "login", "signin", "signup", "register", "sso", "accounts", "account", "id", "identity", "oauth",
    "static", "cdn", "cdn1", "cdn2", "assets", "img", "images", "media", "files", "js", "css",
    "shop", "store", "cart", "checkout", "payment", "pay", "billing", "invoice",
    "blog", "news", "forum", "community", "support", "help", "faq", "kb",
    "docs", "doc", "documentation", "wiki", "kb",
    "git", "gitlab", "github", "bitbucket", "jenkins", "ci", "cd", "build", "deploy",
    "monitor", "monitoring", "grafana", "kibana", "prometheus", "nagios", "status", "health",
    "db", "database", "mysql", "postgres", "mongo", "redis", "elastic", "elasticsearch",
    "old", "legacy", "backup", "backups", "archive", "temp", "tmp",
    "secure", "vpn", "remote", "gateway", "proxy", "edge",
    "autodiscover", "autoconfig", "exchange", "owa", "rpc",
    "s3", "aws", "azure", "gcp", "cloud", "storage", "bucket",
    "internal", "private", "intranet", "extranet",
    "partners", "clients", "customer", "customers",
    "integration", "dev-api", "test-api", "staging-api", "uat-api", "prod-api",
    "dev-app", "test-app", "staging-app",
    "mail-server", "mailserver", "relay", "smtp-out", "smtp-in",
]


# ============================================================
# HTTP Helper
# ============================================================

def _make_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _fetch(url, timeout=15, headers=None):
    """Fetch URL text."""
    default_headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) "
                      "AppleWebKit/537.36 Chrome/120.0.0.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if headers:
        default_headers.update(headers)

    try:
        req = urllib.request.Request(url, headers=default_headers)
        with urllib.request.urlopen(req, timeout=timeout, context=_make_ctx()) as r:
            return r.read(500000).decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        try:
            return e.read(100000).decode("utf-8", errors="ignore")
        except Exception:
            return None
    except Exception:
        return None


# ============================================================
# Passive Sources
# ============================================================

def _src_crtsh(domain):
    """Certificate Transparency via crt.sh."""
    subs = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        body = _fetch(url, timeout=30)
        if not body:
            return subs

        data = json.loads(body)
        for entry in data:
            name = entry.get("name_value", "")
            for n in name.split("\n"):
                n = n.strip().lower()
                if n.endswith(f".{domain}") or n == domain:
                    if "*" not in n and n != domain:
                        subs.add(n)
    except Exception as e:
        logger.debug(f"crt.sh failed: {e}")
    return subs


def _src_hackertarget(domain):
    """hackertarget.com free API."""
    subs = set()
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        body = _fetch(url, timeout=20)
        if not body:
            return subs
        if "error" in body.lower() or "api count exceeded" in body.lower():
            return subs
        for line in body.splitlines():
            if "," in line:
                sub = line.split(",")[0].strip().lower()
                if sub.endswith(f".{domain}") and sub != domain:
                    subs.add(sub)
    except Exception as e:
        logger.debug(f"hackertarget failed: {e}")
    return subs


def _src_rapiddns(domain):
    """rapiddns.io subdomain finder."""
    subs = set()
    try:
        url = f"https://rapiddns.io/subdomain/{domain}?full=1"
        body = _fetch(url, timeout=20)
        if not body:
            return subs

        import re
        pattern = rf"([a-zA-Z0-9_\-\.]+\.{re.escape(domain)})"
        for match in re.finditer(pattern, body):
            sub = match.group(1).lower().strip(".")
            if sub != domain and "*" not in sub:
                subs.add(sub)
    except Exception as e:
        logger.debug(f"rapiddns failed: {e}")
    return subs


def _src_alienvault(domain):
    """AlienVault OTX passive DNS."""
    subs = set()
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        body = _fetch(url, timeout=20)
        if not body:
            return subs

        data = json.loads(body)
        for record in data.get("passive_dns", []):
            hostname = record.get("hostname", "").lower()
            if hostname.endswith(f".{domain}") and hostname != domain:
                subs.add(hostname)
    except Exception as e:
        logger.debug(f"alienvault failed: {e}")
    return subs


def _src_urlscan(domain):
    """urlscan.io search."""
    subs = set()
    try:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000"
        body = _fetch(url, timeout=20)
        if not body:
            return subs

        data = json.loads(body)
        for result in data.get("results", []):
            page_domain = result.get("page", {}).get("domain", "").lower()
            if page_domain.endswith(f".{domain}") and page_domain != domain:
                subs.add(page_domain)
            # Also check task domain
            task_domain = result.get("task", {}).get("domain", "").lower()
            if task_domain.endswith(f".{domain}") and task_domain != domain:
                subs.add(task_domain)
    except Exception as e:
        logger.debug(f"urlscan failed: {e}")
    return subs


def _src_webarchive(domain):
    """Web Archive CDX API."""
    subs = set()
    try:
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey&limit=1000"
        body = _fetch(url, timeout=25)
        if not body:
            return subs

        data = json.loads(body)
        import re
        pattern = rf"https?://([a-zA-Z0-9_\-\.]+\.{re.escape(domain)})"
        for row in data[1:]:  # Skip header
            if row and len(row) > 0:
                for m in re.finditer(pattern, str(row[0])):
                    sub = m.group(1).lower()
                    if sub != domain:
                        subs.add(sub)
    except Exception as e:
        logger.debug(f"webarchive failed: {e}")
    return subs


def _src_threatcrowd(domain):
    """ThreatCrowd historical subdomains."""
    subs = set()
    try:
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        body = _fetch(url, timeout=20)
        if not body:
            return subs

        data = json.loads(body)
        for sub in data.get("subdomains", []):
            sub = sub.lower().strip()
            if sub.endswith(f".{domain}") and sub != domain:
                subs.add(sub)
    except Exception as e:
        logger.debug(f"threatcrowd failed: {e}")
    return subs


# ============================================================
# Brute Force
# ============================================================

def _resolve(hostname, timeout=3):
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname(hostname)
    except Exception:
        return None


def _bruteforce(domain, wordlist, workers=50):
    """Brute-force subdomains from wordlist."""
    found = {}

    def check(word):
        hostname = f"{word}.{domain}"
        ip = _resolve(hostname)
        if ip:
            return hostname, ip
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(check, w): w for w in wordlist}
        for future in concurrent.futures.as_completed(futures):
            try:
                r = future.result(timeout=8)
                if r:
                    found[r[0]] = r[1]
            except Exception:
                pass

    return found


# ============================================================
# Main
# ============================================================

def run_subfinder_clone(domain, passive=True, bruteforce=True,
                        workers=30, verbose=True):
    """
    Full subdomain enumeration without external tools.
    """
    result = {
        "timestamp": datetime.now().isoformat(),
        "domain": domain,
        "subdomains": [],
        "by_source": {},
        "total": 0,
        "errors": [],
    }

    all_subs = set()

    # === Passive sources ===
    if passive:
        sources = [
            ("crt.sh", _src_crtsh),
            ("hackertarget", _src_hackertarget),
            ("rapiddns", _src_rapiddns),
            ("alienvault", _src_alienvault),
            ("urlscan", _src_urlscan),
            ("webarchive", _src_webarchive),
            ("threatcrowd", _src_threatcrowd),
        ]

        if verbose:
            print(f"  {C_CYAN}[*]{C_RST} Querying {len(sources)} passive sources...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(sources)) as ex:
            futures = {ex.submit(fn, domain): name for name, fn in sources}

            for future in concurrent.futures.as_completed(futures):
                name = futures[future]
                try:
                    subs = future.result(timeout=35)
                    if subs:
                        count = len(subs)
                        result["by_source"][name] = count
                        all_subs.update(subs)
                        if verbose:
                            print(f"      {C_GREEN}✓{C_RST} {name}: {count}")
                    else:
                        if verbose:
                            print(f"      {C_GRAY}·{C_RST} {name}: 0")
                except Exception as e:
                    result["errors"].append(f"{name}: {e}")
                    if verbose:
                        print(f"      {C_RED}✗{C_RST} {name}: error")

    # === Brute force ===
    if bruteforce:
        if verbose:
            print(f"  {C_CYAN}[*]{C_RST} Brute-forcing {len(WORDLIST)} words...")

        bf_found = _bruteforce(domain, WORDLIST, workers=50)
        result["by_source"]["bruteforce"] = len(bf_found)
        all_subs.update(bf_found.keys())

        if verbose:
            print(f"      {C_GREEN}✓{C_RST} bruteforce: {len(bf_found)}")

    # === Resolve IPs ===
    if verbose:
        print(f"  {C_CYAN}[*]{C_RST} Resolving {len(all_subs)} candidates...")

    for hostname in sorted(all_subs):
        ip = _resolve(hostname, timeout=2)
        if ip:
            result["subdomains"].append({
                "hostname": hostname,
                "ip": ip,
            })

    result["total"] = len(result["subdomains"])

    return result


# ============================================================
# Colors for standalone use
# ============================================================

C_CYAN = "\033[96m"
C_GREEN = "\033[92m"
C_GRAY = "\033[90m"
C_RED = "\033[91m"
C_RST = "\033[0m"


# ============================================================
# Report Printer
# ============================================================

def print_subfinder_clone_report(result):
    print("\n" + "=" * 70)
    print("  Subfinder Clone Report - ReconX")
    print("=" * 70)

    print(f"\n[*] Domain: {result.get('domain')}")
    print(f"[*] Found:  {result.get('total', 0)} subdomains")

    if result.get("by_source"):
        print(f"\n[*] By Source:")
        for src, count in sorted(result["by_source"].items()):
            marker = "✓" if count > 0 else "·"
            print(f"    {marker} {src:<20} {count}")

    if result.get("subdomains"):
        print(f"\n[+] Subdomains:")
        for s in result["subdomains"][:50]:
            print(f"    ✓ {s['hostname']:<50} {s['ip']}")
        if len(result["subdomains"]) > 50:
            print(f"    ... and {len(result['subdomains']) - 50} more")

    if result.get("errors"):
        print(f"\n[!] Errors:")
        for e in result["errors"][:3]:
            print(f"    - {e}")

    print("\n" + "=" * 70 + "\n")


# ============================================================
# CLI Test
# ============================================================

if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) < 2:
        print("Usage: python -m modules.subfinder_clone <domain> [--no-passive] [--no-bruteforce]")
        sys.exit(1)

    domain = sys.argv[1]
    passive = "--no-passive" not in sys.argv
    bruteforce = "--no-bruteforce" not in sys.argv

    print(f"\n[*] Enumerating subdomains for {domain}...")
    print(f"[*] Passive: {passive} | Brute force: {bruteforce}\n")

    result = run_subfinder_clone(domain, passive=passive, bruteforce=bruteforce)
    print_subfinder_clone_report(result)
