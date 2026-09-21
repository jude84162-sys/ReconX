# modules/web/subfinder_clone.py
"""ReconX - Subfinder Clone v2 (no external tools).
Uses multiple free passive sources + optional brute force.
Adds cross-validation confidence scores.
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
# Wordlist
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
# HTTP Helper (with UA rotation)
# ============================================================

USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
]


def _make_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _fetch(url, timeout=20, retries=2):
    """Fetch URL text with retries + UA rotation."""
    import random
    import time as _time

    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": random.choice(USER_AGENTS),
                    "Accept": "*/*",
                    "Accept-Language": "en-US,en;q=0.9",
                },
            )
            with urllib.request.urlopen(req, timeout=timeout, context=_make_ctx()) as r:
                return r.read(500000).decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as e:
            try:
                return e.read(100000).decode("utf-8", errors="ignore")
            except Exception:
                if attempt < retries:
                    _time.sleep(2)
                    continue
                return None
        except Exception:
            if attempt < retries:
                _time.sleep(2)
                continue
            return None

    return None


# ============================================================
# Passive Sources (each returns set of subdomains)
# ============================================================

def _src_crtsh(domain):
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
                if n.endswith(f".{domain}") and "*" not in n and n != domain:
                    subs.add(n)
    except Exception as e:
        logger.debug(f"crt.sh failed: {e}")
    return subs


def _src_hackertarget(domain):
    subs = set()
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        body = _fetch(url, timeout=20)
        if not body or "error" in body.lower():
            return subs
        for line in body.splitlines():
            if "," in line:
                sub = line.split(",")[0].strip().lower()
                if sub.endswith(f".{domain}") and sub != domain:
                    subs.add(sub)
    except Exception:
        pass
    return subs


def _src_rapiddns(domain):
    subs = set()
    try:
        import re
        url = f"https://rapiddns.io/subdomain/{domain}?full=1"
        body = _fetch(url, timeout=20)
        if not body:
            return subs
        pattern = rf"([a-zA-Z0-9_\-\.]+\.{re.escape(domain)})"
        for match in re.finditer(pattern, body):
            sub = match.group(1).lower().strip(".")
            if sub != domain and "*" not in sub:
                subs.add(sub)
    except Exception:
        pass
    return subs


def _src_alienvault(domain):
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
    except Exception:
        pass
    return subs


def _src_urlscan(domain):
    subs = set()
    try:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000"
        body = _fetch(url, timeout=20)
        if not body:
            return subs
        data = json.loads(body)
        for result in data.get("results", []):
            page = result.get("page", {}).get("domain", "").lower()
            if page.endswith(f".{domain}") and page != domain:
                subs.add(page)
            task = result.get("task", {}).get("domain", "").lower()
            if task.endswith(f".{domain}") and task != domain:
                subs.add(task)
    except Exception:
        pass
    return subs


def _src_webarchive(domain):
    subs = set()
    try:
        import re
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey&limit=1000"
        body = _fetch(url, timeout=25)
        if not body:
            return subs
        data = json.loads(body)
        pattern = rf"https?://([a-zA-Z0-9_\-\.]+\.{re.escape(domain)})"
        for row in data[1:]:
            if row and len(row) > 0:
                for m in re.finditer(pattern, str(row[0])):
                    sub = m.group(1).lower()
                    if sub != domain:
                        subs.add(sub)
    except Exception:
        pass
    return subs


def _src_threatcrowd(domain):
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
    except Exception:
        pass
    return subs


# ============================================================
# DNS Resolution (thread-safe)
# ============================================================

def _resolve(hostname, timeout=4):
    """Resolve A record (thread-safe)."""
    try:
        infos = socket.getaddrinfo(
            hostname, None,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
        )
        if infos:
            return infos[0][4][0]
    except (socket.gaierror, socket.timeout, OSError):
        pass
    return None


def _resolve_all(hostname, timeout=4):
    """Resolve A + AAAA."""
    result = {"A": [], "AAAA": []}
    try:
        infos = socket.getaddrinfo(hostname, None)
        for info in infos:
            family, _, _, _, sockaddr = info
            addr = sockaddr[0]
            if family == socket.AF_INET and addr not in result["A"]:
                result["A"].append(addr)
            elif family == socket.AF_INET6 and addr not in result["AAAA"]:
                result["AAAA"].append(addr)
    except Exception:
        pass
    return result


# ============================================================
# Brute Force
# ============================================================

def _bruteforce(domain, wordlist, workers=50):
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
                r = future.result(timeout=10)
                if r:
                    found[r[0]] = r[1]
            except Exception:
                pass
    return found


# ============================================================
# Confidence Scoring
# ============================================================

def _compute_confidence(sources_list, resolved_ips):
    """
    Compute confidence for a subdomain.

    sources_list: list of source names that found it
    resolved_ips: dict with A + AAAA arrays
    """
    n_sources = len(sources_list)
    has_ip = bool(resolved_ips.get("A") or resolved_ips.get("AAAA"))

    # Base score from sources count
    if n_sources >= 3:
        score = 0.95
    elif n_sources == 2:
        score = 0.85
    elif n_sources == 1:
        score = 0.70
    else:
        score = 0.50

    # Bonus for successful resolution
    if has_ip:
        score = min(score + 0.05, 0.99)
    else:
        score = max(score - 0.20, 0.10)

    # Brute force only
    if sources_list == ["bruteforce"] and has_ip:
        score = 0.90

    # Classify
    if score >= 0.90:
        level = "HIGH"
    elif score >= 0.75:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "score": round(score, 2),
        "level": level,
        "sources_count": n_sources,
        "sources": sources_list,
        "resolved": has_ip,
    }


# ============================================================
# Main
# ============================================================

def run_subfinder_clone(domain, passive=True, bruteforce=True,
                        workers=30, verbose=True):
    """Full subdomain enumeration with confidence scoring."""
    result = {
        "timestamp": datetime.now().isoformat(),
        "domain": domain,
        "subdomains": [],
        "by_source": {},
        "total": 0,
        "errors": [],
        "confidence_summary": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
    }

    # Map subdomain -> list of sources
    sub_sources = {}

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
                    subs = future.result(timeout=40)
                    if subs:
                        result["by_source"][name] = len(subs)
                        for sub in subs:
                            sub_sources.setdefault(sub, []).append(name)
                        if verbose:
                            print(f"      {C_GREEN}✓{C_RST} {name}: {len(subs)}")
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
        for sub in bf_found.keys():
            sub_sources.setdefault(sub, []).append("bruteforce")

        if verbose:
            print(f"      {C_GREEN}✓{C_RST} bruteforce: {len(bf_found)}")

    # === Resolve IPs (parallel) ===
    if verbose:
        print(f"  {C_CYAN}[*]{C_RST} Resolving {len(sub_sources)} candidates...")

    resolved_data = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(_resolve_all, host): host for host in sub_sources}
        for future in concurrent.futures.as_completed(futures):
            try:
                ips = future.result(timeout=8)
                host = futures[future]
                if ips["A"] or ips["AAAA"]:
                    resolved_data[host] = ips
            except Exception:
                pass

    # === Build results with confidence ===
    for hostname in sorted(sub_sources.keys()):
        sources_list = sub_sources[hostname]
        ips = resolved_data.get(hostname, {"A": [], "AAAA": []})

        # Skip if not resolved AND only from bruteforce (probably wildcard)
        if not ips["A"] and not ips["AAAA"] and sources_list == ["bruteforce"]:
            continue

        confidence = _compute_confidence(sources_list, ips)

        entry = {
            "hostname": hostname,
            "ip": ips["A"][0] if ips["A"] else None,
            "ipv4": ips["A"],
            "ipv6": ips["AAAA"],
            "sources": sources_list,
            "confidence": confidence,
        }
        result["subdomains"].append(entry)
        result["confidence_summary"][confidence["level"]] += 1

    result["total"] = len(result["subdomains"])

    return result


# ============================================================
# Colors
# ============================================================

C_CYAN = "\033[96m"
C_GREEN = "\033[92m"
C_GRAY = "\033[90m"
C_RED = "\033[91m"
C_RST = "\033[0m"


# ============================================================
# Report
# ============================================================

def print_subfinder_clone_report(result):
    print("\n" + "=" * 70)
    print("  Subfinder Clone v2 (with confidence) — ReconX")
    print("=" * 70)

    print(f"\n[*] Domain: {result.get('domain')}")
    print(f"[*] Found:  {result.get('total', 0)} subdomains")

    if result.get("by_source"):
        print(f"\n[*] By Source:")
        for src, count in sorted(result["by_source"].items()):
            marker = "✓" if count > 0 else "·"
            print(f"    {marker} {src:<20} {count}")

    if result.get("confidence_summary"):
        c = result["confidence_summary"]
        print(f"\n[*] Confidence breakdown:")
        print(f"    🟢 HIGH    {c.get('HIGH', 0)}")
        print(f"    🟡 MEDIUM  {c.get('MEDIUM', 0)}")
        print(f"    🔴 LOW     {c.get('LOW', 0)}")

    if result.get("subdomains"):
        print(f"\n[+] Subdomains (sorted by confidence):")

        sorted_subs = sorted(
            result["subdomains"],
            key=lambda x: (-x["confidence"]["score"], x["hostname"])
        )

        for s in sorted_subs[:50]:
            conf = s["confidence"]
            level = conf["level"]
            score = conf["score"]
            marker = {"HIGH": "🟢", "MEDIUM": "🟡", "LOW": "🔴"}.get(level, "⚪")
            ip = s["ip"] or "unresolved"
            src_count = len(s["sources"])
            print(f"    {marker} {s['hostname']:<45} {ip:<15} [{score:.2f} / {src_count} src]")

        if len(result["subdomains"]) > 50:
            print(f"    ... and {len(result['subdomains']) - 50} more")

    if result.get("errors"):
        print(f"\n[!] Errors:")
        for e in result["errors"][:3]:
            print(f"    - {e}")

    print("\n" + "=" * 70 + "\n")


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) < 2:
        print("Usage: python -m modules.web.subfinder_clone <domain> [--no-passive] [--no-bruteforce]")
        sys.exit(1)

    domain = sys.argv[1]
    passive = "--no-passive" not in sys.argv
    bruteforce = "--no-bruteforce" not in sys.argv

    print(f"\n[*] Enumerating subdomains for {domain}...")
    print(f"[*] Passive: {passive} | Brute force: {bruteforce}\n")

    result = run_subfinder_clone(domain, passive=passive, bruteforce=bruteforce)
    print_subfinder_clone_report(result)
