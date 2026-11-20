# modules/domain_osint.py
"""ReconX - Domain OSINT (v2 — Pure Python, no external tools).
Uses DoH for DNS + socket WHOIS + crt.sh with fallback.
"""

import json
import socket
import ssl
import logging
import urllib.request
import urllib.error
import concurrent.futures
from datetime import datetime

from modules.utils.crtsh import crtsh_lookup

logger = logging.getLogger("ReconX.domain")

VERIFY_WORKERS = 100
VERIFY_DEADLINE = 30


# ============================================================
# Constants
# ============================================================

COMMON_SUBDOMAINS = [
    "www", "www1", "www2", "web", "website", "webmail",
    "mail", "smtp", "pop", "pop3", "imap", "mx", "mx1", "mx2",
    "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
    "dev", "development", "staging", "stage", "test", "testing",
    "demo", "sandbox", "beta", "alpha", "preview", "preprod",
    "qa", "uat", "prod", "production", "live",
    "api", "api-v1", "api-v2", "rest", "graphql", "grpc",
    "app", "apps", "mobile", "m", "v1", "v2",
    "admin", "administrator", "panel", "cpanel", "whm",
    "dashboard", "manage", "management", "console", "portal",
    "auth", "login", "signin", "sso", "accounts", "account",
    "id", "identity", "oauth",
    "static", "cdn", "assets", "img", "images", "media", "files",
    "js", "css", "fonts", "downloads", "download",
    "shop", "store", "cart", "checkout", "payment", "pay", "billing",
    "blog", "news", "forum", "community", "support", "help",
    "docs", "doc", "documentation", "wiki", "kb", "faq",
    "git", "gitlab", "github", "bitbucket", "jenkins", "ci", "cd",
    "build", "deploy", "registry", "docker", "k8s", "kubernetes",
    "monitor", "monitoring", "grafana", "kibana", "prometheus",
    "nagios", "zabbix", "status", "health", "uptime", "alerts",
    "db", "database", "mysql", "postgres", "postgresql", "mongo",
    "mongodb", "redis", "elastic", "elasticsearch", "cassandra",
    "old", "legacy", "backup", "backups", "bak", "archive",
    "temp", "tmp", "private", "internal", "secure", "vpn",
    "remote", "gateway", "proxy", "firewall", "edge",
    "autodiscover", "autoconfig", "exchange", "owa", "rpc",
    "s3", "aws", "azure", "gcp", "cloud", "storage",
]


# ============================================================
# Thread-safe DNS resolution (no setdefaulttimeout)
# ============================================================

def _resolve_all_ips(hostname, timeout=3):
    """Resolve to all IPs (A + AAAA) — thread-safe."""
    ips = {"A": [], "AAAA": []}

    # IPv4
    try:
        infos = socket.getaddrinfo(
            hostname, None,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
        )
        for info in infos:
            addr = info[4][0]
            if addr not in ips["A"]:
                ips["A"].append(addr)
    except (socket.gaierror, socket.timeout, OSError):
        pass

    # IPv6 (optional, can be slow)
    try:
        infos = socket.getaddrinfo(
            hostname, None,
            family=socket.AF_INET6,
            type=socket.SOCK_STREAM,
        )
        for info in infos:
            addr = info[4][0]
            if addr not in ips["AAAA"]:
                ips["AAAA"].append(addr)
    except (socket.gaierror, socket.timeout, OSError):
        pass

    return ips


def _resolve_a_only(hostname, timeout=3):
    """Fast A-only resolution."""
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


# ============================================================
# DNS over HTTPS (no nslookup needed)
# ============================================================

DOH_ENDPOINTS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
]

DNS_TYPES = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15,
    "TXT": 16, "AAAA": 28, "CAA": 257, "PTR": 12,
}


def _doh_query(domain, rtype, timeout=10):
    """Query DNS via DoH."""
    type_num = DNS_TYPES.get(rtype, 1)

    for endpoint in DOH_ENDPOINTS:
        try:
            url = f"{endpoint}?name={domain}&type={rtype}"
            ctx = ssl.create_default_context()
            req = urllib.request.Request(
                url,
                headers={
                    "Accept": "application/dns-json",
                    "User-Agent": "ReconX/1.0",
                },
            )
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                data = json.loads(r.read())

            answers = data.get("Answer", [])
            results = []
            for ans in answers:
                if ans.get("type") != type_num:
                    continue
                results.append({
                    "name": ans.get("name", "").rstrip("."),
                    "ttl": ans.get("TTL", 0),
                    "data": ans.get("data", "").rstrip("."),
                })
            return results
        except Exception as e:
            logger.debug(f"DoH {endpoint} failed: {e}")
            continue

    return []


def _get_dns_records(domain):
    """Get DNS records via DoH (parallel)."""
    records = {}

    types_to_fetch = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(types_to_fetch)) as ex:
        futures = {
            ex.submit(_doh_query, domain, rtype): rtype
            for rtype in types_to_fetch
        }
        for future in concurrent.futures.as_completed(futures):
            rtype = futures[future]
            try:
                answers = future.result(timeout=15)
                if answers:
                    records[rtype] = answers
            except Exception:
                pass

    return records


# ============================================================
# Socket WHOIS (no whois command needed)
# ============================================================

WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "info": "whois.afilias.net",
    "dev": "whois.nic.google",
    "app": "whois.nic.google",
    "me": "whois.nic.me",
    "xyz": "whois.nic.xyz",
    "ai": "whois.nic.ai",
    "sh": "whois.nic.sh",
    "us": "whois.nic.us",
    "uk": "whois.nic.uk",
    "de": "whois.denic.de",
    "fr": "whois.nic.fr",
    "ru": "whois.tcinet.ru",
    "sy": "whois.tld.sy",
    "sa": "whois.nic.net.sa",
    "ae": "whois.aeda.net.ae",
    "eg": "whois.ripe.net",
}


def _whois_socket(domain, timeout=15):
    """
    Socket-based WHOIS (port 43).
    Fallback: try whois.iana.org to find the right server.
    """
    tld = domain.rsplit(".", 1)[-1].lower()
    server = WHOIS_SERVERS.get(tld)

    # Try IANA referral if no direct mapping
    if not server:
        try:
            server = _iana_referral(tld)
        except Exception:
            pass

    if not server:
        return None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((server, 43))

        query = f"{domain}\r\n".encode()
        sock.send(query)

        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 100000:
                    break
            except socket.timeout:
                break

        sock.close()
        return response.decode("utf-8", errors="ignore")

    except Exception as e:
        logger.debug(f"WHOIS socket failed for {domain}: {e}")
        return None


def _iana_referral(tld):
    """Get WHOIS server for TLD from IANA."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(("whois.iana.org", 43))
        sock.send(f"{tld}\r\n".encode())

        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        sock.close()

        text = response.decode("utf-8", errors="ignore")
        for line in text.splitlines():
            if line.lower().startswith("refer:"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return None


def _parse_whois(raw):
    """Parse WHOIS text into structured dict."""
    result = {
        "registrar": None,
        "creation_date": None,
        "expiry_date": None,
        "updated_date": None,
        "name_servers": [],
        "status": [],
        "registrant": None,
        "registrant_country": None,
        "dnssec": None,
        "raw_length": len(raw) if raw else 0,
    }

    if not raw:
        return result

    for line in raw.splitlines():
        lower = line.lower().strip()
        if not lower or lower.startswith("%") or lower.startswith("#"):
            continue

        if ":" not in line:
            continue

        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()

        if not value:
            continue

        # Registrar
        if key in ("registrar", "registrar name", "sponsoring registrar") and not result["registrar"]:
            result["registrar"] = value

        # Creation date
        elif key in ("creation date", "created", "created on", "registered on",
                     "domain registration date", "registration date") and not result["creation_date"]:
            result["creation_date"] = value

        # Expiry date
        elif key in ("registry expiry date", "expiry date", "expiration date",
                     "expires", "expires on", "paid-till", "registrar registration expiration date") and not result["expiry_date"]:
            result["expiry_date"] = value

        # Updated date
        elif key in ("updated date", "last updated", "last modified") and not result["updated_date"]:
            result["updated_date"] = value

        # Nameservers
        elif key in ("name server", "nameserver", "nserver"):
            ns = value.lower().strip()
            if ns and ns not in result["name_servers"]:
                result["name_servers"].append(ns)

        # Status
        elif key == "domain status" or key == "status":
            if value not in result["status"]:
                result["status"].append(value)

        # Registrant
        elif key in ("registrant organization", "registrant name", "org") and not result["registrant"]:
            result["registrant"] = value

        elif key in ("registrant country", "country") and not result["registrant_country"]:
            result["registrant_country"] = value

        # DNSSEC
        elif key == "dnssec" and not result["dnssec"]:
            result["dnssec"] = value

    return result


# ============================================================
# crt.sh (with HTML fallback)
# ============================================================

def _crtsh_subdomains(domain, timeout=30):
    """Get subdomains from crt.sh (JSON + HTML fallback, shared per process)."""
    return crtsh_lookup(domain, timeout=timeout)


# ============================================================
# Subdomain Verification (parallel, deadline-bounded)
# ============================================================

def _verify_subdomains_ex(domain, subs, workers=VERIFY_WORKERS, timeout=3,
                         deadline=VERIFY_DEADLINE):
    """Resolve candidate subdomains in parallel.

    Returns (verified entries, unverified hostnames). Names still unresolved
    after ``deadline`` seconds are reported as unverified instead of holding
    up the caller; ``deadline=None`` waits for every lookup.
    """
    suffix = f".{domain}"
    hostnames = sorted({sub if sub.endswith(suffix) else f"{sub}{suffix}" for sub in subs})
    if not hostnames:
        return [], []

    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(workers, len(hostnames))))
    futures = {}
    try:
        for hostname in hostnames:
            futures[ex.submit(_resolve_a_only, hostname, timeout)] = hostname
        concurrent.futures.wait(futures, timeout=deadline)
    finally:
        for future in futures:
            future.cancel()
        ex.shutdown(wait=False)

    verified, unverified = [], []
    for future, hostname in futures.items():
        if not future.done() or future.cancelled():
            unverified.append(hostname)
            continue
        try:
            ip = future.result()
        except Exception:
            ip = None
        if ip:
            verified.append({
                "hostname": hostname,
                "ip": ip,
                "ipv4": [ip],
                "ipv6": [],
            })
    return verified, sorted(unverified)


def _verify_subdomains(domain, subs, workers=50, timeout=3, deadline=None):
    """Verify subdomains in parallel (verified entries only)."""
    return _verify_subdomains_ex(domain, subs, workers=workers, timeout=timeout,
                                 deadline=deadline)[0]


def _stage_result(future, label, errors, default=None):
    try:
        value = future.result()
    except Exception as e:
        errors.append(f"{label}: {e}")
        return default
    return default if value is None else value


# ============================================================
# Main
# ============================================================

def run_domain_osint(domain, deep=False, workers=VERIFY_WORKERS,
                     verify_deadline=VERIFY_DEADLINE, ips=None):
    """Full domain recon — pure Python.

    rDNS, DoH records, WHOIS and crt.sh run concurrently; subdomain
    verification starts as soon as crt.sh answers. ``workers`` caps the
    parallel DNS lookups used for verification and ``ips`` (the dict
    returned by _resolve_all_ips) skips resolving the domain again.
    """
    result = {
        "timestamp": datetime.now().isoformat(),
        "domain": domain,
        "ips": {"A": [], "AAAA": []},
        "reverse_dns": {},
        "dns_records": {},
        "whois": {},
        "subdomains": [],
        "unverified": [],
        "sources_used": [],
        "errors": [],
    }

    # === 1. Resolve main domain ===
    if ips is None:
        print(f"  [*] Resolving {domain}...")
        ips = _resolve_all_ips(domain)
    elif isinstance(ips, dict):
        ips = {"A": list(ips.get("A") or []), "AAAA": list(ips.get("AAAA") or [])}
    else:
        ips = {"A": list(ips), "AAAA": []}
    result["ips"] = ips

    # === 2-5. Reverse DNS, DoH records, WHOIS and crt.sh (concurrent) ===
    rdns_ips = ips["A"][:10]
    print(f"  [*] Reverse DNS lookup...")
    print(f"  [*] Fetching DNS records (DoH)...")
    print(f"  [*] Querying WHOIS (socket)...")
    print(f"  [*] Querying Certificate Transparency (crt.sh)...")

    stage_ex = concurrent.futures.ThreadPoolExecutor(max_workers=3 + len(rdns_ips))
    try:
        rdns_futures = {stage_ex.submit(_reverse_dns, ip): ip for ip in rdns_ips}
        dns_future = stage_ex.submit(_get_dns_records, domain)
        whois_future = stage_ex.submit(_whois_socket, domain)
        crtsh_future = stage_ex.submit(_crtsh_subdomains, domain)

        crtsh_subs = _stage_result(crtsh_future, "crt.sh", result["errors"], default=set())

        # === 6. Brute force (if deep) ===
        subs_to_check = set(crtsh_subs)
        if deep:
            print(f"  [*] Adding {len(COMMON_SUBDOMAINS)} brute-force words...")
            subs_to_check.update(COMMON_SUBDOMAINS)

        # === 7. Verify subdomains (parallel, bounded by a deadline) ===
        if subs_to_check:
            print(f"  [*] Verifying {len(subs_to_check)} subdomains...")
            verified, unverified = _verify_subdomains_ex(
                domain, subs_to_check, workers=workers, deadline=verify_deadline)
            result["subdomains"] = sorted(verified, key=lambda x: x["hostname"])
            result["unverified"] = unverified
            if unverified:
                result["errors"].append(
                    f"verification: {len(unverified)} name(s) not resolved "
                    f"within {verify_deadline}s")

        for future, ip in rdns_futures.items():
            host = _stage_result(future, f"reverse DNS {ip}", result["errors"])
            if host:
                result["reverse_dns"][ip] = host

        result["dns_records"] = _stage_result(dns_future, "DoH", result["errors"], default={})

        whois_raw = _stage_result(whois_future, "WHOIS", result["errors"])
    finally:
        stage_ex.shutdown(wait=False)

    if whois_raw:
        result["whois"] = _parse_whois(whois_raw)
        if result["whois"].get("registrar"):
            result["sources_used"].append("whois")
    else:
        result["whois"] = _parse_whois(None)

    if crtsh_subs:
        result["sources_used"].append(f"crt.sh ({len(crtsh_subs)} found)")

    return result


def _reverse_dns(ip, timeout=5):
    """Reverse DNS lookup."""
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None


# ============================================================
# Report
# ============================================================

def print_domain_report(result):
    print("\n" + "=" * 70)
    print("  🌐 Domain OSINT - ReconX")
    print("=" * 70)

    print(f"\n[*] Domain: {result.get('domain')}")

    ips = result.get("ips", {})
    if ips.get("A"):
        print(f"\n[+] IPv4 ({len(ips['A'])}):")
        for ip in ips["A"]:
            rev = result.get("reverse_dns", {}).get(ip, "")
            print(f"    • {ip}" + (f"  ← {rev}" if rev else ""))
    else:
        print(f"\n[!] No IPv4 addresses resolved")

    if ips.get("AAAA"):
        print(f"\n[+] IPv6 ({len(ips['AAAA'])}):")
        for ip in ips["AAAA"][:5]:
            print(f"    • {ip}")

    # WHOIS
    whois = result.get("whois", {})
    if whois.get("registrar") or whois.get("creation_date"):
        print(f"\n[+] WHOIS:")
        if whois.get("registrar"):
            print(f"    Registrar:  {whois['registrar']}")
        if whois.get("creation_date"):
            print(f"    Created:    {whois['creation_date']}")
        if whois.get("expiry_date"):
            print(f"    Expires:    {whois['expiry_date']}")
        if whois.get("updated_date"):
            print(f"    Updated:    {whois['updated_date']}")
        if whois.get("registrant"):
            print(f"    Registrant: {whois['registrant']}")
        if whois.get("registrant_country"):
            print(f"    Country:    {whois['registrant_country']}")
        if whois.get("dnssec"):
            print(f"    DNSSEC:     {whois['dnssec']}")
    else:
        print(f"\n[!] WHOIS: no data (some TLDs block port 43)")

    if whois.get("name_servers"):
        print(f"\n[+] Nameservers:")
        for ns in whois["name_servers"][:5]:
            print(f"    • {ns}")

    # DNS records summary
    dns_records = result.get("dns_records", {})
    if dns_records:
        print(f"\n[+] DNS Records:")
        for rtype, answers in dns_records.items():
            print(f"    [{rtype}] {len(answers)} record(s)")
            for a in answers[:3]:
                data = a.get("data", "")
                print(f"      • {data[:80]}")

    # Subdomains
    subs = result.get("subdomains", [])
    if subs:
        print(f"\n[+] Subdomains ({len(subs)}):")
        for s in subs[:30]:
            ip = s.get("ip", "?")
            print(f"    ✓ {s['hostname']:<45} {ip}")
        if len(subs) > 30:
            print(f"    ... and {len(subs) - 30} more")
    else:
        print(f"\n[!] No subdomains found")

    if result.get("unverified"):
        print(f"[!] {len(result['unverified'])} subdomain(s) not verified before the deadline")

    if result.get("sources_used"):
        print(f"\n[*] Sources: {', '.join(result['sources_used'])}")

    print("\n" + "=" * 70 + "\n")


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) < 2:
        print("Usage: python -m modules.web.domain_osint <domain> [--deep]")
        sys.exit(1)

    domain = sys.argv[1]
    deep = "--deep" in sys.argv

    print(f"\n[*] Domain OSINT: {domain} (deep={deep})")
    result = run_domain_osint(domain, deep=deep)
    print_domain_report(result)
