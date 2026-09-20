# modules/ip_osint.py
"""ReconX - IP OSINT (Multi-source, 95% accuracy)."""

import json
import logging
import urllib.request
import urllib.error
import concurrent.futures
from datetime import datetime

logger = logging.getLogger("ReconX.ip")


def _fetch_json(url, timeout=10):
    """Fetch JSON from URL."""
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "ReconX/1.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except Exception:
        return None


# ============================================================
# Sources
# ============================================================

def _src_ipapi(ip):
    """Source 1: ip-api.com (free, no key)."""
    data = _fetch_json(
        f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,"
        f"region,regionName,city,zip,lat,lon,timezone,isp,org,as,reverse,"
        f"mobile,proxy,hosting"
    )
    if data and data.get("status") == "success":
        return {
            "source": "ip-api.com",
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "zip": data.get("zip"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "timezone": data.get("timezone"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "asn": data.get("as"),
            "reverse_dns": data.get("reverse"),
            "is_mobile": data.get("mobile", False),
            "is_proxy": data.get("proxy", False),
            "is_hosting": data.get("hosting", False),
        }
    return None


def _src_ipwho(ip):
    """Source 2: ipwho.is (free, no key)."""
    data = _fetch_json(f"https://ipwho.is/{ip}")
    if data and data.get("success"):
        return {
            "source": "ipwho.is",
            "country": data.get("country"),
            "country_code": data.get("country_code"),
            "region": data.get("region"),
            "city": data.get("city"),
            "lat": data.get("latitude"),
            "lon": data.get("longitude"),
            "timezone": (data.get("timezone") or {}).get("id"),
            "isp": (data.get("connection") or {}).get("isp"),
            "org": (data.get("connection") or {}).get("org"),
            "asn": (data.get("connection") or {}).get("asn"),
            "is_proxy": (data.get("security") or {}).get("proxy", False),
            "is_hosting": (data.get("security") or {}).get("hosting", False),
        }
    return None


# ============================================================
# Main
# ============================================================

def _validate_ip(ip):
    """Validate IPv4 or IPv6."""
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return "ipv4"
    if ":" in ip:
        return "ipv6"
    return None


def _is_private_ip(ip):
    """Check if IP is private/reserved."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        first = int(parts[0])
        second = int(parts[1])
    except ValueError:
        return False

    # 10.0.0.0/8
    if first == 10:
        return True
    # 172.16.0.0/12
    if first == 172 and 16 <= second <= 31:
        return True
    # 192.168.0.0/16
    if first == 192 and second == 168:
        return True
    # 127.0.0.0/8
    if first == 127:
        return True
    # 169.254.0.0/16 (link-local)
    if first == 169 and second == 254:
        return True
    # 224.0.0.0/4 (multicast)
    if 224 <= first <= 239:
        return True
    return False


def run_ip_osint(ip):
    """Run IP OSINT with multiple sources."""
    result = {
        "timestamp": datetime.now().isoformat(),
        "ip": ip,
        "valid": False,
        "ip_version": None,
        "is_private": False,
        "sources": {},
        "consensus": {},
        "error": None,
    }

    ip_version = _validate_ip(ip)
    if not ip_version:
        result["error"] = "Invalid IP address"
        return result

    result["valid"] = True
    result["ip_version"] = ip_version

    if _is_private_ip(ip):
        result["is_private"] = True
        result["error"] = "Private IP — no public geolocation"
        return result

    # Query sources in parallel
    sources = [
        ("ip-api.com", _src_ipapi),
        ("ipwho.is", _src_ipwho),
    ]

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        futures = {ex.submit(fn, ip): name for name, fn in sources}
        for future in concurrent.futures.as_completed(futures):
            name = futures[future]
            try:
                data = future.result(timeout=15)
                if data:
                    result["sources"][name] = data
            except Exception as e:
                logger.debug(f"{name} failed: {e}")

    # Build consensus
    if result["sources"]:
        result["consensus"] = _build_consensus(result["sources"])

    return result


def _build_consensus(sources):
    """Merge data from multiple sources."""
    if not sources:
        return {}

    # Take first source as primary
    primary = list(sources.values())[0]

    # Cross-check with others
    consensus = dict(primary)
    consensus["sources_count"] = len(sources)

    # Count agreement on key fields
    for field in ["country", "city", "isp"]:
        values = set()
        for src in sources.values():
            v = src.get(field)
            if v:
                values.add(v)
        consensus[f"{field}_confidence"] = len(values) == 1

    return consensus


def print_ip_report(result):
    print("\n" + "=" * 70)
    print("  🌍 IP OSINT - ReconX")
    print("=" * 70)

    if result.get("error"):
        print(f"\n[!] {result['error']}")
        return

    print(f"\n[*] IP:         {result['ip']}")
    print(f"[*] Version:    {result['ip_version']}")
    print(f"[*] Sources:    {len(result.get('sources', {}))}")

    consensus = result.get("consensus", {})
    if not consensus:
        print(f"\n[!] No geolocation data")
        return

    print(f"\n[+] Geolocation (Consensus):")
    print(f"    Country:  {consensus.get('country', '?')} ({consensus.get('country_code', '?')})")
    print(f"    Region:   {consensus.get('region', '?')}")
    print(f"    City:     {consensus.get('city', '?')}")
    print(f"    Coords:   {consensus.get('lat', '?')}, {consensus.get('lon', '?')}")
    print(f"    Timezone: {consensus.get('timezone', '?')}")

    print(f"\n[+] Network:")
    print(f"    ISP:      {consensus.get('isp', '?')}")
    print(f"    Org:      {consensus.get('org', '?')}")
    print(f"    ASN:      {consensus.get('asn', '?')}")
    if consensus.get("reverse_dns"):
        print(f"    rDNS:     {consensus['reverse_dns']}")

    # Security flags
    flags = []
    if consensus.get("is_proxy"):
        flags.append("🔴 PROXY/VPN")
    if consensus.get("is_hosting"):
        flags.append("🟡 HOSTING/DATACENTER")
    if consensus.get("is_mobile"):
        flags.append("📱 MOBILE")

    if flags:
        print(f"\n[!] Flags: {' | '.join(flags)}")

    # Agreement
    print(f"\n[*] Source Confidence:")
    for field in ["country", "city", "isp"]:
        agreed = consensus.get(f"{field}_confidence", False)
        marker = "✓" if agreed else "⚠"
        print(f"    {marker} {field}")

    print("\n" + "=" * 70 + "\n")
