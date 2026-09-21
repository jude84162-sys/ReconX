# modules/dns_deep.py
"""ReconX - DNS Deep Recon (Pure Python, DoH-based, no nslookup needed)."""

import json
import socket
import ssl
import logging
import urllib.request
import urllib.error
import concurrent.futures
from datetime import datetime

logger = logging.getLogger("ReconX.dns_deep")


# ============================================================
# DNS-over-HTTPS (no external tools needed)
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
    """Query DNS via DoH (Cloudflare + Google fallback)."""
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
            if not answers:
                return []

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
            logger.debug(f"DoH {endpoint} failed for {rtype}: {e}")
            continue

    return []


# ============================================================
# Socket-based A/AAAA (fast fallback)
# ============================================================

def _socket_resolve(domain):
    """Resolve A/AAAA via socket (no external tools)."""
    result = {"A": [], "AAAA": []}
    try:
        socket.setdefaulttimeout(5)
        infos = socket.getaddrinfo(domain, None)
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
# Record fetchers (all DoH-based)
# ============================================================

def _get_ns(domain):
    answers = _doh_query(domain, "NS")
    return [a["data"] for a in answers if a["data"]]


def _get_mx(domain):
    answers = _doh_query(domain, "MX")
    return [
        {"priority": int(a["data"].split()[0]) if " " in a["data"] else 0,
         "host": a["data"].split()[-1]}
        for a in answers if a["data"]
    ]


def _get_txt(domain):
    answers = _doh_query(domain, "TXT")
    return [a["data"].strip('"') for a in answers if a["data"]]


def _get_soa(domain):
    answers = _doh_query(domain, "SOA")
    if answers:
        return answers[0]["data"]
    return None


def _get_caa(domain):
    answers = _doh_query(domain, "CAA")
    return [a["data"] for a in answers if a["data"]]


def _get_cname(domain):
    answers = _doh_query(domain, "CNAME")
    return [a["data"] for a in answers if a["data"]]


def _check_dmarc(domain):
    """Check DMARC via TXT on _dmarc.domain."""
    answers = _doh_query(f"_dmarc.{domain}", "TXT")
    for a in answers:
        data = a["data"].strip('"')
        if "v=DMARC1" in data:
            return data
    return None


def _check_spf(txt_records):
    """Find SPF in TXT records."""
    for txt in txt_records:
        if txt.startswith("v=spf1"):
            return txt
    return None


# ============================================================
# Zone transfer attempt (via socket, best-effort)
# ============================================================

def _try_zone_transfer(domain, ns):
    """Best-effort AXFR via socket. Most servers refuse."""
    try:
        # Resolve NS to IP
        ns_ips = _socket_resolve(ns).get("A", [])
        if not ns_ips:
            return None

        ns_ip = ns_ips[0]

        # Send AXFR query packet
        # Build DNS AXFR query manually
        import struct
        import random

        txn_id = random.randint(1, 65535)
        flags = 0x0000  # Standard query
        qdcount = 1
        header = struct.pack("!HHHHHH", txn_id, flags, qdcount, 0, 0, 0)

        # Encode domain name
        parts = domain.split(".")
        qname = b""
        for p in parts:
            qname += bytes([len(p)]) + p.encode()
        qname += b"\x00"

        # QTYPE=252 (AXFR), QCLASS=1 (IN)
        question = qname + struct.pack("!HH", 252, 1)
        packet = header + question

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(8)
        sock.connect((ns_ip, 53))
        sock.send(packet)

        # Read response
        response = sock.recv(4096)
        sock.close()

        if len(response) < 12:
            return None

        # Parse response code
        resp_id, resp_flags = struct.unpack("!HH", response[:4])
        rcode = resp_flags & 0x000F

        if rcode == 5:  # REFUSED
            return None
        if rcode == 0 and len(response) > 12:
            # Got some data
            return f"Received {len(response)} bytes from {ns}"
    except Exception:
        pass
    return None


# ============================================================
# Main
# ============================================================

def run_dns_deep(domain):
    """Deep DNS recon — pure Python, no external tools."""
    result = {
        "timestamp": datetime.now().isoformat(),
        "domain": domain,
        "records": {},
        "nameservers": [],
        "mx": [],
        "txt": [],
        "caa": [],
        "cname": [],
        "spf": None,
        "dmarc": None,
        "soa": None,
        "zone_transfer": None,
        "indicators": [],
        "summary": {},
        "error": None,
    }

    # === Parallel fetch all record types ===
    print(f"  [*] Querying DNS records via DoH (parallel)...")

    tasks = {
        "ns":   (lambda: _get_ns(domain)),
        "mx":   (lambda: _get_mx(domain)),
        "txt":  (lambda: _get_txt(domain)),
        "soa":  (lambda: _get_soa(domain)),
        "caa":  (lambda: _get_caa(domain)),
        "cname":(lambda: _get_cname(domain)),
        "dmarc":(lambda: _check_dmarc(domain)),
    }

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks)) as ex:
        futures = {ex.submit(fn): name for name, fn in tasks.items()}
        for future in concurrent.futures.as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result(timeout=15)
            except Exception as e:
                logger.debug(f"{name} failed: {e}")
                results[name] = None

    result["nameservers"] = results.get("ns") or []
    result["mx"] = results.get("mx") or []
    result["txt"] = results.get("txt") or []
    result["soa"] = results.get("soa")
    result["caa"] = results.get("caa") or []
    result["cname"] = results.get("cname") or []
    result["dmarc"] = results.get("dmarc")

    # SPF from TXT
    result["spf"] = _check_spf(result["txt"])

    # === Zone transfer attempt ===
    for ns in result["nameservers"][:2]:
        print(f"  [*] Attempting AXFR via {ns}...")
        zt = _try_zone_transfer(domain, ns)
        if zt:
            result["zone_transfer"] = {
                "nameserver": ns,
                "content": zt,
            }
            result["indicators"].append(
                ("CRITICAL", f"Zone transfer succeeded via {ns}!")
            )
            break

    # === Analysis ===
    if not result["spf"]:
        result["indicators"].append(
            ("MEDIUM", "No SPF record (email spoofing risk)")
        )
    if not result["dmarc"]:
        result["indicators"].append(
            ("MEDIUM", "No DMARC record (email spoofing risk)")
        )
    if not result["mx"]:
        result["indicators"].append(
            ("LOW", "No MX records (cannot receive email)")
        )
    if not result["nameservers"]:
        result["indicators"].append(
            ("HIGH", "No NS records found — domain may not exist")
        )

    # === Summary ===
    result["summary"] = {
        "nameservers": len(result["nameservers"]),
        "mx_records": len(result["mx"]),
        "txt_records": len(result["txt"]),
        "caa_records": len(result["caa"]),
        "has_spf": bool(result["spf"]),
        "has_dmarc": bool(result["dmarc"]),
        "has_caa": bool(result["caa"]),
        "zone_transfer": bool(result["zone_transfer"]),
        "indicators": len(result["indicators"]),
    }

    return result


# ============================================================
# Report
# ============================================================

def print_dns_deep_report(result):
    print("\n" + "=" * 70)
    print("  DNS Deep Recon - ReconX")
    print("=" * 70)

    print(f"\n[*] Domain: {result.get('domain')}")

    if result.get("nameservers"):
        print(f"\n[+] Nameservers ({len(result['nameservers'])}):")
        for ns in result["nameservers"]:
            print(f"    • {ns}")
    else:
        print(f"\n[!] No nameservers found")

    if result.get("mx"):
        print(f"\n[+] MX Records ({len(result['mx'])}):")
        for mx in result["mx"][:10]:
            if isinstance(mx, dict):
                print(f"    • {mx['priority']:>3}  {mx['host']}")
            else:
                print(f"    • {mx}")

    if result.get("cname"):
        print(f"\n[+] CNAME ({len(result['cname'])}):")
        for c in result["cname"][:5]:
            print(f"    • {c}")

    if result.get("spf"):
        print(f"\n[+] SPF: {result['spf'][:100]}")
    else:
        print(f"\n[!] SPF: MISSING")

    if result.get("dmarc"):
        print(f"[+] DMARC: {result['dmarc'][:100]}")
    else:
        print(f"[!] DMARC: MISSING")

    if result.get("caa"):
        print(f"\n[+] CAA ({len(result['caa'])}):")
        for c in result["caa"][:5]:
            print(f"    • {c}")

    if result.get("soa"):
        print(f"\n[+] SOA: {result['soa'][:120]}")

    if result.get("zone_transfer"):
        zt = result["zone_transfer"]
        print(f"\n[🔴] ZONE TRANSFER SUCCESS!")
        print(f"    Nameserver: {zt['nameserver']}")
        print(f"    Preview: {zt['content'][:200]}")

    if result.get("indicators"):
        print(f"\n[!] Indicators:")
        for level, reason in result["indicators"]:
            m = "[!!]" if level == "CRITICAL" else "[!]" if level == "HIGH" else "[~]"
            print(f"    {m} [{level}] {reason}")

    print("\n" + "=" * 70 + "\n")


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(f"\n[*] DNS Deep: {domain}")
    result = run_dns_deep(domain)
    print_dns_deep_report(result)
