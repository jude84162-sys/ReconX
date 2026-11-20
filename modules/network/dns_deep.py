# modules/dns_deep.py
"""ReconX - DNS Deep Recon (Pure Python, DoH-based, no nslookup needed)."""

import json
import random
import socket
import ssl
import struct
import time
import logging
import urllib.request
import urllib.error
import concurrent.futures
from datetime import datetime

logger = logging.getLogger("ReconX.dns_deep")

AXFR_TIMEOUT = 4.0
AXFR_MAX_BYTES = 1024 * 1024
AXFR_MAX_SECONDS = 20.0
AXFR_MAX_NAMES = 50


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

def _resolve_ipv4(host, port=53):
    """First IPv4 address of host, without touching global socket state."""
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    except Exception:
        return None
    for info in infos:
        return info[4][0]
    return None


def _encode_qname(domain):
    qname = b""
    for label in domain.strip().rstrip(".").split("."):
        if not label:
            continue
        raw = label.encode("idna")
        if len(raw) > 63:
            raise ValueError("label too long")
        qname += bytes([len(raw)]) + raw
    return qname + b"\x00"


def _recv_exact(sock, n, deadline, timeout):
    """Read exactly n bytes, or return None if the peer closes first."""
    buf = bytearray()
    while len(buf) < n:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout("AXFR time budget exhausted")
        sock.settimeout(min(timeout, remaining))
        chunk = sock.recv(min(n - len(buf), 65536))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def _read_tcp_message(sock, deadline, timeout):
    """Read one length-prefixed DNS message (RFC 1035 4.2.2)."""
    head = _recv_exact(sock, 2, deadline, timeout)
    if head is None:
        return None
    (length,) = struct.unpack("!H", head)
    if length == 0:
        return b""
    return _recv_exact(sock, length, deadline, timeout)


def _parse_name(msg, off):
    """Decode a (possibly compressed) name; return (name, offset after it)."""
    labels = []
    end = None
    hops = 0
    while True:
        if off >= len(msg):
            raise ValueError("truncated name")
        length = msg[off]
        if length & 0xC0 == 0xC0:
            if off + 1 >= len(msg):
                raise ValueError("truncated pointer")
            if end is None:
                end = off + 2
            hops += 1
            if hops > 64:
                raise ValueError("compression loop")
            off = ((length & 0x3F) << 8) | msg[off + 1]
            continue
        if length & 0xC0:
            raise ValueError("unsupported label type")
        if length == 0:
            off += 1
            break
        if off + 1 + length > len(msg):
            raise ValueError("truncated label")
        labels.append(msg[off + 1:off + 1 + length].decode("ascii", "replace"))
        off += 1 + length
    return ".".join(labels), (end if end is not None else off)


def _parse_axfr_message(msg, txn_id):
    """Return (rcode, [(owner, rtype), ...]) for one AXFR response message.

    rcode is None when the message is not a reply to our query.
    """
    if not msg or len(msg) < 12:
        return None, []
    rid, flags, qdcount, ancount, _ns, _ar = struct.unpack("!HHHHHH", msg[:12])
    if rid != txn_id or not flags & 0x8000:
        return None, []
    rcode = flags & 0x000F
    if rcode != 0:
        return rcode, []
    records = []
    off = 12
    try:
        for _ in range(qdcount):
            _, off = _parse_name(msg, off)
            off += 4
        for _ in range(ancount):
            owner, off = _parse_name(msg, off)
            if off + 10 > len(msg):
                break
            rtype, _cls, _ttl, rdlength = struct.unpack("!HHIH", msg[off:off + 10])
            off += 10 + rdlength
            if off > len(msg):
                break
            records.append((owner, rtype))
    except ValueError:
        pass
    return rcode, records


def _try_zone_transfer(domain, ns, timeout=AXFR_TIMEOUT, port=53,
                       max_bytes=AXFR_MAX_BYTES, max_seconds=AXFR_MAX_SECONDS):
    """Best-effort AXFR over DNS-over-TCP. Most servers refuse."""
    sock = None
    total = 0
    record_count = 0
    soa_seen = 0
    names = []
    seen = set()
    try:
        ns_ip = _resolve_ipv4(ns, port)
        if not ns_ip:
            return None

        txn_id = random.randint(1, 65535)
        header = struct.pack("!HHHHHH", txn_id, 0x0000, 1, 0, 0, 0)
        # QTYPE=252 (AXFR), QCLASS=1 (IN)
        query = header + _encode_qname(domain) + struct.pack("!HH", 252, 1)

        deadline = time.monotonic() + max(timeout, max_seconds)
        sock = socket.create_connection((ns_ip, port), timeout=timeout)
        sock.sendall(struct.pack("!H", len(query)) + query)

        while total < max_bytes:
            reply = _read_tcp_message(sock, deadline, timeout)
            if reply is None:
                break
            rcode, records = _parse_axfr_message(reply, txn_id)
            if rcode != 0 or not records:
                break
            total += len(reply) + 2
            record_count += len(records)
            for owner, rtype in records:
                if rtype == 6:
                    soa_seen += 1
                if owner and owner not in seen and len(names) < AXFR_MAX_NAMES:
                    seen.add(owner)
                    names.append(owner)
            if soa_seen >= 2:
                break
    except Exception as e:
        logger.debug(f"AXFR via {ns} failed: {e}")
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

    if not record_count:
        return None
    content = f"Received {total} bytes ({record_count} records) from {ns}"
    if soa_seen < 2:
        content += " [partial]"
    if names:
        content += ": " + ", ".join(names)
    return content


# ============================================================
# Main
# ============================================================

def run_dns_deep(domain, axfr_timeout=AXFR_TIMEOUT, axfr_workers=2):
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
    candidates = result["nameservers"][:2]
    outcomes = []
    if candidates:
        for ns in candidates:
            print(f"  [*] Attempting AXFR via {ns}...")
        pool_size = max(1, min(int(axfr_workers or 1), len(candidates)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=pool_size) as ex:
            futures = [
                ex.submit(_try_zone_transfer, domain, ns, timeout=axfr_timeout)
                for ns in candidates
            ]
            for ns, future in zip(candidates, futures):
                try:
                    outcomes.append((ns, future.result()))
                except Exception as e:
                    logger.debug(f"AXFR via {ns} failed: {e}")
                    outcomes.append((ns, None))

    for ns, zt in outcomes:
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
