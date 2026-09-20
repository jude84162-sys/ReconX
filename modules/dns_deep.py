# modules/dns_deep.py
"""ReconX - DNS Deep Recon (records, zone transfer, DNSSEC)."""

import subprocess
import socket
import logging
from datetime import datetime

logger = logging.getLogger("ReconX.dns_deep")


def _run_cmd(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout if r.returncode == 0 else None
    except Exception:
        return None


def _get_ns_records(domain):
    output = _run_cmd(["nslookup", "-type=NS", domain])
    if not output:
        return []
    nss = []
    for line in output.splitlines():
        line = line.strip()
        if "nameserver" in line.lower() or "=" in line:
            parts = line.split("=")
            if len(parts) == 2:
                ns = parts[1].strip().rstrip(".")
                if ns and ns not in nss:
                    nss.append(ns)
    return nss


def _get_mx_records(domain):
    output = _run_cmd(["nslookup", "-type=MX", domain])
    if not output:
        return []
    mxs = []
    for line in output.splitlines():
        if "mail exchanger" in line.lower() or "MX preference" in line:
            mxs.append(line.strip())
    return mxs


def _get_txt_records(domain):
    output = _run_cmd(["nslookup", "-type=TXT", domain])
    if not output:
        return []
    txts = []
    for line in output.splitlines():
        line = line.strip()
        if "text =" in line.lower():
            txts.append(line.split("=", 1)[1].strip().strip('"'))
    return txts


def _get_soa_record(domain):
    output = _run_cmd(["nslookup", "-type=SOA", domain])
    if not output:
        return None
    for line in output.splitlines():
        if "primary name server" in line.lower() or "serial" in line.lower():
            return line.strip()
    return None


def _try_zone_transfer(domain, ns):
    """Attempt AXFR zone transfer."""
    try:
        r = subprocess.run(
            ["nslookup", "-type=AXFR", domain, ns],
            capture_output=True, text=True, timeout=15
        )
        if r.returncode == 0 and r.stdout and "refused" not in r.stdout.lower():
            if "server can't find" not in r.stdout.lower():
                return r.stdout[:2000]
    except Exception:
        pass
    return None


def _check_spf(txt_records):
    """Check SPF record."""
    for txt in txt_records:
        if txt.startswith("v=spf1"):
            return txt
    return None


def _check_dmarc(domain):
    """Check DMARC record."""
    output = _run_cmd(["nslookup", "-type=TXT", f"_dmarc.{domain}"])
    if not output:
        return None
    for line in output.splitlines():
        if "v=DMARC1" in line:
            return line.strip()
    return None


def run_dns_deep(domain):
    """Deep DNS recon."""
    result = {
        "timestamp": datetime.now().isoformat(),
        "domain": domain,
        "records": {},
        "nameservers": [],
        "mx": [],
        "txt": [],
        "spf": None,
        "dmarc": None,
        "soa": None,
        "zone_transfer": None,
        "indicators": [],
        "summary": {},
        "error": None,
    }

    print(f"  [*] Fetching NS records...")
    result["nameservers"] = _get_ns_records(domain)

    print(f"  [*] Fetching MX records...")
    result["mx"] = _get_mx_records(domain)

    print(f"  [*] Fetching TXT records...")
    result["txt"] = _get_txt_records(domain)

    print(f"  [*] Checking SPF...")
    result["spf"] = _check_spf(result["txt"])

    print(f"  [*] Checking DMARC...")
    result["dmarc"] = _check_dmarc(domain)

    print(f"  [*] Fetching SOA record...")
    result["soa"] = _get_soa_record(domain)

    # Zone transfer attempt
    for ns in result["nameservers"][:2]:
        print(f"  [*] Attempting zone transfer via {ns}...")
        zt = _try_zone_transfer(domain, ns)
        if zt:
            result["zone_transfer"] = {
                "nameserver": ns,
                "content": zt,
            }
            result["indicators"].append(("CRITICAL", f"Zone transfer succeeded via {ns}!"))
            break

    # Analysis
    if not result["spf"]:
        result["indicators"].append(("MEDIUM", "No SPF record (email spoofing risk)"))
    if not result["dmarc"]:
        result["indicators"].append(("MEDIUM", "No DMARC record (email spoofing risk)"))

    # Summary
    result["summary"] = {
        "nameservers": len(result["nameservers"]),
        "mx_records": len(result["mx"]),
        "txt_records": len(result["txt"]),
        "has_spf": bool(result["spf"]),
        "has_dmarc": bool(result["dmarc"]),
        "zone_transfer": bool(result["zone_transfer"]),
        "indicators": len(result["indicators"]),
    }

    return result


def print_dns_deep_report(result):
    print("\n" + "=" * 70)
    print("  DNS Deep Recon - ReconX")
    print("=" * 70)

    print(f"\n[*] Domain: {result.get('domain')}")

    if result.get("nameservers"):
        print(f"\n[+] Nameservers ({len(result['nameservers'])}):")
        for ns in result["nameservers"]:
            print(f"    • {ns}")

    if result.get("mx"):
        print(f"\n[+] MX Records ({len(result['mx'])}):")
        for mx in result["mx"][:5]:
            print(f"    • {mx}")

    if result.get("spf"):
        print(f"\n[+] SPF: {result['spf']}")

    if result.get("dmarc"):
        print(f"\n[+] DMARC: {result['dmarc']}")

    if result.get("soa"):
        print(f"\n[+] SOA: {result['soa']}")

    if result.get("zone_transfer"):
        zt = result["zone_transfer"]
        print(f"\n[🔴] ZONE TRANSFER SUCCESS!")
        print(f"    Nameserver: {zt['nameserver']}")
        print(f"    Preview: {zt['content'][:200]}")

    if result.get("indicators"):
        print(f"\n[!] Indicators:")
        for level, reason in result["indicators"]:
            m = "[!!]" if level == "CRITICAL" else "[!]" if level == "HIGH" else "[~]"
            print(f"    {m} {reason}")

    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(f"\n[*] DNS Deep: {domain}")
    result = run_dns_deep(domain)
    print_dns_deep_report(result)
