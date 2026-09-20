# modules/subdomain_enum.py
"""ReconX - Subdomain Enumerator (uses subfinder_clone - no install)."""

import logging
from datetime import datetime

logger = logging.getLogger("ReconX.subdomain")


try:
    from modules.subfinder_clone import (
        run_subfinder_clone,
        print_subfinder_clone_report,
    )
    HAS_CLONE = True
except ImportError:
    HAS_CLONE = False


def run_subdomain_enum(domain, use_clone=True, use_bruteforce=True):
    """Enumerate subdomains using subfinder clone."""
    result = {
        "timestamp": datetime.now().isoformat(),
        "domain": domain,
        "subdomains": [],
        "by_source": {},
        "total_unique": 0,
        "errors": []
    }

    if not HAS_CLONE:
        result["errors"].append("subfinder_clone not available")
        return result

    print(f"  [*] Running Subfinder Clone (7 passive sources + bruteforce)...")

    clone_result = run_subfinder_clone(
        domain,
        passive=True,
        bruteforce=use_bruteforce,
        workers=30,
        verbose=True,
    )

    result["by_source"] = clone_result.get("by_source", {})
    result["errors"] = clone_result.get("errors", [])

    # Build subdomains list
    for sub in clone_result.get("subdomains", []):
        result["subdomains"].append({
            "hostname": sub["hostname"],
            "ip": sub["ip"],
            "source": "subfinder_clone",
        })

    result["total_unique"] = len(result["subdomains"])

    return result


def print_subdomain_report(result):
    print("\n" + "=" * 70)
    print("  Subdomain Enumerator - ReconX")
    print("=" * 70)

    print(f"\n[*] Domain: {result.get('domain')}")
    print(f"[*] Found:  {result.get('total_unique', 0)} subdomains")

    if result.get("by_source"):
        print(f"\n[*] By Source:")
        for src, count in sorted(result["by_source"].items()):
            marker = "✓" if count > 0 else "·"
            print(f"    {marker} {src:<20} {count}")

    if result.get("subdomains"):
        print(f"\n[+] Subdomains (first 50):")
        for s in result["subdomains"][:50]:
            print(f"    ✓ {s['hostname']:<50} {s['ip']}")
        if len(result["subdomains"]) > 50:
            print(f"    ... and {len(result['subdomains']) - 50} more")

    if result.get("errors"):
        print(f"\n[!] Errors:")
        for e in result["errors"][:3]:
            print(f"    - {e}")

    print("\n" + "=" * 70 + "\n")
