# modules/vuln/scanner_manager.py
"""ReconX - Vulnerability Scanner Manager.

Orchestrates all web vulnerability scanners:
  - SQLi, XSS, SSRF, SSTI, CMDi, JWT
  - Unified output format
  - Deduplication across scanners
  - Severity sorting
"""

import logging
import concurrent.futures
from datetime import datetime

logger = logging.getLogger("ReconX.vuln_manager")


# Available scanners
SCANNERS = {
    "sqli": {
        "module": "modules.vuln.web.sqli_scanner",
        "name": "SQL Injection",
        "icon": "💉",
        "needs_deps": "sqlmap (optional)",
    },
    "xss": {
        "module": "modules.vuln.web.xss_scanner",
        "name": "XSS",
        "icon": "🎯",
        "needs_deps": "dalfox (optional)",
    },
    "ssrf": {
        "module": "modules.vuln.web.ssrf_scanner",
        "name": "SSRF",
        "icon": "🌐",
        "needs_deps": None,
    },
    "ssti": {
        "module": "modules.vuln.web.ssti_scanner",
        "name": "SSTI",
        "icon": "📐",
        "needs_deps": None,
    },
    "cmdi": {
        "module": "modules.vuln.web.cmdi_scanner",
        "name": "Command Injection",
        "icon": "💻",
        "needs_deps": None,
    },
    "jwt": {
        "module": "modules.vuln.web.jwt_scanner",
        "name": "JWT",
        "icon": "🔑",
        "needs_deps": None,
    },
}


def list_scanners():
    return SCANNERS


def run_scanner(scanner_key, target, timeout=300, verbose=False):
    """Run a single scanner."""
    config = SCANNERS.get(scanner_key)
    if not config:
        return {"error": f"Unknown scanner: {scanner_key}", "findings": []}

    try:
        # Dynamic import
        mod = __import__(config["module"], fromlist=["scan", "print_report"])
        scan_fn = getattr(mod, "scan")

        # Run
        if scanner_key in ("sqli",):
            result = scan_fn(target, timeout=timeout, verbose=verbose)
        elif scanner_key in ("jwt",):
            result = scan_fn(target, timeout=10, verbose=verbose)
        else:
            result = scan_fn(target, verbose=verbose)

        result["scanner"] = scanner_key
        result["scanner_name"] = config["name"]
        return result

    except Exception as e:
        logger.error(f"Scanner {scanner_key} failed: {e}")
        return {
            "scanner": scanner_key,
            "scanner_name": config["name"],
            "error": str(e),
            "findings": [],
        }


def run_all(target, scanners=None, workers=3, timeout=300, verbose=True):
    """Run multiple scanners in parallel."""
    if scanners is None:
        scanners = ["ssrf", "ssti", "cmdi", "xss", "jwt", "sqli"]

    result = {
        "timestamp": datetime.now().isoformat(),
        "target": target,
        "scanners_run": [],
        "scanners_failed": [],
        "findings": [],
        "errors": [],
        "total_findings": 0,
    }

    if verbose:
        print(f"\n  [*] Running {len(scanners)} scanners (workers={workers})...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {
            ex.submit(run_scanner, s, target, timeout=timeout, verbose=False): s
            for s in scanners
        }

        for future in concurrent.futures.as_completed(futures):
            key = futures[future]
            try:
                r = future.result(timeout=timeout + 60)

                if r.get("error") and not r.get("findings"):
                    result["scanners_failed"].append({
                        "scanner": key,
                        "error": r["error"],
                    })
                    if verbose:
                        print(f"  ✗ {SCANNERS[key]['name']}: {r['error']}")
                else:
                    result["scanners_run"].append(key)
                    n = len(r.get("findings", []))
                    if verbose:
                        print(f"  ✓ {SCANNERS[key]['name']}: {n} findings")

                    for f in r.get("findings", []):
                        f["scanner"] = key
                        f["scanner_name"] = SCANNERS[key]["name"]
                        result["findings"].append(f)

            except Exception as e:
                result["scanners_failed"].append({"scanner": key, "error": str(e)})
                if verbose:
                    print(f"  ✗ {SCANNERS[key]['name']}: {e}")

    # Dedupe by (title + url)
    seen = set()
    unique = []
    for f in result["findings"]:
        key = (f.get("title", "")[:80], f.get("url", ""))
        if key not in seen:
            seen.add(key)
            unique.append(f)

    result["findings"] = unique
    result["total_findings"] = len(unique)

    # Sort by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    result["findings"].sort(
        key=lambda x: (sev_order.get(x.get("severity", "info"), 99),
                       -x.get("confidence", 0))
    )

    return result


def print_all_report(result):
    """Print unified report."""
    print("\n" + "=" * 70)
    print("  Vulnerability Scan Summary — ReconX")
    print("=" * 70)

    print(f"\n[*] Target:         {result.get('target')}")
    print(f"[*] Scanners run:   {len(result.get('scanners_run', []))}")
    print(f"[*] Scanners failed: {len(result.get('scanners_failed', []))}")
    print(f"[*] Total findings: {result.get('total_findings', 0)}")

    if result.get("scanners_run"):
        print(f"\n[*] Run: {', '.join(result['scanners_run'])}")

    if result.get("scanners_failed"):
        print(f"\n[!] Failed:")
        for f in result["scanners_failed"]:
            print(f"    ✗ {f['scanner']}: {f['error'][:80]}")

    # By severity
    findings = result.get("findings", [])
    if findings:
        by_sev = {}
        for f in findings:
            s = f.get("severity", "info")
            by_sev[s] = by_sev.get(s, 0) + 1

        icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
        print(f"\n[*] By severity:")
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in by_sev:
                print(f"    {icons[sev]} {sev.capitalize():<10} {by_sev[sev]}")

        print(f"\n[+] All findings:")
        for f in findings:
            sev = f.get("severity", "info")
            icon = icons.get(sev, "⚪")
            scanner = f.get("scanner_name", "?")
            title = f.get("title", "?")[:70]

            print(f"\n  {icon} [{sev.upper():<8}] [{scanner}] {title}")
            if f.get("url"):
                print(f"       URL:      {f['url'][:80]}")
            if f.get("parameter"):
                print(f"       Param:    {f['parameter']}")
            if f.get("evidence"):
                print(f"       Evidence: {f['evidence'][:100]}")
            if f.get("payout_potential"):
                print(f"       Payout:   {f['payout_potential']}")

    print("\n" + "=" * 70 + "\n")


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    import sys
    import logging as _log
    _log.basicConfig(level=_log.WARNING)

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python -m modules.vuln.scanner_manager <url>")
        print("  python -m modules.vuln.scanner_manager <url> --scanners sqli xss ssrf")
        print("  python -m modules.vuln.scanner_manager --list")
        print("")
        print("Available scanners:")
        for key, cfg in SCANNERS.items():
            print(f"  {key:<8} {cfg['name']:<20} deps: {cfg['needs_deps'] or 'none'}")
        sys.exit(1)

    if sys.argv[1] == "--list":
        for key, cfg in SCANNERS.items():
            print(f"{key:<8} {cfg['name']}")
        sys.exit(0)

    target = sys.argv[1]
    scanners = None
    if "--scanners" in sys.argv:
        idx = sys.argv.index("--scanners")
        scanners = sys.argv[idx + 1:]

    print(f"\n[*] Vuln scan: {target}")
    if scanners:
        print(f"[*] Scanners: {scanners}")

    result = run_all(target, scanners=scanners, verbose=True)
    print_all_report(result)
