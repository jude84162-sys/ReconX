# modules/vuln/bugbounty_nikto.py
"""ReconX - Bug Bounty Nikto Engine.

Bug-bounty-oriented Nikto wrapper:
  - Multi-target parallel scanning
  - WAF-aware (skip or bypass)
  - Adaptive rate limiting
  - Payout-oriented severity
  - Deduplication across targets
  - HackerOne / Bugcrowd friendly output
"""

import os
import re
import json
import time
import shutil
import random
import logging
import subprocess
import tempfile
import concurrent.futures
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("ReconX.bounty_nikto")


# ============================================================
# Bounty-specific severity mapping (payout-oriented)
# ============================================================

BOUNTY_SEVERITY = {
    "critical": ["rce", "remote code exec", "command inject", "sql inject",
                 "auth bypass", "authn bypass", "backdoor", "shell upload",
                 "default password", "default cred", ".git/", ".env", ".svn/"],
    "high":     ["xss", "cross site script", "ssrf", "ssti", "xxe", "csrf",
                 "path traversal", "lfi", "rfi", "phpmyadmin", "phpinfo",
                 "admin panel", "admin login", "server-status", "server-info",
                 "swagger", "graphql", "actuator"],
    "medium":   ["open redirect", "directory listing", "index of",
                 "backup", ".bak", ".old", "config", "xmlrpc", "verbose error",
                 "info disclosure", "info leak", "cors"],
    "low":      ["missing header", "cookie without", "etag inode",
                 "http trace", "http options", "uncommon header"],
    "info":     ["robots.txt", "sitemap", "well-known", "favicon"],
}


def classify_bounty_severity(message):
    """Classify by bug bounty payout potential."""
    if not message:
        return "info"
    text = message.lower()
    for sev, keywords in BOUNTY_SEVERITY.items():
        for kw in keywords:
            if kw in text:
                return sev
    return "info"


# ============================================================
# Payout estimation
# ============================================================

PAYOUT_RANGES = {
    "critical": "$1000-$10000+",
    "high":     "$500-$3000",
    "medium":   "$150-$800",
    "low":      "$0-$200",
    "info":     "$0 (informational)",
}


# ============================================================
# WAF Detection (fast)
# ============================================================

WAF_HEADERS = {
    "Cloudflare": ["cf-ray", "cf-cache-status", "server: cloudflare"],
    "Akamai":     ["akamai", "x-akamai"],
    "Sucuri":     ["x-sucuri"],
    "Incapsula":  ["x-cdn: incapsula", "incap_ses"],
    "AWS WAF":    ["x-amzn-requestid", "awselb"],
    "Fastly":     ["x-served-by", "x-fastly"],
    "F5 BIG-IP":  ["bigipserver"],
    "Barracuda":  ["barra_counter"],
}


def quick_waf_check(url, timeout=5):
    """Quick WAF detection before Nikto."""
    import urllib.request
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0",
            "Accept": "*/*",
        })
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            headers_str = " ".join(f"{k.lower()}: {v.lower()}" for k, v in r.headers.items())

        for waf_name, patterns in WAF_HEADERS.items():
            for pat in patterns:
                if pat in headers_str:
                    return waf_name
        return None
    except Exception:
        return None


# ============================================================
# Single target Nikto
# ============================================================

def run_nikto_bounty(target, port=443, ssl=True, timeout=120,
                     tuning=None, waf_skip=False, verbose=False):
    """Run Nikto with bounty-tuned options."""
    result = {
        "target": target,
        "port": port,
        "findings": [],
        "target_info": {},
        "waf": None,
        "skipped": False,
        "duration": 0,
        "error": None,
    }

    if not shutil.which("nikto"):
        result["error"] = "nikto not installed"
        return result

    url = f"{'https' if ssl else 'http'}://{target}:{port}"

    # WAF check
    if waf_skip:
        waf = quick_waf_check(url, timeout=5)
        if waf:
            result["waf"] = waf
            result["skipped"] = True
            result["error"] = f"WAF detected ({waf}) — skipped"
            return result

    # Build command — bounty tuning
    if not tuning:
        # Focus on high-value checks: SQLi, XSS, RCE, files, config
        tuning = "123b"  # Full + interesting files

    cmd = ["nikto", "-h", target, "-p", str(port),
           "-nointeractive", "-ask", "no", "-Tuning", tuning]
    if ssl:
        cmd.append("-ssl")

    # Rate limiting: Nikto has -Pause
    cmd.extend(["-Pause", "1"])  # 1 sec between tests (safer)

    # Max time per target
    cmd.extend(["-maxtime", "60s"])

    # Temp output
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    tmp_path = tmp.name
    tmp.close()
    cmd.extend(["-Format", "json", "-o", tmp_path])

    start = datetime.now()
    try:
        if verbose:
            print(f"    [>] {' '.join(cmd)}")

        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        result["duration"] = (datetime.now() - start).total_seconds()

        # Parse
        if os.path.exists(tmp_path):
            parsed = _parse_bounty_nikto(tmp_path)
            result["findings"] = parsed["findings"]
            result["target_info"] = parsed["target_info"]

    except subprocess.TimeoutExpired:
        result["error"] = f"timeout after {timeout}s"
        if os.path.exists(tmp_path):
            parsed = _parse_bounty_nikto(tmp_path)
            result["findings"] = parsed["findings"]
    except Exception as e:
        result["error"] = str(e)
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

    return result


def _parse_bounty_nikto(path):
    """Parse Nikto JSON with bounty classification."""
    findings = []
    target_info = {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read().strip()
    except Exception:
        return {"findings": [], "target_info": {}}

    if not content:
        return {"findings": [], "target_info": {}}

    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return {"findings": [], "target_info": {}}

    if isinstance(data, dict):
        if "target" in data and isinstance(data["target"], dict):
            target_info = data["target"]

    raw = data.get("findings") or data.get("alerts") or []

    # False positive filter
    fp_patterns = [
        r"no cgi", r"no end", r"starting nikto", r"target ip",
        r"target hostname", r"scan completed", r"retrieved from",
        r"^\+\s+\d+\s+item", r"nikto v\d", r"root page found",
    ]

    for item in raw:
        if not isinstance(item, dict):
            continue

        msg = (item.get("msg") or item.get("message") or "").strip()
        if not msg or len(msg) < 5:
            continue

        # Skip false positives
        if any(re.search(p, msg.lower()) for p in fp_patterns):
            continue

        url = item.get("url") or item.get("path") or ""
        osvdb = item.get("osvdb") or item.get("osvdb_id")

        # Extract CVEs
        cve_ids = list(item.get("cve") or [])
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        cve_ids += re.findall(r"CVE-\d{4}-\d{4,}", msg, re.IGNORECASE)
        cve_ids = list(dict.fromkeys(c.upper() for c in cve_ids))

        severity = classify_bounty_severity(msg)
        payout = PAYOUT_RANGES.get(severity, "?")

        # Confidence
        confidence = 0.75
        if url:
            confidence = 0.85
        if cve_ids or osvdb:
            confidence = 0.95

        findings.append({
            "title": msg[:200],
            "url": url,
            "severity": severity,
            "payout_potential": payout,
            "confidence": confidence,
            "cve": cve_ids,
            "osvdb": osvdb,
            "evidence": msg[:500],
            "source": "nikto",
        })

    return {"findings": findings, "target_info": target_info}


# ============================================================
# Multi-target parallel scan
# ============================================================

def scan_targets(targets, port=443, ssl=True, workers=3, timeout=120,
                 waf_skip=False, verbose=True):
    """
    Scan multiple targets in parallel (low workers for politeness).

    Args:
        targets: list of hosts/URLs
        workers: parallel scans (keep low — 3-5 for bug bounty)
    """
    if not shutil.which("nikto"):
        return {"available": False, "error": "nikto not installed", "findings": []}

    result = {
        "available": True,
        "started_at": datetime.now().isoformat(),
        "total_targets": len(targets),
        "scanned": 0,
        "skipped_waf": 0,
        "errors": 0,
        "findings": [],
        "target_results": [],
        "duration": 0,
    }

    start = datetime.now()

    def scan_one(target):
        t = target.replace("https://", "").replace("http://", "").rstrip("/")
        if ":" in t:
            t = t.split(":")[0]
        return run_nikto_bounty(t, port=port, ssl=ssl, timeout=timeout,
                                waf_skip=waf_skip, verbose=False)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scan_one, t): t for t in targets}

        for future in concurrent.futures.as_completed(futures):
            target = futures[future]
            try:
                r = future.result(timeout=timeout + 30)

                if r.get("skipped"):
                    result["skipped_waf"] += 1
                    if verbose:
                        print(f"  ⊘ {target} — WAF ({r.get('waf')})")
                elif r.get("error") and not r.get("findings"):
                    result["errors"] += 1
                    if verbose:
                        print(f"  ✗ {target} — {r['error']}")
                else:
                    result["scanned"] += 1
                    n = len(r.get("findings", []))
                    if verbose:
                        print(f"  ✓ {target} — {n} findings")

                    for f in r["findings"]:
                        f["target"] = target
                        result["findings"].append(f)

                result["target_results"].append({
                    "target": target,
                    "findings": len(r.get("findings", [])),
                    "waf": r.get("waf"),
                    "error": r.get("error"),
                })

            except Exception as e:
                result["errors"] += 1
                if verbose:
                    print(f"  ✗ {target} — {e}")

    result["duration"] = (datetime.now() - start).total_seconds()
    result["ended_at"] = datetime.now().isoformat()

    # Sort by severity + payout
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    result["findings"].sort(
        key=lambda x: (sev_order.get(x.get("severity", "info"), 99),
                       -x.get("confidence", 0))
    )

    return result


# ============================================================
# Report
# ============================================================

def print_bounty_nikto_report(result):
    print("\n" + "=" * 70)
    print("  Bug Bounty Nikto — ReconX")
    print("=" * 70)

    if not result.get("available"):
        print(f"\n[!] {result.get('error', 'Nikto not available')}")
        print(f"    Install: sudo apt install nikto")
        return

    print(f"\n[*] Targets:      {result.get('total_targets', 0)}")
    print(f"[*] Scanned:      {result.get('scanned', 0)}")
    print(f"[*] Skipped WAF:  {result.get('skipped_waf', 0)}")
    print(f"[*] Errors:       {result.get('errors', 0)}")
    print(f"[*] Duration:     {result.get('duration', 0):.1f}s")

    findings = result.get("findings", [])
    print(f"\n[*] Total findings: {len(findings)}")

    if findings:
        by_sev = {}
        for f in findings:
            s = f.get("severity", "info")
            by_sev[s] = by_sev.get(s, 0) + 1

        icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
        print(f"\n[*] By severity (payout potential):")
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in by_sev:
                payout = PAYOUT_RANGES.get(sev, "?")
                print(f"    {icons[sev]} {sev.capitalize():<10} {by_sev[sev]:<5} ({payout})")

        print(f"\n[+] Top findings (by payout potential):")
        seen = set()
        count = 0
        for f in findings:
            # Dedup by title+target
            key = (f.get("target"), f.get("title", "")[:50])
            if key in seen:
                continue
            seen.add(key)

            if count >= 20:
                break
            count += 1

            sev = f.get("severity", "info")
            icon = icons.get(sev, "⚪")
            target = f.get("target", "?")
            payout = f.get("payout_potential", "?")

            print(f"\n  {icon} [{sev.upper()}] {f.get('title', '?')[:70]}")
            print(f"       Target:   {target}")
            print(f"       URL:      {f.get('url', '?')[:80]}")
            print(f"       Payout:   {payout}")
            print(f"       Conf:     {f.get('confidence', 0):.2f}")
            if f.get("cve"):
                print(f"       CVEs:     {', '.join(f['cve'][:3])}")

    print("\n" + "=" * 70 + "\n")


def save_bounty_report(result, prefix="bounty_scan"):
    """Save bounty report to JSON."""
    p = Path("outputs")
    p.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fp = p / f"{prefix}_{ts}.json"

    with open(fp, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False, default=str)

    return fp


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python -m modules.vuln.bugbounty_nikto <target>")
        print("  python -m modules.vuln.bugbounty_nikto -f targets.txt")
        print("")
        print("Options:")
        print("  --waf-skip    Skip targets with WAF")
        print("  --workers N   Parallel workers (default 3)")
        print("  --port N      Port (default 443)")
        sys.exit(1)

    # Parse args
    if sys.argv[1] == "-f":
        target_file = sys.argv[2]
        with open(target_file) as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        print(f"\n[*] Loaded {len(targets)} targets from {target_file}")
    else:
        targets = [sys.argv[1]]

    waf_skip = "--waf-skip" in sys.argv
    workers = 3
    for i, arg in enumerate(sys.argv):
        if arg == "--workers" and i + 1 < len(sys.argv):
            workers = int(sys.argv[i + 1])
        if arg == "--port" and i + 1 < len(sys.argv):
            port = int(sys.argv[i + 1])
        else:
            port = 443

    print(f"\n[*] Bug Bounty Nikto: {len(targets)} targets")
    print(f"[*] WAF skip: {waf_skip}  |  Workers: {workers}  |  Port: {port}")

    result = scan_targets(targets, port=port, workers=workers,
                          waf_skip=waf_skip, verbose=True)

    print_bounty_nikto_report(result)

    out = save_bounty_report(result)
    print(f"✓ Saved: {out}\n")
