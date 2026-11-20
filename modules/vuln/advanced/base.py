# modules/vuln/advanced/base.py
"""ReconX - Shared helpers for the advanced scanner package."""

import concurrent.futures
import json
from datetime import datetime

# Conservative default for per-target request concurrency. Keep it small: these
# scanners fire active payloads at a single host, so a modest pool amortises the
# per-request handshake latency without turning a scan into a burst a WAF/IDS
# would ban.
DEFAULT_WORKERS = 5

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_ICONS = {
    "critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪",
}

# Rough bug-bounty ranges used by the rest of the suite.
PAYOUTS = {
    "critical": "$1000-$10000+",
    "high": "$500-$5000",
    "medium": "$150-$1500",
    "low": "$50-$500",
    "info": "n/a",
}


def parallel_map(items, fn, workers=DEFAULT_WORKERS):
    """Run ``fn(item)`` over ``items`` on a bounded pool, keeping input order.

    Returns a list aligned 1:1 with ``items`` (``results[i]`` is ``fn(items[i])``).
    Order-preserving so callers can replay results deterministically (pick the
    first finding in iteration order, keep "first N" semantics, etc.) even though
    the work ran concurrently. An item whose ``fn`` raises yields ``None`` in its
    slot, matching the "skip this probe and continue" behaviour of the serial
    loops these scanners used before.
    """
    items = list(items)
    if not items:
        return []
    count = max(1, min(int(workers or 1), len(items)))
    results = [None] * len(items)
    with concurrent.futures.ThreadPoolExecutor(max_workers=count) as ex:
        future_index = {ex.submit(fn, item): i for i, item in enumerate(items)}
        for future in concurrent.futures.as_completed(future_index):
            idx = future_index[future]
            try:
                results[idx] = future.result()
            except Exception:
                results[idx] = None
    return results


def new_result(target, **extra):
    result = {
        "timestamp": datetime.now().isoformat(),
        "target": target,
        "findings": [],
        "checks_run": [],
        "errors": [],
    }
    result.update(extra)
    return result


def finding(fid, title, severity, url, evidence, description="", remediation="",
            confidence=0.7, bug_class="", payout=None, source="advanced", **extra):
    item = {
        "id": fid,
        "title": title,
        "severity": severity,
        "bug_class": bug_class or fid,
        "payout_potential": payout if payout is not None else PAYOUTS.get(severity, "n/a"),
        "confidence": round(float(confidence), 2),
        "url": url,
        "evidence": str(evidence)[:500],
        "description": description,
        "remediation": remediation,
        "source": source,
    }
    item.update(extra)
    return item


def add_finding(result, item):
    if item:
        result.setdefault("findings", []).append(item)
    return item


def finalize(result):
    """Deduplicate by (title, url, parameter) and sort by severity/confidence."""
    seen, unique = set(), []
    for f in result.get("findings", []):
        key = (f.get("title", "")[:100], f.get("url", ""), f.get("parameter", ""))
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)

    unique.sort(key=lambda x: (SEVERITY_ORDER.get(x.get("severity", "info"), 99),
                               -x.get("confidence", 0)))
    result["findings"] = unique
    result["total_findings"] = len(unique)
    return result


def print_report(result, title="Advanced Scanner"):
    """Unified report printer for every advanced module."""
    print("\n" + "=" * 72)
    print(f"  {title} — ReconX")
    print("=" * 72)

    print(f"\n[*] Target:   {result.get('target')}")
    checks = result.get("checks_run", [])
    if checks:
        print(f"[*] Checks:   {', '.join(checks)}")
    if result.get("endpoint"):
        print(f"[*] Endpoint: {result['endpoint']}")
    print(f"[*] Findings: {len(result.get('findings', []))}")

    for extra_key, label in (("discovered_specs", "API specs"),
                             ("tested", "Requests"),
                             ("note", "Note")):
        value = result.get(extra_key)
        if value:
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value[:8])
            print(f"[*] {label + ':':<10} {value}")

    if result.get("errors"):
        print(f"\n[!] Errors ({len(result['errors'])}):")
        for err in result["errors"][:10]:
            print(f"    ✗ {str(err)[:100]}")

    findings = result.get("findings", [])
    if not findings:
        print("\n[OK] No findings")
    else:
        for f in findings:
            sev = f.get("severity", "info")
            icon = SEVERITY_ICONS.get(sev, "⚪")
            print(f"\n  {icon} [{sev.upper():<8}] {f.get('title', '?')}")
            print(f"       Bug class:  {f.get('bug_class', '?')}")
            print(f"       Confidence: {f.get('confidence', 0):.2f}")
            print(f"       URL:        {str(f.get('url', '?'))[:100]}")
            if f.get("parameter"):
                print(f"       Parameter:  {f['parameter']}")
            if f.get("evidence"):
                print(f"       Evidence:   {str(f['evidence'])[:160]}")
            if f.get("remediation"):
                print(f"       Fix:        {str(f['remediation'])[:120]}")

    print("\n" + "=" * 72 + "\n")
    return result


def save_report(result, prefix):
    """Write a JSON report into ./outputs and return the path."""
    from pathlib import Path

    outputs = Path(__file__).resolve().parents[3] / "outputs"
    outputs.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = outputs / f"{prefix}_{ts}.json"
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False, default=str)
    return path
