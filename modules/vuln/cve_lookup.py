# modules/vuln/cve_lookup.py
"""ReconX - CVE Lookup via NVD API (no key required)."""

import re
import json
import time
import ssl
import logging
import urllib.request
import urllib.error
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger("ReconX.cve")

# ============================================================
# Cache
# ============================================================

CACHE_DIR = Path.home() / ".reconx" / "cve_cache"
CACHE_TTL_DAYS = 30


def _cache_path(cve_id):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR / f"{cve_id}.json"


def _load_cache(cve_id):
    p = _cache_path(cve_id)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text())
        cached_at = datetime.fromisoformat(data.get("_cached_at", ""))
        if datetime.now() - cached_at > timedelta(days=CACHE_TTL_DAYS):
            return None
        return data
    except Exception:
        return None


def _save_cache(cve_id, data):
    try:
        data["_cached_at"] = datetime.now().isoformat()
        _cache_path(cve_id).write_text(json.dumps(data, indent=2))
    except Exception:
        pass


# ============================================================
# NVD API
# ============================================================

def _fetch_nvd(cve_id, timeout=15):
    """Fetch CVE from NVD API 2.0."""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(url, headers={
            "User-Agent": "ReconX-CVE/1.0",
            "Accept": "application/json",
        })
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            data = json.loads(r.read())
        return data
    except Exception as e:
        logger.debug(f"NVD fetch {cve_id} failed: {e}")
        return None


def lookup_cve(cve_id, use_cache=True):
    """Look up a single CVE by ID."""
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id, re.IGNORECASE):
        return None

    cve_id = cve_id.upper()

    if use_cache:
        cached = _load_cache(cve_id)
        if cached:
            return cached

    data = _fetch_nvd(cve_id)
    if not data:
        return None

    try:
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None

        cve = vulns[0].get("cve", {})
        metrics = cve.get("metrics", {})

        # Extract CVSS score (prefer v3.1 > v3.0 > v2)
        cvss_score = None
        cvss_severity = None
        cvss_vector = None

        for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version_key in metrics and metrics[version_key]:
                m = metrics[version_key][0]
                cvss_data = m.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString")
                cvss_severity = (
                    cvss_data.get("baseSeverity") or m.get("baseSeverity")
                )
                break

        # Description (English)
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        # References
        refs = [r.get("url") for r in cve.get("references", [])[:5] if r.get("url")]

        result = {
            "id": cve_id,
            "description": desc,
            "published": cve.get("published"),
            "modified": cve.get("lastModified"),
            "cvss_score": cvss_score,
            "cvss_severity": (cvss_severity or "").lower() or None,
            "cvss_vector": cvss_vector,
            "references": refs,
        }

        if use_cache:
            _save_cache(cve_id, result)

        return result
    except Exception as e:
        logger.debug(f"CVE parse {cve_id} failed: {e}")
        return None


def lookup_multiple(cve_ids, delay=6.0, max_cves=10):
    """
    Look up multiple CVEs with rate limiting.
    NVD public API: 5 requests / 30s without key → 6s delay is safe.
    """
    results = []
    for i, cve_id in enumerate(cve_ids[:max_cves]):
        r = lookup_cve(cve_id)
        if r:
            results.append(r)
        if i < len(cve_ids) - 1:
            time.sleep(delay)
    return results


def extract_cves_from_text(text):
    """Extract all CVE IDs from text."""
    if not text:
        return []
    matches = re.findall(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE)
    return list(dict.fromkeys(c.upper() for c in matches))


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) < 2:
        print("Usage: python -m modules.vuln.cve_lookup CVE-2021-44228")
        sys.exit(1)

    cve_id = sys.argv[1]
    print(f"\n[*] Looking up {cve_id}...")

    result = lookup_cve(cve_id)
    if not result:
        print(f"✗ Not found")
        sys.exit(1)

    print(f"\n{'=' * 60}")
    print(f"  {result['id']}")
    print(f"{'=' * 60}")
    print(f"\n[*] CVSS Score:    {result.get('cvss_score', 'N/A')}")
    print(f"[*] Severity:      {result.get('cvss_severity', 'N/A')}")
    print(f"[*] Published:     {result.get('published', 'N/A')}")
    print(f"\n[*] Description:")
    print(f"    {result.get('description', 'N/A')[:500]}")

    if result.get("references"):
        print(f"\n[*] References:")
        for ref in result["references"][:5]:
            print(f"    • {ref}")

    print()
