# modules/vuln/web/xss_scanner.py
"""ReconX - XSS Scanner (dalfox + custom reflection)."""

import shutil
import logging
import subprocess
import re
import ssl
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime

logger = logging.getLogger("ReconX.xss")


def is_dalfox_available():
    return shutil.which("dalfox") is not None


# Custom XSS payloads for reflection testing
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    'javascript:alert(1)',
]


def _make_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _fetch(url, timeout=10):
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0",
        })
        with urllib.request.urlopen(req, timeout=timeout, context=_make_ctx()) as r:
            return r.status, r.read(100000).decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(50000).decode("utf-8", errors="ignore")
        except Exception:
            return e.code, ""
    except Exception:
        return None, None


def reflection_test(url, params=None, timeout=10, verbose=False):
    """Custom XSS reflection test (no dalfox needed)."""
    findings = []

    parsed = urllib.parse.urlparse(url)
    if params is None:
        params = list(urllib.parse.parse_qs(parsed.query).keys())

    if not params:
        return findings

    for param in params:
        for payload in XSS_PAYLOADS[:4]:
            qs = urllib.parse.parse_qs(parsed.query)
            qs[param] = [payload]
            test_url = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(qs, doseq=True))
            )

            status, body = _fetch(test_url, timeout=timeout)

            if status is None or not body:
                continue

            # Check if payload reflected UNESCAPED
            if payload in body:
                # Context detection
                context = "html_body"
                if f'value="{payload}"' in body or f"value='{payload}'" in body:
                    context = "html_attribute"
                elif f"<script>{payload}" in body or f"{payload}</script>" in body:
                    context = "script_tag"

                findings.append({
                    "id": f"xss_{param}",
                    "title": f"Reflected XSS in '{param}' parameter",
                    "parameter": param,
                    "context": context,
                    "severity": "high",
                    "bug_class": "reflected_xss",
                    "payout_potential": "$300-$2000",
                    "confidence": 0.85,
                    "url": test_url,
                    "payload": payload,
                    "evidence": f"Payload reflected unescaped in {context}",
                    "source": "custom_xss",
                })
                break  # One finding per param

    return findings


def run_dalfox(target, timeout=300, verbose=False):
    """Run dalfox XSS scanner."""
    findings = []

    if not is_dalfox_available():
        return findings, "dalfox not installed"

    cmd = ["dalfox", "url", target, "--no-color", "--silence", "--skip-bav"]

    try:
        if verbose:
            print(f"    [>] {' '.join(cmd)}")

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = proc.stdout + proc.stderr

        for line in output.splitlines():
            if "[VULN]" in line or "XSS" in line.upper():
                findings.append({
                    "id": "xss_dalfox",
                    "title": "XSS vulnerability confirmed by dalfox",
                    "severity": "high",
                    "bug_class": "xss",
                    "payout_potential": "$300-$2000",
                    "confidence": 0.92,
                    "url": target,
                    "evidence": line.strip()[:200],
                    "source": "dalfox",
                })
    except Exception as e:
        return findings, str(e)

    return findings, None


def scan(target, use_dalfox=True, use_custom=True, timeout=300, verbose=False):
    """Full XSS scan."""
    result = {
        "timestamp": datetime.now().isoformat(),
        "target": target,
        "dalfox_available": is_dalfox_available(),
        "findings": [],
        "error": None,
    }

    # Custom reflection test first (fast)
    if use_custom:
        if verbose:
            print(f"  [*] Custom reflection test...")
        try:
            findings = reflection_test(target, verbose=verbose)
            result["findings"].extend(findings)
        except Exception as e:
            result["error"] = str(e)

    # dalfox (if available)
    if use_dalfox and is_dalfox_available():
        if verbose:
            print(f"  [*] dalfox scan...")
        findings, err = run_dalfox(target, timeout=timeout, verbose=verbose)
        result["findings"].extend(findings)
        if err and not result["error"]:
            result["error"] = err

    # Dedupe by param
    seen = set()
    unique = []
    for f in result["findings"]:
        key = (f.get("parameter"), f.get("url"))
        if key not in seen:
            seen.add(key)
            unique.append(f)

    result["findings"] = unique
    return result


def print_report(result):
    print("\n" + "=" * 70)
    print("  XSS Scanner — ReconX")
    print("=" * 70)

    print(f"\n[*] Target:  {result.get('target')}")
    print(f"[*] dalfox:  {'✓ installed' if result.get('dalfox_available') else '✗ not installed'}")
    print(f"[*] Findings: {len(result.get('findings', []))}")

    if result.get("findings"):
        for f in result["findings"]:
            print(f"\n  🟠 [{f.get('severity', 'high').upper()}] {f['title']}")
            if f.get("parameter"):
                print(f"       Parameter: {f['parameter']}")
            if f.get("context"):
                print(f"       Context:   {f['context']}")
            if f.get("payload"):
                print(f"       Payload:   {f['payload']}")
            print(f"       URL:       {f.get('url', '?')}")
            print(f"       Payout:    {f.get('payout_potential', '?')}")
            print(f"       Source:    {f.get('source', '?')}")
    else:
        print(f"\n[OK] No XSS found")

    if result.get("error"):
        print(f"\n[!] {result['error']}")

    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) < 2:
        print("Usage: python -m modules.vuln.web.xss_scanner <url-with-params>")
        print("Example: python -m modules.vuln.web.xss_scanner 'http://testphp.vulnweb.com/search.php?test=1'")
        sys.exit(1)

    url = sys.argv[1]
    print(f"\n[*] XSS scan: {url}")

    result = scan(url, verbose=True)
    print_report(result)
