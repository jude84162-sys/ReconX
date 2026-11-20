# modules/vuln/web/ssti_scanner.py
"""ReconX - SSTI Scanner (Server-Side Template Injection)."""

import ssl
import logging
import concurrent.futures
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime

logger = logging.getLogger("ReconX.ssti")


# SSTI payloads per template engine
# Format: (payload, expected_math_result, engine_name)
SSTI_PAYLOADS = [
    # Jinja2 / Twig (Python / PHP)
    ("{{7*7}}", "49", "Jinja2/Twig"),
    ("{{7*'7'}}", "7777777", "Jinja2 (string mult)"),
    ("{{7*7}}", "49", "Nunjucks"),

    # Freemarker (Java)
    ("${7*7}", "49", "Freemarker"),

    # Spring EL (Java)
    ("${7*7}", "49", "Spring EL"),
    ("#{7*7}", "49", "Spring EL (alt)"),

    # ERB (Ruby)
    ("<%= 7*7 %>", "49", "ERB"),
    ("#{7*7}", "49", "Ruby string interp"),

    # Handlebars / Mustache (JS)
    ("{{#with 7 as |x|}}{{x}}{{/with}}", "7", "Handlebars"),
    ("${{7*7}}", "49", "Handlebars"),

    # Razor (.NET)
    ("@{7*7}", "49", "Razor"),
    ("@(7*7)", "49", "Razor (alt)"),

    # Velocity (Java)
    ("#set($x=7*7)$x", "49", "Velocity"),

    # Smarty (PHP)
    ("{7*7}", "49", "Smarty"),
    ("{math equation='7*7'}", "49", "Smarty (math)"),

    # Mako (Python)
    ("${7*7}", "49", "Mako"),
]


# Common injectable parameters
COMMON_PARAMS = [
    "name", "q", "search", "query", "message", "text", "title",
    "content", "template", "page", "view", "action", "cmd",
    "url", "file", "path", "input", "data", "value", "param",
]


def _make_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# One shared SSL context, reused across all requests (and threads) instead of
# rebuilding one per fetch.
_SSL_CTX = _make_ctx()


def _fetch(url, timeout=10):
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0",
        })
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as r:
            return r.status, r.read(100000).decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(50000).decode("utf-8", errors="ignore")
        except Exception:
            return e.code, ""
    except Exception:
        return None, None


def _build_url(base_url, param, payload):
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query)
    qs[param] = [payload]
    return urllib.parse.urlunparse(
        parsed._replace(query=urllib.parse.urlencode(qs, doseq=True))
    )


def _baseline(url, param, timeout=10):
    """Get baseline response (param with benign value)."""
    test_url = _build_url(url, param, "test123")
    status, body = _fetch(test_url, timeout=timeout)
    return status, body or ""


def test_ssti(url, param, timeout=10, verbose=False):
    """Test SSTI on one parameter."""
    findings = []

    # Get baseline first
    base_status, base_body = _baseline(url, param, timeout=timeout)

    for payload, expected, engine in SSTI_PAYLOADS:
        test_url = _build_url(url, param, payload)

        status, body = _fetch(test_url, timeout=timeout)

        if status is None or not body:
            continue

        # Detection: expected result appears + payload doesn't appear raw
        # (If payload appears raw, it's just reflection, not evaluation)
        if expected in body and payload not in body:
            # Extra validation: baseline didn't have this
            if expected not in base_body:
                findings.append({
                    "id": f"ssti_{param}_{engine.replace(' ', '_').lower()}",
                    "title": f"SSTI in '{param}' ({engine})",
                    "parameter": param,
                    "engine": engine,
                    "payload": payload,
                    "expected_result": expected,
                    "severity": "critical",
                    "bug_class": "ssti",
                    "payout_potential": "$1000-$10000+",
                    "confidence": 0.90,
                    "url": test_url,
                    "evidence": f"Payload '{payload}' evaluated to '{expected}'",
                    "source": "custom_ssti",
                })
                break  # One engine per param is enough

    return findings


def _test_payload(url, param, payload, expected, engine, base_body, timeout=10):
    """Test a single SSTI payload against a param given its baseline body."""
    test_url = _build_url(url, param, payload)
    status, body = _fetch(test_url, timeout=timeout)

    if status is None or not body:
        return None

    # Detection: expected result appears + payload doesn't appear raw
    # (If payload appears raw, it's just reflection, not evaluation)
    if expected in body and payload not in body:
        # Extra validation: baseline didn't have this
        if expected not in base_body:
            return {
                "id": f"ssti_{param}_{engine.replace(' ', '_').lower()}",
                "title": f"SSTI in '{param}' ({engine})",
                "parameter": param,
                "engine": engine,
                "payload": payload,
                "expected_result": expected,
                "severity": "critical",
                "bug_class": "ssti",
                "payout_potential": "$1000-$10000+",
                "confidence": 0.90,
                "url": test_url,
                "evidence": f"Payload '{payload}' evaluated to '{expected}'",
                "source": "custom_ssti",
            }
    return None


def scan(target, params=None, timeout=10, verbose=False, workers=5):
    """Full SSTI scan.

    Per-param baselines and the (param x payload) matrix are probed through a
    small ThreadPoolExecutor (``workers`` kwarg, default 5). Output is
    preserved: at most one finding per param, selected from the lowest-indexed
    matching payload (the same engine the original break-on-first loop
    reported), returned in param order.
    """
    result = {
        "timestamp": datetime.now().isoformat(),
        "target": target,
        "findings": [],
        "tested_params": 0,
        "tested_payloads": 0,
        "error": None,
    }

    parsed = urllib.parse.urlparse(target)
    if params is None:
        existing = list(urllib.parse.parse_qs(parsed.query).keys())
        params = existing if existing else COMMON_PARAMS[:8]

    if not params:
        result["error"] = "no parameters"
        return result

    result["tested_params"] = len(params)
    result["tested_payloads"] = len(params) * len(SSTI_PAYLOADS)

    if verbose:
        for param in params:
            print(f"    [*] Testing param: {param}")

    w = max(1, int(workers) if workers else 1)

    # Phase 1: per-param baselines (parallel).
    baselines = {}
    bw = max(1, min(w, len(params)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=bw) as ex:
        futs = {ex.submit(_baseline, target, param, timeout=timeout): param
                for param in params}
        for fut in concurrent.futures.as_completed(futs):
            param = futs[fut]
            try:
                _, base_body = fut.result()
            except Exception:
                base_body = ""
            baselines[param] = base_body or ""

    # Phase 2: (param, payload) evaluation (parallel).
    tasks = []
    for pi, param in enumerate(params):
        for yi, (payload, expected, engine) in enumerate(SSTI_PAYLOADS):
            tasks.append((pi, param, yi, payload, expected, engine))

    best = {}  # param index -> (payload index, finding)
    tw = max(1, min(w, len(tasks)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=tw) as ex:
        futs = {
            ex.submit(_test_payload, target, param, payload, expected, engine,
                      baselines.get(param, ""), timeout): (pi, yi)
            for (pi, param, yi, payload, expected, engine) in tasks
        }
        for fut in concurrent.futures.as_completed(futs):
            pi, yi = futs[fut]
            try:
                finding = fut.result()
            except Exception:
                finding = None
            if finding:
                cur = best.get(pi)
                if cur is None or yi < cur[0]:
                    best[pi] = (yi, finding)

    for pi in range(len(params)):
        if pi in best:
            result["findings"].append(best[pi][1])

    return result


def print_report(result):
    print("\n" + "=" * 70)
    print("  SSTI Scanner — ReconX")
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
            print(f"       Engine:    {f['engine']}")
            print(f"       Payload:   {f['payload']}")
            print(f"       Result:    {f['expected_result']}")
            print(f"       Evidence:  {f['evidence']}")
            print(f"       Payout:    {f.get('payout_potential', '?')}")
    else:
        print(f"\n[OK] No SSTI found")

    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) < 2:
        print("Usage: python -m modules.vuln.web.ssti_scanner <url-with-params>")
        print("Example: python -m modules.vuln.web.ssti_scanner 'https://example.com/?name=test'")
        sys.exit(1)

    url = sys.argv[1]
    print(f"\n[*] SSTI scan: {url}")

    result = scan(url, verbose=True)
    print_report(result)
