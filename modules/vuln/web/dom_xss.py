# modules/vuln/web/dom_xss.py
"""ReconX - DOM-based XSS scanner (headless browser + static taint heuristics).

Two layers:
  1. Static: fetch the page and its scripts, look for URL-controlled sources
     flowing into dangerous sinks inside the same script.
  2. Headless: if Playwright is installed, inject a marker payload into query
     parameters and the URL fragment, execute the SPA, and check whether the
     payload reached a JavaScript sink.

Playwright is optional (``pip install playwright && playwright install chromium``);
without it the module still performs static analysis.
"""

import importlib.util
import re
import urllib.parse

from modules.utils.http_client import (
    base_url, normalize_url, query_params, request, with_params,
)
from modules.vuln.advanced.base import add_finding, finalize, finding, new_result, print_report

SOURCES = re.compile(
    r"(?i)(location\.(?:hash|search|href|pathname)|document\.(?:URL|documentURI|referrer)|"
    r"window\.name|URLSearchParams|document\.cookie)"
)
SINKS = re.compile(
    r"(?i)(\.innerHTML\s*=|\.outerHTML\s*=|document\.write(?:ln)?\s*\(|"
    r"insertAdjacentHTML\s*\(|eval\s*\(|setTimeout\s*\(\s*[\"']|setInterval\s*\(\s*[\"']|"
    r"\.html\s*\(|dangerouslySetInnerHTML|v-html|srcdoc\s*=)"
)
FRAMEWORKS = {
    "jQuery .html()": re.compile(r"\.html\s*\("),
    "React dangerouslySetInnerHTML": re.compile(r"dangerouslySetInnerHTML"),
    "Vue v-html": re.compile(r"v-html"),
    "Angular bypassSecurityTrustHtml": re.compile(r"bypassSecurityTrustHtml"),
}

MARKER_PARAM = "reconx_dom"
MARKER_SCRIPT = (
    '<img src=x onerror="window.__reconx_dom_xss=1" '
    'data-reconx="dom-xss">'
)
HASH_PAYLOAD = '<img src=x onerror="window.__reconx_dom_xss=1">'


def _scripts(base, html, timeout):
    """Inline + same-origin external script bodies."""
    blocks = re.findall(r"(?is)<script\b[^>]*>(.*?)</script>", html or "")
    srcs = re.findall(r"""(?is)<script\b[^>]*\bsrc=["']([^"']+)["']""", html or "")
    out = [("inline", b) for b in blocks if b.strip()]
    for src in srcs[:6]:
        if not src.lower().startswith(("http://", "https://", "/")):
            continue
        url = urllib.parse.urljoin(base, src)
        if urllib.parse.urlparse(url).netloc != urllib.parse.urlparse(base).netloc:
            continue
        resp = request(url, timeout=timeout)
        if not resp.error:
            out.append((url, resp.body))
    return out


def _static_findings(base, html, timeout, result, verbose):
    for origin, code in _scripts(base, html, timeout):
        if not code or len(code) < 20:
            continue
        source_hit = SOURCES.search(code)
        sink_hit = SINKS.search(code)
        if not (source_hit and sink_hit):
            continue
        snippet_start = max(0, min(source_hit.start(), sink_hit.start()) - 40)
        snippet = re.sub(r"\s+", " ", code[snippet_start:snippet_start + 180])
        add_finding(result, finding(
            "dom_xss_static_flow",
            "Potential DOM XSS: URL source flows into a dangerous sink",
            "medium",
            base,
            f"source={source_hit.group(1)}, sink={sink_hit.group(1)}; {snippet}",
            description=("Static analysis found JavaScript reading a URL-controlled value and "
                         "writing it into an HTML/JS sink. This is a candidate, not a proof; "
                         "confirm in the headless browser."),
            remediation="Use textContent/setAttribute or sanitize with DOMPurify before sinks.",
            confidence=0.55,
            bug_class="dom_xss",
            script=origin,
            source="dom_xss",
        ))
        if verbose:
            print(f"    [?] Static DOM XSS candidate in {origin}")


def _browser_available():
    return importlib.util.find_spec("playwright") is not None


def _browser_findings(target, timeout, result, verbose):
    """Return True when browser testing actually ran."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        result["browser"] = "unavailable"
        result["note"] = ("Playwright is not installed. Static analysis only. "
                          "Install: pip install playwright && playwright install chromium")
        return False

    params = query_params(target) or ["q"]
    attempts = []
    for param in params[:4]:
        attempts.append(("query", param, with_params(target, {param: MARKER_SCRIPT})))
    attempts.append(("hash", "fragment", target.split("#", 1)[0] + "#" + HASH_PAYLOAD))

    confirmed = None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            page.add_init_script(
                "window.__reconx_dom_xss = 0;"
                "(function(){var a=window.alert;window.alert=function(){"
                "window.__reconx_dom_xss=1;return a&&a.apply(window,arguments);};})();"
            )
            dialogs = []
            page.on("dialog", lambda d: (dialogs.append(d.message or ""), d.dismiss()))

            for kind, name, url in attempts:
                page.goto(url, wait_until="domcontentloaded", timeout=timeout * 1000)
                try:
                    page.wait_for_timeout(1200)
                except Exception:
                    pass
                fired = page.evaluate("window.__reconx_dom_xss || 0")
                if fired or dialogs:
                    confirmed = (kind, name, url, "alert hooked" if fired else "dialog fired")
                    break

            browser.close()
    except Exception as e:
        result["browser"] = "error"
        result["errors"].append(f"playwright: {str(e)[:160]}")
        return False

    result["browser"] = "ran"
    if confirmed:
        kind, name, url, how = confirmed
        add_finding(result, finding(
            "dom_xss_confirmed",
            f"DOM-based XSS confirmed via {kind} ({name})",
            "high",
            url,
            f"Payload executed in headless Chromium ({how})",
            description=("JavaScript executed the injected payload without a server-side "
                         "reflection, confirming a DOM XSS sink reachable from the URL."),
            remediation=("Context-aware output encoding; avoid innerHTML/eval with URL data; "
                         "add a strict CSP."),
            confidence=0.95,
            bug_class="dom_xss",
            parameter=name,
            source="dom_xss",
        ))
        if verbose:
            print(f"    [!] DOM XSS confirmed via {kind} ({name})")
    return True


def scan(target, timeout=20, use_browser=None, verbose=False):
    target = normalize_url(target)
    result = new_result(target, browser="skipped")
    result["checks_run"].append("static_dom_analysis")

    resp = request(target, timeout=min(timeout, 15))
    if resp.error:
        result["errors"].append(f"target unreachable: {resp.error}")
        return finalize(result)

    _static_findings(base_url(target), resp.body, timeout, result, verbose)

    # Detect obvious dangerous libraries in use.
    for name, pattern in FRAMEWORKS.items():
        if pattern.search(resp.body or ""):
            result.setdefault("frameworks", []).append(name)

    should_browse = use_browser
    if should_browse is None:
        should_browse = _browser_available()
    if should_browse:
        result["checks_run"].append("headless_browser")
        try:
            _browser_findings(target, timeout, result, verbose)
        except Exception as e:
            result["errors"].append(f"browser: {e}")
    else:
        result["note"] = result.get("note") or (
            "Headless browser not requested; DOM XSS was assessed statically only")

    if not result["findings"]:
        result["note"] = result.get("note") or (
            "No DOM XSS indicator found. SPAs with hash routing deserve a manual review.")
    return finalize(result)


run_scanner = scan


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m modules.vuln.web.dom_xss <url> [--no-browser]")
        sys.exit(1)
    res = scan(sys.argv[1], use_browser=("--no-browser" not in sys.argv), verbose=True)
    print_report(res, "DOM XSS")
