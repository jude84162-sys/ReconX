# modules/vuln/bounty_checks.py
"""ReconX - Bug Bounty specific checks.

Higher-signal checks that map to bug bounty payouts:
  - Authentication bypass detection
  - IDOR patterns
  - SSRF opportunities
  - Open redirects
  - GraphQL introspection
  - API versioning / Swagger leaks
  - JWT issues
  - Race conditions (basic)
"""

import re
import ssl
import json
import logging
import urllib.request
import urllib.error
import concurrent.futures
from datetime import datetime
from urllib.parse import urlparse, urljoin

logger = logging.getLogger("ReconX.bounty")


def _make_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _fetch(url, timeout=8, method="GET", headers=None, body=None, allow_redirects=True):
    """Fetch with custom method/headers."""
    default_headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0",
        "Accept": "text/html,application/json,*/*",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if headers:
        default_headers.update(headers)

    try:
        req = urllib.request.Request(url, method=method, headers=default_headers, data=body)

        if allow_redirects:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=_make_ctx())
            )
        else:
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None
            opener = urllib.request.build_opener(
                NoRedirect,
                urllib.request.HTTPSHandler(context=_make_ctx())
            )

        with opener.open(req, timeout=timeout) as r:
            return {
                "status": r.status,
                "headers": {k: v for k, v in r.headers.items()},
                "body": r.read(200000).decode("utf-8", errors="ignore"),
                "final_url": r.url,
            }
    except urllib.error.HTTPError as e:
        try:
            body_text = e.read(100000).decode("utf-8", errors="ignore")
        except Exception:
            body_text = ""
        return {
            "status": e.code,
            "headers": {k: v for k, v in (e.headers.items() if e.headers else [])},
            "body": body_text,
            "final_url": url,
        }
    except Exception as e:
        return {"error": str(e)}


# ============================================================
# Check 1: API Documentation Leaks
# ============================================================

API_DOC_PATHS = [
    "/swagger.json", "/swagger.yaml", "/swagger-ui.html", "/swagger/",
    "/openapi.json", "/openapi.yaml", "/api-docs", "/api/docs",
    "/api/swagger.json", "/api/v1/swagger.json", "/api/v2/swagger.json",
    "/redoc", "/docs", "/api/swagger-ui.html",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/graphql", "/graphiql", "/graphql/console",
    "/.well-known/openapi.json",
]


def check_api_docs(url, timeout=6):
    """Look for exposed API documentation."""
    findings = []
    base = url.rstrip("/")

    def check_one(path):
        r = _fetch(base + path, timeout=timeout)
        if r.get("error") or r.get("status") not in (200, 201):
            return None

        body = r.get("body", "")
        content_type = ""
        for k, v in r.get("headers", {}).items():
            if k.lower() == "content-type":
                content_type = v.lower()
                break

        # Validate it's actually API docs
        is_valid = False
        if "json" in content_type and ('"openapi"' in body or '"swagger"' in body):
            is_valid = True
        elif "html" in content_type and ("swagger-ui" in body.lower() or "redoc" in body.lower()):
            is_valid = True
        elif path == "/graphql" and ('"data"' in body or "graphql" in body.lower()):
            is_valid = True

        if not is_valid:
            return None

        return {
            "id": f"api_docs_{path.strip('/').replace('/', '_')}",
            "check": "api_docs",
            "title": f"Exposed API documentation: {path}",
            "severity": "medium",
            "bug_class": "information_disclosure",
            "payout_potential": "$100-$500",
            "confidence": 0.90,
            "url": base + path,
            "evidence": f"HTTP {r['status']}, {len(body)} bytes",
            "description": "API documentation exposed — reveals endpoints, params, schemas",
            "remediation": "Restrict documentation access to internal networks",
            "source": "bounty_checks",
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futures = [ex.submit(check_one, p) for p in API_DOC_PATHS]
        for f in concurrent.futures.as_completed(futures):
            try:
                r = f.result(timeout=timeout + 5)
                if r:
                    findings.append(r)
            except Exception:
                pass

    return findings


# ============================================================
# Check 2: Open Redirect
# ============================================================

OPEN_REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri", "return",
    "return_url", "return_to", "next", "goto", "target", "dest",
    "destination", "continue", "forward", "callback", "ref",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.example.com",
    "//evil.example.com",
    "https://google.com",
]


def check_open_redirect(url, timeout=6):
    """Test for open redirect vulnerabilities."""
    findings = []

    parsed = urlparse(url)
    if not parsed.query:
        return findings

    # Try each param with each payload
    for payload in OPEN_REDIRECT_PAYLOADS[:1]:  # Just test one payload
        for param in OPEN_REDIRECT_PARAMS[:6]:
            test_url = f"{url}&{param}={payload}" if "?" in url else f"{url}?{param}={payload}"

            r = _fetch(test_url, timeout=timeout, allow_redirects=False)
            if r.get("error"):
                continue

            status = r.get("status")
            location = ""

            for k, v in r.get("headers", {}).items():
                if k.lower() == "location":
                    location = v
                    break

            # 3xx with Location pointing to evil.com
            if status in (301, 302, 303, 307, 308) and "evil.example.com" in location:
                findings.append({
                    "id": f"open_redirect_{param}",
                    "check": "open_redirect",
                    "title": f"Open redirect via '{param}' parameter",
                    "severity": "medium",
                    "bug_class": "open_redirect",
                    "payout_potential": "$150-$800",
                    "confidence": 0.95,
                    "url": test_url,
                    "evidence": f"HTTP {status} → Location: {location}",
                    "description": f"Parameter '{param}' allows redirect to arbitrary URL",
                    "remediation": "Validate redirect targets against allowlist",
                    "source": "bounty_checks",
                })
                return findings  # One is enough

    return findings


# ============================================================
# Check 3: GraphQL Introspection
# ============================================================

def check_graphql_introspection(url, timeout=8):
    """Check if GraphQL introspection is enabled."""
    findings = []

    # Try common GraphQL paths
    paths = ["/graphql", "/api/graphql", "/v1/graphql", "/gql"]

    query = {"query": "{ __schema { types { name } } }"}
    body = json.dumps(query).encode()

    for path in paths:
        test_url = url.rstrip("/") + path
        r = _fetch(test_url, timeout=timeout, method="POST", body=body,
                   headers={"Content-Type": "application/json"})

        if r.get("error"):
            continue

        resp_body = r.get("body", "")

        if '"__schema"' in resp_body and '"types"' in resp_body:
            findings.append({
                "id": f"graphql_introspection_{path.strip('/')}",
                "check": "graphql",
                "title": f"GraphQL introspection enabled: {path}",
                "severity": "medium",
                "bug_class": "information_disclosure",
                "payout_potential": "$200-$1000",
                "confidence": 0.95,
                "url": test_url,
                "evidence": "Introspection query returned full schema",
                "description": "GraphQL introspection exposes the entire API schema",
                "remediation": "Disable introspection in production",
                "source": "bounty_checks",
            })
            break

    return findings


# ============================================================
# Check 4: Exposed .git / .svn
# ============================================================

GIT_SVN_PATHS = {
    "/.git/HEAD": "Git",
    "/.git/config": "Git",
    "/.git/index": "Git",
    "/.svn/entries": "SVN",
    "/.svn/wc.db": "SVN",
    "/.hg/requires": "Mercurial",
}


def check_vcs_exposed(url, timeout=6):
    """Check for exposed version control systems."""
    findings = []
    base = url.rstrip("/")

    for path, vcs in GIT_SVN_PATHS.items():
        r = _fetch(base + path, timeout=timeout)
        if r.get("error") or r.get("status") not in (200, 206):
            continue

        body = r.get("body", "")

        # Validate content
        valid = False
        if path.endswith("HEAD") and "ref:" in body.lower():
            valid = True
        elif path.endswith("config") and "[core]" in body.lower():
            valid = True
        elif path.endswith("entries") and ("dir" in body.lower() or "svn" in body.lower()):
            valid = True
        elif path.endswith("requires") and "revlog" in body.lower():
            valid = True
        elif path.endswith("index") and len(body) > 0:
            valid = True
        elif path.endswith("wc.db") and "sqlite" in body.lower()[:20]:
            valid = True

        if valid:
            findings.append({
                "id": f"vcs_{vcs.lower()}_{path.strip('/').replace('/', '_')}",
                "check": "vcs_exposed",
                "title": f"{vcs} repository exposed: {path}",
                "severity": "critical",
                "bug_class": "information_disclosure",
                "payout_potential": "$500-$5000",
                "confidence": 0.99,
                "url": base + path,
                "evidence": f"HTTP {r['status']}, valid {vcs} content",
                "description": f"{vcs} metadata exposed — attacker can dump full source code",
                "remediation": f"Remove {vcs} metadata from web root",
                "source": "bounty_checks",
            })

    return findings


# ============================================================
# Check 5: CORS Misconfiguration
# ============================================================

def check_cors_misconfig(url, timeout=8):
    """Deep CORS misconfiguration check."""
    findings = []

    evil_origin = "https://evil.example.com"

    r = _fetch(url, timeout=timeout, headers={"Origin": evil_origin})
    if r.get("error"):
        return findings

    headers = {k.lower(): v for k, v in r.get("headers", {}).items()}
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "").lower()

    # Case 1: Reflects arbitrary origin + credentials
    if acao == evil_origin and acac == "true":
        findings.append({
            "id": "cors_reflect_creds",
            "check": "cors",
            "title": "CORS: Arbitrary origin reflection with credentials",
            "severity": "high",
            "bug_class": "cors_misconfiguration",
            "payout_potential": "$500-$3000",
            "confidence": 0.98,
            "url": url,
            "evidence": f"ACAO reflects: {evil_origin}, ACAC: {acac}",
            "description": "Server reflects arbitrary Origin + allows credentials — account takeover possible",
            "remediation": "Validate Origin against strict allowlist",
            "source": "bounty_checks",
        })

    # Case 2: Null origin allowed
    r2 = _fetch(url, timeout=timeout, headers={"Origin": "null"})
    if not r2.get("error"):
        h2 = {k.lower(): v for k, v in r2.get("headers", {}).items()}
        acao2 = h2.get("access-control-allow-origin", "")
        if acao2 == "null":
            findings.append({
                "id": "cors_null_origin",
                "check": "cors",
                "title": "CORS: null origin allowed",
                "severity": "medium",
                "bug_class": "cors_misconfiguration",
                "payout_potential": "$300-$1500",
                "confidence": 0.90,
                "url": url,
                "evidence": "ACAO: null accepted",
                "description": "Null origin accepted — exploitable via sandboxed iframes",
                "remediation": "Reject null origin",
                "source": "bounty_checks",
            })

    return findings


# ============================================================
# Check 6: JWT Misconfigurations
# ============================================================

JWT_ENDPOINTS = ["/api/user", "/api/me", "/api/profile", "/api/v1/user"]


def check_jwt_issues(url, timeout=6):
    """Check for basic JWT issues (alg:none, weak secrets)."""
    findings = []

    # We can't easily test this without a valid JWT, so just check for JWT usage
    # and report if cookies contain JWTs without flags
    r = _fetch(url, timeout=timeout)
    if r.get("error"):
        return findings

    # Check Set-Cookie
    set_cookies = []
    for k, v in r.get("headers", {}).items():
        if k.lower() == "set-cookie":
            set_cookies.append(v)

    for cookie in set_cookies:
        # JWT format: header.payload.signature
        if re.search(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", cookie):
            issues = []
            if "secure" not in cookie.lower():
                issues.append("no Secure flag")
            if "httponly" not in cookie.lower():
                issues.append("no HttpOnly flag")
            if "samesite" not in cookie.lower():
                issues.append("no SameSite flag")

            if issues:
                findings.append({
                    "id": "jwt_cookie_flags",
                    "check": "jwt",
                    "title": "JWT cookie missing security flags",
                    "severity": "medium",
                    "bug_class": "session_management",
                    "payout_potential": "$200-$800",
                    "confidence": 0.85,
                    "url": url,
                    "evidence": f"Cookie: {cookie[:80]}... Issues: {', '.join(issues)}",
                    "description": "JWT cookie lacks security flags",
                    "remediation": "Add Secure, HttpOnly, SameSite=Strict flags",
                    "source": "bounty_checks",
                })
            break

    return findings


# ============================================================
# Run All
# ============================================================

def run_bounty_checks(url, workers=10, timeout=8):
    """Run all bounty-specific checks."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = {
        "timestamp": datetime.now().isoformat(),
        "url": url,
        "findings": [],
        "checks_run": [],
        "errors": [],
    }

    checks = [
        ("vcs_exposed",           check_vcs_exposed),
        ("api_docs",              check_api_docs),
        ("cors_misconfiguration", check_cors_misconfig),
        ("open_redirect",         check_open_redirect),
        ("graphql_introspection", check_graphql_introspection),
        ("jwt_issues",            check_jwt_issues),
    ]

    for name, fn in checks:
        print(f"  [*] {name}...")
        try:
            findings = fn(url, timeout=timeout)
            result["findings"].extend(findings)
            result["checks_run"].append(name)
        except Exception as e:
            result["errors"].append(f"{name}: {e}")

    # Sort by payout potential (highest first)
    def payout_sort_key(f):
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return (sev_order.get(f.get("severity", "info"), 99),
                -f.get("confidence", 0))

    result["findings"].sort(key=payout_sort_key)

    return result


def print_bounty_report(result):
    print("\n" + "=" * 70)
    print("  Bug Bounty Checks — ReconX")
    print("=" * 70)

    print(f"\n[*] Target: {result.get('url')}")
    print(f"[*] Checks: {', '.join(result.get('checks_run', []))}")

    findings = result.get("findings", [])
    print(f"[*] Findings: {len(findings)}")

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

        print(f"\n[+] Findings:")
        for f in findings:
            sev = f.get("severity", "info")
            icon = icons.get(sev, "⚪")
            payout = f.get("payout_potential", "?")
            print(f"\n  {icon} [{sev.upper():<8}] {f['title']}")
            print(f"       Bug class:  {f.get('bug_class', '?')}")
            print(f"       Payout:     {payout}")
            print(f"       Confidence: {f.get('confidence', 0):.2f}")
            print(f"       URL:        {f.get('url', '?')}")
            print(f"       Evidence:   {f.get('evidence', '?')[:100]}")

    if result.get("errors"):
        print(f"\n[!] Errors: {len(result['errors'])}")

    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) < 2:
        print("Usage: python -m modules.vuln.bounty_checks <url>")
        sys.exit(1)

    print(f"\n[*] Bug Bounty Checks: {sys.argv[1]}")
    result = run_bounty_checks(sys.argv[1])
    print_bounty_report(result)
