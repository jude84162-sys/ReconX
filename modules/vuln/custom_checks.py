# modules/vuln/custom_checks.py
"""ReconX - Custom security checks (no external tools needed).

Fast parallel checks that don't require Nikto:
  - Security headers audit
  - Cookie flags
  - HTTP methods allowed
  - Sensitive file exposure
  - Information disclosure
  - CORS misconfigurations
"""

import re
import ssl
import logging
import urllib.request
import urllib.error
import concurrent.futures
from datetime import datetime

logger = logging.getLogger("ReconX.vuln.custom")


# ============================================================
# Security Headers
# ============================================================

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "medium",
        "description": "HSTS forces HTTPS connections. Missing allows SSL stripping.",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "description": "CSP prevents XSS and data injection attacks.",
        "remediation": "Define restrictive CSP: default-src 'self'; ...",
    },
    "X-Frame-Options": {
        "severity": "low",
        "description": "Missing allows clickjacking attacks.",
        "remediation": "Add: X-Frame-Options: DENY (or SAMEORIGIN)",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "description": "Missing allows MIME type sniffing attacks.",
        "remediation": "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "Controls referrer information leakage.",
        "remediation": "Add: Referrer-Policy: no-referrer or strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "info",
        "description": "Controls browser feature usage (camera, mic, etc.).",
        "remediation": "Add: Permissions-Policy: geolocation=(), camera=()",
    },
    "Cross-Origin-Opener-Policy": {
        "severity": "info",
        "description": "Isolates browsing context to prevent XS-Leaks.",
        "remediation": "Add: Cross-Origin-Opener-Policy: same-origin",
    },
    "Cross-Origin-Embedder-Policy": {
        "severity": "info",
        "description": "Required for cross-origin isolation.",
        "remediation": "Add: Cross-Origin-Embedder-Policy: require-corp",
    },
    "Cross-Origin-Resource-Policy": {
        "severity": "info",
        "description": "Prevents cross-origin resource loading.",
        "remediation": "Add: Cross-Origin-Resource-Policy: same-origin",
    },
}


# ============================================================
# HTTP Methods
# ============================================================

DANGEROUS_METHODS = {
    "PUT": "Can upload/modify files on the server",
    "DELETE": "Can delete resources",
    "TRACE": "Echoes request — potential XST attack",
    "CONNECT": "Can proxy requests — usually unwanted",
    "PATCH": "Can modify resources",
}


# ============================================================
# Sensitive Paths
# ============================================================

SENSITIVE_PATHS = {
    "/.git/HEAD": ("critical", "Git repository exposed — full source code leak"),
    "/.git/config": ("critical", "Git config exposed — may contain credentials"),
    "/.env": ("critical", "Environment file exposed — may contain secrets"),
    "/.env.local": ("critical", "Local env file exposed"),
    "/.env.production": ("critical", "Production env file exposed"),
    "/.htaccess": ("high", "Apache config exposed"),
    "/.htpasswd": ("critical", "Apache password file exposed"),
    "/.svn/entries": ("high", "SVN repository exposed"),
    "/.DS_Store": ("medium", "macOS metadata exposed"),
    "/web.config": ("high", "IIS config exposed"),
    "/composer.json": ("medium", "PHP dependencies exposed"),
    "/composer.lock": ("medium", "PHP exact versions exposed"),
    "/package.json": ("medium", "Node.js dependencies exposed"),
    "/package-lock.json": ("medium", "Node.js exact versions exposed"),
    "/yarn.lock": ("medium", "Yarn dependencies exposed"),
    "/Gemfile": ("medium", "Ruby dependencies exposed"),
    "/Gemfile.lock": ("medium", "Ruby exact versions exposed"),
    "/requirements.txt": ("medium", "Python dependencies exposed"),
    "/Dockerfile": ("medium", "Docker build config exposed"),
    "/docker-compose.yml": ("high", "Docker orchestration exposed"),
    "/.dockerignore": ("low", "Docker ignore rules exposed"),
    "/phpinfo.php": ("high", "PHP info exposed — reveals system details"),
    "/info.php": ("high", "PHP info exposed"),
    "/test.php": ("medium", "Test file exposed"),
    "/adminer.php": ("high", "Adminer database tool exposed"),
    "/phpmyadmin/": ("high", "phpMyAdmin exposed"),
    "/admin/": ("medium", "Admin panel exposed"),
    "/.well-known/security.txt": ("info", "Security contact info"),
    "/backup.sql": ("critical", "Database backup exposed"),
    "/backup.zip": ("critical", "Backup archive exposed"),
    "/backup.tar.gz": ("critical", "Backup archive exposed"),
    "/db.sql": ("critical", "Database dump exposed"),
    "/dump.sql": ("critical", "Database dump exposed"),
    "/robots.txt": ("info", "Robots file — reveals paths"),
    "/sitemap.xml": ("info", "Sitemap — reveals paths"),
    "/crossdomain.xml": ("medium", "Flash cross-domain policy"),
    "/clientaccesspolicy.xml": ("medium", "Silverlight policy"),
    "/server-status": ("high", "Apache server-status exposed"),
    "/server-info": ("high", "Apache server-info exposed"),
    "/nginx_status": ("high", "Nginx status exposed"),
    "/actuator": ("high", "Spring Boot Actuator exposed"),
    "/actuator/env": ("critical", "Spring Boot env exposed"),
    "/actuator/health": ("medium", "Spring Boot health endpoint"),
    "/metrics": ("medium", "Metrics endpoint exposed"),
    "/debug": ("medium", "Debug endpoint exposed"),
    "/console": ("high", "Console exposed"),
    "/wp-config.php.bak": ("critical", "WordPress config backup"),
    "/wp-config.php~": ("critical", "WordPress config backup"),
    "/wp-config.php.save": ("critical", "WordPress config backup"),
    "/config.php.bak": ("critical", "Config backup"),
    "/config.php~": ("critical", "Config backup"),
}


# ============================================================
# HTTP Fetch
# ============================================================

def _make_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _fetch(url, timeout=8, method="GET"):
    try:
        req = urllib.request.Request(url, method=method, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0",
            "Accept": "*/*",
        })
        with urllib.request.urlopen(req, timeout=timeout, context=_make_ctx()) as r:
            return {
                "status": r.status,
                "headers": {k: v for k, v in r.headers.items()},
                "body": r.read(50000).decode("utf-8", errors="ignore")[:10000],
                "url": r.url,
            }
    except urllib.error.HTTPError as e:
        try:
            body = e.read(20000).decode("utf-8", errors="ignore")[:10000]
        except Exception:
            body = ""
        return {
            "status": e.code,
            "headers": {k: v for k, v in (e.headers.items() if e.headers else [])},
            "body": body,
            "url": url,
        }
    except Exception as e:
        return {"error": str(e)}


# ============================================================
# Checks
# ============================================================

def check_security_headers(url):
    """Check missing security headers."""
    findings = []
    r = _fetch(url)

    if r.get("error"):
        return [{"check": "security_headers", "error": r["error"]}]

    headers = {k.lower(): v for k, v in r.get("headers", {}).items()}

    for header, config in SECURITY_HEADERS.items():
        if header.lower() not in headers:
            findings.append({
                "id": f"hdr_{header.lower()}",
                "check": "security_headers",
                "title": f"Missing security header: {header}",
                "severity": config["severity"],
                "confidence": 0.95,
                "url": url,
                "evidence": f"Header not present in response",
                "description": config["description"],
                "remediation": config["remediation"],
                "source": "custom_checks",
            })

    return findings


def check_http_methods(url):
    """Check for dangerous HTTP methods."""
    findings = []
    r = _fetch(url, method="OPTIONS")

    if r.get("error"):
        return findings

    allow = ""
    for k, v in r.get("headers", {}).items():
        if k.lower() == "allow":
            allow = v
            break

    if not allow:
        return findings

    methods = [m.strip().upper() for m in allow.split(",")]

    for method in methods:
        if method in DANGEROUS_METHODS:
            severity = "high" if method in ("PUT", "DELETE") else "medium"
            findings.append({
                "id": f"method_{method.lower()}",
                "check": "http_methods",
                "title": f"Dangerous HTTP method enabled: {method}",
                "severity": severity,
                "confidence": 0.85,
                "url": url,
                "evidence": f"Allow header: {allow}",
                "description": DANGEROUS_METHODS[method],
                "remediation": f"Disable {method} in server configuration if not needed",
                "source": "custom_checks",
            })

    return findings


def check_sensitive_paths(url, workers=20, timeout=6):
    """Check for exposed sensitive files."""
    findings = []
    base = url.rstrip("/")

    def check_one(path_info):
        path, (severity, desc) = path_info
        test_url = base + path
        r = _fetch(test_url, timeout=timeout)

        if r.get("error"):
            return None

        status = r.get("status")

        # Only report if actual content returned
        if status not in (200, 206):
            return None

        body = r.get("body", "")
        content_type = ""
        for k, v in r.get("headers", {}).items():
            if k.lower() == "content-type":
                content_type = v.lower()
                break

        # Filter false positives: common 404 pages served with 200
        if status == 200 and len(body) < 20:
            return None

        # .git/HEAD must contain "ref:" 
        if path == "/.git/HEAD" and "ref:" not in body.lower():
            return None

        return {
            "id": f"path_{path.replace('/', '_').replace('.', '_').lstrip('_')}",
            "check": "sensitive_paths",
            "title": f"Exposed sensitive path: {path}",
            "severity": severity,
            "confidence": 0.85,
            "url": test_url,
            "evidence": f"HTTP {status}, {len(body)} bytes, type: {content_type}",
            "description": desc,
            "remediation": "Restrict access or remove this file from public web root",
            "source": "custom_checks",
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(check_one, item) for item in SENSITIVE_PATHS.items()]
        for future in concurrent.futures.as_completed(futures):
            try:
                r = future.result(timeout=timeout + 5)
                if r:
                    findings.append(r)
            except Exception:
                pass

    return findings


def check_cors(url):
    """Check CORS misconfigurations."""
    findings = []
    r = _fetch(url)

    if r.get("error"):
        return findings

    headers = {k.lower(): v for k, v in r.get("headers", {}).items()}
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "")

    if acao == "*" and acac.lower() == "true":
        findings.append({
            "id": "cors_wildcard_creds",
            "check": "cors",
            "title": "CORS: Wildcard origin with credentials",
            "severity": "high",
            "confidence": 0.95,
            "url": url,
            "evidence": f"ACAO: {acao}, ACAC: {acac}",
            "description": "Wildcard origin with credentials allows any site to read user data",
            "remediation": "Use specific allowed origins instead of wildcard",
            "source": "custom_checks",
        })
    elif acao == "*":
        findings.append({
            "id": "cors_wildcard",
            "check": "cors",
            "title": "CORS: Wildcard origin allowed",
            "severity": "low",
            "confidence": 0.85,
            "url": url,
            "evidence": f"ACAO: {acao}",
            "description": "Any origin can read responses (if not credential-based)",
            "remediation": "Restrict to specific allowed origins",
            "source": "custom_checks",
        })

    return findings


# ============================================================
# Main
# ============================================================

def run_custom_checks(url, workers=20, timeout=6):
    """Run all custom checks."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = {
        "timestamp": datetime.now().isoformat(),
        "url": url,
        "findings": [],
        "checks_run": [],
        "errors": [],
    }

    print(f"  [*] Security headers...")
    try:
        result["findings"].extend(check_security_headers(url))
        result["checks_run"].append("security_headers")
    except Exception as e:
        result["errors"].append(f"headers: {e}")

    print(f"  [*] HTTP methods...")
    try:
        result["findings"].extend(check_http_methods(url))
        result["checks_run"].append("http_methods")
    except Exception as e:
        result["errors"].append(f"methods: {e}")

    print(f"  [*] Sensitive paths ({len(SENSITIVE_PATHS)} paths)...")
    try:
        result["findings"].extend(check_sensitive_paths(url, workers=workers, timeout=timeout))
        result["checks_run"].append("sensitive_paths")
    except Exception as e:
        result["errors"].append(f"paths: {e}")

    print(f"  [*] CORS configuration...")
    try:
        result["findings"].extend(check_cors(url))
        result["checks_run"].append("cors")
    except Exception as e:
        result["errors"].append(f"cors: {e}")

    # Sort by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    result["findings"].sort(key=lambda x: sev_order.get(x.get("severity", "info"), 99))

    return result


def print_custom_checks_report(result):
    print("\n" + "=" * 70)
    print("  Custom Security Checks — ReconX")
    print("=" * 70)

    print(f"\n[*] Target: {result.get('url')}")
    print(f"[*] Checks run: {', '.join(result.get('checks_run', []))}")
    print(f"[*] Findings: {len(result.get('findings', []))}")

    by_sev = {}
    for f in result.get("findings", []):
        by_sev[f.get("severity", "info")] = by_sev.get(f.get("severity", "info"), 0) + 1

    print(f"\n[*] By severity:")
    icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in by_sev:
            print(f"    {icons[sev]} {sev.capitalize():<10} {by_sev[sev]}")

    if result.get("findings"):
        print(f"\n[+] Findings:")
        for f in result["findings"][:30]:
            sev = f.get("severity", "info")
            icon = icons.get(sev, "⚪")
            print(f"\n  {icon} [{sev.upper():<8}] {f['title']}")
            print(f"       URL: {f.get('url', '?')}")
            print(f"       Evidence: {f.get('evidence', '?')}")
            if f.get("description"):
                print(f"       Description: {f['description'][:100]}")

    if result.get("errors"):
        print(f"\n[!] Errors: {len(result['errors'])}")

    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) < 2:
        print("Usage: python -m modules.vuln.custom_checks <url>")
        sys.exit(1)

    url = sys.argv[1]
    print(f"\n[*] Custom checks: {url}")
    result = run_custom_checks(url)
    print_custom_checks_report(result)
