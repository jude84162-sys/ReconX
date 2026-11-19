# modules/vuln/advanced/deserialization.py
"""ReconX - Insecure deserialization inspector.

Passively inspects everything the target hands to the client (cookies, hidden
form fields, URL parameters, response headers/body) for language-native
serialized object formats:

  Java (rO0AB / AC ED 00 05), PHP (O:8:"..."), Python pickle (gASV...),
  .NET ViewState (/wEP...), Ruby Marshal (BAh...), node-serialize
  (_$$ND_FUNC$$_), Yii (__type), Wicket, Jackson @class, JSON __type.

Finding a serialized object in a client-controlled location is the entry
condition for gadget-chain RCE; the report tells the tester where to aim.
"""

import base64
import binascii
import html
import re
import urllib.parse

from modules.utils.http_client import normalize_url, request
from modules.vuln.advanced.base import add_finding, finalize, finding, new_result, print_report

SIGNATURES = [
    ("Java serialized object (base64)", re.compile(r"^rO0AB[A-Za-z0-9+/=]{8,}"),
     "critical", "Java native deserialization — ysoserial gadget chains apply if reachable"),
    ("Java serialized object (hex)", re.compile(r"(?i)^aced0005"),
     "critical", "Java serialization stream magic bytes"),
    ("PHP serialized object", re.compile(r'(?:^|[;"\'])(?:O:\d+:"|a:\d+:\{|s:\d+:")'),
     "high", "PHP serialize()/unserialize() — test with PHPGGC gadget chains"),
    ("PHP serialized object (base64)", re.compile(r"^TzpcP2FwaXxPOp|^TzpcP2FwaXw"),
     "high", "Base64 PHP serialized payload"),
    ("Python pickle", re.compile(r"^(?:gASV|gAJ9|gAN9|gAWV)[A-Za-z0-9+/=]*"),
     "critical", "Python pickle — pickle.loads on user data is remote code execution"),
    (".NET ViewState", re.compile(r"^/wEP[A-Za-z0-9+/=]+"),
     "high", ".NET ViewState — check machineKey and __VIEWSTATE encryption"),
    ("Ruby Marshal", re.compile(r"^BAh[A-Za-z0-9+/=]+"),
     "high", "Ruby Marshal.load on user data permits object injection"),
    ("node-serialize payload", re.compile(r"_\$\$ND_FUNC\$\$_"),
     "critical", "node-serialize function injection"),
    ("Yii serialized object", re.compile(r"__type\b"),
     "high", "Yii/PHP object injection marker"),
    ("Apache Wicket page map", re.compile(r"wicket:interface"),
     "medium", "Wicket stateful page parameters — review for object injection"),
    ("Jackson polymorphic type", re.compile(r'"@class"\s*:\s*"'),
     "high", "Jackson default typing enabled — gadget-chain deserialization risk"),
    ("JSON.NET type handling", re.compile(r'"\$type"\s*:\s*"'),
     "high", "JSON.NET TypeNameHandling — deserialization gadget risk"),
]

B64_RE = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")


def _decode_bytes(value):
    """Return bytes for a raw or base64-encoded value (best effort)."""
    candidates = [value]
    if B64_RE.match(value or ""):
        try:
            raw = base64.b64decode(value + "=" * (-len(value) % 4), validate=False)
            candidates.append(raw.decode("latin-1"))
        except (binascii.Error, ValueError):
            pass
    return candidates


def _match_value(value):
    if not value or len(value) < 8:
        return None
    for candidate in _decode_bytes(value):
        for label, pattern, severity, note in SIGNATURES:
            if pattern.search(candidate):
                return label, severity, note
    # Generic pickle protocol 0/4 magic after base64/url decoding.
    for candidate in _decode_bytes(value):
        if candidate.startswith("\x80\x04") or candidate.startswith("\x80\x05"):
            return "Python pickle (raw)", "critical", "pickle stream magic detected"
    return None


def _scan_location(result, name, value, location, url):
    if not value:
        return
    value = html.unescape(value)
    decoded = urllib.parse.unquote(value)
    for candidate in (value, decoded):
        match = _match_value(candidate)
        if match:
            label, severity, note = match
            add_finding(result, finding(
                f"deser_{re.sub(r'[^a-z0-9]+', '_', label.lower())}_{location}",
                f"Serialized object exposed in {location}: {label}",
                severity,
                url,
                f"{location} '{name}' = {candidate[:90]}{'...' if len(candidate) > 90 else ''}",
                description=(f"{note}. If this value is deserialized server-side without an "
                             "allowlist, an attacker can supply a crafted object."),
                remediation=("Never deserialize untrusted data. Use JSON with strict schemas, "
                             "signed/encrypted tokens, and class allowlists."),
                confidence=0.8,
                bug_class="insecure_deserialization",
                parameter=name,
                location=location,
                source="deserialization",
            ))
            return


def _extract_hidden_fields(body):
    fields = []
    for m in re.finditer(r"(?is)<input\b[^>]*>", body or ""):
        tag = m.group(0)
        name = re.search(r'(?i)\bname\s*=\s*["\']?([^"\'\s>]+)', tag)
        value = re.search(r'(?i)\bvalue\s*=\s*(["\'])(.*?)\1', tag)
        if not value:
            value = re.search(r'(?i)\bvalue\s*=\s*([^"\'\s>]+)', tag)
        if name and value:
            fields.append((name.group(1), value.group(2) if value.lastindex else value.group(1)))
    return fields


def _extract_js_literals(body):
    """Serialized-looking literals inside inline <script> blocks only."""
    literals = []
    for block in re.findall(r"(?is)<script\b[^>]*>(.*?)</script>", body or ""):
        for m in re.finditer(r"""["'](rO0AB[A-Za-z0-9+/=]{8,}|gASV[A-Za-z0-9+/=]{8,}|"""
                             r"""BAh[A-Za-z0-9+/=]{8,}|/wEP[A-Za-z0-9+/=]{8,})["']""", block):
            literals.append(("js_literal", m.group(1)))
    return literals


def scan(target, timeout=10, verbose=False):
    target = normalize_url(target)
    result = new_result(target)
    result["checks_run"].append("passive_inspection")

    resp = request(target, timeout=timeout)
    if resp.error:
        result["errors"].append(f"target unreachable: {resp.error}")
        return finalize(result)

    parsed = urllib.parse.urlparse(target)
    locations = 0

    for name, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
        _scan_location(result, name, value, "url_parameter", resp.url)

    for cookie in resp.cookies:
        raw = cookie.split(";", 1)[0]
        if "=" in raw:
            name, value = raw.split("=", 1)
            _scan_location(result, name.strip(), value.strip(), "cookie", resp.url)

    for header, value in resp.headers.items():
        if header in ("set-cookie", "etag", "cache-control", "date", "last-modified"):
            continue
        _scan_location(result, header, value, "response_header", resp.url)

    for name, value in _extract_hidden_fields(resp.body):
        _scan_location(result, name, value, "hidden_field", resp.url)
        locations += 1

    for name, value in _extract_js_literals(resp.body):
        _scan_location(result, name, value, "js_variable", resp.url)

    result["inspected"] = {
        "cookies": len(resp.cookies),
        "hidden_fields": locations,
        "url_params": len(urllib.parse.parse_qsl(parsed.query)),
    }

    if not result["findings"]:
        result["note"] = ("No serialized objects found client-side. Also inspect API "
                          "cookies and upload endpoints manually.")

    if verbose:
        print(f"  [*] Inspected {result['inspected']}")

    return finalize(result)


run_scanner = scan


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m modules.vuln.advanced.deserialization <url>")
        sys.exit(1)
    print_report(scan(sys.argv[1], verbose=True), "Deserialization Inspector")
