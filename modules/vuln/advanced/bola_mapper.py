# modules/vuln/advanced/bola_mapper.py
"""ReconX - BOLA / IDOR mapper using two authenticated sessions.

Flow:
  1. Crawl the target with account A's credentials.
  2. Extract object URLs/IDs from JSON responses, links and path segments.
  3. Replay every object with account B's credentials (and unauthenticated).
  4. Flag objects that B can read with content identical to A's response while
     an anonymous request is rejected.

This is the closest an automated scanner can get to a BOLA proof: the final
step is always "does the returned data belong to the other user?".
"""

import json
import re
import urllib.parse

from modules.utils.http_client import (
    compare_responses, normalize_url, request, text_similarity,
)
from modules.vuln.advanced.base import add_finding, finalize, finding, new_result, print_report

PII_MARKERS = ["email", "phone", "address", "username", "user_id", "account_id",
               "full_name", "first_name", "last_name", "ssn", "balance", "iban"]
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
MAX_ENDPOINTS = 20


def _auth_headers(header_name, value):
    if not value:
        return {}
    return {header_name: value}


def _walk_json(node, base_host, collected, limit):
    """Collect same-host URLs and object IDs from a JSON document."""
    if len(collected) >= limit:
        return
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(v, (dict, list)):
                _walk_json(v, base_host, collected, limit)
            elif isinstance(v, str):
                if v.startswith(("http://", "https://")):
                    if urllib.parse.urlparse(v).netloc == base_host:
                        collected.append(v)
                elif v.startswith("/") and len(v) < 200:
                    collected.append(v)
    elif isinstance(node, list):
        for item in node[:50]:
            _walk_json(item, base_host, collected, limit)


def _collect_targets(page_url, body, content_type):
    host = urllib.parse.urlparse(page_url).netloc
    collected = []
    data = None
    if "json" in (content_type or "").lower():
        try:
            data = json.loads(body)
        except Exception:
            data = None
    if data is not None:
        _walk_json(data, host, collected, MAX_ENDPOINTS)
    else:
        for href in re.findall(r"""href=["']([^"'#]+)["']""", body or ""):
            if href.startswith(("http://", "https://")):
                if urllib.parse.urlparse(href).netloc == host:
                    collected.append(href)
            elif href.startswith("/"):
                collected.append(href)
    parsed = urllib.parse.urlparse(page_url)
    path = parsed.path or "/"
    mutated = set()
    for seg in path.split("/"):
        if seg.isdigit():
            for delta in (-1, 1):
                mutated.add(path.replace(f"/{seg}/", f"/{max(1, int(seg) + delta)}/")
                            .replace(f"/{seg}", f"/{max(1, int(seg) + delta)}"))
        elif UUID_RE.match(seg):
            mutated.add(path.replace(seg, seg[:-1] + ("0" if seg[-1] != "0" else "1")))
    targets = [page_url] + [urllib.parse.urljoin(page_url, u) for u in collected]
    targets += [urllib.parse.urlunparse(parsed._replace(path=p)) for p in mutated]
    return list(dict.fromkeys(targets))[:MAX_ENDPOINTS]


def _looks_private(body, status):
    if status != 200 or not body or len(body) < 40:
        return False
    low = body.lower()
    if any(m in low for m in ("login", "sign in", "unauthorized", "forbidden")):
        if not any(m in low for m in PII_MARKERS):
            return False
    return any(m in low for m in PII_MARKERS) or '"id"' in low or '"data"' in low


def scan(target, token_a=None, token_b=None, header="Authorization",
         timeout=10, verbose=False):
    target = normalize_url(target)
    result = new_result(target, tested=0, endpoints=[])
    result["checks_run"].append("baseline_account_a")

    if not token_a or not token_b:
        result["errors"].append(
            "two credentials are required: pass account A and account B tokens "
            "(create two low-privilege test accounts)"
        )
        return finalize(result)

    headers_a = _auth_headers(header, token_a)
    headers_b = _auth_headers(header, token_b)

    base_resp = request(target, headers=headers_a, timeout=timeout)
    if base_resp.error or base_resp.status in (401, 403):
        result["errors"].append(
            f"account A could not access target (HTTP {base_resp.status or base_resp.error})"
        )
        return finalize(result)

    targets = _collect_targets(target, base_resp.body, base_resp.header("content-type"))
    result["endpoints"] = targets
    if verbose:
        print(f"  [*] {len(targets)} candidate object endpoints from account A")

    zero_priv = {}
    for url in targets:
        resp_a = request(url, headers=headers_a, timeout=timeout) if url != target else base_resp
        result["tested"] += 1
        if not _looks_private(resp_a.body, resp_a.status):
            continue

        resp_b = request(url, headers=headers_b, timeout=timeout)
        if resp_b.error or resp_b.status != 200:
            continue

        sim = text_similarity(resp_a.body, resp_b.body)
        if sim < 0.90:
            continue

        if url not in zero_priv:
            anon = request(url, timeout=timeout)
            # If anonymous access works too, this is a public object, not BOLA.
            zero_priv[url] = (anon.status == 200 and
                              text_similarity(anon.body, resp_a.body) > 0.9)
        if zero_priv[url]:
            continue

        diff = compare_responses(resp_a, resp_b)
        add_finding(result, finding(
            "bola_object_access",
            "BOLA/IDOR: second account reads the same protected object",
            "high",
            url,
            f"Account B got HTTP 200 with {sim:.0%} similarity to account A's object "
            f"({len(resp_b.body)} bytes); anonymous access rejected",
            description=("Account B received the exact object owned by account A. Confirm "
                         "manually that the object belongs to A (not shared/public data) "
                         "before reporting."),
            remediation=("Authorize every object access against the session identity "
                         "(row-level ownership check), not just authentication."),
            confidence=0.8,
            bug_class="broken_object_level_authorization",
            similarity=diff.get("similarity"),
            source="bola_mapper",
        ))
        if verbose:
            print(f"    [!] BOLA candidate: {url} ({sim:.0%} identical)")

    if not result["findings"]:
        result["note"] = ("No confident BOLA hit. Review extracted endpoints manually; "
                          "automated mapping needs object IDs in URLs or JSON.")
    return finalize(result)


run_scanner = scan


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 4:
        print("Usage: python -m modules.vuln.advanced.bola_mapper <url> "
              "<account-a-token> <account-b-token> [header-name]")
        print('Example: ... https://api.example.com/users/1 "Bearer AAA" "Bearer BBB"')
        sys.exit(1)
    res = scan(sys.argv[1], sys.argv[2], sys.argv[3],
               header=sys.argv[4] if len(sys.argv) > 4 else "Authorization", verbose=True)
    print_report(res, "BOLA / IDOR Mapper")
