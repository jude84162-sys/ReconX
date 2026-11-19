# modules/vuln/advanced/graphql_scanner.py
"""ReconX - GraphQL introspection, batching and field-suggestion scanner.

Checks performed:
  1. Endpoint discovery (common paths + provided URL)
  2. Full ``__schema`` introspection and sensitive type/field extraction
  3. Query batching (rate-limit / brute-force bypass primitive)
  4. Field suggestions leaking schema names when introspection is disabled
"""

import json
import re

from modules.utils.http_client import join_url, normalize_url, request
from modules.vuln.advanced.base import add_finding, finalize, finding, new_result, print_report

GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql", "/gql",
    "/query", "/api/gql", "/graphql/v1", "/api/v1/graphql", "/index.php?graphql",
]

INTROSPECTION_QUERY = """
query ReconXSchema {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields { name }
    }
  }
}
""".strip()

SENSITIVE_NAME_RE = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|private|ssn|credit|card|"
    r"salary|is[_-]?admin|role|permission|reset|otp|mfa|refresh)"
)


def _is_graphql_response(resp):
    if resp.error or not resp.body:
        return False
    ctype = resp.header("content-type").lower()
    body = resp.body.strip()
    if "json" in ctype:
        data = resp.json()
        if isinstance(data, dict) and ("data" in data or "errors" in data):
            return True
        if isinstance(data, list) and data:
            return True
    return body.startswith("{") and ('"data"' in body or '"errors"' in body)


def discover_endpoint(target, timeout=10):
    """Find a live GraphQL endpoint. Returns (endpoint, base_response)."""
    target = normalize_url(target)
    candidates = [target]
    for path in GRAPHQL_PATHS:
        candidate = join_url(target, path)
        if candidate not in candidates:
            candidates.append(candidate)

    probe = {"query": "{__typename}"}
    for url in candidates[:12]:
        resp = request(url, method="POST", data=probe, timeout=timeout,
                       headers={"Content-Type": "application/json"})
        if _is_graphql_response(resp) and '"errors"' not in resp.body[:400].lower():
            return url, resp
        # Introspection-disabled servers still answer with a GraphQL error shape.
        if _is_graphql_response(resp):
            return url, resp
    return None, None


def run_introspection(endpoint, timeout=15):
    resp = request(endpoint, method="POST",
                   data={"query": INTROSPECTION_QUERY},
                   timeout=timeout,
                   headers={"Content-Type": "application/json"})
    data = resp.json()
    if not isinstance(data, dict):
        return None
    schema = (data.get("data") or {}).get("__schema")
    return schema


def analyze_schema(schema):
    """Return (types, sensitive) where sensitive is [(type, field)]."""
    types = []
    sensitive = []
    for t in schema.get("types") or []:
        name = t.get("name") or ""
        if name.startswith("__"):
            continue
        fields = [f.get("name") for f in (t.get("fields") or []) if f.get("name")]
        types.append({"name": name, "kind": t.get("kind"), "fields": fields})
        for field_name in fields:
            if SENSITIVE_NAME_RE.search(field_name):
                sensitive.append((name, field_name))
    return types, sensitive


def check_batching(endpoint, timeout=10):
    batch = [
        {"query": "{__typename}"},
        {"query": "{__typename}"},
    ]
    resp = request(endpoint, method="POST", data=batch, timeout=timeout,
                   headers={"Content-Type": "application/json"})
    data = resp.json()
    return isinstance(data, list) and len(data) >= 2 and all(
        isinstance(item, dict) for item in data
    )


def check_field_suggestion(endpoint, timeout=10):
    probe = {"query": "{ reconxNoSuchField }"}
    resp = request(endpoint, method="POST", data=probe, timeout=timeout,
                   headers={"Content-Type": "application/json"})
    body = resp.body or ""
    return bool(re.search(r"(?i)did you mean|suggest|unknown field|"
                          r"cannot query field", body)), body[:300]


def scan(target, endpoint=None, timeout=10, verbose=False):
    target = normalize_url(target)
    result = new_result(target, endpoint=None)

    if endpoint:
        endpoint = normalize_url(endpoint)
    else:
        if verbose:
            print("  [*] Discovering GraphQL endpoint...")
        endpoint, _ = discover_endpoint(target, timeout=timeout)
        result["checks_run"].append("discovery")

    if not endpoint:
        result["errors"].append("no GraphQL endpoint responded to a probe query")
        result["note"] = "Provide the endpoint explicitly if it uses a custom path"
        return finalize(result)

    result["endpoint"] = endpoint
    if verbose:
        print(f"  [+] GraphQL endpoint: {endpoint}")

    # 1. Introspection
    schema = run_introspection(endpoint, timeout=timeout)
    result["checks_run"].append("introspection")
    if schema:
        types, sensitive = analyze_schema(schema)
        result["schema_types"] = len(types)
        if verbose:
            print(f"  [!] Introspection enabled — {len(types)} types exposed")

        evidence = f"__schema returned {len(types)} types"
        if sensitive:
            pairs = [f"{t}.{f}" for t, f in sensitive[:12]]
            evidence += f"; sensitive fields: {', '.join(pairs)}"

        add_finding(result, finding(
            "graphql_introspection",
            "GraphQL introspection enabled",
            "high" if sensitive else "medium",
            endpoint,
            evidence,
            description=("The full GraphQL schema is queryable. Attackers can map every "
                         "query, mutation and field without guessing."),
            remediation="Disable introspection in production or restrict it to staff IPs.",
            confidence=0.95,
            bug_class="information_disclosure",
            source="graphql",
            sensitive_fields=[f"{t}.{f}" for t, f in sensitive[:40]],
        ))

        mutation_type = (schema.get("mutationType") or {}).get("name")
        if mutation_type:
            mutations = [t for t in types if t["name"] == mutation_type]
            if mutations and mutations[0]["fields"]:
                result["mutations"] = mutations[0]["fields"]
    else:
        if verbose:
            print("  [OK] Introspection disabled")

    # 2. Query batching
    try:
        if check_batching(endpoint, timeout=timeout):
            result["checks_run"].append("batching")
            add_finding(result, finding(
                "graphql_batching",
                "GraphQL query batching enabled",
                "medium",
                endpoint,
                "A JSON array of two operations returned two results in one request",
                description=("Batching lets an attacker send many operations per HTTP "
                             "request, bypassing rate limits, 2FA throttles and WAF "
                             "request-count rules."),
                remediation="Cap batch size or disable array batching; rate-limit by operation.",
                confidence=0.85,
                bug_class="rate_limit_bypass",
                source="graphql",
            ))
            if verbose:
                print("  [!] Query batching accepted")
    except Exception as e:
        result["errors"].append(f"batching: {e}")

    # 3. Field suggestions leak schema names
    try:
        suggested, evidence = check_field_suggestion(endpoint, timeout=timeout)
        result["checks_run"].append("field_suggestions")
        if suggested and "did you mean" in evidence.lower():
            add_finding(result, finding(
                "graphql_field_suggestion",
                "GraphQL field suggestions leak schema names",
                "low",
                endpoint,
                evidence.replace("\n", " "),
                description=("The server suggests similar field names for invalid queries, "
                             "allowing schema reconstruction even with introspection off."),
                remediation="Disable 'did you mean' suggestions in production.",
                confidence=0.8,
                bug_class="information_disclosure",
                source="graphql",
            ))
    except Exception as e:
        result["errors"].append(f"field_suggestions: {e}")

    return finalize(result)


# Compatibility aliases used by the CLI
run_scanner = scan


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m modules.vuln.advanced.graphql_scanner <url> [endpoint]")
        sys.exit(1)
    res = scan(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None, verbose=True)
    print_report(res, "GraphQL Security")
