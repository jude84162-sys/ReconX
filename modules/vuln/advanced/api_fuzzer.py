# modules/vuln/advanced/api_fuzzer.py
"""ReconX - API specification discovery and parameter type-mismatch fuzzer.

Discovers swagger/openapi/Postman documents, extracts endpoints and query
parameters, then sends type-confused values (arrays, objects, nulls, overflow
integers, traversal strings) looking for server errors, stack traces and
database exception leakage.

Only GET/query and path parameters are fuzzed: no state-changing requests.
"""

import json
import re
import urllib.parse

from modules.utils.http_client import (
    base_url, compare_responses, is_meaningful_change, join_url, normalize_url,
    request, with_params,
)
from modules.vuln.advanced.base import add_finding, finalize, finding, new_result, print_report

API_SPEC_PATHS = [
    "/swagger.json", "/swagger.yaml", "/swagger.yml", "/swagger-ui.html",
    "/swagger-ui/index.html", "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/api-docs", "/api-docs/", "/v2/api-docs", "/v3/api-docs", "/api/swagger.json",
    "/api/v1/swagger.json", "/api/v2/swagger.json", "/api/openapi.json",
    "/.well-known/openapi.json", "/docs/openapi.json", "/api/docs",
    "/redoc", "/postman.json", "/postman_collection.json", "/api/postman.json",
    "/collection.json", "/spec.json", "/api/spec",
]

ERROR_SIGNATURES = [
    "traceback (most recent call last)", "sqlstate", "sql syntax", "ora-0",
    "invalid input syntax", "unhandled exception", "stack trace",
    "at java.", "at org.springframework", "node_modules/", "typeerror:",
    "sequelize", "pymysql", "psycopg2", "microsoft ole db", "odbc drivers",
    "mongoose", "eloquent", "nhibernate", "django.db", "laravel",
    "internal server error", "debug backtrace", "x-powered-by: express",
]

TYPE_PAYLOADS = [
    ("array", "[]"),
    ("object", "{}"),
    ("null", "null"),
    ("bool_for_number", "true"),
    ("negative", "-1"),
    ("integer_overflow", "99999999999999999999999999"),
    ("long_string", "A" * 400),
    ("traversal", "../../../../etc/passwd"),
    ("quote", "reconx'\"`"),
    ("unicode", "%ff%fe%00"),
]

MAX_ENDPOINTS = 12
MAX_PARAMS = 5


def _looks_like_spec(resp):
    if resp.error or resp.status != 200 or not resp.body:
        return None
    body = resp.body.lstrip()
    ctype = resp.header("content-type").lower()
    if body.startswith("{"):
        data = resp.json()
        if isinstance(data, dict):
            if "swagger" in data or "openapi" in data:
                return "openapi"
            if "info" in data and ("item" in data or "_postman_id" in data):
                return "postman"
    if "yaml" in ctype or body.startswith(("openapi:", "swagger:", "paths:")):
        if re.search(r"(?im)^\s*(openapi|swagger|paths)\s*:", resp.body):
            return "yaml"
    return None


def _walk_postman(items, out):
    for item in items or []:
        if not isinstance(item, dict):
            continue
        if "item" in item:
            _walk_postman(item["item"], out)
            continue
        req = item.get("request") or {}
        url = req.get("url")
        method = (req.get("method") or "GET").upper()
        params, path = [], ""
        if isinstance(url, dict):
            path = url.get("path") or ""
            if isinstance(path, list):
                path = "/" + "/".join(str(p) for p in path)
            for q in url.get("query") or []:
                if q.get("key"):
                    params.append({"name": q["key"], "in": "query",
                                   "value": q.get("value")})
        elif isinstance(url, str):
            parsed = urllib.parse.urlparse(url)
            path = parsed.path
            params = [{"name": k, "in": "query", "value": v}
                      for k, v in urllib.parse.parse_qsl(parsed.query)]
        if path:
            out.append({"method": method, "path": path, "params": params})


def parse_spec(resp):
    """Return (kind, endpoints) where endpoints = [{method, path, params}]."""
    data = resp.json()
    if isinstance(data, dict):
        if "swagger" in data or "openapi" in data:
            endpoints = []
            for path, methods in (data.get("paths") or {}).items():
                if not isinstance(methods, dict):
                    continue
                for method, op in methods.items():
                    if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                        continue
                    params = []
                    for p in (op.get("parameters") or []) + (methods.get("parameters") or []):
                        if isinstance(p, dict) and p.get("name"):
                            params.append({
                                "name": p["name"],
                                "in": p.get("in", "query"),
                                "type": (p.get("schema") or {}).get("type")
                                        or p.get("type"),
                                "value": p.get("example") or p.get("default"),
                            })
                    endpoints.append({"method": method.upper(), "path": path,
                                      "params": params})
            return "openapi", endpoints
        if "info" in data and "item" in data:
            endpoints = []
            _walk_postman(data.get("item"), endpoints)
            return "postman", endpoints

    if isinstance(data, list):
        endpoints = []
        _walk_postman(data, endpoints)
        return "postman", endpoints

    # YAML fallback (no PyYAML dependency): extract paths + method blocks.
    text = resp.body
    endpoints = []
    for pm in re.finditer(r"(?m)^\s{2}(/[A-Za-z0-9_\-./{}]+)\s*:\s*$", text):
        path = pm.group(1)
        block = text[pm.end():pm.end() + 2000]
        for mm in re.finditer(r"(?m)^\s{4}(get|post|put|patch|delete)\s*:", block):
            method = mm.group(1).upper()
            sub = block[mm.end():mm.end() + 1200]
            params = []
            for nm in re.finditer(r"(?m)^\s*-?\s*name\s*:\s*['\"]?([\w\-.]+)", sub):
                params.append({"name": nm.group(1), "in": "query"})
            endpoints.append({"method": method, "path": path, "params": params})
    return "yaml", endpoints


def discover_specs(target, timeout=8, verbose=False):
    base = normalize_url(target)
    found = []
    seen = set()
    for path in ["", *API_SPEC_PATHS]:
        url = join_url(base, path) if path else base
        if url in seen:
            continue
        seen.add(url)
        resp = request(url, timeout=timeout)
        kind = _looks_like_spec(resp)
        if not kind:
            continue
        try:
            parsed_kind, endpoints = parse_spec(resp)
        except Exception as e:
            if verbose:
                print(f"    ✗ Could not parse {url}: {e}")
            continue
        found.append({"url": url, "kind": parsed_kind, "bytes": len(resp.body),
                      "endpoints": endpoints})
        if verbose:
            print(f"    [+] {parsed_kind} spec: {url} ({len(endpoints)} endpoints)")
        if len(found) >= 3:
            break
    return found


def _sample_value(param):
    if param.get("value") not in (None, ""):
        return str(param["value"])
    ptype = (param.get("type") or "").lower()
    if ptype in ("integer", "number"):
        return "1"
    if ptype == "boolean":
        return "true"
    return "reconx1"


def _build(ep, param, value):
    path = ep["path"]
    query = {}
    target_name = param.get("name")
    target_in = param.get("in")
    for p in ep["params"]:
        name = p["name"]
        is_target = name == target_name and p.get("in") == target_in
        if p.get("in") == "path":
            path = path.replace("{" + name + "}",
                                urllib.parse.quote(str(value if is_target
                                                       else _sample_value(p))))
        elif p.get("in") == "query":
            query[name] = value if is_target else _sample_value(p)
    return path, query


def _error_signature(body):
    low = (body or "").lower()
    return [sig for sig in ERROR_SIGNATURES if sig in low]


def fuzz_endpoints(base, endpoints, timeout=10, verbose=False, result=None):
    tested = 0
    for ep in endpoints[:MAX_ENDPOINTS]:
        if ep["method"] not in ("GET", "HEAD", "OPTIONS"):
            continue
        params = [p for p in ep.get("params") or [] if p.get("in") in ("query", "path")]
        for param in params[:MAX_PARAMS]:
            path, query = _build(ep, param, _sample_value(param))
            baseline_url = join_url(base, path)
            if query:
                baseline_url = with_params(baseline_url, query)
            baseline = request(baseline_url, timeout=timeout)
            tested += 1
            if baseline.error or (baseline.status or 0) >= 500:
                continue  # endpoint already broken; skip to avoid noise

            for label, payload in TYPE_PAYLOADS:
                test_path, test_query = _build(ep, param, payload)
                test_url = join_url(base, test_path)
                if test_query:
                    test_url = with_params(test_url, test_query)
                test = request(test_url, timeout=timeout)
                tested += 1
                if test.error:
                    continue

                diff = compare_responses(baseline, test)
                sigs = _error_signature(test.body)
                server_error = (test.status or 0) >= 500
                if not (server_error or sigs):
                    continue
                if not is_meaningful_change(diff) and not sigs:
                    continue

                evidence = (f"{label} value for '{param['name']}' -> HTTP {test.status}"
                            f" (baseline {baseline.status})")
                if sigs:
                    evidence += f"; error leak: {', '.join(sigs[:3])}"
                add_finding(result, finding(
                    f"api_type_mismatch_{param['name']}",
                    f"API rejects malformed '{param['name']}' with unhandled error",
                    "high" if sigs else "medium",
                    test_url,
                    evidence,
                    description=("A type-confused value crashed or leaked internals instead of "
                                 "returning a 4xx validation error. This indicates missing "
                                 "input validation and often precedes SQLi/NoSQLi."),
                    remediation=("Validate and coerce parameter types server-side; return a "
                                 "generic 400 and suppress stack traces."),
                    confidence=0.85 if sigs else 0.6,
                    bug_class="improper_input_validation",
                    parameter=param["name"],
                    source="api_fuzzer",
                ))
                if verbose:
                    print(f"    [!] {param['name']} ({label}) -> HTTP {test.status}")
                break
    return tested


def scan(target, timeout=10, verbose=False):
    target = normalize_url(target)
    result = new_result(target, discovered_specs=[], tested=0)
    result["checks_run"].append("spec_discovery")

    specs = discover_specs(target, timeout=timeout, verbose=verbose)
    result["discovered_specs"] = [s["url"] for s in specs]

    if specs:
        spec = specs[0]
        result["endpoint"] = spec["url"]
        add_finding(result, finding(
            "api_spec_exposed",
            f"{spec['kind'].upper()} specification exposed",
            "medium",
            spec["url"],
            f"{len(spec['endpoints'])} endpoints documented, {spec['bytes']} bytes",
            description=("The API contract is public. It lists every endpoint, parameter "
                         "and schema, removing the discovery step for an attacker."),
            remediation="Require authentication for docs or serve them from an internal host.",
            confidence=0.95,
            bug_class="information_disclosure",
            source="api_fuzzer",
        ))

        result["checks_run"].append("parameter_type_fuzzing")
        base = base_url(target)
        for spec in specs:
            if spec["kind"] == "postman":
                continue  # Postman paths often reference external hosts
            result["tested"] += fuzz_endpoints(base, spec["endpoints"], timeout=timeout,
                                               verbose=verbose, result=result)
    else:
        result["note"] = "No API spec found; point the scanner at the API base URL"
        if verbose:
            print("  [OK] No exposed API specification")

    return finalize(result)


run_scanner = scan


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m modules.vuln.advanced.api_fuzzer <url>")
        sys.exit(1)
    res = scan(sys.argv[1], verbose=True)
    print_report(res, "API / Swagger Fuzzer")
