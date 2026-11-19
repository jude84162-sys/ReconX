# modules/vuln/advanced/mass_assignment.py
"""ReconX - Mass assignment and HTTP parameter pollution tester.

Sends the caller's baseline request, then re-sends it with privileged fields
appended (``is_admin``, ``role``, ``verified``, ``balance`` ...). A finding is
raised only when the server accepts the extra field: either it is echoed back
in the response or the response materially changes while staying successful.

Note: this performs state-changing requests if you provide a body. Test only
against accounts created for the engagement.
"""

import json
import re
import urllib.parse

from modules.utils.http_client import (
    compare_responses, is_meaningful_change, normalize_url, request, with_params,
)
from modules.vuln.advanced.base import add_finding, finalize, finding, new_result, print_report

HIDDEN_FIELDS = [
    ("is_admin", True),
    ("admin", True),
    ("is_superuser", True),
    ("role", "admin"),
    ("account_type", "admin"),
    ("user_type", "admin"),
    ("plan", "enterprise"),
    ("subscription", "premium"),
    ("verified", True),
    ("email_verified", True),
    ("is_verified", True),
    ("active", True),
    ("enabled", True),
    ("balance", 999999),
    ("credits", 999999),
    ("discount", 100),
    ("permissions", ["admin"]),
    ("groups", ["administrators"]),
    ("owner_id", 1),
    ("user_id", 1),
    ("tenant_id", "admin"),
    ("price", 0),
]

POLLUTION_TARGETS = ["role", "is_admin", "admin", "user_id", "account_id", "price", "verified"]


def _reflects(test, field, value):
    """True only when the response echoes the injected field AND value.

    An existing key is not enough: a profile may always contain "role": "user"
    while ignoring the injected "role": "admin". Whitespace is normalized so
    pretty-printed JSON and form bodies are both handled.
    """
    body = re.sub(r"\s+", "", (test.body or "").lower())
    field_l = field.lower()
    if field_l not in body:
        return False

    if isinstance(value, bool):
        literal = "true" if value else "false"
        return (f'"{field_l}":{literal}' in body or
                f"{field_l}={literal}" in body)
    if isinstance(value, list):
        return any(str(v).lower() in body for v in value)

    literal = str(value).lower()
    return (f'"{field_l}":"{literal}"' in body or
            f'"{field_l}":{literal}' in body or
            f"{field_l}={literal}" in body)


def _wire_value(value):
    """Lowercase booleans so form/query encoders send true/false, not True/False."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return value


def _extend_body(body, field, value):
    if body is None:
        return None
    stripped = body.strip()
    if stripped.startswith("{"):
        data = json.loads(body)
        data[field] = value
        return data
    sep = "" if not body or body.endswith("&") else "&"
    return body + sep + urllib.parse.urlencode({field: _wire_value(value)})


def _send(target, method, body, headers, timeout):
    hdrs = dict(headers or {})
    if body is not None and not isinstance(body, dict):
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
    return request(target, method=method, data=body, headers=hdrs, timeout=timeout)


def _duplicate_json(body, field, first, second):
    """Build a JSON body with the same key twice (parser differential)."""
    if body is None:
        return None
    try:
        data = json.loads(body)
    except Exception:
        return None
    raw = json.dumps(data)
    if not raw.endswith("}"):
        return None
    prefix = raw[:-1]
    if prefix.strip() == "{":
        return '{"%s":%s,"%s":%s}' % (field, json.dumps(first), field, json.dumps(second))
    return prefix + ',"%s":%s,"%s":%s}' % (field, json.dumps(first), field, json.dumps(second))


def scan(target, body=None, headers=None, timeout=10, verbose=False):
    target = normalize_url(target)
    method = "POST" if body else "GET"
    result = new_result(target, method=method, tested=0)
    result["checks_run"].append("baseline")

    baseline = _send(target, method, body, headers, timeout)
    if baseline.error:
        result["errors"].append(f"baseline request failed: {baseline.error}")
        return finalize(result)

    if verbose:
        print(f"  [*] Baseline HTTP {baseline.status} ({len(baseline.body)} bytes)")

    result["checks_run"].append("hidden_field_injection")
    for field, value in HIDDEN_FIELDS:
        extended = _extend_body(body, field, value)
        if extended is None:
            test = request(with_params(target, {field: _wire_value(value)}), timeout=timeout)
        else:
            test = _send(target, method, extended, headers, timeout)
        result["tested"] += 1

        if test.error or (test.status or 0) >= 400:
            continue

        diff = compare_responses(baseline, test)
        reflected = _reflects(test, field, value)
        # A changed successful response without reflection is weak evidence.
        if not reflected and not is_meaningful_change(diff, min_similarity_delta=0.12):
            continue
        if not reflected and not (test.status == baseline.status == 200):
            continue

        severity = "high" if reflected else "medium"
        evidence = f"Sent {field}={json.dumps(value)} -> HTTP {test.status}"
        if reflected:
            evidence += f"; response echoes '{field}'"
        else:
            evidence += (f"; similarity {diff.get('similarity')} "
                         f"(baseline {diff.get('baseline_length')}b -> {diff.get('length')}b)")

        add_finding(result, finding(
            f"mass_assignment_{field}",
            f"Mass assignment: privileged field '{field}' accepted",
            severity,
            target,
            evidence,
            description=("The endpoint accepted a field the client is not supposed to set. "
                         "If persisted, an attacker can escalate privileges or change billing "
                         "state. Confirm by reading the field back from the account profile."),
            remediation=("Bind requests to an explicit allowlist (DTO/serializer schema); "
                         "never pass request bodies straight into the model."),
            confidence=0.8 if reflected else 0.5,
            bug_class="mass_assignment",
            parameter=field,
            source="mass_assignment",
        ))
        if verbose:
            print(f"    [!] {field} accepted (reflected={reflected})")

    # HTTP parameter pollution (duplicate keys, last/first wins differential)
    result["checks_run"].append("parameter_pollution")
    for field in POLLUTION_TARGETS:
        if body:
            polluted = _duplicate_json(body, field, "user", "admin") if \
                body.strip().startswith("{") else None
            if polluted is None:
                sep = "" if body.endswith("&") else "&"
                polluted = f"{body}{sep}{field}=user&{field}=admin"
            test = _send(target, method, polluted, headers, timeout)
        else:
            sep = "&" if urllib.parse.urlparse(target).query else "?"
            test = request(f"{target}{sep}{field}=user&{field}=admin", timeout=timeout)
        result["tested"] += 1

        if test.error or (test.status or 0) >= 400:
            continue
        body_l = re.sub(r"\s+", "", (test.body or "").lower())
        if (f'"{field}":"admin"' in body_l or f'"{field}":admin' in body_l or
                f"{field}=admin" in body_l):
            add_finding(result, finding(
                f"param_pollution_{field}",
                f"HTTP parameter pollution: duplicated '{field}' reaches backend",
                "medium",
                target,
                f"Sent '{field}=user&{field}=admin'; response reflects the admin value",
                description=("The server accepts duplicate parameters and uses the last/first "
                             "value inconsistently between layers, a classic authorization-bypass "
                             "primitive."),
                remediation="Reject duplicate parameters or normalize them at the edge.",
                confidence=0.65,
                bug_class="parameter_pollution",
                parameter=field,
                source="mass_assignment",
            ))
            if verbose:
                print(f"    [!] Duplicate '{field}' accepted")

    return finalize(result)


run_scanner = scan


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m modules.vuln.advanced.mass_assignment <url> [json-body]")
        print('Example: ... https://api.example.com/users \'{"name":"x"}\'')
        sys.exit(1)
    res = scan(sys.argv[1], body=sys.argv[2] if len(sys.argv) > 2 else None, verbose=True)
    print_report(res, "Mass Assignment / Parameter Pollution")
