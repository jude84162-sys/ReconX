# modules/vuln/advanced/cloud_metadata.py
"""ReconX - Cloud metadata SSRF pivoting and internal port discovery.

Verifies SSRF beyond a simple 200: each cloud metadata endpoint is requested
through a candidate parameter and the response is matched against provider
specific keys (ami-id, AccessKeyId, vmId, ...) to avoid soft-404 false
positives. Then probes localhost ports through the same parameter and compares
against a closed-port control.

Write/echo endpoints are never used; all requests are GETs.
"""

import threading
import time

from modules.utils.http_client import (
    adaptive_request, is_blocked, normalize_url, query_params, random_token,
    request, with_params,
)
from modules.vuln.advanced.base import (
    DEFAULT_WORKERS, add_finding, finalize, finding, new_result, parallel_map,
    print_report,
)

SSRF_PARAMS = [
    "url", "uri", "link", "src", "source", "target", "dest", "destination",
    "redirect", "redirect_uri", "return", "next", "callback", "webhook", "feed",
    "host", "site", "reference", "ref", "path", "file", "load", "page", "image",
    "img", "domain", "proxy", "fetch", "resource", "endpoint", "api",
]

# (id, url, markers, required_headers, label)
CLOUD_TARGETS = [
    ("aws_imds", "http://169.254.169.254/latest/meta-data/",
     ["ami-id", "instance-id", "local-ipv4", "placement", "security-groups"],
     {}, "AWS EC2 metadata (IMDSv1)"),
    ("aws_iam", "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
     ["AccessKeyId", "SecretAccessKey", "Token"], {}, "AWS IAM temporary credentials"),
    ("aws_userdata", "http://169.254.169.254/latest/user-data",
     ["#!/", "cloud-init", "Content-Type"], {}, "AWS instance user-data"),
    ("gcp", "http://metadata.google.internal/computeMetadata/v1/instance/",
     ["service-account", "project-id", "attributes", "zone"],
     {"Metadata-Flavor": "Google"}, "GCP compute metadata"),
    ("gcp_ip", "http://169.254.169.254/computeMetadata/v1/instance/",
     ["service-account", "project-id", "attributes", "zone"],
     {"Metadata-Flavor": "Google"}, "GCP metadata via link-local IP"),
    ("azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
     ["vmId", "subscriptionId", "resourceGroupName", "location"],
     {"Metadata": "true"}, "Azure IMDS"),
    ("oracle", "http://169.254.169.254/opc/v2/instance/",
     ["compartmentId", "displayName", "canonicalRegionName"],
     {"Authorization": "Bearer Oracle"}, "OCI metadata"),
    ("alibaba", "http://100.100.100.200/latest/meta-data/",
     ["instance-id", "region-id", "image-id"], {}, "Alibaba Cloud metadata"),
    ("digitalocean", "http://169.254.169.254/metadata/v1/",
     ["droplet_id", "interfaces", "region", "hostname"], {}, "DigitalOcean metadata"),
    ("kubernetes", "https://kubernetes.default.svc/api/v1/namespaces/default/pods",
     ["PodList", "kind", "metadata"], {}, "Kubernetes API service account"),
]

INTERNAL_HOSTS = ["127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1"]

INTERNAL_PORTS = [22, 80, 443, 2375, 3000, 3306, 5000, 5432, 6379,
                  8000, 8080, 8443, 8888, 9200, 11211, 27017]

MAX_REQUESTS = 120


def _marker(body, markers):
    low = (body or "").lower()
    for marker in markers:
        if marker.lower() in low:
            return marker
    return None


def _param_candidates(target):
    params = query_params(target)
    if not params:
        params = SSRF_PARAMS[:8]
    return params[:10]


def _probe_cloud(target, params, timeout, verbose, result, counter, workers=DEFAULT_WORKERS):
    # Build every (param, metadata-target) probe in deterministic iteration order
    # so the concurrent results can be replayed exactly like the old serial loop.
    work = []
    for param in params:
        for target_id, url, markers, headers, label in CLOUD_TARGETS:
            for with_headers in ([True, False] if headers else [False]):
                work.append((param, target_id, url, markers, headers, label, with_headers))

    lock = threading.Lock()
    state = {"stop": False, "exhausted": False}

    def probe(item):
        param, target_id, url, markers, headers, label, with_headers = item
        with lock:
            # One confirmed metadata hit is enough; stop claiming budget for the rest.
            if state["stop"]:
                return None
            if counter[0] >= MAX_REQUESTS:
                state["exhausted"] = True
                return None
            counter[0] += 1
        hdrs = dict(headers) if with_headers else {}
        send = lambda value, p=param, h=hdrs: request(
            with_params(target, {p: value}), timeout=timeout, headers=h)
        used, resp, mutation = adaptive_request(send, url, limit=2)
        if resp is None or resp.error:
            return None
        found = _marker(resp.body, markers)
        if not found:
            return None
        with lock:
            state["stop"] = True
        return {"param": param, "target_id": target_id, "url": url, "label": label,
                "found": found, "resp_len": len(resp.body), "mutation": mutation}

    hits = parallel_map(work, probe, workers=workers)

    if state["exhausted"]:
        result["errors"].append("request budget exhausted during metadata probing")

    # Replay in iteration order: report the first hit the serial loop would have.
    hit = next((h for h in hits if h), None)
    if not hit:
        return

    mutation = hit["mutation"]
    add_finding(result, finding(
        f"ssrf_{hit['target_id']}",
        f"SSRF reaches {hit['label']}",
        "critical",
        with_params(target, {hit["param"]: hit["url"]}),
        f"Response contains '{hit['found']}' ({hit['resp_len']} bytes)"
        + (f"; WAF evasion: {mutation}" if mutation not in ("plain", "blocked") else ""),
        description=(f"The server-side fetcher followed the injected URL to {hit['label']}. "
                     "Cloud credentials in metadata frequently allow full account "
                     "takeover; user-data often contains secrets and bootstrap tokens."),
        remediation=("Block link-local 169.254.0.0/16 and cloud metadata hostnames in "
                     "the fetcher, require auth for metadata (IMDSv2), and use an "
                     "allowlist of outbound destinations."),
        confidence=0.95 if hit["target_id"] == "aws_iam" else 0.9,
        bug_class="ssrf",
        parameter=hit["param"],
        payload=hit["url"],
        source="cloud_metadata",
    ))
    if verbose:
        print(f"    [!] {hit['label']} via '{hit['param']}' -> {hit['found']}")


def _port_scan(target, params, timeout, verbose, result, counter):
    """Probe loopback and common RFC1918 gateways, using a closed-port control."""
    param = params[0] if params else "url"
    found_ports = []

    for host in INTERNAL_HOSTS:
        control = request(with_params(target, {param: f"http://{host}:1/"}),
                          timeout=timeout)
        if control.error:
            continue
        control_len = len(control.body or "")
        control_status = control.status

        for port in INTERNAL_PORTS:
            if counter[0] >= MAX_REQUESTS:
                break
            counter[0] += 1
            started = time.time()
            resp = request(with_params(target, {param: f"http://{host}:{port}/"}),
                           timeout=timeout)
            if resp is None or resp.error:
                continue
            elapsed = time.time() - started
            body_len = len(resp.body or "")
            changed_status = (resp.status != control_status and
                              resp.status in (200, 301, 302, 400, 401, 403))
            grew = body_len > control_len + max(30, control_len * 0.25)
            slow = elapsed > max(0.5, control.elapsed * 2.5) and resp.status is not None
            if changed_status or grew or slow:
                found_ports.append({"host": host, "port": port,
                                    "status": resp.status, "length": body_len,
                                    "elapsed": round(elapsed, 2)})
                if verbose:
                    print(f"    [?] Internal {host}:{port} responded through SSRF")

    result["internal_ports"] = found_ports
    if found_ports:
        add_finding(result, finding(
            "ssrf_internal_ports",
            "SSRF reaches internal network services",
            "medium",
            target,
            "Reachable: " + ", ".join(
                f"{p['host']}:{p['port']}" for p in found_ports[:15]),
            description=("The fetcher can reach services bound to loopback or private "
                         "gateways, enabling interaction with admin panels, Redis, "
                         "Elasticsearch and cloud metadata from inside the host. "
                         "This is a time/length heuristic; verify each host:port manually."),
            remediation="Allowlist outbound destinations and block loopback/private ranges.",
            confidence=0.4,
            bug_class="ssrf",
            parameter=param,
            source="cloud_metadata",
        ))


def scan(target, timeout=10, verbose=False, workers=DEFAULT_WORKERS):
    target = normalize_url(target)
    result = new_result(target, internal_ports=[])
    result["checks_run"].extend(["cloud_metadata", "internal_port_scan"])

    params = _param_candidates(target)
    if not params:
        result["errors"].append("no candidate parameter found")
        return finalize(result)

    # Drop a broken baseline (DNS failure) early.
    probe = request(with_params(target, {params[0]: random_token()}), timeout=timeout)
    if probe.error:
        result["errors"].append(f"target unreachable: {probe.error}")
        return finalize(result)

    counter = [0]
    try:
        _probe_cloud(target, params, timeout, verbose, result, counter, workers=workers)
    except Exception as e:
        result["errors"].append(f"metadata: {e}")

    try:
        if not is_blocked(probe):
            _port_scan(target, params, timeout, verbose, result, counter)
    except Exception as e:
        result["errors"].append(f"port_scan: {e}")

    result["tested"] = counter[0]
    if not result["findings"]:
        result["note"] = ("No metadata response observed. If the endpoint returns a constant "
                          "error page for every URL, SSRF may still exist blind.")
    return finalize(result)


run_scanner = scan


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m modules.vuln.advanced.cloud_metadata <url-with-param>")
        sys.exit(1)
    print_report(scan(sys.argv[1], verbose=True), "Cloud Metadata SSRF")
