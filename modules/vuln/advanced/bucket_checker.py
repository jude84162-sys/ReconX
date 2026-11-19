# modules/vuln/advanced/bucket_checker.py
"""ReconX - Cloud storage bucket discovery and permission checker.

Generates bucket-name permutations from the target domain and checks:
  * AWS S3        virtual-host listing
  * Azure Blob    container enumeration
  * GCP Storage   JSON object listing

Public listing => high (files enumerable). "Exists but private" => info.
Public WRITE is never tested: uploading to a third-party bucket is an
unauthorized modification and is left to a manual engagement step.
"""

import concurrent.futures
import urllib.parse

from modules.utils.http_client import normalize_url, request
from modules.vuln.advanced.base import add_finding, finalize, finding, new_result, print_report

SUFFIXES = [
    "assets", "static", "media", "uploads", "files", "images", "img", "cdn",
    "data", "backup", "backups", "logs", "public", "private", "dev", "develop",
    "staging", "stage", "prod", "production", "test", "app", "web", "downloads",
]

MAX_NAMES = 24


def _base_names(target):
    parsed = urllib.parse.urlparse(normalize_url(target))
    host = (parsed.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    base = host.split(".")[0]
    stem = host.replace(".", "-")
    names = [base, stem, f"{base}-bucket", f"{stem}-bucket"]

    for suffix in SUFFIXES:
        names.append(f"{base}-{suffix}")
        if stem != base:
            names.append(f"{stem}-{suffix}")

    # Deduplicate, keep valid bucket characters, cap request volume.
    clean = []
    for name in names:
        name = name.strip("-_.")
        if name and 3 <= len(name) <= 63 and all(
                c.isalnum() or c in "-._" for c in name):
            if name not in clean:
                clean.append(name)
    return clean[:MAX_NAMES]


def _check_s3(name, timeout):
    url = f"https://{name}.s3.amazonaws.com/?max-keys=2"
    resp = request(url, timeout=timeout)
    if resp.error:
        return None
    body = resp.body or ""
    if resp.status == 200 and "<ListBucketResult" in body:
        keys = body.count("<Key>")
        return {"provider": "AWS S3", "url": url, "public": "list",
                "evidence": f"HTTP 200 ListBucketResult, {keys} key(s) returned"}
    if resp.status == 403 and ("AccessDenied" in body or "AllAccessDisabled" in body):
        return {"provider": "AWS S3", "url": url, "public": "private",
                "evidence": "HTTP 403 AccessDenied"}
    if resp.status == 404 and "NoSuchBucket" in body:
        return None
    return None


def _check_azure(name, timeout):
    url = f"https://{name}.blob.core.windows.net/?comp=list"
    resp = request(url, timeout=timeout)
    if resp.error:
        return None
    body = resp.body or ""
    if resp.status == 200 and "EnumerationResults" in body:
        containers = body.count("<Container>")
        return {"provider": "Azure Blob", "url": url, "public": "list",
                "evidence": f"HTTP 200 container enumeration, {containers} container(s)"}
    if resp.status == 403:
        return {"provider": "Azure Blob", "url": url, "public": "private",
                "evidence": "HTTP 403"}
    return None


def _check_gcp(name, timeout):
    url = f"https://storage.googleapis.com/storage/v1/b/{name}/o?maxResults=2"
    resp = request(url, timeout=timeout)
    if resp.error:
        return None
    if resp.status == 200:
        data = resp.json()
        if isinstance(data, dict) and data.get("kind", "").startswith("storage#"):
            items = data.get("items") or []
            return {"provider": "GCP Storage", "url": url, "public": "list",
                    "evidence": f"HTTP 200 object listing ({len(items)} item(s) sampled)"}
    if resp.status == 403:
        return {"provider": "GCP Storage", "url": url, "public": "private",
                "evidence": "HTTP 403"}
    return None


def _check_name(name, timeout):
    findings = []
    for checker in (_check_s3, _check_azure, _check_gcp):
        try:
            hit = checker(name, timeout)
        except Exception:
            hit = None
        if hit:
            hit["bucket"] = name
            findings.append(hit)
    return findings


def scan(target, timeout=10, verbose=False):
    target = normalize_url(target)
    result = new_result(target, buckets=[], tested=0)
    result["checks_run"].append("bucket_permutations")

    names = _base_names(target)
    result["tested"] = len(names)

    hits = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(_check_name, n, timeout): n for n in names}
        for future in concurrent.futures.as_completed(futures, timeout=180):
            try:
                hits.extend(future.result() or [])
            except Exception:
                continue

    for hit in hits:
        result["buckets"].append(hit)
        public = hit["public"] == "list"
        add_finding(result, finding(
            f"bucket_{hit['provider'].lower().replace(' ', '_')}_{hit['bucket']}",
            f"{'Public' if public else 'Discovered'} {hit['provider']} bucket: {hit['bucket']}",
            "high" if public else "info",
            hit["url"],
            hit["evidence"],
            description=("The bucket is world-listable: object names, sizes and metadata "
                         "are exposed. Check the objects for customer data, backups and "
                         "source archives. Write access was NOT tested." if public else
                         "The bucket exists but listing is denied. Note it for the "
                         "engagement asset inventory; it may still allow object GET."),
            remediation=("Enable S3 Block Public Access / Azure 'Allow Blob public access: "
                         "off' / GCP uniform bucket-level access, and audit object ACLs."),
            confidence=0.95 if public else 0.6,
            bug_class="cloud_storage_misconfiguration",
            provider=hit["provider"],
            bucket=hit["bucket"],
            source="bucket_checker",
        ))
        if verbose:
            print(f"    {'[!]' if public else '[i]'} {hit['provider']} {hit['bucket']} "
                  f"({hit['public']})")

    if not hits:
        result["note"] = ("No bucket found for the generated permutations. Supply an "
                          "organisation-specific wordlist for wider coverage.")
        if verbose:
            print("  [OK] No buckets discovered")

    return finalize(result)


run_scanner = scan


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m modules.vuln.advanced.bucket_checker <domain>")
        sys.exit(1)
    print_report(scan(sys.argv[1], verbose=True), "Bucket & Asset Permissions")
