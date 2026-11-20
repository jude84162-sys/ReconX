"""Concurrency / correctness tests for the vuln-b advanced scanners.

Covers the bounded-pool parallelization added to:
  - modules/vuln/advanced/base.py             (parallel_map helper)
  - modules/vuln/advanced/cloud_metadata.py   (metadata probe loop)
  - modules/vuln/advanced/api_fuzzer.py        (discover_specs + fuzz_endpoints)
  - modules/vuln/advanced/xxe_lfi.py           (test_lfi params / test_xxe endpoints)
  - modules/vuln/bounty_checks.py              (ALL-runner)

Loopback only: every request is served by a 127.0.0.1 server that fakes the
vulnerable responses, so nothing touches the internet. Concurrency is asserted
by tracking the peak number of in-flight requests (a per-request delay makes the
overlap observable), never by wall-clock thresholds.
"""

import http.server
import io
import json
import threading
import time
import unittest
from contextlib import redirect_stdout
from urllib.parse import parse_qs, urlparse

from modules.vuln import bounty_checks
from modules.vuln.advanced import api_fuzzer, base, cloud_metadata, xxe_lfi


# ============================================================
# Loopback test server with concurrency tracking
# ============================================================

class _Tracker:
    def __init__(self):
        self.lock = threading.Lock()
        self.active = 0
        self.max_active = 0
        self.count = 0

    def enter(self):
        with self.lock:
            self.active += 1
            self.count += 1
            if self.active > self.max_active:
                self.max_active = self.active

    def leave(self):
        with self.lock:
            self.active -= 1


def _make_handler():
    class _H(http.server.BaseHTTPRequestHandler):
        def _serve(self, method):
            self.server.tracker.enter()
            try:
                if self.server.delay:
                    time.sleep(self.server.delay)
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                status, headers, payload = self.server.responder(
                    method, self.path, self.headers, body)
                raw = payload.encode() if isinstance(payload, str) else payload
                self.send_response(status)
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                if method != "HEAD":
                    self.wfile.write(raw)
            finally:
                self.server.tracker.leave()

        def do_GET(self):
            self._serve("GET")

        def do_POST(self):
            self._serve("POST")

        def do_HEAD(self):
            self._serve("HEAD")

        def log_message(self, *args):
            pass

    return _H


class FakeServer:
    """Loopback server whose responses are produced by ``responder``."""

    def __init__(self, responder, delay=0.02):
        self.tracker = _Tracker()
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _make_handler())
        self.httpd.tracker = self.tracker
        self.httpd.responder = responder
        self.httpd.delay = delay
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)

    @property
    def port(self):
        return self.httpd.server_address[1]

    def url(self, path="/"):
        return f"http://127.0.0.1:{self.port}{path}"


def _query_values(path):
    out = []
    for vals in parse_qs(urlparse(path).query, keep_blank_values=True).values():
        out.extend(vals)
    return out


# ============================================================
# base.parallel_map
# ============================================================

class ParallelMapTests(unittest.TestCase):
    def test_preserves_input_order(self):
        self.assertEqual(base.parallel_map([1, 2, 3, 4, 5], lambda x: x * x, workers=3),
                         [1, 4, 9, 16, 25])

    def test_exception_in_item_yields_none_without_failing_the_batch(self):
        def fn(x):
            if x == 3:
                raise ValueError("boom")
            return x

        self.assertEqual(base.parallel_map([1, 2, 3, 4], fn, workers=2),
                         [1, 2, None, 4])

    def test_empty_and_worker_clamp(self):
        self.assertEqual(base.parallel_map([], lambda x: x), [])
        self.assertEqual(base.parallel_map([7], lambda x: x, workers=0), [7])

    def test_runs_concurrently(self):
        tracker = _Tracker()

        def fn(_x):
            tracker.enter()
            time.sleep(0.03)
            tracker.leave()
            return _x

        base.parallel_map(list(range(10)), fn, workers=5)
        self.assertGreater(tracker.max_active, 1)


# ============================================================
# cloud_metadata
# ============================================================

def _clean_responder(method, path, headers, body):
    return 200, {"Content-Type": "text/html"}, "<html>clean</html>"


def _metadata_responder(method, path, headers, body):
    markers = "ami-id instance-id AccessKeyId vmId service-account droplet_id"
    for value in _query_values(path):
        if ("169.254" in value or "metadata" in value or "100.100" in value):
            return 200, {"Content-Type": "text/plain"}, markers
    return 200, {"Content-Type": "text/html"}, "<html>clean</html>"


class CloudMetadataTests(unittest.TestCase):
    def test_clean_target_probes_concurrently_and_finds_nothing(self):
        with FakeServer(_clean_responder) as srv:
            result = cloud_metadata.scan(srv.url("/"), timeout=5, workers=5)
        self.assertEqual(result["findings"], [])
        self.assertIn("note", result)
        self.assertGreater(srv.tracker.max_active, 1)

    def test_single_hit_is_the_first_in_iteration_order(self):
        with FakeServer(_metadata_responder) as srv:
            result = cloud_metadata.scan(srv.url("/"), timeout=5, workers=5)
        # Exactly one metadata finding, and it is param "url" x the first
        # CLOUD_TARGET (aws_imds), matching the serial loop's first hit.
        self.assertEqual(len(result["findings"]), 1)
        f = result["findings"][0]
        self.assertEqual(f["id"], "ssrf_aws_imds")
        self.assertEqual(f["parameter"], "url")
        self.assertGreater(srv.tracker.max_active, 1)

    def test_request_budget_is_still_enforced(self):
        # 11 query params -> _param_candidates caps at 10 -> 140 work items > 120.
        extra = "&".join(f"p{i}={i}" for i in range(11))
        with FakeServer(_clean_responder, delay=0.0) as srv:
            result = cloud_metadata.scan(srv.url("/?" + extra), timeout=5, workers=5)
        self.assertEqual(result["tested"], cloud_metadata.MAX_REQUESTS)
        self.assertTrue(any("budget exhausted" in e for e in result["errors"]))


# ============================================================
# api_fuzzer
# ============================================================

_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "t", "version": "1"},
    "paths": {
        "/items": {"get": {"parameters": [
            {"name": "q", "in": "query", "schema": {"type": "string"}}]}},
        "/users": {"get": {"parameters": [
            {"name": "id", "in": "query", "schema": {"type": "integer"}}]}},
        "/search": {"get": {"parameters": [
            {"name": "term", "in": "query"}]}},
        "/orders": {"get": {"parameters": [
            {"name": "ref", "in": "query"}]}},
    },
}
_SPEC_JSON = json.dumps(_SPEC)


def _api_responder(method, path, headers, body):
    p = urlparse(path).path
    if p == "/openapi.json":
        return 200, {"Content-Type": "application/json"}, _SPEC_JSON
    # Malformed (array/object) values crash the endpoint with a DB error.
    for value in _query_values(path):
        if "[" in value or "{" in value:
            return 500, {"Content-Type": "text/html"}, "DB error: SQLSTATE[42000] syntax"
    return 200, {"Content-Type": "text/html"}, "<html>ok</html>"


def _two_spec_responder(method, path, headers, body):
    p = urlparse(path).path
    if p in ("/swagger.json", "/openapi.json"):
        return 200, {"Content-Type": "application/json"}, _SPEC_JSON
    return 200, {"Content-Type": "text/html"}, "<html>ok</html>"


class ApiFuzzerTests(unittest.TestCase):
    def test_discover_specs_runs_concurrently_and_finds_spec(self):
        with FakeServer(_api_responder) as srv:
            specs = api_fuzzer.discover_specs(srv.url("/"), timeout=5, workers=5)
        urls = [s["url"] for s in specs]
        self.assertTrue(any(u.endswith("/openapi.json") for u in urls))
        self.assertGreater(srv.tracker.max_active, 1)

    def test_discover_specs_keeps_path_order(self):
        with FakeServer(_two_spec_responder) as srv:
            specs = api_fuzzer.discover_specs(srv.url("/"), timeout=5, workers=5)
        # /swagger.json precedes /openapi.json in API_SPEC_PATHS, so it stays first.
        self.assertTrue(specs[0]["url"].endswith("/swagger.json"))

    def test_fuzz_finds_type_mismatch_across_endpoints_concurrently(self):
        with FakeServer(_api_responder) as srv:
            result = api_fuzzer.scan(srv.url("/"), timeout=5, workers=5)
        ids = [f["id"] for f in result["findings"]]
        self.assertIn("api_spec_exposed", ids)
        self.assertTrue(any(i.startswith("api_type_mismatch_") for i in ids))
        self.assertGreater(result["tested"], 0)
        self.assertGreater(srv.tracker.max_active, 1)


# ============================================================
# xxe_lfi
# ============================================================

def _lfi_responder(method, path, headers, body):
    for value in _query_values(path):
        if "passwd" in value:
            return 200, {"Content-Type": "text/plain"}, "root:x:0:0:root:/root:/bin/bash"
    return 200, {"Content-Type": "text/html"}, "<html>home</html>"


def _xxe_responder(method, path, headers, body):
    if b"file:///etc/passwd" in (body or b""):
        return 200, {"Content-Type": "text/plain"}, "root:x:0:0:root:/root:/bin/bash"
    return 200, {"Content-Type": "application/xml"}, "<reconx>ok</reconx>"


class XxeLfiTests(unittest.TestCase):
    def test_lfi_flags_every_param_concurrently(self):
        with FakeServer(_lfi_responder) as srv:
            result = base.new_result(srv.url("/"))
            xxe_lfi.test_lfi(srv.url("/"), timeout=5, result=result, workers=5)
        params = {f["parameter"] for f in result["findings"]}
        self.assertEqual(params, set(xxe_lfi.LFI_PARAMS[:6]))
        self.assertTrue(all(f["id"].startswith("lfi_") for f in result["findings"]))
        self.assertGreater(srv.tracker.max_active, 1)

    def test_xxe_reports_one_critical_from_the_first_endpoint(self):
        with FakeServer(_xxe_responder) as srv:
            result = base.new_result(srv.url("/"))
            xxe_lfi.test_xxe(srv.url("/"), timeout=5, result=result, workers=5)
        findings = result["findings"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "critical")
        self.assertEqual(findings[0]["bug_class"], "xxe")
        self.assertEqual(findings[0]["url"], srv.url("/"))
        self.assertGreater(srv.tracker.max_active, 1)


# ============================================================
# bounty_checks ALL-runner
# ============================================================

_BOUNTY_CHECK_ORDER = [
    "vcs_exposed", "api_docs", "cors_misconfiguration",
    "open_redirect", "graphql_introspection", "jwt_issues",
]


def _bounty_responder(method, path, headers, body):
    p = urlparse(path).path
    if p == "/.git/HEAD":
        return 200, {"Content-Type": "text/plain"}, "ref: refs/heads/main\n"
    out = {"Content-Type": "text/html"}
    origin = headers.get("Origin")
    if origin:
        out["Access-Control-Allow-Origin"] = origin
        out["Access-Control-Allow-Credentials"] = "true"
    return 200, out, "<html>site</html>"


class BountyChecksTests(unittest.TestCase):
    def test_all_checks_run_concurrently_and_in_declared_order(self):
        with FakeServer(_bounty_responder) as srv:
            with redirect_stdout(io.StringIO()):
                result = bounty_checks.run_bounty_checks(srv.url("/"), workers=10, timeout=4)
        self.assertEqual(result["checks_run"], _BOUNTY_CHECK_ORDER)
        ids = [f["id"] for f in result["findings"]]
        self.assertTrue(any(i.startswith("vcs_") for i in ids))
        self.assertGreater(srv.tracker.max_active, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
