"""Concurrency/correctness tests for the vuln-a scanners.

Covers the parallelized SSRF / SSTI / CMDi scanners and the scanner_manager
``run_all`` default-worker change (findings 1, 26, 27, 29).

Everything binds to 127.0.0.1 only and never touches the internet. A small
loopback HTTP server counts in-flight requests (overall and split by payload
kind) so the tests can assert that:
  * param x payload probes actually run concurrently, and
  * command-injection *time-based* (sleep) probes never overlap.
"""

import io
import http.server
import threading
import time
import unittest
import urllib.parse
from contextlib import redirect_stdout

from modules.vuln.web import ssrf_scanner, ssti_scanner, cmdi_scanner
from modules.vuln import scanner_manager


def _classify(val):
    """Classify an injected value as a time-based or other probe."""
    if "sleep" in val or "ping " in val or "timeout" in val:
        return "time"
    return "other"


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        srv = self.server
        qs = urllib.parse.urlparse(self.path).query
        values = urllib.parse.parse_qs(qs)
        val = ""
        for vs in values.values():
            if vs:
                val = vs[0]
        kind = _classify(val)

        with srv.lock:
            srv.inflight += 1
            srv.cur[kind] = srv.cur.get(kind, 0) + 1
            srv.maxc = max(srv.maxc, srv.inflight)
            srv.maxkind[kind] = max(srv.maxkind.get(kind, 0), srv.cur[kind])
            srv.count[kind] = srv.count.get(kind, 0) + 1

        try:
            body_text, delay = srv.responder(val)
            if delay:
                time.sleep(delay)
            body = body_text.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionError):
            # Client (the scanner) timed out and closed the socket — expected in
            # the out_timeout test; don't let the server thread dump a traceback.
            pass
        finally:
            with srv.lock:
                srv.inflight -= 1
                srv.cur[kind] -= 1

    def log_message(self, *args):
        pass


class CountingServer:
    """Loopback server that records concurrency, with a pluggable responder."""

    def __init__(self, responder):
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.responder = responder
        self.httpd.lock = threading.Lock()
        self.httpd.inflight = 0
        self.httpd.maxc = 0
        self.httpd.cur = {}
        self.httpd.maxkind = {}
        self.httpd.count = {}
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

    @property
    def maxc(self):
        return self.httpd.maxc

    def maxkind(self, kind):
        return self.httpd.maxkind.get(kind, 0)

    def count(self, kind):
        return self.httpd.count.get(kind, 0)


# ---- responders -----------------------------------------------------------

def _clean(delay):
    def respond(val):
        return "<html>hello world</html>", delay
    return respond


def _ssrf_vuln(delay=0.0):
    def respond(val):
        if "file://" in val or "/etc/passwd" in val:
            return "root:x:0:0:root:/root:/bin/bash\n", delay
        return "<html>hello</html>", delay
    return respond


def _ssti_vuln(delay=0.0):
    def respond(val):
        # Simulate a Jinja2-style engine: evaluate 7*7 server-side, echo only
        # the result (never the raw payload).
        if "7*7" in val:
            return "result is 49 ok", delay
        return "<html>hello</html>", delay
    return respond


def _cmdi_output_vuln(output_delay=0.05):
    id_markers = (";id", "|id", "&&id", "`id`", "$(id)")

    def respond(val):
        if _classify(val) == "time":
            # Respond quickly so no time-based finding fires; keep a tiny delay
            # so overlaps would be observable *if* they happened (they must not).
            return "<html>hello</html>", 0.05
        if any(m in val for m in id_markers):
            return "uid=0(root) gid=0(root) groups=0(root)", output_delay
        return "<html>hello</html>", output_delay
    return respond


def _cmdi_time_vuln(sleep_delay=4.2):
    fired = {"done": False}
    lock = threading.Lock()

    def respond(val):
        if _classify(val) == "time":
            with lock:
                if not fired["done"]:
                    fired["done"] = True
                    return "<html>hello</html>", sleep_delay
            return "<html>hello</html>", 0.0
        return "<html>hello</html>", 0.0
    return respond


# ---- SSRF -----------------------------------------------------------------

class SsrfScannerTests(unittest.TestCase):
    def test_finding_on_vulnerable_single_param(self):
        with CountingServer(_ssrf_vuln()) as srv:
            res = ssrf_scanner.scan(srv.url("/?url=x"), workers=5)
        self.assertEqual(res["tested_params"], 1)
        self.assertEqual(res["tested_payloads"], len(ssrf_scanner.SSRF_PAYLOADS))
        self.assertEqual(len(res["findings"]), 1)
        f = res["findings"][0]
        self.assertEqual(f["parameter"], "url")
        self.assertEqual(f["severity"], "critical")
        self.assertIn(f["bug_class"], ("ssrf", "ssrf_file_read"))

    def test_clean_target_no_findings(self):
        with CountingServer(_clean(0.0)) as srv:
            res = ssrf_scanner.scan(srv.url("/?url=x"), workers=5)
        self.assertEqual(res["findings"], [])

    def test_default_params_run_concurrently(self):
        with CountingServer(_clean(0.05)) as srv:
            res = ssrf_scanner.scan(srv.url("/"), workers=5)
        # param-less -> SSRF_PARAMS[:10]
        self.assertEqual(res["tested_params"], 10)
        self.assertEqual(res["tested_payloads"], 10 * len(ssrf_scanner.SSRF_PAYLOADS))
        self.assertEqual(res["findings"], [])
        self.assertGreaterEqual(srv.maxc, 2)
        self.assertLessEqual(srv.maxc, 5)

    def test_single_worker_is_serial(self):
        with CountingServer(_clean(0.02)) as srv:
            ssrf_scanner.scan(srv.url("/?url=x"), workers=1)
        self.assertEqual(srv.maxc, 1)


# ---- SSTI -----------------------------------------------------------------

class SstiScannerTests(unittest.TestCase):
    def test_finding_reports_lowest_index_engine(self):
        with CountingServer(_ssti_vuln()) as srv:
            res = ssti_scanner.scan(srv.url("/?name=x"), workers=5)
        self.assertEqual(res["tested_params"], 1)
        self.assertEqual(res["tested_payloads"], len(ssti_scanner.SSTI_PAYLOADS))
        self.assertEqual(len(res["findings"]), 1)
        f = res["findings"][0]
        self.assertEqual(f["parameter"], "name")
        # {{7*7}} (Jinja2/Twig) is payload index 0 -> must be the reported one.
        self.assertEqual(f["engine"], "Jinja2/Twig")
        self.assertEqual(f["severity"], "critical")

    def test_clean_target_no_findings(self):
        with CountingServer(_clean(0.0)) as srv:
            res = ssti_scanner.scan(srv.url("/?name=x"), workers=5)
        self.assertEqual(res["findings"], [])

    def test_default_params_run_concurrently(self):
        with CountingServer(_clean(0.05)) as srv:
            res = ssti_scanner.scan(srv.url("/"), workers=5)
        self.assertEqual(res["tested_params"], 8)
        self.assertEqual(res["tested_payloads"], 8 * len(ssti_scanner.SSTI_PAYLOADS))
        self.assertEqual(res["findings"], [])
        self.assertGreaterEqual(srv.maxc, 2)
        self.assertLessEqual(srv.maxc, 5)


# ---- CMDi -----------------------------------------------------------------

class CmdiScannerTests(unittest.TestCase):
    def test_output_finding_and_time_payloads_stay_serial(self):
        with CountingServer(_cmdi_output_vuln(output_delay=0.06)) as srv:
            res = cmdi_scanner.scan(srv.url("/?cmd=x"), workers=5)
        self.assertEqual(res["tested_params"], 1)
        self.assertEqual(
            res["tested_payloads"],
            len(cmdi_scanner.TIME_PAYLOADS) + len(cmdi_scanner.OUTPUT_PAYLOADS),
        )
        self.assertEqual(len(res["findings"]), 1)
        f = res["findings"][0]
        self.assertEqual(f["parameter"], "cmd")
        self.assertIn("output-based", f["title"])
        self.assertEqual(f["bug_class"], "command_injection")
        # Time-based probes must never run concurrently against the same target.
        self.assertLessEqual(srv.maxkind("time"), 1)
        self.assertGreaterEqual(srv.count("time"), 2)  # several time probes issued
        # Output probes should be parallelized.
        self.assertGreaterEqual(srv.maxkind("other"), 2)

    def test_time_based_finding_detected(self):
        with CountingServer(_cmdi_time_vuln(sleep_delay=4.2)) as srv:
            res = cmdi_scanner.scan(srv.url("/?host=x"), workers=5)
        self.assertEqual(len(res["findings"]), 1)
        f = res["findings"][0]
        self.assertEqual(f["parameter"], "host")
        self.assertIn("time-based", f["title"])
        self.assertEqual(f["bug_class"], "command_injection")
        self.assertEqual(f["confidence"], 0.80)
        # A time hit short-circuits the param -> the time probes never overlap.
        self.assertLessEqual(srv.maxkind("time"), 1)

    def test_output_timeout_is_applied(self):
        # Output responses are slow; a tiny out_timeout must cut them off, so no
        # output finding is reported even though the marker is present.
        with CountingServer(_cmdi_output_vuln(output_delay=1.0)) as srv:
            res_short = cmdi_scanner.scan(
                srv.url("/?cmd=x"), workers=5, out_timeout=0.3)
        self.assertEqual(res_short["findings"], [])

        with CountingServer(_cmdi_output_vuln(output_delay=0.05)) as srv:
            res_ok = cmdi_scanner.scan(
                srv.url("/?cmd=x"), workers=5, out_timeout=5)
        self.assertEqual(len(res_ok["findings"]), 1)

    def test_no_params_errors(self):
        with CountingServer(_clean(0.0)) as srv:
            res = cmdi_scanner.scan(srv.url("/"), workers=5)
        self.assertEqual(res["findings"], [])
        self.assertIn("no parameters", res["error"])


# ---- scanner_manager.run_all default workers ------------------------------

class RunAllWorkerDefaultTests(unittest.TestCase):
    def setUp(self):
        self._orig = scanner_manager.run_scanner

        def _stub(key, target, timeout=300, verbose=False):
            return {"findings": [], "scanner": key}

        scanner_manager.run_scanner = _stub

    def tearDown(self):
        scanner_manager.run_scanner = self._orig

    def _workers_line(self, **kwargs):
        buf = io.StringIO()
        with redirect_stdout(buf):
            scanner_manager.run_all("http://127.0.0.1/", verbose=True, **kwargs)
        return buf.getvalue()

    def test_default_scanners_use_six_workers(self):
        out = self._workers_line()
        self.assertIn("workers=6", out)

    def test_worker_count_matches_scanner_count(self):
        out = self._workers_line(scanners=["ssrf", "ssti"])
        self.assertIn("workers=2", out)

    def test_worker_count_capped_at_six(self):
        out = self._workers_line(scanners=[
            "ssrf", "ssti", "cmdi", "xss", "jwt", "sqli", "graphql", "buckets"])
        self.assertIn("workers=6", out)

    def test_explicit_workers_respected(self):
        out = self._workers_line(scanners=["ssrf", "ssti", "cmdi"], workers=3)
        self.assertIn("workers=3", out)


if __name__ == "__main__":
    unittest.main()
