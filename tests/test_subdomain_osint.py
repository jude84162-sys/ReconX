"""Tests for crt.sh sharing, domain OSINT staging and subfinder_clone.

Everything binds to 127.0.0.1 or is monkeypatched: no test touches the
internet or a real DNS resolver.
"""

import http.server
import io
import json
import os
import socket
import threading
import time
import unittest
import urllib.error
from contextlib import redirect_stdout
from unittest import mock

from modules.utils import crtsh
from modules.web import domain_osint, subfinder_clone
from modules.web import subdomain_enum

DOMAIN = "example.test"


class _CrtHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        srv = self.server
        with srv.lock:
            srv.hits.append(self.path)
            n = len(srv.hits)
        status, body, delay = srv.respond(self.path, "output=json" in self.path, n)
        if delay:
            time.sleep(delay)
        if isinstance(body, str):
            body = body.encode()
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass

    def log_message(self, *args):
        pass


class CrtServer:
    """Loopback stand-in for crt.sh; ``respond(path, is_json, n)`` scripts it."""

    def __init__(self, respond):
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _CrtHandler)
        self.httpd.respond = respond
        self.httpd.hits = []
        self.httpd.lock = threading.Lock()
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def hits(self):
        with self.httpd.lock:
            return list(self.httpd.hits)

    def __enter__(self):
        self.thread.start()
        port = self.httpd.server_address[1]
        self._patches = [
            mock.patch.object(crtsh, "CRTSH_URL", f"http://127.0.0.1:{port}/"),
            mock.patch.dict(os.environ, {"no_proxy": "127.0.0.1,localhost",
                                         "NO_PROXY": "127.0.0.1,localhost"}),
        ]
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in reversed(self._patches):
            p.stop()
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


def _crt_json(*names):
    return json.dumps([{"id": i, "name_value": n, "common_name": n.split("\n")[0]}
                       for i, n in enumerate(names)])


class CrtshLookupTests(unittest.TestCase):
    def setUp(self):
        crtsh.clear_cache()

    def tearDown(self):
        crtsh.clear_cache()

    def test_json_names_are_filtered_and_lowercased(self):
        body = _crt_json("WWW.Example.test\napi.example.test", "*.example.test",
                         "example.test", "other.test", "a.b.example.test")
        with CrtServer(lambda path, is_json, n: (200, body, 0)) as srv:
            subs = crtsh.crtsh_lookup(DOMAIN, timeout=5)
        self.assertEqual(subs, {"www.example.test", "api.example.test", "a.b.example.test"})
        self.assertEqual(len(srv.hits), 1)
        self.assertIn("output=json", srv.hits[0])

    def test_concurrent_callers_share_one_request_and_cache(self):
        body = _crt_json("a.example.test", "b.example.test")
        results = []
        with CrtServer(lambda path, is_json, n: (200, body, 0.4)) as srv:
            threads = [threading.Thread(
                target=lambda: results.append(crtsh.crtsh_lookup(DOMAIN, timeout=5)))
                for _ in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(10)
            again = crtsh.crtsh_lookup(DOMAIN, timeout=5)
            hits = srv.hits
        self.assertEqual(len(hits), 1)
        self.assertEqual(len(results), 5)
        for r in results + [again]:
            self.assertEqual(r, {"a.example.test", "b.example.test"})

    def test_timeout_does_not_fall_back_to_html_and_is_not_cached(self):
        with CrtServer(lambda path, is_json, n: (200, "[]", 2.0)) as srv:
            start = time.monotonic()
            subs = crtsh.crtsh_lookup(DOMAIN, timeout=0.5)
            elapsed = time.monotonic() - start
            first_hits = srv.hits
            crtsh.crtsh_lookup(DOMAIN, timeout=0.5)
            second_hits = srv.hits
        self.assertEqual(subs, set())
        self.assertLess(elapsed, 1.5)
        self.assertEqual(len(first_hits), 1)
        self.assertIn("output=json", first_hits[0])
        self.assertEqual(len(second_hits), 2, "a timed-out lookup must not be cached")

    def test_502_gets_one_quick_retry_then_html_fallback(self):
        html = ("<TABLE><TR><TD>a.example.test<BR>b.example.test</TD></TR>"
                "<TR><TD>*.example.test</TD></TR></TABLE>")

        def respond(path, is_json, n):
            return (502, "bad gateway", 0) if is_json else (200, html, 0)

        with mock.patch.object(crtsh, "RETRY_DELAY", 0.01), CrtServer(respond) as srv:
            subs = crtsh.crtsh_lookup(DOMAIN, timeout=10)
            hits = srv.hits
        self.assertEqual(subs, {"a.example.test", "b.example.test"})
        self.assertEqual(["output=json" in h for h in hits], [True, True, False])

    def test_503_then_success_uses_json(self):
        def respond(path, is_json, n):
            return (503, "busy", 0) if n == 1 else (200, _crt_json("x.example.test"), 0)

        with mock.patch.object(crtsh, "RETRY_DELAY", 0.01), CrtServer(respond) as srv:
            subs = crtsh.crtsh_lookup(DOMAIN, timeout=10)
            hits = srv.hits
        self.assertEqual(subs, {"x.example.test"})
        self.assertEqual(len(hits), 2)
        self.assertTrue(all("output=json" in h for h in hits))

    def test_429_is_neither_retried_nor_sent_to_html(self):
        with CrtServer(lambda path, is_json, n: (429, "slow down", 0)) as srv:
            subs = crtsh.crtsh_lookup(DOMAIN, timeout=5)
            hits = srv.hits
        self.assertEqual(subs, set())
        self.assertEqual(len(hits), 1)

    def test_unparseable_json_falls_back_to_html(self):
        def respond(path, is_json, n):
            if is_json:
                return 200, "<html>Sorry, something went wrong</html>", 0
            return 200, "<TD>mail.example.test</TD>", 0

        with CrtServer(respond) as srv:
            subs = crtsh.crtsh_lookup(DOMAIN, timeout=5)
            hits = srv.hits
        self.assertEqual(subs, {"mail.example.test"})
        self.assertEqual(len(hits), 2)

    def test_empty_json_list_is_final_and_cached(self):
        with CrtServer(lambda path, is_json, n: (200, "[]", 0)) as srv:
            self.assertEqual(crtsh.crtsh_lookup(DOMAIN, timeout=5), set())
            self.assertEqual(crtsh.crtsh_lookup(DOMAIN, timeout=5), set())
            hits = srv.hits
        self.assertEqual(len(hits), 1)

    def test_oversized_body_is_bounded_and_names_salvaged(self):
        names = [f"h{i}.example.test" for i in range(400)]
        body = _crt_json(*["\n".join(names[i:i + 2]) for i in range(0, 400, 2)])
        with CrtServer(lambda path, is_json, n: (200, body, 0)) as srv:
            subs = crtsh.crtsh_lookup(DOMAIN, timeout=5, max_bytes=4000)
            hits = srv.hits
        self.assertEqual(len(hits), 1, "a truncated body must not trigger the HTML query")
        self.assertTrue(subs)
        self.assertTrue(subs <= set(names), subs - set(names))
        self.assertLess(len(subs), len(names))

    def test_domain_osint_and_subfinder_share_the_query(self):
        body = _crt_json("shared.example.test")
        out = {}
        with CrtServer(lambda path, is_json, n: (200, body, 0.4)) as srv:
            t1 = threading.Thread(target=lambda: out.__setitem__(
                "osint", domain_osint._crtsh_subdomains(DOMAIN, timeout=5)))
            t2 = threading.Thread(target=lambda: out.__setitem__(
                "subfinder", subfinder_clone._src_crtsh(DOMAIN)))
            t1.start()
            t2.start()
            t1.join(10)
            t2.join(10)
            hits = srv.hits
        self.assertEqual(len(hits), 1)
        self.assertEqual(out["osint"], {"shared.example.test"})
        self.assertEqual(out["subfinder"], {"shared.example.test"})


class VerifySubdomainsTests(unittest.TestCase):
    def setUp(self):
        self.release = threading.Event()

    def tearDown(self):
        self.release.set()

    def _resolver(self, hostname, timeout=3):
        if hostname.startswith("slow"):
            self.release.wait(5)
            return "10.0.0.9"
        if hostname.startswith("live"):
            return "10.0.0.1"
        return None

    def test_deadline_reports_stragglers_as_unverified(self):
        subs = {"live1", "live2.example.test", "dead", "slow1", "slow2"}
        with mock.patch.object(domain_osint, "_resolve_a_only", self._resolver):
            start = time.monotonic()
            verified, unverified = domain_osint._verify_subdomains_ex(
                DOMAIN, subs, workers=8, deadline=0.3)
            elapsed = time.monotonic() - start
        self.assertLess(elapsed, 1.5, "verification must not wait for stragglers")
        self.assertEqual(sorted(v["hostname"] for v in verified),
                         ["live1.example.test", "live2.example.test"])
        self.assertEqual(unverified, ["slow1.example.test", "slow2.example.test"])
        for entry in verified:
            self.assertEqual(set(entry), {"hostname", "ip", "ipv4", "ipv6"})

    def test_legacy_wrapper_returns_verified_list(self):
        with mock.patch.object(domain_osint, "_resolve_a_only", self._resolver):
            verified = domain_osint._verify_subdomains(DOMAIN, {"live1", "dead"})
        self.assertEqual(verified, [{"hostname": "live1.example.test", "ip": "10.0.0.1",
                                     "ipv4": ["10.0.0.1"], "ipv6": []}])


class RunDomainOsintTests(unittest.TestCase):
    ORIGINAL_KEYS = {"timestamp", "domain", "ips", "reverse_dns", "dns_records",
                     "whois", "subdomains", "sources_used", "errors"}

    def _patch(self, **fns):
        patches = [mock.patch.object(domain_osint, name, fn) for name, fn in fns.items()]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def _run(self, **kwargs):
        with redirect_stdout(io.StringIO()):
            return domain_osint.run_domain_osint(DOMAIN, **kwargs)

    def test_stages_run_concurrently(self):
        def slow(value):
            def fn(*a, **k):
                time.sleep(0.4)
                return value
            return fn

        self._patch(
            _resolve_all_ips=lambda d, timeout=3: {"A": ["10.0.0.1"], "AAAA": []},
            _reverse_dns=slow("host.example.test"),
            _get_dns_records=slow({"A": [{"name": DOMAIN, "ttl": 1, "data": "10.0.0.1"}]}),
            _whois_socket=slow("Registrar: Test Registrar\nCreation Date: 2001-01-01\n"),
            _crtsh_subdomains=slow({"a.example.test", "b.example.test"}),
            _resolve_a_only=lambda h, timeout=3: "10.0.0.2" if h.startswith("a.") else None,
        )
        start = time.monotonic()
        result = self._run()
        elapsed = time.monotonic() - start

        self.assertLess(elapsed, 1.2, "four 0.4 s stages should overlap")
        self.assertTrue(self.ORIGINAL_KEYS <= set(result))
        self.assertEqual(result["unverified"], [])
        self.assertEqual(result["ips"], {"A": ["10.0.0.1"], "AAAA": []})
        self.assertEqual(result["reverse_dns"], {"10.0.0.1": "host.example.test"})
        self.assertIn("A", result["dns_records"])
        self.assertEqual(result["whois"]["registrar"], "Test Registrar")
        self.assertEqual([s["hostname"] for s in result["subdomains"]], ["a.example.test"])
        self.assertEqual(result["sources_used"], ["whois", "crt.sh (2 found)"])

    def test_verification_starts_without_waiting_for_whois(self):
        verification_started = threading.Event()

        def whois(domain, timeout=15):
            verification_started.wait(5)
            return None

        def resolve(hostname, timeout=3):
            verification_started.set()
            return "10.0.0.3"

        self._patch(
            _resolve_all_ips=lambda d, timeout=3: {"A": [], "AAAA": []},
            _get_dns_records=lambda d: {},
            _whois_socket=whois,
            _crtsh_subdomains=lambda d, timeout=30: {"c.example.test"},
            _resolve_a_only=resolve,
        )
        start = time.monotonic()
        result = self._run()
        self.assertLess(time.monotonic() - start, 3)
        self.assertEqual([s["hostname"] for s in result["subdomains"]], ["c.example.test"])
        self.assertEqual(result["whois"]["registrar"], None)

    def test_ips_kwarg_skips_resolution_and_stage_errors_are_recorded(self):
        def boom(*a, **k):
            raise RuntimeError("doh down")

        def must_not_resolve(*a, **k):
            raise AssertionError("domain must not be resolved again")

        self._patch(
            _resolve_all_ips=must_not_resolve,
            _reverse_dns=lambda ip, timeout=5: None,
            _get_dns_records=boom,
            _whois_socket=lambda d, timeout=15: None,
            _crtsh_subdomains=lambda d, timeout=30: set(),
        )
        result = self._run(ips={"A": ["10.0.0.7"], "AAAA": ["::1"]})
        self.assertEqual(result["ips"], {"A": ["10.0.0.7"], "AAAA": ["::1"]})
        self.assertEqual(result["dns_records"], {})
        self.assertTrue(any("doh down" in e for e in result["errors"]), result["errors"])
        self.assertEqual(result["subdomains"], [])


def _no_ips():
    return {"A": [], "AAAA": []}


class SubfinderCloneTests(unittest.TestCase):
    SOURCES = ("_src_crtsh", "_src_hackertarget", "_src_rapiddns", "_src_alienvault",
               "_src_urlscan", "_src_webarchive", "_src_threatcrowd")

    def setUp(self):
        self.release = threading.Event()

    def tearDown(self):
        self.release.set()

    def _patch(self, resolver, **sources):
        fns = {name: (lambda domain: set()) for name in self.SOURCES}
        fns.update(sources)
        fns["_resolve_all"] = resolver
        for name, fn in fns.items():
            p = mock.patch.object(subfinder_clone, name, fn)
            p.start()
            self.addCleanup(p.stop)

    def _run(self, **kwargs):
        kwargs.setdefault("verbose", False)
        with redirect_stdout(io.StringIO()):
            return subfinder_clone.run_subfinder_clone(DOMAIN, **kwargs)

    def test_wildcard_zone_drops_bruteforce_hits(self):
        def resolver(hostname, timeout=4):
            if hostname == "api.example.test":
                return {"A": ["10.0.0.5"], "AAAA": []}
            if hostname.endswith("." + DOMAIN):
                return {"A": ["10.9.9.9"], "AAAA": []}
            return _no_ips()

        self._patch(resolver, _src_hackertarget=lambda d: {"www.example.test"})
        result = self._run()

        by_host = {s["hostname"]: s for s in result["subdomains"]}
        self.assertTrue(result["wildcard"])
        self.assertEqual(result["wildcard_ips"], ["10.9.9.9"])
        self.assertEqual(set(by_host), {"api.example.test", "www.example.test"})
        self.assertEqual(by_host["api.example.test"]["sources"], ["bruteforce"])
        self.assertEqual(by_host["www.example.test"]["sources"], ["hackertarget"])
        self.assertEqual(result["by_source"]["bruteforce"], 1)
        unique_words = len(set(subfinder_clone.WORDLIST))
        self.assertEqual(result["wildcard_filtered"], unique_words - 1)
        self.assertEqual(result["total"], 2)

    def test_no_wildcard_keeps_bruteforce_hits(self):
        real = {"api.example.test": "10.0.0.5", "mail.example.test": "10.0.0.6"}

        def resolver(hostname, timeout=4):
            if hostname in real:
                return {"A": [real[hostname]], "AAAA": []}
            return _no_ips()

        self._patch(resolver)
        result = self._run()
        self.assertFalse(result["wildcard"])
        self.assertEqual(result["wildcard_ips"], [])
        self.assertEqual(result["wildcard_filtered"], 0)
        self.assertEqual({s["hostname"] for s in result["subdomains"]}, set(real))
        for s in result["subdomains"]:
            self.assertEqual(s["confidence"]["level"], "HIGH")
            self.assertEqual(s["ip"], real[s["hostname"]])

    def test_slow_passive_source_is_cut_at_the_deadline(self):
        def slow_source(domain):
            self.release.wait(5)
            return {"late.example.test"}

        self._patch(lambda h, timeout=4: _no_ips(),
                    _src_webarchive=slow_source,
                    _src_alienvault=lambda d: {"early.example.test"})
        start = time.monotonic()
        result = self._run(bruteforce=False, passive_timeout=0.3)
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 2)
        self.assertIn("webarchive: timeout after 0.3s", result["errors"])
        self.assertEqual([s["hostname"] for s in result["subdomains"]], ["early.example.test"])
        self.assertNotIn("webarchive", result["by_source"])

    def test_names_are_resolved_while_slower_sources_run(self):
        def slow_source(domain):
            self.release.wait(5)
            return {"slow.example.test"}

        def resolver(hostname, timeout=4):
            if hostname == "fast.example.test":
                self.release.set()
                return {"A": ["10.0.0.8"], "AAAA": []}
            return _no_ips()

        self._patch(resolver,
                    _src_hackertarget=lambda d: {"fast.example.test"},
                    _src_webarchive=slow_source)
        start = time.monotonic()
        result = self._run(bruteforce=False, passive_timeout=10)
        self.assertLess(time.monotonic() - start, 3,
                        "resolution should start before the slowest source answers")
        by_host = {s["hostname"]: s for s in result["subdomains"]}
        self.assertEqual(by_host["fast.example.test"]["ip"], "10.0.0.8")
        self.assertIn("slow.example.test", by_host)

    def test_subdomain_enum_exposes_wildcard_flag(self):
        def resolver(hostname, timeout=4):
            if hostname.endswith("." + DOMAIN):
                return {"A": ["10.9.9.9"], "AAAA": []}
            return _no_ips()

        self._patch(resolver)
        with redirect_stdout(io.StringIO()):
            result = subdomain_enum.run_subdomain_enum(DOMAIN)
        self.assertTrue(result["wildcard"])
        self.assertEqual(result["wildcard_ips"], ["10.9.9.9"])
        self.assertEqual(result["subdomains"], [])
        self.assertEqual(result["total_unique"], 0)


class _FakeResponse:
    def __init__(self, body):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, n=-1):
        return self._body


class FetchRetryTests(unittest.TestCase):
    def _fetch_with(self, outcomes):
        calls = []
        sleeps = []

        def fake_urlopen(req, timeout=None, context=None):
            calls.append(req.full_url)
            outcome = outcomes[min(len(calls), len(outcomes)) - 1]
            if isinstance(outcome, BaseException):
                raise outcome
            return _FakeResponse(outcome)

        with mock.patch("urllib.request.urlopen", fake_urlopen), \
                mock.patch("time.sleep", lambda s: sleeps.append(s)):
            body = subfinder_clone._fetch("https://source.invalid/x", timeout=1)
        return body, calls, sleeps

    def test_timeouts_are_not_retried(self):
        for exc in (urllib.error.URLError(socket.timeout("timed out")),
                    socket.timeout("The read operation timed out")):
            with self.subTest(exc=exc):
                body, calls, sleeps = self._fetch_with([exc])
                self.assertIsNone(body)
                self.assertEqual(len(calls), 1)
                self.assertEqual(sleeps, [])

    def test_connection_reset_is_retried_once(self):
        body, calls, sleeps = self._fetch_with([ConnectionResetError("reset"), b"ok"])
        self.assertEqual(body, "ok")
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(sleeps), 1)

    def test_server_error_is_retried_then_body_returned(self):
        err = urllib.error.HTTPError("https://source.invalid/x", 503, "busy", {},
                                     io.BytesIO(b"busy"))
        body, calls, _ = self._fetch_with([err, b"fine"])
        self.assertEqual(body, "fine")
        self.assertEqual(len(calls), 2)

    def test_client_error_body_returned_without_retry(self):
        err = urllib.error.HTTPError("https://source.invalid/x", 404, "nope", {},
                                     io.BytesIO(b"not found"))
        body, calls, sleeps = self._fetch_with([err])
        self.assertEqual(body, "not found")
        self.assertEqual(len(calls), 1)
        self.assertEqual(sleeps, [])


if __name__ == "__main__":
    unittest.main()
