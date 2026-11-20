"""Keep-alive pool in modules.utils.http_client and the web finders that use it.

Everything binds to 127.0.0.1; nothing here touches the internet.
"""

import http.server
import json
import os
import threading
import time
import unittest
from unittest import mock

from modules.utils import http_client as hc
from modules.web import attack_surface, login_finder, param_finder, register_finder


class _KAHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ReconXTest/1.0"
    sys_version = ""

    def setup(self):
        super().setup()
        self.requests_on_conn = 0
        with self.server.lock:
            self.server.connections += 1

    def finish(self):
        super().finish()
        with self.server.lock:
            self.server.closed += 1

    def _record(self):
        self.requests_on_conn += 1
        with self.server.lock:
            self.server.paths.append(self.path)
            self.server.conn_headers.append(self.headers.get("Connection"))

    def _send(self, status, body, ctype="text/html; charset=utf-8", extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        self._record()
        path = self.path.split("?", 1)[0]
        if path == "/redir":
            self._send(302, b"", extra={"Location": "/page"})
        elif path == "/missing":
            self._send(404, b"<html>nope</html>")
        elif path == "/big":
            self._send(200, b"A" * 5000)
        elif path == "/chunked":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for part in (b"hello ", b"chunked ", b"world"):
                self.wfile.write(b"%x\r\n%s\r\n" % (len(part), part))
            self.wfile.write(b"0\r\n\r\n")
        elif path == "/flaky":
            if self.requests_on_conn > 1:
                # A server that already dropped this idle connection.
                self.close_connection = True
                return
            self._send(200, b"fresh")
        elif path == "/always-drop":
            self.close_connection = True
        elif path == "/login":
            self._send(200, b"<html><title>Login</title><form action='/login'>"
                            b"<input type='password' name='password'></form></html>")
        elif path == "/register":
            self._send(200, b"<html><title>Sign up</title><form action='/register'>"
                            b"<input type='password' name='password'></form></html>")
        elif path == "/":
            query = self.path.split("?", 1)[1] if "?" in self.path else ""
            body = b"<html><body>base page</body></html>"
            if "q=" in query:
                body = ("<html><body>you searched " + query + "</body></html>").encode()
            self._send(200, body)
        else:
            self._send(200, b"<html><body>hello</body></html>")

    def do_POST(self):
        self._record()
        length = int(self.headers.get("Content-Length") or 0)
        data = self.rfile.read(length)
        self._send(200, b"echo:" + data, ctype="text/plain")

    def log_message(self, *args):
        pass


class _IdleCloseHandler(_KAHandler):
    timeout = 0.3

    def log_error(self, *args):
        pass


class _HTTP10Handler(_KAHandler):
    protocol_version = "HTTP/1.0"


class KAServer:
    def __init__(self, handler=_KAHandler):
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.httpd.daemon_threads = True
        self.httpd.lock = threading.Lock()
        self.httpd.connections = 0
        self.httpd.closed = 0
        self.httpd.paths = []
        self.httpd.conn_headers = []
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        hc.close_connections()
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)

    @property
    def connections(self):
        with self.httpd.lock:
            return self.httpd.connections

    @property
    def paths(self):
        with self.httpd.lock:
            return list(self.httpd.paths)

    def url(self, path="/"):
        return "http://127.0.0.1:%d%s" % (self.httpd.server_address[1], path)


class _Base(unittest.TestCase):
    def setUp(self):
        hc.close_connections()
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop(hc.NO_KEEPALIVE_ENV, None)

    def tearDown(self):
        hc.close_connections()


class KeepAliveTests(_Base):
    def test_sequential_requests_reuse_one_connection(self):
        with KAServer() as srv:
            for _ in range(10):
                r = hc.request(srv.url("/page"))
                self.assertEqual(r.status, 200)
                self.assertIn("hello", r.body)
            self.assertEqual(srv.connections, 1)
            self.assertNotIn("close", [h and h.lower() for h in srv.httpd.conn_headers])

    def test_redirects_followed_on_the_same_connection(self):
        with KAServer() as srv:
            r = hc.request(srv.url("/redir"))
            self.assertEqual(r.status, 200)
            self.assertTrue(r.final_url.endswith("/page"))
            self.assertEqual(r.url, srv.url("/redir"))
            self.assertEqual(srv.paths, ["/redir", "/page"])
            self.assertEqual(srv.connections, 1)

    def test_redirect_not_followed_when_disabled(self):
        with KAServer() as srv:
            r = hc.request(srv.url("/redir"), allow_redirects=False)
            self.assertEqual(r.status, 302)
            self.assertEqual(r.header("location"), "/page")
            self.assertEqual(r.final_url, srv.url("/redir"))
            r2 = hc.request(srv.url("/page"), allow_redirects=False)
            self.assertEqual(r2.status, 200)
            self.assertEqual(srv.connections, 1)

    def test_error_status_body_read_and_connection_reused(self):
        with KAServer() as srv:
            r = hc.request(srv.url("/missing"))
            self.assertEqual(r.status, 404)
            self.assertEqual(r.body, "<html>nope</html>")
            self.assertFalse(r.ok)
            self.assertEqual(hc.request(srv.url("/page")).status, 200)
            self.assertEqual(srv.connections, 1)

    def test_chunked_body_fully_read_and_reused(self):
        with KAServer() as srv:
            r = hc.request(srv.url("/chunked"))
            self.assertEqual(r.body, "hello chunked world")
            self.assertEqual(hc.request(srv.url("/chunked")).body, "hello chunked world")
            self.assertEqual(srv.connections, 1)

    def test_post_and_head(self):
        with KAServer() as srv:
            r = hc.request(srv.url("/echo"), method="POST", data={"a": 1})
            self.assertEqual(r.body, 'echo:{"a": 1}')
            r = hc.request(srv.url("/echo"), method="POST", data="x=1")
            self.assertEqual(r.body, "echo:x=1")
            r = hc.request(srv.url("/page"), method="HEAD")
            self.assertEqual(r.status, 200)
            self.assertEqual(r.body, "")
            self.assertEqual(hc.request(srv.url("/page")).status, 200)
            self.assertEqual(srv.connections, 1)

    def test_truncated_body_is_not_reused_but_next_request_works(self):
        with KAServer() as srv, mock.patch.object(hc, "MAX_BODY", 100):
            r = hc.request(srv.url("/big"))
            self.assertEqual(len(r.body), 100)
            r2 = hc.request(srv.url("/page"))
            self.assertEqual(r2.status, 200)
            self.assertIn("hello", r2.body)
            self.assertEqual(srv.connections, 2)

    def test_server_closing_idle_connection_reconnects(self):
        with KAServer(_IdleCloseHandler) as srv:
            self.assertEqual(hc.request(srv.url("/page")).status, 200)
            time.sleep(0.7)
            r = hc.request(srv.url("/page"))
            self.assertEqual(r.status, 200, r.error)
            self.assertEqual(srv.connections, 2)

    def test_stale_reused_connection_is_retried_once(self):
        with KAServer() as srv:
            self.assertEqual(hc.request(srv.url("/page")).status, 200)
            r = hc.request(srv.url("/flaky"))
            self.assertIsNone(r.error)
            self.assertEqual(r.status, 200)
            self.assertEqual(r.body, "fresh")
            self.assertEqual(srv.paths, ["/page", "/flaky", "/flaky"])
            self.assertEqual(srv.connections, 2)

    def test_fresh_connection_failure_is_not_retried(self):
        with KAServer() as srv:
            r = hc.request(srv.url("/always-drop"))
            self.assertIsNotNone(r.error)
            self.assertIn("RemoteDisconnected", r.error)
            self.assertEqual(srv.paths, ["/always-drop"])

    def test_threads_do_not_share_connections(self):
        with KAServer() as srv:
            errors = []
            barrier = threading.Barrier(4)

            def worker(n):
                try:
                    barrier.wait(timeout=5)
                    for i in range(5):
                        r = hc.request(srv.url("/echo"), method="POST",
                                       data="t%d-%d" % (n, i))
                        if r.body != "echo:t%d-%d" % (n, i):
                            errors.append(r.body or r.error)
                finally:
                    hc.close_connections()

            threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10)
            self.assertEqual(errors, [])
            self.assertEqual(srv.connections, 4)

    def test_worker_thread_connections_closed_when_thread_exits(self):
        import concurrent.futures
        with KAServer() as srv:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                for _ in range(3):
                    self.assertEqual(ex.submit(hc.request, srv.url("/page")).result().status, 200)
            self.assertEqual(srv.connections, 1)
            deadline = time.time() + 5
            while time.time() < deadline:
                with srv.httpd.lock:
                    if srv.httpd.closed >= 1:
                        break
                time.sleep(0.05)
            with srv.httpd.lock:
                self.assertEqual(srv.httpd.closed, 1)

    def test_http10_server_still_works(self):
        with KAServer(_HTTP10Handler) as srv:
            for _ in range(3):
                self.assertEqual(hc.request(srv.url("/page")).status, 200)
            self.assertEqual(srv.connections, 3)

    def test_escape_hatch_restores_connection_close(self):
        os.environ[hc.NO_KEEPALIVE_ENV] = "1"
        with KAServer() as srv:
            for _ in range(3):
                self.assertEqual(hc.request(srv.url("/page")).status, 200)
            r = hc.request(srv.url("/redir"))
            self.assertTrue(r.final_url.endswith("/page"))
            self.assertEqual(srv.connections, 5)
            self.assertTrue(all(h == "close" for h in srv.httpd.conn_headers))

    def test_env_proxy_uses_one_shot_urllib_path(self):
        with KAServer() as proxy, mock.patch.dict(hc._OPENERS, clear=True):
            os.environ["http_proxy"] = proxy.url("")
            os.environ["HTTP_PROXY"] = proxy.url("")
            for _ in range(2):
                r = hc.request("http://example.invalid/page")
                self.assertEqual(r.status, 200, r.error)
            self.assertEqual(proxy.paths, ["http://example.invalid/page"] * 2)
            self.assertEqual(proxy.connections, 2)
            self.assertTrue(all(h == "close" for h in proxy.httpd.conn_headers))

    def test_connection_refused_reports_error(self):
        from tests.helpers import free_port
        r = hc.request("http://127.0.0.1:%d/" % free_port(), timeout=2)
        self.assertIsNone(r.status)
        self.assertIn("URLError", r.error)

    def test_pool_is_bounded_per_thread(self):
        servers = [KAServer() for _ in range(3)]
        for s in servers:
            s.__enter__()
        try:
            with mock.patch.object(hc, "POOL_MAX_PER_THREAD", 2):
                for s in servers:
                    self.assertEqual(hc.request(s.url("/page")).status, 200)
                self.assertLessEqual(len(hc._thread_connections()), 2)
        finally:
            for s in servers:
                s.__exit__(None, None, None)


class FinderReuseTests(_Base):
    def test_login_finder_reuses_connection(self):
        with KAServer() as srv:
            res = login_finder.run_login_finder(
                srv.url(""), workers=1, custom_paths=["login", "a", "b", "c"])
            self.assertEqual([f["path"] for f in res["found"]], ["login"])
            self.assertEqual(srv.connections, 1)

    def test_register_finder_reuses_connection(self):
        with KAServer() as srv:
            res = register_finder.run_register_finder(
                srv.url(""), workers=1, custom_paths=["register", "a", "b"])
            self.assertEqual([f["path"] for f in res["found"]], ["register"])
            self.assertEqual(srv.connections, 1)

    def test_login_finder_fetch_shape(self):
        with KAServer() as srv:
            status, body, final = login_finder._fetch(srv.url("/redir"))
            self.assertEqual(status, 200)
            self.assertTrue(final.endswith("/page"))
            status, body, final = login_finder._fetch(srv.url("/missing"))
            self.assertEqual((status, body, final), (404, "<html>nope</html>", srv.url("/missing")))


class ParamFinderBaselineTests(_Base):
    def test_baseline_fetched_once_not_per_param(self):
        with KAServer() as srv:
            params = ["q", "a", "b", "c", "d"]
            res = param_finder.run_param_finder(srv.url("/?id=1"), workers=2,
                                                custom_params=params)
            base_hits = [p for p in srv.paths if p == "/?id=1"]
            self.assertEqual(len(base_hits), 2)
            self.assertEqual(len(srv.paths), 2 + len(params))
            accepted = {a["param"]: a for a in res["accepted"]}
            self.assertIn("q", accepted)
            self.assertTrue(accepted["q"]["reflected"])
            self.assertEqual(set(accepted), {"q"})
            self.assertEqual(res["total_checked"], len(params))

    def test_baseline_failure_returns_early(self):
        from tests.helpers import free_port
        res = param_finder.run_param_finder("http://127.0.0.1:%d/?id=1" % free_port(),
                                            custom_params=["a", "b"], timeout=2)
        self.assertEqual(res["accepted"], [])
        self.assertTrue(res["errors"])

    def test_test_param_still_accepts_old_call(self):
        with KAServer() as srv:
            r = param_finder._test_param(srv.url("/?id=1"), "q")
            self.assertTrue(r["accepted"])
            self.assertEqual(srv.paths.count("/?id=1"), 1)


class AttackSurfaceTests(_Base):
    def _engine(self, **kw):
        return attack_surface.AttackSurfaceEngine("example.invalid", delay=0, **kw)

    def test_request_reads_capped_prefix_with_real_size(self):
        eng = self._engine()
        with KAServer() as srv:
            code, body, size, truncated = eng._fetch(srv.url("/big"), max_bytes=64)
            self.assertEqual(code, 200)
            self.assertEqual(len(body), 64)
            self.assertEqual(size, 5000)
            self.assertTrue(truncated)
            code, body = eng._request(srv.url("/big"))
            self.assertEqual((code, len(body)), (200, 5000))

    def test_wayback_uses_bounded_text_query(self):
        eng = self._engine(wayback_limit=123)
        seen = {}
        body = ("http://example.invalid/a.js\n"
                "https://api.example.invalid/v1?id=3\n"
                "http://example.invalid/partial-li")

        def fake_fetch(url, headers=None, max_bytes=None):
            seen["url"], seen["max_bytes"] = url, max_bytes
            return 200, body, len(body), True

        eng._fetch = fake_fetch
        eng._harvest_wayback()
        self.assertIn("fl=original", seen["url"])
        self.assertIn("limit=123", seen["url"])
        self.assertNotIn("output=json", seen["url"])
        self.assertEqual(seen["max_bytes"], attack_surface.CDX_MAX_BYTES)
        self.assertEqual(eng.endpoints, {"http://example.invalid/a.js",
                                         "https://api.example.invalid/v1?id=3"})
        self.assertEqual(eng.js_files, {"http://example.invalid/a.js"})
        self.assertIn("api.example.invalid", eng.subdomains)

    def test_sensitive_file_probes_are_capped_and_parallel(self):
        eng = self._engine(workers=3)
        calls = []
        lock = threading.Lock()
        active = {"now": 0, "max": 0}

        def fake_fetch(url, headers=None, max_bytes=None):
            with lock:
                calls.append((url, max_bytes))
                active["now"] += 1
                active["max"] = max(active["max"], active["now"])
            time.sleep(0.05)
            with lock:
                active["now"] -= 1
            if url.endswith("/database.sql"):
                return 200, "-- MySQL dump", 10 * 1024 * 1024, True
            return 200, "<html><body>soft 404</body></html>", 34, False

        eng._fetch = fake_fetch
        eng._fuzz_sensitive_files()
        self.assertEqual(len(calls), 10)
        self.assertTrue(all(mb == attack_surface.PROBE_MAX_BYTES for _, mb in calls))
        self.assertGreater(active["max"], 1)
        self.assertLessEqual(active["max"], 3)
        self.assertEqual([f["path"] for f in eng.sensitive_findings], ["/database.sql"])
        self.assertEqual(eng.sensitive_findings[0]["size"], 10 * 1024 * 1024)

    def test_crtsh_and_wayback_merge(self):
        eng = self._engine()
        crt = json.dumps([{"name_value": "a.example.invalid\n*.example.invalid"}])

        def fake_fetch(url, headers=None, max_bytes=None):
            if "crt.sh" in url:
                return 200, crt, len(crt), False
            return 200, "http://b.example.invalid/x\n", 27, False

        eng._fetch = fake_fetch
        eng._mine_crtsh()
        eng._harvest_wayback()
        self.assertEqual(eng.subdomains, {"a.example.invalid", "b.example.invalid"})


if __name__ == "__main__":
    unittest.main()
