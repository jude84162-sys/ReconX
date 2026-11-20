"""Tests for the recon orchestration speed fixes.

Covers recon.run_recon / _run_parallel (domain step in the pool, real per-step
and overall time limits, early screenshots, subdomain probe filtering), the
dirb engine (recursion flag, threaded wordlist scan), dir_buster's time budget
and the GUI/CLI default worker counts. Every server binds to 127.0.0.1 only.
"""

import contextlib
import http.server
import io
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import recon  # noqa: E402
from modules.vuln import dirb_engine  # noqa: E402
from modules.web import dir_buster  # noqa: E402
from tests.helpers import free_port  # noqa: E402

NO_PROXY = {"no_proxy": "127.0.0.1,localhost", "NO_PROXY": "127.0.0.1,localhost",
            "http_proxy": "", "HTTP_PROXY": ""}


# ============================================================
# Local content server
# ============================================================

class _ContentHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    wbufsize = -1
    server_version = "ReconXTest/1.0"
    sys_version = ""

    ROUTES = {
        "/admin": (200, b"<html>admin panel</html>" * 60),
        "/robots.txt": (200, b"User-agent: *\nDisallow: /private\n"),
        "/.git/HEAD": (200, b"ref: refs/heads/main\n"),
        "/limited": (429, b"slow down"),
    }
    NOT_FOUND = b"<html><h1>Not Found</h1></html>"

    def handle(self):
        with self.server.lock:
            self.server.connections += 1
        super().handle()

    def do_GET(self):
        with self.server.lock:
            self.server.paths.append(self.path)
        delay = self.server.delay
        if delay:
            time.sleep(delay)
        if self.path == "/images":
            self.send_response(301)
            self.send_header("Location", "/images/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        code, body = self.ROUTES.get(self.path, (404, self.NOT_FOUND))
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class ContentServer:
    def __init__(self, delay=0.0):
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _ContentHandler)
        self.httpd.lock = threading.Lock()
        self.httpd.connections = 0
        self.httpd.paths = []
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
    def base(self):
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"


def _wordlist(words):
    f = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8")
    f.write("\n".join(words))
    f.close()
    return f.name


@contextlib.contextmanager
def _quiet():
    with contextlib.redirect_stdout(io.StringIO()) as out, \
            contextlib.redirect_stderr(io.StringIO()):
        yield out


# ============================================================
# dirb engine
# ============================================================

class DirbFlagTests(unittest.TestCase):
    def _cmd(self, **kwargs):
        seen = {}

        def fake_run(cmd, **kw):
            seen["cmd"] = list(cmd)
            out = cmd[cmd.index("-o") + 1]
            with open(out, "w", encoding="utf-8") as f:
                f.write("+ http://t.example/admin (CODE:200|SIZE:1234)\n")

        with mock.patch.object(dirb_engine, "is_dirb_available", return_value=True), \
                mock.patch.object(dirb_engine, "get_dirb_version", return_value="2.22"), \
                mock.patch.object(dirb_engine.subprocess, "run", side_effect=fake_run):
            result = dirb_engine.run_dirb("http://t.example", wordlist="/wl.txt", **kwargs)
        return seen["cmd"], result

    def test_default_is_not_recursive(self):
        cmd, result = self._cmd()
        self.assertIn("-r", cmd)  # dirb's -r means "don't search recursively"
        self.assertEqual(result["findings"][0]["path"], "/admin")
        self.assertEqual(result["summary"], {"total": 1, "by_severity": {"medium": 1}})

    def test_recurse_true_omits_flag(self):
        cmd, _ = self._cmd(recurse=True)
        self.assertNotIn("-r", cmd)

    def test_signature_unchanged(self):
        import inspect
        params = list(inspect.signature(dirb_engine.run_dirb).parameters)
        self.assertEqual(params, ["target", "wordlist", "extensions", "timeout",
                                  "recurse", "verbose", "extra_args"])


class WordlistTests(unittest.TestCase):
    def test_load_skips_blank_comments_and_duplicates(self):
        path = _wordlist(["admin", "", "# comment", "  login  ", "admin", ".git/HEAD"])
        self.addCleanup(os.unlink, path)
        self.assertEqual(dirb_engine.load_wordlist(path), ["admin", "login", ".git/HEAD"])
        self.assertEqual(dirb_engine.load_wordlist(path, max_words=2), ["admin", "login"])

    def test_default_wordlist_prefers_common(self):
        with mock.patch.object(dirb_engine, "get_wordlists",
                               return_value={"big.txt": "/b", "common.txt": "/c"}):
            self.assertEqual(dirb_engine.default_wordlist(), "/c")
        with mock.patch.object(dirb_engine, "get_wordlists", return_value={"big.txt": "/b"}):
            self.assertEqual(dirb_engine.default_wordlist(), "/b")
        with mock.patch.object(dirb_engine, "get_wordlists", return_value={}):
            self.assertIsNone(dirb_engine.default_wordlist())


class ThreadedDirbTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, NO_PROXY)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_dirb_shaped_findings_over_reused_connections(self):
        words = ["admin", "robots.txt", ".git/HEAD", "images", "limited"] + \
                [f"missing{i}" for i in range(200)]
        path = _wordlist(words)
        self.addCleanup(os.unlink, path)
        with ContentServer() as srv, _quiet():
            r = dirb_engine.run_dirb_threaded(srv.base, wordlist=path, workers=8, budget=30)
            connections = srv.httpd.connections

        by_path = {f["path"]: f for f in r["findings"]}
        self.assertEqual(set(by_path), {"/admin", "/robots.txt", "/.git/HEAD", "/images"})
        git = by_path["/.git/HEAD"]
        self.assertEqual(git["severity"], "critical")
        self.assertEqual(git["status"], 200)
        self.assertEqual(git["source"], "dir_buster")
        for key in ("path", "url", "status", "size", "severity", "confidence", "description"):
            self.assertIn(key, git)
        self.assertEqual(by_path["/images"]["status"], 301)
        self.assertEqual(r["findings"][0]["path"], "/.git/HEAD")  # sorted by severity
        self.assertEqual(r["summary"]["total"], 4)
        self.assertEqual(r["summary"]["by_severity"]["critical"], 1)
        self.assertEqual(r["rate_limited"], 1)
        self.assertEqual(r["total_words"], 205)
        self.assertEqual(r["total_checked"], 205)
        self.assertGreaterEqual(r["filtered_soft404"], 200)
        self.assertIsNone(r["error"])
        self.assertFalse(r["partial"])
        # 8 workers + 3 baseline probes; one new connection per request would be ~208
        self.assertLessEqual(connections, 20)

    def test_summary_indicators_from_threaded_result(self):
        path = _wordlist([".env", "robots.txt"])
        self.addCleanup(os.unlink, path)

        class Env(_ContentHandler):
            ROUTES = dict(_ContentHandler.ROUTES, **{"/.env": (200, b"SECRET=1")})

        with ContentServer() as srv, _quiet():
            srv.httpd.RequestHandlerClass = Env
            r = dirb_engine.run_dirb_threaded(srv.base, wordlist=path, workers=2)
        summary = recon.build_summary("t.example", {"dirb": r})
        self.assertEqual(summary["dirb"]["total"], 2)
        details = [i["detail"] for i in summary["risk"]["indicators"] if i["category"] == "dirb"]
        self.assertTrue(any("/.env" in d for d in details), details)

    def test_unreachable_target_stops_after_baseline(self):
        path = _wordlist([f"w{i}" for i in range(500)])
        self.addCleanup(os.unlink, path)
        start = time.monotonic()
        with _quiet():
            r = dirb_engine.run_dirb_threaded(f"http://127.0.0.1:{free_port()}",
                                              wordlist=path, workers=4)
        self.assertLess(time.monotonic() - start, 3)
        self.assertIn("no response", r["error"])
        self.assertEqual(r["findings"], [])
        self.assertEqual(r["unchecked"], 500)

    def test_missing_wordlist(self):
        with mock.patch.object(dirb_engine, "get_wordlists", return_value={}):
            r = dirb_engine.run_dirb_threaded("http://127.0.0.1:1")
        self.assertEqual(r["error"], "no dirb wordlist found")
        self.assertEqual(r["summary"], {"total": 0, "by_severity": {}})


class DirBusterBudgetTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, NO_PROXY)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_budget_stops_scan_and_counts_unchecked(self):
        paths = [f"p{i}" for i in range(40)]
        with ContentServer(delay=0.3) as srv, _quiet():
            start = time.monotonic()
            r = dir_buster.run_dir_bust(srv.base, workers=2, paths=paths, timeout=5,
                                        budget=1.2)
            elapsed = time.monotonic() - start
        self.assertLess(elapsed, 2.5)
        self.assertTrue(r["budget_exceeded"])
        self.assertGreater(r["unchecked"], 20)
        self.assertEqual(r["total_checked"] + r["unchecked"], 40)
        self.assertTrue(any("budget" in e for e in r["errors"]))

    def test_no_budget_keeps_old_shape(self):
        with ContentServer() as srv, _quiet():
            r = dir_buster.run_dir_bust(srv.base, workers=4, paths=["admin", "nothing"])
        self.assertEqual(r["total_checked"], 2)
        self.assertNotIn("budget_exceeded", r)
        self.assertEqual([f["path"] for f in r["found"]], ["admin"])
        for key in ("timestamp", "url", "found", "filtered_soft404", "total_checked",
                    "soft_404_baseline", "soft_404_probes", "sensitive_findings", "errors"):
            self.assertIn(key, r)

    def test_large_404_bodies_still_reuse_connections(self):
        class Big(_ContentHandler):
            NOT_FOUND = b"<html>Not Found " + b"x" * 30000 + b"</html>"

        paths = [f"gone{i}" for i in range(60)]
        with ContentServer() as srv, _quiet():
            srv.httpd.RequestHandlerClass = Big
            r = dir_buster.run_dir_bust(srv.base, workers=4, paths=paths)
            connections = srv.httpd.connections
        self.assertEqual(r["found"], [])
        self.assertEqual(r["filtered_soft404"], 60)
        self.assertLessEqual(connections, 10)

    def test_baseline_probes_run_concurrently(self):
        with ContentServer(delay=0.4) as srv:
            start = time.monotonic()
            baseline = dir_buster._detect_soft_404(srv.base, probes=3)
            elapsed = time.monotonic() - start
        self.assertEqual(baseline["status"], 404)
        self.assertEqual(baseline["probes"], 3)
        self.assertLess(elapsed, 1.0)

    def test_redirects_are_not_followed(self):
        with ContentServer() as srv:
            r = dir_buster._fetch(srv.base, "images")
            paths = list(srv.httpd.paths)
        self.assertEqual(r["status"], 301)
        self.assertTrue(r["redirect"])
        self.assertEqual(r["location"], "/images/")
        self.assertEqual(paths, ["/images"])


# ============================================================
# Parallel runner
# ============================================================

class RunParallelTests(unittest.TestCase):
    def setUp(self):
        self.release = threading.Event()
        self.addCleanup(self.release.set)

    def _slow(self, seconds):
        def step():
            self.release.wait(seconds)
            return {"slow": True}
        return step

    def test_step_timeout_is_enforced(self):
        tasks = {"fast": (lambda: {"ok": 1}, (), {}),
                 "slow": (self._slow(5), (), {})}
        start = time.monotonic()
        with _quiet():
            results, timed_out = recon._run_parallel(tasks, step_timeout=0.4, deadline=10)
        self.assertLess(time.monotonic() - start, 1.5)
        self.assertEqual(results["fast"], {"ok": 1})
        self.assertTrue(results["slow"]["timed_out"])
        self.assertTrue(results["slow"]["partial"])
        self.assertIn("timeout", results["slow"]["error"])
        self.assertEqual(timed_out, ["slow"])

    def test_overall_deadline_caps_every_step(self):
        tasks = {"a": (self._slow(5), (), {}), "b": (self._slow(5), (), {}),
                 "c": (lambda: {"ok": 1}, (), {})}
        start = time.monotonic()
        with _quiet():
            results, timed_out = recon._run_parallel(tasks, step_timeout=60, deadline=0.5)
        self.assertLess(time.monotonic() - start, 1.5)
        self.assertEqual(sorted(timed_out), ["a", "b"])
        self.assertEqual(results["c"], {"ok": 1})

    def test_per_step_override_and_no_limit(self):
        tasks = {"long": (lambda: (time.sleep(0.5), {"done": 1})[1], (), {}),
                 "short": (self._slow(5), (), {})}
        with _quiet():
            results, timed_out = recon._run_parallel(
                tasks, step_timeout=0.2, deadline=0, step_timeouts={"long": 3})
        self.assertEqual(results["long"], {"done": 1})
        self.assertEqual(timed_out, ["short"])

        with _quiet():
            results, timed_out = recon._run_parallel(
                {"x": (lambda: (time.sleep(0.3), {"x": 1})[1], (), {})},
                step_timeout=0, deadline=None)
        self.assertEqual(results, {"x": {"x": 1}})
        self.assertEqual(timed_out, [])

    def test_follow_up_starts_while_other_steps_run(self):
        marks = {}

        def follow(value):
            marks["follow_start"] = time.monotonic()
            return {"got": value}

        def on_done(name, value, submit):
            if name == "first":
                submit("follow", follow, (value,), {}, timeout=5)

        def slow():
            time.sleep(0.6)
            marks["slow_end"] = time.monotonic()
            return {"slow": 1}

        tasks = {"first": (lambda: {"v": 1}, (), {}), "slow": (slow, (), {})}
        with _quiet():
            results, _ = recon._run_parallel(tasks, step_timeout=5, deadline=5,
                                             on_done=on_done, extra_workers=1)
        self.assertEqual(results["follow"], {"got": {"v": 1}})
        self.assertLess(marks["follow_start"], marks["slow_end"])

    def test_on_done_also_runs_for_timed_out_steps(self):
        seen = []
        tasks = {"slow": (self._slow(5), (), {})}
        with _quiet():
            recon._run_parallel(tasks, step_timeout=0.2, deadline=5,
                                on_done=lambda n, v, s: seen.append((n, v.get("timed_out"))))
        self.assertEqual(seen, [("slow", True)])

    def test_exception_in_step_is_captured(self):
        def boom():
            raise RuntimeError("nope")
        with _quiet():
            results, timed_out = recon._run_parallel({"boom": (boom, (), {})})
        self.assertEqual(results, {"boom": {}})
        self.assertEqual(timed_out, [])


# ============================================================
# run_recon
# ============================================================

STEP_NAMES = ["step_domain", "step_ip_multi", "step_ports", "step_dns", "step_subdomains",
              "step_fingerprint", "step_ssl", "step_dirs", "step_login", "step_register",
              "step_waf", "step_params", "step_dirb_engine"]


class RunReconTests(unittest.TestCase):
    def setUp(self):
        self.calls = {}
        self.release = threading.Event()
        self.addCleanup(self.release.set)
        self.patches = {}
        for name in STEP_NAMES:
            self.patches[name] = self._recorder(name)
        resolver = mock.patch("modules.web.domain_osint._resolve_all_ips",
                              return_value={"A": ["192.0.2.1", "192.0.2.2"],
                                            "AAAA": ["2001:db8::1"]})
        resolver.start()
        self.addCleanup(resolver.stop)

    def _recorder(self, name, result=None):
        def step(*args, **kwargs):
            self.calls[name] = (args, kwargs, time.monotonic())
            return dict(result or {"step": name})
        return step

    def _run(self, **kwargs):
        with contextlib.ExitStack() as stack:
            for name, fn in self.patches.items():
                stack.enter_context(mock.patch.object(recon, name, fn))
            out = stack.enter_context(_quiet())
            result = recon.run_recon("Example.COM", **kwargs)
        return result, out.getvalue()

    def test_domain_step_runs_in_pool_with_resolved_ips(self):
        barrier = threading.Barrier(2, timeout=3)

        def domain(target, ips=None):
            barrier.wait()
            self.calls["step_domain"] = ((target,), {"ips": ips}, time.monotonic())
            return {"ips": ips, "subdomains": [], "whois": {"registrar": "R"}}

        def ip_multi(ips, max_ips=3):
            barrier.wait()  # only passes if domain runs at the same time
            self.calls["step_ip_multi"] = ((ips,), {"max_ips": max_ips}, time.monotonic())
            return {"consensus": {"country": "X"}}

        self.patches["step_domain"] = domain
        self.patches["step_ip_multi"] = ip_multi
        result, _ = self._run(max_ips=2)

        self.assertEqual(self.calls["step_domain"][1]["ips"]["A"], ["192.0.2.1", "192.0.2.2"])
        self.assertEqual(self.calls["step_ip_multi"][0][0], ["192.0.2.1", "192.0.2.2"])
        self.assertEqual(self.calls["step_ip_multi"][1], {"max_ips": 2})
        self.assertEqual(self.calls["step_ports"][0], ("192.0.2.1",))
        self.assertEqual(self.calls["step_dns"][0], ("example.com",))
        steps = result["steps"]
        self.assertEqual(list(steps)[0], "domain")
        self.assertEqual(len(steps), 13)
        self.assertEqual(result["summary"]["domain"]["registrar"], "R")
        self.assertEqual(result["summary"]["primary_ip"], "192.0.2.1")
        self.assertEqual(result["summary"]["ip"]["country"], "X")
        self.assertEqual(result["summary"]["timed_out_steps"], [])

    def test_slow_step_is_reported_as_timed_out(self):
        def dns(target):
            self.release.wait(5)
            return {"late": True}

        self.patches["step_dns"] = dns
        start = time.monotonic()
        result, out = self._run(step_timeout=0.4, deadline=10)
        self.assertLess(time.monotonic() - start, 2)
        self.assertTrue(result["steps"]["dns"]["timed_out"])
        self.assertEqual(result["summary"]["timed_out_steps"], ["dns"])
        self.assertEqual(result["steps"]["ssl"], {"step": "step_ssl"})
        self.assertIn("TIMED OUT", out)

    def test_timed_out_domain_step_keeps_resolved_ips(self):
        def domain(target, ips=None):
            self.release.wait(5)
            return {}

        self.patches["step_domain"] = domain
        result, _ = self._run(step_timeout=0.4)
        self.assertTrue(result["steps"]["domain"]["timed_out"])
        self.assertEqual(result["summary"]["primary_ip"], "192.0.2.1")
        self.assertEqual(result["summary"]["domain"]["ips"], 2)
        self.assertEqual(result["summary"]["timed_out_steps"], ["domain"])

    def test_overall_deadline(self):
        def slow(*args, **kwargs):
            self.release.wait(5)
            return {}

        self.patches["step_login"] = slow
        self.patches["step_waf"] = slow
        start = time.monotonic()
        result, _ = self._run(deadline=0.5)
        self.assertLess(time.monotonic() - start, 2)
        self.assertEqual(sorted(result["summary"]["timed_out_steps"]), ["login", "waf"])

    def test_screenshots_start_when_subdomains_finish(self):
        marks = {}

        def subdomains(target, deep=True):
            return {"live": {"alive": 1, "results": [{"url": "https://a.example",
                                                      "alive": True}]}}

        def params(target):
            time.sleep(0.6)
            marks["params_end"] = time.monotonic()
            return {"accepted": []}

        def shots(target, subs, outdir=None):
            marks["shots_start"] = time.monotonic()
            marks["subs"] = subs
            return {"captured": 1}

        self.patches["step_subdomains"] = subdomains
        self.patches["step_params"] = params
        self.patches["step_screenshots"] = shots
        result, _ = self._run(screenshots=True)
        self.assertLess(marks["shots_start"], marks["params_end"])
        self.assertEqual(marks["subs"]["live"]["alive"], 1)
        self.assertEqual(result["steps"]["screenshots"], {"captured": 1})
        self.assertEqual(list(result["steps"])[-1], "screenshots")

    def test_no_screenshots_key_by_default(self):
        result, _ = self._run()
        self.assertNotIn("screenshots", result["steps"])


# ============================================================
# Individual recon steps
# ============================================================

class StepSubdomainsTests(unittest.TestCase):
    def test_only_resolved_hosts_are_probed_with_default_threads(self):
        enum = {
            "total_unique": 4, "by_source": {"crtsh": 4},
            "wildcard": True, "wildcard_ips": ["203.0.113.9"],
            "subdomains": [
                {"hostname": "a.example.com", "ip": "192.0.2.1"},
                {"hostname": "stale.example.com", "ip": None},
                {"hostname": "v6.example.com", "ip": None, "ipv6": ["2001:db8::2"]},
                {"hostname": "b.example.com", "ip": "192.0.2.3"},
            ],
        }
        probe = mock.Mock(return_value={"total": 3, "alive": 0, "dead": 3, "results": []})
        with mock.patch("modules.web.subdomain_enum.run_subdomain_enum", return_value=enum), \
                mock.patch("modules.web.live_probe.probe_hosts", probe), _quiet() as out:
            result = recon.step_subdomains("example.com")

        args, kwargs = probe.call_args
        self.assertEqual(args[0], ["a.example.com", "v6.example.com", "b.example.com"])
        self.assertNotIn("threads", kwargs)
        self.assertEqual(kwargs["timeout"], 5)
        self.assertEqual(result["live"]["total"], 3)
        text = out.getvalue()
        self.assertIn("1 unresolved skipped", text)
        self.assertIn("Wildcard DNS", text)
        self.assertIn("203.0.113.9", text)


class StepDomainTests(unittest.TestCase):
    def test_ips_are_passed_through(self):
        fake = mock.Mock(return_value={"ips": {"A": ["192.0.2.1"]}, "subdomains": [],
                                       "whois": {}})
        ips = {"A": ["192.0.2.1"], "AAAA": []}
        with mock.patch("modules.web.domain_osint.run_domain_osint", fake), _quiet():
            result = recon.step_domain("example.com", ips=ips)
        fake.assert_called_once_with("example.com", deep=False, ips=ips)
        self.assertEqual(result["ips"]["A"], ["192.0.2.1"])


class StepDirbTests(unittest.TestCase):
    def test_threaded_scan_used_when_wordlist_present(self):
        threaded = mock.Mock(return_value={"findings": [], "summary": {"total": 0},
                                           "error": None})
        real = mock.Mock()
        with mock.patch.object(dirb_engine, "default_wordlist", return_value="/wl/common.txt"), \
                mock.patch.object(dirb_engine, "run_dirb_threaded", threaded), \
                mock.patch.object(dirb_engine, "run_dirb", real), _quiet():
            recon.step_dirb_engine("example.com")
        real.assert_not_called()
        args, kwargs = threaded.call_args
        self.assertEqual(args, ("https://example.com",))
        self.assertEqual(kwargs, {"wordlist": "/wl/common.txt",
                                  "workers": recon.DIRB_WORKERS, "budget": recon.DIRB_BUDGET})

    def test_falls_back_to_dirb_without_wordlist(self):
        real = mock.Mock(return_value={"findings": [], "summary": {}, "error": None})
        with mock.patch.object(dirb_engine, "default_wordlist", return_value=None), \
                mock.patch.object(dirb_engine, "is_dirb_available", return_value=True), \
                mock.patch.object(dirb_engine, "run_dirb", real), _quiet():
            recon.step_dirb_engine("example.com")
        real.assert_called_once_with("https://example.com", timeout=180, verbose=False)

    def test_not_installed_without_wordlist_or_binary(self):
        with mock.patch.object(dirb_engine, "default_wordlist", return_value=None), \
                mock.patch.object(dirb_engine, "is_dirb_available", return_value=False), \
                _quiet():
            r = recon.step_dirb_engine("example.com")
        self.assertEqual(r, {"available": False, "error": "not_installed"})

    def test_partial_result_is_kept(self):
        partial = {"findings": [{"path": "/admin", "status": 200, "severity": "medium"}],
                   "summary": {"total": 1, "by_severity": {"medium": 1}},
                   "error": "timeout after 120s (10 of 20 paths not checked)",
                   "partial": True}
        with mock.patch.object(dirb_engine, "default_wordlist", return_value="/wl"), \
                mock.patch.object(dirb_engine, "run_dirb_threaded", return_value=partial), \
                _quiet() as out:
            r = recon.step_dirb_engine("example.com")
        self.assertIs(r, partial)
        self.assertIn("timeout after 120s", out.getvalue())

    def test_fast_mode_skips(self):
        with _quiet():
            self.assertEqual(recon.step_dirb_engine("example.com", deep=False), {})


class ReconCliTests(unittest.TestCase):
    def test_budget_and_step_timeout_flags(self):
        run = mock.Mock()
        argv = ["recon.py", "example.com", "--budget", "90", "--step-timeout", "30"]
        with mock.patch.object(recon, "run_recon", run), mock.patch.object(sys, "argv", argv):
            self.assertEqual(recon.main(), 0)
        kwargs = run.call_args[1]
        self.assertEqual(kwargs["deadline"], 90)
        self.assertEqual(kwargs["step_timeout"], 30)

    def test_defaults(self):
        run = mock.Mock()
        with mock.patch.object(recon, "run_recon", run), \
                mock.patch.object(sys, "argv", ["recon.py", "example.com"]):
            recon.main()
        kwargs = run.call_args[1]
        self.assertEqual(kwargs["deadline"], recon.RECON_DEADLINE)
        self.assertIsNone(kwargs["step_timeout"])


if __name__ == "__main__":
    unittest.main()
