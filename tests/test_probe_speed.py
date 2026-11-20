"""Speed/correctness tests for live probing and screenshot capture.

Covers the short connect timeout + recheck in modules/web/live_probe.py and the
batched pre-probe, JSON target selection, concurrent Playwright capture and the
Chrome retry rule in modules/web/aquatone_clone.py.

Loopback only: DNS and connects to non-local names are faked, and Playwright /
Chrome are replaced with in-process fakes.
"""

import http.server
import inspect
import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest import mock

from modules.web import aquatone_clone, live_probe
from tests.helpers import LocalServer, free_port


class _SlowHandler(http.server.BaseHTTPRequestHandler):
    delay = 0.4

    def do_GET(self):
        time.sleep(self.delay)
        body = b"<title>slow</title>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class SlowServer(LocalServer):
    def __init__(self):
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SlowHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)


# ============================================================
# live_probe
# ============================================================

class ConnectTimeoutTests(unittest.TestCase):
    def test_connect_is_capped_but_reads_keep_the_full_timeout(self):
        real = socket.create_connection
        seen = []

        def wrapped(address, timeout=None, source_address=None):
            sock = real(address, timeout, source_address)
            seen.append((timeout, sock))
            return sock

        with LocalServer() as server, \
                mock.patch.object(live_probe.socket, "create_connection", wrapped):
            resp = live_probe._request(server.url("/"), timeout=6, connect_timeout=3)

        self.assertEqual(resp["status"], 200)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0][0], 3)
        self.assertEqual(seen[0][1].gettimeout(), 6)

    def test_probe_host_default_keeps_the_full_connect_timeout(self):
        real = socket.create_connection
        seen = []

        def wrapped(address, timeout=None, source_address=None):
            seen.append(timeout)
            return real(address, timeout, source_address)

        with LocalServer() as server, \
                mock.patch.object(live_probe.socket, "create_connection", wrapped):
            result = live_probe.probe_host(server.url("/"), timeout=6)

        self.assertTrue(result["alive"])
        self.assertEqual(seen, [6])

    def test_blackholed_host_fails_fast_and_is_rechecked_once(self):
        calls = []

        def blackhole(address, timeout=None, source_address=None):
            calls.append((address[1], timeout))
            raise socket.timeout("timed out")

        with mock.patch.object(live_probe.socket, "create_connection", blackhole):
            result = live_probe.probe_hosts(["filtered.invalid"], timeout=6)

        # pass 1: both schemes with the short connect timeout;
        # recheck: full timeout, stopping at the first handshake that still hangs
        self.assertEqual(calls, [(443, 3), (80, 3), (443, 6)])
        self.assertEqual(result["alive"], 0)
        self.assertEqual(result["dead"], 1)
        entry = result["results"][0]
        self.assertFalse(entry["alive"])
        self.assertEqual(entry["errors"], [
            "https://filtered.invalid: connect timeout",
            "http://filtered.invalid: connect timeout",
        ])

    def test_slow_to_accept_host_is_found_by_the_recheck(self):
        real = socket.create_connection
        calls = []

        with LocalServer() as server:
            def slow_accept(address, timeout=None, source_address=None):
                calls.append(timeout)
                if timeout is not None and timeout < 5:
                    raise socket.timeout("timed out")
                return real(("127.0.0.1", server.port), timeout, source_address)

            with mock.patch.object(live_probe.socket, "create_connection", slow_accept):
                result = live_probe.probe_hosts(["http://slow.invalid:8080/"], timeout=6)
                calls_with_recheck = list(calls)
                del calls[:]
                no_recheck = live_probe.probe_hosts(
                    ["http://slow.invalid:8080/"], timeout=6, recheck=False)

        self.assertEqual(calls_with_recheck, [3, 6])
        self.assertEqual(result["alive"], 1)
        self.assertEqual(result["results"][0]["status"], 200)
        self.assertEqual(result["results"][0]["title"], "Test & Probe")

        self.assertEqual(calls, [3])
        self.assertEqual(no_recheck["alive"], 0)
        self.assertTrue(no_recheck["results"][0]["errors"][-1].endswith("connect timeout"))

    def test_refused_hosts_are_not_rechecked(self):
        real = socket.create_connection
        calls = []

        def wrapped(address, timeout=None, source_address=None):
            calls.append(timeout)
            return real(address, timeout, source_address)

        with mock.patch.object(live_probe.socket, "create_connection", wrapped):
            result = live_probe.probe_hosts(
                [f"http://127.0.0.1:{free_port()}"], timeout=6)

        self.assertEqual(result["dead"], 1)
        self.assertEqual(calls, [3])

    def test_connect_timeout_never_exceeds_the_timeout(self):
        calls = []

        def blackhole(address, timeout=None, source_address=None):
            calls.append(timeout)
            raise socket.timeout("timed out")

        with mock.patch.object(live_probe.socket, "create_connection", blackhole):
            live_probe.probe_hosts(["http://x.invalid"], timeout=2)

        # connect timeout == timeout, so there is nothing to recheck
        self.assertEqual(calls, [2])


class ProbeConcurrencyTests(unittest.TestCase):
    def test_default_threads_is_fifty(self):
        params = inspect.signature(live_probe.probe_hosts).parameters
        self.assertEqual(params["threads"].default, 50)
        self.assertEqual(live_probe.DEFAULT_THREADS, 50)

    def test_hosts_are_probed_in_parallel_by_default(self):
        with SlowServer() as server:
            targets = [server.url(f"/p{i}") for i in range(12)]
            started = time.monotonic()
            result = live_probe.probe_hosts(targets, timeout=5)
            elapsed = time.monotonic() - started

        self.assertEqual(result["total"], 12)
        self.assertEqual(result["alive"], 12)
        # 12 x 0.4s one at a time would take ~4.8s
        self.assertLess(elapsed, 2.5)

    def test_result_shape_is_unchanged(self):
        with LocalServer() as server:
            result = live_probe.probe_hosts([server.url("/")], threads=2, timeout=3)
        self.assertEqual(set(result), {"timestamp", "total", "alive", "dead", "results"})
        self.assertEqual(set(result["results"][0]), {
            "input", "host", "alive", "url", "status", "title", "server",
            "content_type", "content_length", "redirects", "final_url", "tls",
            "elapsed_ms", "errors",
        })


# ============================================================
# aquatone_clone: pre-probe and JSON targets
# ============================================================

class PrepareJobsBatchTests(unittest.TestCase):
    def test_bare_hosts_are_probed_in_one_concurrent_batch(self):
        calls = []

        def fake_probe_hosts(targets, threads=None, timeout=None, **kwargs):
            calls.append((list(targets), threads, timeout))
            return {"results": [
                {"input": "b.example", "alive": False,
                 "errors": ["http://b.example: connect timeout"]},
                {"input": "a.example", "alive": True, "url": "https://a.example",
                 "final_url": "https://a.example/home", "title": "A"},
            ]}

        def no_single_probe(*args, **kwargs):
            raise AssertionError("probe_host must not be called one host at a time")

        with mock.patch.object(aquatone_clone.live_probe, "probe_hosts", fake_probe_hosts), \
                mock.patch.object(aquatone_clone.live_probe, "probe_host", no_single_probe):
            jobs, skipped = aquatone_clone._prepare_jobs(
                ["a.example", "https://c.example/x", "b.example", "A.EXAMPLE"],
                timeout=25, verbose=False)

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], ["a.example", "b.example"])
        self.assertEqual(calls[0][1], 50)
        self.assertLessEqual(calls[0][2], 6)

        self.assertEqual([j["url"] for j in jobs],
                         ["https://a.example/home", "https://c.example/x"])
        self.assertEqual(jobs[0]["title"], "A")
        self.assertEqual(jobs[0]["host"], "a.example")
        self.assertIsNone(jobs[1]["title"])
        self.assertEqual(len(skipped), 1)
        self.assertEqual(skipped[0]["input"], "b.example")
        self.assertEqual(skipped[0]["error"], "http://b.example: connect timeout")

    def test_only_urls_skip_the_probe(self):
        with mock.patch.object(aquatone_clone.live_probe, "probe_hosts") as probe:
            jobs, skipped = aquatone_clone._prepare_jobs(
                ["http://127.0.0.1:1/"], timeout=5, verbose=False)
        probe.assert_not_called()
        self.assertEqual(len(jobs), 1)
        self.assertEqual(skipped, [])

    def test_mixed_live_and_dead_loopback_hosts_keep_input_order(self):
        with LocalServer() as one, LocalServer() as two:
            dead = f"127.0.0.1:{free_port()}"
            targets = [f"127.0.0.1:{two.port}", dead, f"127.0.0.1:{one.port}"]
            jobs, skipped = aquatone_clone._prepare_jobs(targets, timeout=3, verbose=False)

        self.assertEqual([j["input"] for j in jobs], [targets[0], targets[2]])
        self.assertEqual([j["url"] for j in jobs],
                         [f"http://127.0.0.1:{two.port}", f"http://127.0.0.1:{one.port}"])
        self.assertEqual([s["input"] for s in skipped], [dead])


class TargetsFromJsonLiveTests(unittest.TestCase):
    def write_json(self, payload):
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8")
        with handle:
            json.dump(payload, handle)
        self.addCleanup(lambda: Path(handle.name).unlink())
        return handle.name

    def test_recon_report_prefers_live_results(self):
        payload = {"steps": {"subdomains": {
            "subdomains": [{"hostname": "a.example"}, {"hostname": "b.example"},
                           {"hostname": "c.example"}],
            "live": {"results": [
                {"input": "a.example", "host": "a.example", "alive": True,
                 "url": "https://a.example", "final_url": "https://a.example/"},
                {"input": "b.example", "host": "b.example", "alive": False, "url": None},
                {"input": "c.example", "host": "c.example", "alive": True,
                 "url": "http://c.example"},
            ]},
        }}}
        self.assertEqual(aquatone_clone._targets_from_json(self.write_json(payload)),
                         ["https://a.example", "http://c.example"])

    def test_recon_report_without_live_hosts_falls_back_to_subdomains(self):
        payload = {"steps": {"subdomains": {
            "subdomains": [{"hostname": "a.example"}],
            "live": {"results": [{"input": "a.example", "alive": False}]},
        }}}
        self.assertEqual(aquatone_clone._targets_from_json(self.write_json(payload)),
                         ["a.example"])

    def test_saved_subdomain_report_prefers_live_results(self):
        payload = {"subdomains": {
            "subdomains": [{"hostname": "a.example"}, {"hostname": "b.example"}],
            "live": {"results": [
                {"input": "b.example", "alive": True, "url": "https://b.example"},
            ]},
        }}
        self.assertEqual(aquatone_clone._targets_from_json(self.write_json(payload)),
                         ["https://b.example"])

    def test_probe_report_drops_dead_rows_that_carry_a_host(self):
        # real probe_hosts rows always carry "host", so dead rows used to be
        # re-probed as bare hostnames
        payload = {"results": [
            {"input": "a.example", "host": "a.example", "alive": True,
             "url": "https://a.example"},
            {"input": "dead.example", "host": "dead.example", "alive": False,
             "url": None},
        ]}
        self.assertEqual(aquatone_clone._targets_from_json(self.write_json(payload)),
                         ["https://a.example"])

    def test_plain_lists_without_alive_flags_are_kept(self):
        path = self.write_json(["a.example", {"hostname": "b.example"},
                                {"host": "c.example", "alive": False}])
        self.assertEqual(aquatone_clone._targets_from_json(path),
                         ["a.example", "b.example"])


# ============================================================
# aquatone_clone: capture backends
# ============================================================

class _FakePlaywright:
    """In-process stand-in for playwright.sync_api (records concurrency)."""

    def __init__(self, delay=0.2, fail_launches=0):
        self.lock = threading.Lock()
        self.delay = delay
        self.fail_launches = fail_launches
        self.active = 0
        self.peak = 0
        self.instances = 0
        self.threads = set()
        self.load_waits = []
        self.fixed_sleeps = 0

    def module(self):
        api = types.ModuleType("playwright.sync_api")
        api.sync_playwright = self.sync_playwright
        pkg = types.ModuleType("playwright")
        pkg.sync_api = api
        return {"playwright": pkg, "playwright.sync_api": api}

    def sync_playwright(self):
        env = self

        class _Manager:
            def __enter__(self):
                with env.lock:
                    env.instances += 1
                    env.threads.add(threading.get_ident())
                return types.SimpleNamespace(
                    chromium=types.SimpleNamespace(launch=env.launch))

            def __exit__(self, *exc):
                return False

        return _Manager()

    def launch(self, headless=True):
        with self.lock:
            if self.fail_launches > 0:
                self.fail_launches -= 1
                raise RuntimeError("Executable doesn't exist")
        return _FakeBrowser(self)


class _FakeBrowser:
    def __init__(self, env):
        self.env = env

    def new_context(self, **kwargs):
        return _FakeContext(self.env)

    def close(self):
        pass


class _FakeContext:
    def __init__(self, env):
        self.env = env

    def new_page(self):
        return _FakePage(self.env)

    def add_cookies(self, cookies):
        pass


class _FakePage:
    def __init__(self, env):
        self.env = env

    def goto(self, url, wait_until=None, timeout=None):
        env = self.env
        with env.lock:
            env.active += 1
            env.peak = max(env.peak, env.active)
        time.sleep(env.delay)
        with env.lock:
            env.active -= 1
        return types.SimpleNamespace(status=200)

    def wait_for_load_state(self, state, timeout=None):
        with self.env.lock:
            self.env.load_waits.append((state, timeout))

    def wait_for_timeout(self, ms):
        with self.env.lock:
            self.env.fixed_sleeps += 1

    def screenshot(self, path, full_page=False):
        Path(path).write_bytes(b"\x89PNG fake")

    def title(self):
        return "Fake"

    def close(self):
        pass


def _jobs(tmp, count):
    return [{"url": f"http://127.0.0.1:1/{i}", "path": Path(tmp) / f"{i}.png",
             "title": None} for i in range(count)]


class PlaywrightCaptureTests(unittest.TestCase):
    def capture(self, env, jobs, workers):
        with mock.patch.dict(sys.modules, env.module()):
            return aquatone_clone._capture_playwright(
                jobs, 1280, 800, 25, False, False, workers=workers)

    def test_pages_are_captured_concurrently_one_browser_per_worker(self):
        env = _FakePlaywright(delay=0.3)
        with tempfile.TemporaryDirectory() as tmp:
            jobs = _jobs(tmp, 8)
            started = time.monotonic()
            done = self.capture(env, jobs, workers=4)
            elapsed = time.monotonic() - started

            self.assertEqual([j["status"] for j in done], ["captured"] * 8)
            self.assertEqual(done, jobs)
            self.assertTrue(all(j["path"].exists() for j in jobs))
            self.assertEqual({j["title"] for j in jobs}, {"Fake"})

        self.assertEqual(env.instances, 4)
        self.assertEqual(len(env.threads), 4)
        self.assertGreater(env.peak, 1)
        self.assertLess(elapsed, 8 * 0.3)

    def test_networkidle_replaces_the_fixed_sleep(self):
        env = _FakePlaywright(delay=0)
        with tempfile.TemporaryDirectory() as tmp:
            self.capture(env, _jobs(tmp, 2), workers=1)
        self.assertEqual(env.fixed_sleeps, 0)
        self.assertEqual(env.load_waits, [("networkidle", 2000)] * 2)

    def test_workers_are_capped_by_the_job_count(self):
        env = _FakePlaywright(delay=0)
        with tempfile.TemporaryDirectory() as tmp:
            self.capture(env, _jobs(tmp, 2), workers=8)
        self.assertEqual(env.instances, 2)

    def test_one_failed_launch_leaves_the_jobs_to_other_workers(self):
        env = _FakePlaywright(delay=0.05, fail_launches=1)
        with tempfile.TemporaryDirectory() as tmp:
            jobs = _jobs(tmp, 6)
            done = self.capture(env, jobs, workers=3)
        self.assertEqual([j["status"] for j in done], ["captured"] * 6)

    def test_raises_when_no_browser_starts_so_chrome_can_take_over(self):
        env = _FakePlaywright(delay=0, fail_launches=99)
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(RuntimeError):
                self.capture(env, _jobs(tmp, 4), workers=3)
            env = _FakePlaywright(delay=0, fail_launches=99)
            with self.assertRaises(RuntimeError):
                self.capture(env, _jobs(tmp, 4), workers=1)


class ChromeRetryTests(unittest.TestCase):
    def run_once(self, stderr):
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(list(cmd))
            return subprocess.CompletedProcess(cmd, 0, stdout=b"", stderr=stderr)

        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(aquatone_clone.subprocess, "run", fake_run):
            job = {"url": "http://127.0.0.1:1/", "path": Path(tmp) / "x.png"}
            aquatone_clone._chrome_once("chrome", job, 1280, 800, 5)
        return calls

    def test_no_blind_retry_when_chrome_produced_no_image(self):
        calls = self.run_once(b"[ERROR:net] net::ERR_CONNECTION_REFUSED\n")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1], "--headless=new")

    def test_retries_with_old_headless_when_the_flag_is_rejected(self):
        calls = self.run_once(b"chrome: unrecognized option '--headless=new'\n")
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1][1], "--headless")

    def test_flag_error_detection(self):
        self.assertTrue(aquatone_clone._headless_flag_rejected(
            "Unknown flag: --headless=new"))
        self.assertTrue(aquatone_clone._headless_flag_rejected(
            b"invalid value 'new' for --headless"))
        self.assertFalse(aquatone_clone._headless_flag_rejected(b""))
        self.assertFalse(aquatone_clone._headless_flag_rejected(None))
        self.assertFalse(aquatone_clone._headless_flag_rejected(
            "unknown error loading page\nrunning headless"))


class DefaultWorkersTests(unittest.TestCase):
    def test_default_workers_is_bounded(self):
        self.assertGreaterEqual(aquatone_clone.DEFAULT_WORKERS, 3)
        self.assertLessEqual(aquatone_clone.DEFAULT_WORKERS, 8)

    def run_with_backend(self, backend, **kwargs):
        seen = {}

        def fake_chrome(jobs, width, height, timeout, workers, verbose,
                        full_page=False, headers=None, cookies=None):
            seen["chrome"] = workers
            return jobs

        def fake_playwright(jobs, width, height, timeout, full_page, verbose,
                            headers=None, cookies=None, workers=1):
            seen["playwright"] = workers
            return jobs

        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(aquatone_clone, "screenshot_backend",
                                  lambda preferred=None: backend), \
                mock.patch.object(aquatone_clone, "_capture_chrome", fake_chrome), \
                mock.patch.object(aquatone_clone, "_capture_playwright", fake_playwright):
            aquatone_clone.run_screenshots(["http://127.0.0.1:1/"], outdir=tmp,
                                           verbose=False, **kwargs)
        return seen

    def test_run_screenshots_uses_the_default_for_chrome(self):
        self.assertEqual(self.run_with_backend("chrome"),
                         {"chrome": aquatone_clone.DEFAULT_WORKERS})

    def test_playwright_receives_the_workers_knob(self):
        self.assertEqual(self.run_with_backend("playwright", workers=2),
                         {"playwright": 2})
        self.assertEqual(self.run_with_backend("playwright"),
                         {"playwright": aquatone_clone.DEFAULT_WORKERS})


if __name__ == "__main__":
    unittest.main()
