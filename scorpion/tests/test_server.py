"""Tests for the Scorpion.ai dashboard server.

NETWORK ISOLATION: the server is driven by a FAKE ``agent_factory`` whose agent
emits a few canned SHARED EVENTS and findings on the ``on_event`` callback. No
real scanning, no Anthropic/Telegram traffic, no sockets beyond a loopback
``ThreadingHTTPServer`` bound to 127.0.0.1 on an ephemeral port (:0).

Sibling scorpion modules (tools.recon_tools, brain, notify, agent) are NOT
imported — only the already-frozen contracts (config, scope, ratelimit) that
``scorpion.server`` itself imports — so this suite never depends on a
half-written peer.

Run just this module from the repo root:
    python3 -m unittest scorpion.tests.test_server -v
"""
import json
import threading
import time
import unittest
from urllib import request as urlrequest
from urllib.error import HTTPError

from scorpion.config import Config
from scorpion.server import ScorpionServer


# --------------------------------------------------------------------------
# fake agents (stand in for scorpion.agent.Agent)
# --------------------------------------------------------------------------
class QuickFakeAgent:
    """Emits a canned engagement and returns — no network, instant."""

    def __init__(self, target_findings=1):
        self.n = target_findings
        self.ran_with = None

    def run(self, target, goal=None, on_event=None):
        self.ran_with = (target, goal)

        def emit(ev):
            if on_event:
                on_event(ev)

        finding = {
            "title": "Exposed admin panel", "severity": "high",
            "detail": "/admin returns 200 without auth", "target": target,
        }
        emit({"type": "status", "ts": time.time(),
              "text": "engagement starting", "engine": "fake", "target": target})
        emit({"type": "thinking", "ts": time.time(), "text": "planning recon"})
        emit({"type": "tool_call", "ts": time.time(),
              "text": "resolve_osint(target=%s)" % target,
              "tool": "resolve_osint", "args": {"target": target}})
        emit({"type": "tool_result", "ts": time.time(), "text": "",
              "tool": "resolve_osint", "ok": True, "blocked": False,
              "summary": "resolved 2 IPs, 3 subdomains"})
        emit({"type": "finding", "ts": time.time(),
              "text": finding["title"], "title": finding["title"],
              "severity": finding["severity"], "detail": finding["detail"],
              "target": target})
        report_md = ("# Scorpion.ai report\n\n## Summary\n\n"
                     "One **high** severity finding on %s.\n\n"
                     "- Exposed admin panel at `/admin`\n" % target)
        emit({"type": "report", "ts": time.time(),
              "text": "report ready", "markdown": report_md})
        emit({"type": "done", "ts": time.time(),
              "text": "engagement finished", "engine": "fake", "steps": 2,
              "findings": [finding], "report": report_md})
        return {"engine": "fake", "target": target, "findings": [finding],
                "report": report_md, "steps": 2, "stop_reason": "end_turn"}


class BlockingFakeAgent:
    """Emits one status then blocks until released — to test 'running' state."""

    def __init__(self):
        self.release = threading.Event()
        self.started = threading.Event()

    def run(self, target, goal=None, on_event=None):
        if on_event:
            on_event({"type": "status", "ts": time.time(),
                      "text": "working on %s" % target, "engine": "fake"})
        self.started.set()
        self.release.wait(timeout=10)
        if on_event:
            on_event({"type": "done", "ts": time.time(), "text": "done",
                      "findings": [], "report": "", "engine": "fake"})
        return {"engine": "fake", "target": target, "findings": [], "report": ""}


def quick_factory(agent=None):
    holder = {"agent": agent}

    def factory(cfg, scope, limiter, registry):
        a = holder["agent"] or QuickFakeAgent()
        holder["agent"] = None  # fresh agent per engagement if none pinned
        return a
    return factory


# --------------------------------------------------------------------------
# http helpers (loopback only)
# --------------------------------------------------------------------------
def _request(method, url, body=None, timeout=5):
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urlrequest.Request(url, data=data, headers=headers, method=method)
    try:
        with urlrequest.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return resp.status, raw
    except HTTPError as exc:
        return exc.code, exc.read()


def _get(url, timeout=5):
    return _request("GET", url, timeout=timeout)


def _post(url, body, timeout=5):
    return _request("POST", url, body=body, timeout=timeout)


def _json(raw):
    return json.loads(raw.decode("utf-8"))


class ServerHarness:
    """Boot a ScorpionServer on 127.0.0.1:0 in a background thread."""

    def __init__(self, factory, cfg=None):
        self.cfg = cfg or Config(host="127.0.0.1", port=0, no_llm=True)
        self.server = ScorpionServer(self.cfg, factory)
        self.httpd = self.server.build_httpd()
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.thread.join(timeout=5)

    @property
    def base(self):
        host, port = self.server.address
        return "http://127.0.0.1:%d" % port

    def url(self, path):
        return self.base + path


def _wait_for(predicate, timeout=5.0, interval=0.03):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


# --------------------------------------------------------------------------
# tests
# --------------------------------------------------------------------------
class IndexAndStaticTest(unittest.TestCase):
    def test_root_serves_dashboard_html(self):
        with ServerHarness(quick_factory()) as h:
            code, raw = _get(h.url("/"))
            self.assertEqual(code, 200)
            body = raw.decode("utf-8")
            self.assertIn("Scorpion.ai", body)
            self.assertIn("<title>Scorpion.ai</title>", body)

    def test_static_assets(self):
        with ServerHarness(quick_factory()) as h:
            for path, needle in (("/app.js", "EventSource"),
                                 ("/style.css", "--accent")):
                code, raw = _get(h.url(path))
                self.assertEqual(code, 200, path)
                self.assertIn(needle, raw.decode("utf-8"), path)

    def test_unknown_path_404(self):
        with ServerHarness(quick_factory()) as h:
            code, _ = _get(h.url("/nope"))
            self.assertEqual(code, 404)

    def test_path_traversal_blocked(self):
        with ServerHarness(quick_factory()) as h:
            code, _ = _get(h.url("/../server.py"))
            self.assertIn(code, (400, 404))


class ConfigTest(unittest.TestCase):
    def test_config_shape(self):
        with ServerHarness(quick_factory()) as h:
            code, raw = _get(h.url("/api/config"))
            self.assertEqual(code, 200)
            obj = _json(raw)
            for key in ("config", "scope", "brain", "telegram", "status"):
                self.assertIn(key, obj)
            # secrets never leak: redacted() masks the key to "" or "set"
            self.assertIn(obj["config"].get("anthropic_api_key"), ("", "set"))
            self.assertIn("available", obj["brain"])
            self.assertTrue(obj["scope"].get("empty"))  # fail-closed by default

    def test_config_brain_available_tracks_cfg(self):
        cfg = Config(host="127.0.0.1", port=0,
                     anthropic_api_key="x-test-key", no_llm=False)
        with ServerHarness(quick_factory(), cfg=cfg) as h:
            obj = _json(_get(h.url("/api/config"))[1])
            self.assertTrue(obj["brain"]["available"])


class ScopeTest(unittest.TestCase):
    def test_set_scope(self):
        with ServerHarness(quick_factory()) as h:
            code, raw = _post(h.url("/api/scope"),
                              {"allow": "example.com, *.example.com",
                               "deny": "secret.example.com"})
            self.assertEqual(code, 200)
            obj = _json(raw)
            self.assertIn("example.com", obj["allow"])
            self.assertIn("*.example.com", obj["allow"])
            self.assertIn("secret.example.com", obj["deny"])
            self.assertFalse(obj["empty"])
            # and it is reflected on the live server scope
            self.assertTrue(h.server.scope.is_in_scope("https://app.example.com"))
            self.assertFalse(h.server.scope.is_in_scope("https://secret.example.com"))

    def test_scope_accepts_list_form(self):
        with ServerHarness(quick_factory()) as h:
            obj = _json(_post(h.url("/api/scope"),
                              {"allow": ["a.com", "b.com"], "deny": []})[1])
            self.assertEqual(sorted(obj["allow"]), ["a.com", "b.com"])


class StartEngagementTest(unittest.TestCase):
    def test_start_out_of_scope_refused(self):
        with ServerHarness(quick_factory()) as h:
            # scope empty by default -> fail closed
            code, raw = _post(h.url("/api/start"), {"target": "example.com"})
            self.assertEqual(code, 400)
            obj = _json(raw)
            self.assertEqual(obj.get("error"), "out_of_scope")
            self.assertIn("message", obj)

    def test_start_requires_target(self):
        with ServerHarness(quick_factory()) as h:
            code, raw = _post(h.url("/api/start"), {"target": ""})
            self.assertEqual(code, 400)

    def test_start_runs_fake_agent_and_populates_engagement(self):
        with ServerHarness(quick_factory()) as h:
            _post(h.url("/api/scope"), {"allow": "example.com"})
            code, raw = _post(h.url("/api/start"),
                              {"target": "https://example.com",
                               "goal": "find exposed admin"})
            self.assertEqual(code, 202)
            self.assertTrue(_json(raw)["accepted"])

            # the fake agent finishes almost immediately
            got = _wait_for(lambda: _json(_get(h.url("/api/engagement"))[1])
                            .get("status") == "done", timeout=5)
            self.assertTrue(got, "engagement never reached 'done'")

            eng = _json(_get(h.url("/api/engagement"))[1])
            self.assertEqual(eng["target"], "https://example.com")
            self.assertEqual(eng["goal"], "find exposed admin")
            self.assertFalse(eng["running"])
            self.assertEqual(len(eng["findings"]), 1)
            f = eng["findings"][0]
            self.assertEqual(f["severity"], "high")
            self.assertEqual(f["title"], "Exposed admin panel")
            self.assertIn("Scorpion.ai report", eng["report"])

    def test_second_start_while_running_conflicts(self):
        blocker = BlockingFakeAgent()
        with ServerHarness(quick_factory(agent=blocker)) as h:
            _post(h.url("/api/scope"), {"allow": "example.com"})
            code, _ = _post(h.url("/api/start"), {"target": "example.com"})
            self.assertEqual(code, 202)
            self.assertTrue(blocker.started.wait(timeout=5))

            # a second start must be refused with 409
            code2, raw2 = _post(h.url("/api/start"), {"target": "example.com"})
            self.assertEqual(code2, 409)
            self.assertIn("error", _json(raw2))

            # engagement reports running
            eng = _json(_get(h.url("/api/engagement"))[1])
            self.assertTrue(eng["running"])
            self.assertEqual(eng["status"], "running")

            blocker.release.set()
            self.assertTrue(_wait_for(
                lambda: not _json(_get(h.url("/api/engagement"))[1])["running"],
                timeout=5))


class ChatTest(unittest.TestCase):
    def test_chat_accepted_when_idle(self):
        with ServerHarness(quick_factory()) as h:
            code, raw = _post(h.url("/api/chat"), {"message": "hello agent"})
            self.assertEqual(code, 200)
            obj = _json(raw)
            self.assertTrue(obj["accepted"])
            self.assertFalse(obj["running"])

    def test_empty_chat_rejected(self):
        with ServerHarness(quick_factory()) as h:
            obj = _json(_post(h.url("/api/chat"), {"message": "   "})[1])
            self.assertFalse(obj["accepted"])


class SSETest(unittest.TestCase):
    def test_events_stream_emits_data_lines(self):
        with ServerHarness(quick_factory()) as h:
            _post(h.url("/api/scope"), {"allow": "example.com"})
            _post(h.url("/api/start"), {"target": "example.com"})
            # let the canned events accumulate in the bus history
            self.assertTrue(_wait_for(
                lambda: _json(_get(h.url("/api/engagement"))[1]).get("status")
                == "done", timeout=5))

            # open the SSE stream and read until we see at least one data line
            resp = urlrequest.urlopen(h.url("/api/events"), timeout=5)
            try:
                ctype = resp.headers.get("Content-Type", "")
                self.assertIn("text/event-stream", ctype)
                found = None
                for _ in range(400):
                    line = resp.readline()
                    if not line:
                        break
                    if line.startswith(b"data:"):
                        found = line
                        break
                self.assertIsNotNone(found, "no SSE 'data:' line received")
                payload = json.loads(found[len(b"data:"):].strip().decode("utf-8"))
                self.assertIn("type", payload)
            finally:
                resp.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
