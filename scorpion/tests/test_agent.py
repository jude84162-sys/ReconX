"""Tests for the Scorpion orchestrator (agent + planner + memory + subagents).

NETWORK ISOLATION: these tests never touch the internet or any real API. The
Brain is replaced with a scripted ``FakeBrain``, and the tools are tiny in-memory
``Tool`` subclasses that return canned ``ToolResult`` objects — no module under
``modules/*`` is imported and no socket is opened. Sibling Scorpion components
still under construction (the real Brain client, the notifier, the dashboard)
are stubbed, so this suite does not depend on a half-written file.

Run just this module from the repo root:
    python3 -m unittest scorpion.tests.test_agent -v
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

from scorpion.config import Config
from scorpion.scope import Scope
from scorpion.ratelimit import NullRateLimiter
from scorpion.tools.base import Tool, ToolResult, ToolRegistry

from scorpion.memory import (
    Memory,
    Engagement,
    make_event,
    dispatch_event,
    notify_safely,
    normalize_severity,
    safe_target_name,
)
from scorpion import planner as planner_mod
from scorpion import subagents
from scorpion.agent import Agent


# --------------------------------------------------------------------------- #
# scripted Brain + fake notifier (sibling stubs — never the real ones)
# --------------------------------------------------------------------------- #
def _tool_use(tool_id, name, inp, text=""):
    content = []
    if text:
        content.append({"type": "text", "text": text})
    content.append({"type": "tool_use", "id": tool_id, "name": name,
                    "input": inp})
    return {"text": text, "assistant_content": content,
            "tool_calls": [{"id": tool_id, "name": name, "input": inp}],
            "stop_reason": "tool_use", "usage": {}, "error": ""}


def _final(text=""):
    content = [{"type": "text", "text": text}] if text else []
    return {"text": text, "assistant_content": content, "tool_calls": [],
            "stop_reason": "end_turn", "usage": {}, "error": ""}


def _json_findings(findings):
    body = json.dumps({"findings": findings})
    return {"text": body, "assistant_content": [{"type": "text", "text": body}],
            "tool_calls": [], "stop_reason": "end_turn", "usage": {}, "error": ""}


class FakeBrain:
    """Scripted stand-in for scorpion.brain.claude.Brain (no network)."""

    def __init__(self, responses=None, default=None, available=True):
        self.responses = list(responses or [])
        self.default = default if default is not None else _final("")
        self.available = available
        self.calls = []

    def complete(self, system, messages, tools=None, model=None,
                 max_tokens=None):
        self.calls.append({"system": system, "messages": messages,
                           "tools": tools, "model": model})
        if self.responses:
            return self.responses.pop(0)
        return dict(self.default)


class FakeNotifier:
    def __init__(self):
        self.events = []

    def notify(self, event):
        self.events.append(event)


# --------------------------------------------------------------------------- #
# in-memory tools (no modules/* import, no network)
# --------------------------------------------------------------------------- #
CALL_LOG = []


class OsintTool(Tool):
    name = "resolve_and_osint"
    description = "dummy osint"
    scope_field = "domain"
    input_schema = {"type": "object",
                    "properties": {"domain": {"type": "string"}},
                    "required": ["domain"]}

    def _execute(self, domain="", **_):
        CALL_LOG.append((self.name, {"domain": domain}))
        return ToolResult(
            ok=True, tool=self.name, target=domain, summary="osint ok",
            data={"findings": [{"title": "Exposed .git directory",
                                "severity": "medium",
                                "type": "exposed-git",
                                "url": "http://example.com/.git/"}],
                  "subdomains": ["api.example.com"]})


class VulnTool(Tool):
    name = "vuln_scan"
    description = "dummy vuln scan"
    scope_field = "target"
    input_schema = {"type": "object",
                    "properties": {"target": {"type": "string"},
                                   "scanner": {"type": "string"}},
                    "required": ["target"]}

    def _execute(self, target="", scanner="", **_):
        CALL_LOG.append((self.name, {"target": target, "scanner": scanner}))
        return ToolResult(ok=True, tool=self.name, target=target,
                          summary="1 finding",
                          data={"findings": [{"title": "SQL injection",
                                              "severity": "high",
                                              "type": "sqli",
                                              "url": target}]})


class BoomTool(Tool):
    name = "resolve_and_osint"   # same name, but raises
    description = "raises"
    scope_field = "domain"
    input_schema = {"type": "object",
                    "properties": {"domain": {"type": "string"}},
                    "required": ["domain"]}

    def _execute(self, domain="", **_):
        CALL_LOG.append((self.name, {"domain": domain}))
        raise RuntimeError("kaboom")


def _cfg(tmpdir, **over):
    base = dict(scope_allow=["example.com"], data_dir=tmpdir, max_steps=8,
                no_llm=False, anthropic_api_key="")
    base.update(over)
    return Config(**base)


def _registry(cfg, tool_classes):
    scope = Scope.from_config(cfg)
    reg = ToolRegistry(scope, NullRateLimiter(), cfg)
    reg.register_all(tool_classes)
    return reg


# --------------------------------------------------------------------------- #
# memory
# --------------------------------------------------------------------------- #
class MemoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="scorp-mem-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_safe_target_name(self):
        self.assertEqual(safe_target_name("https://API.Example.com/path?x=1"),
                         "api.example.com")
        self.assertEqual(safe_target_name("203.0.113.0/24"), "203.0.113.0_24")
        self.assertEqual(safe_target_name(""), "unknown")
        self.assertNotIn("/", safe_target_name("a/../../etc/passwd"))

    def test_save_load_round_trip(self):
        mem = Memory("api.example.com", scope_desc="allow=example.com",
                     data_dir=self.tmp, goal="find auth bugs")
        mem.add_event(make_event("status", "starting"))
        mem.add_event(make_event("tool_call", "resolve_and_osint", tool="x"))
        mem.add_finding({"title": "SQLi", "severity": "HIGH",
                         "target": "api.example.com"})
        mem.set_report("# Report\nhello")
        path = mem.save()

        self.assertTrue(os.path.isfile(path))
        self.assertTrue(path.endswith(os.path.join("api.example.com",
                                                    "state.json")))
        loaded = Memory.load(path)
        self.assertEqual(loaded.target, "api.example.com")
        self.assertEqual(loaded.scope_desc, "allow=example.com")
        self.assertEqual(loaded.goal, "find auth bugs")
        self.assertEqual(len(loaded.events), 2)
        self.assertEqual(len(loaded.findings), 1)
        self.assertEqual(loaded.findings[0]["severity"], "high")  # normalised
        self.assertEqual(loaded.report, "# Report\nhello")

    def test_open_reloads_existing(self):
        m1 = Memory.open(self.tmp, "example.com", scope_desc="allow=example.com")
        m1.add_finding({"title": "X", "severity": "low"})
        m1.save()
        m2 = Memory.open(self.tmp, "example.com")
        self.assertEqual(len(m2.findings), 1)

    def test_engagement_is_alias(self):
        self.assertIs(Engagement, Memory)


# --------------------------------------------------------------------------- #
# event plumbing
# --------------------------------------------------------------------------- #
class EventDispatchTests(unittest.TestCase):
    def test_dispatch_fans_out_and_isolates_failures(self):
        mem = Memory("example.com", data_dir=tempfile.mkdtemp(prefix="scorp-ev-"))
        got = []

        def bad_sink(ev):
            raise ValueError("sink boom")

        notifier = FakeNotifier()
        # on_event raises -> must not propagate; memory + notifier still updated
        ev = dispatch_event(make_event("status", "hi"), on_event=bad_sink,
                            memory=mem, notifier=notifier)
        self.assertEqual(ev["type"], "status")
        self.assertEqual(len(mem.events), 1)
        self.assertEqual(len(notifier.events), 1)

        # a good sink receives it too
        dispatch_event(make_event("finding", "f"), on_event=got.append,
                       memory=mem, notifier=notifier)
        self.assertEqual(got[0]["type"], "finding")

    def test_notify_safely_accepts_callable(self):
        seen = []
        notify_safely(seen.append, make_event("status", "x"))
        self.assertEqual(len(seen), 1)
        # a raising notifier never propagates
        notify_safely(lambda e: (_ for _ in ()).throw(RuntimeError()),
                      make_event("status", "x"))


# --------------------------------------------------------------------------- #
# candidate extraction
# --------------------------------------------------------------------------- #
class ExtractCandidatesTests(unittest.TestCase):
    def test_scanner_findings(self):
        r = ToolResult(ok=True, tool="vuln_scan", target="http://example.com",
                       data={"findings": [{"title": "XSS", "severity": "high",
                                           "url": "http://example.com/?q="}]})
        cands = planner_mod.extract_candidates(r)
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0]["severity"], "high")

    def test_zone_transfer_and_headers_and_tls(self):
        r1 = ToolResult(ok=True, tool="dns_recon", target="example.com",
                        data={"zone_transfer_open": True,
                              "zone_transfer_ns": "ns1.example.com"})
        r2 = ToolResult(ok=True, tool="web_fingerprint", target="http://example.com",
                        data={"missing_headers": ["Content-Security-Policy",
                                                  "Strict-Transport-Security"]})
        r3 = ToolResult(ok=True, tool="ssl_analyze", target="example.com",
                        data={"grade": "F", "issues": ["SSLv3 enabled"]})
        self.assertEqual(planner_mod.extract_candidates(r1)[0]["severity"], "high")
        self.assertEqual(planner_mod.extract_candidates(r2)[0]["type"],
                         "missing-security-headers")
        self.assertEqual(planner_mod.extract_candidates(r3)[0]["type"], "weak-tls")

    def test_blocked_result_yields_nothing(self):
        r = ToolResult(ok=False, tool="x", target="evil.com", blocked=True,
                       data={})
        self.assertEqual(planner_mod.extract_candidates(r), [])


# --------------------------------------------------------------------------- #
# subagents
# --------------------------------------------------------------------------- #
class SubagentTests(unittest.TestCase):
    def test_triage_rules_dedupes(self):
        cands = [
            {"title": "SQLi", "severity": "medium", "type": "sqli",
             "target": "http://example.com/a"},
            {"title": "SQLi", "severity": "high", "type": "sqli",
             "target": "http://example.com/a"},
            {"title": "XSS", "severity": "low", "type": "xss",
             "target": "http://example.com/b"},
        ]
        out = subagents.triage(None, cands)
        self.assertEqual(len(out), 2)                 # the two SQLi merged
        self.assertEqual(out[0]["severity"], "high")  # worst kept, ranked first

    def test_triage_brain_json_path(self):
        brain = FakeBrain(responses=[_json_findings([
            {"title": "Auth bypass", "severity": "critical",
             "target": "example.com", "detail": "d", "false_positive": False},
            {"title": "noise", "severity": "info", "false_positive": True},
        ])])
        out = subagents.triage(brain, [{"title": "x", "severity": "low"}],
                               target="example.com")
        self.assertEqual(len(out), 1)                 # false positive dropped
        self.assertEqual(out[0]["severity"], "critical")
        self.assertEqual(len(brain.calls), 1)

    def test_triage_brain_falls_back_on_garbage(self):
        brain = FakeBrain(responses=[_final("not json at all")])
        out = subagents.triage(brain, [{"title": "SQLi", "severity": "high",
                                        "type": "sqli", "target": "t"}])
        self.assertEqual(len(out), 1)                 # rules fallback kept it

    def test_write_report_template(self):
        md = subagents.write_report(None, "example.com", "allow=example.com",
                                    [{"title": "SQLi", "severity": "high",
                                      "target": "http://example.com/a",
                                      "detail": "param id"}])
        self.assertIn("# Engagement Report", md)
        self.assertIn("SQLi", md)
        self.assertIn("Severity: high", md)

    def test_write_report_brain_path(self):
        brain = FakeBrain(responses=[_final("# Custom Report\nall good")])
        md = subagents.write_report(brain, "example.com", "allow=example.com", [])
        self.assertEqual(md, "# Custom Report\nall good")


# --------------------------------------------------------------------------- #
# agent — LLM tool loop
# --------------------------------------------------------------------------- #
class AgentLLMLoopTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="scorp-agent-")
        del CALL_LOG[:]

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_loop_calls_tool_emits_events_and_reports(self):
        cfg = _cfg(self.tmp)
        reg = _registry(cfg, [OsintTool, VulnTool])
        brain = FakeBrain(responses=[
            _tool_use("t1", "resolve_and_osint", {"domain": "example.com"},
                      text="Starting passive recon."),
            _final("Found an exposed .git directory on example.com (medium)."),
        ])
        notifier = FakeNotifier()
        events = []
        agent = Agent(cfg, reg, brain, memory=None, notifier=notifier)
        result = agent.run("example.com", goal="find exposures",
                           on_event=events.append)

        # the tool the model asked for actually ran, exactly once
        self.assertEqual(CALL_LOG, [("resolve_and_osint", {"domain": "example.com"})])

        self.assertEqual(result["engine"], "llm")
        self.assertEqual(result["stop_reason"], "end_turn")
        self.assertTrue(result["findings"])
        self.assertTrue(any(f.get("severity") == "medium"
                            for f in result["findings"]))
        self.assertIn("# Engagement Report", result["report"])

        types = [e["type"] for e in events]
        for needed in ("status", "thinking", "tool_call", "tool_result",
                       "finding", "report", "done"):
            self.assertIn(needed, types, "missing %s event" % needed)

        # notifier saw the run too, including the terminal 'done'
        self.assertTrue(any(e["type"] == "done" for e in notifier.events))

        # memory persisted
        self.assertTrue(os.path.isfile(agent.memory.path))
        self.assertTrue(agent.memory.findings)

    def test_respects_max_steps(self):
        cfg = _cfg(self.tmp, max_steps=3)
        reg = _registry(cfg, [OsintTool])
        # a Brain that NEVER stops asking for the tool
        loop_resp = _tool_use("t", "resolve_and_osint", {"domain": "example.com"})
        brain = FakeBrain(responses=[], default=loop_resp)
        agent = Agent(cfg, reg, brain, notifier=None)
        result = agent.run("example.com")
        # exactly max_steps tool executions, not more
        self.assertEqual(len(CALL_LOG), 3)
        self.assertEqual(result["steps"], 3)
        self.assertEqual(result["engine"], "llm")

    def test_wall_clock_budget_stops_before_first_step(self):
        cfg = _cfg(self.tmp)
        reg = _registry(cfg, [OsintTool])
        brain = FakeBrain(responses=[], default=_tool_use(
            "t", "resolve_and_osint", {"domain": "example.com"}))
        agent = Agent(cfg, reg, brain)
        result = agent.run("example.com", budget_seconds=0)
        self.assertEqual(result["steps"], 0)
        self.assertEqual(CALL_LOG, [])
        self.assertEqual(result["stop_reason"], "budget")
        # a report is still produced
        self.assertIn("# Engagement Report", result["report"])

    def test_tool_error_never_aborts_run(self):
        cfg = _cfg(self.tmp)
        reg = _registry(cfg, [BoomTool])
        brain = FakeBrain(responses=[
            _tool_use("t1", "resolve_and_osint", {"domain": "example.com"}),
            _final("done despite the tool error."),
        ])
        events = []
        agent = Agent(cfg, reg, brain)
        result = agent.run("example.com", on_event=events.append)
        # the run completed and returned, the tool was invoked and failed softly
        self.assertEqual(result["engine"], "llm")
        self.assertEqual(len(CALL_LOG), 1)
        tr = [e for e in events if e["type"] == "tool_result"]
        self.assertTrue(tr and tr[0]["ok"] is False)

    def test_brain_error_is_surfaced_not_raised(self):
        cfg = _cfg(self.tmp)
        reg = _registry(cfg, [OsintTool])
        brain = FakeBrain(responses=[{"text": "", "assistant_content": [],
                                      "tool_calls": [], "stop_reason": "",
                                      "usage": {}, "error": "HTTP 529: overloaded"}])
        events = []
        agent = Agent(cfg, reg, brain)
        result = agent.run("example.com", on_event=events.append)
        self.assertEqual(result["engine"], "llm")
        self.assertTrue(any(e["type"] == "error" for e in events))


# --------------------------------------------------------------------------- #
# agent — no-LLM planner fallback
# --------------------------------------------------------------------------- #
class AgentPlannerFallbackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="scorp-plan-")
        del CALL_LOG[:]

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_no_llm_uses_planner(self):
        cfg = _cfg(self.tmp, no_llm=True)
        reg = _registry(cfg, [OsintTool])
        brain = FakeBrain(available=True)   # present but no_llm forces planner
        events = []
        agent = Agent(cfg, reg, brain, notifier=None)
        result = agent.run("example.com", on_event=events.append)

        self.assertEqual(result["engine"], "planner")
        self.assertEqual(len(brain.calls), 0)          # brain never consulted
        # the deterministic pipeline invoked the one registered tool
        self.assertIn(("resolve_and_osint", {"domain": "example.com"}), CALL_LOG)
        self.assertTrue(result["findings"])
        self.assertIn("# Engagement Report", result["report"])

        types = [e["type"] for e in events]
        for needed in ("tool_call", "tool_result", "finding", "report", "done"):
            self.assertIn(needed, types)
        self.assertTrue(os.path.isfile(agent.memory.path))

    def test_unavailable_brain_uses_planner(self):
        cfg = _cfg(self.tmp, no_llm=False)
        reg = _registry(cfg, [OsintTool])
        brain = FakeBrain(available=False)
        agent = Agent(cfg, reg, brain)
        result = agent.run("example.com")
        self.assertEqual(result["engine"], "planner")

    def test_planner_run_direct_skips_absent_tools(self):
        cfg = _cfg(self.tmp, no_llm=True)
        reg = _registry(cfg, [])            # empty registry: everything skipped
        mem = Memory.from_config(cfg, "example.com")
        result = planner_mod.run("example.com", reg, on_event=None, memory=mem)
        self.assertEqual(result["engine"], "planner")
        self.assertEqual(result["steps"], 0)          # nothing to run
        self.assertEqual(result["findings"], [])
        self.assertIn("# Engagement Report", result["report"])


if __name__ == "__main__":
    unittest.main()
