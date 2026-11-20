"""Tests for the Brain (Anthropic Messages client) and the prompts.

NETWORK ISOLATION: every test replaces ``urllib.request.urlopen`` with a fake
that returns canned Anthropic JSON (or raises a canned HTTPError). Nothing here
ever opens a socket or touches the real Anthropic API, and ``time.sleep`` is
stubbed so retry/backoff paths run instantly.

Run just this module from the repo root:
    python3 -m unittest scorpion.tests.test_brain -v
"""
import io
import json
import unittest
from unittest import mock
from urllib.error import HTTPError, URLError

from scorpion.config import Config, load_config
from scorpion.brain.claude import Brain, _parse_response
from scorpion.brain import prompts


# --------------------------------------------------------------------------
# canned API responses
# --------------------------------------------------------------------------
TEXT_RESPONSE = {
    "id": "msg_text",
    "type": "message",
    "role": "assistant",
    "model": "claude-sonnet-5-5",
    "content": [
        {"type": "text", "text": "Hello from the model."},
    ],
    "stop_reason": "end_turn",
    "stop_sequence": None,
    "usage": {"input_tokens": 10, "output_tokens": 4},
}

TOOL_RESPONSE = {
    "id": "msg_tool",
    "type": "message",
    "role": "assistant",
    "model": "claude-sonnet-5-5",
    "content": [
        {"type": "text", "text": "I'll enumerate subdomains."},
        {"type": "tool_use", "id": "toolu_01",
         "name": "subdomains", "input": {"domain": "example.com"}},
    ],
    "stop_reason": "tool_use",
    "usage": {"input_tokens": 22, "output_tokens": 18},
}


class _FakeResponse:
    """Minimal stand-in for the urlopen context-manager object."""

    def __init__(self, payload):
        if isinstance(payload, (dict, list)):
            payload = json.dumps(payload)
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        self._payload = payload

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _http_error(code, body=None, headers=None):
    if body is None:
        body = {"type": "error",
                "error": {"type": "api_error", "message": "boom %d" % code}}
    if isinstance(body, (dict, list)):
        body = json.dumps(body)
    fp = io.BytesIO(body.encode("utf-8") if isinstance(body, str) else body)
    return HTTPError("https://api.test/v1/messages", code, "err",
                     headers or {}, fp)


def _brain(**overrides):
    """A Brain with a key set (so .available is True) and no real sleeping."""
    cfg = Config(anthropic_api_key="sk-test-key", model="claude-sonnet-5-5",
                 max_tokens=1024, **overrides)
    b = Brain(cfg, base_delay=0.0, max_delay=0.0)
    return b


# --------------------------------------------------------------------------
# availability
# --------------------------------------------------------------------------
class AvailabilityTests(unittest.TestCase):
    def test_available_false_without_key(self):
        b = Brain(load_config(anthropic_api_key=""))
        self.assertFalse(b.available)

    def test_available_false_when_no_llm(self):
        b = Brain(Config(anthropic_api_key="sk-x", no_llm=True))
        self.assertFalse(b.available)

    def test_available_true_with_key(self):
        self.assertTrue(_brain().available)

    def test_complete_short_circuits_when_unavailable(self):
        b = Brain(Config(anthropic_api_key=""))  # no key -> unavailable
        # urlopen must never be called; make it explode if it is.
        with mock.patch("urllib.request.urlopen",
                        side_effect=AssertionError("network touched!")):
            out = b.complete(system="s", messages=[{"role": "user", "content": "hi"}])
        self.assertTrue(out["error"])
        self.assertEqual(out["tool_calls"], [])
        self.assertEqual(out["assistant_content"], [])


# --------------------------------------------------------------------------
# parsing a text response
# --------------------------------------------------------------------------
class TextResponseTests(unittest.TestCase):
    def test_parses_text_and_shape(self):
        b = _brain()
        with mock.patch("urllib.request.urlopen",
                        return_value=_FakeResponse(TEXT_RESPONSE)) as uo:
            out = b.complete(system="sys",
                             messages=[{"role": "user", "content": "hi"}])
        self.assertEqual(uo.call_count, 1)
        self.assertEqual(out["error"], "")
        self.assertEqual(out["text"], "Hello from the model.")
        self.assertEqual(out["stop_reason"], "end_turn")
        self.assertEqual(out["tool_calls"], [])
        self.assertEqual(out["usage"], {"input_tokens": 10, "output_tokens": 4})
        # assistant_content is the raw content list, verbatim, for replay
        self.assertEqual(out["assistant_content"], TEXT_RESPONSE["content"])

    def test_request_is_well_formed(self):
        """Capture the outgoing request and assert endpoint/headers/body."""
        captured = {}

        def fake_urlopen(req, timeout=None):
            captured["url"] = req.full_url
            captured["method"] = req.get_method()
            captured["headers"] = {k.lower(): v for k, v in req.header_items()}
            captured["body"] = json.loads(req.data.decode("utf-8"))
            return _FakeResponse(TEXT_RESPONSE)

        b = _brain()
        tools = [{"name": "subdomains", "description": "d",
                  "input_schema": {"type": "object", "properties": {}}}]
        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            b.complete(system="SYS", messages=[{"role": "user", "content": "hi"}],
                       tools=tools, max_tokens=321)

        self.assertEqual(captured["url"], "https://api.anthropic.com/v1/messages")
        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["headers"]["x-api-key"], "sk-test-key")
        self.assertEqual(captured["headers"]["anthropic-version"], "2023-06-01")
        self.assertEqual(captured["headers"]["content-type"], "application/json")
        self.assertEqual(captured["body"]["model"], "claude-sonnet-5-5")
        self.assertEqual(captured["body"]["max_tokens"], 321)
        self.assertEqual(captured["body"]["system"], "SYS")
        self.assertEqual(captured["body"]["tools"], tools)

    def test_model_override(self):
        captured = {}

        def fake_urlopen(req, timeout=None):
            captured["body"] = json.loads(req.data.decode("utf-8"))
            return _FakeResponse(TEXT_RESPONSE)

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            _brain().complete(system=None, messages=[{"role": "user", "content": "x"}],
                              model="claude-opus-5-5")
        self.assertEqual(captured["body"]["model"], "claude-opus-5-5")
        self.assertNotIn("system", captured["body"])
        self.assertNotIn("tools", captured["body"])


# --------------------------------------------------------------------------
# parsing a tool_use response
# --------------------------------------------------------------------------
class ToolResponseTests(unittest.TestCase):
    def test_parses_tool_calls(self):
        b = _brain()
        with mock.patch("urllib.request.urlopen",
                        return_value=_FakeResponse(TOOL_RESPONSE)):
            out = b.complete(system="sys",
                             messages=[{"role": "user", "content": "scan example.com"}])
        self.assertEqual(out["error"], "")
        self.assertEqual(out["stop_reason"], "tool_use")
        self.assertEqual(out["text"], "I'll enumerate subdomains.")
        self.assertEqual(len(out["tool_calls"]), 1)
        call = out["tool_calls"][0]
        self.assertEqual(call["id"], "toolu_01")
        self.assertEqual(call["name"], "subdomains")
        self.assertEqual(call["input"], {"domain": "example.com"})
        # the full content (text + tool_use) is preserved for replay
        self.assertEqual(out["assistant_content"], TOOL_RESPONSE["content"])

    def test_multiple_tool_calls(self):
        resp = {
            "content": [
                {"type": "tool_use", "id": "t1", "name": "a", "input": {"x": 1}},
                {"type": "tool_use", "id": "t2", "name": "b", "input": {}},
            ],
            "stop_reason": "tool_use",
            "usage": {},
        }
        out = _parse_response(resp)
        self.assertEqual([c["name"] for c in out["tool_calls"]], ["a", "b"])
        self.assertEqual(out["tool_calls"][0]["input"], {"x": 1})
        self.assertEqual(out["tool_calls"][1]["input"], {})


# --------------------------------------------------------------------------
# error handling — must never raise
# --------------------------------------------------------------------------
class ErrorHandlingTests(unittest.TestCase):
    def test_http_400_error_body_no_raise(self):
        b = _brain()
        with mock.patch("urllib.request.urlopen", side_effect=_http_error(
                400, {"type": "error",
                      "error": {"type": "invalid_request_error",
                                "message": "bad model"}})):
            out = b.complete(system="s", messages=[{"role": "user", "content": "x"}])
        self.assertIn("400", out["error"])
        self.assertIn("bad model", out["error"])
        self.assertEqual(out["text"], "")
        self.assertEqual(out["tool_calls"], [])
        self.assertEqual(out["assistant_content"], [])

    def test_400_is_not_retried(self):
        b = _brain()
        uo = mock.MagicMock(side_effect=_http_error(400))
        with mock.patch("urllib.request.urlopen", uo):
            b.complete(system="s", messages=[{"role": "user", "content": "x"}])
        self.assertEqual(uo.call_count, 1)        # client error -> no retry

    def test_top_level_error_object_in_200(self):
        body = {"type": "error",
                "error": {"type": "overloaded_error", "message": "too busy"}}
        out = _parse_response(body)
        self.assertIn("too busy", out["error"])
        self.assertEqual(out["tool_calls"], [])

    def test_invalid_json_body(self):
        b = _brain()
        with mock.patch("urllib.request.urlopen",
                        return_value=_FakeResponse(b"not-json-at-all")):
            out = b.complete(system="s", messages=[{"role": "user", "content": "x"}])
        self.assertIn("invalid JSON", out["error"])

    def test_network_error_no_raise(self):
        b = _brain()
        with mock.patch("urllib.request.urlopen",
                        side_effect=URLError("name resolution failed")):
            out = b.complete(system="s", messages=[{"role": "user", "content": "x"}])
        self.assertIn("network error", out["error"])
        self.assertEqual(out["assistant_content"], [])


# --------------------------------------------------------------------------
# retry/backoff
# --------------------------------------------------------------------------
class RetryTests(unittest.TestCase):
    def test_retries_on_429_then_succeeds(self):
        calls = {"n": 0}

        def flaky(req, timeout=None):
            calls["n"] += 1
            if calls["n"] < 3:
                raise _http_error(429, headers={"retry-after": "0"})
            return _FakeResponse(TEXT_RESPONSE)

        b = _brain()
        with mock.patch("time.sleep") as slept, \
                mock.patch("urllib.request.urlopen", side_effect=flaky):
            out = b.complete(system="s", messages=[{"role": "user", "content": "x"}])
        self.assertEqual(calls["n"], 3)
        self.assertEqual(out["error"], "")
        self.assertEqual(out["text"], "Hello from the model.")
        self.assertGreaterEqual(slept.call_count, 2)   # backed off before each retry

    def test_gives_up_after_max_retries(self):
        cfg = Config(anthropic_api_key="sk", model="m", max_tokens=16)
        b = Brain(cfg, max_retries=2, base_delay=0.0, max_delay=0.0)
        uo = mock.MagicMock(side_effect=_http_error(529))   # always overloaded
        with mock.patch("time.sleep"), \
                mock.patch("urllib.request.urlopen", uo):
            out = b.complete(system="s", messages=[{"role": "user", "content": "x"}])
        self.assertEqual(uo.call_count, 3)              # 1 try + 2 retries
        self.assertIn("529", out["error"])


# --------------------------------------------------------------------------
# prompts
# --------------------------------------------------------------------------
class PromptTests(unittest.TestCase):
    def test_system_prompt_mentions_scope_and_methodology(self):
        self.assertIn("SCOPE", prompts.SYSTEM_PROMPT.upper())
        low = prompts.SYSTEM_PROMPT.lower()
        for step in ("recon", "enumerate", "fingerprint", "triage", "report"):
            self.assertIn(step, low)

    def test_build_system_prompt_appends_engagement(self):
        out = prompts.build_system_prompt(target="example.com",
                                          scope_desc="scope: allow=example.com",
                                          max_steps=40, rate_per_host=8.0)
        self.assertTrue(out.startswith(prompts.SYSTEM_PROMPT.rstrip()[:30]))
        self.assertIn("example.com", out)
        self.assertIn("40", out)
        self.assertIn("This engagement", out)

    def test_build_system_prompt_base_only(self):
        out = prompts.build_system_prompt()
        self.assertNotIn("This engagement", out)

    def test_severities_scale(self):
        self.assertEqual(prompts.SEVERITIES,
                         ("info", "low", "medium", "high", "critical"))

    def test_triage_and_report_prompts_exist(self):
        self.assertIn("severity", prompts.TRIAGE_PROMPT.lower())
        self.assertIn("json", prompts.TRIAGE_PROMPT.lower())
        self.assertIn("markdown", prompts.REPORT_PROMPT.lower())

    def test_build_triage_prompt_is_compact_string(self):
        candidates = [{"title": "open redirect", "target": "a.example.com"}]
        msg = prompts.build_triage_prompt(candidates, target="example.com")
        self.assertIsInstance(msg, str)
        self.assertIn("example.com", msg)
        self.assertIn("open redirect", msg)

    def test_build_report_prompt_includes_recon(self):
        msg = prompts.build_report_prompt(
            findings=[{"title": "x", "severity": "high"}],
            recon_summary={"hosts": 3}, target="example.com")
        self.assertIn("RECON SUMMARY", msg)
        self.assertIn("high", msg)


if __name__ == "__main__":
    unittest.main()
