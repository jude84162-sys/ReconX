"""Scope Guard tests — the safety-critical core, so it gets its own full suite."""
import unittest

from scorpion.scope import Scope, ScopeError, extract_host
from scorpion.tools.base import Tool, ToolResult
from scorpion.ratelimit import RateLimiter, NullRateLimiter


class ExtractHostTests(unittest.TestCase):
    def test_variants(self):
        self.assertEqual(extract_host("https://App.Example.com/path?x=1"), "app.example.com")
        self.assertEqual(extract_host("example.com:8443"), "example.com")
        self.assertEqual(extract_host("user:pw@host.example.com"), "host.example.com")
        self.assertEqual(extract_host("http://[::1]:9000/"), "::1")
        self.assertEqual(extract_host("203.0.113.5"), "203.0.113.5")
        self.assertEqual(extract_host(""), "")


class ScopeTests(unittest.TestCase):
    def test_empty_scope_blocks_everything(self):
        s = Scope()
        self.assertTrue(s.is_empty)
        self.assertFalse(s.is_in_scope("example.com"))
        with self.assertRaises(ScopeError):
            s.check("example.com")

    def test_apex_entry_covers_subdomains(self):
        s = Scope(allow=["example.com"])
        self.assertTrue(s.is_in_scope("example.com"))
        self.assertTrue(s.is_in_scope("api.example.com"))
        self.assertTrue(s.is_in_scope("https://deep.api.example.com/x"))
        self.assertFalse(s.is_in_scope("evil.com"))
        self.assertFalse(s.is_in_scope("notexample.com"))
        self.assertFalse(s.is_in_scope("example.com.evil.com"))

    def test_wildcard_is_subdomains_only(self):
        s = Scope(allow=["*.example.com"])
        self.assertFalse(s.is_in_scope("example.com"))
        self.assertTrue(s.is_in_scope("a.example.com"))
        s2 = Scope(allow=[".example.com"])
        self.assertFalse(s2.is_in_scope("example.com"))
        self.assertTrue(s2.is_in_scope("a.example.com"))

    def test_deny_overrides_allow(self):
        s = Scope(allow=["example.com"], deny=["secret.example.com"])
        self.assertTrue(s.is_in_scope("api.example.com"))
        self.assertFalse(s.is_in_scope("secret.example.com"))
        self.assertFalse(s.is_in_scope("sub.secret.example.com"))

    def test_single_ip(self):
        s = Scope(allow=["203.0.113.10"])
        self.assertTrue(s.is_in_scope("203.0.113.10"))
        self.assertTrue(s.is_in_scope("http://203.0.113.10:8080/"))
        self.assertFalse(s.is_in_scope("203.0.113.11"))

    def test_cidr(self):
        s = Scope(allow=["10.0.0.0/8"])
        self.assertTrue(s.is_in_scope("10.1.2.3"))
        self.assertFalse(s.is_in_scope("11.0.0.1"))
        # a domain is never matched by a CIDR entry
        self.assertFalse(s.is_in_scope("example.com"))

    def test_domain_not_matched_by_ip_entry_and_vice_versa(self):
        s = Scope(allow=["example.com"])
        self.assertFalse(s.is_in_scope("203.0.113.10"))

    def test_from_config(self):
        class Cfg:
            scope_allow = ["example.com"]
            scope_deny = ["admin.example.com"]
        s = Scope.from_config(Cfg())
        self.assertTrue(s.is_in_scope("x.example.com"))
        self.assertFalse(s.is_in_scope("admin.example.com"))


class _DummyTool(Tool):
    name = "dummy"
    description = "test"
    input_schema = {"type": "object", "properties": {"target": {"type": "string"}}}
    scope_field = "target"

    def _execute(self, target=""):
        return ToolResult(ok=True, tool=self.name, target=target,
                          summary="ran", data={"hit": True})


class ToolScopeIntegrationTests(unittest.TestCase):
    def test_out_of_scope_tool_is_blocked_before_execute(self):
        tool = _DummyTool(Scope(allow=["example.com"]), NullRateLimiter())
        res = tool.run(target="evil.com")
        self.assertFalse(res.ok)
        self.assertTrue(res.blocked)
        self.assertEqual(res.data, {})          # _execute never ran

    def test_in_scope_tool_runs(self):
        tool = _DummyTool(Scope(allow=["example.com"]), NullRateLimiter())
        res = tool.run(target="api.example.com")
        self.assertTrue(res.ok)
        self.assertEqual(res.data, {"hit": True})
        self.assertGreaterEqual(res.duration, 0.0)

    def test_exceptions_become_error_results(self):
        class Boom(_DummyTool):
            name = "boom"
            def _execute(self, target=""):
                raise RuntimeError("kaboom")
        tool = Boom(Scope(allow=["example.com"]), NullRateLimiter())
        res = tool.run(target="api.example.com")
        self.assertFalse(res.ok)
        self.assertFalse(res.blocked)
        self.assertIn("kaboom", res.error)


class RateLimiterTests(unittest.TestCase):
    def test_limits_rate_per_host(self):
        import time
        rl = RateLimiter(per_host_rate=20.0)
        start = time.monotonic()
        for _ in range(6):
            rl.acquire("host.example.com")
        # 6 tokens at 20/s with capacity ~20 should be near-instant (burst)
        self.assertLess(time.monotonic() - start, 1.0)


if __name__ == "__main__":
    unittest.main()
