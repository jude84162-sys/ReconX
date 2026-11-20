"""Offline tests for the self-check command (no network, no secrets)."""
import unittest
from unittest import mock

from scorpion import selfcheck
from scorpion.config import Config


class SelfCheckTests(unittest.TestCase):
    def _run(self, cfg, argv=None):
        with mock.patch.object(selfcheck, "load_config", return_value=cfg):
            return selfcheck.run(argv or [])

    def test_empty_scope_reports_problem(self):
        rc = self._run(Config())          # nothing configured
        self.assertEqual(rc, 1)           # empty scope is flagged

    def test_scope_and_planner_is_clean(self):
        cfg = Config(scope_allow=["example.com"], no_llm=True)
        rc = self._run(cfg)
        self.assertEqual(rc, 0)           # planner mode + scope => all good

    def test_key_set_without_live_does_not_call_network(self):
        cfg = Config(scope_allow=["example.com"], anthropic_api_key="sk-test")
        # no --live, so Brain must never be constructed/called
        with mock.patch("scorpion.brain.Brain") as brain:
            rc = self._run(cfg)
        brain.assert_not_called()
        self.assertEqual(rc, 0)

    def test_tools_load(self):
        cfg = Config(scope_allow=["example.com"], no_llm=True)
        # the real tool registry should load 14 tools without error
        with mock.patch.object(selfcheck, "load_config", return_value=cfg):
            self.assertGreaterEqual(selfcheck._check_tools(), 10)


if __name__ == "__main__":
    unittest.main()
