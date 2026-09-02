"""Tests for the core Engine and Module classes."""

import unittest
from reconx.core.engine import Engine, Module


class MockModule(Module):
    """Test module for Engine tests."""
    name = "mock"
    description = "Mock module for testing"

    def run(self, target):
        self.add_result("test", f"https://example.com/{target}", "found")
        return self.results


class FailingModule(Module):
    """Module that always fails."""
    name = "failing"
    description = "Failing module for testing"

    def run(self, target):
        raise RuntimeError("Intentional failure")


class TestModule(unittest.TestCase):
    def test_add_result(self):
        m = Module(verbose=False, timeout=5)
        entry = m.add_result("Platform", "https://example.com", "found", {"key": "val"})
        self.assertEqual(entry["platform"], "Platform")
        self.assertEqual(entry["url"], "https://example.com")
        self.assertEqual(entry["status"], "found")
        self.assertEqual(entry["extra"], {"key": "val"})

    def test_get_results_empty(self):
        m = Module()
        self.assertEqual(m.get_results(), [])

    def test_get_results(self):
        m = Module()
        m.add_result("A", "https://a.com", "found")
        m.add_result("B", "https://b.com", "not_found")
        results = m.get_results()
        self.assertEqual(len(results), 2)

    def test_run_not_implemented(self):
        m = Module()
        with self.assertRaises(NotImplementedError):
            m.run("target")


class TestEngine(unittest.TestCase):
    def test_register_module(self):
        engine = Engine()
        engine.register(MockModule)
        modules = engine.list_modules()
        self.assertEqual(len(modules), 1)
        self.assertEqual(modules[0]["name"], "mock")

    def test_run_module(self):
        engine = Engine()
        engine.register(MockModule)
        results = engine.run_module("mock", "testuser")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["platform"], "test")

    def test_run_module_not_found(self):
        engine = Engine()
        with self.assertRaises(ValueError):
            engine.run_module("nonexistent", "test")

    def test_run_all(self):
        engine = Engine()
        engine.register(MockModule)
        engine.register(FailingModule)
        results = engine.run_all("test")
        self.assertIn("mock", results)
        self.assertIn("failing", results)
        self.assertEqual(len(results["mock"]), 1)
        self.assertIn("error", results["failing"])

    def test_list_modules_empty(self):
        engine = Engine()
        self.assertEqual(engine.list_modules(), [])


if __name__ == "__main__":
    unittest.main()
