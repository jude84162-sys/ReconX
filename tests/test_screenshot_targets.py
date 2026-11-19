"""Tests for screenshot target parsing in modules/web/aquatone_clone.py.

Covers JSON target extraction, target normalisation, job preparation and
output filename sanitising. Loopback only — no internet access.
"""

import json
import tempfile
import unittest
from pathlib import Path

from modules.web.aquatone_clone import _prepare_jobs, _safe_name, _targets_from_json
from tests.helpers import LocalServer, free_port


class TargetsFromJsonTests(unittest.TestCase):
    def write_json(self, payload):
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8"
        )
        with handle:
            json.dump(payload, handle)
        self.addCleanup(lambda: Path(handle.name).unlink(missing_ok=True))
        return handle.name

    def test_plain_list(self):
        path = self.write_json(["a.example", {"hostname": "b.example"}])
        self.assertEqual(_targets_from_json(path), ["a.example", "b.example"])

    def test_subdomain_enum_report_shape(self):
        payload = {
            "subdomains": {
                "total_unique": 2,
                "subdomains": [
                    {"hostname": "api.example", "ip": "1.2.3.4"},
                    {"hostname": "www.example", "ip": None},
                ],
            }
        }
        self.assertEqual(_targets_from_json(self.write_json(payload)),
                         ["api.example", "www.example"])

    def test_flat_list_keys(self):
        for key in ("subdomains", "results", "hosts"):
            with self.subTest(key=key):
                path = self.write_json({key: ["a.example", "a.example", "b.example"]})
                self.assertEqual(_targets_from_json(path), ["a.example", "b.example"])

    def test_probe_report_keeps_live_urls_and_drops_entryless_rows(self):
        payload = {
            "total": 3,
            "alive": 1,
            "results": [
                {"input": "a.example", "url": "https://a.example/login", "alive": True},
                {"input": "dead.example", "url": None, "alive": False},
                {"input": "b.example", "alive": False},
            ],
        }
        # dead rows carry no url/hostname/host, so they are not capture targets
        self.assertEqual(_targets_from_json(self.write_json(payload)),
                         ["https://a.example/login"])

    def test_recon_report_shape(self):
        payload = {
            "target": "example.com",
            "steps": {
                "subdomains": {
                    "subdomains": [{"hostname": "dev.example"}, {"hostname": "staging.example"}],
                }
            },
        }
        self.assertEqual(_targets_from_json(self.write_json(payload)),
                         ["dev.example", "staging.example"])

    def test_unknown_shape_raises(self):
        path = self.write_json({"target": "example.com"})
        with self.assertRaises(ValueError):
            _targets_from_json(path)


class PrepareJobsTests(unittest.TestCase):
    def test_explicit_url_is_used_without_probing(self):
        with LocalServer() as server:
            url = server.url("/page")
            jobs, skipped = _prepare_jobs([url], timeout=3, verbose=False)

            self.assertEqual(skipped, [])
            self.assertEqual(len(jobs), 1)
            self.assertEqual(jobs[0]["url"], url)
            self.assertEqual(jobs[0]["input"], url)
            self.assertEqual(jobs[0]["host"], f"127.0.0.1:{server.port}")
            self.assertIsNone(jobs[0]["title"])

    def test_bare_host_is_probed_and_resolved(self):
        with LocalServer() as server:
            target = f"127.0.0.1:{server.port}"
            jobs, skipped = _prepare_jobs([target], timeout=3, verbose=False)

            self.assertEqual(skipped, [])
            self.assertEqual(len(jobs), 1)
            self.assertEqual(jobs[0]["url"], f"http://127.0.0.1:{server.port}")
            self.assertEqual(jobs[0]["host"], target)
            self.assertEqual(jobs[0]["title"], "Test & Probe")

    def test_dead_target_is_skipped_with_a_reason(self):
        target = f"127.0.0.1:{free_port()}"
        jobs, skipped = _prepare_jobs([target], timeout=2, verbose=False)

        self.assertEqual(jobs, [])
        self.assertEqual(len(skipped), 1)
        self.assertEqual(skipped[0]["status"], "skipped")
        self.assertEqual(skipped[0]["input"], target)
        self.assertIsNone(skipped[0]["url"])
        self.assertIsNone(skipped[0]["screenshot"])
        self.assertTrue(skipped[0]["error"])

    def test_duplicate_targets_collapse(self):
        with LocalServer() as server:
            jobs, _ = _prepare_jobs(
                [server.url("/"), server.url("/")], timeout=3, verbose=False
            )
        self.assertEqual(len(jobs), 1)


class SafeNameTests(unittest.TestCase):
    def test_unsafe_characters_are_replaced(self):
        self.assertEqual(_safe_name("https://a.example:8080/x?y=1"),
                         "https_a.example_8080_x_y_1")

    def test_fallback_and_truncation(self):
        self.assertEqual(_safe_name(""), "host")
        self.assertEqual(_safe_name(None), "host")
        self.assertEqual(_safe_name("..."), "host")
        self.assertEqual(len(_safe_name("a" * 200)), 80)


if __name__ == "__main__":
    unittest.main()
