"""Tests for modules/web/live_probe.py (loopback only, no internet access)."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from modules.web import live_probe
from tests.helpers import LocalServer, free_port


class NormalizeHostTests(unittest.TestCase):
    def test_accepts_urls_dicts_and_hosts(self):
        cases = [
            ("https://a.example/x?y=1", "https://a.example/x?y=1"),
            ("http://b.example/path/", "http://b.example/path/"),
            ("c.example/path", "c.example"),
            ("c.example:8443/path", "c.example:8443"),
            ("  spaced.example  ", "spaced.example"),
            ({"hostname": "d.example"}, "d.example"),
            ({"url": "https://e.example/p"}, "https://e.example/p"),
            ({"host": "f.example"}, "f.example"),
            ({"hostname": "", "host": "g.example"}, "g.example"),
            (None, ""),
            ("", ""),
        ]
        for raw, expected in cases:
            with self.subTest(raw=raw):
                self.assertEqual(live_probe.normalize_host(raw), expected)


class CandidateUrlTests(unittest.TestCase):
    def test_bare_host_tries_https_then_http(self):
        self.assertEqual(
            live_probe._candidate_urls("example.com"),
            ["https://example.com", "http://example.com"],
        )
        self.assertEqual(
            live_probe._candidate_urls("example.com/"),
            ["https://example.com", "http://example.com"],
        )

    def test_explicit_scheme_is_kept(self):
        self.assertEqual(
            live_probe._candidate_urls("http://example.com:8080/app"),
            ["http://example.com:8080/app"],
        )
        self.assertEqual(
            live_probe._candidate_urls("https://example.com"),
            ["https://example.com"],
        )

    def test_empty_targets_have_no_candidates(self):
        self.assertEqual(live_probe._candidate_urls(""), [])
        self.assertEqual(live_probe._candidate_urls(None), [])
        self.assertEqual(live_probe._candidate_urls("   "), [])


class DedupeTests(unittest.TestCase):
    def test_dedupes_case_insensitively_and_keeps_order(self):
        self.assertEqual(
            live_probe._dedupe(["a.example", "A.EXAMPLE", "b.example",
                                "", "a.example/path", None]),
            ["a.example", "b.example"],
        )

    def test_empty_input(self):
        self.assertEqual(live_probe._dedupe([]), [])
        self.assertEqual(live_probe._dedupe(None), [])


class ExtractTitleTests(unittest.TestCase):
    def test_collapses_whitespace_and_unescapes_entities(self):
        body = b"<html><head><title>  Test\n &amp;  Probe </title></head></html>"
        self.assertEqual(live_probe.extract_title(body), "Test & Probe")

    def test_missing_or_empty_title(self):
        self.assertIsNone(live_probe.extract_title(b"<html><body>no title</body></html>"))
        self.assertIsNone(live_probe.extract_title(b""))
        self.assertIsNone(live_probe.extract_title(None))

    def test_title_can_be_an_empty_string(self):
        self.assertIsNone(live_probe.extract_title(b"<title>   </title>"))

    def test_long_titles_are_truncated(self):
        title = live_probe.extract_title(b"<title>" + b"a" * 300 + b"</title>")
        self.assertEqual(len(title), 120)


class ProbeHostTests(unittest.TestCase):
    def test_live_host_is_probed_over_http(self):
        with LocalServer() as server:
            result = live_probe.probe_host(f"127.0.0.1:{server.port}", timeout=5)

            self.assertTrue(result["alive"])
            self.assertEqual(result["status"], 200)
            self.assertEqual(result["title"], "Test & Probe")
            self.assertEqual(result["content_type"], "text/html")
            self.assertIsNone(result["tls"])
            self.assertEqual(result["host"], f"127.0.0.1:{server.port}")
            self.assertEqual(result["url"], f"http://127.0.0.1:{server.port}")
            self.assertEqual(result["final_url"], f"http://127.0.0.1:{server.port}")
            self.assertEqual(result["redirects"], [])
            self.assertIsInstance(result["elapsed_ms"], int)

    def test_redirect_chain_is_followed(self):
        with LocalServer() as server:
            result = live_probe.probe_host(server.url("/redir"), timeout=5)

            self.assertTrue(result["alive"])
            self.assertEqual(result["status"], 200)
            self.assertEqual(result["final_url"], server.url("/page"))
            self.assertEqual(len(result["redirects"]), 1)
            self.assertEqual(result["redirects"][0]["status"], 302)
            self.assertEqual(result["redirects"][0]["location"], "/page")

    def test_redirect_can_be_disabled(self):
        with LocalServer() as server:
            result = live_probe.probe_host(
                server.url("/redir"), timeout=5, follow_redirects=False
            )

            self.assertTrue(result["alive"])
            self.assertEqual(result["status"], 302)
            self.assertEqual(result["final_url"], server.url("/redir"))
            self.assertEqual(result["redirects"], [])

    def test_closed_port_is_not_alive(self):
        result = live_probe.probe_host(f"http://127.0.0.1:{free_port()}", timeout=2)

        self.assertFalse(result["alive"])
        self.assertIsNone(result["url"])
        self.assertTrue(result["errors"])

    def test_empty_target_has_no_candidates(self):
        result = live_probe.probe_host("")

        self.assertFalse(result["alive"])
        self.assertEqual(result["errors"], ["empty target"])


class ProbeHostsTests(unittest.TestCase):
    def test_counts_dedupes_and_sorts_alive_first(self):
        with LocalServer() as server:
            target = server.url("/")
            dead = f"http://127.0.0.1:{free_port()}"
            result = live_probe.probe_hosts(
                [target, target, dead], threads=4, timeout=3
            )

        self.assertEqual(result["total"], 2)
        self.assertEqual(result["alive"], 1)
        self.assertEqual(result["dead"], 1)
        self.assertEqual([r["alive"] for r in result["results"]], [True, False])
        self.assertEqual(len(live_probe.live_hosts(result)), 1)
        self.assertEqual(live_probe.live_hosts(result)[0]["url"],
                         f"http://127.0.0.1:{server.port}")

    def test_empty_input(self):
        result = live_probe.probe_hosts([], threads=2)

        self.assertEqual(result["total"], 0)
        self.assertEqual(result["alive"], 0)
        self.assertEqual(result["dead"], 0)
        self.assertEqual(result["results"], [])

    def test_live_hosts_ignores_missing_results(self):
        self.assertEqual(live_probe.live_hosts({}), [])


class ReportTests(unittest.TestCase):
    def test_print_report_shows_live_and_dead_hosts(self):
        with LocalServer() as server:
            result = live_probe.probe_hosts(
                [server.url("/"), f"http://127.0.0.1:{free_port()}"],
                threads=2, timeout=3,
            )

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            live_probe.print_probe_report(result)

        output = buffer.getvalue()
        self.assertIn("Live Host Prober", output)
        self.assertIn(f"http://127.0.0.1:{server.port}", output)
        self.assertIn("Test & Probe", output)
        self.assertIn("No HTTP response", output)

    def test_save_report_writes_json(self):
        payload = {"total": 0, "alive": 0, "dead": 0, "results": []}
        with tempfile.TemporaryDirectory() as tmp:
            path = live_probe.save_probe_report(payload, outdir=tmp)

            self.assertEqual(Path(path).parent, Path(tmp))
            self.assertTrue(Path(path).name.startswith("live_hosts_"))
            self.assertEqual(json.loads(Path(path).read_text(encoding="utf-8")), payload)


if __name__ == "__main__":
    unittest.main()
