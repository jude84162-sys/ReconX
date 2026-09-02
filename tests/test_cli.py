"""Tests for CLI argument parsing."""

import unittest
import json
import os
from unittest.mock import patch
from reconx.cli import create_parser


class TestCLI(unittest.TestCase):
    def test_no_args_returns_none(self):
        parser = create_parser()
        args = parser.parse_args([])
        # argparse with no required args won't error - it just returns None targets
        self.assertIsNone(args.username)
        self.assertIsNone(args.email)
        self.assertIsNone(args.domain)
        self.assertIsNone(args.ip)

    def test_username_arg(self):
        parser = create_parser()
        args = parser.parse_args(["-u", "testuser"])
        self.assertEqual(args.username, "testuser")
        self.assertIsNone(args.email)

    def test_email_arg(self):
        parser = create_parser()
        args = parser.parse_args(["-e", "test@example.com"])
        self.assertEqual(args.email, "test@example.com")

    def test_domain_arg(self):
        parser = create_parser()
        args = parser.parse_args(["-d", "example.com"])
        self.assertEqual(args.domain, "example.com")

    def test_ip_arg(self):
        parser = create_parser()
        args = parser.parse_args(["-i", "8.8.8.8"])
        self.assertEqual(args.ip, "8.8.8.8")

    def test_timeout_arg(self):
        parser = create_parser()
        args = parser.parse_args(["-u", "test", "-t", "30"])
        self.assertEqual(args.timeout, 30)

    def test_workers_arg(self):
        parser = create_parser()
        args = parser.parse_args(["-u", "test", "-w", "50"])
        self.assertEqual(args.workers, 50)

    def test_output_json(self):
        parser = create_parser()
        args = parser.parse_args(["-u", "test", "-o", "json"])
        self.assertEqual(args.output, "json")

    def test_output_csv(self):
        parser = create_parser()
        args = parser.parse_args(["-u", "test", "-o", "csv"])
        self.assertEqual(args.output, "csv")

    def test_output_txt(self):
        parser = create_parser()
        args = parser.parse_args(["-u", "test", "-o", "txt"])
        self.assertEqual(args.output, "txt")

    def test_no_banner_flag(self):
        parser = create_parser()
        args = parser.parse_args(["-u", "test", "--no-banner"])
        self.assertTrue(args.no_banner)

    def test_verbose_flag(self):
        parser = create_parser()
        args = parser.parse_args(["-u", "test", "--verbose"])
        self.assertTrue(args.verbose)

    def test_list_flag(self):
        parser = create_parser()
        args = parser.parse_args(["--list"])
        self.assertTrue(args.list)

    def test_file_arg(self):
        parser = create_parser()
        args = parser.parse_args(["-u", "test", "-o", "json", "-f", "my_results.json"])
        self.assertEqual(args.file, "my_results.json")

    def test_combined_args(self):
        parser = create_parser()
        args = parser.parse_args([
            "-u", "johndoe", "-t", "15", "-w", "40",
            "-o", "csv", "-f", "out.csv", "--verbose", "--no-banner"
        ])
        self.assertEqual(args.username, "johndoe")
        self.assertEqual(args.timeout, 15)
        self.assertEqual(args.workers, 40)
        self.assertEqual(args.output, "csv")
        self.assertTrue(args.verbose)
        self.assertTrue(args.no_banner)


class TestExportResults(unittest.TestCase):
    def test_export_json(self):
        from reconx.cli import export_results
        results = [
            {"platform": "GitHub", "url": "https://github.com/test", "status": "found"},
            {"platform": "Twitter", "url": "https://twitter.com/test", "status": "not_found"},
        ]
        fname = "/tmp/test_reconx_export.json"
        if os.path.exists(fname):
            os.remove(fname)
        export_results(results, "json", fname)
        self.assertTrue(os.path.exists(fname))
        with open(fname) as f:
            data = json.load(f)
        self.assertEqual(len(data), 2)
        os.remove(fname)

    def test_export_csv(self):
        from reconx.cli import export_results
        results = [
            {"platform": "GitHub", "url": "https://github.com/test", "status": "found", "extra": {}},
        ]
        fname = "/tmp/test_reconx_export.csv"
        if os.path.exists(fname):
            os.remove(fname)
        export_results(results, "csv", fname)
        self.assertTrue(os.path.exists(fname))
        with open(fname) as f:
            lines = f.readlines()
        self.assertEqual(len(lines), 2)  # header + 1 row
        os.remove(fname)

    def test_export_txt(self):
        from reconx.cli import export_results
        results = [
            {"platform": "GitHub", "url": "https://github.com/test", "status": "found"},
        ]
        fname = "/tmp/test_reconx_export.txt"
        if os.path.exists(fname):
            os.remove(fname)
        export_results(results, "txt", fname)
        self.assertTrue(os.path.exists(fname))
        os.remove(fname)


if __name__ == "__main__":
    unittest.main()
