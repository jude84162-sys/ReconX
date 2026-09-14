"""Tests for CLI argument parsing."""

import unittest
import json
import os
import tempfile
from unittest.mock import patch
from reconx.cli import create_parser, create_subcommand_parser, main
from reconx.modules.ip import _resolve_abuseipdb_api_key


class TestCLI(unittest.TestCase):
    def _assert_main_runs_module(self, argv, module_path, target, workers=False):
        with patch("reconx.cli.print_banner"), patch(module_path) as module_class:
            module_class.return_value.get_results.return_value = []
            main(argv + ["--no-banner"])

        module_class.assert_called_once_with(verbose=False, timeout=10)
        if workers:
            module_class.return_value.run.assert_called_once_with(target, workers=20)
        else:
            module_class.return_value.run.assert_called_once_with(target)

    def test_no_args_returns_none(self):
        parser = create_parser()
        args = parser.parse_args([])
        # argparse with no required args won't error - it just returns None targets
        self.assertIsNone(args.username)
        self.assertIsNone(args.domain)
        self.assertIsNone(args.ip)

    def test_username_arg(self):
        parser = create_parser()
        args = parser.parse_args(["-u", "testuser"])
        self.assertEqual(args.username, "testuser")

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

    def test_quiet_flag(self):
        parser = create_parser()
        args = parser.parse_args(["-u", "test", "--quiet"])
        self.assertTrue(args.quiet)
        self.assertFalse(args.no_banner)

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

    def test_username_subcommand(self):
        parser = create_subcommand_parser()
        args = parser.parse_args(["username", "testuser", "-t", "15", "-w", "30", "-o", "json"])
        self.assertEqual(args.command, "username")
        self.assertEqual(args.target, "testuser")
        self.assertEqual(args.timeout, 15)
        self.assertEqual(args.workers, 30)
        self.assertEqual(args.output, "json")

    def test_domain_subcommand(self):
        parser = create_subcommand_parser()
        args = parser.parse_args(["domain", "example.com"])
        self.assertEqual(args.command, "domain")
        self.assertEqual(args.target, "example.com")

    def test_ip_subcommand(self):
        parser = create_subcommand_parser()
        args = parser.parse_args(["ip", "8.8.8.8"])
        self.assertEqual(args.command, "ip")
        self.assertEqual(args.target, "8.8.8.8")

    def test_fediverse_subcommands(self):
        parser = create_subcommand_parser()
        for command, target in (
            ("fedifinder", "example.com"),
            ("fediverse-observer", "mastodon.social"),
            ("fediverse-osint", "johndoe"),
        ):
            args = parser.parse_args([command, target])
            self.assertEqual(args.command, command)
            self.assertEqual(args.target, target)

    def test_fediverse_legacy_flags(self):
        parser = create_parser()
        self.assertEqual(parser.parse_args(["--fedifinder", "example.com"]).fedifinder, "example.com")
        self.assertEqual(
            parser.parse_args(["--fediverse-observer", "mastodon.social"]).fediverse_observer,
            "mastodon.social",
        )
        self.assertEqual(parser.parse_args(["--fediverse-osint", "johndoe"]).fediverse_osint, "johndoe")

    def test_instagram_subcommands(self):
        parser = create_subcommand_parser()
        for command in ("masto", "inflact", "osintgram"):
            self.assertEqual(parser.parse_args([command, "johndoe"]).command, command)

    def test_instagram_legacy_flags(self):
        parser = create_parser()
        self.assertEqual(parser.parse_args(["--masto", "@jane@example.com"]).masto, "@jane@example.com")
        self.assertEqual(parser.parse_args(["--inflact", "jane"]).inflact, "jane")
        self.assertEqual(parser.parse_args(["--osintgram", "jane"]).osintgram, "jane")

    @patch("reconx.cli.list_modules")
    def test_list_subcommand(self, list_modules):
        main(["list", "--no-banner"])
        list_modules.assert_called_once_with()

    @patch("reconx.cli.list_modules")
    def test_list_subcommand_via_flag(self, list_modules):
        main(["--list", "--no-banner"])
        list_modules.assert_called_once_with()

    def test_legacy_username_still_works(self):
        self._assert_main_runs_module(
            ["-u", "testuser"], "reconx.modules.username.UsernameRecon", "testuser", workers=True
        )

    def test_legacy_domain_still_works(self):
        self._assert_main_runs_module(
            ["-d", "example.com"], "reconx.modules.domain.DomainRecon", "example.com"
        )

    def test_legacy_ip_still_works(self):
        self._assert_main_runs_module(
            ["-i", "8.8.8.8"], "reconx.modules.ip.IPRecon", "8.8.8.8"
        )

    def test_username_subcommand_runs_module(self):
        self._assert_main_runs_module(
            ["username", "testuser"], "reconx.modules.username.UsernameRecon", "testuser", workers=True
        )

    def test_domain_subcommand_runs_module(self):
        self._assert_main_runs_module(
            ["domain", "example.com"], "reconx.modules.domain.DomainRecon", "example.com"
        )

    def test_ip_subcommand_runs_module(self):
        self._assert_main_runs_module(
            ["ip", "8.8.8.8"], "reconx.modules.ip.IPRecon", "8.8.8.8"
        )


class TestIPConfig(unittest.TestCase):
    def test_env_var_has_priority(self):
        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "env-key"}, clear=False):
            self.assertEqual(_resolve_abuseipdb_api_key(), "env-key")

    def test_json_config_file_is_read(self):
        old_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, "config.json")
            with open(config_path, "w", encoding="utf-8") as handle:
                json.dump({"abuseipdb_api_key": "file-key"}, handle)
            try:
                os.chdir(tmpdir)
                self.assertEqual(_resolve_abuseipdb_api_key(), "file-key")
            finally:
                os.chdir(old_cwd)


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
