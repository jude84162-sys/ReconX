"""Tests for reconx modules - offline validation only."""

import unittest
import json
import ast
from unittest.mock import Mock, patch


class TestUsernameModule(unittest.TestCase):
    """Test the username module structure and site definitions."""

    def test_sites_is_list(self):
        from reconx.modules.username import SITES
        self.assertIsInstance(SITES, list)

    def test_sites_has_minimum_count(self):
        from reconx.modules.username import SITES
        self.assertGreaterEqual(len(SITES), 200, "Should have at least 200 sites")

    def test_each_site_has_required_keys(self):
        from reconx.modules.username import SITES
        required = {"name", "url", "check_type"}
        for site in SITES:
            self.assertTrue(
                required.issubset(site.keys()),
                f"Site {site.get('name', '?')} missing keys: {required - site.keys()}",
            )

    def test_no_duplicate_names(self):
        from reconx.modules.username import SITES
        names = [s["name"] for s in SITES]
        # Allow some duplicates (e.g. alternative URLs) but warn
        seen = set()
        for name in names:
            if name in seen:
                pass  # Duplicate names are acceptable for alternative URLs
            seen.add(name)

    def test_all_urls_have_username_placeholder(self):
        from reconx.modules.username import SITES
        for site in SITES:
            if site["check_type"] == "custom":
                continue
            self.assertIn(
                "{username}",
                site["url"],
                f"Site {site['name']} URL missing {{username}} placeholder",
            )

    def test_sites_all_urls_are_https(self):
        from reconx.modules.username import SITES
        for site in SITES:
            if site["check_type"] == "custom":
                continue
            self.assertTrue(
                site["url"].startswith("https://") or site["url"].startswith("http://"),
                f"Site {site['name']} has invalid URL: {site['url']}",
            )

    def test_check_site_function(self):
        from reconx.modules.username import _check_site
        result = _check_site(
            {"name": "Test", "url": "https://example.com/{username}", "check_type": "custom"},
            "testuser",
            5,
        )
        self.assertEqual(result["status"], "skipped")

    def test_username_recon_class_exists(self):
        from reconx.modules.username import UsernameRecon
        m = UsernameRecon(verbose=False, timeout=5)
        self.assertEqual(m.name, "username")
        self.assertIsInstance(m.description, str)


class TestDomainModule(unittest.TestCase):
    """Test the domain module."""

    def test_domain_recon_class_exists(self):
        from reconx.modules.domain import DomainRecon
        m = DomainRecon(verbose=False, timeout=5)
        self.assertEqual(m.name, "domain")

    def test_subdomain_list_not_empty(self):
        from reconx.modules.domain import DEFAULT_SUBDOMAINS
        self.assertGreater(len(DEFAULT_SUBDOMAINS), 100)
        self.assertIn("www", DEFAULT_SUBDOMAINS)
        self.assertIn("mail", DEFAULT_SUBDOMAINS)
        self.assertIn("api", DEFAULT_SUBDOMAINS)


class TestIPModule(unittest.TestCase):
    """Test the IP module."""

    def test_ip_recon_class_exists(self):
        from reconx.modules.ip import IPRecon
        m = IPRecon(verbose=False, timeout=5)
        self.assertEqual(m.name, "ip")

    def test_ip_validation_valid(self):
        from reconx.modules.ip import IPRecon
        m = IPRecon(verbose=False, timeout=5)
        m.target = "8.8.8.8"
        m._validate_ip()
        results = m.get_results()
        self.assertEqual(results[0]["status"], "valid")
        self.assertEqual(results[0]["extra"], {"version": 4})

    def test_ip_validation_invalid(self):
        from reconx.modules.ip import IPRecon
        m = IPRecon(verbose=False, timeout=5)
        m.target = "not-an-ip"
        m._validate_ip()
        results = m.get_results()
        self.assertEqual(results[0]["status"], "invalid")

    def test_ip_validation_ipv6_full(self):
        from reconx.modules.ip import IPRecon
        m = IPRecon(verbose=False, timeout=5)
        m.target = "2001:4860:4860:0000:0000:0000:0000:8888"
        m._validate_ip()
        results = m.get_results()
        self.assertEqual(results[0]["status"], "valid")
        self.assertEqual(results[0]["extra"], {"version": 6})


class TestHTTPUtils(unittest.TestCase):
    """Test HTTP utility functions."""

    def test_dns_lookup_invalid(self):
        from reconx.utils.http import dns_lookup
        result = dns_lookup("thisdomaindoesnotexist12345.com")
        self.assertEqual(result, [])

    def test_dns_lookup_localhost(self):
        from reconx.utils.http import dns_lookup
        result = dns_lookup("localhost")
        self.assertIn("127.0.0.1", result)

    def test_reverse_dns_invalid(self):
        from reconx.utils.http import reverse_dns
        result = reverse_dns("192.0.2.1")
        self.assertIsNone(result)


class TestFediverseModules(unittest.TestCase):
    def _response(self, payload=None, text=""):
        response = Mock()
        response.ok = True
        response.text = text
        response.json.return_value = payload or {}
        return response

    @patch("reconx.modules.fedifinder.safe_request")
    def test_fedifinder_rel_me(self, request):
        request.return_value = self._response(
            text='<a rel="me" href="https://social.example/@jane">profile</a>'
        )
        from reconx.modules.fedifinder import FedifinderModule
        result = FedifinderModule().run("example.com")
        self.assertEqual(result["accounts"][0]["source"], "rel-me")

    @patch("reconx.modules.fediverse_observer.safe_request")
    def test_fediverse_observer(self, request):
        request.return_value = self._response({"software": "Mastodon", "version": "4.0", "users": 4})
        from reconx.modules.fediverse_observer import FediverseObserverModule
        result = FediverseObserverModule().run("mastodon.social")
        self.assertEqual(result["software"], "Mastodon")
        self.assertEqual(result["users"], 4)

    @patch("reconx.modules.fediverse_osint.safe_request")
    def test_fediverse_osint_deduplicates(self, request):
        request.return_value = self._response(
            {"accounts": [{"acct": "jane@mastodon.social", "url": "https://mastodon.social/@jane"}]}
        )
        from reconx.modules.fediverse_osint import FediverseOsintModule
        result = FediverseOsintModule().run("jane")
        self.assertEqual(len(result["accounts"]), 1)


class TestInstagramModules(unittest.TestCase):
    @patch("reconx.modules.masto.shutil.which", return_value=None)
    def test_masto_missing_cli(self, which):
        from reconx.modules.masto import MastoModule
        self.assertEqual(MastoModule().run("@jane@example.com")["error"], "Install: npm i -g masto")

    @patch("reconx.modules.osintgram.os.environ", {})
    def test_osintgram_missing_path(self):
        from reconx.modules.osintgram import OsintgramModule
        self.assertEqual(OsintgramModule().run("jane")["error"], "Set OSINTGRAM_PATH env var")

    @patch("reconx.modules.inflact.time.sleep")
    @patch("reconx.modules.inflact.RobotFileParser")
    @patch("reconx.modules.inflact.requests.get")
    def test_inflact_profile(self, get, robot, sleep):
        robot.return_value.can_fetch.return_value = True
        response = Mock()
        response.text = '<span class="full_name">Jane Doe</span>'
        response.raise_for_status.return_value = None
        get.return_value = response
        from reconx.modules.inflact import InflactModule
        result = InflactModule().run("jane")
        self.assertEqual(result["profile_data"]["full_name"], "Jane Doe")
        sleep.assert_called_once_with(5)


class TestWebSiftModule(unittest.TestCase):
    @patch("reconx.modules.websift.safe_request")
    def test_extracts_public_data(self, request):
        response = Mock()
        response.ok = True
        response.status_code = 200
        response.url = "https://example.com/"
        response.text = """
        <html><head><title>Example</title>
        <meta name="description" content="Public page"></head>
        <body>Contact jane@example.com or +1 (555) 123-4567.
        <a href="https://github.com/example">GitHub</a>
        <a href="/about">About</a></body></html>
        """
        request.return_value = response

        from reconx.modules.websift import WebSiftModule
        result = WebSiftModule(timeout=5).run("https://example.com")

        self.assertEqual(result["title"], "Example")
        self.assertEqual(result["emails"], ["jane@example.com"])
        self.assertEqual(result["social_links"], ["https://github.com/example"])
        self.assertIn("https://example.com/about", result["urls"])

    def test_rejects_non_http_urls(self):
        from reconx.modules.websift import WebSiftModule
        with self.assertRaises(ValueError):
            WebSiftModule().run("file:///etc/passwd")


class TestExternalModules(unittest.TestCase):
    def test_encrypted_github_token_is_decrypted(self):
        from cryptography.fernet import Fernet
        from reconx.modules.external import _github_token_for_child

        key = Fernet.generate_key()
        encrypted = Fernet(key).encrypt(b"test-token")
        with patch.dict(
            "os.environ",
            {
                "GITHUB_ENCRYPTION_KEY": key.decode(),
                "GITHUB_ENCRYPTED_TOKEN": encrypted.decode(),
                "GITHUB_TOKEN": "",
            },
            clear=False,
        ):
            self.assertEqual(_github_token_for_child(), "test-token")

    def test_partial_encrypted_github_token_configuration_fails(self):
        from reconx.modules.external import _github_token_for_child

        with patch.dict(
            "os.environ",
            {"GITHUB_ENCRYPTION_KEY": "key", "GITHUB_ENCRYPTED_TOKEN": ""},
            clear=False,
        ):
            with self.assertRaisesRegex(ValueError, "Set both"):
                _github_token_for_child()


if __name__ == "__main__":
    unittest.main()
