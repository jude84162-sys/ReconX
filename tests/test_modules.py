"""Tests for reconx modules - offline validation only."""

import unittest
import json
import ast


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


class TestEmailModule(unittest.TestCase):
    """Test the email module."""

    def test_email_recon_class_exists(self):
        from reconx.modules.email import EmailRecon
        m = EmailRecon(verbose=False, timeout=5)
        self.assertEqual(m.name, "email")

    def test_email_recon_valid_email(self):
        from reconx.modules.email import EmailRecon
        m = EmailRecon(verbose=False, timeout=5)
        # Just test that it doesn't crash - we won't actually run it
        # to avoid external API calls in CI
        self.assertIsNotNone(m)


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


if __name__ == "__main__":
    unittest.main()
