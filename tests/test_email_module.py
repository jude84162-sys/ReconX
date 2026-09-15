"""Security-focused tests for the email breach module (offline only)."""

import tempfile
import unittest
from pathlib import Path

from reconx.modules.email import EmailBreachModule


class TestSecretRedaction(unittest.TestCase):
    def test_telegram_bot_token_is_redacted(self):
        url = "https://api.telegram.org/bot123456:AAsecrettoken/sendMessage"
        redacted = EmailBreachModule._redact_url(url)
        self.assertNotIn("AAsecrettoken", redacted)
        self.assertIn("/bot<redacted>/", redacted)

    def test_credential_query_params_are_redacted(self):
        redacted = EmailBreachModule._redact_url(
            "https://example.com/v1/check?api_key=supersecret&ip=1.2.3.4"
        )
        self.assertNotIn("supersecret", redacted)
        self.assertIn("ip=1.2.3.4", redacted)


class TestRetryDelay(unittest.TestCase):
    def test_numeric_retry_after(self):
        self.assertEqual(EmailBreachModule._retry_delay("5", 1, 2.0), 5.0)

    def test_http_date_retry_after_does_not_crash(self):
        # RFC 7231 allows an HTTP-date; float() would raise ValueError here.
        delay = EmailBreachModule._retry_delay(
            "Wed, 21 Oct 2015 07:28:00 GMT", 2, 2.0
        )
        self.assertEqual(delay, 4.0)


class TestPurgeLocalSessions(unittest.TestCase):
    def _module(self):
        return EmailBreachModule()

    def test_only_full_address_match_is_purged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Contains only the local-part ("admin") -> must survive.
            (root / "unrelated.json").write_text(
                '{"user": "admin", "note": "service account"}', encoding="utf-8"
            )
            # Contains the full address -> eligible for purge.
            (root / "session.token").write_text(
                "token for admin@example.com", encoding="utf-8"
            )
            purged = self._module().purge_local_sessions(
                "admin@example.com", [root]
            )
            self.assertEqual(purged, [str(root / "session.token")])
            self.assertTrue((root / "unrelated.json").exists())

    def test_symlinks_cannot_reach_outside_the_allowed_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            allowed = root / "allowed"
            outside = root / "outside"
            allowed.mkdir()
            outside.mkdir()
            secret = outside / "session.json"
            secret.write_text("admin@example.com", encoding="utf-8")
            link = allowed / "link.json"
            try:
                link.symlink_to(secret)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks not supported on this platform")

            purged = self._module().purge_local_sessions(
                "admin@example.com", [allowed]
            )
            # The link is skipped, so a symlink cannot trick the sweep into
            # deleting a file outside the authorised directory.
            self.assertEqual(purged, [])
            self.assertTrue(secret.exists())
            self.assertTrue(link.is_symlink())

    def test_non_matching_suffix_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "notes.txt").write_text("admin@example.com", encoding="utf-8")
            purged = self._module().purge_local_sessions(
                "admin@example.com", [root]
            )
            self.assertEqual(purged, [])
            self.assertTrue((root / "notes.txt").exists())


if __name__ == "__main__":
    unittest.main()
