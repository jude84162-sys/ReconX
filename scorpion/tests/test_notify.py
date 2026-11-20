"""Tests for the notification layer (Telegram + voice + Notifier).

NETWORK ISOLATION: every Telegram test replaces ``urllib.request.urlopen`` with
a fake that captures the outgoing request and returns a canned Bot-API JSON body
(or raises a canned URLError/HTTPError). Nothing here opens a socket, touches
the real Telegram API, or needs an audio device: ``shutil.which`` is monkeypatched
so the voice engine reports "unavailable" and ``subprocess.run`` is patched to
blow up if any test ever tries to actually shell out.

Sibling scorpion modules are NOT imported — the Notifier is exercised against
fakes so this suite does not depend on a half-written peer.

Run just this module from the repo root:
    python3 -m unittest scorpion.tests.test_notify -v
"""
import io
import json
import unittest
from unittest import mock
from urllib.error import HTTPError, URLError

from scorpion.config import Config
from scorpion.notify import Notifier, _format_event, _count_severities
from scorpion.notify.telegram import Telegram, API_ROOT, _encode_multipart, _truncate
from scorpion.notify.voice import Voice


# --------------------------------------------------------------------------
# fakes / helpers
# --------------------------------------------------------------------------
class _FakeResponse:
    """Stand-in for the urlopen context-manager object."""

    def __init__(self, payload):
        if isinstance(payload, (dict, list)):
            payload = json.dumps(payload)
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        self._payload = payload

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _http_error(code, body=None):
    if body is None:
        body = {"ok": False, "error_code": code, "description": "boom %d" % code}
    if isinstance(body, (dict, list)):
        body = json.dumps(body)
    fp = io.BytesIO(body.encode("utf-8") if isinstance(body, str) else body)
    return HTTPError("https://api.telegram.org/x", code, "err", {}, fp)


class _Capture:
    """Records every request urlopen receives and returns a canned body."""

    def __init__(self, response=None):
        self.calls = []
        self._response = response if response is not None else {"ok": True, "result": {}}

    def urlopen(self, req, timeout=None):
        self.calls.append({
            "url": req.full_url,
            "method": req.get_method(),
            "headers": {k.lower(): v for k, v in req.header_items()},
            "body": req.data,
            "timeout": timeout,
        })
        return _FakeResponse(self._response)

    def methods(self):
        return [c["url"].rsplit("/", 1)[-1] for c in self.calls]


class FakeTelegram:
    """A Telegram double that records calls without any network."""

    def __init__(self, available=True, send_ok=True, raises=False):
        self._available = available
        self._send_ok = send_ok
        self._raises = raises
        self.sent = []
        self.voices = []

    @property
    def available(self):
        return self._available

    def send(self, text, parse_mode=None, disable_preview=True):
        if self._raises:
            raise RuntimeError("telegram exploded")
        self.sent.append(text)
        return self._send_ok

    def send_voice(self, ogg_bytes, caption=""):
        self.voices.append((ogg_bytes, caption))
        return self._send_ok


class FakeVoice:
    """A Voice double that never shells out."""

    def __init__(self, audio=b"OGGDATA", engine="fake"):
        self._audio = audio
        self._engine = engine
        self.tts_calls = []
        self.speak_calls = []

    @property
    def engine_name(self):
        return self._engine

    @property
    def available(self):
        return self._engine is not None

    def tts(self, text):
        self.tts_calls.append(text)
        return self._audio

    def speak(self, text):
        self.speak_calls.append(text)
        return True


def _tg_cfg(**over):
    base = dict(telegram_token="TTOKEN", telegram_chat_id="99")
    base.update(over)
    return Config(**base)


def _blow_up_subprocess(*a, **k):
    raise AssertionError("subprocess.run must not be called in these tests")


# --------------------------------------------------------------------------
# Telegram: availability
# --------------------------------------------------------------------------
class TelegramAvailabilityTests(unittest.TestCase):
    def test_unavailable_without_token(self):
        self.assertFalse(Telegram(Config(telegram_chat_id="99")).available)

    def test_unavailable_without_chat_id(self):
        self.assertFalse(Telegram(Config(telegram_token="t")).available)

    def test_available_with_both(self):
        self.assertTrue(Telegram(_tg_cfg()).available)

    def test_send_short_circuits_when_unavailable(self):
        tg = Telegram(Config())  # nothing configured
        with mock.patch("urllib.request.urlopen",
                        side_effect=AssertionError("network touched!")):
            self.assertFalse(tg.send("hi"))
            self.assertFalse(tg.send_voice(b"x"))
            self.assertEqual(tg.get_updates(), [])


# --------------------------------------------------------------------------
# Telegram: sendMessage URL + payload
# --------------------------------------------------------------------------
class TelegramSendTests(unittest.TestCase):
    def test_builds_correct_url_and_payload(self):
        cap = _Capture({"ok": True, "result": {"message_id": 1}})
        tg = Telegram(_tg_cfg())
        with mock.patch("urllib.request.urlopen", side_effect=cap.urlopen):
            ok = tg.send("hello world")
        self.assertTrue(ok)
        self.assertEqual(len(cap.calls), 1)
        call = cap.calls[0]
        self.assertEqual(call["url"], API_ROOT + "/botTTOKEN/sendMessage")
        self.assertEqual(call["method"], "POST")
        self.assertEqual(call["headers"]["content-type"], "application/json")
        body = json.loads(call["body"].decode("utf-8"))
        self.assertEqual(body["chat_id"], "99")
        self.assertEqual(body["text"], "hello world")
        self.assertTrue(body["disable_web_page_preview"])
        self.assertNotIn("parse_mode", body)

    def test_parse_mode_is_passed_through(self):
        cap = _Capture()
        tg = Telegram(_tg_cfg())
        with mock.patch("urllib.request.urlopen", side_effect=cap.urlopen):
            tg.send("*bold*", parse_mode="MarkdownV2")
        body = json.loads(cap.calls[0]["body"].decode("utf-8"))
        self.assertEqual(body["parse_mode"], "MarkdownV2")

    def test_empty_text_not_sent(self):
        cap = _Capture()
        tg = Telegram(_tg_cfg())
        with mock.patch("urllib.request.urlopen", side_effect=cap.urlopen):
            self.assertFalse(tg.send("   "))
        self.assertEqual(cap.calls, [])

    def test_api_not_ok_returns_false(self):
        cap = _Capture({"ok": False, "description": "chat not found"})
        tg = Telegram(_tg_cfg())
        with mock.patch("urllib.request.urlopen", side_effect=cap.urlopen):
            self.assertFalse(tg.send("hi"))

    def test_network_error_returns_false_not_exception(self):
        tg = Telegram(_tg_cfg())
        with mock.patch("urllib.request.urlopen",
                        side_effect=URLError("no route to host")):
            self.assertFalse(tg.send("hi"))  # must not raise

    def test_http_error_returns_false_not_exception(self):
        tg = Telegram(_tg_cfg())
        with mock.patch("urllib.request.urlopen", side_effect=_http_error(429)):
            self.assertFalse(tg.send("hi"))  # must not raise

    def test_oserror_returns_false_not_exception(self):
        tg = Telegram(_tg_cfg())
        with mock.patch("urllib.request.urlopen",
                        side_effect=OSError("connection reset")):
            self.assertFalse(tg.send("hi"))

    def test_non_json_body_returns_false(self):
        tg = Telegram(_tg_cfg())
        with mock.patch("urllib.request.urlopen",
                        return_value=_FakeResponse(b"<html>nope</html>")):
            self.assertFalse(tg.send("hi"))

    def test_long_text_is_truncated(self):
        cap = _Capture()
        tg = Telegram(_tg_cfg())
        with mock.patch("urllib.request.urlopen", side_effect=cap.urlopen):
            tg.send("A" * 9000)
        body = json.loads(cap.calls[0]["body"].decode("utf-8"))
        self.assertLessEqual(len(body["text"]), 4096)
        self.assertTrue(body["text"].endswith("..."))


# --------------------------------------------------------------------------
# Telegram: sendVoice multipart
# --------------------------------------------------------------------------
class TelegramVoiceTests(unittest.TestCase):
    def test_multipart_upload_shape(self):
        cap = _Capture()
        tg = Telegram(_tg_cfg())
        with mock.patch("urllib.request.urlopen", side_effect=cap.urlopen):
            ok = tg.send_voice(b"OGGDATA", caption="critical finding")
        self.assertTrue(ok)
        call = cap.calls[0]
        self.assertEqual(call["url"], API_ROOT + "/botTTOKEN/sendVoice")
        ctype = call["headers"]["content-type"]
        self.assertTrue(ctype.startswith("multipart/form-data; boundary="))
        raw = call["body"]
        self.assertIn(b"OGGDATA", raw)
        self.assertIn(b'name="chat_id"', raw)
        self.assertIn(b"99", raw)
        self.assertIn(b'name="voice"; filename="scorpion.ogg"', raw)
        self.assertIn(b'name="caption"', raw)

    def test_no_bytes_returns_false(self):
        tg = Telegram(_tg_cfg())
        with mock.patch("urllib.request.urlopen",
                        side_effect=AssertionError("network touched!")):
            self.assertFalse(tg.send_voice(b""))
            self.assertFalse(tg.send_voice(None))

    def test_voice_network_error_returns_false(self):
        tg = Telegram(_tg_cfg())
        with mock.patch("urllib.request.urlopen",
                        side_effect=URLError("down")):
            self.assertFalse(tg.send_voice(b"OGGDATA"))


# --------------------------------------------------------------------------
# Telegram: getUpdates
# --------------------------------------------------------------------------
class TelegramGetUpdatesTests(unittest.TestCase):
    def test_parses_messages(self):
        resp = {"ok": True, "result": [
            {"update_id": 5, "message": {"text": "status?",
                                         "chat": {"id": 99}}},
            {"update_id": 6, "message": {"chat": {"id": 99}}},  # no text
        ]}
        cap = _Capture(resp)
        tg = Telegram(_tg_cfg())
        with mock.patch("urllib.request.urlopen", side_effect=cap.urlopen):
            updates = tg.get_updates(offset=4)
        self.assertEqual(updates, [
            {"update_id": 5, "text": "status?", "chat_id": 99},
            {"update_id": 6, "text": "", "chat_id": 99},
        ])
        body = json.loads(cap.calls[0]["body"].decode("utf-8"))
        self.assertEqual(body["offset"], 4)

    def test_network_error_yields_empty_list(self):
        tg = Telegram(_tg_cfg())
        with mock.patch("urllib.request.urlopen", side_effect=URLError("x")):
            self.assertEqual(tg.get_updates(), [])


# --------------------------------------------------------------------------
# multipart encoder (pure)
# --------------------------------------------------------------------------
class MultipartEncoderTests(unittest.TestCase):
    def test_encodes_fields_and_file(self):
        body, ctype = _encode_multipart(
            {"chat_id": "99", "caption": "hi"},
            "voice", "a.ogg", b"BYTES", "audio/ogg")
        self.assertTrue(ctype.startswith("multipart/form-data; boundary="))
        boundary = ctype.split("boundary=", 1)[1]
        self.assertIn(("--" + boundary).encode("ascii"), body)
        self.assertTrue(body.rstrip().endswith(("--" + boundary + "--").encode("ascii")))
        self.assertIn(b"BYTES", body)
        self.assertIn(b'name="chat_id"', body)


# --------------------------------------------------------------------------
# Voice: graceful degradation with no engine
# --------------------------------------------------------------------------
class VoiceUnavailableTests(unittest.TestCase):
    def test_reports_unavailable_and_tts_returns_none(self):
        v = Voice(Config(voice_enabled=True))
        with mock.patch("shutil.which", return_value=None), \
                mock.patch("subprocess.run", side_effect=_blow_up_subprocess):
            self.assertIsNone(v.engine_name)
            self.assertFalse(v.available)
            self.assertIsNone(v.tts("hello there"))     # no error, no subprocess
            self.assertFalse(v.speak("hello there"))

    def test_blank_text_returns_none_even_with_engine(self):
        v = Voice(Config())
        with mock.patch("shutil.which", return_value="/usr/bin/espeak"), \
                mock.patch("subprocess.run", side_effect=_blow_up_subprocess):
            self.assertIsNone(v.tts("   "))             # blank -> never shells out
            self.assertFalse(v.speak(""))


class VoiceEngineSelectionTests(unittest.TestCase):
    def _which_only(self, *names):
        allowed = set(names)
        return lambda cmd: ("/usr/bin/" + cmd) if cmd in allowed else None

    def test_picks_espeak_when_present(self):
        v = Voice(Config())
        with mock.patch("shutil.which", side_effect=self._which_only("espeak")):
            self.assertEqual(v.engine_name, "espeak")

    def test_prefers_espeak_ng_over_espeak(self):
        v = Voice(Config())
        with mock.patch("shutil.which",
                        side_effect=self._which_only("espeak-ng", "espeak", "say")):
            self.assertEqual(v.engine_name, "espeak-ng")

    def test_say_when_only_macos(self):
        v = Voice(Config())
        with mock.patch("shutil.which", side_effect=self._which_only("say")):
            self.assertEqual(v.engine_name, "say")

    def test_piper_needs_a_model(self):
        v = Voice(Config())
        with mock.patch("shutil.which", side_effect=self._which_only("piper")):
            self.assertIsNone(v.engine_name)           # no model -> piper skipped
            v.piper_model = "/models/voice.onnx"
            self.assertEqual(v.engine_name, "piper")

    def test_available_tracks_enabled_flag(self):
        with mock.patch("shutil.which", side_effect=self._which_only("espeak")):
            self.assertTrue(Voice(Config(voice_enabled=True)).available)
            self.assertFalse(Voice(Config(voice_enabled=False)).available)

    def test_speak_disabled_returns_false_without_touching_which(self):
        v = Voice(Config(voice_enabled=False))
        with mock.patch("shutil.which",
                        side_effect=AssertionError("which touched!")), \
                mock.patch("subprocess.run", side_effect=_blow_up_subprocess):
            self.assertFalse(v.speak("hi"))


# --------------------------------------------------------------------------
# formatting helpers (pure)
# --------------------------------------------------------------------------
class FormattingTests(unittest.TestCase):
    def test_finding_message_is_compact(self):
        msg = _format_event(
            {"type": "finding", "severity": "critical", "title": "RCE in /api",
             "target": "api.example.com", "detail": "unauth command injection"},
            "finding")
        self.assertIn("CRITICAL", msg)
        self.assertIn("RCE in /api", msg)
        self.assertIn("api.example.com", msg)
        self.assertIn("command injection", msg)

    def test_done_message_counts_severities(self):
        msg = _format_event(
            {"type": "done",
             "findings": [{"severity": "critical"}, {"severity": "high"},
                          {"severity": "high"}, {"severity": "info"}]},
            "done")
        self.assertIn("4 findings", msg)
        self.assertIn("1 critical", msg)
        self.assertIn("2 high", msg)

    def test_count_severities_order(self):
        counts = _count_severities(
            [{"severity": "low"}, {"severity": "critical"}, {"severity": "low"}])
        self.assertEqual(counts, [("critical", 1), ("low", 2)])

    def test_error_and_status_messages(self):
        self.assertIn("Scorpion error", _format_event(
            {"type": "error", "text": "boom"}, "error"))
        self.assertIn("recon starting", _format_event(
            {"type": "status", "text": "recon starting"}, "status"))


# --------------------------------------------------------------------------
# Notifier: safe no-op when nothing is configured
# --------------------------------------------------------------------------
class NotifierNoOpTests(unittest.TestCase):
    def test_unconfigured_is_inactive_and_silent(self):
        n = Notifier(Config())  # no telegram, default voice (no engine in tests)
        self.assertFalse(n.active)
        with mock.patch("urllib.request.urlopen",
                        side_effect=AssertionError("network touched!")), \
                mock.patch("subprocess.run", side_effect=_blow_up_subprocess), \
                mock.patch("shutil.which", return_value=None):
            for ev in (
                {"type": "status", "text": "x"},
                {"type": "finding", "severity": "critical", "title": "t"},
                {"type": "done", "findings": [{"severity": "high"}]},
                {"type": "error", "text": "e"},
                {"type": "report", "markdown": "# r"},
                {"type": "thinking", "text": "hmm"},
                "not-a-dict",
            ):
                n.notify_event(ev)             # must not raise, must not call network
            self.assertFalse(n.notify_text("hello"))
        n.close()  # no-op, must not raise


# --------------------------------------------------------------------------
# Notifier: routing when Telegram IS configured
# --------------------------------------------------------------------------
class NotifierRoutingTests(unittest.TestCase):
    def test_critical_finding_routes_to_telegram_with_voice_note(self):
        cap = _Capture()
        voice = FakeVoice(audio=b"OGGDATA")
        n = Notifier(_tg_cfg(), voice=voice)   # real Telegram, fake Voice
        with mock.patch("urllib.request.urlopen", side_effect=cap.urlopen):
            n.notify_event({"type": "finding", "severity": "critical",
                            "title": "RCE", "target": "api.example.com"})
        methods = cap.methods()
        self.assertIn("sendMessage", methods)          # text alert sent
        self.assertIn("sendVoice", methods)            # loud -> voice note
        self.assertEqual(voice.tts_calls and True, True)
        # the text message carried the finding
        msg_call = next(c for c in cap.calls if c["url"].endswith("sendMessage"))
        body = json.loads(msg_call["body"].decode("utf-8"))
        self.assertEqual(body["chat_id"], "99")
        self.assertIn("CRITICAL", body["text"])
        self.assertIn("RCE", body["text"])
        # the voice note was a multipart upload containing the synthesized bytes
        voice_call = next(c for c in cap.calls if c["url"].endswith("sendVoice"))
        self.assertIn(b"OGGDATA", voice_call["body"])

    def test_info_finding_sends_text_but_no_voice(self):
        cap = _Capture()
        voice = FakeVoice()
        n = Notifier(_tg_cfg(), voice=voice)
        with mock.patch("urllib.request.urlopen", side_effect=cap.urlopen):
            n.notify_event({"type": "finding", "severity": "info", "title": "banner"})
        self.assertEqual(cap.methods(), ["sendMessage"])   # text only
        self.assertEqual(voice.tts_calls, [])              # not loud -> no synth

    def test_done_event_sends_text_and_voice(self):
        cap = _Capture()
        voice = FakeVoice(audio=b"OGG")
        n = Notifier(_tg_cfg(), voice=voice)
        with mock.patch("urllib.request.urlopen", side_effect=cap.urlopen):
            n.notify_event({"type": "done",
                            "findings": [{"severity": "high"}], "report": "# R"})
        self.assertEqual(sorted(set(cap.methods())), ["sendMessage", "sendVoice"])

    def test_noisy_events_are_dropped(self):
        cap = _Capture()
        n = Notifier(_tg_cfg(), voice=FakeVoice())
        with mock.patch("urllib.request.urlopen", side_effect=cap.urlopen):
            for t in ("thinking", "tool_call", "tool_result"):
                n.notify_event({"type": t, "text": "noise"})
        self.assertEqual(cap.calls, [])                    # nothing forwarded

    def test_voice_disabled_sends_text_only(self):
        cap = _Capture()
        voice = FakeVoice()
        n = Notifier(_tg_cfg(voice_enabled=False), voice=voice)
        with mock.patch("urllib.request.urlopen", side_effect=cap.urlopen):
            n.notify_event({"type": "finding", "severity": "critical", "title": "x"})
        self.assertEqual(cap.methods(), ["sendMessage"])   # no voice note
        self.assertEqual(voice.tts_calls, [])

    def test_voice_synth_returning_none_skips_voice_note(self):
        cap = _Capture()
        voice = FakeVoice(audio=None)                      # engine yields nothing
        n = Notifier(_tg_cfg(), voice=voice)
        with mock.patch("urllib.request.urlopen", side_effect=cap.urlopen):
            n.notify_event({"type": "finding", "severity": "high", "title": "x"})
        self.assertEqual(cap.methods(), ["sendMessage"])
        self.assertEqual(len(voice.tts_calls), 1)          # tried, but got None

    def test_notify_text_sends(self):
        cap = _Capture()
        n = Notifier(_tg_cfg(), voice=FakeVoice())
        with mock.patch("urllib.request.urlopen", side_effect=cap.urlopen):
            self.assertTrue(n.notify_text("ping"))
        self.assertEqual(cap.methods(), ["sendMessage"])

    def test_notify_event_swallows_telegram_exceptions(self):
        n = Notifier(_tg_cfg(), telegram=FakeTelegram(raises=True),
                     voice=FakeVoice())
        # must not propagate the RuntimeError from telegram.send
        n.notify_event({"type": "error", "text": "boom"})

    def test_local_speech_opt_in(self):
        voice = FakeVoice()
        n = Notifier(_tg_cfg(), telegram=FakeTelegram(), voice=voice,
                     speak_locally=True)
        n.notify_event({"type": "done", "findings": []})
        self.assertTrue(voice.speak_calls)                 # spoke locally
        self.assertTrue(n.active)


if __name__ == "__main__":
    unittest.main()
