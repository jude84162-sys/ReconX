"""Notifications for Scorpion.ai.

:class:`Notifier` is the single fan-out sink the agent writes to. It takes the
shared *event* dicts the agent emits (the same ones the dashboard renders) and
forwards the notable ones to Telegram, attaches a spoken voice note to the
loud ones (``high`` / ``critical`` findings and the final ``done`` event), and
optionally speaks them on the local machine.

Event contract (see the package docstring)::

    {"type": t, "ts": float, "text": str, ...extra}

    "status" | "thinking" | "tool_call" | "tool_result" |
    "finding"(title, severity, detail, target) | "report"(markdown) |
    "error"(text) | "done"(findings:[...], report:str)

Severity scale: "info" < "low" < "medium" < "high" < "critical".

A :class:`Notifier` is always safe to construct: with no Telegram token and no
voice engine it becomes a silent no-op sink, so the agent never has to branch on
"is notification configured".
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from .telegram import Telegram, _truncate
from .voice import Voice

log = logging.getLogger("scorpion.notify")

# Which event types are worth forwarding to Telegram. The high-frequency
# narration ("thinking", "tool_call", "tool_result") is deliberately dropped so
# the operator's phone is not spammed; the dashboard already shows those live.
FORWARD_TYPES = frozenset(("status", "finding", "report", "error", "done"))

# Events that also deserve a spoken voice note / local speech.
LOUD_SEVERITIES = frozenset(("high", "critical"))

_SEV_ORDER = ("critical", "high", "medium", "low", "info")


class Notifier:
    """Fan a single event dict out to Telegram and (optionally) local speech."""

    def __init__(self, cfg: Any,
                 telegram: Optional[Telegram] = None,
                 voice: Optional[Voice] = None,
                 speak_locally: bool = False):
        self.cfg = cfg
        self.telegram = telegram if telegram is not None else Telegram(cfg)
        self.voice = voice if voice is not None else Voice(cfg)
        self.voice_enabled = bool(getattr(cfg, "voice_enabled", True))
        # Local speech is off by default: most deployments are headless servers
        # where the operator wants Telegram, not a server talking to an empty room.
        self.speak_locally = bool(speak_locally)

    # -- introspection -----------------------------------------------------
    @property
    def active(self) -> bool:
        """True when at least one channel can actually deliver something."""
        tg = self.telegram is not None and self.telegram.available
        local = (self.speak_locally and self.voice_enabled
                 and self.voice is not None)
        return bool(tg or local)

    # -- the public sink ---------------------------------------------------
    def notify_event(self, event: Dict[str, Any]) -> None:
        """Route one event dict to the configured channels. Never raises."""
        if not isinstance(event, dict):
            return
        etype = str(event.get("type", ""))
        if etype not in FORWARD_TYPES:
            return
        try:
            self._route(event, etype)
        except Exception as exc:  # noqa: BLE001 - a bad event must not crash the agent
            log.warning("notify_event(%s) failed: %s", etype, exc)

    def notify_text(self, text: str) -> bool:
        """Send a plain, ad-hoc message (and speak it locally if enabled)."""
        body = text if isinstance(text, str) else str(text or "")
        if not body.strip():
            return False
        sent = False
        if self.telegram is not None and self.telegram.available:
            try:
                sent = bool(self.telegram.send(body))
            except Exception as exc:  # noqa: BLE001
                log.warning("notify_text telegram failed: %s", exc)
        self._maybe_speak(body)
        return sent

    def close(self) -> None:
        """Lifecycle hook. Nothing is held open today; present for the contract."""
        return None

    # -- internals ---------------------------------------------------------
    def _route(self, event: Dict[str, Any], etype: str) -> None:
        loud = self._is_loud(event, etype)
        message = _format_event(event, etype)

        if self.telegram is not None and self.telegram.available and message:
            self.telegram.send(message)
            if loud:
                audio = self._make_voice(event, etype)
                if audio:
                    self.telegram.send_voice(
                        audio, caption=_truncate(_spoken_text(event, etype), 200))

        if loud:
            self._maybe_speak(_spoken_text(event, etype))

    def _is_loud(self, event: Dict[str, Any], etype: str) -> bool:
        if etype == "done":
            return True
        if etype == "finding":
            return str(event.get("severity", "info")).lower() in LOUD_SEVERITIES
        return False

    def _make_voice(self, event: Dict[str, Any], etype: str) -> Optional[bytes]:
        if not self.voice_enabled or self.voice is None:
            return None
        try:
            return self.voice.tts(_spoken_text(event, etype))
        except Exception as exc:  # noqa: BLE001
            log.warning("voice synthesis failed: %s", exc)
            return None

    def _maybe_speak(self, text: str) -> None:
        if not (self.speak_locally and self.voice_enabled and self.voice is not None):
            return
        try:
            self.voice.speak(text)
        except Exception as exc:  # noqa: BLE001
            log.warning("local speech failed: %s", exc)


# ---------------------------------------------------------------------------
# formatting helpers (pure functions, easy to test)
# ---------------------------------------------------------------------------
def _format_event(event: Dict[str, Any], etype: str) -> str:
    """Render an event as a compact Telegram text message."""
    text = str(event.get("text", "") or "")
    if etype == "finding":
        sev = str(event.get("severity", "info")).lower()
        title = str(event.get("title", "") or text or "finding")
        lines: List[str] = ["Scorpion [%s] %s" % (sev.upper(), title)]
        target = event.get("target")
        if target:
            lines.append("target: %s" % target)
        detail = event.get("detail")
        if detail:
            lines.append(_truncate(str(detail), 800))
        return "\n".join(lines)
    if etype == "done":
        findings = event.get("findings")
        findings = findings if isinstance(findings, (list, tuple)) else []
        counts = _count_severities(findings)
        head = "Scorpion engagement complete: %d finding%s" % (
            len(findings), "" if len(findings) == 1 else "s")
        if counts:
            head += " (" + ", ".join("%d %s" % (c, s) for s, c in counts) + ")"
        if text:
            head += "\n" + _truncate(text, 500)
        return head
    if etype == "error":
        return "Scorpion error: %s" % _truncate(text or "unknown error", 1000)
    if etype == "report":
        md = event.get("markdown")
        md = md if isinstance(md, str) and md else text
        return _truncate(str(md or "(empty report)"), 3500)
    if etype == "status":
        return "Scorpion: %s" % _truncate(text or "status update", 500)
    return _truncate(text, 1000)


def _spoken_text(event: Dict[str, Any], etype: str) -> str:
    """A short, plain phrase suitable for speech / a voice-note caption."""
    if etype == "finding":
        sev = str(event.get("severity", "info")).lower()
        title = str(event.get("title", "")
                    or event.get("text", "") or "an issue")
        return "Scorpion found a %s severity issue: %s" % (sev, title)
    if etype == "done":
        findings = event.get("findings")
        n = len(findings) if isinstance(findings, (list, tuple)) else 0
        return "Scorpion engagement complete. %d finding%s." % (
            n, "" if n == 1 else "s")
    if etype == "error":
        return "Scorpion error. %s" % str(event.get("text", "") or "")
    return str(event.get("text", "") or "")


def _count_severities(findings) -> List[Tuple[str, int]]:
    counts: Dict[str, int] = {}
    for f in findings or []:
        sev = str(f.get("severity", "info")).lower() if isinstance(f, dict) else "info"
        counts[sev] = counts.get(sev, 0) + 1
    ordered = [(s, counts[s]) for s in _SEV_ORDER if s in counts]
    # include any out-of-scale severities after the known ones, stable-sorted
    for s in sorted(counts):
        if s not in _SEV_ORDER:
            ordered.append((s, counts[s]))
    return ordered


__all__ = ["Notifier", "Telegram", "Voice", "FORWARD_TYPES", "LOUD_SEVERITIES"]
