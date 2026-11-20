"""Telegram notifications for Scorpion.ai.

Pure stdlib: all HTTP is ``urllib.request`` over HTTPS, so there is no
third-party dependency and ``HTTPS_PROXY`` / ``HTTP_PROXY`` are honoured
automatically. Secrets are never hard-coded; the bot token and the chat id come
from the :class:`~scorpion.config.Config` the operator built.

Nothing in here raises on a network error. Every public method returns a bool
(or an empty list for :meth:`Telegram.get_updates`) and logs the failure
instead, so the agent and the dashboard keep running even when Telegram is
unreachable or the token is wrong.
"""
from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
import uuid
from typing import Any, Dict, List, Optional

log = logging.getLogger("scorpion.notify.telegram")

# The public Bot API root. Kept as a module constant so tests / self-hosted
# proxies can read it, but the actual request still goes through urllib (which
# applies the HTTPS_PROXY environment variable on its own).
API_ROOT = "https://api.telegram.org"

# Hard limits imposed by the Bot API.
_TEXT_LIMIT = 4096
_CAPTION_LIMIT = 1024


class Telegram:
    """Thin Bot-API client: ``sendMessage``, ``sendVoice`` and ``getUpdates``."""

    def __init__(self, cfg: Any, timeout: float = 15.0):
        self.cfg = cfg
        self.token = str(getattr(cfg, "telegram_token", "") or "")
        self.chat_id = str(getattr(cfg, "telegram_chat_id", "") or "")
        try:
            self.timeout = float(timeout)
        except (TypeError, ValueError):
            self.timeout = 15.0

    # -- availability ------------------------------------------------------
    @property
    def available(self) -> bool:
        """True only when both a bot token and a chat id are configured."""
        return bool(self.token and self.chat_id)

    def _api_url(self, method: str) -> str:
        return "%s/bot%s/%s" % (API_ROOT, self.token, method)

    # -- sending -----------------------------------------------------------
    def send(self, text: str, parse_mode: Optional[str] = None,
             disable_preview: bool = True) -> bool:
        """POST a text message. Returns True on a confirmed ``ok`` response."""
        if not self.available:
            return False
        body = text if isinstance(text, str) else str(text)
        if not body.strip():
            return False
        payload: Dict[str, Any] = {
            "chat_id": self.chat_id,
            "text": _truncate(body, _TEXT_LIMIT),
        }
        if parse_mode:
            payload["parse_mode"] = parse_mode
        if disable_preview:
            payload["disable_web_page_preview"] = True
        try:
            data = json.dumps(payload).encode("utf-8")
        except (TypeError, ValueError) as exc:
            log.warning("telegram sendMessage: could not encode payload: %s", exc)
            return False
        req = urllib.request.Request(
            self._api_url("sendMessage"), data=data,
            headers={"content-type": "application/json",
                     "accept": "application/json"},
            method="POST")
        return self._do(req, "sendMessage")

    def send_voice(self, ogg_bytes: Optional[bytes], caption: str = "") -> bool:
        """Upload an OGG/Opus (or WAV) voice note via multipart/form-data."""
        if not self.available:
            return False
        if not ogg_bytes:
            return False
        fields: Dict[str, str] = {"chat_id": self.chat_id}
        if caption:
            fields["caption"] = _truncate(
                caption if isinstance(caption, str) else str(caption),
                _CAPTION_LIMIT)
        try:
            body, content_type = _encode_multipart(
                fields, "voice", "scorpion.ogg", bytes(ogg_bytes), "audio/ogg")
        except (TypeError, ValueError) as exc:
            log.warning("telegram sendVoice: could not encode upload: %s", exc)
            return False
        req = urllib.request.Request(
            self._api_url("sendVoice"), data=body,
            headers={"content-type": content_type, "accept": "application/json"},
            method="POST")
        return self._do(req, "sendVoice")

    # -- receiving (optional; the server may long-poll for operator commands)
    def get_updates(self, offset: Optional[int] = None,
                    timeout: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        """Long-poll for inbound messages.

        Returns a simple, compact list ``[{"update_id","text","chat_id"}]`` so
        a caller can build an operator command channel later. Never raises;
        returns ``[]`` on any failure.
        """
        if not self.available:
            return []
        try:
            poll = max(0, int(timeout))
        except (TypeError, ValueError):
            poll = 0
        payload: Dict[str, Any] = {"timeout": poll}
        try:
            payload["limit"] = max(1, min(100, int(limit)))
        except (TypeError, ValueError):
            payload["limit"] = 100
        if offset is not None:
            try:
                payload["offset"] = int(offset)
            except (TypeError, ValueError):
                pass
        try:
            data = json.dumps(payload).encode("utf-8")
        except (TypeError, ValueError):
            return []
        req = urllib.request.Request(
            self._api_url("getUpdates"), data=data,
            headers={"content-type": "application/json",
                     "accept": "application/json"},
            method="POST")
        # allow extra wall-clock room for the long poll
        obj = self._fetch(req, "getUpdates", extra_timeout=float(poll))
        if not isinstance(obj, dict) or not obj.get("ok"):
            return []
        out: List[Dict[str, Any]] = []
        for upd in obj.get("result") or []:
            if not isinstance(upd, dict):
                continue
            msg = upd.get("message") or upd.get("channel_post") or {}
            if not isinstance(msg, dict):
                msg = {}
            chat = msg.get("chat") if isinstance(msg.get("chat"), dict) else {}
            out.append({
                "update_id": upd.get("update_id"),
                "text": msg.get("text") or "",
                "chat_id": chat.get("id"),
            })
        return out

    # -- transport ---------------------------------------------------------
    def _do(self, req: "urllib.request.Request", method: str) -> bool:
        """Perform a request whose success is the API's ``ok`` flag."""
        obj = self._fetch(req, method)
        if not isinstance(obj, dict):
            return False
        ok = bool(obj.get("ok"))
        if not ok:
            log.warning("telegram %s rejected: %s", method,
                        str(obj.get("description"))[:200])
        return ok

    def _fetch(self, req: "urllib.request.Request", method: str,
               extra_timeout: float = 0.0) -> Optional[Dict[str, Any]]:
        """Send ``req`` and parse the JSON body. Returns None on any failure."""
        try:
            with urllib.request.urlopen(
                    req, timeout=self.timeout + max(0.0, extra_timeout)) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            # The Bot API returns a JSON body even on 4xx; try to read it.
            detail = _read_error_body(exc)
            log.warning("telegram %s HTTP %s: %s", method,
                        getattr(exc, "code", "?"), detail)
            return None
        except (urllib.error.URLError, OSError) as exc:
            log.warning("telegram %s network error: %s", method,
                        getattr(exc, "reason", exc))
            return None
        except Exception as exc:  # noqa: BLE001 - notifications must never raise
            log.warning("telegram %s unexpected error: %s", method, exc)
            return None
        text = raw.decode("utf-8", "replace") if isinstance(
            raw, (bytes, bytearray)) else str(raw)
        try:
            obj = json.loads(text)
        except ValueError:
            log.warning("telegram %s: non-JSON response", method)
            return None
        return obj if isinstance(obj, dict) else None


# ---------------------------------------------------------------------------
# module-level helpers (pure, easy to test)
# ---------------------------------------------------------------------------
def _truncate(text: str, limit: int) -> str:
    s = text if isinstance(text, str) else str(text)
    if len(s) <= limit:
        return s
    if limit <= 3:
        return s[:limit]
    return s[: limit - 3] + "..."


def _encode_multipart(fields: Dict[str, str], file_field: str, filename: str,
                      file_bytes: bytes, file_ctype: str):
    """Build a ``multipart/form-data`` body. Returns ``(body, content_type)``."""
    boundary = "----ScorpionBoundary" + uuid.uuid4().hex
    bnd = boundary.encode("ascii")
    crlf = b"\r\n"
    parts: List[bytes] = []
    for name, value in fields.items():
        parts.append(b"--" + bnd)
        parts.append(
            ('Content-Disposition: form-data; name="%s"' % name).encode("utf-8"))
        parts.append(b"")
        parts.append(str(value).encode("utf-8"))
    parts.append(b"--" + bnd)
    parts.append(('Content-Disposition: form-data; name="%s"; filename="%s"'
                  % (file_field, filename)).encode("utf-8"))
    parts.append(("Content-Type: %s" % file_ctype).encode("utf-8"))
    parts.append(b"")
    parts.append(file_bytes)
    parts.append(b"--" + bnd + b"--")
    parts.append(b"")
    body = crlf.join(parts)
    content_type = "multipart/form-data; boundary=%s" % boundary
    return body, content_type


def _read_error_body(exc: "urllib.error.HTTPError") -> str:
    try:
        data = exc.read()
    except Exception:  # noqa: BLE001 - diagnostics must never raise
        return getattr(exc, "reason", "") or "http error"
    text = data.decode("utf-8", "replace") if isinstance(
        data, (bytes, bytearray)) else str(data)
    try:
        obj = json.loads(text)
    except ValueError:
        return text[:200] or "http error"
    if isinstance(obj, dict) and obj.get("description"):
        return str(obj["description"])[:200]
    return text[:200] or "http error"


__all__ = ["Telegram", "API_ROOT"]
