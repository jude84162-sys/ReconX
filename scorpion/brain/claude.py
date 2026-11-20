"""The Brain: a tiny stdlib-only client for the Anthropic Messages API.

No `anthropic` / `requests` SDK — just `urllib.request` over HTTPS, which means
no third-party dependency and automatic respect for the `HTTPS_PROXY`/`HTTP_PROXY`
environment variables. Secrets are never hard-coded; the API key comes from the
Config the operator built.

The agent owns the tool-use loop. The Brain only does one thing: send one
Messages request and parse the response into a flat dict the agent can use:

    {
        "text":             str,   # concatenated text blocks
        "assistant_content": list, # the raw response "content" list, verbatim,
                                   # so the agent can append it as the assistant turn
        "tool_calls":       list,  # [{"id","name","input"}] parsed from tool_use blocks
        "stop_reason":      str,   # "end_turn" | "tool_use" | "max_tokens" | "refusal" | ...
        "usage":            dict,  # token usage from the API
        "error":            str,   # non-empty on any failure (the Brain NEVER raises)
    }

On any HTTP or network error the dict is returned with `error` set and the other
fields empty — callers check `error` (or `available`) rather than catching
exceptions. Transient failures (429 / 529 / 5xx / connection resets) are retried
a few times with exponential backoff, honouring a `Retry-After` header when the
server sends one.
"""
from __future__ import annotations

import json
import random
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from ..config import ANTHROPIC_BASE, ANTHROPIC_VERSION

# status codes worth retrying: rate limit, overloaded, and transient server errors
_RETRY_STATUS = frozenset((408, 409, 425, 429, 500, 502, 503, 504, 529))


class Brain:
    """One instance per process; cheap to construct, holds no open sockets."""

    def __init__(self, cfg: Any,
                 max_retries: int = 4,
                 timeout: float = 120.0,
                 base_delay: float = 0.8,
                 max_delay: float = 20.0):
        self.cfg = cfg
        base = str(getattr(cfg, "anthropic_base", "") or ANTHROPIC_BASE)
        self.base = base.rstrip("/")
        self.api_key = str(getattr(cfg, "anthropic_api_key", "") or "")
        self.model = str(getattr(cfg, "model", "") or "")
        self.heavy_model = str(getattr(cfg, "heavy_model", "") or self.model)
        try:
            self.max_tokens = int(getattr(cfg, "max_tokens", 4096) or 4096)
        except (TypeError, ValueError):
            self.max_tokens = 4096
        self.version = ANTHROPIC_VERSION
        # retry/backoff knobs (kept as instance attrs so tests can tune them)
        self.max_retries = max(0, int(max_retries))
        self.timeout = float(timeout)
        self.base_delay = float(base_delay)
        self.max_delay = float(max_delay)

    # -- availability ------------------------------------------------------
    @property
    def available(self) -> bool:
        """True when the engagement is configured to use the LLM."""
        return bool(getattr(self.cfg, "has_brain", False))

    # -- the one public call -----------------------------------------------
    def complete(self,
                 system: Optional[str],
                 messages: List[Dict[str, Any]],
                 tools: Optional[List[Dict[str, Any]]] = None,
                 model: Optional[str] = None,
                 max_tokens: Optional[int] = None) -> Dict[str, Any]:
        """Send one Messages request and return the parsed result dict.

        Never raises — failures come back as ``{"error": ...}``.
        """
        if not self.available:
            return _result(error="brain unavailable: no Anthropic API key "
                                 "configured (or no_llm is set)")

        body: Dict[str, Any] = {
            "model": model or self.model,
            "max_tokens": _coerce_int(max_tokens, self.max_tokens),
            "messages": messages or [],
        }
        if system:
            body["system"] = system
        if tools:
            body["tools"] = tools

        raw, err = self._post(body)
        if err:
            return _result(error=err)
        return _parse_response(raw)

    # -- HTTP with retries -------------------------------------------------
    def _post(self, body: Dict[str, Any]):
        """POST the body to /v1/messages. Returns (parsed_json, error_str)."""
        try:
            data = json.dumps(body).encode("utf-8")
        except (TypeError, ValueError) as exc:
            return None, "could not encode request: %s" % exc

        url = self.base + "/v1/messages"
        headers = {
            "content-type": "application/json",
            "accept": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": self.version,
        }

        last_err = "request failed"
        for attempt in range(self.max_retries + 1):
            req = urllib.request.Request(url, data=data, headers=headers,
                                         method="POST")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    payload = resp.read()
                text = payload.decode("utf-8", "replace") if isinstance(
                    payload, (bytes, bytearray)) else str(payload)
                try:
                    return json.loads(text), ""
                except ValueError as exc:
                    return None, "invalid JSON from API: %s" % exc
            except urllib.error.HTTPError as exc:          # 4xx/5xx with a body
                detail = _read_http_error(exc)
                last_err = "HTTP %s: %s" % (exc.code, detail)
                if exc.code in _RETRY_STATUS and attempt < self.max_retries:
                    self._backoff(attempt, exc)
                    continue
                return None, last_err
            except urllib.error.URLError as exc:           # DNS/connection/proxy
                last_err = "network error: %s" % (getattr(exc, "reason", exc),)
                if attempt < self.max_retries:
                    self._backoff(attempt, None)
                    continue
                return None, last_err
            except OSError as exc:                         # socket timeout, reset
                last_err = "connection error: %s" % exc
                if attempt < self.max_retries:
                    self._backoff(attempt, None)
                    continue
                return None, last_err
        return None, last_err

    def _backoff(self, attempt: int, http_exc) -> None:
        delay = min(self.base_delay * (2 ** attempt), self.max_delay)
        if http_exc is not None:
            retry_after = _retry_after_seconds(http_exc)
            if retry_after is not None:
                delay = max(delay, min(retry_after, self.max_delay))
        time.sleep(delay + random.uniform(0.0, 0.25))


# ---------------------------------------------------------------------------
# module-level helpers (pure, easy to test)
# ---------------------------------------------------------------------------
def _result(text: str = "",
            assistant_content: Optional[List[Any]] = None,
            tool_calls: Optional[List[Dict[str, Any]]] = None,
            stop_reason: str = "",
            usage: Optional[Dict[str, Any]] = None,
            error: str = "") -> Dict[str, Any]:
    return {
        "text": text,
        "assistant_content": assistant_content if assistant_content is not None else [],
        "tool_calls": tool_calls if tool_calls is not None else [],
        "stop_reason": stop_reason,
        "usage": usage if usage is not None else {},
        "error": error,
    }


def _coerce_int(value, default: int) -> int:
    try:
        if value is None:
            return int(default)
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def _parse_response(raw: Any) -> Dict[str, Any]:
    """Turn the Anthropic Messages response JSON into the Brain's flat dict."""
    if not isinstance(raw, dict):
        return _result(error="unexpected API response type: %s" % type(raw).__name__)

    # a top-level API error object (can arrive with HTTP 200 in some setups)
    if raw.get("type") == "error":
        err = raw.get("error")
        msg = err.get("message") if isinstance(err, dict) else err
        return _result(error="API error: %s" % (msg or raw))

    content = raw.get("content")
    if not isinstance(content, list):
        content = []

    texts: List[str] = []
    tool_calls: List[Dict[str, Any]] = []
    for block in content:
        if not isinstance(block, dict):
            continue
        btype = block.get("type")
        if btype == "text":
            chunk = block.get("text")
            if chunk:
                texts.append(chunk)
        elif btype == "tool_use":
            tool_calls.append({
                "id": block.get("id", ""),
                "name": block.get("name", ""),
                "input": block.get("input") if isinstance(block.get("input"), dict) else {},
            })

    usage = raw.get("usage")
    return _result(
        text="\n".join(texts),
        assistant_content=content,          # verbatim, for the agent to replay
        tool_calls=tool_calls,
        stop_reason=raw.get("stop_reason") or "",
        usage=usage if isinstance(usage, dict) else {},
        error="",
    )


def _read_http_error(exc: "urllib.error.HTTPError") -> str:
    """Pull a human-readable message out of an HTTPError body."""
    raw = ""
    try:
        data = exc.read()
        raw = data.decode("utf-8", "replace") if isinstance(
            data, (bytes, bytearray)) else str(data)
    except Exception:  # noqa: BLE001 - diagnostics must never raise
        return getattr(exc, "reason", "") or "http error"
    try:
        obj = json.loads(raw)
    except ValueError:
        return (raw[:500] or getattr(exc, "reason", "") or "http error")
    err = obj.get("error") if isinstance(obj, dict) else None
    if isinstance(err, dict) and err.get("message"):
        return str(err["message"])
    return raw[:500] or "http error"


def _retry_after_seconds(http_exc) -> Optional[float]:
    headers = getattr(http_exc, "headers", None)
    if headers is None:
        return None
    try:
        value = headers.get("retry-after")
    except Exception:  # noqa: BLE001
        return None
    if not value:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


__all__ = ["Brain"]
