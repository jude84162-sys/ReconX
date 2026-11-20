# modules/utils/crtsh.py
"""ReconX - Shared crt.sh (Certificate Transparency) lookup.

One query per domain per process: callers that ask for a domain while a
request for it is already in flight wait for that request instead of sending
their own, and a successful answer is cached for CACHE_TTL seconds. A failed
or timed-out lookup is handed to the callers already waiting but never cached.
"""

import concurrent.futures
import json
import logging
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request

logger = logging.getLogger("ReconX.crtsh")

CRTSH_URL = "https://crt.sh/"
USER_AGENT = "ReconX/1.0"
MAX_BODY = 20 * 1024 * 1024
CACHE_TTL = 600
CACHE_MAX = 64
RETRY_STATUSES = (502, 503)
RETRY_DELAY = 1.0
MIN_FALLBACK_TIME = 5.0

_lock = threading.Lock()
_inflight = {}
_cache = {}


def is_timeout(exc):
    """True for socket/read timeouts, including ones wrapped in a URLError."""
    if isinstance(exc, urllib.error.URLError) and not isinstance(exc, urllib.error.HTTPError):
        exc = exc.reason
    return isinstance(exc, (socket.timeout, TimeoutError))


def clear_cache():
    """Forget cached answers (in-flight requests are not affected)."""
    with _lock:
        _cache.clear()


def _normalize(domain):
    return (domain or "").strip().lower().rstrip(".")


def _names_from_json(data, domain):
    subs = set()
    suffix = "." + domain
    for entry in data:
        if not isinstance(entry, dict):
            continue
        for n in str(entry.get("name_value", "")).split("\n"):
            n = n.strip().lower()
            if n.endswith(suffix) and "*" not in n and n != domain:
                subs.add(n)
    return subs


def _names_from_text(text, domain):
    """Pull hostnames under ``domain`` out of HTML or (partial) JSON text."""
    subs = set()
    suffix = "." + domain
    pattern = r"([a-zA-Z0-9_\-\.]+\.%s)(?![a-zA-Z0-9\-])" % re.escape(domain)
    for match in re.finditer(pattern, text.replace("\\n", "\n"), re.IGNORECASE):
        sub = match.group(1).lower().strip(".")
        if sub != domain and "*" not in sub and sub.endswith(suffix):
            subs.add(sub)
    return subs


def _read_bounded(resp, max_bytes, deadline):
    """Read at most ``max_bytes``; returns (bytes, truncated)."""
    chunks = []
    total = 0
    while total <= max_bytes:
        if time.monotonic() > deadline:
            raise socket.timeout("crt.sh read deadline exceeded")
        chunk = resp.read(min(65536, max_bytes + 1 - total))
        if not chunk:
            return b"".join(chunks), False
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)[:max_bytes], True


def _http_get(url, timeout, max_bytes, deadline):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        body, truncated = _read_bounded(r, max_bytes, deadline)
    return body.decode("utf-8", errors="ignore"), truncated


def _describe(exc):
    if is_timeout(exc):
        return "timeout"
    if isinstance(exc, urllib.error.HTTPError):
        return "HTTP %s" % exc.code
    return str(exc) or exc.__class__.__name__


def _query(domain, timeout, max_bytes, budget):
    """One crt.sh lookup. Returns (subdomains, ok, error)."""
    deadline = time.monotonic() + budget

    def remaining():
        return deadline - time.monotonic()

    json_url = f"{CRTSH_URL}?q=%25.{domain}&output=json&deduplicate=Y"
    body = None
    truncated = False
    use_html = False
    error = None

    for attempt in (1, 2):
        started = time.monotonic()
        try:
            body, truncated = _http_get(json_url, min(timeout, max(remaining(), 1.0)),
                                        max_bytes, deadline)
            break
        except urllib.error.HTTPError as e:
            error = _describe(e)
            if e.code not in RETRY_STATUSES:
                return set(), False, error
            quick = time.monotonic() - started < timeout / 2.0
            if attempt == 1 and quick and remaining() > RETRY_DELAY + MIN_FALLBACK_TIME:
                time.sleep(RETRY_DELAY)
                continue
            if attempt == 1:
                return set(), False, error
            use_html = True
            break
        except Exception as e:
            return set(), False, _describe(e)

    if body is not None:
        try:
            data = json.loads(body)
        except ValueError:
            data = None
        if isinstance(data, list):
            return _names_from_json(data, domain), True, None
        if truncated:
            return _names_from_text(body, domain), True, None
        use_html = True
        error = "invalid JSON"

    if not use_html or remaining() < MIN_FALLBACK_TIME:
        return set(), False, error

    try:
        html, _ = _http_get(f"{CRTSH_URL}?q=%25.{domain}", min(timeout, remaining()),
                            max_bytes, deadline)
    except Exception as e:
        return set(), False, "HTML fallback: " + _describe(e)
    subs = _names_from_text(html, domain)
    return subs, bool(subs), None if subs else error


def _trim_cache():
    while len(_cache) > CACHE_MAX:
        oldest = min(_cache, key=lambda k: _cache[k][0])
        _cache.pop(oldest, None)


def crtsh_lookup(domain, timeout=30, max_bytes=MAX_BODY, budget=None, use_cache=True):
    """Subdomains of ``domain`` seen in crt.sh certificate logs (a new set).

    ``timeout`` is the per-request socket timeout and ``budget`` (default
    ``timeout + 20``) bounds the whole lookup including one quick retry on
    HTTP 502/503 and the HTML fallback. A timeout is never followed by the
    HTML query. Concurrent calls for the same domain share one request;
    ``use_cache=False`` skips the cached answer but still shares in-flight
    requests. Never raises: a failed lookup returns an empty set.
    """
    key = _normalize(domain)
    if not key:
        return set()
    if budget is None:
        budget = timeout + 20

    with _lock:
        hit = _cache.get(key) if use_cache else None
        if hit is not None and time.monotonic() - hit[0] < CACHE_TTL:
            return set(hit[1])
        future = _inflight.get(key)
        owner = future is None
        if owner:
            future = concurrent.futures.Future()
            _inflight[key] = future

    if not owner:
        try:
            return set(future.result(timeout=budget + 10))
        except Exception:
            return set()

    subs, ok = set(), False
    try:
        subs, ok, error = _query(key, timeout, max_bytes, budget)
        if not ok:
            logger.debug(f"crt.sh lookup for {key} failed: {error}")
    except Exception as e:
        logger.debug(f"crt.sh lookup for {key} failed: {e}")
    finally:
        frozen = frozenset(subs)
        with _lock:
            _inflight.pop(key, None)
            if ok:
                _cache[key] = (time.monotonic(), frozen)
                _trim_cache()
        future.set_result(frozen)
    return set(frozen)
