# modules/utils/http_client.py
"""ReconX - Shared HTTP engine.

Provides three things the advanced scanners build on:

  * ``request()``          - small stdlib HTTP wrapper returning a Response object
  * ``compare_responses()`` - semantic/differential response analysis
  * ``adaptive_request()``  - payload mutation when a WAF blocks the plain request

Zero external dependencies (stdlib only), TLS verification disabled on purpose:
these scanners run against targets that frequently use self-signed certificates.

Connections are kept alive and reused per worker thread. Set the environment
variable ``RECONX_NO_KEEPALIVE=1`` to open a new connection for every request.
"""

import base64
import collections
import difflib
import hashlib
import http.client
import json
import os
import random
import re
import select
import socket
import ssl
import string
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import weakref

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

DEFAULT_HEADERS = {
    "User-Agent": DEFAULT_UA,
    "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

MAX_BODY = 500_000


class Response:
    """Minimal response object shared by every scanner."""

    def __init__(self, url, status=None, headers=None, body="", elapsed=0.0,
                 error=None, final_url=None, cookies=None):
        self.url = url
        self.status = status
        self.headers = headers or {}
        self.body = body or ""
        self.elapsed = elapsed
        self.error = error
        self.final_url = final_url or url
        self.cookies = cookies or []

    @property
    def ok(self):
        return self.error is None and self.status is not None and 200 <= self.status < 400

    def header(self, name, default=""):
        return self.headers.get(name.lower(), default)

    def json(self):
        try:
            return json.loads(self.body)
        except Exception:
            return None

    def __repr__(self):
        if self.error:
            return f"<Response error={self.error[:60]!r}>"
        return f"<Response {self.status} {len(self.body)}b {self.url[:60]}>"


def _ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# ============================================================
# Keep-alive connection pool (one set of connections per thread)
# ============================================================

NO_KEEPALIVE_ENV = "RECONX_NO_KEEPALIVE"
POOL_MAX_PER_THREAD = 16

# Errors that mean a reused keep-alive socket had already been closed by the
# server; the request is sent once more on a fresh connection.
_STALE_ERRORS = (http.client.BadStatusLine, BrokenPipeError, ConnectionResetError,
                 ConnectionAbortedError, ssl.SSLEOFError, ssl.SSLZeroReturnError)


def keepalive_enabled():
    """False when ``RECONX_NO_KEEPALIVE`` is set to a true value."""
    value = os.environ.get(NO_KEEPALIVE_ENV, "").strip().lower()
    return value not in ("1", "true", "yes", "on")


def _close_all(conns):
    while conns:
        _, conn = conns.popitem()
        try:
            conn.close()
        except Exception:
            pass


class _ThreadConnections:
    """Per-thread pool; its connections are closed when the thread exits."""

    def __init__(self):
        self.conns = collections.OrderedDict()
        weakref.finalize(self, _close_all, self.conns)


_LOCAL = threading.local()


def _thread_connections():
    holder = getattr(_LOCAL, "holder", None)
    if holder is None:
        holder = _LOCAL.holder = _ThreadConnections()
    return holder.conns


def close_connections():
    """Close every keep-alive connection held by the calling thread."""
    _close_all(_thread_connections())


class _PooledResponse(http.client.HTTPResponse):
    """HTTPResponse that knows whether its body was read to the end.

    A keep-alive connection is only reused after the previous response on it
    was fully consumed; closing it early leaves unread bytes on the socket, so
    the connection is dropped instead.
    """

    _reconx_aborted = False
    _reconx_conn = None
    _reconx_sock = None

    def _reconx_complete(self):
        return self.fp is None and not self._reconx_aborted

    def close(self):
        if self.fp is None:
            super().close()
            return
        self._reconx_aborted = True
        try:
            super().close()
        finally:
            ref = self._reconx_conn
            conn = ref() if ref is not None else None
            if (conn is not None and conn.sock is not None
                    and conn.sock is self._reconx_sock
                    and getattr(conn, "_reconx_last", None) is self):
                try:
                    conn.close()
                except Exception:
                    pass


def _sock_timeout(timeout):
    if timeout is socket._GLOBAL_DEFAULT_TIMEOUT:
        return socket.getdefaulttimeout()
    return timeout


def _sock_dropped(sock):
    """True when an idle socket was closed by the peer (or has stray data)."""
    try:
        if sock.fileno() < 0:
            return True
        pending = getattr(sock, "pending", None)
        if pending is not None and pending():
            return True
        if hasattr(select, "poll"):
            poller = select.poll()
            poller.register(sock, select.POLLIN | select.POLLPRI)
            return bool(poller.poll(0))
        readable, _, _ = select.select([sock], [], [], 0)
        return bool(readable)
    except (OSError, ValueError):
        return True


def _is_stale(exc):
    if isinstance(exc, urllib.error.URLError) and isinstance(exc.reason, BaseException):
        exc = exc.reason
    return isinstance(exc, _STALE_ERRORS)


def _checkout(key, http_class, host, timeout, conn_args, debuglevel):
    """Return ``(connection, reused)`` for this thread."""
    conns = _thread_connections()
    conn = conns.get(key)
    reused = False
    if conn is None:
        conn = http_class(host, timeout=timeout, **conn_args)
        conn.response_class = _PooledResponse
        conns[key] = conn
        while len(conns) > POOL_MAX_PER_THREAD:
            _, old = conns.popitem(last=False)
            try:
                old.close()
            except Exception:
                pass
    else:
        conns.move_to_end(key)
        conn.timeout = timeout
        if conn.sock is not None:
            last = getattr(conn, "_reconx_last", None)
            if (last is not None and last._reconx_complete()
                    and not _sock_dropped(conn.sock)):
                try:
                    conn.sock.settimeout(_sock_timeout(timeout))
                    reused = True
                except OSError:
                    conn.close()
            else:
                conn.close()
    conn.set_debuglevel(debuglevel)
    return conn, reused


class _KeepAliveMixin:
    """urllib handler that sends requests over pooled keep-alive connections.

    Proxied requests (env HTTP(S)_PROXY) take urllib's normal one-shot path.
    """

    def do_open(self, http_class, req, **http_conn_args):
        if req._tunnel_host or req.has_proxy():
            return super().do_open(http_class, req, **http_conn_args)
        host = req.host
        if not host:
            raise urllib.error.URLError("no host given")

        headers = dict(req.unredirected_hdrs)
        headers.update({k: v for k, v in req.headers.items() if k not in headers})
        headers = {name.title(): val for name, val in headers.items()}

        key = (http_class, host, id(http_conn_args.get("context")))
        replayable = req.data is None or isinstance(req.data, (bytes, bytearray))
        debuglevel = getattr(self, "_debuglevel", 0)
        retried = False
        while True:
            conn, reused = _checkout(key, http_class, host, req.timeout,
                                     http_conn_args, debuglevel)
            try:
                try:
                    conn.request(req.get_method(), req.selector, req.data, headers,
                                 encode_chunked=req.has_header("Transfer-encoding"))
                except OSError as err:
                    raise urllib.error.URLError(err)
                r = conn.getresponse()
            except BaseException as exc:
                conn.close()
                if reused and replayable and not retried and _is_stale(exc):
                    retried = True
                    continue
                raise
            break

        r._reconx_conn = weakref.ref(conn)
        r._reconx_sock = conn.sock
        conn._reconx_last = r
        r.url = req.get_full_url()
        r.msg = r.reason
        return r


class _KeepAliveHTTPHandler(_KeepAliveMixin, urllib.request.HTTPHandler):
    pass


class _KeepAliveHTTPSHandler(_KeepAliveMixin, urllib.request.HTTPSHandler):
    pass


_OPENERS = {}


def _opener(allow_redirects, keepalive=None):
    if keepalive is None:
        keepalive = keepalive_enabled()
    key = (bool(allow_redirects), bool(keepalive))
    if key not in _OPENERS:
        if keepalive:
            handlers = [_KeepAliveHTTPHandler(),
                        _KeepAliveHTTPSHandler(context=_ssl_context())]
        else:
            handlers = [urllib.request.HTTPSHandler(context=_ssl_context())]
        if not allow_redirects:
            handlers.insert(0, _NoRedirect())
        _OPENERS[key] = urllib.request.build_opener(*handlers)
    return _OPENERS[key]


def open_request(req, timeout=10, allow_redirects=True):
    """Open a ``urllib.request.Request`` through the shared keep-alive opener.

    Behaves like ``urllib.request.urlopen`` with TLS verification disabled:
    redirects are followed (unless ``allow_redirects`` is False), environment
    proxies are honoured and 4xx/5xx raise ``urllib.error.HTTPError``.
    """
    return _opener(allow_redirects).open(req, timeout=timeout)


def request(url, method="GET", headers=None, data=None, timeout=10,
            allow_redirects=True):
    """Perform one HTTP request and return a :class:`Response`.

    ``data`` may be bytes, str or dict (dict is sent as JSON).
    """
    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url

    hdrs = dict(DEFAULT_HEADERS)
    if headers:
        hdrs.update({k: v for k, v in headers.items() if v is not None})

    if isinstance(data, (dict, list)):
        data = json.dumps(data).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    elif isinstance(data, str):
        data = data.encode("utf-8")

    req = urllib.request.Request(url, data=data, headers=hdrs, method=method.upper())
    started = time.time()
    try:
        with _opener(allow_redirects).open(req, timeout=timeout) as r:
            raw = r.read(MAX_BODY)
            return Response(
                url=url,
                status=r.status,
                headers={k.lower(): v for k, v in r.headers.items()},
                body=raw.decode("utf-8", errors="ignore"),
                elapsed=time.time() - started,
                final_url=r.url,
                cookies=r.headers.get_all("Set-Cookie") or [],
            )
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(MAX_BODY)
        except Exception:
            raw = b""
        try:
            e.close()
        except Exception:
            pass
        return Response(
            url=url,
            status=e.code,
            headers={k.lower(): v for k, v in (e.headers.items() if e.headers else [])},
            body=raw.decode("utf-8", errors="ignore"),
            elapsed=time.time() - started,
            final_url=url,
            cookies=(e.headers.get_all("Set-Cookie") if e.headers else []) or [],
        )
    except Exception as e:
        return Response(url=url, error=f"{type(e).__name__}: {e}",
                        elapsed=time.time() - started)


# ============================================================
# URL helpers
# ============================================================

def normalize_url(url, scheme="https"):
    url = (url or "").strip()
    if not url:
        return url
    if not url.lower().startswith(("http://", "https://")):
        url = f"{scheme}://{url.lstrip('/')}"
    return url


def query_params(url):
    """Return parameter names present in a URL query string."""
    return [k for k, _ in urllib.parse.parse_qsl(urllib.parse.urlparse(url).query,
                                                 keep_blank_values=True)]


def with_params(url, values):
    """Return ``url`` with ``values`` merged into the query string (replace)."""
    parsed = urllib.parse.urlparse(url)
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    merged, replaced = [], set()
    for k, v in pairs:
        if k in values:
            if k in replaced:
                continue
            merged.append((k, values[k]))
            replaced.add(k)
        else:
            merged.append((k, v))
    for k, v in values.items():
        if k not in replaced:
            merged.append((k, v))
    query = urllib.parse.urlencode(merged, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=query))


def base_url(url):
    parsed = urllib.parse.urlparse(normalize_url(url))
    return f"{parsed.scheme}://{parsed.netloc}"


def join_url(url, path):
    """Join a base and a path without doubling slashes."""
    if path.lower().startswith(("http://", "https://")):
        return path
    return base_url(url).rstrip("/") + "/" + path.lstrip("/")


def random_token(length=8):
    return "".join(random.choice(string.ascii_lowercase + string.digits)
                   for _ in range(length))


# ============================================================
# Differential / semantic response analysis
# ============================================================

_SCRIPT_STYLE_RE = re.compile(r"(?is)<(script|style)\b.*?</\1>")
_TAG_RE = re.compile(r"(?s)<[^>]+>")
_NOISE_RE = re.compile(r"(?i)\b[0-9a-f]{8,}\b|\d+")
_WS_RE = re.compile(r"\s+")


def _visible_text(body):
    if not body:
        return ""
    text = _SCRIPT_STYLE_RE.sub(" ", body)
    text = _TAG_RE.sub(" ", text)
    text = _WS_RE.sub(" ", text).strip().lower()
    return text


def _normalize(body):
    # Numbers and hex tokens are the usual source of random noise in responses
    # (CSRF tokens, timestamps, request ids); blank them before comparing.
    return _NOISE_RE.sub("#", _visible_text(body))[:30000]


def text_similarity(a, b):
    """0..1 similarity between two response bodies (1 = identical)."""
    na, nb = _normalize(a), _normalize(b)
    if not na and not nb:
        return 1.0
    return difflib.SequenceMatcher(None, na, nb).ratio()


def dom_signature(body):
    """Structural fingerprint: tag histogram + text length."""
    tags = [t.lower() for t in re.findall(r"<([a-zA-Z][a-zA-Z0-9]*)", body or "")]
    return {
        "length": len(body or ""),
        "tags": len(tags),
        "distinct_tags": sorted(set(tags))[:40],
        "text_len": len(_visible_text(body)),
        "hash": hashlib.sha256(_normalize(body).encode()).hexdigest()[:16],
    }


def compare_responses(baseline, test, marker=None):
    """Compare a test response against a baseline.

    Returns a dict with status/length/similarity/structure deltas and whether
    ``marker`` (a unique injected token) was reflected.
    """
    if baseline is None or test is None:
        return {"error": "missing response"}

    sig_a, sig_b = dom_signature(baseline.body), dom_signature(test.body)
    sim = text_similarity(baseline.body, test.body)
    length_ratio = (len(test.body) / len(baseline.body)) if baseline.body else 0.0
    tag_union = set(sig_a["distinct_tags"]) | set(sig_b["distinct_tags"])
    shared = set(sig_a["distinct_tags"]) & set(sig_b["distinct_tags"])

    return {
        "baseline_status": baseline.status,
        "status": test.status,
        "status_changed": baseline.status != test.status,
        "baseline_length": len(baseline.body),
        "length": len(test.body),
        "length_delta": len(test.body) - len(baseline.body),
        "length_ratio": length_ratio,
        "similarity": round(sim, 3),
        "structure_changed": sig_a["hash"] != sig_b["hash"],
        "structure_similarity": round(len(shared) / len(tag_union), 3) if tag_union else 1.0,
        "reflected": bool(marker) and marker in (test.body or ""),
        "baseline_error": baseline.error,
        "error": test.error,
    }


def is_meaningful_change(diff, min_similarity_delta=0.05, length_tolerance=0.10):
    """True when a diff is larger than normal response noise."""
    if diff.get("error") or diff.get("baseline_error"):
        return False
    if diff.get("status_changed"):
        return True
    if diff.get("similarity", 1.0) <= 1.0 - min_similarity_delta:
        return True
    ratio = diff.get("length_ratio", 1.0)
    if ratio and abs(ratio - 1.0) > length_tolerance:
        return True
    return False


# ============================================================
# WAF evasion / payload mutation engine
# ============================================================

WAF_BLOCK_MARKERS = [
    "access denied", "request blocked", "request rejected", "web application firewall",
    "cloudflare", "attention required", "incapsula", "sucuri", "mod_security",
    "modsecurity", "not acceptable", "security violation", "blocked by",
    "your request has been blocked", "the requested url was rejected", "akamai",
    "imperva", "barracuda", "fortiweb", "aws waf", "bad request: suspicious",
]

BLOCK_STATUSES = {403, 406, 429, 501, 503}


def is_blocked(resp):
    """Heuristic: did a WAF/proxy reject this request?"""
    if resp is None or resp.error:
        return False
    if resp.status in BLOCK_STATUSES:
        return True
    body = (resp.body or "").lower()
    return any(m in body for m in WAF_BLOCK_MARKERS)


def _mut_url(payload):
    return urllib.parse.quote(payload, safe="")


def _mut_double_url(payload):
    return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")


def _mut_hex(payload):
    return "".join("%{:02x}".format(b) for b in payload.encode("utf-8"))


def _mut_unicode(payload):
    return "".join(c if c.isalnum() else "\\u%04x" % ord(c) for c in payload)


def _mut_html_entity(payload):
    return "".join("&#x%x;" % ord(c) for c in payload)


def _mut_case(payload):
    return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload))


def _mut_comment_split(payload):
    return re.sub(r"\s+", "/**/", payload)


def _mut_null_byte(payload):
    return payload + "%00"


def _mut_overlong(payload):
    # IIS-style UTF-8 overlong encoding of the first character.
    if not payload:
        return payload
    first = "%c0%af" if payload[0] == "/" else "%%%02x" % (ord(payload[0]) + 0x80)
    return first + urllib.parse.quote(payload[1:], safe="")


def _mut_base64(payload):
    return base64.b64encode(payload.encode()).decode()


MUTATORS = [
    ("url", _mut_url),
    ("double_url", _mut_double_url),
    ("hex", _mut_hex),
    ("unicode", _mut_unicode),
    ("html_entity", _mut_html_entity),
    ("case_swap", _mut_case),
    ("comment_split", _mut_comment_split),
    ("null_byte", _mut_null_byte),
    ("overlong_utf8", _mut_overlong),
]


def mutations(payload, limit=6):
    """Yield (name, mutated_payload) variants, deduplicated."""
    seen = {payload}
    out = []
    for name, fn in MUTATORS:
        try:
            value = fn(payload)
        except Exception:
            continue
        if value and value not in seen:
            seen.add(value)
            out.append((name, value))
        if len(out) >= limit:
            break
    return out


def adaptive_request(send, payload, limit=4):
    """Send ``payload``; if blocked, retry with WAF-evasion mutations.

    ``send`` is a callable taking a payload value and returning a Response.
    Returns ``(payload_used, response, mutation_name)``.
    """
    response = send(payload)
    if not is_blocked(response):
        return payload, response, "plain"

    for name, mutated in mutations(payload, limit=limit):
        candidate = send(mutated)
        if candidate.error is None and not is_blocked(candidate):
            return mutated, candidate, name
        if candidate.error is None and candidate.status not in BLOCK_STATUSES:
            return mutated, candidate, name
    return payload, response, "blocked"


# ============================================================
# Misc
# ============================================================

def body_has_any(body, needles):
    body = (body or "").lower()
    return [n for n in needles if n.lower() in body]


def decode_cookie_map(cookies):
    """Cookie header strings -> {name: value}."""
    jar = {}
    for raw in cookies or []:
        first = raw.split(";", 1)[0]
        if "=" in first:
            k, v = first.split("=", 1)
            jar[k.strip()] = v.strip()
    return jar
