"""Dependency-free HTTP client (stdlib urllib) with optional `requests` upgrade.

Keeps the whole suite installable with zero pip packages, matching ReconX's
"zero mandatory external tools" design. If `requests` happens to be present it is
NOT required; urllib covers everything we need (custom headers, no-follow
redirects, timing, raw body).
"""
from __future__ import annotations

import ssl
import time
import gzip
import zlib
import socket
import urllib.request
import urllib.parse
import urllib.error
from dataclasses import dataclass, field
from typing import Optional

DEFAULT_UA = "ReconX-GUI/1.0 (+authorized-security-testing)"
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE  # recon tools routinely hit hosts with bad certs


@dataclass
class Response:
    url: str
    status: int
    headers: dict = field(default_factory=dict)
    body: str = ""
    raw: bytes = b""
    elapsed_ms: int = 0
    final_url: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    def header(self, name: str, default: str = "") -> str:
        name = name.lower()
        for k, v in self.headers.items():
            if k.lower() == name:
                return v
        return default


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _decode_body(raw: bytes, headers: dict) -> str:
    enc = ""
    for k, v in headers.items():
        if k.lower() == "content-encoding":
            enc = v.lower()
    try:
        if "gzip" in enc:
            raw = gzip.decompress(raw)
        elif "deflate" in enc:
            raw = zlib.decompress(raw)
    except Exception:
        pass
    for cs in ("utf-8", "latin-1"):
        try:
            return raw.decode(cs, errors="replace")
        except Exception:
            continue
    return raw.decode("utf-8", errors="replace")


def request(
    url: str,
    method: str = "GET",
    headers: Optional[dict] = None,
    data=None,
    timeout: float = 12.0,
    allow_redirects: bool = True,
    max_bytes: int = 600_000,
) -> Response:
    if "://" not in url:
        url = "http://" + url
    hdrs = {"User-Agent": DEFAULT_UA, "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate", "Connection": "close"}
    if headers:
        hdrs.update(headers)

    body_bytes = None
    if data is not None:
        if isinstance(data, dict):
            body_bytes = urllib.parse.urlencode(data).encode()
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif isinstance(data, str):
            body_bytes = data.encode()
        else:
            body_bytes = data

    handlers = [urllib.request.HTTPSHandler(context=_CTX)]
    if not allow_redirects:
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)

    req = urllib.request.Request(url, data=body_bytes, headers=hdrs,
                                 method=method.upper())
    t0 = time.time()
    try:
        with opener.open(req, timeout=timeout) as r:
            raw = r.read(max_bytes)
            rh = {k: v for k, v in r.headers.items()}
            return Response(url=url, status=r.status, headers=rh,
                            body=_decode_body(raw, rh), raw=raw,
                            elapsed_ms=int((time.time() - t0) * 1000),
                            final_url=r.geturl())
    except urllib.error.HTTPError as e:
        raw = b""
        try:
            raw = e.read(max_bytes)
        except Exception:
            pass
        rh = {k: v for k, v in (e.headers or {}).items()}
        return Response(url=url, status=e.code, headers=rh,
                        body=_decode_body(raw, rh), raw=raw,
                        elapsed_ms=int((time.time() - t0) * 1000),
                        final_url=url)
    except (urllib.error.URLError, socket.timeout, ssl.SSLError,
            ConnectionError, OSError) as e:
        return Response(url=url, status=0,
                        elapsed_ms=int((time.time() - t0) * 1000),
                        error=str(getattr(e, "reason", e)))
    except Exception as e:  # noqa
        return Response(url=url, status=0, error=f"{type(e).__name__}: {e}")


def normalize_url(target: str) -> str:
    target = (target or "").strip()
    if not target:
        return ""
    if "://" not in target:
        target = "https://" + target
    return target


def host_of(target: str) -> str:
    target = normalize_url(target)
    try:
        return urllib.parse.urlparse(target).hostname or ""
    except Exception:
        return ""
