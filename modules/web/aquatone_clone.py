# modules/web/aquatone_clone.py
"""ReconX - Screenshot Gallery (Aquatone-style, no external tools required).

Takes screenshots of live web hosts and writes a browsable HTML gallery,
the same workflow as Aquatone:

    live probe -> capture page -> outputs/screenshots/<host>.png + index.html

Backends (auto-detected, first available wins):
  1. Playwright + Chromium  (pip install playwright && playwright install chromium)
  2. Any installed Chrome / Chromium / Edge via headless CLI

Bare hostnames are probed first (modules.web.live_probe), so dead subdomains
are skipped instead of producing blank images.
"""

import base64
import html
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import concurrent.futures
from datetime import datetime
from pathlib import Path

from modules.web import live_probe

C_GREEN = "\033[92m"
C_GRAY = "\033[90m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_RST = "\033[0m"

UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

CHROME_NAMES = [
    "google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
    "chrome", "microsoft-edge", "msedge", "brave-browser",
]


# ============================================================
# Backend detection
# ============================================================

def find_chrome():
    """Locate a Chrome/Chromium/Edge binary, or None."""
    env = os.environ.get("CHROME_PATH") or os.environ.get("CHROMIUM_PATH")
    if env and Path(env).exists():
        return env

    for name in CHROME_NAMES:
        path = shutil.which(name)
        if path:
            return path

    candidates = []
    if os.name == "nt":
        for base in (os.environ.get("PROGRAMFILES"),
                     os.environ.get("PROGRAMFILES(X86)"),
                     os.environ.get("LOCALAPPDATA")):
            if not base:
                continue
            candidates += [
                os.path.join(base, "Google", "Chrome", "Application", "chrome.exe"),
                os.path.join(base, "Microsoft", "Edge", "Application", "msedge.exe"),
                os.path.join(base, "Chromium", "Application", "chrome.exe"),
            ]
    else:
        candidates += [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            "/usr/bin/google-chrome",
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/data/data/com.termux/files/usr/bin/chromium-browser",
        ]

    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def has_playwright():
    import importlib.util
    return importlib.util.find_spec("playwright") is not None


def screenshot_backend(preferred=None):
    """Return 'playwright', 'chrome' or None."""
    if preferred == "chrome":
        return "chrome" if find_chrome() else None
    if preferred == "playwright":
        return "playwright" if has_playwright() else None
    if has_playwright():
        return "playwright"
    if find_chrome():
        return "chrome"
    return None


def is_screenshot_available():
    return screenshot_backend() is not None


def backend_hint():
    backend = screenshot_backend()
    if backend == "playwright":
        return "Playwright Chromium"
    if backend == "chrome":
        return f"headless Chrome ({find_chrome()})"
    return ("no browser found — install Playwright (pip install playwright && "
            "playwright install chromium) or Chrome/Chromium")


# ============================================================
# Targets
# ============================================================

def _dedupe(targets):
    seen = set()
    out = []
    for t in targets or []:
        host = live_probe.normalize_host(t)
        if host and host.lower() not in seen:
            seen.add(host.lower())
            out.append(host)
    return out


def _safe_name(value):
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", value or "host").strip("._-")
    return (name or "host")[:80]


def _prepare_jobs(targets, timeout, verbose):
    """Resolve each target to a live URL; dead hosts get a skipped entry."""
    prepared, skipped = [], []

    for target in _dedupe(targets):
        if "://" in target:
            url = target
            probe = None
        else:
            probe = live_probe.probe_host(target, timeout=min(timeout, 8))
            if not probe.get("alive"):
                reason = (probe.get("errors") or ["no HTTP(S) response"])[-1]
                skipped.append({
                    "input": target,
                    "status": "skipped",
                    "url": None,
                    "title": None,
                    "screenshot": None,
                    "error": reason,
                })
                if verbose:
                    print(f"      {C_GRAY}·{C_RST} {target:<50} not alive")
                continue
            url = probe.get("final_url") or probe.get("url")

        netloc = urllib.parse.urlsplit(url).netloc or target
        prepared.append({
            "input": target,
            "host": netloc,
            "url": url,
            "title": (probe or {}).get("title"),
        })

    return prepared, skipped


# ============================================================
# Auth input (cookies / headers)
# ============================================================

def _normalize_headers(headers):
    """Accept {'Name': 'value'} or ['Name: value', ...] -> dict."""
    if not headers:
        return {}
    if isinstance(headers, dict):
        items = headers.items()
    else:
        items = []
        for raw in headers:
            if isinstance(raw, dict):
                items.extend(raw.items())
                continue
            if ":" not in str(raw):
                raise ValueError(f"header must look like 'Name: value' ({raw!r})")
            name, value = str(raw).split(":", 1)
            items.append((name, value))

    clean = {}
    for name, value in items:
        name = str(name).strip()
        value = str(value).strip()
        if not name:
            raise ValueError("header name is empty")
        if any(ch in name for ch in "\r\n:") or any(ch in value for ch in "\r\n"):
            raise ValueError(f"invalid characters in header {name!r}")
        clean[name] = value
    return clean


def _normalize_cookies(cookies):
    """Accept 'a=1; b=2' or [{'name','value'}, ...] -> list of pairs."""
    if not cookies:
        return []
    if isinstance(cookies, (list, tuple)):
        parsed = []
        for item in cookies:
            if isinstance(item, dict):
                name = str(item.get("name", "")).strip()
                value = str(item.get("value", ""))
                if not name:
                    raise ValueError("cookie name is empty")
                parsed.append({"name": name, "value": value})
            else:
                parsed.extend(_normalize_cookies(item))
        return parsed

    parsed = []
    for chunk in str(cookies).split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "=" not in chunk:
            raise ValueError(f"cookie must look like 'name=value' ({chunk!r})")
        name, value = chunk.split("=", 1)
        name, value = name.strip(), value.strip()
        if not name:
            raise ValueError(f"cookie has an empty name ({chunk!r})")
        if any(ch in value for ch in "\r\n"):
            raise ValueError(f"invalid characters in cookie {name!r}")
        parsed.append({"name": name, "value": value})
    return parsed


def _auth_summary(headers, cookies):
    """Names only — never persist or print secret values."""
    if not headers and not cookies:
        return None
    return {
        "headers": sorted(headers or {}),
        "cookies": [c["name"] for c in (cookies or [])],
    }


# ============================================================
# Captures
# ============================================================

def _capture_playwright(jobs, width, height, timeout, full_page, verbose,
                        headers=None, cookies=None):
    from playwright.sync_api import sync_playwright

    done = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            ignore_https_errors=True,
            user_agent=UA,
            viewport={"width": width, "height": height},
            extra_http_headers=headers or {},
        )
        for job in jobs:
            page = context.new_page()
            try:
                if cookies:
                    context.add_cookies([
                        {"name": c["name"], "value": c["value"], "url": job["url"]}
                        for c in cookies
                    ])
                resp = page.goto(job["url"], wait_until="domcontentloaded",
                                 timeout=timeout * 1000)
                try:
                    page.wait_for_timeout(1500)
                except Exception:
                    pass
                page.screenshot(path=str(job["path"]), full_page=full_page)
                job["status"] = "captured"
                job["status_code"] = resp.status if resp else None
                if not job.get("title"):
                    try:
                        job["title"] = (page.title() or "").strip()[:120] or None
                    except Exception:
                        pass
                if verbose:
                    print(f"      {C_GREEN}✓{C_RST} {job['url']}")
            except Exception as e:
                job["status"] = "failed"
                job["error"] = str(e)[:160]
                if verbose:
                    print(f"      {C_RED}✗{C_RST} {job['url']} — {job['error'][:70]}")
            finally:
                try:
                    page.close()
                except Exception:
                    pass
            done.append(job)
        browser.close()
    return done


def _chrome_once(chrome, job, width, height, timeout):
    profile = tempfile.mkdtemp(prefix="reconx-shot-")
    # Chrome silently fails on a relative --screenshot path (Windows in particular)
    shot_path = Path(job["path"]).resolve().as_posix()
    cmd = [
        chrome,
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--hide-scrollbars",
        "--mute-audio",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-sync",
        "--disable-extensions",
        f"--user-data-dir={profile}",
        f"--window-size={width},{height}",
        "--virtual-time-budget=6000",
        f"--screenshot={shot_path}",
        job["url"],
    ]
    try:
        subprocess.run(cmd, capture_output=True, timeout=timeout + 20)
        if not job["path"].exists() or job["path"].stat().st_size == 0:
            # Older Chrome builds do not understand --headless=new
            cmd[1] = "--headless"
            subprocess.run(cmd, capture_output=True, timeout=timeout + 20)
    finally:
        shutil.rmtree(profile, ignore_errors=True)


# ------------------------------------------------------------
# Chrome + DevTools Protocol (used for authenticated captures:
# the CLI has no cookie/header flags, and secrets stay out of argv)
# ------------------------------------------------------------

class _CdpError(RuntimeError):
    pass


class _Cdp:
    """Tiny Chrome DevTools Protocol client over a raw websocket (stdlib only)."""

    def __init__(self, ws_url, timeout=15):
        parts = urllib.parse.urlsplit(ws_url)
        if parts.scheme != "ws" or not parts.hostname:
            raise _CdpError(f"unsupported DevTools URL: {ws_url}")
        host, port = parts.hostname, parts.port or 80
        path = parts.path + (("?" + parts.query) if parts.query else "")

        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(request.encode())

        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise _CdpError("DevTools closed the connection during handshake")
            raw += chunk
        head, rest = raw.split(b"\r\n\r\n", 1)
        if b" 101 " not in head.split(b"\r\n", 1)[0]:
            raise _CdpError("DevTools websocket handshake failed")

        self._buf = rest
        self._next_id = 0
        self.events = {}

    # --- websocket framing ---
    def _read_exact(self, size, deadline):
        while len(self._buf) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _CdpError("timed out waiting for the browser")
            self.sock.settimeout(max(0.05, min(remaining, 5)))
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                raise _CdpError("browser closed the DevTools connection")
            self._buf += chunk
        data, self._buf = self._buf[:size], self._buf[size:]
        return data

    def _read_frame(self, deadline):
        first, second = self._read_exact(2, deadline)
        opcode = first & 0x0F
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", self._read_exact(2, deadline))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._read_exact(8, deadline))[0]
        mask = self._read_exact(4, deadline) if second & 0x80 else None
        payload = self._read_exact(length, deadline) if length else b""
        if mask:
            payload = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
        return opcode, payload

    def _send_frame(self, payload, opcode=0x1):
        header = bytearray([0x80 | opcode])
        length = len(payload)
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header += struct.pack("!H", length)
        else:
            header.append(0x80 | 127)
            header += struct.pack("!Q", length)
        mask = os.urandom(4)
        header += mask
        body = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
        self.sock.sendall(bytes(header) + body)

    def _next_message(self, deadline):
        while True:
            opcode, payload = self._read_frame(deadline)
            if opcode == 0x8:
                raise _CdpError("browser closed the DevTools session")
            if opcode == 0x9:
                self._send_frame(payload, opcode=0xA)
                continue
            if opcode not in (0x1, 0x2):
                continue
            try:
                return json.loads(payload.decode("utf-8", "replace"))
            except ValueError:
                continue

    def send(self, method, params=None):
        self._next_id += 1
        message = {"id": self._next_id, "method": method, "params": params or {}}
        self._send_frame(json.dumps(message).encode())
        return self._next_id

    def wait(self, msg_id, timeout=15):
        deadline = time.monotonic() + timeout
        while True:
            message = self._next_message(deadline)
            if "method" in message:
                self.events.setdefault(message["method"], message.get("params", {}))
                continue
            if message.get("id") == msg_id:
                if "error" in message:
                    raise _CdpError(message["error"].get("message") or "DevTools error")
                return message.get("result", {})

    def call(self, method, params=None, timeout=15):
        return self.wait(self.send(method, params), timeout=timeout)

    def wait_event(self, name, timeout=15):
        deadline = time.monotonic() + timeout
        if name in self.events:
            return self.events.pop(name)
        while True:
            message = self._next_message(deadline)
            if "method" in message:
                self.events.setdefault(message["method"], message.get("params", {}))
                if name in self.events:
                    return self.events.pop(name)

    def close(self):
        try:
            self._send_frame(b"", opcode=0x8)
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass


def _start_chrome_for_cdp(chrome, width, height):
    profile = tempfile.mkdtemp(prefix="reconx-shot-")
    cmd = [
        chrome,
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--hide-scrollbars",
        "--mute-audio",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-sync",
        "--disable-extensions",
        "--remote-debugging-port=0",
        "--remote-allow-origins=*",
        f"--user-data-dir={profile}",
        f"--window-size={width},{height}",
        "about:blank",
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    port_file = Path(profile) / "DevToolsActivePort"
    deadline = time.monotonic() + 20
    port = None
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        try:
            first = port_file.read_text(errors="ignore").splitlines()[0].strip()
            if first.isdigit():
                port = int(first)
                break
        except (OSError, IndexError):
            pass
        time.sleep(0.1)

    if port is None:
        _stop_chrome(proc, profile)
        raise _CdpError("headless Chrome did not expose a DevTools port")
    return proc, profile, port


def _stop_chrome(proc, profile):
    if proc is not None and proc.poll() is None:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
    shutil.rmtree(profile, ignore_errors=True)


def _devtools_page(port, timeout=10):
    url = f"http://127.0.0.1:{port}/json/list"
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as resp:
                targets = json.loads(resp.read().decode("utf-8", "replace"))
            for target in targets:
                if target.get("type") == "page" and target.get("webSocketDebuggerUrl"):
                    return target["webSocketDebuggerUrl"]
        except Exception as e:  # browser still starting up
            last = e
        time.sleep(0.15)
    raise _CdpError(f"DevTools endpoint unavailable: {last}")


def _cdp_capture(chrome, job, width, height, timeout, full_page, headers, cookies):
    """Capture one page with cookies/headers via the DevTools Protocol."""
    proc = None
    profile = None
    cdp = None
    try:
        proc, profile, port = _start_chrome_for_cdp(chrome, width, height)
        cdp = _Cdp(_devtools_page(port, timeout=min(timeout, 10)), timeout=timeout)

        cdp.call("Page.enable")
        cdp.call("Network.enable")
        cdp.call("Emulation.setDeviceMetricsOverride", {
            "width": width, "height": height, "deviceScaleFactor": 1, "mobile": False,
        })
        cdp.call("Network.setUserAgentOverride", {"userAgent": UA})
        if headers:
            cdp.call("Network.setExtraHTTPHeaders", {"headers": headers})
        if cookies:
            cdp.call("Network.setCookies", {"cookies": [
                {"name": c["name"], "value": c["value"], "url": job["url"]}
                for c in cookies
            ]})

        cdp.events.pop("Page.loadEventFired", None)
        navigation = cdp.call("Page.navigate", {"url": job["url"]}, timeout=timeout)
        if navigation.get("errorText"):
            raise _CdpError(navigation["errorText"])
        try:
            cdp.wait_event("Page.loadEventFired", timeout=timeout)
        except _CdpError:
            pass  # slow page — capture whatever has rendered
        time.sleep(1.0)

        shot = cdp.call("Page.captureScreenshot", {
            "format": "png", "captureBeyondViewport": bool(full_page),
        }, timeout=timeout)
        data = shot.get("data")
        if not data:
            raise _CdpError("browser returned an empty screenshot")
        Path(job["path"]).write_bytes(base64.b64decode(data))

        if not job.get("title"):
            try:
                evaluated = cdp.call("Runtime.evaluate", {
                    "expression": "document.title", "returnByValue": True,
                }, timeout=min(timeout, 10))
                title = ((evaluated.get("result") or {}).get("value") or "").strip()
                job["title"] = title[:120] or None
            except Exception:
                pass
    finally:
        if cdp is not None:
            cdp.close()
        _stop_chrome(proc, profile)


def _capture_chrome(jobs, width, height, timeout, workers, verbose,
                    full_page=False, headers=None, cookies=None):
    chrome = find_chrome()
    if not chrome:
        raise RuntimeError("no Chrome/Chromium binary found")

    authenticated = bool(headers or cookies)

    def worker(job):
        try:
            if authenticated:
                _cdp_capture(chrome, job, width, height, timeout, full_page,
                             headers, cookies)
                if not job["path"].exists() or job["path"].stat().st_size == 0:
                    raise _CdpError("browser produced no image")
            else:
                _chrome_once(chrome, job, width, height, timeout)
            if job["path"].exists() and job["path"].stat().st_size > 0:
                job["status"] = "captured"
                if verbose:
                    print(f"      {C_GREEN}✓{C_RST} {job['url']}")
            else:
                job["status"] = "failed"
                job["error"] = "browser produced no image"
                if verbose:
                    print(f"      {C_RED}✗{C_RST} {job['url']} — no image")
        except subprocess.TimeoutExpired:
            job["status"] = "failed"
            job["error"] = "browser timeout"
            if verbose:
                print(f"      {C_RED}✗{C_RST} {job['url']} — timeout")
        except Exception as e:
            job["status"] = "failed"
            job["error"] = str(e)[:160]
            if verbose:
                print(f"      {C_RED}✗{C_RST} {job['url']} — {job['error'][:70]}")
        return job

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        return list(ex.map(worker, jobs))


# ============================================================
# Gallery
# ============================================================

def _write_gallery(outdir, entries, backend, source):
    cards = []
    for entry in entries:
        image = ""
        if entry.get("screenshot"):
            image = ("<img loading=\"lazy\" src=\""
                     + html.escape(Path(entry["screenshot"]).name)
                     + "\" alt=\"" + html.escape(entry.get("host") or "") + "\">")
        cards.append(f"""
    <article class="card">
      <a class="shot" href="{html.escape(entry.get('url') or '#')}" target="_blank" rel="noreferrer">{image}</a>
      <div class="meta">
        <h2>{html.escape(entry.get('host') or entry.get('input') or 'unknown')}</h2>
        <p class="url">{html.escape(entry.get('url') or '')}</p>
        <p class="title">{html.escape(entry.get('title') or 'no title')}</p>
        <p class="status {html.escape(entry.get('status') or '')}">
          {html.escape((entry.get('status') or '').upper())}
          {html.escape(str(entry.get('status_code') or ''))}
        </p>
      </div>
    </article>""")

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ReconX Screenshot Gallery — {html.escape(source or '')}</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ margin:0; background:#0d1117; color:#e6edf3;
         font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif; }}
  header {{ padding:24px 28px 8px; }}
  header h1 {{ margin:0 0 6px; font-size:20px; }}
  header p {{ margin:2px 0; color:#8b949e; }}
  .grid {{ display:grid; gap:18px; padding:20px 28px 40px;
           grid-template-columns:repeat(auto-fill,minmax(320px,1fr)); }}
  .card {{ background:#161b22; border:1px solid #30363d; border-radius:10px;
           overflow:hidden; }}
  .shot {{ display:block; aspect-ratio:16/10; background:#0b0f14; }}
  .shot img {{ width:100%; height:100%; object-fit:cover; display:block; }}
  .meta {{ padding:12px 14px; }}
  .meta h2 {{ margin:0 0 4px; font-size:15px; word-break:break-all; }}
  .meta p {{ margin:2px 0; color:#8b949e; font-size:12px; word-break:break-all; }}
  .meta .title {{ color:#c9d1d9; }}
  .status {{ color:#8b949e; font-size:11px; letter-spacing:.04em; }}
  .status.captured {{ color:#3fb950; }}
  .status.skipped {{ color:#d29922; }}
  .status.failed {{ color:#f85149; }}
</style>
</head>
<body>
<header>
  <h1>ReconX Screenshot Gallery</h1>
  <p>Target: {html.escape(source or '')}</p>
  <p>Captured: {sum(1 for e in entries if e.get('status') == 'captured')} /
     {len(entries)} hosts · backend: {html.escape(backend or 'none')} ·
     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
</header>
<div class="grid">{''.join(cards)}
</div>
</body>
</html>
"""
    path = outdir / "index.html"
    path.write_text(page, encoding="utf-8")
    return path


# ============================================================
# Main entry point
# ============================================================

def run_screenshots(targets, outdir="outputs/screenshots", width=1280, height=800,
                    timeout=25, full_page=False, backend=None, workers=3,
                    verbose=True, source=None, headers=None, cookies=None):
    """Probe hosts, screenshot the live ones and build an HTML gallery.

    headers: {'Name': 'value'} or ['Name: value', ...]
    cookies: 'a=1; b=2' or [{'name': 'a', 'value': '1'}, ...]
    Cookies are set per target origin, so the same values work across hosts.
    """
    headers = _normalize_headers(headers)
    cookies = _normalize_cookies(cookies)
    auth = _auth_summary(headers, cookies)

    outdir = Path(outdir)
    result = {
        "timestamp": datetime.now().isoformat(),
        "source": source,
        "backend": None,
        "auth": auth,
        "outdir": str(outdir),
        "total": 0,
        "captured": 0,
        "failed": 0,
        "skipped": 0,
        "gallery": None,
        "results": [],
    }

    if verbose:
        print(f"  {C_GRAY}[*] Resolving live hosts...{C_RST}")

    jobs, skipped = _prepare_jobs(targets, timeout, verbose)
    for entry in jobs:
        entry["status"] = "pending"
        entry["screenshot"] = None
        entry["error"] = None
        entry["status_code"] = None

    chosen = screenshot_backend(backend)
    if chosen is None:
        for entry in jobs:
            entry["status"] = "failed"
            entry["error"] = "no browser backend available"
        result["results"] = jobs + skipped
        result["total"] = len(jobs) + len(skipped)
        result["failed"] = len(jobs)
        result["skipped"] = len(skipped)
        result["note"] = backend_hint()
        return result

    outdir.mkdir(parents=True, exist_ok=True)
    for index, entry in enumerate(jobs, start=1):
        name = f"{index:03d}_{_safe_name(entry['host'])}.png"
        entry["path"] = outdir / name
        entry["screenshot"] = str(entry["path"])

    if verbose:
        if auth:
            print(f"  {C_GRAY}[*] Auth: {len(auth['headers'])} header(s), "
                  f"{len(auth['cookies'])} cookie(s) — values hidden{C_RST}")
        print(f"  {C_GRAY}[*] Capturing {len(jobs)} page(s) with {chosen}...{C_RST}")

    captured = []
    if chosen == "playwright":
        try:
            captured = _capture_playwright(jobs, width, height, timeout, full_page,
                                           verbose, headers, cookies)
        except Exception as e:
            fallback = find_chrome()
            if not fallback:
                for entry in jobs:
                    entry["status"] = "failed"
                    entry["error"] = f"playwright failed: {str(e)[:120]}"
                captured = jobs
                chosen = None
            else:
                if verbose:
                    print(f"  {C_YELLOW}[!] Playwright failed ({str(e)[:60]}), "
                          f"falling back to headless Chrome{C_RST}")
                chosen = "chrome"
                captured = _capture_chrome(jobs, width, height, timeout, workers,
                                           verbose, full_page, headers, cookies)
    elif chosen == "chrome":
        captured = _capture_chrome(jobs, width, height, timeout, workers,
                                   verbose, full_page, headers, cookies)

    result["backend"] = chosen
    for entry in captured:
        if entry.get("status") == "captured":
            result["captured"] += 1
        else:
            result["failed"] += 1
            entry.setdefault("status", "failed")
    result["results"] = captured + skipped
    result["skipped"] = len(skipped)
    result["total"] = len(captured) + len(skipped)

    gallery = _write_gallery(outdir, result["results"], chosen, source)
    result["gallery"] = str(gallery)

    return result


def print_screenshot_report(result):
    print("\n" + "=" * 78)
    print("  Screenshot Gallery (Aquatone-style) — ReconX")
    print("=" * 78)
    print(f"\n[*] Backend:   {result.get('backend') or 'none'}")
    auth = result.get("auth") or {}
    if auth:
        names = auth.get("headers", []) + auth.get("cookies", [])
        print(f"[*] Auth:      {len(auth.get('headers', []))} header(s), "
              f"{len(auth.get('cookies', []))} cookie(s) ({', '.join(names)})")
    print(f"[*] Target:    {result.get('source') or '-'}")
    print(f"[*] Hosts:     {result.get('total', 0)}  "
          f"captured: {result.get('captured', 0)}  "
          f"failed: {result.get('failed', 0)}  "
          f"skipped: {result.get('skipped', 0)}")

    if result.get("note"):
        print(f"\n[!] {result['note']}")

    captured = [r for r in result.get("results", []) if r.get("status") == "captured"]
    if captured:
        print(f"\n[+] Screenshots:")
        for r in captured[:50]:
            print(f"    ✓ {r['url']:<52} {Path(r['screenshot']).name}")
        if len(captured) > 50:
            print(f"    ... and {len(captured) - 50} more")

    problems = [r for r in result.get("results", []) if r.get("status") != "captured"]
    if problems:
        print(f"\n[!] Not captured ({len(problems)}):")
        for r in problems[:10]:
            print(f"    · {r.get('url') or r.get('input') or '?':<52} "
                  f"{(r.get('error') or r.get('status') or '')[:50]}")

    if result.get("gallery"):
        print(f"\n[+] Gallery:   {result['gallery']}")

    print("\n" + "=" * 78 + "\n")


def save_screenshot_report(result, outdir="outputs"):
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"screenshots_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False, default=str)
    return path


# ============================================================
# CLI
# ============================================================

def _targets_from_json(path):
    with open(path, encoding="utf-8", errors="ignore") as fh:
        data = json.load(fh)

    if isinstance(data, list):
        return live_probe._dedupe(data)

    for key in ("subdomains", "results", "hosts"):
        value = data.get(key) if isinstance(data, dict) else None
        if isinstance(value, list):
            return live_probe._dedupe(value)
        # cli.py saves subdomain_enum output as {"subdomains": {"subdomains": [...]}}
        if isinstance(value, dict) and isinstance(value.get("subdomains"), list):
            return live_probe._dedupe(value["subdomains"])

    if isinstance(data, dict) and isinstance(data.get("steps"), dict):
        subs = data["steps"].get("subdomains", {})
        if isinstance(subs, dict) and subs.get("subdomains"):
            return live_probe._dedupe(subs["subdomains"])

    raise ValueError(f"no host list found in {path}")


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="ReconX Screenshot Gallery (Aquatone-style)"
    )
    parser.add_argument("targets", nargs="*", help="Hostnames or URLs")
    parser.add_argument("-f", "--file", help="File with one target per line")
    parser.add_argument("--from-json", help="Reuse a ReconX subdomain/probe JSON")
    parser.add_argument("-o", "--outdir", default="outputs/screenshots")
    parser.add_argument("--width", type=int, default=1280)
    parser.add_argument("--height", type=int, default=800)
    parser.add_argument("--timeout", type=int, default=25)
    parser.add_argument("--workers", type=int, default=3,
                        help="Parallel headless-Chrome jobs")
    parser.add_argument("--full-page", action="store_true")
    parser.add_argument("--backend", choices=["playwright", "chrome"])
    parser.add_argument("--header", action="append", metavar="'Name: value'",
                        help="Extra request header, e.g. 'Authorization: Bearer ...' "
                             "(repeatable)")
    parser.add_argument("--cookie", action="append", metavar="'a=1; b=2'",
                        help="Cookie(s) sent to every target, e.g. 'session=...' "
                             "(repeatable)")
    parser.add_argument("--json", action="store_true", help="Save JSON report")
    args = parser.parse_args()

    targets = list(args.targets)
    if args.file:
        try:
            with open(args.file, encoding="utf-8", errors="ignore") as fh:
                targets += [l.strip() for l in fh
                            if l.strip() and not l.startswith("#")]
        except OSError as e:
            print(f"  ✗ Can't read {args.file}: {e}")
            return 1
    if args.from_json:
        try:
            targets += _targets_from_json(args.from_json)
        except Exception as e:
            print(f"  ✗ {e}")
            return 1

    if not targets:
        print("Usage: python -m modules.web.aquatone_clone <host> [...] | "
              "-f hosts.txt | --from-json report.json")
        return 1

    print(f"\n  [*] Screenshot backend: {backend_hint()}")
    try:
        result = run_screenshots(
            targets, outdir=args.outdir, width=args.width, height=args.height,
            timeout=args.timeout, full_page=args.full_page, backend=args.backend,
            workers=args.workers, verbose=True,
            headers=args.header, cookies=args.cookie,
        )
    except ValueError as e:
        print(f"  ✗ {e}")
        return 1
    print_screenshot_report(result)

    if args.json:
        print(f"  ✓ Saved: {save_screenshot_report(result)}")

    return 0 if result.get("captured") else 2


if __name__ == "__main__":
    sys.exit(main())
