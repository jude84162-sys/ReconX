#!/usr/bin/env python3
"""ReconX-GUI — stdlib HTTP server (no Flask, no pip).

Serves a single-page web UI and a small JSON/SSE API that drives the 38-tool
ReconX suite. Runs anywhere Python 3.8+ exists (Kali / WSL / Termux / macOS).

    python3 server.py              # http://127.0.0.1:8777
    python3 server.py --port 9000 --host 0.0.0.0 --no-browser
"""
from __future__ import annotations

import os
import re
import sys
import json
import time
import argparse
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)
# make a sibling ReconX repo importable (so modules.* / recon resolve if present)
for extra in (BASE, os.path.dirname(BASE)):
    if extra not in sys.path:
        sys.path.append(extra)

from engine import registry, bridge, jobs as jobsmod  # noqa: E402

MANAGER = jobsmod.JobManager()
STATE = {"authorized": False, "scope": ""}
OUTPUTS = os.path.join(BASE, "outputs")
os.makedirs(OUTPUTS, exist_ok=True)

_CT = {".html": "text/html; charset=utf-8", ".js": "application/javascript",
       ".css": "text/css", ".json": "application/json", ".ico": "image/x-icon",
       ".svg": "image/svg+xml"}


def _tools_payload():
    out = []
    for t in registry.TOOLS:
        out.append({k: t[k] for k in ("id", "num", "name", "icon", "cat",
                                      "danger", "desc", "inputs")} |
                   {"availability": bridge.availability(t)})
    return {"categories": registry.CATEGORIES, "tools": out,
            "authorized": STATE["authorized"], "scope": STATE["scope"],
            "has_modules": any(bridge.availability(t) == "module"
                               for t in registry.TOOLS)}


class Handler(BaseHTTPRequestHandler):
    server_version = "ReconX-GUI"
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):   # quiet
        pass

    # ---- helpers ----
    def _send(self, code, body=b"", ctype="application/json", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, default=str), "application/json")

    def _read_json(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}

    def _file(self, relpath):
        path = os.path.normpath(os.path.join(BASE, "web", relpath))
        if not path.startswith(os.path.join(BASE, "web")) or not os.path.isfile(path):
            return self._send(404, b"not found", "text/plain")
        ext = os.path.splitext(path)[1]
        with open(path, "rb") as f:
            self._send(200, f.read(), _CT.get(ext, "application/octet-stream"))

    # ---- routing ----
    def do_GET(self):
        p = urlparse(self.path).path
        if p == "/" or p == "/index.html":
            return self._file("index.html")
        if p.startswith("/static/"):
            return self._file(p[1:])
        if p == "/api/tools":
            return self._json(_tools_payload())
        if p == "/api/jobs":
            return self._json({"jobs": MANAGER.list()})
        m = re.match(r"/api/job/(\w+)$", p)
        if m:
            j = MANAGER.get(m.group(1))
            return self._json(j.to_dict(full=True) if j else {"error": "not found"},
                              200 if j else 404)
        m = re.match(r"/api/stream/(\w+)$", p)
        if m:
            return self._stream(m.group(1))
        m = re.match(r"/api/download/(\w+)$", p)
        if m:
            return self._download(m.group(1))
        return self._send(404, b"not found", "text/plain")

    def do_POST(self):
        p = urlparse(self.path).path
        if p == "/api/authorize":
            body = self._read_json()
            STATE["authorized"] = bool(body.get("authorized"))
            STATE["scope"] = str(body.get("scope", ""))[:300]
            return self._json({"authorized": STATE["authorized"], "scope": STATE["scope"]})
        if p == "/api/run":
            return self._run(self._read_json())
        m = re.match(r"/api/cancel/(\w+)$", p)
        if m:
            j = MANAGER.get(m.group(1))
            if j:
                j.cancel()
            return self._json({"ok": bool(j)})
        return self._send(404, b"not found", "text/plain")

    do_HEAD = do_GET

    # ---- actions ----
    def _run(self, body):
        tool_id = body.get("tool_id", "")
        params = body.get("params", {}) or {}
        tool = registry.BY_ID.get(tool_id)
        if not tool:
            return self._json({"error": "unknown tool"}, 400)
        # authorization gate for anything that touches the target
        if tool["danger"] in ("active", "intrusive") and not STATE["authorized"]:
            return self._json({"error": "authorization_required",
                               "message": "Confirm you are authorized to test this "
                               "target before running active/intrusive tools."}, 403)
        # required-field check
        for f in tool["inputs"]:
            if f.get("required") and not str(params.get(f["name"], "")).strip():
                return self._json({"error": f"missing required field: {f['label']}"}, 400)
        job = MANAGER.create(tool_id, params)
        return self._json({"job_id": job.id})

    def _stream(self, jid):
        job = MANAGER.get(jid)
        if not job:
            return self._send(404, b"no job", "text/plain")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        self.close_connection = True  # no keep-alive: unambiguous SSE framing
        q = job.subscribe()
        try:
            self._sse("hello", {"id": jid})
            last_ping = time.time()
            while True:
                try:
                    kind, payload = q.get(timeout=1.0)
                except Exception:
                    if time.time() - last_ping > 15:
                        self._sse("ping", {})
                        last_ping = time.time()
                    continue
                self._sse(kind, payload if not isinstance(payload, str)
                          else {"line": payload})
                if kind == "end":
                    break
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            job.unsubscribe(q)

    def _sse(self, event, data):
        try:
            msg = f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"
            self.wfile.write(msg.encode("utf-8"))
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            raise

    def _download(self, jid):
        job = MANAGER.get(jid)
        if not job:
            return self._send(404, b"no job", "text/plain")
        report = {"tool": job.tool["name"], "tool_id": job.tool_id,
                  "params": getattr(job, "params", {}), "engine": job.engine,
                  "status": job.status, "summary": job.summary,
                  "findings": job.findings, "data": job.result,
                  "log": job.lines, "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
                  "_tool": "ReconX-GUI 1.0"}
        blob = json.dumps(report, indent=2, default=str)
        ts = time.strftime("%Y%m%d_%H%M%S")
        fname = f"{job.tool_id}_{ts}.json"
        try:
            with open(os.path.join(OUTPUTS, fname), "w", encoding="utf-8") as f:
                f.write(blob)
        except Exception:
            pass
        self._send(200, blob, "application/json",
                   {"Content-Disposition": f'attachment; filename="{fname}"'})


def main():
    ap = argparse.ArgumentParser(description="ReconX-GUI web server")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8777)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host if args.host != '0.0.0.0' else '127.0.0.1'}:{args.port}"
    has_mod = any(bridge.availability(t) == "module" for t in registry.TOOLS)
    print("\n  ReconX-GUI  —  web recon & vuln suite")
    print(f"  ▸ {url}")
    print(f"  ▸ backend: {'ReconX modules detected (full 38 tools)' if has_mod else 'standalone builtins (stdlib)'}")
    print("  ▸ Authorized testing only. Ctrl-C to stop.\n")
    if not args.no_browser:
        threading.Timer(0.7, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  bye.\n")
        srv.shutdown()


if __name__ == "__main__":
    main()
