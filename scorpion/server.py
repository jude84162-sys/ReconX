#!/usr/bin/env python3
"""Scorpion.ai — the agent's web dashboard (stdlib ``http.server``, no deps).

A small, self-contained :class:`ThreadingHTTPServer` that drives one autonomous
engagement at a time and streams the agent's SHARED EVENTS to any number of
browser clients over Server-Sent Events. Modelled on ``reconx_gui/server.py``
but agent-centric: instead of running one tool per request it starts an
:class:`~scorpion.agent.Agent` in a background thread and narrates it live.

    python3 -m scorpion.server            # http://127.0.0.1:8778
    python3 -m scorpion.server --port 9000 --host 0.0.0.0 --no-browser

Design notes
------------
* Only the already-frozen contract modules (``config``, ``scope``,
  ``ratelimit``) are imported at module load. Every sibling that another agent
  may still be writing (``tools.recon_tools``, ``brain``, ``notify``,
  ``agent``) is imported *lazily* inside :func:`run` / the default factory, so
  this module imports cleanly even while its peers are half-written.
* The server is fed an ``agent_factory`` so tests can inject a fake agent and
  nothing ever touches the network. The real factory (built in :func:`run`)
  wires Scope + RateLimiter + ToolRegistry(ALL_TOOLS) + Brain + Notifier into a
  real :class:`~scorpion.agent.Agent`.
* The Scope lives in a single mutable object shared by the server, the
  ToolRegistry and every Tool, so ``POST /api/scope`` mutates it in place and
  the change is seen immediately by the live registry.

SHARED EVENT CONTRACT (dict): ``{"type": t, "ts": float, "text": str, ...}``
with ``t`` in: status | thinking | tool_call | tool_result | finding | report |
error | done. Severity: info | low | medium | high | critical.
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

# --- frozen contracts only (safe to import at module load) -----------------
from .config import Config, load_config
from .ratelimit import RateLimiter
from .scope import Scope

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")

SEVERITIES = ("info", "low", "medium", "high", "critical")
EVENT_TYPES = ("status", "thinking", "tool_call", "tool_result",
               "finding", "report", "error", "done")

_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".png": "image/png",
    ".map": "application/json; charset=utf-8",
}

# how often the SSE loop emits a heartbeat comment when idle (seconds)
_HEARTBEAT = 12.0
# cap the in-memory event history so a long engagement can't grow unbounded
_HISTORY_CAP = 4000


# --------------------------------------------------------------------------- #
# small helpers (self-contained — no sibling imports)
# --------------------------------------------------------------------------- #
def _event(etype: str, text: str = "", **extra: Any) -> Dict[str, Any]:
    """Build a SHARED EVENT dict (local copy so we don't import ``memory``)."""
    ev: Dict[str, Any] = {"type": etype, "ts": time.time(), "text": text or ""}
    for k, v in extra.items():
        if k not in ev:
            ev[k] = v
    return ev


def _norm_sev(value: Any) -> str:
    if not value:
        return "info"
    s = str(value).strip().lower()
    return s if s in SEVERITIES else {
        "informational": "info", "none": "info", "warn": "low", "warning": "low",
        "moderate": "medium", "med": "medium", "important": "high",
        "severe": "high", "crit": "critical",
    }.get(s, "info")


def _as_list(value: Any) -> List[str]:
    """Coerce a scope value (list, or comma/newline string) into a clean list."""
    if value is None:
        return []
    if isinstance(value, str):
        parts = value.replace("\n", ",").split(",")
    elif isinstance(value, (list, tuple)):
        parts = []
        for item in value:
            parts.extend(str(item).replace("\n", ",").split(","))
    else:
        parts = [str(value)]
    out: List[str] = []
    for p in parts:
        p = p.strip()
        if p:
            out.append(p)
    return out


# --------------------------------------------------------------------------- #
# the event bus feeding SSE
# --------------------------------------------------------------------------- #
class _EventBus:
    """Fan events out to every connected SSE client, with replayable history.

    Each subscriber gets its own bounded :class:`queue.Queue`; a slow or dead
    client can never block the agent (``put_nowait`` drops on overflow).
    """

    def __init__(self, cap: int = _HISTORY_CAP):
        self._lock = threading.Lock()
        self._subs: "set[queue.Queue]" = set()
        self._history: List[Dict[str, Any]] = []
        self._cap = cap

    def publish(self, event: Dict[str, Any]) -> None:
        with self._lock:
            self._history.append(event)
            if len(self._history) > self._cap:
                self._history = self._history[-self._cap:]
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait(event)
            except queue.Full:
                pass

    def subscribe(self) -> Tuple["queue.Queue", List[Dict[str, Any]]]:
        q: "queue.Queue" = queue.Queue(maxsize=2000)
        with self._lock:
            self._subs.add(q)
            history = list(self._history)
        return q, history

    def unsubscribe(self, q: "queue.Queue") -> None:
        with self._lock:
            self._subs.discard(q)

    def reset(self) -> None:
        """Clear history for a fresh engagement (keeps subscribers attached)."""
        with self._lock:
            self._history = []

    def snapshot(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._history)

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subs)


# --------------------------------------------------------------------------- #
# the server
# --------------------------------------------------------------------------- #
class ScorpionServer:
    """Hosts one engagement at a time and streams its events to the dashboard.

    Parameters
    ----------
    cfg : Config
        Runtime config (host/port/scope/model ... from :func:`load_config`).
    agent_factory : callable
        ``agent_factory(cfg, scope, limiter, registry) -> agent`` where the
        returned ``agent`` exposes ``run(target, goal=None, on_event=cb)``
        (the :class:`~scorpion.agent.Agent` contract). Injected so tests can
        pass a fake that emits canned events without any network.
    scope : Scope, optional
        The live Scope (defaults to ``Scope.from_config(cfg)``). Shared by the
        registry, so ``set_scope`` mutates it in place.
    limiter : RateLimiter, optional
        Shared per-host limiter handed to the agent/registry.
    registry : ToolRegistry, optional
        The live tool registry (built in :func:`run`); kept only so the config
        endpoint can report the available tools. May be ``None`` in tests.
    web_dir : str, optional
        Directory holding ``index.html`` / ``app.js`` / ``style.css``.
    """

    def __init__(self, cfg: Config, agent_factory: Callable[..., Any],
                 scope: Optional[Scope] = None,
                 limiter: Optional[Any] = None,
                 registry: Optional[Any] = None,
                 web_dir: Optional[str] = None):
        self.cfg = cfg
        self.agent_factory = agent_factory
        self.scope = scope if scope is not None else Scope.from_config(cfg)
        self.limiter = limiter
        self.registry = registry
        self.web_dir = os.path.abspath(web_dir or WEB_DIR)

        self._bus = _EventBus()
        self._lock = threading.RLock()
        self._running = False
        self._status = "idle"          # idle | running | done | error
        self._agent: Any = None
        self._thread: Optional[threading.Thread] = None
        self._engagement: Dict[str, Any] = self._blank_engagement()
        self._chat_log: List[Dict[str, Any]] = []
        self._httpd: Optional[ThreadingHTTPServer] = None

    # ------------------------------------------------------------------ #
    # engagement state
    # ------------------------------------------------------------------ #
    @staticmethod
    def _blank_engagement() -> Dict[str, Any]:
        return {
            "target": "", "goal": "", "status": "idle",
            "findings": [], "report": "", "stop_reason": "",
            "started_at": None, "finished_at": None, "steps": 0,
        }

    def engagement_state(self) -> Dict[str, Any]:
        with self._lock:
            eng = dict(self._engagement)
            eng["findings"] = list(eng.get("findings", []))
            eng["running"] = self._running
            eng["status"] = self._status
            eng["event_count"] = len(self._bus.snapshot())
            eng["clients"] = self._bus.subscriber_count
            return eng

    # ------------------------------------------------------------------ #
    # scope
    # ------------------------------------------------------------------ #
    def scope_payload(self) -> Dict[str, Any]:
        sc = self.scope
        return {
            "allow": list(getattr(sc, "allow_raw", [])),
            "deny": list(getattr(sc, "deny_raw", [])),
            "empty": bool(getattr(sc, "is_empty", True)),
            "describe": sc.describe() if hasattr(sc, "describe") else "",
        }

    def set_scope(self, allow: Any, deny: Any) -> Dict[str, Any]:
        """Replace the live Scope, mutating the shared object in place so the
        registry and every already-built Tool pick up the change at once."""
        new = Scope(allow=_as_list(allow), deny=_as_list(deny))
        with self._lock:
            sc = self.scope
            copied = True
            for attr in ("allow_raw", "deny_raw", "_allow", "_deny"):
                if hasattr(sc, attr) and hasattr(new, attr):
                    setattr(sc, attr, getattr(new, attr))
                else:
                    copied = False
            if not copied:
                # internals changed under us — fall back to swapping the object
                self.scope = new
                if self.registry is not None:
                    try:
                        self.registry.scope = new
                        for t in getattr(self.registry, "_tools", {}).values():
                            t.scope = new
                    except Exception:
                        pass
        return self.scope_payload()

    # ------------------------------------------------------------------ #
    # config
    # ------------------------------------------------------------------ #
    def config_payload(self) -> Dict[str, Any]:
        cfg = self.cfg
        tools: List[str] = []
        if self.registry is not None:
            try:
                tools = list(self.registry.names())
            except Exception:
                tools = []
        return {
            "config": cfg.redacted() if hasattr(cfg, "redacted") else {},
            "scope": self.scope_payload(),
            "brain": {"available": bool(getattr(cfg, "has_brain", False)),
                      "model": getattr(cfg, "model", ""),
                      "heavy_model": getattr(cfg, "heavy_model", "")},
            "telegram": {"available": bool(getattr(cfg, "has_telegram", False))},
            "voice": {"enabled": bool(getattr(cfg, "voice_enabled", False))},
            "tools": tools,
            "running": self._running,
            "status": self._status,
            "name": "Scorpion.ai",
        }

    # ------------------------------------------------------------------ #
    # starting / running an engagement
    # ------------------------------------------------------------------ #
    def start_engagement(self, target: str,
                         goal: str = "") -> Tuple[int, Dict[str, Any]]:
        """Scope-guard and launch an engagement. Returns ``(http_code, body)``."""
        target = str(target or "").strip()
        goal = str(goal or "").strip()
        if not target:
            return 400, {"error": "a target is required"}

        with self._lock:
            if self._running:
                return 409, {"error": "an engagement is already running",
                             "status": self._status,
                             "target": self._engagement.get("target", "")}
            ok, reason = self.scope.classify(target)
            if not ok:
                return 400, {"error": "out_of_scope", "message": reason,
                             "scope": self.scope_payload()}

            self._running = True
            self._status = "running"
            self._engagement = self._blank_engagement()
            self._engagement.update({"target": target, "goal": goal,
                                     "status": "running",
                                     "started_at": time.time()})
            self._bus.reset()
            self._thread = threading.Thread(
                target=self._run_agent, args=(target, goal),
                name="scorpion-engagement", daemon=True)
            self._thread.start()

        self._publish(_event("status",
                             "Engagement accepted for %s" % target,
                             target=target, goal=goal, engine="pending"))
        return 202, {"accepted": True, "target": target, "goal": goal,
                     "status": "running"}

    def _run_agent(self, target: str, goal: str) -> None:
        try:
            agent = self.agent_factory(self.cfg, self.scope, self.limiter,
                                       self.registry)
            with self._lock:
                self._agent = agent
            agent.run(target, goal=goal or None, on_event=self._on_event)
        except Exception as exc:  # noqa: BLE001 - surface, never crash the thread
            self._on_event(_event(
                "error", "engagement failed to run: %s: %s"
                % (type(exc).__name__, exc)))
        finally:
            with self._lock:
                self._running = False
                self._agent = None
                self._engagement["finished_at"] = time.time()
                if self._status == "running":
                    self._status = "done"
                    self._engagement["status"] = "done"

    # ------------------------------------------------------------------ #
    # event sink (called by the agent on its own thread)
    # ------------------------------------------------------------------ #
    def _on_event(self, event: Dict[str, Any]) -> None:
        if not isinstance(event, dict):
            event = _event("status", str(event))
        event.setdefault("type", "status")
        event.setdefault("ts", time.time())
        event.setdefault("text", "")
        etype = event.get("type")

        with self._lock:
            eng = self._engagement
            if etype == "finding":
                eng.setdefault("findings", []).append({
                    "title": event.get("title") or event.get("text") or "finding",
                    "severity": _norm_sev(event.get("severity")),
                    "detail": event.get("detail", ""),
                    "target": event.get("target", eng.get("target", "")),
                })
            elif etype == "report":
                md = event.get("markdown") or event.get("report") or event.get("text")
                if md:
                    eng["report"] = md
            elif etype == "done":
                findings = event.get("findings")
                if isinstance(findings, list):
                    eng["findings"] = [{
                        "title": f.get("title", "finding"),
                        "severity": _norm_sev(f.get("severity")),
                        "detail": f.get("detail", ""),
                        "target": f.get("target", eng.get("target", "")),
                    } for f in findings if isinstance(f, dict)]
                if event.get("report"):
                    eng["report"] = event.get("report")
                if event.get("steps") is not None:
                    eng["steps"] = event.get("steps")
                self._status = "done"
                eng["status"] = "done"
            elif etype == "error":
                self._status = "error"
                eng["status"] = "error"
            if event.get("engine"):
                eng["engine"] = event.get("engine")
            if event.get("stop_reason"):
                eng["stop_reason"] = event.get("stop_reason")

        self._publish(event)

    def _publish(self, event: Dict[str, Any]) -> None:
        self._bus.publish(event)

    # ------------------------------------------------------------------ #
    # chat
    # ------------------------------------------------------------------ #
    def chat(self, message: str) -> Dict[str, Any]:
        """Queue an operator message to the running agent, or record a one-off
        when idle. Always returns an ``accepted`` acknowledgement."""
        message = str(message or "").strip()
        if not message:
            return {"accepted": False, "error": "empty message"}

        with self._lock:
            running = self._running
            agent = self._agent
            self._chat_log.append({"ts": time.time(), "text": message})

        delivered = False
        if running and agent is not None:
            # forward-compatible hook: a future Agent may accept live turns.
            post = getattr(agent, "post_message", None)
            if callable(post):
                try:
                    post(message)
                    delivered = True
                except Exception:  # noqa: BLE001
                    delivered = False

        self._publish(_event("status", "operator: %s" % message,
                             role="operator", chat=True, delivered=delivered))
        return {"accepted": True, "queued": running, "delivered": delivered,
                "running": running}

    # ------------------------------------------------------------------ #
    # SSE stream (driven by the handler, kept here so state stays private)
    # ------------------------------------------------------------------ #
    def stream(self, write: Callable[[bytes], None],
               should_stop: Callable[[], bool]) -> None:
        """Replay history then stream live events through ``write`` until the
        client disconnects (``write`` raises) or ``should_stop`` returns True."""
        q, history = self._bus.subscribe()
        try:
            write(b": connected to Scorpion.ai event stream\n\n")
            for ev in history:
                write(self._sse(ev))
            last = time.time()
            while not should_stop():
                try:
                    ev = q.get(timeout=1.0)
                except queue.Empty:
                    now = time.time()
                    if now - last >= _HEARTBEAT:
                        write(b": heartbeat\n\n")
                        last = now
                    continue
                write(self._sse(ev))
                last = time.time()
        finally:
            self._bus.unsubscribe(q)

    @staticmethod
    def _sse(event: Dict[str, Any]) -> bytes:
        try:
            data = json.dumps(event, default=str)
        except (TypeError, ValueError):
            data = json.dumps({"type": "status", "text": "unserialisable event"})
        return ("data: %s\n\n" % data).encode("utf-8")

    # ------------------------------------------------------------------ #
    # http plumbing
    # ------------------------------------------------------------------ #
    def make_handler(self) -> type:
        app = self

        class _Handler(BaseHTTPRequestHandler):
            server_version = "Scorpion.ai"
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):  # quiet by default
                pass

            # -- low-level senders --
            def _send(self, code: int, body: bytes = b"",
                      ctype: str = "application/json; charset=utf-8",
                      extra: Optional[Dict[str, str]] = None):
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
                    try:
                        self.wfile.write(body)
                    except (BrokenPipeError, ConnectionResetError):
                        pass

            def _json(self, obj: Any, code: int = 200):
                self._send(code, json.dumps(obj, default=str),
                           "application/json; charset=utf-8")

            def _read_json(self) -> Dict[str, Any]:
                try:
                    n = int(self.headers.get("Content-Length", 0) or 0)
                except (TypeError, ValueError):
                    n = 0
                if n <= 0:
                    return {}
                try:
                    raw = self.rfile.read(n)
                    obj = json.loads(raw or b"{}")
                    return obj if isinstance(obj, dict) else {}
                except Exception:  # noqa: BLE001
                    return {}

            def _static(self, filename: str):
                safe = os.path.normpath(filename).lstrip(os.sep)
                path = os.path.normpath(os.path.join(app.web_dir, safe))
                if (not path.startswith(app.web_dir + os.sep)
                        and path != app.web_dir) or not os.path.isfile(path):
                    return self._send(404, b"not found", "text/plain; charset=utf-8")
                ext = os.path.splitext(path)[1].lower()
                try:
                    with open(path, "rb") as fh:
                        body = fh.read()
                except OSError:
                    return self._send(404, b"not found", "text/plain; charset=utf-8")
                self._send(200, body,
                           _CONTENT_TYPES.get(ext, "application/octet-stream"))

            # -- routing --
            def do_GET(self):
                p = urlparse(self.path).path
                if p in ("/", "/index.html"):
                    return self._static("index.html")
                if p in ("/app.js", "/style.css"):
                    return self._static(p.lstrip("/"))
                if p == "/favicon.ico":
                    return self._send(204, b"", "image/x-icon")
                if p == "/api/config":
                    return self._json(app.config_payload())
                if p == "/api/engagement":
                    return self._json(app.engagement_state())
                if p == "/api/scope":
                    return self._json(app.scope_payload())
                if p == "/api/events":
                    return self._events()
                return self._send(404, b"not found", "text/plain; charset=utf-8")

            def do_POST(self):
                p = urlparse(self.path).path
                if p == "/api/scope":
                    body = self._read_json()
                    return self._json(app.set_scope(body.get("allow"),
                                                    body.get("deny")))
                if p == "/api/start":
                    body = self._read_json()
                    code, payload = app.start_engagement(
                        body.get("target", ""), body.get("goal", ""))
                    return self._json(payload, code)
                if p == "/api/chat":
                    body = self._read_json()
                    return self._json(app.chat(body.get("message", "")))
                return self._send(404, b"not found", "text/plain; charset=utf-8")

            do_HEAD = do_GET

            # -- SSE --
            def _events(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.send_header("X-Accel-Buffering", "no")
                self.end_headers()
                self.close_connection = True  # unambiguous close-delimited framing

                def write(chunk: bytes):
                    self.wfile.write(chunk)
                    self.wfile.flush()

                try:
                    app.stream(write, lambda: False)
                except (BrokenPipeError, ConnectionResetError, ValueError, OSError):
                    pass

        return _Handler

    # ------------------------------------------------------------------ #
    # lifecycle
    # ------------------------------------------------------------------ #
    def build_httpd(self) -> ThreadingHTTPServer:
        host = getattr(self.cfg, "host", "127.0.0.1")
        port = int(getattr(self.cfg, "port", 8778) or 0)
        httpd = ThreadingHTTPServer((host, port), self.make_handler())
        httpd.daemon_threads = True
        self._httpd = httpd
        return httpd

    @property
    def address(self) -> Tuple[str, int]:
        if self._httpd is not None:
            return self._httpd.server_address  # type: ignore[return-value]
        return (getattr(self.cfg, "host", "127.0.0.1"),
                int(getattr(self.cfg, "port", 8778) or 0))

    def serve_forever(self) -> None:
        httpd = self._httpd or self.build_httpd()
        httpd.serve_forever()

    def shutdown(self) -> None:
        if self._httpd is not None:
            try:
                self._httpd.shutdown()
            except Exception:  # noqa: BLE001
                pass
            try:
                self._httpd.server_close()
            except Exception:  # noqa: BLE001
                pass


# --------------------------------------------------------------------------- #
# the real wiring (lazy sibling imports live here)
# --------------------------------------------------------------------------- #
def _build_registry(scope: Scope, limiter: Any, cfg: Config) -> Optional[Any]:
    """Build a ToolRegistry with every recon tool. Best-effort: returns ``None``
    if a sibling module can't be imported yet."""
    try:
        from .tools.base import ToolRegistry
        from .tools.recon_tools import ALL_TOOLS
    except Exception:  # noqa: BLE001
        return None
    try:
        registry = ToolRegistry(scope, limiter, cfg)
        registry.register_all(ALL_TOOLS)
        return registry
    except Exception:  # noqa: BLE001
        return None


def _build_notifier(cfg: Config) -> Optional[Callable[[Dict[str, Any]], Any]]:
    """Build a Notifier and adapt it to the plain ``callable(event)`` sink the
    Agent's fan-out expects. Returns ``None`` if the notify layer is absent."""
    try:
        from .notify import Notifier
    except Exception:  # noqa: BLE001
        return None
    try:
        notifier = Notifier(cfg)
    except Exception:  # noqa: BLE001
        return None

    def _sink(event: Dict[str, Any]) -> None:
        try:
            notifier.notify_event(event)
        except Exception:  # noqa: BLE001 - a notifier must never kill a run
            pass

    return _sink


def default_agent_factory(cfg: Config, scope: Scope, limiter: Any,
                          registry: Any) -> Any:
    """Build the real :class:`~scorpion.agent.Agent` (lazy sibling imports)."""
    from .agent import Agent
    from .brain import Brain
    if registry is None:
        registry = _build_registry(scope, limiter, cfg)
    brain = None
    try:
        brain = Brain(cfg)
    except Exception:  # noqa: BLE001
        brain = None
    notifier = _build_notifier(cfg)
    return Agent(cfg, registry, brain=brain, notifier=notifier)


def build_server(cfg: Optional[Config] = None, **overrides) -> ScorpionServer:
    """Assemble a fully wired :class:`ScorpionServer` from config."""
    if cfg is None:
        cfg = load_config(**overrides)
    scope = Scope.from_config(cfg)
    try:
        limiter = RateLimiter(getattr(cfg, "rate_per_host", 8.0))
    except Exception:  # noqa: BLE001
        limiter = None
    registry = _build_registry(scope, limiter, cfg)
    return ScorpionServer(cfg, default_agent_factory, scope=scope,
                          limiter=limiter, registry=registry)


def run(argv: Optional[List[str]] = None) -> None:
    ap = argparse.ArgumentParser(description="Scorpion.ai web dashboard")
    ap.add_argument("--host", default=None)
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args(argv)

    overrides: Dict[str, Any] = {}
    if args.host is not None:
        overrides["host"] = args.host
    if args.port is not None:
        overrides["port"] = args.port
    cfg = load_config(**overrides)

    server = build_server(cfg)
    httpd = server.build_httpd()
    host, port = server.address
    shown = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    url = "http://%s:%s" % (shown, port)

    brain_on = bool(getattr(cfg, "has_brain", False))
    print("\n  Scorpion.ai  —  autonomous recon / bug-bounty agent")
    print("  ▸ %s" % url)
    print("  ▸ brain:   %s" % ("Claude (%s)" % cfg.model if brain_on
                                    else "deterministic planner (no API key)"))
    print("  ▸ scope:   %s" % server.scope.describe())
    print("  ▸ telegram:%s" % (" on" if getattr(cfg, "has_telegram", False)
                                    else " off"))
    print("  ▸ Authorized testing only. Ctrl-C to stop.\n")

    if not args.no_browser and host not in ("0.0.0.0", "::"):
        try:
            import webbrowser
            threading.Timer(0.7, lambda: webbrowser.open(url)).start()
        except Exception:  # noqa: BLE001
            pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  bye.\n")
        server.shutdown()


def main() -> None:
    run()


if __name__ == "__main__":
    main()
