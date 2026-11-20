"""Engagement memory: persistent state + shared-event plumbing.

A single engagement's life (its target, scope, every event it emitted, the
findings it confirmed and the final report) is held in one :class:`Memory`
object and persisted to a human-readable ``state.json`` under the operator's
``data_dir``:

    {data_dir}/{safe target}/state.json

Pure stdlib (``json`` + ``os``). Nothing here imports a sibling Scorpion module
that another agent might still be writing, so it is safe to import and test in
isolation.

This module also owns the *representation* of a SHARED EVENT and the small
fan-out helper that both the agent and the deterministic planner use to push an
event to (a) the caller's ``on_event`` callback, (b) the engagement memory, and
(c) an optional notifier — defensively, so one bad sink never aborts a run.

SHARED EVENT CONTRACT (dict):
    {"type": t, "ts": float, "text": str, ...extra}
with ``t`` in: status | thinking | tool_call | tool_result | finding |
report | error | done.
Severity scale (for findings): info | low | medium | high | critical.
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Callable, Dict, List, Optional

SEVERITIES = ("info", "low", "medium", "high", "critical")
_SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# the event types the dashboard / notifier understand
EVENT_TYPES = (
    "status", "thinking", "tool_call", "tool_result",
    "finding", "report", "error", "done",
)


# --------------------------------------------------------------------------- #
# severity + naming helpers
# --------------------------------------------------------------------------- #
def normalize_severity(value: Any) -> str:
    """Coerce an arbitrary severity into one of the fixed SEVERITIES."""
    if not value:
        return "info"
    s = str(value).strip().lower()
    if s in _SEVERITY_RANK:
        return s
    # tolerate a few common aliases scanners emit
    aliases = {
        "informational": "info", "none": "info", "warn": "low",
        "warning": "low", "moderate": "medium", "med": "medium",
        "important": "high", "severe": "high", "crit": "critical",
    }
    return aliases.get(s, "info")


def severity_rank(value: Any) -> int:
    """Higher == worse. Unknown severities sort as 'info'."""
    return _SEVERITY_RANK.get(normalize_severity(value), 0)


def safe_target_name(target: str) -> str:
    """Make a filesystem-safe directory name from an arbitrary target string.

    Strips any URL scheme and path, lowercases, and replaces every character
    that is not ``[a-z0-9._-]`` with ``_``. Never returns an empty string and
    never escapes the parent directory (no slashes, no '..').
    """
    if not target:
        return "unknown"
    t = str(target).strip().lower()
    # For a URL, drop the scheme and the path (keep host[:port]); for a bare
    # target keep it whole so a CIDR like 203.0.113.0/24 survives sanitisation.
    if "://" in t:
        t = t.split("://", 1)[1]
        t = t.split("/")[0]
    t = t.split("@")[-1]              # strip credentials
    t = re.sub(r"[^a-z0-9._-]", "_", t)
    t = re.sub(r"_+", "_", t).strip("._-")
    if not t or t in (".", ".."):
        return "unknown"
    return t[:100]


# --------------------------------------------------------------------------- #
# event construction + fan-out
# --------------------------------------------------------------------------- #
def make_event(etype: str, text: str = "", ts: Optional[float] = None,
               **extra: Any) -> Dict[str, Any]:
    """Build a SHARED EVENT dict. Extra keyword args ride along verbatim."""
    ev: Dict[str, Any] = {
        "type": etype,
        "ts": float(ts) if ts is not None else time.time(),
        "text": text or "",
    }
    for k, v in extra.items():
        if k not in ev:
            ev[k] = v
    return ev


def notify_safely(notifier: Any, event: Dict[str, Any]) -> None:
    """Hand an event to a notifier without ever raising.

    The notifier is a sibling component whose exact shape is not fixed here; we
    accept a plain callable or an object exposing one of a few conventional
    methods.
    """
    if notifier is None:
        return
    try:
        if callable(notifier) and not hasattr(notifier, "notify"):
            notifier(event)
            return
        for meth in ("notify", "emit", "send", "on_event", "handle", "publish"):
            fn = getattr(notifier, meth, None)
            if callable(fn):
                fn(event)
                return
        if callable(notifier):
            notifier(event)
    except Exception:  # noqa: BLE001 - a notifier must never kill a run
        pass


def dispatch_event(event: Dict[str, Any],
                   on_event: Optional[Callable[[Dict[str, Any]], Any]] = None,
                   memory: Optional["Memory"] = None,
                   notifier: Any = None) -> Dict[str, Any]:
    """Record ``event`` in memory and fan it out to on_event + notifier.

    Each sink is isolated: a failure in one does not stop the others, and none
    of them can abort the engagement.
    """
    if memory is not None:
        try:
            memory.add_event(event)
        except Exception:  # noqa: BLE001
            pass
    if on_event is not None:
        try:
            on_event(event)
        except Exception:  # noqa: BLE001
            pass
    notify_safely(notifier, event)
    return event


# --------------------------------------------------------------------------- #
# the engagement record
# --------------------------------------------------------------------------- #
class Memory:
    """Persistent state for one engagement.

    Attributes mirror the on-disk ``state.json``: ``target``, ``scope_desc``,
    ``events``, ``findings``, ``report`` and the ``created_at`` / ``updated_at``
    timestamps.
    """

    FILENAME = "state.json"

    def __init__(self, target: str = "", scope_desc: str = "",
                 data_dir: str = "outputs/engagements",
                 events: Optional[List[Dict[str, Any]]] = None,
                 findings: Optional[List[Dict[str, Any]]] = None,
                 report: str = "",
                 created_at: Optional[float] = None,
                 updated_at: Optional[float] = None,
                 goal: str = ""):
        self.target = target or ""
        self.scope_desc = scope_desc or ""
        self.goal = goal or ""
        self.data_dir = data_dir or "outputs/engagements"
        self.events: List[Dict[str, Any]] = list(events or [])
        self.findings: List[Dict[str, Any]] = list(findings or [])
        self.report = report or ""
        now = time.time()
        self.created_at = float(created_at) if created_at is not None else now
        self.updated_at = float(updated_at) if updated_at is not None else now

    # -- construction ------------------------------------------------------
    @classmethod
    def from_config(cls, cfg: Any, target: str, scope_desc: str = "",
                    goal: str = "") -> "Memory":
        data_dir = getattr(cfg, "data_dir", "outputs/engagements")
        return cls(target=target, scope_desc=scope_desc,
                   data_dir=data_dir, goal=goal)

    @classmethod
    def open(cls, data_dir: str, target: str, scope_desc: str = "",
             goal: str = "") -> "Memory":
        """Load an existing engagement for this target, or start a fresh one."""
        path = cls.path_for(data_dir, target)
        if os.path.isfile(path):
            try:
                mem = cls.load(path)
                if scope_desc and not mem.scope_desc:
                    mem.scope_desc = scope_desc
                if goal and not mem.goal:
                    mem.goal = goal
                return mem
            except Exception:  # noqa: BLE001 - a corrupt file starts fresh
                pass
        return cls(target=target, scope_desc=scope_desc,
                   data_dir=data_dir, goal=goal)

    # -- paths -------------------------------------------------------------
    @classmethod
    def path_for(cls, data_dir: str, target: str) -> str:
        return os.path.join(data_dir, safe_target_name(target), cls.FILENAME)

    @property
    def dir(self) -> str:
        return os.path.join(self.data_dir, safe_target_name(self.target))

    @property
    def path(self) -> str:
        return os.path.join(self.dir, self.FILENAME)

    # -- mutation ----------------------------------------------------------
    def touch(self) -> None:
        self.updated_at = time.time()

    def add_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(event, dict):
            event = make_event("status", str(event))
        event.setdefault("ts", time.time())
        event.setdefault("type", "status")
        event.setdefault("text", "")
        self.events.append(event)
        self.touch()
        return event

    def add_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(finding, dict):
            finding = {"title": str(finding)}
        f = dict(finding)
        f["severity"] = normalize_severity(f.get("severity"))
        f.setdefault("title", "finding")
        self.findings.append(f)
        self.touch()
        return f

    def set_findings(self, findings: List[Dict[str, Any]]) -> None:
        self.findings = [self._clean_finding(f) for f in (findings or [])]
        self.touch()

    @staticmethod
    def _clean_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
        f = dict(finding) if isinstance(finding, dict) else {"title": str(finding)}
        f["severity"] = normalize_severity(f.get("severity"))
        f.setdefault("title", "finding")
        return f

    def set_report(self, markdown: str) -> None:
        self.report = markdown or ""
        self.touch()

    # -- serialisation -----------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "scope_desc": self.scope_desc,
            "goal": self.goal,
            "events": self.events,
            "findings": self.findings,
            "report": self.report,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, obj: Dict[str, Any],
                  data_dir: str = "outputs/engagements") -> "Memory":
        if not isinstance(obj, dict):
            raise ValueError("state must be a JSON object")
        return cls(
            target=obj.get("target", ""),
            scope_desc=obj.get("scope_desc", ""),
            goal=obj.get("goal", ""),
            data_dir=data_dir,
            events=obj.get("events", []),
            findings=obj.get("findings", []),
            report=obj.get("report", ""),
            created_at=obj.get("created_at"),
            updated_at=obj.get("updated_at"),
        )

    def save(self) -> str:
        """Persist to ``self.path`` (atomic rename). Returns the path written."""
        os.makedirs(self.dir, exist_ok=True)
        payload = json.dumps(self.to_dict(), indent=2, default=str,
                             ensure_ascii=False)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(payload)
        os.replace(tmp, self.path)
        return self.path

    @classmethod
    def load(cls, path: str) -> "Memory":
        """Load a Memory from a ``state.json`` path."""
        with open(path, "r", encoding="utf-8") as fh:
            obj = json.load(fh)
        # the data_dir is two levels up from the state.json
        data_dir = os.path.dirname(os.path.dirname(os.path.abspath(path)))
        mem = cls.from_dict(obj, data_dir=data_dir)
        return mem


# A friendly alias — the orchestrator talks about an "engagement".
Engagement = Memory


__all__ = [
    "SEVERITIES",
    "EVENT_TYPES",
    "Memory",
    "Engagement",
    "make_event",
    "dispatch_event",
    "notify_safely",
    "normalize_severity",
    "severity_rank",
    "safe_target_name",
]
