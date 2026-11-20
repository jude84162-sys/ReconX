"""The Tool contract shared by the recon tools, the agent, and the brain.

A Tool is a thin, uniform wrapper around a ReconX module function. Every tool:
  * declares an Anthropic-style JSON `input_schema` so the LLM can call it,
  * names which input field carries the target (`scope_field`),
  * is run through the Scope Guard and RateLimiter BEFORE it touches the host,
  * returns a `ToolResult` with a machine-readable `data` dict and a short
    `summary` string the LLM (and the dashboard) can read.

Tool authors subclass `Tool` and implement `_execute`. They must NOT perform
their own scope decisions — the base class does the scope/rate/timeout work so
the safety guarantee lives in exactly one place.
"""
from __future__ import annotations

import time
import traceback
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, List, Optional

from ..scope import Scope, ScopeError, extract_host


@dataclass
class ToolResult:
    ok: bool
    tool: str
    target: str
    summary: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    error: str = ""
    blocked: bool = False          # True when the Scope Guard refused it
    duration: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def for_llm(self) -> str:
        """Compact text handed back to the model as a tool_result block."""
        import json as _json
        head = ("OK" if self.ok else ("BLOCKED" if self.blocked else "ERROR"))
        body = {"tool": self.tool, "target": self.target, "status": head,
                "summary": self.summary}
        if self.error:
            body["error"] = self.error
        if self.data:
            body["data"] = self.data
        try:
            return _json.dumps(body, default=str)[:12000]
        except (TypeError, ValueError):
            return "%s: %s" % (head, self.summary)


class Tool:
    name: str = "tool"
    description: str = ""
    # JSON schema (Anthropic tool-use "input_schema") describing the arguments.
    input_schema: Dict[str, Any] = {"type": "object", "properties": {}}
    # which argument holds the host/url to scope-check:
    scope_field: str = "target"
    # whether this tool makes network requests (and so needs scope + rate limit):
    network: bool = True

    def __init__(self, scope: Scope, limiter=None, cfg=None):
        self.scope = scope
        self.limiter = limiter
        self.cfg = cfg

    # --- subclasses implement this ---
    def _execute(self, **kwargs) -> ToolResult:
        raise NotImplementedError

    # --- the base class runs scope + rate + timing around it ---
    def run(self, **kwargs) -> ToolResult:
        target = str(kwargs.get(self.scope_field, "") or "")
        started = time.monotonic()
        if self.network:
            try:
                host = self.scope.check(target)
            except ScopeError as exc:
                return ToolResult(ok=False, tool=self.name, target=target,
                                  blocked=True, error=str(exc),
                                  summary="refused by Scope Guard: %s" % exc,
                                  duration=time.monotonic() - started)
            if self.limiter is not None:
                try:
                    self.limiter.acquire(host)
                except Exception:  # noqa: BLE001 - a limiter must never kill a run
                    pass
        try:
            result = self._execute(**kwargs)
            if not isinstance(result, ToolResult):
                result = ToolResult(ok=True, tool=self.name, target=target,
                                    summary=str(result)[:400],
                                    data={"raw": result})
            result.duration = time.monotonic() - started
            return result
        except Exception as exc:  # noqa: BLE001 - surface failures as data, never crash the agent
            return ToolResult(ok=False, tool=self.name, target=target,
                              error="%s: %s" % (type(exc).__name__, exc),
                              summary="tool raised %s" % type(exc).__name__,
                              data={"traceback": traceback.format_exc()[-1500:]},
                              duration=time.monotonic() - started)

    def spec(self) -> Dict[str, Any]:
        """Anthropic tool-use schema entry."""
        return {"name": self.name, "description": self.description,
                "input_schema": self.input_schema}


class ToolRegistry:
    """Instantiated per engagement with a live Scope + limiter."""

    def __init__(self, scope: Scope, limiter=None, cfg=None):
        self.scope = scope
        self.limiter = limiter
        self.cfg = cfg
        self._tools: Dict[str, Tool] = {}

    def register(self, tool_cls) -> None:
        tool = tool_cls(self.scope, self.limiter, self.cfg)
        self._tools[tool.name] = tool

    def register_all(self, tool_classes) -> None:
        for tc in tool_classes:
            self.register(tc)

    def get(self, name: str) -> Optional[Tool]:
        return self._tools.get(name)

    def names(self) -> List[str]:
        return sorted(self._tools)

    def specs(self) -> List[Dict[str, Any]]:
        return [t.spec() for t in self._tools.values()]

    def call(self, name: str, arguments: Dict[str, Any]) -> ToolResult:
        tool = self._tools.get(name)
        if tool is None:
            return ToolResult(ok=False, tool=name, target="",
                              error="unknown tool: %s" % name,
                              summary="no such tool")
        return tool.run(**(arguments or {}))
