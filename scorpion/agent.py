"""The Scorpion orchestrator.

:class:`Agent` runs one engagement from start to finish. With a Brain it drives
the Anthropic tool-use loop (per the SHARED BRAIN contract): ask the model,
run each tool it calls through the :class:`~scorpion.tools.base.ToolRegistry`,
hand the results back, and loop until the model stops or the step / wall-clock
budget runs out. Candidate findings are harvested from every tool result *and*
from the model's own final narrative, then triaged into confirmed findings and
written up as a report by the sub-agents.

Without a Brain (no API key, or ``cfg.no_llm``) it delegates to the
deterministic :mod:`scorpion.planner`.

Every step emits a SHARED EVENT (``status | thinking | tool_call |
tool_result | finding | report | error | done``) to the caller's ``on_event``
callback, to the engagement :class:`~scorpion.memory.Memory`, and to an
optional notifier — each isolated so one bad sink never aborts the run. A
single tool error is surfaced as data and never ends the engagement.
"""
from __future__ import annotations

import time
from typing import Any, Callable, Dict, List, Optional

from .memory import (
    Memory,
    make_event,
    dispatch_event,
    normalize_severity,
)
from . import planner as planner_mod
from . import subagents
from .brain.prompts import build_system_prompt

# how long a whole engagement may run, by default, when the caller gives no
# explicit budget: a generous per-step allowance bounded by the step budget.
_DEFAULT_SECONDS_PER_STEP = 60


class Agent:
    def __init__(self, cfg: Any, registry: Any, brain: Any = None,
                 memory: Any = None, notifier: Any = None):
        self.cfg = cfg
        self.registry = registry
        self.brain = brain
        self.memory = memory
        self.notifier = notifier

    # ------------------------------------------------------------------ #
    def run(self, target: str, goal: Optional[str] = None,
            on_event: Optional[Callable[[Dict[str, Any]], Any]] = None,
            budget_seconds: Optional[float] = None) -> Dict[str, Any]:
        """Run the engagement against ``target`` and return a result dict.

        Result keys: ``engine`` ("llm" | "planner"), ``target``, ``findings``,
        ``report``, ``steps``, ``events``, and (llm path) ``stop_reason``.
        """
        cfg = self.cfg
        registry = self.registry
        scope = getattr(registry, "scope", None)
        scope_desc = _scope_desc(scope)

        memory = self.memory
        if memory is None:
            memory = Memory.from_config(cfg, target, scope_desc=scope_desc,
                                        goal=goal or "")
            self.memory = memory
        else:
            if not getattr(memory, "target", ""):
                memory.target = target
            if scope_desc and not getattr(memory, "scope_desc", ""):
                memory.scope_desc = scope_desc
            if goal and not getattr(memory, "goal", ""):
                memory.goal = goal

        def emit(etype: str, text: str = "", **extra: Any) -> Dict[str, Any]:
            return dispatch_event(make_event(etype, text, **extra),
                                  on_event=on_event, memory=memory,
                                  notifier=self.notifier)

        # -- decide engine --------------------------------------------------
        use_brain = (self.brain is not None
                     and getattr(self.brain, "available", False)
                     and not getattr(cfg, "no_llm", False))
        if not use_brain:
            reason = ("no_llm set" if getattr(cfg, "no_llm", False)
                      else "no brain available")
            emit("status", "Using deterministic planner (%s)" % reason,
                 engine="planner")
            return planner_mod.run(target, registry, on_event=on_event,
                                   memory=memory, notifier=self.notifier,
                                   deadline=self._deadline(budget_seconds),
                                   goal=goal)

        return self._run_llm(target, goal, emit, memory, scope, scope_desc,
                             budget_seconds)

    # ------------------------------------------------------------------ #
    def _run_llm(self, target: str, goal: Optional[str],
                 emit: Callable[..., Dict[str, Any]], memory: Any,
                 scope: Any, scope_desc: str,
                 budget_seconds: Optional[float]) -> Dict[str, Any]:
        cfg = self.cfg
        registry = self.registry
        brain = self.brain
        max_steps = int(getattr(cfg, "max_steps", 40) or 40)
        deadline = self._deadline(budget_seconds)

        system = build_system_prompt(
            scope_desc=scope_desc or None,
            target=target,
            max_steps=max_steps,
            rate_per_host=getattr(cfg, "rate_per_host", None),
            extra=("- Operator goal: %s" % goal) if goal else None,
        )
        try:
            tools = registry.specs()
        except Exception:  # noqa: BLE001
            tools = []

        user0 = _initial_user_message(target, goal)
        messages: List[Dict[str, Any]] = [{"role": "user", "content": user0}]

        emit("status", "LLM engagement starting on %s" % target,
             target=target, engine="llm")

        candidates: List[Dict[str, Any]] = []
        steps = 0
        stop_reason = ""
        final_text = ""

        while steps < max_steps:
            if deadline is not None and time.monotonic() >= deadline:
                emit("status", "wall-clock budget reached; finishing up",
                     engine="llm")
                stop_reason = "budget"
                break

            emit("thinking", "deciding the next action (step %d/%d)"
                 % (steps + 1, max_steps))
            resp = brain.complete(system, messages, tools=tools)

            if not isinstance(resp, dict) or resp.get("error"):
                err = (resp or {}).get("error", "unknown brain error")
                emit("error", "brain error: %s" % err)
                stop_reason = "error"
                break

            text = (resp.get("text") or "").strip()
            if text:
                final_text = text
                emit("thinking", text)

            assistant_content = resp.get("assistant_content") or []
            if assistant_content:
                messages.append({"role": "assistant",
                                 "content": assistant_content})

            tool_calls = resp.get("tool_calls") or []
            stop_reason = resp.get("stop_reason") or ""

            if stop_reason != "tool_use" or not tool_calls:
                break

            # run every requested tool, collect results for a single user turn
            result_blocks: List[Dict[str, Any]] = []
            for call in tool_calls:
                steps += 1
                name = call.get("name", "")
                args = call.get("input") or {}
                tool_id = call.get("id", "")
                emit("tool_call", "%s %s" % (name, _fmt_args(args)),
                     tool=name, args=args)
                result = registry.call(name, args)
                emit("tool_result",
                     getattr(result, "summary", "") or "",
                     tool=name,
                     ok=bool(getattr(result, "ok", False)),
                     blocked=bool(getattr(result, "blocked", False)),
                     summary=getattr(result, "summary", ""))
                for cand in planner_mod.extract_candidates(result):
                    candidates.append(cand)
                result_blocks.append({
                    "type": "tool_result",
                    "tool_use_id": tool_id,
                    "content": _for_llm(result),
                })
                if steps >= max_steps:
                    break

            messages.append({"role": "user", "content": result_blocks})

        # -- harvest findings from the model's final narrative too ----------
        if final_text:
            candidates.append({
                "title": "agent narrative",
                "severity": "info",
                "type": "agent-summary",
                "target": target,
                "detail": final_text,
                "source": "model_final",
            })

        # -- triage (asks the model for structured findings) + report -------
        findings = subagents.triage(brain, candidates, target=target,
                                    model=getattr(cfg, "heavy_model", None))
        for f in findings:
            emit("finding", f.get("title", "finding"),
                 title=f.get("title"),
                 severity=normalize_severity(f.get("severity")),
                 detail=f.get("detail", ""),
                 target=f.get("target", target))
        try:
            memory.set_findings(findings)
        except Exception:  # noqa: BLE001
            pass

        report = subagents.write_report(
            brain, target, scope or scope_desc, findings,
            events=list(getattr(memory, "events", []) or []),
            model=getattr(cfg, "heavy_model", None),
        )
        try:
            memory.set_report(report)
        except Exception:  # noqa: BLE001
            pass
        emit("report", "engagement report ready", markdown=report)

        emit("done", "engagement finished: %d finding(s) in %d step(s)"
             % (len(findings), steps),
             findings=findings, report=report, engine="llm")

        try:
            memory.save()
        except Exception:  # noqa: BLE001
            pass

        return {
            "engine": "llm",
            "target": target,
            "findings": findings,
            "report": report,
            "steps": steps,
            "stop_reason": stop_reason,
            "events": list(getattr(memory, "events", []) or []),
        }

    # ------------------------------------------------------------------ #
    def _deadline(self, budget_seconds: Optional[float]) -> Optional[float]:
        secs = budget_seconds
        if secs is None:
            secs = getattr(self.cfg, "max_wall_seconds", None)
        if secs is None:
            max_steps = int(getattr(self.cfg, "max_steps", 40) or 40)
            secs = max_steps * _DEFAULT_SECONDS_PER_STEP
        try:
            secs = float(secs)
        except (TypeError, ValueError):
            return None
        if secs <= 0:
            # a zero/negative budget means "already over": stop before step 1
            return time.monotonic()
        return time.monotonic() + secs


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _initial_user_message(target: str, goal: Optional[str]) -> str:
    parts = ["Begin the engagement against the authorised target: %s." % target]
    if goal:
        parts.append("Operator goal: %s" % goal)
    parts.append("Start with passive reconnaissance, then enumerate and "
                 "fingerprint the surface, run only the vulnerability checks "
                 "the surface justifies, and finish with a clear report.")
    return " ".join(parts)


def _for_llm(result: Any) -> str:
    fn = getattr(result, "for_llm", None)
    if callable(fn):
        try:
            return fn()
        except Exception:  # noqa: BLE001
            pass
    return str(result)


def _fmt_args(args: Dict[str, Any]) -> str:
    try:
        parts = []
        for k, v in (args or {}).items():
            sv = v if isinstance(v, (str, int, float, bool)) else "[...]"
            parts.append("%s=%s" % (k, sv))
        return "(" + ", ".join(parts) + ")"
    except Exception:  # noqa: BLE001
        return "()"


def _scope_desc(scope: Any) -> str:
    if scope is None:
        return ""
    describe = getattr(scope, "describe", None)
    if callable(describe):
        try:
            return str(describe())
        except Exception:  # noqa: BLE001
            return ""
    return ""


__all__ = ["Agent"]
