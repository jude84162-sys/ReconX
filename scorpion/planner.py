"""The deterministic, no-LLM pipeline.

When there is no Brain (no API key, or ``no_llm`` is set) the agent still has to
do useful work. The planner drives the registered tools in a sensible,
fixed order for a domain engagement, emits the same SHARED EVENTS the LLM agent
does, extracts candidate findings from the tool results, triages them (rules
based) and writes a templated report.

It is defensive about which tools exist: every step looks the tool up by name
and skips gracefully when it is absent, so a partial registry (or a future one
with renamed tools) never crashes the run.

This module also owns :func:`extract_candidates`, the logic that turns a
``ToolResult`` into candidate findings — the LLM agent reuses it, which is why
it lives in the lowest-level pipeline module rather than in the agent.
"""
from __future__ import annotations

import time
from typing import Any, Callable, Dict, List, Optional

from .memory import (
    make_event,
    dispatch_event,
    normalize_severity,
    safe_target_name,  # noqa: F401 - re-exported convenience
)

# severities considered "weak" for a TLS grade
_WEAK_TLS_GRADES = frozenset({"c", "d", "e", "f", "t"})


# --------------------------------------------------------------------------- #
# candidate-finding extraction (shared with the agent)
# --------------------------------------------------------------------------- #
def extract_candidates(result: Any) -> List[Dict[str, Any]]:
    """Turn one ``ToolResult`` into a list of candidate finding dicts.

    Keys off the *shape* of ``result.data`` rather than the tool name, so it
    works for any tool that reports findings/weaknesses in the conventional
    fields. Returns ``[]`` for blocked/empty/benign results.
    """
    out: List[Dict[str, Any]] = []
    if result is None:
        return out
    data = getattr(result, "data", None)
    if not isinstance(data, dict):
        return out
    tool = getattr(result, "tool", "") or ""
    target = getattr(result, "target", "") or ""
    if getattr(result, "blocked", False):
        return out

    # 1) explicit scanner findings
    findings = data.get("findings")
    if isinstance(findings, list):
        for f in findings:
            if not isinstance(f, dict):
                continue
            out.append({
                "title": f.get("title") or f.get("name") or f.get("type")
                or "vulnerability",
                "severity": normalize_severity(f.get("severity")),
                "type": f.get("type") or f.get("category"),
                "target": f.get("url") or f.get("target") or target,
                "url": f.get("url"),
                "param": f.get("param") or f.get("parameter"),
                "detail": f.get("detail") or f.get("evidence")
                or f.get("description"),
                "source": tool,
            })

    # 2) open DNS zone transfer — high severity, unambiguous
    if data.get("zone_transfer_open"):
        ns = data.get("zone_transfer_ns")
        out.append({
            "title": "DNS zone transfer (AXFR) allowed",
            "severity": "high",
            "type": "dns-zone-transfer",
            "target": target,
            "detail": "The zone could be transferred from nameserver %s, "
                      "exposing the full DNS record set." % (ns or "(unknown)"),
            "source": tool,
        })

    # 3) sensitive directory-bust hits
    sensitive_count = data.get("sensitive_count")
    found = data.get("found")
    if sensitive_count and isinstance(found, list):
        for item in found:
            if isinstance(item, dict) and item.get("sensitive"):
                out.append({
                    "title": "Sensitive path exposed: %s" % item.get("path"),
                    "severity": normalize_severity(item.get("severity") or "medium"),
                    "type": "exposed-path",
                    "target": target,
                    "detail": "Path %s returned status %s."
                              % (item.get("path"), item.get("status")),
                    "source": tool,
                })

    # 4) weak TLS posture
    grade = data.get("grade")
    if isinstance(grade, str) and grade.strip().lower() in _WEAK_TLS_GRADES:
        issues = data.get("issues") or []
        out.append({
            "title": "Weak TLS configuration (grade %s)" % grade,
            "severity": "medium" if grade.strip().lower() in ("c", "d") else "high",
            "type": "weak-tls",
            "target": target,
            "detail": "; ".join(str(i) for i in issues[:5]) or "TLS grade %s" % grade,
            "source": tool,
        })

    # 5) missing security headers (informational-to-low)
    missing = data.get("missing_headers")
    if isinstance(missing, list) and missing:
        out.append({
            "title": "Missing security headers",
            "severity": "low",
            "type": "missing-security-headers",
            "target": target,
            "detail": "Absent headers: %s" % ", ".join(str(m) for m in missing[:12]),
            "source": tool,
        })

    return out


# --------------------------------------------------------------------------- #
# the pipeline
# --------------------------------------------------------------------------- #
def run(target: str,
        registry: Any,
        on_event: Optional[Callable[[Dict[str, Any]], Any]] = None,
        memory: Any = None,
        notifier: Any = None,
        deadline: Optional[float] = None,
        goal: Optional[str] = None) -> Dict[str, Any]:
    """Run the deterministic recon pipeline against ``target``.

    Returns ``{"engine","target","findings","report","steps","events"}``.
    Never raises on a single tool error — tool failures are surfaced as events
    and the pipeline continues.
    """
    from . import subagents  # local import keeps module import light + acyclic

    def emit(etype: str, text: str = "", **extra: Any) -> Dict[str, Any]:
        return dispatch_event(make_event(etype, text, **extra),
                              on_event=on_event, memory=memory, notifier=notifier)

    scope = getattr(registry, "scope", None)
    scope_desc = ""
    if memory is not None and getattr(memory, "scope_desc", ""):
        scope_desc = memory.scope_desc
    elif scope is not None and hasattr(scope, "describe"):
        try:
            scope_desc = scope.describe()
        except Exception:  # noqa: BLE001
            scope_desc = ""

    emit("status", "Planner (no-LLM) engagement starting on %s" % target,
         target=target, engine="planner")

    candidates: List[Dict[str, Any]] = []
    steps = 0

    def over_budget() -> bool:
        return deadline is not None and time.monotonic() >= deadline

    def call(name: str, args: Dict[str, Any]) -> Any:
        """Invoke a tool if present; emit the shared events; collect findings."""
        nonlocal steps
        if over_budget():
            return None
        tool = _get_tool(registry, name)
        if tool is None:
            return None
        steps += 1
        emit("tool_call", "%s %s" % (name, _fmt_args(args)), tool=name, args=args)
        try:
            result = registry.call(name, args)
        except Exception as exc:  # noqa: BLE001 - defensive; registry is safe
            emit("error", "%s raised %s" % (name, exc), tool=name)
            return None
        emit("tool_result",
             getattr(result, "summary", "") or "",
             tool=name,
             ok=bool(getattr(result, "ok", False)),
             blocked=bool(getattr(result, "blocked", False)),
             summary=getattr(result, "summary", ""))
        for cand in extract_candidates(result):
            candidates.append(cand)
        return result

    # 1) resolve + OSINT, subdomain enumeration, DNS
    osint = call("resolve_and_osint", {"domain": target})
    subs = call("enum_subdomains", {"domain": target})
    call("dns_recon", {"domain": target})

    # 2) assemble the host list to probe (apex + discovered subdomains, capped)
    hosts = _collect_hosts(target, osint, subs)
    live_hosts: List[str] = []
    if not over_budget():
        probe = call("live_probe", {"target": target, "hosts": hosts[1:]})
        live_hosts = _live_from_probe(probe)
    if not live_hosts:
        live_hosts = [target]

    # 3) per-live-host web recon
    for host in live_hosts:
        if over_budget():
            emit("status", "time budget reached; wrapping up", engine="planner")
            break
        url = _as_url(host)
        call("web_fingerprint", {"url": url})
        call("detect_waf", {"url": url})
        call("ssl_analyze", {"hostname": _host_only(host)})
        call("dir_bust", {"url": url})
        call("find_login", {"url": url})
        call("find_params", {"url": url})

    # 4) vulnerability sweep on the primary target
    if not over_budget():
        call("vuln_scan_all", {"target": _as_url(live_hosts[0])})

    # 5) triage + report
    findings = subagents.triage(None, candidates, target=target)
    for f in findings:
        emit("finding", f.get("title", "finding"),
             title=f.get("title"), severity=normalize_severity(f.get("severity")),
             detail=f.get("detail", ""), target=f.get("target", target))
    if memory is not None:
        try:
            memory.set_findings(findings)
        except Exception:  # noqa: BLE001
            pass

    report = subagents.write_report(None, target, scope or scope_desc,
                                    findings, events=_mem_events(memory))
    if memory is not None:
        try:
            memory.set_report(report)
        except Exception:  # noqa: BLE001
            pass
    emit("report", "engagement report ready", markdown=report)

    emit("done", "planner finished: %d finding(s) in %d step(s)"
         % (len(findings), steps),
         findings=findings, report=report, engine="planner")

    if memory is not None:
        try:
            memory.save()
        except Exception:  # noqa: BLE001
            pass

    return {
        "engine": "planner",
        "target": target,
        "findings": findings,
        "report": report,
        "steps": steps,
        "events": _mem_events(memory),
    }


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _get_tool(registry: Any, name: str) -> Any:
    getter = getattr(registry, "get", None)
    if callable(getter):
        try:
            return getter(name)
        except Exception:  # noqa: BLE001
            return None
    names = getattr(registry, "names", None)
    if callable(names):
        try:
            return name if name in names() else None
        except Exception:  # noqa: BLE001
            return None
    return None


def _fmt_args(args: Dict[str, Any]) -> str:
    try:
        parts = []
        for k, v in (args or {}).items():
            sv = v if isinstance(v, (str, int, float, bool)) else "[...]"
            parts.append("%s=%s" % (k, sv))
        return "(" + ", ".join(parts) + ")"
    except Exception:  # noqa: BLE001
        return "()"


def _collect_hosts(target: str, osint: Any, subs: Any) -> List[str]:
    hosts: List[str] = [target]
    seen = {target.lower()}

    def add_many(items: Any) -> None:
        if not isinstance(items, list):
            return
        for h in items:
            if isinstance(h, str) and h and h.lower() not in seen:
                hosts.append(h)
                seen.add(h.lower())

    for res in (osint, subs):
        data = getattr(res, "data", None)
        if not isinstance(data, dict):
            continue
        add_many(data.get("subdomains"))
        add_many(data.get("hostnames"))
    return hosts[:25]


def _live_from_probe(probe: Any) -> List[str]:
    data = getattr(probe, "data", None)
    if not isinstance(data, dict):
        return []
    live = data.get("live")
    out: List[str] = []
    if isinstance(live, list):
        for item in live:
            if isinstance(item, dict):
                u = item.get("url") or item.get("input")
                if u:
                    out.append(u)
            elif isinstance(item, str):
                out.append(item)
    return out[:15]


def _as_url(host: str) -> str:
    if not host:
        return host
    if "://" in host:
        return host
    return "http://" + host


def _host_only(host: str) -> str:
    h = host
    if "://" in h:
        h = h.split("://", 1)[1]
    h = h.split("/")[0]
    if h.count(":") == 1:
        h = h.split(":")[0]
    return h


def _mem_events(memory: Any) -> List[Dict[str, Any]]:
    if memory is None:
        return []
    evs = getattr(memory, "events", None)
    return list(evs) if isinstance(evs, list) else []


__all__ = ["run", "extract_candidates"]
