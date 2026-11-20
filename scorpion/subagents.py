"""Helper sub-agents: triage and report writing.

Both work with *or* without the Brain:

* :func:`triage` turns raw candidate observations into a ranked, de-duplicated
  list of findings with a normalised severity. With a Brain it uses
  ``TRIAGE_PROMPT`` (and falls back to the rules path on any model/parse
  failure); without one it dedupes deterministically by ``(type, target)``.
* :func:`write_report` produces the engagement's Markdown report. With a Brain
  it uses ``REPORT_PROMPT``; without one it fills a plain template.

Only the *done* contract modules are imported (``brain.prompts``, ``memory``).
No sibling under active construction is imported, so this module tests in
isolation.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from .brain.prompts import (
    TRIAGE_PROMPT,
    REPORT_PROMPT,
    build_triage_prompt,
    build_report_prompt,
)
from .memory import normalize_severity, severity_rank


# --------------------------------------------------------------------------- #
# triage
# --------------------------------------------------------------------------- #
def triage(brain: Any, candidates: List[Dict[str, Any]],
           target: Optional[str] = None,
           model: Optional[str] = None) -> List[Dict[str, Any]]:
    """Rank + de-duplicate candidate findings into reportable findings.

    Returns a list of finding dicts (most severe first), each with at least
    ``title``, ``severity`` (normalised), ``target`` and ``detail``.
    """
    cands = [_coerce_candidate(c) for c in (candidates or []) if c]
    if not cands:
        return []

    if brain is not None and getattr(brain, "available", False):
        llm = _triage_with_brain(brain, cands, target, model)
        if llm is not None:
            return _rank(llm)
    return _rank(_triage_rules(cands))


def _triage_with_brain(brain: Any, candidates: List[Dict[str, Any]],
                       target: Optional[str],
                       model: Optional[str]) -> Optional[List[Dict[str, Any]]]:
    """Ask the model to emit structured findings. None on any failure."""
    try:
        user = build_triage_prompt(candidates, target)
        resp = brain.complete(TRIAGE_PROMPT,
                              [{"role": "user", "content": user}],
                              model=model)
    except Exception:  # noqa: BLE001 - the Brain shouldn't raise, but be safe
        return None
    if not isinstance(resp, dict) or resp.get("error"):
        return None
    parsed = _parse_findings_json(resp.get("text", ""))
    if parsed is None:
        return None
    out: List[Dict[str, Any]] = []
    for f in parsed:
        if not isinstance(f, dict):
            continue
        if f.get("false_positive"):
            continue
        out.append(_coerce_candidate(f, default_target=target))
    return out


def _triage_rules(candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deterministic dedupe: keep the worst severity per (type, target)."""
    merged: Dict[tuple, Dict[str, Any]] = {}
    for c in candidates:
        key = (
            (c.get("type") or c.get("title") or "").strip().lower(),
            (c.get("target") or "").strip().lower(),
        )
        prev = merged.get(key)
        if prev is None:
            merged[key] = dict(c)
            continue
        # keep the higher severity; merge a count so humans see duplication
        if severity_rank(c.get("severity")) > severity_rank(prev.get("severity")):
            merged[key] = dict(c)
            keep = merged[key]
        else:
            keep = prev
        keep["duplicates"] = int(keep.get("duplicates", 1)) + 1
    return list(merged.values())


# --------------------------------------------------------------------------- #
# report writing
# --------------------------------------------------------------------------- #
def write_report(brain: Any, target: str, scope: Any,
                 findings: List[Dict[str, Any]],
                 events: Optional[List[Dict[str, Any]]] = None,
                 recon_summary: Any = None,
                 model: Optional[str] = None) -> str:
    """Produce the engagement report as Markdown (always returns a string)."""
    findings = [_coerce_candidate(f, default_target=target) for f in (findings or [])]
    scope_desc = _scope_desc(scope)

    if brain is not None and getattr(brain, "available", False):
        md = _report_with_brain(brain, target, findings, recon_summary, model)
        if md:
            return md
    return _report_template(target, scope_desc, findings, events)


def _report_with_brain(brain: Any, target: str,
                       findings: List[Dict[str, Any]],
                       recon_summary: Any,
                       model: Optional[str]) -> Optional[str]:
    try:
        user = build_report_prompt(findings, recon_summary, target)
        resp = brain.complete(REPORT_PROMPT,
                              [{"role": "user", "content": user}],
                              model=model)
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(resp, dict) or resp.get("error"):
        return None
    text = (resp.get("text") or "").strip()
    return text or None


def _report_template(target: str, scope_desc: str,
                     findings: List[Dict[str, Any]],
                     events: Optional[List[Dict[str, Any]]]) -> str:
    ranked = _rank(findings)
    lines: List[str] = []
    lines.append("# Engagement Report — %s" % (target or "(unknown target)"))
    lines.append("")
    lines.append("## Summary")
    if ranked:
        counts: Dict[str, int] = {}
        for f in ranked:
            s = normalize_severity(f.get("severity"))
            counts[s] = counts.get(s, 0) + 1
        breakdown = ", ".join("%d %s" % (counts[s], s)
                              for s in reversed(("info", "low", "medium",
                                                 "high", "critical"))
                              if counts.get(s))
        lines.append("Automated recon of %s produced %d confirmed finding(s): %s."
                     % (target or "the target", len(ranked), breakdown))
    else:
        lines.append("Automated recon of %s completed. No confirmed findings; "
                     "the attack surface mapped is summarised below."
                     % (target or "the target"))
    lines.append("")
    lines.append("## Scope")
    lines.append(scope_desc or "(scope not recorded)")
    lines.append("")
    lines.append("## Findings")
    if ranked:
        for f in ranked:
            lines.append("")
            lines.append("### %s  (Severity: %s)"
                         % (f.get("title") or "finding",
                            normalize_severity(f.get("severity"))))
            lines.append("- Affected: %s" % (f.get("target") or "(unspecified)"))
            detail = f.get("detail") or f.get("evidence") or ""
            if detail:
                lines.append("- Evidence: %s" % _oneline(detail))
            if f.get("type"):
                lines.append("- Type: %s" % f.get("type"))
            if f.get("url"):
                lines.append("- URL: %s" % f.get("url"))
            if f.get("recommendation"):
                lines.append("- Recommendation: %s" % _oneline(f["recommendation"]))
    else:
        lines.append("No confirmed findings.")
    lines.append("")
    lines.append("## Recon notes")
    note = _recon_note(events)
    lines.append(note or "See the event log for the tools that ran.")
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #
def _rank(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(findings, key=lambda f: severity_rank(f.get("severity")),
                  reverse=True)


def _coerce_candidate(c: Dict[str, Any],
                      default_target: Optional[str] = None) -> Dict[str, Any]:
    if not isinstance(c, dict):
        c = {"title": str(c)}
    out: Dict[str, Any] = dict(c)
    out["title"] = (c.get("title") or c.get("name") or c.get("type")
                    or "finding")
    out["severity"] = normalize_severity(c.get("severity"))
    tgt = c.get("target") or c.get("url") or c.get("endpoint") or default_target
    if tgt:
        out["target"] = tgt
    if not out.get("detail"):
        detail = c.get("detail") or c.get("evidence") or c.get("description")
        if detail:
            out["detail"] = detail
    return out


def _parse_findings_json(text: str) -> Optional[List[Dict[str, Any]]]:
    """Pull a findings list out of a model response. None if unparseable."""
    if not text:
        return None
    raw = text.strip()
    # tolerate ```json fences
    if raw.startswith("```"):
        raw = raw.split("```", 2)
        raw = raw[1] if len(raw) > 1 else text
        if raw.lstrip().lower().startswith("json"):
            raw = raw.lstrip()[4:]
    obj = _loads_lenient(raw)
    if obj is None:
        return None
    if isinstance(obj, dict):
        found = obj.get("findings")
        if isinstance(found, list):
            return found
        return None
    if isinstance(obj, list):
        return obj
    return None


def _loads_lenient(text: str) -> Any:
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        pass
    # last resort: carve out the outermost {...} or [...] block
    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        end = text.rfind(closer)
        if 0 <= start < end:
            try:
                return json.loads(text[start:end + 1])
            except (ValueError, TypeError):
                continue
    return None


def _scope_desc(scope: Any) -> str:
    if scope is None:
        return ""
    if isinstance(scope, str):
        return scope
    describe = getattr(scope, "describe", None)
    if callable(describe):
        try:
            return str(describe())
        except Exception:  # noqa: BLE001
            return ""
    return str(scope)


def _recon_note(events: Optional[List[Dict[str, Any]]]) -> str:
    if not events:
        return ""
    tools: List[str] = []
    for ev in events:
        if isinstance(ev, dict) and ev.get("type") == "tool_result":
            name = ev.get("tool")
            summ = ev.get("summary") or ev.get("text") or ""
            if name:
                tools.append("- %s: %s" % (name, _oneline(summ)))
    if not tools:
        return ""
    return "Tools run during the engagement:\n" + "\n".join(tools[:40])


def _oneline(text: Any, limit: int = 300) -> str:
    s = str(text).replace("\n", " ").replace("\r", " ").strip()
    return s[:limit]


__all__ = ["triage", "write_report"]
