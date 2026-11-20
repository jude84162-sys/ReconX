"""The Scorpion brain: the Claude Messages API client and the agent prompts.

    Brain               — stdlib-only Anthropic Messages client (no SDK)
    SYSTEM_PROMPT       — the main agent's methodology + safety prompt
    TRIAGE_PROMPT       — the triage sub-agent's prompt
    REPORT_PROMPT       — the report-writer sub-agent's prompt
    build_* helpers     — compose prompts with per-engagement context
"""
from __future__ import annotations

from .claude import Brain
from .prompts import (
    SEVERITIES,
    SYSTEM_PROMPT,
    TRIAGE_PROMPT,
    REPORT_PROMPT,
    build_system_prompt,
    build_triage_prompt,
    build_report_prompt,
)

__all__ = [
    "Brain",
    "SEVERITIES",
    "SYSTEM_PROMPT",
    "TRIAGE_PROMPT",
    "REPORT_PROMPT",
    "build_system_prompt",
    "build_triage_prompt",
    "build_report_prompt",
]
