"""Scorpion.ai — an autonomous bug-bounty / recon agent built on the ReconX modules.

The package is layered so each piece can be tested in isolation:

    config   — runtime configuration from env / .env (never hard-codes secrets)
    scope    — the Scope Guard: every target is checked against an allow-list (fail-closed)
    ratelimit— polite per-host token bucket shared by all tools
    tools/   — the ReconX modules wrapped as LLM-callable tools (uniform ToolResult)
    brain/   — the Claude API client + tool-use loop (stdlib urllib, no SDK)
    agent    — the orchestrator: plan -> call tool -> observe -> decide -> report
    memory   — engagement state + findings, persisted to disk
    subagents— helper agents (triage, report writer)
    notify/  — Telegram + voice notifications
    server   — the stdlib web dashboard (the agent's GUI)

Nothing here speaks to the network until a Scope is set, and the Scope is
empty (allows nothing) unless the operator configures it.
"""

__version__ = "0.1.0"
NAME = "Scorpion.ai"

__all__ = ["__version__", "NAME"]
