# 🦂 Scorpion.ai

An autonomous recon / bug-bounty agent built on the ReconX modules. You give it
a target in scope; it plans, runs the recon and vulnerability tools, reads the
results, decides what to do next, and reports — with a live web dashboard,
Telegram alerts, and voice.

> **Authorized testing only.** Scorpion refuses any target outside the scope you
> declare. You are responsible for having permission to test what you point it at.

## How it's built

```
scorpion/
  config.py      runtime config from env / .env (no hard-coded secrets)
  scope.py       the Scope Guard — fail-closed allow/deny list (every tool checks it)
  ratelimit.py   polite per-host token bucket
  tools/         the ReconX modules wrapped as 14 LLM-callable tools
  brain/         Claude API client + prompts (stdlib urllib, no SDK)
  agent.py       orchestrator: plan -> call tool -> observe -> decide -> report
  planner.py     deterministic fallback pipeline when no API key is set
  memory.py      per-engagement state + findings, saved to disk
  subagents.py   triage + report-writer helper agents
  notify/        Telegram + voice (TTS)
  server.py      the stdlib web dashboard (the GUI)
```

The **brain** is a Claude model (set `ANTHROPIC_API_KEY`). Without a key, Scorpion
still runs in **deterministic-planner mode** — it executes a sensible recon
pipeline, just without the model deciding the next step.

## Quick start

```bash
cp .env.example .env         # then edit .env
#   ANTHROPIC_API_KEY=...    (optional — planner mode works without it)
#   SCORPION_SCOPE=example.com,*.example.com    (REQUIRED to scan anything)
#   TELEGRAM_BOT_TOKEN=... TELEGRAM_CHAT_ID=...  (optional)

python3 -m scorpion          # dashboard at http://127.0.0.1:8778
```

Reach the dashboard from your laptop over an SSH tunnel — never expose it:

```bash
ssh -L 8778:127.0.0.1:8778 user@server
```

## Scope (the Scope Guard)

Every tool call is checked before a single packet is sent. The scope is
**fail-closed**: empty scope blocks everything.

| entry | matches |
|---|---|
| `example.com` | the apex **and** every subdomain |
| `*.example.com` / `.example.com` | subdomains only |
| `app.example.com` | that host (and its subdomains) |
| `203.0.113.10` | one IP |
| `203.0.113.0/24` | a CIDR range |

Deny entries (`SCORPION_SCOPE_DENY`) always win.

## Voice

Scorpion speaks high/critical findings. It uses whatever local engine exists
(`piper`, `espeak`/`espeak-ng`, or macOS `say`) and sends Telegram voice notes.
On a headless server with no audio it degrades silently to text.

## Tests

```bash
python3 -m unittest discover -s scorpion/tests -t . -v
```

All tests bind to loopback only and never touch the real internet or the real
Claude / Telegram APIs.
