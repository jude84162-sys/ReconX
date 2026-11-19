# ReconX-GUI

A web-based GUI for the ReconX 38-tool recon & vulnerability suite — the
graphical, more powerful sibling of `cli.py`. Pure Python **standard library**:
no Flask, no pip install, runs anywhere Python 3.8+ exists (Kali / WSL / Termux
/ macOS / Linux).

```bash
python3 server.py
# → opens http://127.0.0.1:8777 in your browser
```

Options:

```bash
python3 server.py --port 9000 --host 0.0.0.0 --no-browser
```

## Two backends, automatic

- **Standalone (default):** ~20 tools are implemented in self-contained stdlib
  scanners (`engine/builtins.py`) — DNS, subdomains (crt.sh), port scan,
  fingerprint, SSL/TLS, WAF, dir/login/param discovery, bounty quick-checks,
  reflected XSS, error-based SQLi, SSTI, SSRF/cloud-metadata, GraphQL
  introspection, open-redirect, CORS, live host probe. Works with zero setup.
- **Full 38 tools:** drop this `reconx_gui/` folder **inside your ReconX repo**
  (next to `cli.py` / `recon.py` / `modules/`). The bridge (`engine/bridge.py`)
  auto-detects `modules.*` and drives your real engines — the GUI calls the exact
  same functions `cli.py` does, streaming their output live. Each tool's badge
  shows `mod` (ReconX module) / `built-in` / `n/a`.

## What's more powerful than the CLI

- Concurrent scans with a **live-streaming console** (Server-Sent Events).
- **Findings view** — results ranked by severity (critical→info) as cards.
- **Scan history** — reopen any past scan, replay its log, re-download.
- **One-click JSON export** (also saved to `outputs/`).
- Per-tool **danger levels** (passive / active / intrusive) with dots + tags.
- An explicit **Authorization gate**: active/intrusive tools won't run until you
  flip the *Authorized* switch and note your scope. Keep it honest — only test
  targets you're permitted to.

## Layout

```
reconx_gui/
  server.py            # stdlib HTTP + SSE server (entrypoint)
  engine/
    http_client.py     # dependency-free HTTP (urllib)
    builtins.py        # standalone stdlib scanners
    registry.py        # the 38-tool catalog (metadata + input forms)
    bridge.py          # adapters to the real ReconX modules.* when present
    jobs.py            # threaded job manager + live log fan-out
  web/
    index.html         # single-page UI
    static/app.js      # frontend logic (vanilla JS)
  outputs/             # exported JSON reports
```

## Safety / scope

This drives active security tooling. Every active/intrusive tool is gated behind
the Authorization switch and labelled. Use it **only** against systems you own or
are explicitly authorized to test (your bug-bounty program scope, a signed
engagement, your lab). You are responsible for staying in scope.
