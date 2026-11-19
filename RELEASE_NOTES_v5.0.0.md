# ReconX v5.0.0 — Advanced Scanners & Attack Surface

**38 recon and vulnerability-assessment tools** in one interface, stdlib-first,
for Termux, Kali and WSL.

## Highlights

- **38 tools, up from 15** in v4.1.0, organized into 11 sections in `cli.py`.
- **10 advanced scanners:** GraphQL introspection/batching, API/Swagger fuzzing,
  mass assignment, BOLA/IDOR mapping, race conditions, deserialization,
  XXE & LFI, cloud metadata SSRF, bucket permissions, and headless DOM XSS.
- **Shared analysis engine** (`modules/utils/http_client.py`): a differential
  response analyzer (semantic similarity, DOM structure, reflection context)
  plus a WAF-evasion mutation engine that retries blocked payloads with
  URL/double-URL/hex/Unicode/entity/comment encodings.
- **Live host probing** (`modules/web/live_probe.py`): httpx/httprobe-style
  liveness checks with status, title, server, content-type, redirect chain and
  TLS protocol for every discovered host.
- **Screenshot gallery** (`modules/web/aquatone_clone.py`): aquatone-style
  captures via Playwright or headless Chrome, with authenticated captures
  through `--header` / `--cookie` (values never printed or stored).
- **Attack Surface & Vuln Fuzzer** (`modules/web/attack_surface.py`): crt.sh and
  Wayback collection, parameter triage, leak fuzzing, optional Tor SOCKS5.
- **Diagnostics:** `doctor.py` (self-healing checks for structure, imports and
  connectivity) and `fix_attack_surface.py` (idempotent integration auditor).
- **Documentation:** new `SOURCES.md` documenting every external API, resolver,
  optional tool and bundled signature set; README rewritten around 38 tools.
- **Tests:** `tests/` — a stdlib `unittest` suite of 32 cases, loopback-only and
  offline, replacing the old `test_all_tools.py` script.

## Web GUI

`reconx_gui/` ships in this release line: a stdlib HTTP + SSE server with a
38-tool registry matching `cli.py`'s numbering and a bridge that drives the real
`modules.*` engines (all 38 bind to a module when the folder sits at the repo
root), with standalone builtin scanners as a fallback. It adds a live-streaming
console, severity-ranked findings, replayable scan history, JSON export, and an
*Authorized* switch plus scope note gating active and intrusive tools.

```bash
python reconx_gui/server.py        # → http://127.0.0.1:8777
```

## Version consistency

All version strings are now `5.0.0`: `modules/__init__.py`,
`modules/vuln/__init__.py`, `recon.py --version` and its banner, the attack
surface banner, the HTML report footer, the doctor user agent, and the README.

## Upgrade notes

- `python -m unittest discover -s tests -t . -v` replaces `test_all_tools.py`.
- No new mandatory dependencies — still Python 3.8+ stdlib only. Playwright and
  Chromium remain optional, needed for DOM XSS and screenshot capture.
- `requirements.txt` lists only the pre-existing optional extras.

## Accuracy and scope

The README publishes per-tool accuracy estimates rather than a blanket claim;
treat them as guidance and verify critical findings manually. Several advanced
modules send crafted objects, XML entities and repeated requests — some tests
are state-changing. Use only against systems you own or have explicit written
permission to test.
