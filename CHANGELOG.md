# Changelog

All notable changes to ReconX will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The canonical version is `__version__` in `reconx/__init__.py`.

## [Unreleased]

### Known follow-ups
- **Promote the CI lint job from advisory to blocking.** `black`, `isort`,
  `flake8` and `bandit` currently report without failing the build because the
  codebase predates formatter adoption. Run `black .` and `isort .` once, clear
  the `flake8` output, then drop the `continue-on-error` lines in
  `.github/workflows/ci.yml` and add the job to branch protection.
- **Wire the email breach module into the CLI.** `reconx/modules/email.py` is
  fully implemented but has no entry point, so it is currently dead code.
- Backfill tags for v1.1.0–v1.4.0 (only `v1.0.0` was ever tagged).

## [1.5.0] - 2026-09-15

### Added
- **Restored the six Fediverse and Instagram modules** (`fedifinder`,
  `fediverse_observer`, `fediverse_osint`, `masto`, `inflact`, `osintgram`)
  that commit `11495f2` ("Fix failing CI build") deleted along with their CLI
  wiring, while leaving their tests behind. `reconx list` advertised features
  that could no longer be imported.
- **Email breach intelligence returns to Python v1** as
  `reconx/modules/email.py`: async HIBP/EmailRep queries, k-anonymity password
  checking, automated risk scoring, incident-response link generation, and
  Telegram alerting. Library only for now — no CLI entry point.
- `.github/PULL_REQUEST_TEMPLATE.md`, `.github/CODEOWNERS` and
  `docs/REVIEW_GUIDELINES.md` describing the review process.
- `tests/test_email_module.py` covering secret redaction, `Retry-After`
  parsing, and the session-purge safety rules.

### Changed
- **CI now runs the Python test suite** on Python 3.10–3.13. The previous
  workflow ran `cargo fmt`/`clippy`/`test` with `working-directory: ./reconx-v2`,
  a directory that does not exist in this repository, so CI could never pass
  and `pytest` never ran at all.
- **Minimum Python is now 3.10** (3.8 and 3.9 reached end of life). Updated
  `requires-python`, package classifiers and black's `target-version` to match.
- **The version is now a single source of truth.** `pyproject.toml` reads
  `__version__` from `reconx/__init__.py` via `[tool.setuptools.dynamic]`; the
  banner in `reconx/utils/output.py` interpolates it instead of hardcoding it.
  Previously the three places disagreed (1.2.0 / 1.4.0 / 1.4.0).
- Advertised counts are derived from code rather than hardcoded, so they cannot
  drift again: the username module reports `len(SITES)` (536) instead of "100+"
  or "250+".
- The bug report template now asks for a Python version and OS instead of a
  Rust version, and documents commands that actually exist.

### Fixed
- **Security:** `reconx/modules/email.py` did not compile — an unquoted string
  in a `logger.warning` call made the entire module unimportable.
- **Security:** `purge_local_sessions()` recursively deleted any
  `.json`/`.key`/`.cache`/`.token`/`.session` file whose contents contained the
  target's bare email local-part, and defaulted to sweeping `$HOME/.config` and
  the current working directory. It now requires the full address, skips
  symlinks, and refuses to run without an explicit directory allowlist.
- **Security:** TLS certificate verification was disabled in the username
  lookup and the domain header/tech-detection requests.
- **Security:** Telegram bot tokens and target addresses were written to logs;
  they are now redacted. User input is percent-encoded before use in URLs and
  escaped before entering Rich or Telegram markup.
- **Security:** declared the undeclared runtime dependencies `aiohttp` and
  `beautifulsoup4`, which the code imported but neither manifest listed.
- Addressed Bandit B324 properly with `hashlib.sha1(..., usedforsecurity=False)`
  rather than adding it to the skip list, since SHA-1 is required by the Pwned
  Passwords k-anonymity protocol and is not used as a security primitive.
- `Retry-After` headers in HTTP-date form no longer raise `ValueError`, and
  rate-limited responses are released back to the connection pool.

## [1.4.0]

### Added
- Masto, Inflact, and Osintgram integrations with legal-use disclaimers.

## [1.3.0]

### Added
- Fedifinder, Fediverse Observer, and Fediverse OSINT modules.
- Flag and subcommand interfaces for the new Fediverse tools.

## [1.2.0] - 2026-09-14 (Python v1)

### Added
- Username scanner: **250+ → 500+ sites** (+150 new platforms)
  - Search engines, professional networks, education
  - Gaming, music, photography, blogging
  - Crypto/NFT, sports, podcasts, fediverse
  - Asian platforms, dating, niche communities
- Bumped version to 1.2.0

### Changed
- Email module moved to v2 (Rust)
  - Removed `reconx/modules/email.py`
  - Removed `-e/--email` flag from CLI
  - Use `reconx-v2` for email breach intelligence

### Removed
- `reconx/modules/email.py`

> **Note:** the v2 (Rust) track was abandoned; email intelligence was restored
> to v1 in 1.5.0 with a fresh async implementation.

## [1.0.0] - 2026-08-XX

### Added
- Initial release
- Username scanner (250+ sites)
- Email reconnaissance
- Domain intelligence
- IP profiling
