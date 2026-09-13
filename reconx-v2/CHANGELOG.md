# Changelog

All notable changes to ReconX v2 will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Username scanner (250+ sites)
- Image EXIF + pHash
- Phone number reconnaissance
- Gmail-specific intelligence
- Web dashboard

## [0.2.0] - 2026-09-13

### Added
- Initial v2 release — Rust rewrite of ReconX
- `reconx-core`: types, errors, `ReconModule` trait, auth context
- `reconx-common`: tracing, audit log, retry helper
- `reconx-breach`: 4 API integrations
  - HIBP (Have I Been Pwned)
  - EmailRep.io
  - BreachDirectory
  - Gravatar
- `reconx-cli`: binary `reconx` with `email` subcommand
- Async parallel scanning via `tokio::join!`
- Risk scoring (0-100) with confidence weighting
- Multi-format output: JSON, CSV, TXT
- Audit logging to `~/.reconx/audit.log`
- Authorization gate (`--self` / `--authorized-for` + `--consent-file`)
- GitHub Actions CI (fmt, clippy, test, build)
- Multi-stage Dockerfile
- 5 unit tests passing
- Zero clippy warnings

### Security
- No plaintext passwords stored (SHA-256 hashed from BreachDirectory)
- All scans require authorization flag

## [0.1.0] - 2026-08-XX (Python v1)

See [root CHANGELOG](../CHANGELOG.md) for v1 history.

[Unreleased]: https://github.com/jude84162-sys/ReconX/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/jude84162-sys/ReconX/releases/tag/v0.2.0
