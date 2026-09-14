# Changelog

All notable changes to ReconX will be documented in this file.

## [Unreleased]

### Added
- Added modern `username`, `domain`, `ip`, and `list` CLI subcommands.
- Preserved the existing flag-based CLI syntax for backward compatibility.

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
- **Email module moved to v2 (Rust)**
  - Removed `reconx/modules/email.py`
  - Removed `-e/--email` flag from CLI
  - Use `reconx-v2` for email breach intelligence

### Removed
- `reconx/modules/email.py`

## [1.0.0] - 2026-08-XX

### Added
- Initial release
- Username scanner (250+ sites)
- Email reconnaissance
- Domain intelligence
- IP profiling
