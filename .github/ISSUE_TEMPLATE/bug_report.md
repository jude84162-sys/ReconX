---
name: Bug report
about: Create a report to help us improve
title: '[BUG] '
labels: bug
assignees: ''
---

## Describe the bug

A clear and concise description of what the bug is.

## To reproduce

Steps to reproduce the behavior:

1. Run `reconx username <target>` (or the equivalent `reconx -u <target>`)
2. See error

## Expected behavior

What you expected to happen.

## Actual behavior

What actually happened. Include the full error messages / traceback.

## Environment

- **OS**: [e.g. Ubuntu 22.04, Windows 11, macOS 14]
- **Python version**: [output of `python --version`, e.g. 3.12.4]
- **ReconX version**: [output of `reconx --version`, e.g. v1.4.0]
- **Install method**: [e.g. `pip install -e .`, `pip install reconx`]
- **Command run**: [e.g. `reconx -d example.com -t 15 --verbose`]

Valid commands: `username`, `domain`, `ip`, `list`, plus the module flags
`--fedifinder`, `--fediverse-observer`, `--fediverse-osint`, `--masto`,
`--inflact`, `--osintgram`. Run `reconx --list` for the full list.

## Additional context

Any other context, screenshots, or configuration.

**Note:** Do NOT include API keys, `.session`/`.token` files, or personal data.
