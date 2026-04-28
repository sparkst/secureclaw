# SecureClaw — Claude Code Guidelines

> Cross-platform prompt injection scanner for AI tool users.
> Python 3.9+, MIT licensed, published as `secureclaw` on PyPI.

---

## Project Overview

SecureClaw scans files for prompt injection attacks targeting AI tools (Cursor, Copilot, Claude Code, etc.). It produces terminal, HTML, JSON, and text reports with simple and detailed modes. It ships as:

- **CLI tool** (`secureclaw scan`, `secureclaw posture`, `secureclaw fix`, `secureclaw allowlist`)
- **Standalone single-file** (`tools/build_standalone.py` → `dist/secureclaw.py`)
- **Native Mac app** (`tools/build_mac_app.sh` → PyInstaller `.app` bundle in `.dmg`)

## Quick Reference

```bash
# Dev setup
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Quality gates (must all pass before commit)
ruff check secureclaw/ tests/
ruff format --check secureclaw/ tests/
python -m pytest tests/ -v --tb=short

# Run the scanner
secureclaw scan <path> --format html --report-mode simple -o report.html
secureclaw --version
```

## Architecture

```
secureclaw/
├── cli.py              # Argument parsing, subcommands
├── core/               # Scanner engine, models, confidence scoring
├── posture/            # Security posture assessment
├── reporters/          # Output formatters (terminal, html, json, text)
├── rules/              # Detection rule definitions (JSON)
└── __init__.py         # Version: __version__ = "X.Y.Z"

tests/                  # Co-located by module: test_scanner.py, test_reporters.py, etc.
tools/
├── build_standalone.py # Bundles into single-file dist/secureclaw.py
├── build_mac_app.sh    # PyInstaller + codesign + create-dmg
├── Info.plist          # Mac app metadata
└── READ_FIRST.txt      # First-time user instructions (staged into DMG)

assets/                 # App icons (.icns, .png), DMG background
```

## Development Rules

### Before Coding
- Ask clarifying questions if requirements are ambiguous
- Choose the simplest solution that satisfies the requirement
- Check `requirements/current.md` for active requirements

### While Coding
- **TDD**: Write failing test first, then implement
- Target Python 3.9 — no 3.10+ syntax (walrus in comprehensions, match/case, etc.)
- Keep functions small, use domain vocabulary
- Code explains itself — avoid comments unless the WHY is non-obvious
- `ruff` enforces style: E, F, W, PTH rules, 100-char line length

### Testing
- Tests live in `tests/` mirroring source modules
- Run full suite: `python -m pytest tests/ -v --tb=short`
- CI runs across Python 3.9–3.13 on Linux, macOS, Windows

### Mac App / Standalone Build
- Build script: `tools/build_mac_app.sh` — NEVER bypass with manual hdiutil/codesign
- Ad-hoc signing (`codesign --force --deep -s -`) is REQUIRED for the app to launch
- `create-dmg` produces the professional drag-to-Applications layout
- Standalone build: `python tools/build_standalone.py` → `dist/secureclaw.py` + `dist/SHA256SUMS`

## Version Management

Version lives in two places — keep them in sync:
1. `secureclaw/__init__.py` → `__version__ = "X.Y.Z"`
2. `pyproject.toml` → `version = "X.Y.Z"`

After any version bump, verify both files match before committing.

## CI/CD

GitHub Actions CI runs on every push/PR to `main`:
- Lint: `ruff check` + `ruff format --check`
- Test: pytest across 3 OS x 5 Python versions
- Verify: CLI entry points (`--version`, `scan`, `posture`, `fix`, `allowlist`)

When CI fails, investigate and fix immediately.

## Git

- Repository: `https://github.com/sparkst/secureclaw`
- GitHub account: `sparkst`
- Conventional commits: `feat:`, `fix:`, `test:`, `refactor:`, `docs:`

## General Rules

- Never claim a fix is working until verified end-to-end
- Never fabricate sources, citations, or examples
- After version bumps, verify ALL relevant files before pushing
- When CI fails, proactively investigate and offer fixes

## Story Points

**Baseline:** 1 SP = simple CLI subcommand (tested, documented, CI green)

Scales:
- Planning: 1, 2, 3, 5, 8, 13 (Fibonacci; break >13)
- Coding: 0.05, 0.1, 0.2, 0.3, 0.5, 0.8, 1, 2, 3, 5 (break >5)

All outputs include SP estimates.

## Permissions

- Default: `acceptEdits`
- Narrow scope; deny secrets/dangerous commands
