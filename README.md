# SecureClaw

**Cross-platform prompt injection scanner for AI tool users.**

Your AI reads your files. Make sure those files aren't trying to hijack it.

Built by [Sparkry AI](https://sparkry.ai) for solo founders who use AI tools like Claude Code, Cursor, and OpenClaw.

---

## Quick Start

```bash
# Install
pip install secureclaw

# Scan your current directory
secureclaw scan .

# Scan specific AI tool directories
secureclaw scan ~/.claude ~/.cursor ~/Documents

# Check your AI tool security posture
secureclaw posture

# Generate an HTML report
secureclaw scan . --format html -o report.html

# JSON output for CI/CD
secureclaw scan . --format json --fail-on-high
```

## Features

- **Zero dependencies** - Pure Python stdlib, runs anywhere Python 3.9+ is installed
- **Cross-platform** - macOS, Linux, Windows with automatic path handling
- **Decode-then-scan** - Strips zero-width Unicode, normalizes NFKC, decodes HTML entities and base64 to catch encoded injections
- **Allowlist system** - Suppress false positives with HMAC-integrity-checked allowlists
- **Auto-remediation** - Redact leaked credentials and suppress false positives automatically
- **Three output formats** - Terminal (with color), self-contained HTML, versioned JSON for CI/CD
- **Documented exit codes** - `0` clean, `1` findings, `2` user error, `3` internal error

## What It Does

SecureClaw scans your files for **28 known prompt injection patterns** across three severity levels:

- **CRITICAL RISK** - Active exfiltration, identity hijacking, jailbreak attempts
- **HIGH RISK** - Instruction overrides, hidden text, credential requests
- **ADVISORY** - Suspicious patterns worth reviewing

It also checks the security posture of your AI tools:
- Claude Code settings, permissions, and MCP servers
- Cursor configuration and rules
- OpenClaw skills and scheduled tasks
- Downloads/Documents for risky scripts
- Browser cache directories

## How It Works

```
                    ┌──────────────────────────────────────────────────────┐
                    │              SecureClaw Architecture                  │
                    └──────────────────────────────────────────────────────┘

    ┌──────────┐    ┌───────────────────────────────────────────────────┐
    │  Target   │    │              Scan Pipeline                        │
    │ Directory │───▶│                                                   │
    │           │    │  ┌─────────┐  ┌──────────┐  ┌────────────────┐   │
    └──────────┘    │  │ File    │  │ Binary   │  │ Encoding       │   │
                    │  │ Walker  │──▶│ Detector │──▶│ Handler        │   │
    ┌──────────┐    │  │(pathlib)│  │(null-byte│  │(utf-8 +        │   │
    │ Allowlist│    │  └─────────┘  │ check)   │  │ errors=replace)│   │
    │  (JSON + │    │               └──────────┘  └───────┬────────┘   │
    │   HMAC)  │    │                                     │            │
    └────┬─────┘    │              Decode-then-Scan Pipeline            │
         │         │  ┌──────────┐  ┌──────────┐  ┌──────┴───────┐    │
         │         │  │ Strip    │  │ Unicode  │  │ HTML Entity  │    │
         │         │  │ Zero-    │──▶│ NFKC     │──▶│ Decode       │    │
         │         │  │ Width    │  │ Normalize│  │              │    │
         │         │  │ Chars    │  │          │  └──────┬───────┘    │
         │         │  └──────────┘  └──────────┘         │            │
         │         │                          ┌──────────▼─────────┐  │
         │         │                          │  Pattern Engine     │  │
         │         │                          │  28 rules (JSON)    │  │
         │         │                          │  + Base64 decode    │  │
         │         │                          └──────────┬─────────┘  │
         │         │                                     │            │
         │         │  ┌──────────┐  ┌──────────┐  ┌─────▼──────┐     │
         └────────▶│  │ Allowlist│──▶│  Dedup   │──▶│  Sort by   │     │
                   │  │ Filter  │  │ (file +  │  │  Severity  │     │
                   │  │         │  │  line +  │  │            │     │
                   │  │         │  │  pattern)│  │            │     │
                   │  └──────────┘  └──────────┘  └─────┬──────┘     │
                   │                                     │            │
                   └─────────────────────────────────────┼────────────┘
                                                         │
                    ┌────────────────────────────────────┼────────────┐
                    │              Reporters              │            │
                    │                                     ▼            │
                    │  ┌──────────┐  ┌──────────┐  ┌──────────┐      │
                    │  │ Terminal │  │   HTML    │  │   JSON   │      │
                    │  │ (ANSI   │  │ (Self-    │  │ (Schema  │      │
                    │  │  auto-  │  │ contained │  │  v1 for  │      │
                    │  │  detect)│  │ + Sparkry │  │  CI/CD)  │      │
                    │  │         │  │  branded) │  │          │      │
                    │  └──────────┘  └──────────┘  └──────────┘      │
                    └─────────────────────────────────────────────────┘

                    ┌──────────────────────────────────────────────────┐
                    │          Security Posture Analyzer                │
                    │                                                   │
                    │  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
                    │  │ Claude   │  │ Cursor   │  │ OpenClaw │       │
                    │  │ Code     │  │ AI       │  │          │       │
                    │  │ ─settings│  │ ─rules   │  │ ─skills  │       │
                    │  │ ─MCP     │  │ ─MCP     │  │ ─cron    │       │
                    │  │ ─perms   │  │ ─config  │  │ ─config  │       │
                    │  └──────────┘  └──────────┘  └──────────┘       │
                    │                                                   │
                    │  ┌──────────┐  ┌──────────┐                      │
                    │  │Downloads │  │ Browser  │                      │
                    │  │Documents │  │  Cache   │                      │
                    │  │(scripts) │  │ (Chrome, │                      │
                    │  │          │  │  Firefox,│                      │
                    │  │          │  │  Edge)   │                      │
                    │  └──────────┘  └──────────┘                      │
                    └──────────────────────────────────────────────────┘


    ┌──────────────────────────────────────────────────────────────────┐
    │                    Attack Vectors Detected                        │
    ├──────────────────────────────────────────────────────────────────┤
    │                                                                  │
    │  CRITICAL RISK (immediate danger)                                │
    │  ├── PI-001  Ignore Previous Instructions                        │
    │  ├── PI-002  New Identity Assignment (DAN, jailbreak)            │
    │  ├── PI-003  System Prompt Extraction                            │
    │  ├── PI-004  Data Exfiltration via URL                           │
    │  ├── PI-005  Markdown Image Exfiltration                         │
    │  ├── PI-006  Tool/Function Call Manipulation                     │
    │  ├── PI-007  MCP Server Manipulation                             │
    │  ├── PI-008  Command Execution Injection                         │
    │  ├── PI-009  Jailbreak Keywords (DAN, developer mode)            │
    │  ├── PI-022  Exposed API Keys/Credentials                        │
    │  ├── PI-024  Indirect Injection (AI-addressed instructions)      │
    │  └── PI-028  Webhook/Callback Injection                          │
    │                                                                  │
    │  HIGH RISK (review soon)                                         │
    │  ├── PI-010  Instruction Boundary Delimiters                     │
    │  ├── PI-011  Output Format Manipulation                          │
    │  ├── PI-012  Prompt Leaking via Repetition                       │
    │  ├── PI-013  Hidden Text via CSS/HTML                            │
    │  ├── PI-014  Unicode Direction Override                          │
    │  ├── PI-015  Credential/Secret Request                           │
    │  ├── PI-016  File System Access Injection                        │
    │  ├── PI-017  Multi-step Injection Chain                          │
    │  ├── PI-018  Encoded Payload Marker                              │
    │  ├── PI-019  Conversation History Manipulation                   │
    │  ├── PI-020  Excel Formula Injection (CellShock)                 │
    │  └── PI-023  Model-specific Prompt Tokens                        │
    │                                                                  │
    │  ADVISORY (review when convenient)                               │
    │  ├── PI-021  AI Safety Bypass Language (hypothetical framing)    │
    │  ├── PI-025  Prompt Injection in Comments                        │
    │  ├── PI-026  Environment Variable Exfiltration                   │
    │  └── PI-027  Recursive Self-Reference Injection                  │
    │                                                                  │
    └──────────────────────────────────────────────────────────────────┘


    ┌──────────────────────────────────────────────────────────────────┐
    │                    Cross-Platform Support                         │
    ├──────────────────────────────────────────────────────────────────┤
    │                                                                  │
    │  macOS        Linux         Windows                              │
    │  ──────       ──────        ────────                             │
    │  pathlib      pathlib       pathlib (auto \ -> /)                │
    │  ANSI color   ANSI color    ANSI detection + fallback            │
    │  UTF-8        UTF-8         errors='replace' for cp1252          │
    │  chmod 600    chmod 600     (permission checks skipped)          │
    │  /Library     /etc          C:\Windows (system dirs)             │
    │  brew install apt install   python.org installer                 │
    │                                                                  │
    │  Python 3.9+  Python 3.9+  Python 3.9+                          │
    │  pip install   pip install  pip install                          │
    │  Zero deps    Zero deps    Zero deps                             │
    │                                                                  │
    └──────────────────────────────────────────────────────────────────┘
```

## Commands

### `secureclaw scan`

Scan files and directories for prompt injection patterns.

```bash
secureclaw scan .                                   # Scan current directory
secureclaw scan ~/Documents ~/Downloads             # Scan multiple directories
secureclaw scan . --format html -o report.html      # HTML report
secureclaw scan . --format json -o report.json      # JSON report for CI/CD
secureclaw scan . --severity critical               # Only critical findings
secureclaw scan . --fail-on-high --no-posture       # CI/CD mode
```

### `secureclaw posture`

Check the security posture of your AI tools (Claude Code, Cursor, OpenClaw).

```bash
secureclaw posture
secureclaw posture /path/to/project
```

### `secureclaw fix`

Auto-remediate findings from a previous scan report. Safe actions include redacting leaked credentials and adding false positives to the allowlist.

By default, `fix` runs in **dry-run mode** (preview only). Add `--apply` to actually modify files.

```bash
# Step 1: Generate a JSON scan report
secureclaw scan . --format json -o report.json

# Step 2: Preview what would be fixed (dry run)
secureclaw fix report.json

# Step 3: Apply the fixes
secureclaw fix report.json --apply

# Fix only "act_now" tier findings (default)
secureclaw fix report.json --apply --tier act_now

# Fix all auto-fixable findings regardless of tier
secureclaw fix report.json --apply --tier all
```

### `secureclaw allowlist`

Manage the allowlist of suppressed findings. Allowlist files are stored at `.secureclaw/allowlist.json` with HMAC integrity checking to detect tampering.

```bash
# Suppress a specific finding
secureclaw allowlist add --file "*.md" --pattern PI-001 --reason "Legitimate AI instruction file"

# View all suppressions
secureclaw allowlist list

# Remove a suppression
secureclaw allowlist remove --file "*.md" --pattern PI-001
```

## CI/CD Integration

```yaml
# GitHub Actions example
- name: Scan for prompt injections
  run: |
    pip install secureclaw
    secureclaw scan . --format json --fail-on-high --no-posture
```

Exit codes: `0` = clean, `1` = findings above threshold, `2` = error.

## Project Structure

```
secureclaw/
├── secureclaw/
│   ├── cli.py              # CLI entry point (argparse)
│   ├── core/
│   │   ├── models.py       # Finding, ScanResult, Severity dataclasses
│   │   ├── scanner.py      # File walker, binary detection, encoding
│   │   ├── patterns.py     # Pattern engine + decode-then-scan pipeline
│   │   └── allowlist.py    # Allowlist with HMAC integrity
│   ├── reporters/
│   │   ├── terminal.py     # ANSI color with auto-detection
│   │   ├── html_report.py  # Self-contained branded HTML
│   │   └── json_report.py  # Versioned JSON schema for CI/CD
│   ├── posture/
│   │   └── analyzer.py     # Claude Code, Cursor, OpenClaw posture checks
│   └── rules/
│       └── default_rules.json  # 28 detection patterns
├── tests/
├── pyproject.toml          # Python packaging (hatchling)
└── README.md
```

## License

MIT License - Copyright (c) 2026 Sparkry AI

---

Built with field-tested systems by [Sparkry AI](https://sparkry.ai) - Your Solo Founder's AI Advantage.
