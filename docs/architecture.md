# SecureClaw Architecture

> Concise architectural reference. Detailed per-component docs live alongside the code (`secureclaw/core/*.py` docstrings).

## Core pipeline

```
raw bytes
  → [P1] file-type detect
  → enter normalize_loop(text, depth=0):
        [P2]    strip invisibles (Tag block + zero-width + variation selectors)
        [P3]    NFKC normalize
        [P4]    HTML entity decode
        [P3.5]  template-token whitespace collapse
        [P5]    base64/hex/rot13 candidate detection (recursive, capped)
        return cleaned text + maps
  → [P6] structural region parsing (file-type aware, three-tier streaming-lite)
  → regions[(text, region_kind, file_type, invisible_char_map, homoglyph_map)]
  → [M1] route patterns to regions via applies_to + region_kinds tags
  → [M2] regex match (compiled patterns; runtime timeout via regex library)
  → [M3] sentence-boundary co-occurrence check for multi-token rules
matches[]
  → [S1-S4] match-quality scoring (no path inputs)
  → [S5] path heuristics (no content inputs)
findings → composite confidence with two-tier veto rule → dedupe → emit
```

Detail per stage in `secureclaw/core/*.py`.

## Module map

| Path | Role |
|---|---|
| `secureclaw/cli.py` | CLI entry; `scan`, `posture`, `fix`, `gui`, `dev` subcommands |
| `secureclaw/core/models.py` | Dataclasses: `Finding`, `Pattern`, `ScanResult`, `Severity`, etc. |
| `secureclaw/core/scanner.py` | File walker; orchestrates pipeline per file |
| `secureclaw/core/patterns.py` | Pattern engine (current); v1.3 splits into `match_quality.py` + region routers |
| `secureclaw/core/confidence.py` | Path-only scoring (becomes `path_heuristics.py` post-A3) |
| `secureclaw/core/normalize.py` | Invisible-char + NFKC + decode pipeline (NEW v1.3) |
| `secureclaw/core/parsers/` | Structural region parsers (markdown, html, email, py-ast) (NEW v1.3) |
| `secureclaw/core/match_quality.py` | Content-only match scoring (NEW v1.3) |
| `secureclaw/core/credentials.py` | Single-source-of-truth `REAL_TOKEN_PREFIXES` (NEW v1.3) |
| `secureclaw/core/safe_regex.py` | Runtime regex with timeout + quarantine (NEW v1.3) |
| `secureclaw/core/safe_trash.py` | send2trash wrapper with lstat-walk (NEW v1.3) |
| `secureclaw/legacy/v1_engine.py` | Frozen pre-v1.3 engine for `SECURECLAW_ENGINE=v1` (NEW v1.3) |
| `secureclaw/posture/analyzer.py` | AI tool security posture |
| `secureclaw/reporters/` | Output formatters (terminal, html, json, text) |
| `secureclaw/rules/default_rules.json` | Pattern catalog |
| `secureclaw/rules/categories.json` | Category registry (NEW v1.3) |
| `secureclaw/sync/` | Upstream rule sync IR + adapters (NEW v1.3.2) |
| `secureclaw/dev/` | Internal CLI subcommands (NEW v1.3) |

## Confidence scoring

```
match_quality = clamp(0, 100, sum_of_S1_to_S4)
path_modifier = clamp(-50, +50, S5)
candidate_final = clamp(0, 100, match_quality + path_modifier)

# Veto rules (REQ-1.4):
#   1. NO finding may enter "Needs Action" tier (≥75) unless
#      match_quality ≥ 50 AND candidate_final ≥ 75
#      AND NOT (file_context in {test_fixture, security_research, archive})
#   2. NO finding may enter "Worth a Look" tier (≥40) unless match_quality ≥ 25
#   3. Findings with match_quality < 25 are "Minor" regardless of path strength
```

Calibration: deterministic exhaustive grid search; container-canonical baseline.

## Engine dispatcher

`secureclaw/__init__.py` reads `SECURECLAW_ENGINE` env var (canonicalized via
`_canonical_engine_setting`); falls back to `~/.secureclaw/config.json` `engine`
field; default `"default"`. When `legacy` is selected, the dispatcher routes to
`secureclaw/legacy/v1_engine.py` AND emits a banner per REQ-18.

## Runtime dependencies

- `regex==2024.11.6` — Unicode property classes + per-match timeout.
- `send2trash>=1.8,<2.0` — cross-platform recoverable delete.

stdlib otherwise.

## Detailed design

For deep dives:

- `docs/state.md` — state-storage strategy.
- `docs/runners.md` — federated CI infrastructure.
- `docs/contributing-rules.md` — how to add a detection rule (Foundation deliverable).
- `docs/security.md` — security model + CVE response.
- `docs/release.md` — release procedure + rollback.
- `docs/dev-cli.md` — `secureclaw dev` reference.
