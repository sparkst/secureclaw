# PLAN: SecureClaw HTML Report Redesign for Non-Technical Users

## Overview

Redesign the SecureClaw HTML findings report from a tabbed developer dashboard into a single-page vertical scroll optimized for Lauren (non-tech TV/film producer). The existing report remains available as `--report-mode detailed`.

**Estimate:** 3 SP coding / 8 SP planning scale

## Architecture

### New Report Mode: "simple" (default)

Single-page scroll replacing the 3-tab dashboard:

```
HEADER (compact: logo + title + date)
HERO VERDICT (72px traffic light circle + headline + subtext)
SUMMARY COUNTS (2 cards: Need Action Now / Worth Reviewing)
FINDINGS (grouped by triage tier, suppressed hidden)
  --- Needs Action Now (N) ---
  [Finding Cards: plain English first, technical detail behind <details>]
  --- Worth Reviewing (N) ---
  [Finding Cards...]
SECURITY CHECKLIST (collapsed <details>)
GET HELP (Share with IT email / Fix with Claude Code prompt)
FOOTER (version, scan metadata)
```

### Key Design Decisions

1. **Dispatcher pattern**: `format_html_report(result, mode="simple")` routes to `_simple` or `_detailed`
2. **No shared f-string template**: Each mode has its own complete HTML generation to avoid cross-mode bugs
3. **Reuse helpers**: `_icon()`, `_e()`, `_WTD_TEXT`, `_CATEGORY_LABELS`, `_TRIAGE_CSS` shared between modes
4. **Progressive disclosure**: Plain English for Lauren, `<details>` toggles for IT contact
5. **Native HTML**: `<details>/<summary>` for collapsible sections (no JS needed, accessible by default)

## Tasks

| ID | Summary | SP | Depends |
|----|---------|-----|---------|
| T-001 | Write failing tests for simple-mode (TDD red phase) | 0.3 | - |
| T-002 | Add --report-mode CLI arg + dispatcher | 0.2 | - |
| T-003 | Build traffic-light hero verdict | 0.2 | T-002 |
| T-004 | Build simplified finding cards | 0.5 | T-002 |
| T-005 | Build 'Get Help' section (email + Claude Code handoff) | 0.5 | T-004 |
| T-006 | Build posture checklist + assemble complete page | 0.8 | T-003, T-004, T-005 |
| T-007 | Integration test + visual QA | 0.3 | T-006 |

**Total: 2.8 SP coding**

## Files to Change

| File | Changes |
|------|---------|
| `secureclaw/reporters/html_report.py` | Add `format_html_report_simple()`, new helpers, dispatcher |
| `secureclaw/cli.py` | Add `--report-mode` argument |
| `tests/test_reporters.py` | Add `TestHTMLSimpleReport` + `TestHTMLDetailedMode` |

## Acceptance Criteria

1. `secureclaw scan . --format html` generates single-page scroll (no tabs, no filters)
2. `--report-mode detailed` generates unchanged tabbed dashboard
3. Traffic-light hero as first visual element
4. Finding cards: "What to do" visible, technical detail behind "For IT" toggle
5. Suppressed findings completely absent from simple mode
6. "Share with IT" with mailto + "Fix with Claude Code" with copyable prompt
7. Posture as collapsed checklist
8. Self-contained HTML, XSS-safe, all tests pass

## Risks

| Risk | Mitigation |
|------|------------|
| f-string complexity (doubled template) | Separate functions per mode, shared helpers |
| mailto body length limits | Truncate to top-3 findings |
| Breaking existing consumers | --report-mode detailed preserves exact output |
