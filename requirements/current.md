# SecureClaw Requirements

## Active

### REQ-001: Simple Report Mode
- The default HTML report mode presents a traffic-light verdict, finding cards with plain-English descriptions, and action buttons
- Acceptance: Non-technical user can determine safety status in under 5 seconds
- Status: In progress (v2 interactive features partially implemented)

### REQ-002: Detailed Report Mode
- `--report-mode detailed` produces a table-based report with filtering, confidence scores, and full technical context
- Acceptance: All v1 information is accessible; filtering works
- Status: In progress (migrated from tabbed to table layout)

### REQ-003: Mac App Packaging
- Native .app bundle via PyInstaller, ad-hoc signed, distributed as DMG with drag-to-Applications
- Acceptance: App launches on macOS Sequoia after Gatekeeper bypass; runs scan and produces report
- Status: Working (tools/build_mac_app.sh)

### REQ-004: Cross-Platform CLI
- `secureclaw` CLI works on Python 3.9–3.13 across Linux, macOS, Windows
- Acceptance: CI green on all 15 matrix cells (3 OS x 5 Python)
- Status: Complete

### REQ-005: Standalone Single-File Distribution
- `tools/build_standalone.py` produces a single `secureclaw.py` with SHA256 checksum
- Acceptance: `python secureclaw.py scan <path>` works without pip install
- Status: Complete

## Backlog

### REQ-006: Move Website to Separate Repo
- The `site/` directory (Cloudflare Workers) needs to move to either its own GitHub repo or into sparkry-website
- Status: TODO
