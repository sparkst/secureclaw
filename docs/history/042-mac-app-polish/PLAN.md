# Execution Plan: SecureClaw Native Mac App - Professional Polish & Packaging. Build a polished native macOS app experience for non-tech users. Current state: bare arm64 binary in a DMG with no .app bundle, no icon, no drag-to-Applications, and a scan GUI that doesn't match the marketing site branding (secureclaw.sparkry.ai). Requirements: (1) Proper .app bundle with icon - the SC from the secureclaw-logo wordmark together in Sparkry Orange makes a nice app icon (2) Universal binary arm64+x86_64 so it works on Intel and Apple Silicon Macs (3) Professional DMG with drag-to-Applications (4) Ad-hoc code signing with clear right-click-Open instructions (5) GUI redesign matching secureclaw.sparkry.ai branding - charcoal #1b1b1b background, orange #E8751A accent, base64-embedded secureclaw-logo.png wordmark (6) Tooltips and in-app help throughout for non-tech users like Lauren who found CLI scary (7) Update HTML report branding to match. Source: single Python file at projects/019-prompt-injection-attacks/secureclaw/dist/secureclaw.py. PyInstaller spec at projects/019-prompt-injection-attacks/secureclaw/SecureClaw.spec. Marketing site reference: secureclaw.sparkry.ai. Plan document with detailed exploration already at /Users/travis/.claude/plans/snug-percolating-fern.md

### Task T-001: User sees SecureClaw logo in both GUI and report (base64 embed)
- **Files**: secureclaw/gui.py, secureclaw/reporters/html_report.py
- **Acceptance**: Logo visible in scan GUI header and report header
- **Tests needed**: No

### Task T-002: User never sees 'prompt injection' — all copy is plain language
- **Files**: secureclaw/gui.py, secureclaw/reporters/html_report.py
- **Acceptance**: String 'prompt injection' appears nowhere in user-facing GUI or report
- **Tests needed**: No

### Task T-003: User sees branded charcoal/orange scan interface matching marketing site
- **Files**: secureclaw/gui.py
- **Depends on**: T-001
- **Acceptance**: Scan GUI visually matches secureclaw.sparkry.ai color scheme
- **Tests needed**: No

### Task T-004: User confirms folder + sees file count before scan starts
- **Files**: secureclaw/gui.py
- **Depends on**: T-003
- **Acceptance**: User can select folder, see confirmation with file count, then start scan
- **Tests needed**: No

### Task T-005: Non-technical user understands every screen without help
- **Files**: secureclaw/gui.py
- **Depends on**: T-003
- **Acceptance**: All 5 states have contextual help text
- **Acceptance**: (?) popover opens and closes
- **Tests needed**: No

### Task T-006: User knows what to do with every finding in the report
- **Files**: secureclaw/reporters/html_report.py
- **Depends on**: T-002
- **Acceptance**: Every finding has actionable What to do section
- **Tests needed**: No

### Task T-007: Report branding matches scan GUI — unified charcoal/orange palette
- **Files**: secureclaw/reporters/html_report.py
- **Depends on**: T-001
- **Acceptance**: Report opens with same charcoal/orange palette as scan GUI
- **Tests needed**: No

### Task T-008: User can share scan results via email/Slack as plain text
- **Files**: secureclaw/reporters/
- **Depends on**: T-006
- **Acceptance**: .txt file appears next to HTML report after scan
- **Tests needed**: No

### Task T-009: Standalone secureclaw.py rebuilt with all changes and verified
- **Files**: tools/build_standalone.py, dist/secureclaw.py
- **Depends on**: T-003, T-004, T-005, T-006, T-007, T-008
- **Acceptance**: GUI launches with branded interface
- **Acceptance**: CLI scan command works
- **Acceptance**: SHA256SUMS generated
- **Tests needed**: No

### Task T-010: SecureClaw has a proper app icon in Finder and Dock
- **Files**: assets/SC-icon.png, assets/SecureClaw.icns
- **Acceptance**: SecureClaw.icns exists and shows SC lettermark at all sizes
- **Tests needed**: No

### Task T-011: Build environment ready for PyInstaller with Python 3.12
- **Acceptance**: pyinstaller --version runs in build venv
- **Tests needed**: No

### Task T-012: SecureClaw builds as macOS binary via PyInstaller
- **Files**: SecureClaw.spec
- **Depends on**: T-009, T-010, T-011
- **Acceptance**: Binary runs and file command shows architecture info
- **Tests needed**: No

### Task T-013: User can drag SecureClaw.app to Applications and double-click to launch
- **Files**: tools/build_mac_app.sh, tools/Info.plist
- **Depends on**: T-012
- **Acceptance**: Double-click .app opens browser GUI with no Terminal window
- **Tests needed**: No

### Task T-014: User downloads professional DMG and installs in 30 seconds
- **Files**: tools/build_mac_app.sh
- **Depends on**: T-013
- **Acceptance**: Mount DMG shows branded window with drag-to-Applications layout
- **Acceptance**: SHA256SUMS published alongside DMG
- **Tests needed**: No

### Task T-015: User knows how to handle Gatekeeper and understands privacy guarantee
- **Files**: secureclaw/gui.py
- **Depends on**: T-013
- **Acceptance**: Instructions visible in DMG
- **Acceptance**: Privacy statement in help popover
- **Acceptance**: Zero network connections stated
- **Tests needed**: No

### Execution Order

1. [T-001, T-010, T-011] parallel (worktree isolation)
2. [T-002] solo
3. [T-003, T-006] parallel (worktree isolation)
4. [T-004, T-007, T-008] parallel (worktree isolation)
5. [T-005] solo
6. [T-009] solo
7. [T-012] solo
8. [T-013] solo
9. [T-014, T-015] parallel (worktree isolation)

### Quality Gate

```
npm run test
```
