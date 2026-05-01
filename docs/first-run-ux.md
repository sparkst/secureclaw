# First-Run & Error UX

> Foundation deliverable per v1.3-plan-v10 Section O / REQ-9.20.
> This document is the source of truth for the copy text, layout, and
> deep-link behavior of every first-run, zero-findings, error, and
> Gatekeeper state. Implementations in `secureclaw/gui.py` and
> `secureclaw/reporters/html_report.py` MUST match the copy here verbatim;
> the vocab CI lint (`tests/test_no_jargon_in_rules.py`) enforces the
> banned-term list against the rendered output.

## Copy principles (Lauren persona)

- **Plain language, not jargon.** Replacements per the vocab table
  (`v1.3-plan-v10 §H.2`) and Section P user-test results.
- **Concrete next-step affordance per state.** Never leave the user
  guessing what to do.
- **One-liner explanation, expandable for the curious.**
- **No technical reasons in user-facing copy.** Technical reason → server log;
  user-facing copy → branched by reason class (`v1.3-plan-v10 §H.4`).

---

## 1. Landing page

**Trigger**: first GUI launch (no scan yet) or after `secureclaw gui` from CLI.

**Layout**:

```
┌─────────────────────────────────────────────────────┐
│  SecureClaw                              About →    │
│─────────────────────────────────────────────────────│
│                                                     │
│         🛡️                                           │
│                                                     │
│   SecureClaw scans your local files for hidden      │
│   instructions that could hijack your AI tools.    │
│                                                     │
│   Pick a folder to start.                           │
│                                                     │
│   [ Choose folder… ]                                │
│                                                     │
│   or paste a folder path:                           │
│   [ ~/Documents/                              ]     │
│                                                     │
│   Quick options:                                    │
│   • ~/Desktop  • ~/Documents  • ~/Downloads         │
│   • ~/.claude (Claude Code projects)                │
│                                                     │
│   Your files stay on your machine. SecureClaw       │
│   never uploads anything.                           │
│                                                     │
└─────────────────────────────────────────────────────┘
```

**Wireframe**: see `docs/wireframes/first-run-landing.svg` (committed in this PR).

**Required ARIA semantics**:

- Top container is `<main role="main">`.
- "Choose folder…" button is `<button>` with `aria-describedby` pointing to the privacy line.
- Path input is `<input type="text" aria-label="Folder path">` with autocomplete on the quick-option list.
- Quick option chips are `<button>` not `<a>` (they trigger the picker, not a navigation).

**Reviewer**: ≥1 non-technical reader sign-off before v1.3.0 release per N DoD.

---

## 2. Zero-findings state

**Trigger**: scan completes, ZERO findings in any tier.

**Copy**:

```
✅ Your files look clean
We didn't find anything that looks like an attempt to hijack
your AI tools. Nice work.

What's next?
• Scan another folder →
• Schedule a weekly scan →   (v1.3.2 feature; gray out for v1.3.0)
• See what SecureClaw checks for →
```

**Tone**: positive reinforcement, not defensive. Avoid "no threats detected"
(jargon) and "all good" (dismissive). "Your files look clean" is the
calibrated phrasing per Section P testing.

**Required affordances**:

- "Scan another folder" returns to the landing page.
- "Schedule a weekly scan" is grayed-out in v1.3.0 with a tooltip
  "Coming in v1.3.2 — schedule SecureClaw to run automatically."
- "See what SecureClaw checks for" opens `/glossary` in a new tab.

---

## 3. Permission-denied states

**Trigger**: macOS Files & Folders sandbox denied access to a folder
(Documents, Desktop, Downloads, iCloud Drive, ~/Movies, etc.).

**Detection**: per-folder check via `os.access(path, os.R_OK)` before scan
starts; surface the full list of blocked folders in one summary screen.

### macOS Sequoia 15.x

**Copy** (when blocked folder is `~/Documents`):

```
🔒 macOS needs your permission to scan Documents

To scan this folder, SecureClaw needs Files & Folders
access for Documents.

Steps:
1. Open System Settings → Privacy & Security → Files and Folders
2. Find SecureClaw in the list
3. Toggle "Documents Folder" on

[ Open System Settings → ]   [ Skip this folder ]
```

**Deep-link target**: `x-apple.systempreferences:com.apple.preference.security?Privacy_FilesAndFolders`

### macOS 26 (Tahoe)

**Copy**: same as 15.x; the System Settings layout is identical for the
Files & Folders pane in 26. Deep-link target is unchanged.

### Per-folder phrasing

| Folder | Specific copy |
|---|---|
| `~/Documents` | "scan Documents" + "Documents Folder" toggle |
| `~/Desktop` | "scan Desktop" + "Desktop Folder" toggle |
| `~/Downloads` | "scan Downloads" + "Downloads Folder" toggle |
| iCloud Drive | "scan iCloud Drive" + "iCloud Drive" toggle |
| `~/Movies` | "scan Movies" + "Movies Folder" toggle |
| `~/Music` | "scan Music" + "Music Folder" toggle |
| `~/Pictures` | "scan Pictures" + "Pictures Folder" toggle |
| Other | "scan this folder" + "(folder name) Folder" toggle |

---

## 4. Mid-run error states

**Trigger**: scan started successfully but an individual file or batch
fails. Scan continues; per-file errors aggregate into a summary.

### Single-file unreadable (permissions / corruption / device)

**Per-file message in the report**:

> SecureClaw couldn't open this file (permission denied). [Try Re-scan]

### Disk full mid-write (only relevant if user is using auto-fix)

**Modal copy**:

```
⚠️ Not enough disk space
SecureClaw was about to write a backup but ran out of room.
No files were changed. Free up some space and try again.

[ Open Storage Settings ]   [ Cancel ]
```

### Symlink in chain (REQ-17)

**Per-finding 403 copy** (already covered in §H.4 of plan v10):

> Part of this file's path is a shortcut. We can't show shortcuts safely.
>
> [ Open in Finder ]

### Mid-run cancellation

**Copy** (when user clicks Cancel during scan):

```
Stopping… [ ⏳ ]

(Once cancelled:)
Scan stopped. Showing N files we got to before you cancelled.
[ Resume ]   [ Start over ]
```

---

## 5. Huge-folder pre-warning

**Trigger**: pre-scan walk shows file count > 5000 (default; configurable
via `~/.secureclaw/config.json` `huge_folder_warn_threshold`).

**Modal copy**:

```
This folder has 12,847 files
Scanning could take a couple of minutes. SecureClaw runs entirely on
your computer, so it won't slow down your network.

[ Continue scanning ]   [ Pick a smaller folder ]   [ Cancel ]
```

**Threshold default**: 5000 (from R5-UX P1 fix; configurable per v8 §H.6).

---

## 6. Gatekeeper first-launch

**Trigger**: user double-clicks SecureClaw.app for the first time.

macOS shows the system-controlled "Apple cannot check it for malware" dialog.
We can't replace this; we *can* ship documentation that the user finds
before they delete the app in confusion.

**`first-launch.html`** (bundled in the DMG, opens automatically when DMG is
mounted via `bless` or referenced in the DMG `.background`):

```
Welcome to SecureClaw

You're seeing this page because macOS asks for permission the first
time you open any app from outside the App Store.

What you'll see:

  ┌────────────────────────────────┐
  │  "SecureClaw.app" can't be     │
  │  opened because Apple cannot   │
  │  check it for malicious        │
  │  software.                     │
  │                                │
  │  [ Move to Bin ]   [ Done ]    │
  └────────────────────────────────┘

  Click Done. Then:

  1. Open System Settings → Privacy & Security
  2. Scroll down to Security
  3. Click "Open Anyway" next to SecureClaw

  You'll only see this dialog once. After that SecureClaw
  opens like any other app.

Why does this happen?
SecureClaw is signed with an "ad-hoc" signature, not an Apple
Developer ID certificate. We're working on the Developer ID
upgrade for a future release; until then, the Open Anyway
dance is a one-time step.
```

**Wireframe**: see `docs/wireframes/first-launch-gatekeeper.svg` (placeholder
in this PR; final SVG ships when DMG packaging lands in v1.3.2).

---

## 7. Verification per macOS version

For each macOS major version we support (currently 15 Sequoia and 26 Tahoe):

| State | macOS 15.x verified | macOS 26.x verified |
|---|---|---|
| Landing page renders | ✅ via Safari + Chrome | ✅ via Safari + Chrome |
| Files & Folders deep-link works | _verify per release_ | _verify per release_ |
| Open Anyway flow | _verify per release_ | _verify per release_ |
| Trash semantics (`send2trash`) | _verify per release_ | _verify per release_ |

**Verification protocol per release**: physically click through each state
on a real Mac running each major version. Failure = block release. Tracked
in the release sign-off PR (PR-N).

---

## 8. ARIA / accessibility checklist

Per REQ-9.12 (WCAG 2.1 AA):

- All interactive elements have `aria-label` or visible text label.
- State changes use `aria-live="polite"` (or `aria-live="assertive"` for
  errors).
- Focus management on modals: focus trapped while open; first focusable
  element receives focus on open; previous focus restored on close.
- Skip-link on `/view`.
- All triage badges include text + color + SVG icon (no color-only).
- CI gate: `pa11y` or `axe-core` on the rendered HTML; fails on any
  WCAG 2.1 AA violation.

---

## 9. Sign-off

Foundation DoD requires:

- [ ] ≥1 non-technical reader signs off on landing-page copy.
- [ ] ≥1 non-technical reader signs off on permission-denied per-folder copy
      (specifically: does each "Open System Settings" deep-link land where
      they expect?).
- [ ] ≥1 non-technical reader signs off on Gatekeeper first-launch copy.

Sign-offs recorded in PR-A6's sibling PR or directly in this file via PR
comment chain. Reader pool tracked in `tests/ux/reviewer-roster.md` (created
in PR-A8 when the UX research foundation lands).
