# Concept Synthesis — SecureClaw Native Mac App

**Sources:** Lauren (persona), Marcus (persona), Business Advisor, UI/UX Designer
**Date:** 2026-03-04

---

## P0 — Critical (Must address before building)

### CS-P0-1: Gatekeeper / Code Signing (Lauren P0, Marcus P0, Business P1)
**Consensus: 3/4 reviewers flagged this as critical.**

Ad-hoc signing means Gatekeeper blocks the app with "unidentified developer" warning. For a security tool targeting non-technical users, this is a trust contradiction. Lauren will delete it. Marcus cannot distribute it. Business advisor says it's prerequisite before any marketing spend.

**PO Decision Required:** The $99 Apple Developer ID was deferred in IDEATION ("ship ad-hoc, purchase if promising"). All reviewers disagree — they say it's a P0 prerequisite, not a nice-to-have. However, PO has already decided to ship ad-hoc first with clear instructions, then invest in signing if traction proves out.

**Compromise:** Ship ad-hoc for beta/Lauren testing. Include branded instruction card in DMG explaining right-click > Open. Defer public marketing launch until Developer ID is acquired.

### CS-P0-2: Report Brand Unification (UI Designer P0)
**Already in scope** — PO moved this to MVP. Three palettes (navy GUI, coral report, charcoal marketing) must be unified to charcoal/orange before ship.

### CS-P0-3: Folder Confirmation Before Scan (UI Designer P0)
After folder selection, show path + file count + time estimate before scanning starts. Prevents wrong-folder scans, sets expectations. New "State 1b: Confirm" screen. ~0.5 SP addition.

---

## P1 — Important (Should address in v1)

### CS-P1-1: Jargon Audit — "Prompt Injection" Must Not Appear (Lauren P1, high confidence)
Every visible string in both GUI and report must be audited. "Prompt injection" → "hidden AI threat" or "hidden instruction." Consistent vocabulary everywhere: threat, hidden instruction, manipulated file. The glossary tooltip helps but does not substitute for plain language in primary content.

### CS-P1-2: PDF or Plain-Text Report Export (Lauren P1, Marcus P1)
HTML reports don't travel in Lauren's world (can't email, can't attach to Slack). Marcus needs something for Jira tickets and compliance trails.

**Minimum viable:** Plain-text summary (.txt) alongside HTML. PDF can wait for v2. Low implementation cost, high workflow impact.

### CS-P1-3: SHA256 Checksum for Download Integrity (Marcus P0 → synthesis P1)
Publish SHA256SUMS alongside DMG. Security-conscious users (Marcus) need to verify before distributing. Anchors the "auditable" claim. Already partially exists in the build pipeline.

### CS-P1-4: "What to Do" Sections Are the Differentiator (UI Designer P1, Lauren P1)
Every finding needs: what it is, why it matters, how to fix it — in that order, in plain English. This is the single feature most likely to change user behavior. Write copy targeting Lauren's comprehension level.

### CS-P1-5: Define Consulting Product Before Launch (Business Advisor P1)
One-page description of what a "full AI security review" includes, price range, engagement structure. Must exist before first inbound inquiry arrives.

### CS-P1-6: Accessibility — Focus Management + Keyboard Nav (UI Designer P1)
State transitions must move focus. Drop zone needs role="button". Accordions need aria-expanded. Progress bar needs role="progressbar" + aria attributes.

### CS-P1-7: Scan Time Estimate Must Be Measured (Lauren P2, Marcus P1, UI Designer P1)
Use actual throughput measurement, not heuristic. Recalculate every 2 seconds. Last 10 seconds switch to "Almost done..." Pair with "X of Y files" counter for liveness signal.

---

## P2 — Suggestions (Defer to v1.1+)

### CS-P2-1: Scan History / Past Scan Log (Lauren P1 → synthesis P2)
Lauren wants this but it adds persistence, data model, and new UI surface. Compromise: add "last scanned on [date]" watermark in report header. Defer full history to v2.

### CS-P2-2: Auto-Update Notification (Lauren P2)
In-app "new version available" notification. Not silent auto-update. Deferred.

### CS-P2-3: App Sandbox + Entitlements (Marcus P1 → synthesis P2)
Sandboxing with user-selected.read-only entitlement. Good security hygiene but adds build complexity and may conflict with PyInstaller. Defer unless Developer ID signing is pursued.

### CS-P2-4: Reproducible Build Pipeline (Marcus P1 → synthesis P2)
Published requirements.txt with hashes, reproducible build.sh, GitHub Actions provenance. Important for Marcus's "is this safe?" answer but not blocking MVP.

### CS-P2-5: No Network Activity Disclosure (Marcus P2)
State explicitly: "SecureClaw makes zero network connections." Add to README and in-app help.

### CS-P2-6: Trade Press Placement as Launch Vehicle (Business Advisor P1 → synthesis P2)
One story in Deadline/Ad Age worth more than 10K GitHub downloads. Defer to post-MVP marketing phase.

### CS-P2-7: Calendly → Landing Page (Business Advisor P2)
Add intermediate page between report CTA and booking. Decision-makers need context before committing calendar time.

---

## Changes to IDEATION Based on Synthesis

| # | Change | Source | Impact |
|---|--------|--------|--------|
| 1 | Add folder confirmation screen (State 1b) with path + file count + time estimate | UI Designer | +0.5 SP |
| 2 | Add plain-text report export (.txt alongside HTML) | Lauren + Marcus | +0.3 SP |
| 3 | Full jargon audit: replace "prompt injection" everywhere with plain language | Lauren | +0.2 SP |
| 4 | Add SHA256SUMS alongside DMG download | Marcus | +0.1 SP |
| 5 | Add "last scanned" timestamp to report header | Lauren compromise | +0.1 SP |
| 6 | State "zero network connections" in README + in-app help | Marcus | +0.05 SP |

**Revised estimate:** Original 4.3 SP + 1.25 SP additions = **~5.5 SP**
