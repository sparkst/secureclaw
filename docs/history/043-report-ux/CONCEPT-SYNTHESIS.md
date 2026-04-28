# CONCEPT-SYNTHESIS

## Consolidated Findings from 4 Reviewers (Lauren Persona, Usability Expert, Business Advisor, UI Designer)

## P0 — Critical (unanimous across reviewers)

1. **Kill the tab bar** — Replace with single-page scroll. Tabs hide content, confuse navigation, and force Lauren to guess which tab matters. (Lauren, Usability, UI Designer)

2. **Remove filter toolbar** — 5 dropdowns + search + CSV export = developer power-user pattern. Lauren will never use any of it. Hide behind optional disclosure. (Lauren, Usability)

3. **Gate fix instructions** — "pip install secureclaw" and terminal commands displayed prominently to a non-developer is the highest-friction moment. Frame as "For IT" or hide behind disclosure. (Lauren, Usability)

4. **Add "Share with IT" / Claude Code handoff** — Lauren's #1 need is handing off to someone who can fix it. Provide: pre-written email, structured findings file, and Claude Code prompt. (Lauren, Business, UI Designer)

5. **Remove confidence percentage from card face** — "87%" is meaningless noise. Use qualitative labels only ("Likely real") or remove entirely. (Lauren, Usability, UI Designer)

## P1 — Important

6. **Flip finding card structure** — Lead with plain-English "What to do" (currently hidden behind toggle). Move technical detail (pattern name, badges, matched text) behind "Show details for IT". (Lauren, Usability, UI Designer)

7. **Traffic-light hero verdict** — Full-width, large icon, plain English headline ("2 files need your attention now"). Current verdict card is good but buried under header/tabs/stats. (UI Designer, Lauren)

8. **Remove triage jargon** — "Act Now (HIGH)" / "Suppressed" are internal terms. Use colored dots + plain labels. (Lauren, Usability)

9. **Hide suppressed findings completely** — Even dimmed at 70% opacity, "suppressed" sounds scary. Show only in IT detail view. (Lauren, Usability, User decision: confirmed)

10. **Rename "Security Posture" tab** — Merge into main page as collapsed "Your AI Tool Settings" checklist. (Lauren, Usability, UI Designer)

11. **Scope Claude Code prompt conservatively** — Only high-confidence findings. If it breaks something, Lauren blames SecureClaw. (Business Advisor)

## P2 — Suggestions

12. **Keep current report as --report-mode detailed** — Preserves engineer experience. (User decision: confirmed)
13. **Consider light theme** — Dark theme reads as "developer tool" to non-tech users. (Lauren)
14. **Truncate browser tab title** — Full filesystem path in <title> leaks info when shared. (Lauren)
15. **Move scan metadata to footer** — "Files scanned", "Patterns checked" are instrumentation, not action items. (UI Designer)
16. **Add "What is this report?" banner** — One-time collapsible intro for first-time recipients. (Usability)
