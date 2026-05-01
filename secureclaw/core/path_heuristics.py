"""Path-only score adjustments (per v1.3-plan-v10 §B.5).

This module is deliberately PURE of match content. It reads
``finding.file_path`` (path string, filename, suffix) and may read
``finding.pattern_id`` for conditional path rules (e.g., "self-ref
penalty does not apply to PI-022 because real credentials in our own
files still matter"). It does NOT read ``finding.matched_text`` or
``finding.file_context``.

Verified by property test ``test_path_heuristics_ignores_match_text``.

Returns ``ScoreAdjustment`` (defined in ``match_quality.py``).
"""

from __future__ import annotations

from secureclaw.core.match_quality import ScoreAdjustment
from secureclaw.core.models import Finding

# Archive / backup / history paths that are stale.
ARCHIVE_INDICATORS = (
    "/archive/",
    "/.specstory/",
    "/backup",
    "/history/",
    "-backup-",
    "/old/",
    "/deprecated/",
    "/legacy/",
)

# Security research content that discusses injections by design.
SECURITY_RESEARCH_INDICATORS = (
    "security-scanner",
    "email-security",
    "prompt-injection",
    "secureclaw",
    "injection-test",
    "attack-",
    "pentest",
    "vulnerability",
    "exploit-",
    "cve-",
)

# Coverage / generated report paths.
GENERATED_INDICATORS = (
    "/coverage/",
    "/lcov-report/",
    "/__generated__/",
    "/dist/",
    "/build/",
    ".min.js",
    ".bundle.",
)

# Active environment files (filename match).
ACTIVE_ENV_NAMES = (".env", ".envrc", ".env.local")

# Dependency lockfiles where credentials in third-party blobs aren't ours.
LOCKFILE_NAMES = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml")


def score_path_heuristics(finding: Finding) -> ScoreAdjustment:
    """Score adjustments based on file_path + pattern_id only.

    Pure function of ``finding.file_path`` (and optionally
    ``finding.pattern_id`` for conditional rules). Does NOT read
    ``matched_text`` or ``file_context`` — those are content-derived
    and live in ``match_quality.py``.
    """
    adj = ScoreAdjustment()
    path_str = str(finding.file_path).replace("\\", "/").lower()

    # --- Boosters ---

    # Active .env / .envrc files (not in archive). Matches by exact filename.
    if finding.file_path.name in ACTIVE_ENV_NAMES:
        if not any(ind in path_str for ind in ARCHIVE_INDICATORS):
            adj.delta += 15
            adj.reasons.append("Active environment file")

    # --- Reducers ---

    # Archive / stale file.
    if any(ind in path_str for ind in ARCHIVE_INDICATORS):
        adj.delta -= 20
        adj.reasons.append("Archive/backup file")
        if finding.pattern_id == "PI-022":
            adj.auto_fixable = True
            adj.fix_action = "redact_credential"

    # Security research / scanner code (discusses injections by design).
    if any(ind in path_str for ind in SECURITY_RESEARCH_INDICATORS):
        adj.delta -= 25
        adj.reasons.append("Security research content")
        adj.auto_fixable = True
        adj.fix_action = "allowlist"

    # Generated / coverage reports.
    if any(ind in path_str for ind in GENERATED_INDICATORS):
        adj.delta -= 20
        adj.reasons.append("Generated/coverage file")
        if finding.pattern_id == "PI-022":
            adj.auto_fixable = True
            adj.fix_action = "redact_credential"

    # Self-referential (SecureClaw's own rules/examples). Real creds in our
    # own files still matter, so PI-022 is exempt from the demotion.
    if "secureclaw" in path_str and finding.file_path.suffix in (".py", ".json"):
        if finding.pattern_id != "PI-022":
            adj.delta -= 35
            adj.reasons.append("SecureClaw self-reference")
            adj.auto_fixable = True
            adj.fix_action = "allowlist"

    # n8n workflow backups.
    if "n8n" in path_str and path_str.endswith(".json"):
        adj.delta -= 15
        adj.reasons.append("n8n workflow backup")

    # Package-lock / node lockfiles.
    if finding.file_path.name in LOCKFILE_NAMES:
        adj.delta -= 30
        adj.reasons.append("Dependency lockfile")
        adj.auto_fixable = True
        adj.fix_action = "allowlist"

    return adj
