"""Confidence scoring and triage for findings.

Assigns each finding a confidence score (0-100) and triage tier
(ACT_NOW / REVIEW / SUPPRESSED) based on heuristics about the file path,
match content, and context.
"""

from __future__ import annotations

import re
from typing import List

from secureclaw.core.models import FileContext, Finding, Triage

# Real credential prefixes — these are almost certainly live secrets
REAL_TOKEN_PREFIXES = (
    "sk-ant-",
    "sk-proj-",
    "sk-",
    "ghp_",
    "gho_",
    "ghs_",
    "github_pat_",
    "glpat-",
    "xoxb-",
    "xoxp-",
    "AKIA",
    "eyJ",
    "AIza",
    "r8_",
    "hf_",
    "Bearer ",
)

# Placeholder values that are NOT real credentials
PLACEHOLDER_PATTERNS = re.compile(
    r"(not[_-]configured|your[_-]token|your[_-]key|xxx+|test[_-]secret|"
    r"fake[_-]|example[_-]|placeholder|changeme|TODO|REPLACE_ME|"
    r"insert[_-]|put[_-]your|sk-your|ghp_your|<your|dummy)",
    re.IGNORECASE,
)

# Archive / backup / history paths that are stale
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

# Security research content that discusses injections
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

# Coverage / generated report paths
GENERATED_INDICATORS = (
    "/coverage/",
    "/lcov-report/",
    "/__generated__/",
    "/dist/",
    "/build/",
    ".min.js",
    ".bundle.",
)


def score_finding(finding: Finding) -> Finding:
    """Score a single finding and assign triage tier."""
    score = 50  # baseline
    reasons: list[str] = []
    auto_fixable = False
    fix_action = ""
    path_str = str(finding.file_path).lower()
    match_lower = finding.matched_text.lower()

    # --- Boosters (increase confidence = more likely real) ---

    # Real credential with known prefix
    if finding.pattern_id == "PI-022":
        # Extract the value after the = or :
        for prefix in REAL_TOKEN_PREFIXES:
            if prefix.lower() in match_lower:
                score += 40
                reasons.append(f"Real token prefix ({prefix.rstrip()})")
                auto_fixable = True
                fix_action = "redact_credential"
                break
        # Placeholder check
        if PLACEHOLDER_PATTERNS.search(finding.matched_text):
            score -= 45
            reasons.append("Placeholder/test value")
            auto_fixable = True
            fix_action = "allowlist"

    # Active .env / .envrc files (not in archive)
    if any(finding.file_path.name == n for n in (".env", ".envrc", ".env.local")):
        if not any(ind in path_str for ind in ARCHIVE_INDICATORS):
            score += 15
            reasons.append("Active environment file")

    # --- Reducers (decrease confidence = more likely noise) ---

    # Test fixtures
    if finding.file_context == FileContext.TEST_FIXTURE:
        score -= 30
        reasons.append("Test fixture")
        auto_fixable = True
        fix_action = "allowlist"

    # AI config
    if finding.file_context == FileContext.AI_CONFIG:
        score -= 20
        reasons.append("AI config file")

    # Archive / stale file
    if any(ind in path_str for ind in ARCHIVE_INDICATORS):
        score -= 20
        reasons.append("Archive/backup file")
        if finding.pattern_id == "PI-022":
            auto_fixable = True
            fix_action = "redact_credential"

    # Security research / scanner code (discusses injections by design)
    if any(ind in path_str for ind in SECURITY_RESEARCH_INDICATORS):
        score -= 25
        reasons.append("Security research content")
        auto_fixable = True
        fix_action = "allowlist"

    # Generated / coverage reports
    if any(ind in path_str for ind in GENERATED_INDICATORS):
        score -= 20
        reasons.append("Generated/coverage file")
        if finding.pattern_id == "PI-022":
            auto_fixable = True
            fix_action = "redact_credential"

    # Self-referential (SecureClaw's own rules/examples)
    if "secureclaw" in path_str and finding.file_path.suffix in (".py", ".json"):
        if finding.pattern_id != "PI-022":  # Real creds in secureclaw files still matter
            score -= 35
            reasons.append("SecureClaw self-reference")
            auto_fixable = True
            fix_action = "allowlist"

    # n8n workflow backups
    if "n8n" in path_str and path_str.endswith(".json"):
        score -= 15
        reasons.append("n8n workflow backup")

    # Package-lock / node lockfiles
    if finding.file_path.name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
        score -= 30
        reasons.append("Dependency lockfile")
        auto_fixable = True
        fix_action = "allowlist"

    # PI-027 (self-reference) is very noisy
    if finding.pattern_id == "PI-027":
        if "source" in match_lower and "self" in match_lower:
            score -= 30
            reasons.append("'Source: self' citation pattern")
            auto_fixable = True
            fix_action = "allowlist"

    # Clamp score
    score = max(0, min(100, score))

    # Assign triage tier
    if score >= 60:
        triage = Triage.ACT_NOW
    elif score >= 30:
        triage = Triage.REVIEW
    else:
        triage = Triage.SUPPRESSED

    finding.confidence = score
    finding.confidence_reason = "; ".join(reasons) if reasons else "Baseline"
    finding.triage = triage
    finding.auto_fixable = auto_fixable
    finding.fix_action = fix_action

    return finding


def score_findings(findings: List[Finding]) -> List[Finding]:
    """Score all findings and sort by confidence (highest first within each tier)."""
    for f in findings:
        score_finding(f)

    # Sort: ACT_NOW first, then REVIEW, then SUPPRESSED. Within tier, highest confidence first.
    tier_order = {Triage.ACT_NOW: 0, Triage.REVIEW: 1, Triage.SUPPRESSED: 2}
    findings.sort(key=lambda f: (tier_order[f.triage], -f.confidence, f.severity.sort_key))

    return findings
