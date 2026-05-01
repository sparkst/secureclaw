"""Confidence scoring composition + triage tier assignment.

Per v1.3-plan-v10 §B.5/B.6 (PR-A3 decomposition): the actual scoring
logic lives in ``match_quality.py`` (content-only) and
``path_heuristics.py`` (path-only). This module composes them, applies
clamping, and assigns the triage tier.

Backward compatibility: ``REAL_TOKEN_PREFIXES`` and
``PLACEHOLDER_PATTERNS`` are re-exported from
``secureclaw.core.credentials`` (single source of truth per PR-A2).
"""

from __future__ import annotations

from typing import List

from secureclaw.core.credentials import PLACEHOLDER_PATTERNS, REAL_TOKEN_PREFIXES
from secureclaw.core.match_quality import ScoreAdjustment, score_match_content
from secureclaw.core.models import Finding, Triage
from secureclaw.core.path_heuristics import score_path_heuristics

__all__ = [
    "score_finding",
    "score_findings",
    "REAL_TOKEN_PREFIXES",
    "PLACEHOLDER_PATTERNS",
]

# Triage thresholds (preserved from v1.2; v1.3-plan-v10 §B.6 will tune
# these in a follow-up calibration PR with held-out test data).
TIER_ACT_NOW_MIN = 60
TIER_REVIEW_MIN = 30
BASELINE_SCORE = 50


def _merge_fix_action(content_adj: ScoreAdjustment, path_adj: ScoreAdjustment) -> tuple[bool, str]:
    """Combine fix-action signals from content + path layers.

    Content-layer fix actions take precedence (placeholder-detection in the
    content layer should override an archive demotion in the path layer
    when both fire). Falls back to the path layer if content didn't set
    one.
    """
    if content_adj.fix_action:
        return content_adj.auto_fixable, content_adj.fix_action
    if path_adj.fix_action:
        return path_adj.auto_fixable, path_adj.fix_action
    return False, ""


def score_finding(finding: Finding) -> Finding:
    """Score a single finding and assign triage tier.

    Decomposed per §B.5: content-only (match_quality) + path-only
    (path_heuristics) → composite. Mutates ``finding`` in place and
    returns it (back-compat with the v1.2 signature).
    """
    content_adj = score_match_content(finding)
    path_adj = score_path_heuristics(finding)

    score = BASELINE_SCORE + content_adj.delta + path_adj.delta
    score = max(0, min(100, score))

    reasons = content_adj.reasons + path_adj.reasons
    auto_fixable, fix_action = _merge_fix_action(content_adj, path_adj)

    if score >= TIER_ACT_NOW_MIN:
        triage = Triage.ACT_NOW
    elif score >= TIER_REVIEW_MIN:
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
    """Score all findings and sort by confidence (highest first within tier)."""
    for f in findings:
        score_finding(f)

    # Sort: ACT_NOW first, then REVIEW, then SUPPRESSED. Within tier,
    # highest confidence first; ties broken by severity sort_key.
    tier_order = {Triage.ACT_NOW: 0, Triage.REVIEW: 1, Triage.SUPPRESSED: 2}
    findings.sort(key=lambda f: (tier_order[f.triage], -f.confidence, f.severity.sort_key))

    return findings
