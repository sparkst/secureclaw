"""Content-only score adjustments (per v1.3-plan-v10 §B.5).

This module is deliberately PURE of file-path inputs. Any signal that
depends on where the file lives goes in ``path_heuristics.py``. Any
signal that depends on the matched content, pattern_id, or
file_context (a content-derived classifier) lives here.

The split is verified by property tests in ``test_score_decomposition.py``.

Returns ``ScoreAdjustment`` — a structured tuple of the score delta plus
metadata (reasons, auto_fixable flag, fix_action). The caller composes
match-quality + path-heuristics adjustments and assigns the final triage
tier.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from secureclaw.core.credentials import PLACEHOLDER_PATTERNS, REAL_TOKEN_PREFIXES
from secureclaw.core.models import FileContext, Finding


@dataclass
class ScoreAdjustment:
    """A score adjustment from a single scoring layer.

    Attributes:
        delta: integer to add to the baseline (can be negative).
        reasons: human-readable reason strings (one per signal that fired).
        auto_fixable: True if any rule fired that can be auto-fixed.
        fix_action: which fix to apply (``"redact_credential"``, ``"allowlist"``).
    """

    delta: int = 0
    reasons: List[str] = field(default_factory=list)
    auto_fixable: bool = False
    fix_action: str = ""


def score_match_content(finding: Finding) -> ScoreAdjustment:
    """Score adjustments based on match content + file_context only.

    Pure function of ``finding.pattern_id``, ``finding.matched_text``, and
    ``finding.file_context``. Does NOT read ``finding.file_path`` — that
    lives in ``path_heuristics.py``. Property test
    ``test_match_quality_ignores_path`` enforces this.
    """
    adj = ScoreAdjustment()
    match_lower = finding.matched_text.lower()

    # --- Boosters ---

    # Real credential with known prefix (PI-022 only).
    if finding.pattern_id == "PI-022":
        for prefix in REAL_TOKEN_PREFIXES:
            if prefix.lower() in match_lower:
                adj.delta += 40
                adj.reasons.append(f"Real token prefix ({prefix.rstrip()})")
                adj.auto_fixable = True
                adj.fix_action = "redact_credential"
                break
        # Placeholder check (overrides boost; sets allowlist as fix).
        if PLACEHOLDER_PATTERNS.search(finding.matched_text):
            adj.delta -= 45
            adj.reasons.append("Placeholder/test value")
            adj.auto_fixable = True
            adj.fix_action = "allowlist"

    # --- Reducers ---

    # Test fixtures (file_context is a content-derived classifier).
    if finding.file_context == FileContext.TEST_FIXTURE:
        adj.delta -= 30
        adj.reasons.append("Test fixture")
        adj.auto_fixable = True
        adj.fix_action = "allowlist"

    # AI config files.
    if finding.file_context == FileContext.AI_CONFIG:
        adj.delta -= 20
        adj.reasons.append("AI config file")

    # PI-027 self-reference noise: 'source: self' citation pattern.
    if finding.pattern_id == "PI-027":
        if "source" in match_lower and "self" in match_lower:
            adj.delta -= 30
            adj.reasons.append("'Source: self' citation pattern")
            adj.auto_fixable = True
            adj.fix_action = "allowlist"

    return adj
