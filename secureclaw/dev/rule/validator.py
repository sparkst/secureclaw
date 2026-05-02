"""Validate every rule in ``default_rules.json`` (spec §6.3, §9.5).

Returns ALL :class:`RuleValidationError` items (no bail-on-first). Existing
rules with ``license_chain_audited: true`` are grandfathered for attribution
and test-pair checks; ``strict_attribution=True`` removes that exemption.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from secureclaw.dev.corpus.loader import load_fixtures
from secureclaw.dev.rule.models import RuleValidationError
from secureclaw.dev.rule.schema import validate_rule


def _is_first_party(license_str: str) -> bool:
    lower = license_str.lower()
    return lower.startswith("synthetic") or "(own work)" in lower


def _has_positive(corpus_root: Path, rule_id: str) -> bool:
    """Positive fixtures: the PR-C pattern_id filter (which inspects
    expected_findings) is the right tool here."""
    fixtures = load_fixtures(corpus_root, klass="positive", pattern_id=rule_id)
    return len(fixtures) > 0


def _has_negative(corpus_root: Path, rule_id: str) -> bool:
    """Negative fixtures: PR-C's pattern_id filter only inspects
    expected_findings; we need a post-filter on ``forbidden_findings``
    instead. This is the P1 fix from the spec review.
    """
    all_negs = load_fixtures(corpus_root, klass="negative")
    return any(rule_id in fix.forbidden_findings for fix in all_negs)


def _validate_one_rule(
    rule: Dict[str, Any],
    *,
    corpus_root: Path,
    strict_attribution: bool,
) -> List[RuleValidationError]:
    """Validate a single rule object. Returns all errors (no bail-on-first)."""
    rid = rule.get("id") if isinstance(rule, dict) else "<unknown>"
    if not isinstance(rid, str):
        rid = "<unknown>"

    errors: List[RuleValidationError] = []

    # 1. Schema-level checks via validate_rule.
    grandfathered = bool(
        isinstance(rule, dict) and rule.get("license_chain_audited") is True
    )
    # In default mode, grandfathered rules skip strict attribution; new rules
    # always get the strict check.
    enforce_strict = strict_attribution or not grandfathered
    schema_errors = validate_rule(rule, strict_attribution=enforce_strict)
    for msg in schema_errors:
        # Sources-shape and attribution complaints on grandfathered rules in
        # default mode become warnings — the existing PI-001..PI-028 rules
        # have empty sources[] and no upstream_url, which the plan §C.3
        # explicitly accepts as legacy debt to be backfilled later.
        is_attribution_or_source = (
            "upstream_url" in msg
            or "upstream_commit" in msg
            or "upstream " in msg.lower()
            or "sources" in msg.lower()
        )
        if grandfathered and not strict_attribution and is_attribution_or_source:
            errors.append(
                RuleValidationError(rule_id=rid, severity="warning", message=msg)
            )
        else:
            errors.append(
                RuleValidationError(rule_id=rid, severity="error", message=msg)
            )

    # 2. Test-pair check (only for non-grandfathered rules).
    if not grandfathered and isinstance(rid, str) and rid != "<unknown>":
        if not _has_positive(corpus_root, rid):
            errors.append(
                RuleValidationError(
                    rule_id=rid,
                    severity="error",
                    message=(
                        f"missing positive fixture for {rid} under "
                        f"{corpus_root}/positive/ (declare it in expected_findings)"
                    ),
                )
            )
        if not _has_negative(corpus_root, rid):
            errors.append(
                RuleValidationError(
                    rule_id=rid,
                    severity="error",
                    message=(
                        f"missing negative fixture for {rid} under "
                        f"{corpus_root}/negative/ (declare it in forbidden_findings)"
                    ),
                )
            )

    return errors


def validate_rules(
    rules_file: Path,
    *,
    corpus_root: Path = Path("tests/corpus"),
    strict_attribution: bool = False,
) -> List[RuleValidationError]:
    """Validate every rule in ``rules_file``.

    Returns ALL errors and warnings (no bail-on-first). The caller decides
    exit code based on ``severity == 'error'``.
    """
    rules_file = Path(rules_file)
    corpus_root = Path(corpus_root)

    if not rules_file.exists():
        return [
            RuleValidationError(
                rule_id="<file>",
                severity="error",
                message=f"rules file not found: {rules_file}",
            )
        ]

    try:
        data = json.loads(rules_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [
            RuleValidationError(
                rule_id="<file>",
                severity="error",
                message=f"failed to parse {rules_file}: {exc}",
            )
        ]

    patterns = data.get("patterns") if isinstance(data, dict) else None
    if not isinstance(patterns, list):
        return [
            RuleValidationError(
                rule_id="<file>",
                severity="error",
                message="rules file has no 'patterns' list",
            )
        ]

    all_errors: List[RuleValidationError] = []
    for rule in patterns:
        all_errors.extend(
            _validate_one_rule(
                rule,
                corpus_root=corpus_root,
                strict_attribution=strict_attribution,
            )
        )
    return all_errors
