"""Rule schema validation for ``secureclaw/rules/default_rules.json`` (spec §5).

``load_rule_schema()`` returns the field-requirements descriptor. The
canonical schema is the existing ``default_rules.json`` shape — every field
present in PI-001..PI-028 is required for new rules.

``validate_rule(rule_dict, *, strict_attribution=False)`` returns a list of
human-readable error strings. Empty list means valid.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

# --- Constants -------------------------------------------------------------

_PATTERN_ID_RE = re.compile(r"^PI-[A-Z0-9]+$")
_VALID_SEVERITIES = ("info", "low", "medium", "high", "critical", "advisory")
_COMMIT_RE = re.compile(r"^[a-f0-9]{7,40}$")

# License blocklist substrings (case-insensitive) — mirrors PR-C corpus.
_LICENSE_BLOCK_SUBSTRINGS = (
    "gpl-2.0",
    "gpl-3.0",
    "agpl",
    "cc-by-sa",
    "cc-by-nc",
)

# Required fields per §5 (matches every entry of default_rules.json).
_REQUIRED_FIELDS = (
    "id",
    "name",
    "regex",
    "severity",
    "category",
    "description",
    "remediation",
    "examples",
    "introduced_in_version",
    "applies_to",
    "region_kinds",
    "applies_in_string_literal",
    "applies_in_ai_config",
    "requires_same_sentence_with",
    "boost_on_high_entropy",
    "boost_on_invisible_chars",
    "large_file_safe",
    "sources",
    "license_chain_audited",
    "severity_promotion_evidence",
    "owasp",
    "atlas",
)

# Field types — value is a tuple of acceptable Python types.
_FIELD_TYPES: Dict[str, tuple] = {
    "id": (str,),
    "name": (str,),
    "regex": (str,),
    "severity": (str,),
    "category": (str,),
    "description": (str,),
    "remediation": (str,),
    "examples": (list,),
    "introduced_in_version": (str,),
    "applies_to": (list,),
    "region_kinds": (list,),
    "applies_in_string_literal": (bool,),
    "applies_in_ai_config": (bool,),
    "requires_same_sentence_with": (list,),
    "boost_on_high_entropy": (bool,),
    "boost_on_invisible_chars": (bool,),
    "large_file_safe": (bool,),
    "sources": (list,),
    "license_chain_audited": (bool,),
}

# Lists that must be non-empty for new rules.
_NON_EMPTY_LISTS = ("applies_to", "region_kinds", "sources")


def load_rule_schema() -> Dict[str, Any]:
    """Return the rule-schema descriptor used by :func:`validate_rule`."""
    return {
        "required_fields": list(_REQUIRED_FIELDS),
        "valid_severities": list(_VALID_SEVERITIES),
        "blocked_license_substrings": list(_LICENSE_BLOCK_SUBSTRINGS),
        "non_empty_lists": list(_NON_EMPTY_LISTS),
    }


def _is_first_party(license_str: str) -> bool:
    lower = license_str.lower()
    return lower.startswith("synthetic") or "(own work)" in lower


def _license_blocked(license_str: str) -> bool:
    lower = license_str.lower()
    return any(b in lower for b in _LICENSE_BLOCK_SUBSTRINGS)


def _validate_sources(sources: List[Any], *, strict_attribution: bool) -> List[str]:
    """Validate the ``sources`` array. Returns error strings.

    The empty-list check is handled by the caller (step 6 in validate_rule's
    _NON_EMPTY_LISTS sweep). Skipping it here avoids duplicate warnings.
    """
    errors: List[str] = []
    if not sources:
        return errors

    for idx, src in enumerate(sources):
        if not isinstance(src, dict):
            errors.append(f"sources[{idx}] must be an object")
            continue
        source_val = src.get("source")
        license_val = src.get("license")
        if not isinstance(source_val, str) or not source_val:
            errors.append(f"sources[{idx}].source must be a non-empty string")
        if not isinstance(license_val, str) or not license_val:
            errors.append(f"sources[{idx}].license must be a non-empty string")
            continue  # can't check more without license
        if _license_blocked(license_val):
            errors.append(
                f"sources[{idx}].license '{license_val}' is blocked "
                f"(GPL/AGPL/CC-BY-SA/CC-BY-NC); choose a permissive alternative"
            )
            continue
        # Strict mode: non-synthetic licenses require upstream_url AND upstream_commit.
        if strict_attribution and not _is_first_party(license_val):
            url = src.get("upstream_url")
            commit = src.get("upstream_commit")
            if not isinstance(url, str) or not url:
                errors.append(
                    f"sources[{idx}] requires upstream_url for non-synthetic "
                    f"license '{license_val}' (strict_attribution)"
                )
            if not isinstance(commit, str) or not _COMMIT_RE.match(commit or ""):
                errors.append(
                    f"sources[{idx}] requires upstream_commit (7-40 hex) for "
                    f"non-synthetic license '{license_val}' (strict_attribution)"
                )
    return errors


def validate_rule(
    rule: Dict[str, Any],
    *,
    strict_attribution: bool = False,
) -> List[str]:
    """Validate one rule object. Returns ALL error strings (no bail-on-first)."""
    errors: List[str] = []

    if not isinstance(rule, dict):
        return ["rule must be a JSON object"]

    # 1. Required-field presence.
    for f in _REQUIRED_FIELDS:
        if f not in rule:
            errors.append(f"missing required field {f!r}")

    # 2. Type checks (only for fields that are present).
    for f, types in _FIELD_TYPES.items():
        if f not in rule:
            continue
        val = rule[f]
        if not isinstance(val, types):
            type_names = "|".join(t.__name__ for t in types)
            errors.append(f"field {f!r} must be of type {type_names}, got {type(val).__name__}")

    # 3. id format.
    rid = rule.get("id")
    if isinstance(rid, str) and not _PATTERN_ID_RE.match(rid):
        errors.append(f"id {rid!r} does not match ^PI-[A-Z0-9]+$")

    # 4. severity is a known value.
    sev = rule.get("severity")
    if isinstance(sev, str) and sev not in _VALID_SEVERITIES:
        errors.append(f"severity {sev!r} is not one of {list(_VALID_SEVERITIES)}")

    # 5. regex compiles.
    rgx = rule.get("regex")
    if isinstance(rgx, str):
        try:
            re.compile(rgx)
        except re.error as exc:
            errors.append(f"regex did not compile: {exc}")

    # 6. Non-empty lists.
    for f in _NON_EMPTY_LISTS:
        val = rule.get(f)
        if isinstance(val, list) and len(val) == 0:
            errors.append(f"field {f!r} must be a non-empty list")

    # 7. sources contents.
    sources = rule.get("sources")
    if isinstance(sources, list):
        errors.extend(_validate_sources(sources, strict_attribution=strict_attribution))

    return errors
