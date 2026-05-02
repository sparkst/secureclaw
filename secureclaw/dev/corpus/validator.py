"""Corpus validator (spec §6.3, §13.3).

`validate_corpus(root)` walks all fixtures under ``root`` and returns a list
of :class:`ValidationError`. Reports ALL errors before returning (no
bail-on-first per spec §6.3).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from secureclaw.dev.corpus.models import Fixture, ValidationError
from secureclaw.dev.corpus.schema import validate_against_schema

_VALID_CLASSES = {"positive", "negative", "borderline", "regression", "dos"}

# License blocklist substrings (case-insensitive).
_LICENSE_BLOCK_SUBSTRINGS = (
    "gpl-2.0",
    "gpl-3.0",
    "agpl",
    "cc-by-sa",
    "cc-by-nc",
)

# License allowlist exact strings.
_LICENSE_ALLOW_EXACT = {
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "CC0-1.0",
    "CC-BY-4.0",
    "ISC",
}

# Pattern: ``MIT (anything)`` is allowed.
_LICENSE_MIT_PARENTHESIZED = re.compile(r"^MIT\s*\(.*\)$")


def _license_blocked(license_str: str) -> Optional[str]:
    lower = license_str.lower()
    for blocked in _LICENSE_BLOCK_SUBSTRINGS:
        if blocked in lower:
            return blocked
    return None


def _license_allowed(license_str: str) -> bool:
    if license_str in _LICENSE_ALLOW_EXACT:
        return True
    lower = license_str.lower()
    if lower.startswith("synthetic"):
        return True
    if "(own work)" in lower:
        return True
    if _LICENSE_MIT_PARENTHESIZED.match(license_str):
        return True
    return False


def _is_first_party(license_str: str) -> bool:
    """First-party fixtures (synthetic / own-work) are exempt from upstream_url."""
    lower = license_str.lower()
    return lower.startswith("synthetic") or "(own work)" in lower


def _load_known_pattern_ids() -> Set[str]:
    """Read pattern IDs out of secureclaw/rules/default_rules.json."""
    rules_path = Path(__file__).resolve().parents[2] / "rules" / "default_rules.json"
    try:
        with rules_path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return set()
    ids: Set[str] = set()
    if isinstance(data, dict):
        rules = data.get("patterns") or data.get("rules")
    else:
        rules = data
    if isinstance(rules, list):
        for entry in rules:
            if isinstance(entry, dict):
                pid = entry.get("id")
                if isinstance(pid, str):
                    ids.add(pid)
    return ids


def _validate_one(
    expected_path: Path,
    raw: Dict[str, Any],
    *,
    strict: bool,
    known_pattern_ids: Set[str],
) -> List[ValidationError]:
    """Run all checks on one fixture; return all errors (no bail)."""
    errors: List[ValidationError] = []

    # 1. JSON Schema validation.
    schema_errors = validate_against_schema(raw)
    for msg in schema_errors:
        errors.append(ValidationError(path=expected_path, severity="error", message=msg))

    # If schema check failed catastrophically (missing core fields), skip semantic checks.
    if any(field not in raw for field in ("schema_version", "file", "mode", "license", "source")):
        return errors

    # 2. Try to construct Fixture (catches type-level issues models.py asserts).
    try:
        fixture = Fixture.from_dict(raw, path=expected_path)
    except (ValueError, KeyError, TypeError) as exc:
        errors.append(ValidationError(path=expected_path, severity="error", message=str(exc)))
        return errors

    # 3. Filename matches the actual file.
    declared = fixture.file
    actual_content = expected_path.parent / declared
    if not actual_content.exists():
        errors.append(
            ValidationError(
                path=expected_path,
                severity="error",
                message=f"declared file '{declared}' not found next to expected.json",
            )
        )

    # 4. Class directory matches one of the 5 valid classes.
    try:
        klass = fixture.klass()
    except ValueError as exc:
        errors.append(ValidationError(path=expected_path, severity="error", message=str(exc)))
        return errors
    if klass not in _VALID_CLASSES:
        errors.append(
            ValidationError(
                path=expected_path,
                severity="error",
                message=f"unknown class '{klass}'",
            )
        )

    # 5. License blocklist.
    blocked_substr = _license_blocked(fixture.license)
    if blocked_substr is not None:
        errors.append(
            ValidationError(
                path=expected_path,
                severity="error",
                message=(
                    f"license '{fixture.license}' is blocked "
                    f"(matches '{blocked_substr}'); choose a permissive alternative"
                ),
            )
        )
    elif not _license_allowed(fixture.license):
        # 5b. Allowlist enforcement (only if not blocked — blocked already caught).
        errors.append(
            ValidationError(
                path=expected_path,
                severity="error",
                message=(
                    f"license '{fixture.license}' requires legal review — not in the approved list"
                ),
            )
        )

    # 6. Pattern_id format (Schema already enforces; runtime check for unknown).
    for ef in fixture.expected_findings:
        if ef.pattern_id not in known_pattern_ids and known_pattern_ids:
            severity = "error" if strict else "warning"
            errors.append(
                ValidationError(
                    path=expected_path,
                    severity=severity,
                    message=(
                        f"pattern_id '{ef.pattern_id}' is not present in "
                        f"default_rules.json (use --strict to error vs warn)"
                    ),
                )
            )

    # 7. Line range.
    if actual_content.exists():
        try:
            line_count = sum(1 for _ in actual_content.read_text(encoding="utf-8").splitlines())
        except (OSError, UnicodeDecodeError):
            line_count = 0
        for ef in fixture.expected_findings:
            if ef.line is not None and ef.line > max(line_count, 0):
                errors.append(
                    ValidationError(
                        path=expected_path,
                        severity="error",
                        message=(
                            f"expected_findings line {ef.line} out of range "
                            f"(file has {line_count} lines)"
                        ),
                    )
                )

    # 11. regression_of required when class == regression.
    if klass == "regression" and not fixture.regression_of:
        errors.append(
            ValidationError(
                path=expected_path,
                severity="error",
                message=(
                    "regression_of field required for fixtures under regression/ "
                    "(reference issue, PR, or timestamp)"
                ),
            )
        )

    # 12. upstream_url required when license is non-synthetic.
    if not _is_first_party(fixture.license) and not fixture.upstream_url:
        errors.append(
            ValidationError(
                path=expected_path,
                severity="error",
                message=(
                    f"upstream_url required when license '{fixture.license}' is "
                    f"non-synthetic / not 'own work'"
                ),
            )
        )

    return errors


def validate_corpus(root: Path, *, strict: bool = False) -> List[ValidationError]:
    """Walk ``root`` and return all validation errors (no bail-on-first)."""
    if not root.exists():
        return []

    known_pattern_ids = _load_known_pattern_ids()
    all_errors: List[ValidationError] = []

    for klass_name in sorted(_VALID_CLASSES):
        klass_dir = root / klass_name
        if not klass_dir.is_dir():
            continue
        for expected_path in sorted(klass_dir.rglob("*.expected.json")):
            try:
                with expected_path.open("r", encoding="utf-8") as fh:
                    raw = json.load(fh)
            except (OSError, json.JSONDecodeError) as exc:
                all_errors.append(
                    ValidationError(
                        path=expected_path,
                        severity="error",
                        message=f"failed to parse: {exc}",
                    )
                )
                continue
            all_errors.extend(
                _validate_one(
                    expected_path,
                    raw,
                    strict=strict,
                    known_pattern_ids=known_pattern_ids,
                )
            )

    return all_errors
