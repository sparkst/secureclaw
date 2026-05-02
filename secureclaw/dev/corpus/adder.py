"""Adder for ``secureclaw dev corpus add`` (spec §6.1, §13.4).

Copies an external content file into ``tests/corpus/<class>/`` and emits the
sibling ``.expected.json`` metadata. Defense-in-depth license gating mirrors
the validator (so users get fast feedback at add time, not just on validate).
"""

from __future__ import annotations

import json
import re
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from secureclaw.dev.corpus.models import Fixture
from secureclaw.dev.corpus.schema import validate_against_schema

_PATTERN_ID_RE = re.compile(r"^PI-[A-Z0-9]+$")
_VALID_CLASSES = {"positive", "negative", "borderline", "regression", "dos"}

# Mirrored from validator.py — defense-in-depth.
_LICENSE_BLOCK_SUBSTRINGS = (
    "gpl-2.0",
    "gpl-3.0",
    "agpl",
    "cc-by-sa",
    "cc-by-nc",
)
_LICENSE_ALLOW_EXACT = {
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "CC0-1.0",
    "CC-BY-4.0",
    "ISC",
}
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


def _default_mode(klass: str) -> str:
    """Spec §6.1 — superset for positive, exact for negative, subset for borderline."""
    return {
        "positive": "superset",
        "negative": "exact",
        "borderline": "subset",
        "regression": "exact",
        "dos": "exact",
    }[klass]


def add_fixture(
    content_path: Path,
    *,
    klass: str,
    source_attestation: str,
    license: str,
    pattern_id: Optional[str] = None,
    line: Optional[int] = None,
    confidence_low: int = 75,
    confidence_high: int = 100,
    mode: Optional[str] = None,
    category: Optional[str] = None,
    regression_of: Optional[str] = None,
    regression_group: Optional[str] = None,
    root: Path = Path("tests/corpus"),
    force: bool = False,
) -> Fixture:
    """Copy ``content_path`` into the corpus and emit its ``expected.json``.

    See spec §6.1. Refuses on bad arguments before any filesystem mutation.
    """
    content_path = Path(content_path)
    root = Path(root)

    if not content_path.exists():
        raise FileNotFoundError(f"content file not found: {content_path}")

    if klass not in _VALID_CLASSES:
        raise ValueError(f"--class must be one of {sorted(_VALID_CLASSES)}, got {klass!r}")

    # License: defense-in-depth gates.
    blocked = _license_blocked(license)
    if blocked is not None:
        raise ValueError(
            f"license '{license}' is blocked (matches '{blocked}'); choose a permissive alternative"
        )
    if not _license_allowed(license):
        raise ValueError(f"license '{license}' requires legal review — not in the approved list")

    # Class-specific argument constraints.
    if klass == "positive":
        if not pattern_id:
            raise ValueError("--class positive requires --pattern-id (e.g., PI-001)")
        if not _PATTERN_ID_RE.match(pattern_id):
            raise ValueError(f"--pattern-id must match ^PI-[A-Z0-9]+$, got {pattern_id!r}")
    if klass == "negative" and pattern_id:
        raise ValueError(
            "--class negative cannot have --pattern-id (negatives have no expected findings)"
        )
    if klass == "regression" and not regression_of:
        raise ValueError(
            "--class regression requires --regression-of referencing the issue/PR/timestamp"
        )

    # Determine destination directory (regression supports sub-folder).
    if klass == "regression" and regression_group:
        dst_dir = root / "regression" / regression_group
    else:
        dst_dir = root / klass
    dst_content = dst_dir / content_path.name
    dst_meta = dst_dir / f"{content_path.name}.expected.json"

    if not force and (dst_content.exists() or dst_meta.exists()):
        raise FileExistsError(f"refusing to overwrite {dst_content} or {dst_meta} without --force")

    # Build metadata BEFORE filesystem mutation (so we can validate first).
    meta: Dict[str, Any] = {
        "schema_version": 2,
        "file": content_path.name,
        "mode": mode or _default_mode(klass),
        "source": source_attestation,
        "license": license,
        "added_in_pr": "#TBD-C",
        "anonymization": {"applied": False},
    }
    if pattern_id:
        finding: Dict[str, Any] = {
            "pattern_id": pattern_id,
            "confidence_range": [confidence_low, confidence_high],
        }
        if line is not None:
            finding["line"] = line
        meta["expected_findings"] = [finding]
    else:
        meta["expected_findings"] = []
    if category:
        meta["category"] = category
    if regression_of:
        meta["regression_of"] = regression_of

    # Schema-validate the generated metadata BEFORE writing.
    schema_errors = validate_against_schema(meta)
    if schema_errors:
        raise ValueError("generated metadata failed schema validation: " + "; ".join(schema_errors))

    # Mutate the filesystem.
    dst_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(content_path, dst_content)
    with dst_meta.open("w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2, sort_keys=False)
        fh.write("\n")

    # Hint for the next step (per spec §6.1).
    print(
        f"Next: run `secureclaw dev corpus validate` to confirm; commit with "
        f"`git add {dst_content} {dst_meta}`",
        file=sys.stderr,
    )

    return Fixture.from_dict(meta, path=dst_meta)


# --- set-pr-number verb (spec §6.1a) ---------------------------------------


def set_pr_number(root: Path, pr_number: int, *, dry_run: bool = False) -> Dict[str, List[Path]]:
    """Replace ``"#TBD-C"`` in every ``added_in_pr`` field under ``root``.

    Returns ``{"updated": [...], "skipped": [...], "errors": [...]}``.
    """
    updated: List[Path] = []
    skipped: List[Path] = []
    errors: List[Path] = []

    placeholder = "#TBD-C"
    new_value = f"#{pr_number}"

    if not root.exists():
        return {"updated": updated, "skipped": skipped, "errors": errors}

    for meta_path in sorted(root.rglob("*.expected.json")):
        try:
            text = meta_path.read_text(encoding="utf-8")
        except OSError:
            errors.append(meta_path)
            continue
        if placeholder not in text:
            skipped.append(meta_path)
            continue
        if dry_run:
            updated.append(meta_path)
            continue
        try:
            new_text = text.replace(f'"{placeholder}"', f'"{new_value}"')
            meta_path.write_text(new_text, encoding="utf-8")
            updated.append(meta_path)
        except OSError:
            errors.append(meta_path)

    return {"updated": updated, "skipped": skipped, "errors": errors}
