"""Fixture loader for ``tests/corpus/`` (spec §13.2).

``load_fixtures(root)`` scans the corpus tree, parses each ``*.expected.json``,
and returns a list of :class:`Fixture`. Filters by class and pattern_id.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Iterator, List, Optional

from secureclaw.dev.corpus.models import Fixture

_VALID_CLASSES = {"positive", "negative", "borderline", "regression", "dos"}


def _iter_expected_json_paths(root: Path) -> Iterator[Path]:
    """Yield each ``*.expected.json`` under one of the 5 valid class dirs."""
    if not root.exists():
        return
    for klass in sorted(_VALID_CLASSES):
        klass_dir = root / klass
        if not klass_dir.is_dir():
            continue
        # rglob covers regression/<subgroup>/* too.
        for path in sorted(klass_dir.rglob("*.expected.json")):
            yield path


def _parse_one(path: Path) -> Optional[Fixture]:
    """Read one ``*.expected.json`` and return the Fixture, or None on parse error.

    Parse errors are surfaced via stderr; the loader does not raise — the
    validator handles structural complaints.
    """
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"warning: failed to parse {path}: {exc}", file=sys.stderr)
        return None
    try:
        return Fixture.from_dict(data, path=path)
    except (ValueError, KeyError, TypeError) as exc:
        print(f"warning: invalid fixture metadata at {path}: {exc}", file=sys.stderr)
        return None


def _check_orphans(root: Path) -> None:
    """Emit warnings for content files lacking a ``.expected.json`` sibling."""
    if not root.exists():
        return
    for klass in sorted(_VALID_CLASSES):
        klass_dir = root / klass
        if not klass_dir.is_dir():
            continue
        for content in sorted(klass_dir.rglob("*")):
            if not content.is_file():
                continue
            if content.name.endswith(".expected.json"):
                continue
            if content.name == ".gitkeep":
                continue
            expected = content.with_name(content.name + ".expected.json")
            if not expected.exists():
                print(
                    f"warning: orphan content file (no .expected.json sibling): {content}",
                    file=sys.stderr,
                )


def load_fixtures(
    root: Path,
    *,
    klass: Optional[str] = None,
    pattern_id: Optional[str] = None,
) -> List[Fixture]:
    """Load all fixtures under ``root``.

    ``klass`` filters by class directory (positive|negative|borderline|regression|dos).
    ``pattern_id`` filters fixtures whose ``expected_findings`` contain that ID.
    """
    _check_orphans(root)
    fixtures: List[Fixture] = []
    for path in _iter_expected_json_paths(root):
        fix = _parse_one(path)
        if fix is None:
            continue
        if klass is not None and fix.klass() != klass:
            continue
        if pattern_id is not None:
            if not any(ef.pattern_id == pattern_id for ef in fix.expected_findings):
                continue
        fixtures.append(fix)
    return fixtures


def iter_fixtures(
    root: Path,
    *,
    klass: Optional[str] = None,
    pattern_id: Optional[str] = None,
) -> Iterator[Fixture]:
    """Generator variant of :func:`load_fixtures` (spec §4)."""
    _check_orphans(root)
    for path in _iter_expected_json_paths(root):
        fix = _parse_one(path)
        if fix is None:
            continue
        if klass is not None and fix.klass() != klass:
            continue
        if pattern_id is not None:
            if not any(ef.pattern_id == pattern_id for ef in fix.expected_findings):
                continue
        yield fix
