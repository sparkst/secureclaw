"""CI gate: every committed expected.json validates against the schema.

Spec §9.1 / §13.7. Walks tests/corpus/**/expected.json, validates against
tests/corpus/expected-schema.json. Also enforces the post-merge
``"#TBD-C"`` gate — once `set-pr-number` has been run, no placeholder
should remain.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_ROOT = REPO_ROOT / "tests" / "corpus"


def _expected_json_files() -> list[Path]:
    if not CORPUS_ROOT.exists():
        return []
    # Skip benchmarks — those don't have schema yet.
    skip_dirs = {"benchmarks"}
    out: list[Path] = []
    for path in CORPUS_ROOT.rglob("*.expected.json"):
        rel_parts = path.relative_to(CORPUS_ROOT).parts
        if rel_parts and rel_parts[0] in skip_dirs:
            continue
        out.append(path)
    return out


_FIXTURE_FILES = _expected_json_files()


@pytest.mark.parametrize(
    "expected_path", _FIXTURE_FILES, ids=lambda p: str(p.relative_to(REPO_ROOT))
)
def test_expected_json_validates(expected_path: Path) -> None:
    from secureclaw.dev.corpus.schema import validate_against_schema

    with expected_path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    errors = validate_against_schema(data)
    assert errors == [], f"{expected_path}: schema errors: {errors}"


@pytest.mark.skipif(
    os.environ.get("SECURECLAW_ENFORCE_PR_NUMBER") != "1",
    reason=(
        "Post-merge gate: set SECURECLAW_ENFORCE_PR_NUMBER=1 in CI after running "
        "`secureclaw dev corpus set-pr-number <N>`. The placeholder #TBD-C is "
        "expected during PR-C development."
    ),
)
@pytest.mark.parametrize(
    "expected_path", _FIXTURE_FILES, ids=lambda p: str(p.relative_to(REPO_ROOT))
)
def test_expected_json_has_no_tbd_placeholder(expected_path: Path) -> None:
    """Spec §13.7 — after `set-pr-number` runs, no `#TBD-C` should remain."""
    text = expected_path.read_text(encoding="utf-8")
    assert "#TBD-C" not in text, (
        f"{expected_path}: still contains '#TBD-C' placeholder. "
        "Run `secureclaw dev corpus set-pr-number <N>` before merge."
    )
