"""CI gate: runtime forbidden_findings enforcement (spec §9.3 / §13.7a).

For each fixture with a non-empty `forbidden_findings` list, runs
``scan_file`` on the content file and asserts no forbidden pattern fires
with confidence >= 25 (per CONTRIBUTING.md negative bar).

This is the runtime scan gate, distinct from the validator's syntax check.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_ROOT = REPO_ROOT / "tests" / "corpus"
CLASS_DIRS = ("positive", "negative", "borderline", "regression", "dos")
_FORBIDDEN_THRESHOLD = 25


def _fixture_pairs() -> list[tuple[Path, Path]]:
    """Return (content, expected.json) pairs where forbidden_findings is non-empty."""
    out: list[tuple[Path, Path]] = []
    if not CORPUS_ROOT.exists():
        return out
    for klass in CLASS_DIRS:
        klass_dir = CORPUS_ROOT / klass
        if not klass_dir.is_dir():
            continue
        for meta in klass_dir.rglob("*.expected.json"):
            try:
                data = json.loads(meta.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not data.get("forbidden_findings"):
                continue
            content_name = data.get("file")
            if not content_name:
                continue
            content = meta.parent / content_name
            if content.exists():
                out.append((content, meta))
    return out


_PAIRS = _fixture_pairs()


@pytest.mark.parametrize(
    "content_path,meta_path",
    _PAIRS,
    ids=lambda p: str(p.relative_to(REPO_ROOT)) if isinstance(p, Path) else "",
)
def test_no_forbidden_pattern_fires(content_path: Path, meta_path: Path) -> None:
    from secureclaw.core.confidence import score_findings
    from secureclaw.core.patterns import PatternEngine, load_default_patterns
    from secureclaw.core.scanner import scan_file

    data = json.loads(meta_path.read_text(encoding="utf-8"))
    forbidden = set(data.get("forbidden_findings", []))

    patterns = load_default_patterns()
    engine = PatternEngine(patterns)
    result = scan_file(content_path, engine)
    score_findings(result.findings)

    triggered = [
        (f.pattern_id, f.confidence, f.line_number)
        for f in result.findings
        if f.pattern_id in forbidden and f.confidence >= _FORBIDDEN_THRESHOLD
    ]
    assert not triggered, (
        f"{content_path}: forbidden pattern(s) fired at confidence >= "
        f"{_FORBIDDEN_THRESHOLD}: {triggered}"
    )
