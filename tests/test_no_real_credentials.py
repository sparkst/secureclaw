"""CI gate: SecureClaw self-scan over the corpus must surface no high-confidence
credential findings (spec §9.2).

Walks tests/corpus/{positive,negative,borderline,regression,dos}/ and runs
``scan_file`` over each content file. Fails on any credential-class finding
with confidence >= 75, except for files whose `expected.json` declares
`anonymization.applied: true` (synthetic test prefixes are explicitly
allowed there).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_ROOT = REPO_ROOT / "tests" / "corpus"
CLASS_DIRS = ("positive", "negative", "borderline", "regression", "dos")

# Pattern IDs that count as "credential-class" for this gate.
_CREDENTIAL_PATTERN_IDS = {"PI-022"}
_REFUSAL_THRESHOLD = 75


def _content_files() -> list[Path]:
    out: list[Path] = []
    if not CORPUS_ROOT.exists():
        return out
    for klass in CLASS_DIRS:
        klass_dir = CORPUS_ROOT / klass
        if not klass_dir.is_dir():
            continue
        for path in klass_dir.rglob("*"):
            if not path.is_file():
                continue
            if path.name.endswith(".expected.json"):
                continue
            if path.name == ".gitkeep":
                continue
            out.append(path)
    return out


_CONTENT_FILES = _content_files()


@pytest.mark.parametrize(
    "content_path",
    _CONTENT_FILES,
    ids=lambda p: str(p.relative_to(REPO_ROOT)),
)
def test_no_real_credentials_in_fixture(content_path: Path) -> None:
    from secureclaw.core.confidence import score_findings
    from secureclaw.core.patterns import PatternEngine, load_default_patterns
    from secureclaw.core.scanner import scan_file

    # If anonymization.applied is true in the sibling expected.json, allow
    # synthetic test prefixes.
    meta_path = content_path.with_name(content_path.name + ".expected.json")
    anonymization_applied = False
    if meta_path.exists():
        try:
            data = json.loads(meta_path.read_text(encoding="utf-8"))
            anonymization_applied = bool(data.get("anonymization", {}).get("applied"))
        except (OSError, json.JSONDecodeError):
            pass

    patterns = load_default_patterns()
    engine = PatternEngine(patterns)
    result = scan_file(content_path, engine)
    score_findings(result.findings)

    high_credential = [
        f
        for f in result.findings
        if f.pattern_id in _CREDENTIAL_PATTERN_IDS and f.confidence >= _REFUSAL_THRESHOLD
    ]
    if anonymization_applied:
        # Synthetic prefixes allowed.
        return
    assert not high_credential, (
        f"{content_path}: credential-class finding(s) at confidence >= {_REFUSAL_THRESHOLD}: "
        + ", ".join(f"{f.pattern_id}@line{f.line_number}" for f in high_credential)
    )
