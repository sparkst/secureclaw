"""Run a rule (or all rules) against the corpus fixtures (spec §6.2, §9.4).

``test_rule(rule_id, rules_file, corpus_root)`` finds the rule's positive
and negative fixtures, runs the scanner on each, and returns a
:class:`RuleTestResult`.

Negative-fixture lookup uses ``load_fixtures(klass='negative')`` followed by
a post-filter on ``fixture.forbidden_findings``. PR-C's ``pattern_id`` filter
only matches ``expected_findings``, so we cannot use it for negatives — that
was a P1 finding in the spec review.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from secureclaw.core.patterns import PatternEngine, load_default_patterns
from secureclaw.core.scanner import scan_file
from secureclaw.dev.corpus.loader import load_fixtures
from secureclaw.dev.rule.models import RuleTestResult

# Confidence threshold below which a finding on a negative fixture is
# treated as too noisy to count as a failure (spec §6.2).
_NEGATIVE_CONFIDENCE_THRESHOLD = 25


def _load_rules(rules_file: Path) -> Dict[str, Any]:
    if not rules_file.exists():
        raise FileNotFoundError(f"rules file not found: {rules_file}")
    return json.loads(rules_file.read_text(encoding="utf-8"))


def _build_engine(rules_file: Path) -> PatternEngine:
    """Build a PatternEngine from a specific rules file (for unit tests)."""
    if rules_file == Path("secureclaw/rules/default_rules.json") or not rules_file.exists():
        # Default path: use the standard loader.
        return PatternEngine(load_default_patterns())
    # Custom path: load the JSON and convert via the same shape the default
    # loader uses. We import here to avoid coupling at module load time.
    from secureclaw.core.models import Pattern
    from secureclaw.core.patterns import _category_from_str, _severity_from_str

    data = json.loads(rules_file.read_text(encoding="utf-8"))
    patterns: List[Pattern] = []
    for entry in data.get("patterns", []):
        patterns.append(
            Pattern(
                id=entry["id"],
                name=entry["name"],
                regex=entry["regex"],
                severity=_severity_from_str(entry.get("severity", "advisory")),
                category=_category_from_str(entry.get("category", "instruction_override")),
                description=entry.get("description", ""),
                remediation=entry.get("remediation", ""),
                examples=entry.get("examples", []),
                case_sensitive=entry.get("case_sensitive", False),
            )
        )
    return PatternEngine(patterns)


def _scan_fixture(content_path: Path, engine: PatternEngine) -> Any:
    """Run scan_file on a fixture's content path. Wrapped so tests can patch it."""
    return scan_file(content_path, engine)


def _run_positive(fixture: Any, rule_id: str, engine: PatternEngine) -> Tuple[str, bool, str]:
    content_path = fixture.path.parent / fixture.file
    if not content_path.exists():
        return (str(content_path), False, "content file missing")
    result = scan_file(content_path, engine)
    fired = any(f.pattern_id == rule_id for f in result.findings)
    if fired:
        return (str(content_path), True, "")
    return (
        str(content_path),
        False,
        f"rule {rule_id} did not fire on positive fixture",
    )


def _run_negative(fixture: Any, rule_id: str, engine: PatternEngine) -> Tuple[str, bool, str]:
    content_path = fixture.path.parent / fixture.file
    if not content_path.exists():
        return (str(content_path), False, "content file missing")
    result = scan_file(content_path, engine)
    bad = [
        f
        for f in result.findings
        if f.pattern_id == rule_id
        and getattr(f, "confidence", 100) >= _NEGATIVE_CONFIDENCE_THRESHOLD
    ]
    if bad:
        return (
            str(content_path),
            False,
            (f"rule {rule_id} fired on negative fixture (confidence {bad[0].confidence})"),
        )
    return (str(content_path), True, "")


def test_rule(
    rule_id: str,
    *,
    rules_file: Path = Path("secureclaw/rules/default_rules.json"),
    corpus_root: Path = Path("tests/corpus"),
) -> RuleTestResult:
    """Run ``rule_id`` against its corpus fixtures."""
    rules_file = Path(rules_file)
    corpus_root = Path(corpus_root)

    data = _load_rules(rules_file)
    if not any(p.get("id") == rule_id for p in data.get("patterns", [])):
        raise ValueError(f"rule {rule_id!r} not found in {rules_file}")

    engine = _build_engine(rules_file)

    # Positive fixtures: the PR-C pattern_id filter matches expected_findings,
    # which is the right shape for positives.
    positive_fixtures = load_fixtures(corpus_root, klass="positive", pattern_id=rule_id)

    # Negative fixtures: PR-C's pattern_id filter only matches
    # expected_findings, but our negatives never list the rule there — they
    # list it in forbidden_findings. Load all negatives and post-filter.
    all_negatives = load_fixtures(corpus_root, klass="negative")
    negative_fixtures = [f for f in all_negatives if rule_id in f.forbidden_findings]

    positives = tuple(_run_positive(fix, rule_id, engine) for fix in positive_fixtures)
    negatives = tuple(_run_negative(fix, rule_id, engine) for fix in negative_fixtures)

    return RuleTestResult(rule_id=rule_id, positives=positives, negatives=negatives)


def test_all_rules(
    *,
    rules_file: Path = Path("secureclaw/rules/default_rules.json"),
    corpus_root: Path = Path("tests/corpus"),
) -> List[RuleTestResult]:
    """Run :func:`test_rule` for every rule in ``rules_file``."""
    rules_file = Path(rules_file)
    data = _load_rules(rules_file)
    return [
        test_rule(p["id"], rules_file=rules_file, corpus_root=corpus_root)
        for p in data.get("patterns", [])
        if isinstance(p.get("id"), str)
    ]
