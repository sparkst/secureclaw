"""Bench suite runner (spec §6.1, §9.2).

Cross-platform: per-fixture timeout via ``concurrent.futures`` (works on
Windows; ``signal.alarm`` is POSIX-only and not used here).
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
from pathlib import Path
from typing import List, Optional, Tuple

from secureclaw import __version__
from secureclaw.core.confidence import score_findings
from secureclaw.core.patterns import PatternEngine, load_patterns_from_json
from secureclaw.core.scanner import scan_file
from secureclaw.dev.bench.models import (
    SCHEMA_VERSION,
    BenchResult,
    BenchSuite,
    FixtureResult,
    Outcome,
    Summary,
)
from secureclaw.dev.corpus.loader import load_fixtures
from secureclaw.dev.corpus.models import Fixture

_FORBIDDEN_CONFIDENCE_THRESHOLD = 25

# Suite registry. ``benchmark_subdir`` is relative to ``corpus_root``.
_SUITES = {
    "corpus": BenchSuite(name="corpus", corpus_root=Path("tests/corpus"), benchmark_subdir=None),
    "pint-canary": BenchSuite(
        name="pint-canary",
        corpus_root=Path("tests/corpus"),
        benchmark_subdir="benchmarks/pint",
    ),
    "hackaprompt-canary": BenchSuite(
        name="hackaprompt-canary",
        corpus_root=Path("tests/corpus"),
        benchmark_subdir="benchmarks/hackaprompt",
    ),
}


def known_suites() -> List[str]:
    """Names of all built-in suites (excludes the meta-suite ``all``)."""
    return list(_SUITES.keys())


def _resolve_suite(suite_name: str, corpus_root: Optional[Path]) -> BenchSuite:
    if suite_name not in _SUITES:
        raise ValueError(
            f"unknown bench suite {suite_name!r}; expected one of "
            f"{sorted(_SUITES.keys()) + ['all']}"
        )
    base = _SUITES[suite_name]
    root = corpus_root if corpus_root is not None else base.corpus_root
    return BenchSuite(
        name=base.name,
        corpus_root=Path(root),
        benchmark_subdir=base.benchmark_subdir,
    )


def _hash_rules_file(rules_file: Path) -> str:
    return hashlib.sha256(rules_file.read_bytes()).hexdigest()


def _rule_set_version(rules_file: Path) -> str:
    """Best-effort: read top-level ``version`` field from rules JSON; fall back
    to package version."""
    try:
        data = json.loads(rules_file.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("version"), str):
            return data["version"]
    except (OSError, json.JSONDecodeError):
        pass
    return __version__


def _load_benchmark_fixtures(corpus_root: Path, subdir: str) -> List[Fixture]:
    """Load fixtures under ``<corpus_root>/<subdir>/`` directly.

    Benchmark fixtures live OUTSIDE the 5 canonical class dirs, so the PR-C
    ``load_fixtures`` won't reach them. We mirror its parse-tolerant behaviour
    for ``benchmarks/<name>/*.expected.json``.
    """
    bench_dir = corpus_root / subdir
    out: List[Fixture] = []
    if not bench_dir.is_dir():
        return out
    for meta_path in sorted(bench_dir.rglob("*.expected.json")):
        try:
            data = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        try:
            out.append(Fixture.from_dict(data, path=meta_path))
        except (ValueError, KeyError, TypeError):
            continue
    return out


def _benchmark_klass(suite_name: str) -> str:
    """Pseudo-class for benchmark fixtures (they don't live under positive/)."""
    return "benchmark"


def _classify_outcome(
    *,
    klass: str,
    mode: str,
    expected_pattern_ids: Tuple[str, ...],
    forbidden_pattern_ids: Tuple[str, ...],
    actual_pattern_ids: Tuple[str, ...],
    timed_out: bool,
) -> Outcome:
    """Classify a single fixture per spec §6.1.

    Decision order:
      1. ``klass == 'dos'``: timeout decides. (Other klasses use timeout to
         mark DOS_FAIL too — defensive against runaway scans.)
      2. forbidden_findings hit -> failure (FALSE_POSITIVE for negative,
         FALSE_POSITIVE-equivalent for others).
      3. mode-based comparison:
         - superset: expected ⊆ actual (positive/regression)
         - exact: expected == actual (negative)
         - subset: actual ⊆ expected (borderline)
      4. klass-aware label.
    """
    if klass == "dos":
        return Outcome.DOS_FAIL if timed_out else Outcome.DOS_PASS

    if timed_out:
        return Outcome.DOS_FAIL

    actual_set = set(actual_pattern_ids)
    expected_set = set(expected_pattern_ids)
    forbidden_set = set(forbidden_pattern_ids)

    # Forbidden finding overrides everything else.
    if forbidden_set & actual_set:
        return Outcome.FALSE_POSITIVE

    if mode == "superset":
        matched = expected_set.issubset(actual_set)
    elif mode == "exact":
        matched = expected_set == actual_set
    elif mode == "subset":
        matched = actual_set.issubset(expected_set)
    else:
        # Defensive: unknown mode is a regression flag.
        return Outcome.FALSE_NEGATIVE

    if klass == "regression":
        return Outcome.REGRESSION_PASS if matched else Outcome.REGRESSION_FAIL

    if klass == "negative":
        return Outcome.TRUE_NEGATIVE if matched else Outcome.FALSE_POSITIVE

    if klass == "borderline":
        # ``subset`` mode within bounds = borderline; outside bounds = regression.
        if mode == "subset" and matched:
            return Outcome.BORDERLINE
        return Outcome.FALSE_POSITIVE if not matched else Outcome.BORDERLINE

    # positive / benchmark / anything else.
    if not matched:
        # superset miss -> false negative; exact miss with extras -> false positive.
        if mode == "exact" and actual_set - expected_set:
            return Outcome.FALSE_POSITIVE
        return Outcome.FALSE_NEGATIVE
    return Outcome.TRUE_POSITIVE


def _scan_with_budget(path: Path, engine: PatternEngine, time_budget_ms: int):
    """Run ``scan_file`` with a wall-clock budget. Cross-platform via threads.

    Returns ``(findings, timed_out)``. Findings are the (scored) FileResult's
    findings list; timed_out is True iff the watchdog fired.
    """
    timeout_seconds = time_budget_ms / 1000.0

    # Single-worker pool isolates the scan; the main thread blocks on result().
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(scan_file, path, engine)
        try:
            file_result = future.result(timeout=timeout_seconds)
        except concurrent.futures.TimeoutError:
            # The worker thread keeps running until scan_file returns; that's
            # acceptable because scan_file is bounded by the file's line count
            # and our patterns use re/regex (which has its own per-match budget).
            return [], True

    score_findings(file_result.findings)
    return file_result.findings, False


def run_bench(
    suite_name: str,
    *,
    rules_file: Path,
    corpus_root: Optional[Path] = None,
    pattern_id: Optional[str] = None,
    time_budget_ms: int = 5000,
) -> BenchResult:
    """Run a benchmark suite against a fixture corpus.

    ``suite_name`` is one of ``corpus`` / ``pint-canary`` / ``hackaprompt-canary``.
    Returns a :class:`BenchResult` ready for serialisation. Per spec §6.1.
    """
    rules_file = Path(rules_file)
    if not rules_file.exists():
        raise FileNotFoundError(f"rules file not found: {rules_file}")

    suite = _resolve_suite(suite_name, corpus_root)
    rule_sha = _hash_rules_file(rules_file)
    rule_version = _rule_set_version(rules_file)

    patterns = load_patterns_from_json(rules_file)
    engine = PatternEngine(patterns)

    if suite.benchmark_subdir is None:
        fixtures = load_fixtures(suite.corpus_root, pattern_id=pattern_id)
        # Skip benchmarks/ subtree by definition (load_fixtures only walks the
        # 5 canonical class dirs). Apply pattern_id filter inside the loader.
    else:
        fixtures = _load_benchmark_fixtures(suite.corpus_root, suite.benchmark_subdir)
        if pattern_id is not None:
            fixtures = [
                f
                for f in fixtures
                if any(ef.pattern_id == pattern_id for ef in f.expected_findings)
            ]

    rows: List[FixtureResult] = []
    for fix in fixtures:
        # Determine klass: real corpus uses .klass(); benchmark uses pseudo.
        if suite.benchmark_subdir is None:
            klass = fix.klass()
        else:
            klass = _benchmark_klass(suite.name)

        # Path of the content file, relative to corpus_root.
        content_path = fix.path.parent / fix.file
        try:
            rel_path = str(content_path.relative_to(suite.corpus_root)).replace("\\", "/")
        except ValueError:
            rel_path = str(content_path)

        if not content_path.exists():
            # Missing content file — skip with a synthetic FALSE_NEGATIVE.
            rows.append(
                FixtureResult(
                    path=rel_path,
                    klass=klass,
                    expected_pattern_ids=tuple(ef.pattern_id for ef in fix.expected_findings),
                    forbidden_pattern_ids=tuple(fix.forbidden_findings),
                    actual_findings=(),
                    outcome=Outcome.FALSE_NEGATIVE,
                )
            )
            continue

        findings, timed_out = _scan_with_budget(content_path, engine, time_budget_ms)
        # AI-config + low-confidence filtering: pretend forbidden_findings only
        # count when they fire >= confidence 25 (per CONTRIBUTING.md negative bar).
        actual_pattern_ids = tuple(f.pattern_id for f in findings)
        forbidden_set = set(fix.forbidden_findings)
        # For forbidden-detection at the outcome layer, only consider findings
        # at >= the negative-bar confidence.
        triggered_forbidden = tuple(
            f.pattern_id
            for f in findings
            if f.pattern_id in forbidden_set and f.confidence >= _FORBIDDEN_CONFIDENCE_THRESHOLD
        )
        # If a forbidden fires, ensure it is included in actual_pattern_ids
        # so _classify_outcome can see it. (It already is, by definition.)
        if triggered_forbidden:
            forbidden_for_classifier = triggered_forbidden
        else:
            forbidden_for_classifier = tuple(fix.forbidden_findings)
        # When forbidden is empty in fixture metadata, classifier will get no
        # forbidden hits.
        outcome = _classify_outcome(
            klass=klass,
            mode=fix.mode,
            expected_pattern_ids=tuple(ef.pattern_id for ef in fix.expected_findings),
            forbidden_pattern_ids=forbidden_for_classifier
            if triggered_forbidden
            else tuple(fix.forbidden_findings),
            actual_pattern_ids=(actual_pattern_ids if triggered_forbidden else actual_pattern_ids),
            timed_out=timed_out,
        )
        # Build serialisable actual_findings list.
        actual_findings_dicts = tuple(
            {
                "pattern_id": f.pattern_id,
                "line": f.line_number,
                "confidence": f.confidence,
            }
            for f in findings
        )
        rows.append(
            FixtureResult(
                path=rel_path,
                klass=klass,
                expected_pattern_ids=tuple(ef.pattern_id for ef in fix.expected_findings),
                forbidden_pattern_ids=tuple(fix.forbidden_findings),
                actual_findings=actual_findings_dicts,
                outcome=outcome,
            )
        )

    # Sort fixtures by path for stable serialisation.
    rows.sort(key=lambda r: r.path)
    summary = Summary.from_fixture_results(rows)

    return BenchResult(
        schema_version=SCHEMA_VERSION,
        suite=suite.name,
        secureclaw_version=__version__,
        rule_set_version=rule_version,
        rule_set_sha256=rule_sha,
        fixtures=rows,
        summary=summary,
    )
