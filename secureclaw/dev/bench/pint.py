"""Loader for the vendored Lakera PINT canary subset (spec §7).

Thin wrapper around :func:`secureclaw.dev.bench.runner._load_benchmark_fixtures`.
PR-E vendors ~50 representative entries at ``tests/corpus/benchmarks/pint/``;
the fetch-and-cache flow for the full PINT dataset is deferred to v1.3.1
(``bench fetch``).
"""

from __future__ import annotations

from pathlib import Path
from typing import List

from secureclaw.dev.bench.runner import _load_benchmark_fixtures
from secureclaw.dev.corpus.models import Fixture

PINT_SUBDIR = "benchmarks/pint"


def load_pint_canary(corpus_root: Path) -> List[Fixture]:
    """Return :class:`Fixture` objects for the vendored PINT canary subset."""
    return _load_benchmark_fixtures(Path(corpus_root), PINT_SUBDIR)
