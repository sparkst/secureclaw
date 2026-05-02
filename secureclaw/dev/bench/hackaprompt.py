"""Loader for the vendored HackAPrompt canary subset (spec §7).

Thin wrapper around :func:`secureclaw.dev.bench.runner._load_benchmark_fixtures`.
PR-E vendors ~50 representative entries at
``tests/corpus/benchmarks/hackaprompt/``; the fetch-and-cache flow for the
full dataset is deferred to v1.3.1 (``bench fetch``).
"""

from __future__ import annotations

from pathlib import Path
from typing import List

from secureclaw.dev.bench.runner import _load_benchmark_fixtures
from secureclaw.dev.corpus.models import Fixture

HACKAPROMPT_SUBDIR = "benchmarks/hackaprompt"


def load_hackaprompt_canary(corpus_root: Path) -> List[Fixture]:
    """Return :class:`Fixture` objects for the vendored HackAPrompt canary subset."""
    return _load_benchmark_fixtures(Path(corpus_root), HACKAPROMPT_SUBDIR)
