"""Integration tests for `python -m secureclaw dev corpus *` (spec §13.9).

These tests invoke the CLI as a subprocess and assert exit codes + stdout
content. They turn green once the seed corpus (15 fixtures) is in place
(Phase 6.5).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def _run_cli(*argv: str, cwd: Path = REPO_ROOT) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "secureclaw", *argv],
        capture_output=True,
        text=True,
        cwd=str(cwd),
        timeout=60,
        check=False,
    )


def test_dev_corpus_list_exits_zero_with_15_fixtures() -> None:
    proc = _run_cli("dev", "corpus", "list")
    assert proc.returncode == 0, f"stderr: {proc.stderr}\nstdout: {proc.stdout}"
    # Count fixtures in stdout — each fixture is one line.
    lines = [line for line in proc.stdout.strip().splitlines() if line.strip()]
    assert len(lines) == 15, (
        f"expected 15 fixtures from seed corpus, got {len(lines)}.\nstdout:\n{proc.stdout}"
    )


def test_dev_corpus_validate_exits_zero_on_seed_corpus() -> None:
    proc = _run_cli("dev", "corpus", "validate")
    # Allow non-zero only if no errors (validator may emit warnings on rule mismatches).
    assert proc.returncode == 0, f"stderr: {proc.stderr}\nstdout: {proc.stdout}"


def test_dev_corpus_no_verb_exits_two() -> None:
    proc = _run_cli("dev", "corpus")
    assert proc.returncode == 2
