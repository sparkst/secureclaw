"""Bench baseline I/O (spec §6.2).

Baselines live at ``tests/bench/baselines/<suite>.json`` (canonical, in-repo)
and at ``~/.secureclaw/runs/<sha>.json`` (per-user run cache). Writes are
atomic via tempfile + ``os.replace`` so a partial failure cannot corrupt the
committed file.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from secureclaw.dev.bench.models import BenchResult


def load_baseline(path: Path) -> BenchResult:
    """Read a :class:`BenchResult` JSON document from ``path``."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"baseline not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"baseline at {path} is not valid JSON: {exc}") from exc
    return BenchResult.from_dict(data)


def write_baseline(result: BenchResult, path: Path, *, force: bool = False) -> None:
    """Persist ``result`` to ``path`` atomically.

    Refuses to overwrite an existing baseline unless ``force=True`` (avoids
    silent drift per spec §6.2). The write is two-phase: write to a temp file
    in the same directory, then ``os.replace`` over the destination so the
    file is never observed half-written.
    """
    path = Path(path)
    if path.exists() and not force:
        raise FileExistsError(f"baseline {path} already exists; pass force=True to overwrite")

    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)

    payload = json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n"

    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=parent)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        # Atomic rename. We deliberately use os.replace (not Path.replace) so
        # tests can monkeypatch this module's ``os`` to simulate disk-full
        # failures.
        os.replace(tmp_path, path)  # noqa: PTH105
    except BaseException:
        # Best-effort cleanup of the temp file; don't shadow the original error.
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise
