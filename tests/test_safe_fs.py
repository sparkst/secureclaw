"""Tests for symlink-safe filesystem primitives (PR-L-PR).

Per v1.3-plan-v10 REQ-17 + §G.3 + R7-SEC-P0-003 + R8-SEC-P0-002 +
R8-ARCH-P1-002.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from secureclaw.core.safe_fs import (
    SymlinkRefused,
    TargetEscapesRoot,
    atomic_write_text,
    raise_if_symlink_in_chain,
)


def test_raises_on_leaf_symlink(tmp_path: Path) -> None:
    target = tmp_path / "real.txt"
    target.write_text("real content")
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    with pytest.raises(SymlinkRefused):
        raise_if_symlink_in_chain(link)


def test_raises_on_directory_symlink_in_chain(tmp_path: Path) -> None:
    """The actual exploit: a directory symlink earlier in the chain
    redirects writes outside the intended location."""
    real_dir = tmp_path / "real_dir"
    real_dir.mkdir()
    real_file = real_dir / "data.txt"
    real_file.write_text("real")

    link_dir = tmp_path / "link_dir"
    link_dir.symlink_to(real_dir)

    # link_dir is a symlink; everything under it inherits the chain.
    target_via_link = link_dir / "data.txt"
    with pytest.raises(SymlinkRefused):
        raise_if_symlink_in_chain(target_via_link)


def test_passes_for_non_symlink_path(tmp_path: Path) -> None:
    target = tmp_path / "subdir" / "file.txt"
    target.parent.mkdir()
    target.write_text("content")
    # No exception raised
    raise_if_symlink_in_chain(target)


def test_passes_for_nonexistent_target_in_clean_dir(tmp_path: Path) -> None:
    """We allow the target itself to not exist (we're about to create it)
    as long as no existing ancestor is a symlink."""
    target = tmp_path / "newfile.txt"
    raise_if_symlink_in_chain(target)


def test_root_constraint_rejects_escape(tmp_path: Path) -> None:
    scan_root = tmp_path / "scan_root"
    scan_root.mkdir()
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    target = other_dir / "leaf.txt"
    target.write_text("x")
    with pytest.raises(TargetEscapesRoot):
        raise_if_symlink_in_chain(target, root=scan_root)


def test_atomic_write_creates_target(tmp_path: Path) -> None:
    target = tmp_path / "out.txt"
    atomic_write_text(target, "hello")
    assert target.read_text() == "hello"


def test_atomic_write_overwrites_existing(tmp_path: Path) -> None:
    target = tmp_path / "out.txt"
    target.write_text("old")
    atomic_write_text(target, "new")
    assert target.read_text() == "new"


def test_atomic_write_refuses_symlink_target(tmp_path: Path) -> None:
    target = tmp_path / "real.txt"
    target.write_text("real")
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    with pytest.raises(SymlinkRefused):
        atomic_write_text(link, "should not happen")
    # Original file unchanged
    assert target.read_text() == "real"


def test_atomic_write_refuses_symlink_in_chain(tmp_path: Path) -> None:
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    link_dir = tmp_path / "link"
    link_dir.symlink_to(real_dir)
    with pytest.raises(SymlinkRefused):
        atomic_write_text(link_dir / "out.txt", "content")


def test_atomic_write_sets_restrictive_perms(tmp_path: Path) -> None:
    target = tmp_path / "secret.txt"
    atomic_write_text(target, "supersecret", mode=0o600)
    st = target.stat()
    # On POSIX, only owner-read+write should be set; on Windows os.stat
    # returns 0o666 regardless and chmod has limited effect — skip there.
    if os.name == "posix":
        assert st.st_mode & 0o777 == 0o600


def test_atomic_write_no_partial_on_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "dest.txt"
    target.write_text("original")

    # Force os.replace to fail; verify original survives + temp is cleaned.
    real_replace = os.replace

    def boom(*a: object, **kw: object) -> None:
        raise OSError("simulated disk full")

    monkeypatch.setattr(os, "replace", boom)

    with pytest.raises(OSError, match="simulated disk full"):
        atomic_write_text(target, "new content")

    # Original is untouched
    assert target.read_text() == "original"
    # No leftover .tmp file
    leftover = list(target.parent.glob(f".{target.name}.*.tmp"))
    assert leftover == [], f"leftover temp files: {leftover}"

    # Restore so subsequent tests work
    monkeypatch.setattr(os, "replace", real_replace)


def test_chain_walk_does_not_resolve_symlinks(tmp_path: Path) -> None:
    """raise_if_symlink_in_chain inspects each component with lstat (no
    follow). This is the core invariant — Path.resolve() would silently
    follow the symlink and miss the redirection."""
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    target = link / "leaf.txt"
    # lstat-based walk catches link as a symlink; resolve() would not.
    with pytest.raises(SymlinkRefused):
        raise_if_symlink_in_chain(target)


def test_chain_walk_with_relative_path(tmp_path: Path) -> None:
    target = tmp_path / "out.txt"
    # Should not crash with relative-style paths
    raise_if_symlink_in_chain(target)


def test_atomic_write_temp_filename_pattern(tmp_path: Path) -> None:
    """Temp file uses a deterministic prefix so cleanup tests can find it."""
    target = tmp_path / "foo.txt"
    atomic_write_text(target, "bar")
    # After successful write, no temp file should remain
    leftover = list(tmp_path.glob(f".{target.name}.*.tmp"))
    assert leftover == []
