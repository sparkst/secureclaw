"""Symlink-safe filesystem primitives for auto-fix and trash operations.

Per v1.3-plan-v10 REQ-17 + §G.3 + R7-SEC-P0-003 + R8-SEC-P1-001 +
R8-ARCH-P1-002 fix:

Auto-fix and trash MUST refuse symlinks anywhere in the path chain — not
just the leaf. A malicious ``.env`` symlinking to ``~/.zshrc`` (or worse)
must not let an auto-fix corrupt arbitrary user files. Atomic writes via
``O_EXCL`` + ``fsync`` + ``os.rename`` ensure partial writes never leak.

Public API:
    raise_if_symlink_in_chain(target, root) -> None
    atomic_write_text(target, content, *, mode=0o600) -> None
    safe_send_to_trash(target) -> None  (wraps send2trash with lstat walk)
"""

from __future__ import annotations

import errno
import os
import stat
import tempfile
from pathlib import Path
from typing import Optional


class SymlinkRefused(Exception):
    """Raised when a path or any ancestor in the chain is a symlink."""


class TargetEscapesRoot(Exception):
    """Raised when a path resolves outside the declared scan root."""


def raise_if_symlink_in_chain(target: Path, root: Optional[Path] = None) -> None:
    """Walk every path component from ``root`` (or filesystem root) to
    ``target`` and raise ``SymlinkRefused`` if any is a symlink.

    ``Path.is_symlink()`` only checks the leaf. A directory symlink earlier
    in the chain (e.g., ``~/projects/myrepo/.env`` where ``myrepo`` is a
    symlink to a different user's directory) bypasses the leaf check and
    is the actual exploit vector flagged by R8-SEC-P0-002.

    If ``root`` is provided, the walk starts from ``root.resolve(strict=True)``;
    if not, it starts from the filesystem root and walks every ancestor.
    """
    if root is None:
        # Walk from filesystem root through every parent.
        absolute = Path(target).absolute()
        chain = list(absolute.parents)[::-1] + [absolute]
    else:
        real_root = Path(root).resolve(strict=True)
        try:
            rel_parts = Path(target).resolve(strict=False).relative_to(real_root).parts
        except ValueError as exc:
            raise TargetEscapesRoot(f"target {target!r} is not within root {root!r}") from exc
        chain = [real_root]
        current = real_root
        for part in rel_parts:
            current = current / part
            chain.append(current)

    for entry in chain:
        try:
            st = os.lstat(entry)
        except FileNotFoundError:
            # If a path component doesn't exist yet (e.g., we're about to
            # create a backup file in a non-symlinked directory), that's
            # fine — only existing components need the symlink check.
            continue
        if stat.S_ISLNK(st.st_mode):
            raise SymlinkRefused(f"refusing operation: symlink in path chain at {entry!r}")


def atomic_write_text(
    target: Path,
    content: str,
    *,
    mode: int = 0o600,
    encoding: str = "utf-8",
) -> None:
    """Write ``content`` to ``target`` atomically.

    Pattern: write to a sibling temp file with O_EXCL (rejects pre-created
    attacker file), fsync, then os.rename (atomic on POSIX). On any error
    the temp file is unlinked; the original target is never partially
    overwritten.

    Per R8-SEC backup contract: also validates no symlink in chain before
    write; sets restrictive 0600 perms on the new file.
    """
    target = Path(target)
    raise_if_symlink_in_chain(target)
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True)

    # Use mkstemp with O_EXCL so a pre-created hostile file fails the call.
    fd, tmp_path_str = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=parent,
    )
    tmp_path = Path(tmp_path_str)
    try:
        with os.fdopen(fd, "w", encoding=encoding) as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        tmp_path.chmod(mode)
        tmp_path.replace(target)
    except Exception:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass
        raise


def safe_send_to_trash(target: Path) -> None:
    """Send ``target`` to OS trash with symlink-walk pre-check.

    Per G.0 + R8-SEC-P1-007 fix: ``send2trash`` follows symlinks. We
    refuse if any ancestor (or the leaf) is a symlink, so a malicious
    ``.env`` symlinking outside the scan root can't trash an unrelated
    file.

    Imports send2trash lazily so the unit tests for this module don't
    require the dependency at collection time.
    """
    target = Path(target)
    raise_if_symlink_in_chain(target)
    if not target.exists():
        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), str(target))

    # Lazy import: callers without send2trash installed get a clear error.
    try:
        from send2trash import send2trash as _send_to_trash
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "send2trash is required for trash operations; "
            "install via `pip install secureclaw` (it's a runtime dep)."
        ) from exc

    _send_to_trash(str(target))
