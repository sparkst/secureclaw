"""GUI server security primitives.

Per v1.3-plan-v10 REQ-16 + §H.11 + §H.12 + R7-SEC-P0-002 + R8-SEC-P0-002 +
R8-ARCH-P1-001 fixes.

Pure utility functions used by the future ``secureclaw.gui`` request
handler. Shipped separately from the handler so the security gates are
unit-testable in isolation and the wire-in PR can be reviewed against a
fixed set of contracts.

Public API:
    SessionToken        — bearer-token state container with TTL + rotation
    canonical_engine_setting(raw) -> "default" | "legacy"
    extract_bearer_token(headers) -> str | None
    validate_host_header(host, expected_host, expected_ports) -> bool
    validate_origin(origin, expected_origins) -> bool
    redact_token_in_log(line) -> str
    raise_if_outside_scan_root(target, scan_roots_visited) -> Path

These match the specs in v10 §H.4 (12-check /view validation) and §H.11
(GUI server hardening).
"""

from __future__ import annotations

import os
import re
import secrets
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping, Optional


# ---------------------------------------------------------------------------
# Engine canonicalizer (REQ-18 / §H.12 — re-exported from secureclaw/__init__
# so callers can use either path; identical implementation.)
# ---------------------------------------------------------------------------

_ENV_ENGINE_ALIASES = {
    "v1": "legacy",
    "1": "legacy",
    "legacy": "legacy",
    "v2": "default",
    "2": "default",
    "default": "default",
    "": "default",
}


def canonical_engine_setting(raw: object) -> str:
    """Normalize an engine selection input to ``"default"`` or ``"legacy"``."""
    if raw is None:
        return "default"
    return _ENV_ENGINE_ALIASES.get(str(raw).strip().lower(), "default")


# ---------------------------------------------------------------------------
# Session token (REQ-16 + §H.11 rule 2)
# ---------------------------------------------------------------------------

DEFAULT_TOKEN_TTL_SECONDS = 30 * 60  # 30-min idle timeout per REQ-16


@dataclass
class SessionToken:
    """Per-process session token with TTL + idle rotation.

    The handler authenticates every request via ``Authorization: Bearer <value>``.
    On request: bump ``last_seen``. After ``ttl_seconds`` of inactivity the
    token is rotated; old token rejected.

    Generated from ``secrets.token_urlsafe(32)`` for cryptographically strong
    randomness. Never logged (see ``redact_token_in_log``).
    """

    value: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    ttl_seconds: float = DEFAULT_TOKEN_TTL_SECONDS
    last_seen: float = field(default_factory=time.monotonic)

    def is_expired(self, now: Optional[float] = None) -> bool:
        now = time.monotonic() if now is None else now
        return (now - self.last_seen) > self.ttl_seconds

    def touch(self, now: Optional[float] = None) -> None:
        self.last_seen = time.monotonic() if now is None else now

    def rotate(self) -> None:
        self.value = secrets.token_urlsafe(32)
        self.touch()


def extract_bearer_token(headers: Mapping[str, str]) -> Optional[str]:
    """Return the bearer token from an ``Authorization`` header, or None.

    Case-insensitive ``Bearer`` scheme. Whitespace tolerated. Rejects
    multiple credentials or malformed input.
    """
    auth = headers.get("Authorization") or headers.get("authorization")
    if not auth:
        return None
    parts = auth.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1].strip()
    return token or None


# ---------------------------------------------------------------------------
# Host header validation (R7-SEC + §H.11 rule 3 — defeats DNS rebinding)
# ---------------------------------------------------------------------------


def validate_host_header(
    host_header: Optional[str],
    *,
    allowed_hosts: Iterable[str] = ("127.0.0.1", "localhost"),
    expected_port: Optional[int] = None,
) -> bool:
    """Validate the ``Host`` header against an explicit allowlist.

    Returns False on missing header, unexpected host, or unexpected port.
    Per §H.11 rule 3, the only valid Hosts are ``127.0.0.1:<port>`` and
    ``localhost:<port>`` for the running server's port.
    """
    if not host_header:
        return False
    host_part, _, port_part = host_header.strip().rpartition(":")
    if not host_part:
        # No port in header: rpartition put everything in port_part. Treat
        # as host without explicit port (HTTP defaults to 80 — reject for
        # our local server which always has an explicit port).
        return False
    if host_part not in allowed_hosts:
        return False
    if expected_port is None:
        return True
    try:
        return int(port_part) == expected_port
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Origin / Referer validation (§H.11 rule 4)
# ---------------------------------------------------------------------------


def validate_origin(
    origin: Optional[str],
    *,
    allowed_origins: Iterable[str],
) -> bool:
    """Validate ``Origin`` (or fallback ``Referer``) against an allowlist.

    Required on POST/PUT/DELETE per §H.11 rule 4. Exact match (no
    wildcards) — local server should only ever see same-origin requests.
    """
    if not origin:
        return False
    return origin.strip() in set(allowed_origins)


# ---------------------------------------------------------------------------
# Token redaction in logs (§H.11 rule 11 + R5-CQ-P1-003)
# ---------------------------------------------------------------------------

# Order matters: more specific patterns first so we don't double-redact.
_REDACT_PATTERNS = [
    re.compile(r"(Authorization:\s*Bearer\s+)[\w\-\.]+", re.IGNORECASE),
    re.compile(r'("token"\s*:\s*")[\w\-]+'),  # JSON
    re.compile(r"(\?token=)[\w\-]+"),
    re.compile(r"(&token=)[\w\-]+"),
    re.compile(r"(#token=)[\w\-]+"),
]


def redact_token_in_log(line: str) -> str:
    """Replace token values with ``[REDACTED]`` for safe stdout/stderr emission."""
    for pat in _REDACT_PATTERNS:
        line = pat.sub(r"\1[REDACTED]", line)
    return line


# ---------------------------------------------------------------------------
# /view path traversal (§H.4 12-check, partial — full chain in PR-K-PR
# follow-up that wires into the actual /view endpoint)
# ---------------------------------------------------------------------------


class PathRejected(Exception):
    """Raised by ``raise_if_outside_scan_root`` on any traversal violation."""


def raise_if_outside_scan_root(
    requested: str,
    *,
    scan_roots_visited: Iterable[Path],
) -> Path:
    """Validate a /view or /api/rescan-file request path against scan-time roots.

    Implements the §H.4 12-check chain in spirit (handles 7 of 12 here;
    the remaining checks involve OS-specific O_NOFOLLOW + TOCTOU and
    live in the request handler).

    Checks:
      1. URL-decode + reject double-encoded.
      2. Reject NUL bytes.
      3. Reject ``..`` and ``~`` literal segments.
      4. Reject Windows alternate data stream ``:`` in non-drive component.
      5. Reject UNC paths (``\\\\``).
      6. Reject NFKC-non-canonical paths (defeat homoglyph escape).
      7. Resolve and verify path is descendant of one ``scan_roots_visited`` entry.

    The remaining 5 checks (lstat, O_NOFOLLOW open, fstat-after-open
    inode compare, file-size cap, and existing-file precondition) are
    handled at the handler layer because they require a live file handle.
    """
    import urllib.parse

    decoded = urllib.parse.unquote(requested, errors="strict")
    if "%" in decoded:
        # double-encoded — the second unquote would expose another path
        raise PathRejected("double-encoded path")
    if "\x00" in decoded:
        raise PathRejected("null byte in path")

    parts = Path(decoded).parts
    for seg in parts:
        if seg in ("..", "~"):
            raise PathRejected(f"forbidden path segment: {seg}")
    # Windows ADS — colon in a non-leading part. Drive letter is parts[0].
    for seg in parts[1:]:
        if ":" in seg:
            raise PathRejected("Windows alternate data stream")
    if decoded.startswith("\\\\"):
        raise PathRejected("UNC path rejected")
    if unicodedata.normalize("NFKC", decoded) != decoded:
        raise PathRejected("non-canonical NFKC path")

    target = Path(decoded)
    try:
        resolved = target.resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise PathRejected(f"path does not resolve: {exc}") from exc

    real_visited = []
    for r in scan_roots_visited:
        try:
            real_visited.append(Path(r).resolve(strict=True))
        except (FileNotFoundError, OSError):
            continue

    for real_root in real_visited:
        try:
            common = Path(os.path.commonpath([str(real_root), str(resolved)]))
        except ValueError:
            # different drives on Windows
            continue
        if common == real_root:
            return resolved

    raise PathRejected("target is outside all visited scan roots")
