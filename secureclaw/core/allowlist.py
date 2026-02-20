"""Allowlist management with HMAC integrity verification.

Allowlist entries suppress specific findings by (file_pattern, pattern_id).
The allowlist file includes an HMAC signature to detect tampering.
"""

from __future__ import annotations

import fnmatch
import hashlib
import hmac
import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from secureclaw.core.models import AllowlistEntry, Finding

logger = logging.getLogger(__name__)

# Default allowlist location
DEFAULT_ALLOWLIST_DIR = ".secureclaw"
DEFAULT_ALLOWLIST_FILE = "allowlist.json"


# HMAC key derived from machine-specific data (not a secret — just tamper detection)
def _get_hmac_key() -> bytes:
    """Generate a machine-specific HMAC key for tamper detection."""
    machine_id = f"{os.name}-{Path.home()}-secureclaw"
    return hashlib.sha256(machine_id.encode()).digest()


def _compute_hmac(entries_json: str) -> str:
    """Compute HMAC-SHA256 for the allowlist entries."""
    return hmac.new(_get_hmac_key(), entries_json.encode(), hashlib.sha256).hexdigest()


def _normalize_path(path_str: str) -> str:
    """Normalize path separators for cross-platform matching."""
    return path_str.replace("\\", "/")


class Allowlist:
    """Manages an allowlist of suppressed findings."""

    def __init__(self, entries: Optional[List[AllowlistEntry]] = None):
        self._entries: List[AllowlistEntry] = entries or []

    @property
    def entries(self) -> List[AllowlistEntry]:
        return list(self._entries)

    def add(
        self,
        file_pattern: str,
        pattern_id: str,
        reason: str,
        approved_by: str = "user",
    ) -> AllowlistEntry:
        """Add an allowlist entry.

        Skips if an identical (file_pattern, pattern_id) already exists.
        """
        normalized = _normalize_path(file_pattern)
        # Dedup check: skip if this exact (file_pattern, pattern_id) pair already exists
        for existing in self._entries:
            if existing.file_pattern == normalized and existing.pattern_id == pattern_id:
                logger.debug("Allowlist entry already exists: %s / %s", normalized, pattern_id)
                return existing
        entry = AllowlistEntry(
            file_pattern=normalized,
            pattern_id=pattern_id,
            reason=reason,
            approved_by=approved_by,
            approved_at=datetime.now(timezone.utc).isoformat(),
        )
        self._entries.append(entry)
        return entry

    def remove(self, file_pattern: str, pattern_id: str) -> bool:
        """Remove an allowlist entry by file pattern and pattern ID."""
        normalized = _normalize_path(file_pattern)
        before = len(self._entries)
        self._entries = [
            e
            for e in self._entries
            if not (e.file_pattern == normalized and e.pattern_id == pattern_id)
        ]
        return len(self._entries) < before

    def is_suppressed(self, finding: Finding) -> bool:
        """Check if a finding is suppressed by the allowlist."""
        finding_path = _normalize_path(str(finding.file_path))
        for entry in self._entries:
            if entry.pattern_id != finding.pattern_id:
                continue
            if fnmatch.fnmatch(finding_path, entry.file_pattern):
                return True
            # Also try matching just the filename
            if fnmatch.fnmatch(Path(finding_path).name, entry.file_pattern):
                return True
        return False

    def filter_findings(self, findings: List[Finding]) -> tuple:
        """Filter findings through the allowlist. Returns (kept, suppressed_count)."""
        kept = []
        suppressed = 0
        for f in findings:
            if self.is_suppressed(f):
                suppressed += 1
            else:
                kept.append(f)
        return kept, suppressed

    def save(self, path: Path) -> None:
        """Save allowlist to a JSON file with HMAC integrity."""
        path.parent.mkdir(parents=True, exist_ok=True)
        entries_data = [
            {
                "file_pattern": e.file_pattern,
                "pattern_id": e.pattern_id,
                "reason": e.reason,
                "approved_by": e.approved_by,
                "approved_at": e.approved_at,
            }
            for e in self._entries
        ]
        entries_json = json.dumps(entries_data, indent=2, sort_keys=True)
        data = {
            "secureclaw_allowlist_version": 1,
            "description": (
                "SecureClaw allowlist - suppresses known false positives. "
                "Do not edit the _integrity field manually."
            ),
            "entries": entries_data,
            "_integrity": _compute_hmac(entries_json),
        }
        fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            Path(tmp_path).replace(path)
        except BaseException:
            try:
                Path(tmp_path).unlink()
            except OSError:
                pass
            raise
        logger.info("Allowlist saved to %s (%d entries)", path, len(self._entries))

    @classmethod
    def load(cls, path: Path, verify_integrity: bool = True) -> "Allowlist":
        """Load allowlist from a JSON file, optionally verifying HMAC integrity."""
        if not path.exists():
            return cls()

        with path.open(encoding="utf-8") as f:
            data = json.load(f)

        if verify_integrity:
            stored_hmac = data.get("_integrity", "")
            entries_json = json.dumps(data.get("entries", []), indent=2, sort_keys=True)
            expected_hmac = _compute_hmac(entries_json)
            if not hmac.compare_digest(stored_hmac, expected_hmac):
                logger.warning(
                    "Allowlist integrity check failed for %s. "
                    "The file may have been tampered with. "
                    "Use --skip-integrity to bypass this check.",
                    path,
                )
                return cls()

        entries = []
        for e in data.get("entries", []):
            entries.append(
                AllowlistEntry(
                    file_pattern=e.get("file_pattern", ""),
                    pattern_id=e.get("pattern_id", ""),
                    reason=e.get("reason", ""),
                    approved_by=e.get("approved_by", "unknown"),
                    approved_at=e.get("approved_at", ""),
                )
            )
        return cls(entries)

    @classmethod
    def find_allowlist(cls, scan_dir: Optional[Path] = None) -> Optional[Path]:
        """Find the allowlist file in standard locations."""
        candidates = []
        if scan_dir:
            candidates.append(scan_dir / DEFAULT_ALLOWLIST_DIR / DEFAULT_ALLOWLIST_FILE)
        candidates.append(Path.cwd() / DEFAULT_ALLOWLIST_DIR / DEFAULT_ALLOWLIST_FILE)
        candidates.append(Path.home() / ".config" / "secureclaw" / DEFAULT_ALLOWLIST_FILE)
        for path in candidates:
            if path.exists():
                return path
        return None
