"""Auto-remediation engine for SecureClaw findings.

Supports two safe actions:
1. redact_credential — Replace token values with [REDACTED] in the file
2. allowlist — Add finding to the allowlist to suppress in future scans
"""

from __future__ import annotations

import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Tuple

from secureclaw.core.models import Finding, Triage


@dataclass
class RemediationResult:
    """Result of a remediation run."""

    redacted: List[Tuple[Finding, str]] = field(default_factory=list)  # (finding, old_value)
    allowlisted: List[Finding] = field(default_factory=list)
    skipped: List[Tuple[Finding, str]] = field(default_factory=list)  # (finding, reason)
    errors: List[Tuple[Finding, str]] = field(default_factory=list)  # (finding, error)


# Pattern to find credential assignments: KEY=value or KEY: value
_CREDENTIAL_RE = re.compile(
    r"((?:OPENAI_API_KEY|ANTHROPIC_API_KEY|CLAUDE_API_KEY|AWS_SECRET_ACCESS_KEY|"
    r"GITHUB_TOKEN|PRIVATE_KEY|DATABASE_URL|STRIPE_SECRET)"
    r"\s*[=:]\s*['\"]?)"
    r"([A-Za-z0-9_\-/+=]{10,})"
    r"(['\"]?)",
)

REDACTED = "[REDACTED-BY-SECURECLAW]"


def redact_credential_in_file(finding: Finding) -> Tuple[bool, str]:
    """Redact a credential value in a file, preserving the key name.

    Returns (success, detail).
    """
    path = finding.file_path
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError) as e:
        return False, f"Cannot read: {e}"

    lines = content.split("\n")
    line_idx = finding.line_number - 1

    if line_idx < 0 or line_idx >= len(lines):
        return False, f"Line {finding.line_number} out of range"

    line = lines[line_idx]
    match = _CREDENTIAL_RE.search(line)
    if not match:
        return False, "Could not locate credential pattern on line"

    old_value = match.group(2)
    new_line = line[: match.start(2)] + REDACTED + line[match.end(2) :]
    lines[line_idx] = new_line

    # Atomic write: write to temp file first, then rename
    try:
        fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp", prefix=".secureclaw_")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as tmp_f:
                tmp_f.write("\n".join(lines))
            Path(tmp_path).replace(path)
        except BaseException:
            # Clean up temp file on any failure
            try:
                Path(tmp_path).unlink()
            except OSError:
                pass
            raise
    except (OSError, PermissionError) as e:
        return False, f"Cannot write: {e}"

    return True, old_value


def remediate_findings(
    findings: List[Finding],
    dry_run: bool = False,
    auto_only: bool = True,
) -> RemediationResult:
    """Run auto-remediation on scored findings.

    Args:
        findings: Scored findings (must have confidence/triage set).
        dry_run: If True, don't modify files — just report what would happen.
        auto_only: If True, only fix findings marked auto_fixable.
    """
    result = RemediationResult()

    for finding in findings:
        if auto_only and not finding.auto_fixable:
            result.skipped.append((finding, "Not auto-fixable"))
            continue

        if finding.triage == Triage.ACT_NOW and finding.fix_action == "redact_credential":
            if dry_run:
                result.redacted.append((finding, "[dry-run]"))
            else:
                ok, detail = redact_credential_in_file(finding)
                if ok:
                    result.redacted.append((finding, detail))
                else:
                    result.errors.append((finding, detail))

        elif finding.fix_action == "redact_credential":
            # Non-ACT_NOW credentials (archive, generated, etc.)
            if dry_run:
                result.redacted.append((finding, "[dry-run]"))
            else:
                ok, detail = redact_credential_in_file(finding)
                if ok:
                    result.redacted.append((finding, detail))
                else:
                    result.errors.append((finding, detail))

        elif finding.fix_action == "allowlist":
            result.allowlisted.append(finding)

        else:
            result.skipped.append((finding, f"Unknown action: {finding.fix_action}"))

    return result
