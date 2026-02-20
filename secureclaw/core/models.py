"""Core data models for SecureClaw.

All data flowing through the scan pipeline uses these typed contracts.
Pipeline order: Scan -> Raw Findings -> Allowlist filter -> Dedup -> Sort -> Format
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


class Severity(enum.Enum):
    """Finding severity levels.

    User-facing labels use plain English, not P0/P1/P2 jargon.
    """

    CRITICAL = "critical"  # Active exfiltration, immediate hijack risk
    HIGH = "high"  # Instruction override, role confusion
    ADVISORY = "advisory"  # Suspicious patterns worth reviewing

    @property
    def label(self) -> str:
        labels = {
            Severity.CRITICAL: "CRITICAL RISK",
            Severity.HIGH: "HIGH RISK",
            Severity.ADVISORY: "ADVISORY",
        }
        return labels[self]

    @property
    def description(self) -> str:
        descriptions = {
            Severity.CRITICAL: (
                "An attacker could hijack your AI's behavior or steal your data right now. "
                "Act immediately."
            ),
            Severity.HIGH: (
                "Someone could override your AI's instructions or confuse its role. "
                "Review and fix soon."
            ),
            Severity.ADVISORY: (
                "This pattern looks suspicious but may be intentional. "
                "Review to confirm it's expected."
            ),
        }
        return descriptions[self]

    @property
    def sort_key(self) -> int:
        return {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.ADVISORY: 2}[self]


class PatternCategory(enum.Enum):
    """Categories of prompt injection patterns."""

    EXFILTRATION = "exfiltration"
    INSTRUCTION_OVERRIDE = "instruction_override"
    ROLE_CONFUSION = "role_confusion"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    TOOL_MANIPULATION = "tool_manipulation"
    ENCODED_INJECTION = "encoded_injection"
    INVISIBLE_TEXT = "invisible_text"
    MARKDOWN_INJECTION = "markdown_injection"
    MCP_MANIPULATION = "mcp_manipulation"


@dataclass(frozen=True)
class Pattern:
    """A single detection pattern."""

    id: str
    name: str
    regex: str
    severity: Severity
    category: PatternCategory
    description: str
    remediation: str
    examples: List[str] = field(default_factory=list)
    case_sensitive: bool = False


class FileContext(enum.Enum):
    """Context classification for scanned files."""

    AI_CONFIG = "ai_config"  # Known AI tool config (.claude/, SKILL.md, agents/)
    USER_CONTENT = "user_content"  # Regular user files
    TEST_FIXTURE = "test_fixture"  # Test files that may legitimately contain patterns


class Triage(enum.Enum):
    """Triage tier for prioritized remediation."""

    ACT_NOW = "act_now"
    REVIEW = "review"
    SUPPRESSED = "suppressed"

    @property
    def label(self) -> str:
        return {
            Triage.ACT_NOW: "Act Now",
            Triage.REVIEW: "Review",
            Triage.SUPPRESSED: "Suppressed",
        }[self]


@dataclass
class Finding:
    """A single scan finding.

    Dedup key: (file_path, line_number, pattern_id)
    """

    file_path: Path
    line_number: int
    pattern_id: str
    pattern_name: str
    severity: Severity
    category: PatternCategory
    matched_text: str
    description: str
    remediation: str
    context_before: str = ""
    context_after: str = ""
    file_context: FileContext = FileContext.USER_CONTENT
    confidence: int = 50
    confidence_reason: str = ""
    triage: Triage = Triage.REVIEW
    auto_fixable: bool = False
    fix_action: str = ""

    @property
    def dedup_key(self) -> tuple:
        return (str(self.file_path).replace("\\", "/"), self.line_number, self.pattern_id)


@dataclass
class AllowlistEntry:
    """An allowlist entry to suppress a specific finding."""

    file_pattern: str  # glob pattern for file path
    pattern_id: str  # specific pattern to suppress
    reason: str
    approved_by: str = "user"
    approved_at: str = ""


@dataclass
class FileResult:
    """Scan result for a single file."""

    path: Path
    findings: List[Finding] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""
    encoding_used: str = "utf-8"


@dataclass
class PostureCheck:
    """A security posture check result for an AI tool."""

    tool_name: str
    check_name: str
    status: str  # "secure", "warning", "insecure", "not_found"
    description: str
    recommendation: str = ""
    config_path: Optional[Path] = None


@dataclass
class ScanSummary:
    """Summary statistics for a scan."""

    total_files_scanned: int = 0
    total_files_skipped: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    advisory_count: int = 0
    patterns_checked: int = 0
    scan_duration_seconds: float = 0.0
    directories_scanned: List[str] = field(default_factory=list)
    file_types_scanned: Dict[str, int] = field(default_factory=dict)
    file_types_skipped: Dict[str, int] = field(default_factory=dict)


@dataclass
class ScanResult:
    """Complete scan result — the output of the scan pipeline."""

    findings: List[Finding] = field(default_factory=list)
    file_results: List[FileResult] = field(default_factory=list)
    posture_checks: List[PostureCheck] = field(default_factory=list)
    summary: ScanSummary = field(default_factory=ScanSummary)
    allowlist_suppressions: int = 0
    tool_version: str = ""
    schema_version: int = 1

    @property
    def verdict(self) -> str:
        if self.summary.critical_count > 0:
            return (
                f"{self.summary.critical_count} critical issue(s) found. "
                "Your AI tools may be vulnerable to prompt injection attacks. "
                "See details below."
            )
        if self.summary.high_count > 0:
            return (
                f"{self.summary.high_count} high-risk issue(s) found. "
                "Review the findings below and address them soon."
            )
        if self.summary.advisory_count > 0:
            return (
                f"{self.summary.advisory_count} advisory notice(s). "
                "Your setup looks good overall. Review the notes below when convenient."
            )
        return (
            "No issues found. Your scanned files look clean. "
            "Run SecureClaw periodically to stay safe."
        )
