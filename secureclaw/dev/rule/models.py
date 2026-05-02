"""Foundation types for ``secureclaw.dev.rule`` (spec §9.1).

``RuleScaffold`` — inputs to :func:`scaffold_rule`.
``RuleTestResult`` — per-rule output from :func:`test_rule`.
``RuleValidationError`` — items returned by :func:`validate_rules`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Tuple

# A single fixture's per-rule outcome: ``(path, passed, diagnostic)``.
FixtureOutcome = Tuple[str, bool, str]


@dataclass(frozen=True)
class RuleScaffold:
    """Inputs to :func:`scaffold_rule`.

    Required fields enforced by ``__init__``; optional fields default to
    sensible values matching ``default_rules.json`` conservatism.
    """

    rule_id: str
    name: str
    category: str
    severity: str
    regex: str
    description: str
    remediation: str
    source: str
    license: str

    upstream_url: Optional[str] = None
    upstream_commit: Optional[str] = None
    derived_from: Optional[str] = None

    examples: Tuple[str, ...] = field(default_factory=tuple)
    applies_to: Tuple[str, ...] = ("any",)
    region_kinds: Tuple[str, ...] = ("any",)


@dataclass(frozen=True)
class RuleTestResult:
    """Outcome of :func:`test_rule` on a single rule (spec §9.1)."""

    rule_id: str
    positives: Tuple[FixtureOutcome, ...] = field(default_factory=tuple)
    negatives: Tuple[FixtureOutcome, ...] = field(default_factory=tuple)

    @property
    def passed(self) -> bool:
        """``True`` iff every positive AND every negative fixture passed."""
        return all(p[1] for p in self.positives) and all(n[1] for n in self.negatives)


@dataclass(frozen=True)
class RuleValidationError:
    """One problem found by :func:`validate_rules` (spec §9.1)."""

    rule_id: str
    severity: str  # 'error' or 'warning'
    message: str

    def __post_init__(self) -> None:
        if self.severity not in ("error", "warning"):
            raise ValueError(f"severity must be 'error' or 'warning', got {self.severity!r}")
