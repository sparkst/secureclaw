"""``secureclaw.dev.rule`` — author and validate detection rules.

Public surface (PR-D, spec §4.1).
"""

from __future__ import annotations

from secureclaw.dev.rule.models import (
    RuleScaffold,
    RuleTestResult,
    RuleValidationError,
)

__all__ = [
    "RuleScaffold",
    "RuleTestResult",
    "RuleValidationError",
]
