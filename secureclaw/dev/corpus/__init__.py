"""`secureclaw.dev.corpus` — corpus management for SecureClaw fixtures.

Public surface (cross-PR contract for PR-D and PR-E per spec §4.1).
"""

from __future__ import annotations

from secureclaw.dev.corpus.loader import iter_fixtures, load_fixtures
from secureclaw.dev.corpus.models import (
    AnonymizeReport,
    ExpectedFinding,
    Fixture,
    KlassType,
    RefusalReason,
    ValidationError,
)
from secureclaw.dev.corpus.validator import validate_corpus

__all__ = [
    "AnonymizeReport",
    "ExpectedFinding",
    "Fixture",
    "KlassType",
    "RefusalReason",
    "ValidationError",
    "iter_fixtures",
    "load_fixtures",
    "validate_corpus",
]
