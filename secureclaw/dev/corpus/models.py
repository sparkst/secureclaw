"""Foundation types for `secureclaw.dev.corpus`.

Spec §4 / §5. Single source of truth for `RefusalReason` and `KlassType` —
re-exported from ``secureclaw.dev.corpus.__init__`` per spec §4.1.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple

# --- Type aliases (spec §4.1) ------------------------------------------------

KlassType = Optional[Literal["positive", "negative", "borderline", "regression", "dos"]]
"""Fixture class — directory under tests/corpus/."""

RefusalReason = Literal[
    "secureclaw",
    "gitleaks",
    "trufflehog",
    "entropy_gate",
    "shape_check",
    "permission_error",
    "unicode_error",
    "disk_full",
]
"""Reason a file was refused by the anonymizer (spec §7)."""


_PATTERN_ID_RE = re.compile(r"^PI-[A-Z0-9]+$")
_VALID_MODES = ("exact", "superset", "subset")
_REQUIRED_FIXTURE_FIELDS = ("schema_version", "file", "mode", "source", "license")
_OPTIONAL_FIXTURE_FIELDS = (
    "expected_findings",
    "forbidden_findings",
    "category",
    "added_in_pr",
    "anonymization",
    "upstream_url",
    "upstream_commit",
    "derived_from",
    "regression_of",
)
_ALL_FIXTURE_FIELDS = _REQUIRED_FIXTURE_FIELDS + _OPTIONAL_FIXTURE_FIELDS


@dataclass(frozen=True)
class ExpectedFinding:
    """A finding the scanner is expected to emit on a fixture (spec §5)."""

    pattern_id: str
    line: Optional[int] = None
    confidence_range: Optional[Tuple[int, int]] = None

    def __post_init__(self) -> None:
        if not _PATTERN_ID_RE.match(self.pattern_id):
            raise ValueError(f"pattern_id {self.pattern_id!r} does not match ^PI-[A-Z0-9]+$")
        if self.line is not None and self.line < 1:
            raise ValueError(f"line must be >= 1, got {self.line}")
        if self.confidence_range is not None:
            low, high = self.confidence_range
            if not (0 <= low <= 100 and 0 <= high <= 100):
                raise ValueError(
                    f"confidence_range values must be in [0, 100], got {self.confidence_range}"
                )
            if low > high:
                raise ValueError(
                    f"confidence_range low must be <= high, got {self.confidence_range}"
                )


@dataclass(frozen=True)
class Fixture:
    """A single corpus fixture's metadata (spec §5)."""

    schema_version: int
    file: str
    mode: str
    source: str
    license: str
    path: Path  # path to the .expected.json file

    expected_findings: Tuple[ExpectedFinding, ...] = field(default_factory=tuple)
    forbidden_findings: Tuple[str, ...] = field(default_factory=tuple)
    category: Optional[str] = None
    added_in_pr: Optional[str] = None
    anonymization: Optional[Dict[str, Any]] = None

    # Spec §11 schema bump (optional attribution + regression linkage).
    upstream_url: Optional[str] = None
    upstream_commit: Optional[str] = None
    derived_from: Optional[str] = None
    regression_of: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any], *, path: Path) -> "Fixture":
        # Reject unknown fields per expected-schema.json `additionalProperties: false`.
        for key in data:
            if key not in _ALL_FIXTURE_FIELDS:
                raise ValueError(f"unknown field {key!r} in fixture metadata at {path}")

        # Required fields.
        for required in _REQUIRED_FIXTURE_FIELDS:
            if required not in data:
                raise ValueError(f"missing required field {required!r} at {path}")

        if data["schema_version"] != 2:
            raise ValueError(f"schema_version must be 2, got {data['schema_version']!r} at {path}")
        if data["mode"] not in _VALID_MODES:
            raise ValueError(f"mode must be one of {_VALID_MODES}, got {data['mode']!r} at {path}")

        expected = tuple(
            ExpectedFinding(
                pattern_id=ef["pattern_id"],
                line=ef.get("line"),
                confidence_range=(
                    tuple(ef["confidence_range"]) if "confidence_range" in ef else None
                ),
            )
            for ef in data.get("expected_findings", [])
        )
        forbidden = tuple(data.get("forbidden_findings", []))

        return cls(
            schema_version=data["schema_version"],
            file=data["file"],
            mode=data["mode"],
            source=data["source"],
            license=data["license"],
            path=path,
            expected_findings=expected,
            forbidden_findings=forbidden,
            category=data.get("category"),
            added_in_pr=data.get("added_in_pr"),
            anonymization=data.get("anonymization"),
            upstream_url=data.get("upstream_url"),
            upstream_commit=data.get("upstream_commit"),
            derived_from=data.get("derived_from"),
            regression_of=data.get("regression_of"),
        )

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "schema_version": self.schema_version,
            "file": self.file,
            "mode": self.mode,
            "source": self.source,
            "license": self.license,
        }
        if self.expected_findings:
            out["expected_findings"] = [
                {
                    k: v
                    for k, v in {
                        "pattern_id": ef.pattern_id,
                        "line": ef.line,
                        "confidence_range": (
                            list(ef.confidence_range) if ef.confidence_range else None
                        ),
                    }.items()
                    if v is not None
                }
                for ef in self.expected_findings
            ]
        if self.forbidden_findings:
            out["forbidden_findings"] = list(self.forbidden_findings)
        for opt_key, opt_val in (
            ("category", self.category),
            ("added_in_pr", self.added_in_pr),
            ("anonymization", self.anonymization),
            ("upstream_url", self.upstream_url),
            ("upstream_commit", self.upstream_commit),
            ("derived_from", self.derived_from),
            ("regression_of", self.regression_of),
        ):
            if opt_val is not None:
                out[opt_key] = opt_val
        return out

    def klass(self) -> str:
        """Derive class from the fixture's containing directory."""
        # path = .../tests/corpus/<klass>/<file>.expected.json or
        #        .../tests/corpus/regression/<group>/<file>.expected.json
        parts = self.path.parts
        # Walk back to find the segment after "corpus".
        for i, part in enumerate(parts):
            if part == "corpus" and i + 1 < len(parts):
                return parts[i + 1]
        raise ValueError(f"fixture path {self.path} is not under a tests/corpus/ tree")


@dataclass(frozen=True)
class ValidationError:
    """A problem found by `secureclaw dev corpus validate` (spec §6.3)."""

    path: Path
    severity: str  # 'error' or 'warning'
    message: str

    def __post_init__(self) -> None:
        if self.severity not in ("error", "warning"):
            raise ValueError(f"severity must be 'error' or 'warning', got {self.severity!r}")


@dataclass
class AnonymizeReport:
    """Summary of an `anonymize_tree` run (spec §7.7)."""

    src_root: Path
    dst_root: Path
    processed: int = 0
    refused: int = 0
    skipped: int = 0
    errors: int = 0
    refused_files: List[Tuple[Path, RefusalReason]] = field(default_factory=list)
    aborted: bool = False  # set when run-aborting error (disk full, etc.)

    def exit_code(self) -> int:
        """Spec §6.4: exit non-zero if any file was refused or run aborted."""
        if self.aborted or self.refused or self.errors:
            return 1
        return 0
