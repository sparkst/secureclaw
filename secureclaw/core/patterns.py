"""Pattern engine with decode-then-scan pipeline.

Pipeline: strip zero-width chars -> normalize NFKC -> decode HTML entities -> regex match
"""

from __future__ import annotations

import base64
import html
import json
import logging
import re
import unicodedata
from pathlib import Path
from typing import Dict, List, Optional

from secureclaw.core.models import (
    Finding,
    Pattern,
    PatternCategory,
    Severity,
)

logger = logging.getLogger(__name__)

# Zero-width and invisible Unicode characters used in injection attacks
ZERO_WIDTH_CHARS = re.compile(
    "[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064\ufeff"
    "\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e\u2000-\u200f"
    "\u202a-\u202e\u2066-\u2069\ufff0-\ufff8]"
)

# Base64 pattern (at least 20 chars to avoid false positives on short strings)
BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")


def _severity_from_str(s: str) -> Severity:
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "advisory": Severity.ADVISORY,
    }
    return mapping.get(s.lower(), Severity.ADVISORY)


def _category_from_str(s: str) -> PatternCategory:
    mapping = {e.value: e for e in PatternCategory}
    return mapping.get(s.lower(), PatternCategory.INSTRUCTION_OVERRIDE)


class PatternEngine:
    """Loads patterns and matches them against text using the decode-then-scan pipeline."""

    def __init__(self, patterns: Optional[List[Pattern]] = None):
        self._patterns: List[Pattern] = patterns or []
        self._compiled: Dict[str, re.Pattern] = {}
        self._compile_all()

    def _compile_all(self) -> None:
        for p in self._patterns:
            flags = 0 if p.case_sensitive else re.IGNORECASE
            try:
                self._compiled[p.id] = re.compile(p.regex, flags)
            except re.error as e:
                logger.warning("Invalid regex in pattern %s: %s", p.id, e)

    @property
    def pattern_count(self) -> int:
        return len(self._compiled)

    def preprocess(self, text: str) -> str:
        """Decode-then-scan pipeline: normalize text to expose hidden injections."""
        # Step 1: Strip zero-width / invisible Unicode characters
        cleaned = ZERO_WIDTH_CHARS.sub("", text)
        # Step 2: Unicode NFKC normalization (collapses homoglyphs)
        cleaned = unicodedata.normalize("NFKC", cleaned)
        # Step 3: Decode HTML entities
        cleaned = html.unescape(cleaned)
        return cleaned

    def decode_base64_segments(self, text: str) -> List[str]:
        """Find and decode base64-encoded segments that might contain injections."""
        decoded_segments = []
        for match in BASE64_PATTERN.finditer(text):
            candidate = match.group(0)
            try:
                decoded = base64.b64decode(candidate).decode("utf-8", errors="replace")
                if decoded.isprintable() or "\n" in decoded:
                    decoded_segments.append(decoded)
            except Exception:
                continue
        return decoded_segments

    def match_line(
        self,
        line: str,
        file_path: Path,
        line_number: int,
        context_before: str = "",
        context_after: str = "",
    ) -> List[Finding]:
        """Match a single line against all patterns after preprocessing."""
        findings: List[Finding] = []
        processed = self.preprocess(line)

        # Match against preprocessed line
        findings.extend(
            self._match_text(processed, file_path, line_number, context_before, context_after)
        )

        # Also check for base64-encoded injections in the original line
        for decoded in self.decode_base64_segments(line):
            decoded_processed = self.preprocess(decoded)
            for f in self._match_text(
                decoded_processed, file_path, line_number, context_before, context_after
            ):
                f.matched_text = f"[base64-decoded] {f.matched_text}"
                findings.append(f)

        return findings

    @staticmethod
    def _safe_matched_text(pattern: Pattern, raw: str) -> str:
        """Truncate matched text and redact credential values for PI-022."""
        text = raw[:200]
        if pattern.category == PatternCategory.EXFILTRATION:
            # Redact the value portion of KEY=value patterns
            text = re.sub(r'(=\s*)[^\s,;]+', r'\1[REDACTED]', text)
        return text

    @staticmethod
    def _redact_context(pattern: Pattern, context: str) -> str:
        """Apply the same credential redaction to context fields."""
        text = context[:200]
        if pattern.category == PatternCategory.EXFILTRATION:
            text = re.sub(r'(=\s*)[^\s,;]+', r'\1[REDACTED]', text)
        return text

    def _match_text(
        self,
        text: str,
        file_path: Path,
        line_number: int,
        context_before: str,
        context_after: str,
    ) -> List[Finding]:
        findings: List[Finding] = []
        for pattern in self._patterns:
            compiled = self._compiled.get(pattern.id)
            if not compiled:
                continue
            match = compiled.search(text)
            if match:
                findings.append(
                    Finding(
                        file_path=file_path,
                        line_number=line_number,
                        pattern_id=pattern.id,
                        pattern_name=pattern.name,
                        severity=pattern.severity,
                        category=pattern.category,
                        matched_text=self._safe_matched_text(pattern, match.group(0)),
                        description=pattern.description,
                        remediation=pattern.remediation,
                        context_before=self._redact_context(pattern, context_before),
                        context_after=self._redact_context(pattern, context_after),
                    )
                )
        return findings


def load_patterns_from_json(path: Path) -> List[Pattern]:
    """Load patterns from a JSON rules file."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        logger.error("Invalid JSON in rules file %s: %s", path, e)
        return []
    except OSError as e:
        logger.error("Cannot read rules file %s: %s", path, e)
        return []

    patterns = []
    for entry in data.get("patterns", []):
        try:
            # Validate regex compiles before accepting the pattern
            regex = entry["regex"]
            re.compile(regex)
            patterns.append(
                Pattern(
                    id=entry["id"],
                    name=entry["name"],
                    regex=regex,
                    severity=_severity_from_str(entry.get("severity", "advisory")),
                    category=_category_from_str(entry.get("category", "instruction_override")),
                    description=entry.get("description", ""),
                    remediation=entry.get("remediation", ""),
                    examples=entry.get("examples", []),
                    case_sensitive=entry.get("case_sensitive", False),
                )
            )
        except KeyError as e:
            logger.warning("Skipping pattern missing required field %s in %s", e, path)
        except re.error as e:
            logger.warning("Skipping pattern with invalid regex in %s: %s", path, e)
    return patterns


def load_default_patterns() -> List[Pattern]:
    """Load the built-in default pattern rules."""
    rules_path = Path(__file__).parent.parent / "rules" / "default_rules.json"
    if rules_path.exists():
        return load_patterns_from_json(rules_path)
    logger.warning("Default rules file not found at %s", rules_path)
    return []
