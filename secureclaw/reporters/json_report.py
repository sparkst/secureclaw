"""JSON reporter with versioned schema for CI/CD integration."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict

from secureclaw.core.models import ScanResult


def format_json_report(result: ScanResult) -> str:
    """Generate a JSON report with stable, versioned schema."""
    s = result.summary
    report: Dict[str, Any] = {
        "schema_version": result.schema_version,
        "tool_version": result.tool_version,
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "verdict": result.verdict,
            "total_files_scanned": s.total_files_scanned,
            "total_files_skipped": s.total_files_skipped,
            "total_findings": s.total_findings,
            "critical_count": s.critical_count,
            "high_count": s.high_count,
            "advisory_count": s.advisory_count,
            "patterns_checked": s.patterns_checked,
            "scan_duration_seconds": round(s.scan_duration_seconds, 2),
            "allowlist_suppressions": result.allowlist_suppressions,
            "directories_scanned": s.directories_scanned,
        },
        "posture_checks": [
            {
                "tool_name": c.tool_name,
                "check_name": c.check_name,
                "status": c.status,
                "description": c.description,
                "recommendation": c.recommendation,
                "config_path": str(c.config_path) if c.config_path else None,
            }
            for c in result.posture_checks
        ],
        "findings": [
            {
                "file_path": str(f.file_path),
                "line_number": f.line_number,
                "pattern_id": f.pattern_id,
                "pattern_name": f.pattern_name,
                "severity": f.severity.value,
                "severity_label": f.severity.label,
                "category": f.category.value,
                "file_context": f.file_context.value,
                "confidence": f.confidence,
                "confidence_reason": f.confidence_reason,
                "triage": f.triage.value,
                "triage_label": f.triage.label,
                "auto_fixable": f.auto_fixable,
                "fix_action": f.fix_action,
                "matched_text": f.matched_text[:200],
                "description": f.description,
                "remediation": f.remediation,
            }
            for f in result.findings
        ],
    }
    return json.dumps(report, indent=2, ensure_ascii=False)
