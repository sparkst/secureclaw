"""Self-contained HTML report generator with Sparkry AI branding.

Tabbed interface (Dashboard / Findings / Security Posture).
Inline SVG icons, tooltips on all badges.
Type-ahead search + dropdown filters. CSV export.
All CSS, JS, and icons are inlined for fully offline operation.
User content escaped via html.escape().
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import List

from secureclaw.core.models import (
    Finding,
    PostureCheck,
    ScanResult,
    Triage,
)


# -- Human-readable label maps --

_CATEGORY_LABELS = {
    "exfiltration": "Exposed Credentials",
    "instruction_override": "AI Instruction Tampering",
    "role_confusion": "AI Role Manipulation",
    "system_prompt_extraction": "System Prompt Leakage",
    "tool_manipulation": "Tool Misuse",
    "encoded_injection": "Hidden/Encoded Attacks",
    "invisible_text": "Invisible Text",
    "markdown_injection": "Markdown Injection",
    "mcp_manipulation": "Plugin Manipulation",
}

_CONTEXT_LABELS = {
    "ai_config": "AI Configuration",
    "user_content": "Your Documents",
    "test_fixture": "Test Files",
}

_CONTEXT_ICONS = {
    "ai_config": "bot",
    "user_content": "file-text",
    "test_fixture": "test-tube",
}

_TRIAGE_ICONS = {
    "act_now": "shield-alert",
    "review": "eye",
    "suppressed": "eye-off",
}

_TRIAGE_TIPS = {
    "act_now": "High-confidence threat that needs immediate attention.",
    "review": "Suspicious pattern that may be intentional. Review when you have time.",
    "suppressed": "Automatically downgraded &mdash; found in test files, archives, or placeholder values. Very unlikely to be a real threat.",
}

_CONTEXT_TIPS = {
    "ai_config": "Found in an AI tool configuration file (like CLAUDE.md or .cursorrules).",
    "user_content": "Found in your regular files (not a test or AI config).",
    "test_fixture": "Found in a test file. These often contain example patterns for testing.",
}

# -- Inline SVG icon data (Lucide-compatible, no CDN needed) --
# Each entry maps icon name to its SVG inner elements.
# viewBox is always "0 0 24 24", stroke="currentColor", fill="none".
_ICON_SVGS = {
    "shield": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    "shield-alert": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4"/><path d="M12 16h.01"/>',
    "shield-check": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
    "eye": '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>',
    "eye-off": '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>',
    "layout-dashboard": '<rect width="7" height="9" x="3" y="3" rx="1"/><rect width="7" height="5" x="14" y="3" rx="1"/><rect width="7" height="9" x="14" y="12" rx="1"/><rect width="7" height="5" x="3" y="16" rx="1"/>',
    "file-search": '<path d="M14 2v4a2 2 0 0 0 2 2h4"/><path d="M4.268 21a2 2 0 0 0 1.727 1H18a2 2 0 0 0 2-2V7l-5-5H6a2 2 0 0 0-2 2v3"/><circle cx="5" cy="14" r="3"/><path d="m9 18-1.5-1.5"/>',
    "folder-search": '<path d="M10.7 20H4a2 2 0 0 1-2-2V5c0-1.1.9-2 2-2h3.93a2 2 0 0 1 1.66.9l.82 1.2a2 2 0 0 0 1.66.9H20a2 2 0 0 1 2 2v4.1"/><path d="m21 21-1.9-1.9"/><circle cx="17.5" cy="17.5" r="2.5"/>',
    "zap": '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
    "clock": '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
    "search": '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
    "search-x": '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/><path d="m13.5 8.5-5 5"/><path d="m8.5 8.5 5 5"/>',
    "info": '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>',
    "wrench": '<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>',
    "alert-circle": '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>',
    "alert-triangle": '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
    "check-circle": '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><path d="m9 11 3 3L22 4"/>',
    "x-circle": '<circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/>',
    "file": '<path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/>',
    "file-text": '<path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><line x1="10" y1="9" x2="8" y2="9"/>',
    "test-tube": '<path d="M14.5 2v17.5c0 1.4-1.1 2.5-2.5 2.5s-2.5-1.1-2.5-2.5V2"/><path d="M8.5 2h7"/><path d="M14.5 16h-5"/>',
    "bot": '<path d="M12 8V4H8"/><rect width="16" height="12" x="4" y="8" rx="2"/><path d="M2 14h2"/><path d="M20 14h2"/><path d="M15 13v2"/><path d="M9 13v2"/>',
    "gauge": '<path d="m12 14 4-4"/><path d="M3.34 19a10 10 0 1 1 17.32 0"/>',
    "lightbulb": '<path d="M15 14c.2-1 .7-1.7 1.5-2.5 1-.9 1.5-2.2 1.5-3.5A6 6 0 0 0 6 8c0 1 .2 2.2 1.5 3.5.7.7 1.3 1.5 1.5 2.5"/><path d="M9 18h6"/><path d="M10 22h4"/>',
    "globe": '<circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/>',
    "sparkles": '<path d="m12 3-1.9 5.8a2 2 0 0 1-1.3 1.3L3 12l5.8 1.9a2 2 0 0 1 1.3 1.3L12 21l1.9-5.8a2 2 0 0 1 1.3-1.3L21 12l-5.8-1.9a2 2 0 0 1-1.3-1.3L12 3Z"/><path d="M5 3v4"/><path d="M19 17v4"/><path d="M3 5h4"/><path d="M17 19h4"/>',
    "github": '<path d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.403 5.403 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65-.17.6-.22 1.23-.15 1.85v4"/><path d="M9 18c-4.51 2-5-2-7-2"/>',
    "clipboard-copy": '<rect width="8" height="4" x="8" y="2" rx="1" ry="1"/><path d="M8 4H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/><path d="M16 4h2a2 2 0 0 1 2 2v4"/><path d="M21 14H11"/><path d="m15 10-4 4 4 4"/>',
    "check": '<path d="M20 6 9 17l-5-5"/>',
    "rotate-ccw": '<path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/>',
    "download": '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>',
}


def _icon(name: str, w: int = 0, h: int = 0, extra_style: str = "") -> str:
    """Return inline SVG for the given icon name."""
    svg_inner = _ICON_SVGS.get(name, "")
    if not svg_inner:
        return ""
    style_parts = ["display:inline-block", "vertical-align:middle", "flex-shrink:0"]
    if w:
        style_parts.append(f"width:{w}px")
    if h:
        style_parts.append(f"height:{h}px")
    if extra_style:
        style_parts.append(extra_style)
    style = ";".join(style_parts)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" '
        f'stroke="currentColor" stroke-width="2" stroke-linecap="round" '
        f'stroke-linejoin="round" aria-hidden="true" style="{style}">{svg_inner}</svg>'
    )


def _e(text: str) -> str:
    return html.escape(str(text), quote=True)


def _confidence_class(confidence: int) -> str:
    if confidence >= 60:
        return "confidence-high"
    if confidence >= 30:
        return "confidence-med"
    return "confidence-low"


def _triage_css_class(triage: Triage) -> str:
    return {
        Triage.ACT_NOW: "triage-act",
        Triage.REVIEW: "triage-review",
        Triage.SUPPRESSED: "triage-suppressed",
    }[triage]


def _finding_border_class(triage: Triage) -> str:
    return {
        Triage.ACT_NOW: "act_now",
        Triage.REVIEW: "review",
        Triage.SUPPRESSED: "suppressed",
    }[triage]


def _render_findings(findings: List[Finding]) -> str:
    if not findings:
        return ""
    rows = []
    for f in findings:
        tri_val = f.triage.value
        tri_css = _triage_css_class(f.triage)
        tri_icon = _TRIAGE_ICONS.get(tri_val, "info")
        tri_tip = _TRIAGE_TIPS.get(tri_val, "")
        border = _finding_border_class(f.triage)
        conf_css = _confidence_class(f.confidence)
        ctx_val = f.file_context.value
        ctx_label = _CONTEXT_LABELS.get(ctx_val, ctx_val)
        ctx_icon = _CONTEXT_ICONS.get(ctx_val, "file")
        ctx_tip = _CONTEXT_TIPS.get(ctx_val, "")
        ctx_css = {
            "ai_config": "ctx-ai",
            "user_content": "ctx-user",
            "test_fixture": "ctx-test",
        }.get(ctx_val, "ctx-user")

        auto_fix = ""
        if f.auto_fixable:
            auto_fix = (
                f'<span class="auto-fix-badge tooltip" tabindex="0">{_icon("zap", 11, 11)} Auto-Fix'
                f'<span class="tip-text">SecureClaw can fix this automatically. '
                f"If installed via pip: secureclaw fix report.json --apply | "
                f"If using standalone: python3 secureclaw.py fix report.json --apply</span></span>"
            )

        conf_tip = (
            f"Confidence: how sure we are this is a real threat. {f.confidence}% "
            + (
                "= virtually certain"
                if f.confidence >= 90
                else "= likely real"
                if f.confidence >= 60
                else "= moderate, may be intentional"
                if f.confidence >= 30
                else "= very unlikely to be a real threat"
            )
            + "."
        )

        rows.append(f"""
        <div class="finding {_e(border)}"
             data-category="{_e(f.category.value)}"
             data-context="{_e(ctx_val)}"
             data-triage="{_e(tri_val)}"
             data-autofix="{"yes" if f.auto_fixable else "no"}">
            <div class="finding-header">
                <span class="triage-badge {_e(tri_css)} tooltip" tabindex="0">{_icon(tri_icon, 12, 12)} {_e(f.triage.label)} ({_e(f.severity.value.upper())})<span class="tip-text">{tri_tip}</span></span>
                <span class="confidence-badge {_e(conf_css)} tooltip" tabindex="0">{_icon("gauge", 11, 11)} {f.confidence}%<span class="tip-text">{_e(conf_tip)}</span></span>
                {auto_fix}
                <span class="context-badge {_e(ctx_css)} tooltip" tabindex="0">{_icon(ctx_icon, 11, 11)} {_e(ctx_label)}<span class="tip-text">{_e(ctx_tip)}</span></span>
                <span class="pattern-name">{_e(f.pattern_name)}</span>
            </div>
            <div class="finding-details">
                <p>{_icon("file", 14, 14, "color:#64748b")} <span class="file-path">{_e(str(f.file_path))}:{f.line_number}</span></p>
                <p><strong>Found:</strong> <code>{_e(f.matched_text[:150])}</code></p>
            </div>
            <div class="finding-action">
                <p class="action-fix">{_icon("alert-circle", 16, 16)} <strong>Why it matters:</strong> {_e(f.description)}</p>
                <p class="action-review">{_icon("wrench", 16, 16)} <strong>How to fix:</strong> {_e(f.remediation)}</p>
            </div>
        </div>""")
    return "\n".join(rows)


def _render_posture(checks: List[PostureCheck]) -> str:
    if not checks:
        return ""
    icon_map = {
        "secure": "check-circle",
        "warning": "alert-triangle",
        "insecure": "x-circle",
        "not_found": "info",
        "advisory": "info",
    }
    rows = []
    for c in checks:
        status = c.status
        icon = icon_map.get(status, "info")
        style_class = (
            status if status in ("secure", "warning", "insecure", "not_found") else "not_found"
        )
        rec_html = ""
        if c.recommendation:
            rec_html = f'<div class="posture-rec">{_icon("lightbulb", 14, 14, "color:var(--sparkry-accent)")} {_e(c.recommendation)}</div>'
        rows.append(f"""
    <div class="posture-card {_e(style_class)}">
        <div class="posture-icon {_e(style_class)}">{_icon(icon, 20, 20)}</div>
        <div class="posture-content">
            <strong>{_e(c.tool_name)}</strong> &mdash; {_e(c.check_name)}
            <p>{_e(c.description)}</p>
            {rec_html}
        </div>
    </div>""")
    return "\n".join(rows)


def format_html_report(result: ScanResult) -> str:
    """Generate a self-contained HTML report with tabbed interface."""
    s = result.summary
    now = datetime.now(timezone.utc).strftime("%b %d, %Y at %H:%M UTC")

    # Build a display-friendly scan target for the title
    scan_target = ""
    if result.summary.directories_scanned:
        dirs = result.summary.directories_scanned
        scan_target = dirs[0]
        if len(dirs) > 1:
            scan_target += f" (+{len(dirs) - 1} more)"
    elif result.file_results:
        paths = sorted({str(fr.path.parent) for fr in result.file_results})
        if paths:
            scan_target = paths[0]
            if len(paths) > 1:
                scan_target += f" (+{len(paths) - 1} more)"

    # Triage counts
    findings = result.findings or []
    act_now_count = sum(1 for f in findings if f.triage == Triage.ACT_NOW)
    review_count = sum(1 for f in findings if f.triage == Triage.REVIEW)
    suppressed_count = sum(1 for f in findings if f.triage == Triage.SUPPRESSED)
    auto_fix_count = sum(1 for f in findings if f.auto_fixable)
    total_findings = len(findings)

    # Verdict
    if act_now_count > 0:
        verdict_class = "danger"
        verdict_text = f"{act_now_count} issue{'s' if act_now_count != 1 else ''} need{'s' if act_now_count == 1 else ''} your attention right now"
        verdict_sub = "We found files with exposed credentials or patterns that could let AI tools be manipulated. The good news: most can be fixed automatically."
    elif review_count > 0:
        verdict_class = "warning"
        verdict_text = (
            f"{review_count} item{'s' if review_count != 1 else ''} to review when you have time"
        )
        verdict_sub = "No urgent threats found, but some patterns are worth a quick look."
    else:
        verdict_class = "clean"
        verdict_text = "No issues found"
        verdict_sub = "Your files look clean. Run scans periodically to stay safe."

    # Posture summary counts
    posture_checks = result.posture_checks or []
    posture_secure = sum(1 for c in posture_checks if c.status == "secure")
    posture_warning = sum(1 for c in posture_checks if c.status in ("warning", "insecure"))
    posture_info = sum(1 for c in posture_checks if c.status in ("not_found", "advisory"))

    # Category options (human-readable)
    categories = sorted({f.category.value for f in findings}) if findings else []
    category_options = "\n                ".join(
        f'<option value="{_e(c)}">{_e(_CATEGORY_LABELS.get(c, c.replace("_", " ").title()))}</option>'
        for c in categories
    )

    # Context options (human-readable)
    contexts = sorted({f.file_context.value for f in findings}) if findings else []
    context_options = "\n                ".join(
        f'<option value="{_e(c)}">{_e(_CONTEXT_LABELS.get(c, c))}</option>' for c in contexts
    )

    findings_html = _render_findings(findings)
    posture_html = _render_posture(posture_checks)

    # Pre-compute the check icon for JS (escape single quotes for safe JS embedding)
    check_icon_js = _icon("check", 14, 14).replace("'", "\\'")

    # Posture check count for the tab badge
    posture_count = len(posture_checks)

    # Verdict icon
    verdict_icon_name = (
        "shield-alert"
        if verdict_class == "danger"
        else "alert-triangle"
        if verdict_class == "warning"
        else "shield-check"
    )

    # Pre-compute the posture tab button (avoids backslash escapes in f-string)
    posture_tab_btn = ""
    if posture_checks:
        posture_tab_btn = (
            "<button class='tab-btn' onclick=\"switchTab('posture')\" id='tab-posture'"
            " role='tab' aria-selected='false' aria-controls='panel-posture'>"
            + _icon("shield-check", 18, 18)
            + " Security Posture <span class='tab-count'>"
            + str(posture_count)
            + "</span></button>"
        )

    # Pre-compute the empty-state HTML (avoids nested f""" inside f""")
    empty_state_html = ""
    if total_findings == 0:
        _shield_icon = _icon(
            "shield-check", 48, 48, "color:var(--secure-color);margin-bottom:0.75rem"
        )
        empty_state_html = f"""
    <div style="text-align:center;padding:3rem 1.5rem;color:#64748b;">
        {_shield_icon}
        <p style="font-size:1.1rem;font-weight:600;color:#1e293b;margin-bottom:0.5rem;">No findings &mdash; your files look clean!</p>
        <p style="font-size:0.9rem;">SecureClaw scanned {s.total_files_scanned:,} files and found no prompt injection risks.</p>
        <p style="font-size:0.85rem;margin-top:0.5rem;">Run scans periodically to stay safe.</p>
    </div>
    """

    # Pre-compute posture section (avoids nested f''' with "" inside f""")
    posture_section_html = ""
    if posture_checks:
        _info_icon = _icon("info", 16, 16)
        posture_section_html = f"""
<!-- SECURITY POSTURE -->
<div class="tab-panel" id="panel-posture" role="tabpanel" aria-labelledby="tab-posture">
<div class="container">
    <div style="margin-bottom:1rem;font-size:0.9rem;color:#64748b;display:flex;align-items:center;gap:0.35rem;">
        {_info_icon}
        SecureClaw checks your AI tools' configuration for common security issues.
    </div>
    <div class="posture-summary">
        <div class="posture-stat">
            <div class="p-num" style="color:var(--secure-color);">{posture_secure}</div>
            <div class="p-label">Secure</div>
        </div>
        <div class="posture-stat">
            <div class="p-num" style="color:var(--warning-color);">{posture_warning}</div>
            <div class="p-label">Needs Attention</div>
        </div>
        <div class="posture-stat">
            <div class="p-num" style="color:#94a3b8;">{posture_info}</div>
            <div class="p-label">Informational</div>
        </div>
    </div>
    {posture_html}
</div>
</div>
"""

    # Pre-compute fix section (avoids nested f''' with "" inside f""")
    fix_section_html = ""
    if total_findings > 0:
        _wrench_icon = _icon("wrench", 20, 20)
        _copy_icon = _icon("clipboard-copy", 14, 14)
        fix_section_html = f"""
    <div class="fix-section">
        <h2>{_wrench_icon} How to Fix These Issues</h2>
        <ol class="fix-steps">
            <li><div><strong>Install SecureClaw</strong> (if you haven't already)
                <div class="code-block"><code>pip install secureclaw</code><button class="copy-btn" onclick="copyText(event, 'pip install secureclaw')">{_copy_icon} Copy</button></div>
                <div style="font-size:0.82rem;color:#64748b;margin-top:0.25rem;">Or download standalone: <code style="background:#f1f5f9;padding:0.1rem 0.3rem;border-radius:3px;font-size:0.78rem;">curl -O https://secureclaw.sparkry.ai/secureclaw.py</code></div>
            </div></li>
            <li><div><strong>Scan your files</strong> to generate a fixable report
                <div style="font-size:0.82rem;color:#64748b;margin-bottom:0.25rem;">If installed via pip:</div>
                <div class="code-block"><code>secureclaw scan ~/Documents --format json -o report.json</code><button class="copy-btn" onclick="copyText(event, 'secureclaw scan ~/Documents --format json -o report.json')">{_copy_icon} Copy</button></div>
                <div style="font-size:0.82rem;color:#64748b;margin:0.25rem 0;">If using standalone:</div>
                <div class="code-block"><code>python3 secureclaw.py scan ~/Documents --format json -o report.json</code><button class="copy-btn" onclick="copyText(event, 'python3 secureclaw.py scan ~/Documents --format json -o report.json')">{_copy_icon} Copy</button></div>
            </div></li>
            <li><div><strong>Preview fixes</strong> (safe &mdash; doesn't change anything)
                <div style="font-size:0.82rem;color:#64748b;margin-bottom:0.25rem;">If installed via pip:</div>
                <div class="code-block"><code>secureclaw fix report.json</code><button class="copy-btn" onclick="copyText(event, 'secureclaw fix report.json')">{_copy_icon} Copy</button></div>
                <div style="font-size:0.82rem;color:#64748b;margin:0.25rem 0;">If using standalone:</div>
                <div class="code-block"><code>python3 secureclaw.py fix report.json</code><button class="copy-btn" onclick="copyText(event, 'python3 secureclaw.py fix report.json')">{_copy_icon} Copy</button></div>
            </div></li>
            <li><div><strong>Apply fixes</strong> when you're ready
                <div style="font-size:0.82rem;color:#64748b;margin-bottom:0.25rem;">If installed via pip:</div>
                <div class="code-block"><code>secureclaw fix report.json --apply</code><button class="copy-btn" onclick="copyText(event, 'secureclaw fix report.json --apply')">{_copy_icon} Copy</button></div>
                <div style="font-size:0.82rem;color:#64748b;margin:0.25rem 0;">If using standalone:</div>
                <div class="code-block"><code>python3 secureclaw.py fix report.json --apply</code><button class="copy-btn" onclick="copyText(event, 'python3 secureclaw.py fix report.json --apply')">{_copy_icon} Copy</button></div>
                <div style="font-size:0.82rem;color:#64748b;margin-top:0.35rem;">Redacts exposed credentials and adds safe patterns to your allowlist. Make sure your work is committed to git first.</div>
            </div></li>
        </ol>
    </div>
    """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecureClaw Scan Report{" — " + _e(scan_target) if scan_target else ""}</title>
<style>
:root {{
    --sparkry-dark: #1a1a2e;
    --sparkry-accent: #e94560;
    --sparkry-blue: #0f3460;
    --sparkry-light: #16213e;
    --act-now-bg: #fef2f2; --act-now-color: #dc2626; --act-now-border: #fecaca;
    --review-bg: #fffbeb; --review-color: #d97706; --review-border: #fde68a;
    --suppressed-bg: #f1f5f9; --suppressed-color: #64748b; --suppressed-border: #cbd5e1;
    --secure-color: #10b981; --warning-color: #f59e0b; --insecure-color: #e94560;
    --autofix-bg: #f0fdf4; --autofix-color: #16a34a; --autofix-border: #bbf7d0;
}}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif; background:#f1f5f9; color:#1e293b; line-height:1.6; }}
h1,h2,h3,.tab-btn,.stat-number,.verdict-text {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif; font-weight:700; }}
svg {{ flex-shrink:0; }}

.header {{ background:linear-gradient(135deg,var(--sparkry-dark) 0%,var(--sparkry-blue) 100%); color:white; padding:1.5rem 2rem; display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:1rem; }}
.header-left {{ display:flex; align-items:center; gap:0.75rem; }}
.header-logo {{ display:flex; align-items:center; gap:0.5rem; }}
.header-logo svg {{ width:28px; height:28px; color:var(--sparkry-accent); }}
.header h1 {{ font-size:1.6rem; font-weight:600; letter-spacing:0.02em; }}
.header-tagline {{ font-size:0.85rem; color:#94a3b8; }}
.header-tagline a {{ color:var(--sparkry-accent); text-decoration:none; font-weight:600; }}
.header-tagline a:hover {{ text-decoration:underline; }}
.header-right {{ display:flex; align-items:center; gap:1rem; font-size:0.8rem; color:#94a3b8; }}

.tab-bar {{ background:white; border-bottom:2px solid #e2e8f0; display:flex; padding:0 2rem; position:sticky; top:0; z-index:100; box-shadow:0 1px 3px rgba(0,0,0,0.05); }}
.tab-btn {{ padding:0.85rem 1.5rem; font-size:0.95rem; font-weight:500; color:#64748b; border:none; background:none; cursor:pointer; border-bottom:3px solid transparent; transition:all 0.2s; display:flex; align-items:center; gap:0.5rem; letter-spacing:0.02em; }}
.tab-btn svg {{ width:18px; height:18px; }}
.tab-btn:hover {{ color:var(--sparkry-dark); background:#f8fafc; }}
.tab-btn:focus-visible {{ outline:2px solid var(--sparkry-accent); outline-offset:-2px; }}
.tab-btn.active {{ color:var(--sparkry-dark); border-bottom-color:var(--sparkry-accent); font-weight:600; }}
.tab-btn .tab-count {{ background:#e2e8f0; color:#475569; padding:0.1rem 0.5rem; border-radius:10px; font-size:0.75rem; font-family:inherit; }}
.tab-btn.active .tab-count {{ background:var(--sparkry-accent); color:white; }}
.tab-panel {{ display:none; }}
.tab-panel.active {{ display:block; }}

.container {{ max-width:1000px; margin:0 auto; padding:1.5rem; }}

.verdict-card {{ border-radius:12px; padding:1.5rem; margin-bottom:1.5rem; display:flex; align-items:center; gap:1rem; }}
.verdict-card.danger {{ background:var(--act-now-bg); border:1px solid var(--act-now-border); }}
.verdict-card.warning {{ background:var(--review-bg); border:1px solid var(--review-border); }}
.verdict-card.clean {{ background:#f0fdf4; border:1px solid #bbf7d0; }}
.verdict-card svg {{ width:32px; height:32px; flex-shrink:0; }}
.verdict-card.danger svg {{ color:var(--act-now-color); }}
.verdict-card.warning svg {{ color:var(--review-color); }}
.verdict-card.clean svg {{ color:var(--secure-color); }}
.verdict-text {{ font-size:1.15rem; font-weight:500; }}
.verdict-sub {{ font-size:0.9rem; color:#64748b; margin-top:0.25rem; font-family:inherit; }}

.stats-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:1rem; margin-bottom:1.5rem; }}
.stat-card {{ background:white; border-radius:12px; padding:1.25rem; box-shadow:0 1px 3px rgba(0,0,0,0.06); display:flex; align-items:center; gap:1rem; position:relative; cursor:default; }}
.stat-card.clickable {{ cursor:pointer; }}
.stat-card:hover {{ box-shadow:0 4px 12px rgba(0,0,0,0.1); }}
.stat-icon {{ width:48px; height:48px; border-radius:10px; display:flex; align-items:center; justify-content:center; flex-shrink:0; }}
.stat-icon svg {{ width:24px; height:24px; }}
.stat-icon.act {{ background:var(--act-now-bg); color:var(--act-now-color); }}
.stat-icon.rev {{ background:var(--review-bg); color:var(--review-color); }}
.stat-icon.files {{ background:#eff6ff; color:#3b82f6; }}
.stat-icon.fix {{ background:var(--autofix-bg); color:var(--autofix-color); }}
.stat-number {{ font-size:2rem; font-weight:700; line-height:1; }}
.stat-number.act {{ color:var(--act-now-color); }}
.stat-number.rev {{ color:var(--review-color); }}
.stat-number.files {{ color:#3b82f6; }}
.stat-number.fix {{ color:var(--autofix-color); }}
.stat-label {{ font-size:0.8rem; color:#64748b; margin-top:0.15rem; }}

.tooltip {{ position:relative; }}
.tooltip .tip-text {{ visibility:hidden; background:var(--sparkry-dark); color:white; font-size:0.78rem; line-height:1.4; padding:0.6rem 0.75rem; border-radius:6px; position:absolute; z-index:200; width:240px; top:calc(100% + 8px); left:50%; transform:translateX(-50%); opacity:0; transition:opacity 0.15s; pointer-events:none; font-family:inherit; font-weight:400; }}
.tooltip .tip-text::after {{ content:''; position:absolute; bottom:100%; left:50%; margin-left:-5px; border:5px solid transparent; border-bottom-color:var(--sparkry-dark); }}
.tooltip:hover .tip-text, .tooltip:focus .tip-text, .tooltip:focus-within .tip-text {{ visibility:visible; opacity:1; }}
.tooltip[tabindex] {{ outline:none; }}
.tooltip[tabindex]:focus-visible {{ outline:2px solid var(--sparkry-accent); outline-offset:2px; border-radius:4px; }}

.fix-section {{ background:white; border-radius:12px; padding:1.5rem; margin-bottom:1.5rem; box-shadow:0 1px 3px rgba(0,0,0,0.06); }}
.fix-section h2 {{ font-size:1.1rem; margin-bottom:1rem; display:flex; align-items:center; gap:0.5rem; }}
.fix-section h2 svg {{ width:20px; height:20px; color:var(--sparkry-accent); }}
.fix-steps {{ list-style:none; counter-reset:fix-step; }}
.fix-steps li {{ counter-increment:fix-step; padding:0.75rem 0; border-bottom:1px solid #f1f5f9; display:flex; align-items:flex-start; gap:0.75rem; }}
.fix-steps li:last-child {{ border-bottom:none; }}
.fix-steps li::before {{ content:counter(fix-step); background:var(--sparkry-dark); color:white; width:24px; height:24px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:0.75rem; font-weight:700; flex-shrink:0; margin-top:2px; }}
.code-block {{ background:#1e293b; color:#e2e8f0; padding:0.75rem 1rem; border-radius:6px; font-family:'SF Mono','Fira Code',monospace; font-size:0.85rem; margin:0.5rem 0; display:flex; align-items:center; justify-content:space-between; gap:0.5rem; overflow-x:auto; }}
.code-block code {{ white-space:nowrap; }}
.copy-btn {{ background:rgba(255,255,255,0.1); border:1px solid rgba(255,255,255,0.2); color:#94a3b8; padding:0.3rem 0.6rem; border-radius:4px; cursor:pointer; font-size:0.75rem; display:flex; align-items:center; gap:0.3rem; flex-shrink:0; transition:all 0.15s; }}
.copy-btn:hover {{ background:rgba(255,255,255,0.2); color:white; }}
.copy-btn:focus-visible {{ outline:2px solid var(--sparkry-accent); outline-offset:2px; background:rgba(255,255,255,0.2); color:white; }}
.copy-btn svg {{ width:14px; height:14px; }}

.scan-meta {{ background:white; border-radius:12px; padding:1rem 1.5rem; margin-bottom:1.5rem; box-shadow:0 1px 3px rgba(0,0,0,0.06); font-size:0.85rem; color:#64748b; display:flex; flex-wrap:wrap; gap:1rem; align-items:center; }}
.scan-meta svg {{ width:16px; height:16px; }}
.scan-meta-item {{ display:flex; align-items:center; gap:0.35rem; }}

.toolbar {{ background:white; border-radius:12px; padding:1rem 1.5rem; margin-bottom:1rem; box-shadow:0 1px 3px rgba(0,0,0,0.06); display:flex; flex-wrap:wrap; gap:0.75rem; align-items:center; }}
.toolbar select {{ padding:0.4rem 0.6rem; border:1px solid #e2e8f0; border-radius:6px; font-size:0.85rem; background:white; cursor:pointer; font-family:inherit; }}
.toolbar select:focus {{ outline:none; border-color:var(--sparkry-accent); box-shadow:0 0 0 2px rgba(233,69,96,0.15); }}
.filter-group {{ display:flex; align-items:center; gap:0.35rem; }}
.spacer {{ flex:1; }}
.btn {{ padding:0.45rem 1rem; border:none; border-radius:6px; font-size:0.85rem; font-weight:600; cursor:pointer; transition:all 0.15s; display:inline-flex; align-items:center; gap:0.35rem; font-family:inherit; }}
.btn svg {{ width:16px; height:16px; }}
.btn-export {{ background:var(--sparkry-dark); color:white; }}
.btn-export:hover {{ background:var(--sparkry-light); }}
.btn-reset {{ background:#e2e8f0; color:#475569; }}
.btn-reset:hover {{ background:#cbd5e1; }}
.btn:focus-visible {{ outline:2px solid var(--sparkry-accent); outline-offset:2px; }}
.filter-count {{ font-size:0.85rem; color:#64748b; font-weight:500; }}

.finding {{ background:white; border-radius:10px; padding:1rem 1.25rem; margin:0.6rem 0; box-shadow:0 1px 2px rgba(0,0,0,0.04); transition:all 0.15s; border-left:4px solid transparent; }}
.finding:hover {{ box-shadow:0 4px 12px rgba(0,0,0,0.08); }}
.finding.hidden {{ display:none; }}
.finding.act_now {{ border-left-color:var(--act-now-color); }}
.finding.review {{ border-left-color:var(--review-color); }}
.finding.suppressed {{ border-left-color:var(--suppressed-border); opacity:0.7; }}
.finding.suppressed:hover {{ opacity:1; }}

.finding-header {{ display:flex; align-items:center; gap:0.5rem; margin-bottom:0.5rem; flex-wrap:wrap; }}
.triage-badge {{ padding:0.2rem 0.5rem; border-radius:4px; font-size:0.72rem; font-weight:700; text-transform:uppercase; white-space:nowrap; display:inline-flex; align-items:center; gap:0.25rem; cursor:help; }}
.triage-badge svg {{ width:12px; height:12px; }}
.triage-act {{ background:var(--act-now-bg); color:var(--act-now-color); border:1px solid var(--act-now-border); }}
.triage-review {{ background:var(--review-bg); color:var(--review-color); border:1px solid var(--review-border); }}
.triage-suppressed {{ background:var(--suppressed-bg); color:var(--suppressed-color); border:1px solid var(--suppressed-border); }}

.confidence-badge {{ padding:0.15rem 0.4rem; border-radius:3px; font-size:0.72rem; font-weight:600; background:#f1f5f9; color:#64748b; cursor:help; display:inline-flex; align-items:center; gap:0.2rem; }}
.confidence-badge svg {{ width:11px; height:11px; }}
.confidence-high {{ background:#ede9fe; color:#7c3aed; }}
.confidence-med {{ background:#e0e7ff; color:#4338ca; }}
.confidence-low {{ background:#f1f5f9; color:#475569; }}

.auto-fix-badge {{ padding:0.15rem 0.4rem; border-radius:3px; font-size:0.68rem; font-weight:700; background:var(--autofix-bg); color:var(--autofix-color); border:1px solid var(--autofix-border); display:inline-flex; align-items:center; gap:0.2rem; cursor:help; }}
.auto-fix-badge svg {{ width:11px; height:11px; }}

.context-badge {{ padding:0.15rem 0.4rem; border-radius:3px; font-size:0.68rem; font-weight:600; text-transform:uppercase; letter-spacing:0.03em; cursor:help; display:inline-flex; align-items:center; gap:0.2rem; }}
.context-badge svg {{ width:11px; height:11px; }}
.ctx-ai {{ background:#f0fdf4; color:#166534; border:1px solid #bbf7d0; }}
.ctx-user {{ background:#fef3c7; color:#92400e; border:1px solid #fde68a; }}
.ctx-test {{ background:#e0e7ff; color:#3730a3; border:1px solid #c7d2fe; }}

.pattern-name {{ font-weight:600; font-size:0.9rem; }}

.finding-details {{ font-size:0.88rem; }}
.finding-details p {{ margin:0.35rem 0; display:flex; align-items:center; gap:0.35rem; }}
.finding-details code {{ background:#f1f5f9; padding:0.15rem 0.4rem; border-radius:3px; font-size:0.82rem; word-break:break-all; }}
.file-path {{ color:var(--sparkry-blue); font-family:'SF Mono','Fira Code',monospace; font-size:0.82rem; word-break:break-all; }}
.finding-action {{ margin-top:0.75rem; padding-top:0.75rem; border-top:1px solid #f1f5f9; }}
.finding-action p {{ font-size:0.85rem; color:#475569; display:flex; align-items:flex-start; gap:0.4rem; margin:0.25rem 0; }}
.finding-action p svg {{ width:16px; height:16px; flex-shrink:0; margin-top:2px; }}
.finding-action .action-fix {{ color:var(--act-now-color); }}
.finding-action .action-review {{ color:var(--review-color); }}
.finding-action .action-info {{ color:#64748b; }}

.no-results {{ text-align:center; padding:3rem; color:#94a3b8; display:none; }}
.no-results svg {{ width:48px; height:48px; margin-bottom:0.5rem; }}

.posture-card {{ background:white; border-radius:10px; padding:1rem 1.25rem; margin:0.6rem 0; box-shadow:0 1px 2px rgba(0,0,0,0.04); border-left:4px solid transparent; display:flex; gap:1rem; align-items:flex-start; }}
.posture-card.secure {{ border-left-color:var(--secure-color); }}
.posture-card.warning {{ border-left-color:var(--warning-color); }}
.posture-card.insecure {{ border-left-color:var(--insecure-color); }}
.posture-card.not_found {{ border-left-color:#94a3b8; }}
.posture-icon {{ width:36px; height:36px; border-radius:8px; display:flex; align-items:center; justify-content:center; flex-shrink:0; }}
.posture-icon svg {{ width:20px; height:20px; }}
.posture-icon.secure {{ background:#f0fdf4; color:var(--secure-color); }}
.posture-icon.warning {{ background:var(--review-bg); color:var(--warning-color); }}
.posture-icon.insecure {{ background:var(--act-now-bg); color:var(--insecure-color); }}
.posture-icon.not_found {{ background:#f1f5f9; color:#94a3b8; }}
.posture-content strong {{ font-size:0.95rem; }}
.posture-content p {{ font-size:0.85rem; color:#475569; margin-top:0.25rem; }}
.posture-rec {{ font-size:0.82rem; color:#64748b; font-style:italic; margin-top:0.35rem; display:flex; align-items:flex-start; gap:0.35rem; }}
.posture-rec svg {{ width:14px; height:14px; flex-shrink:0; margin-top:2px; color:var(--sparkry-accent); }}
.posture-summary {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:1rem; margin-bottom:1.5rem; }}
.posture-stat {{ background:white; border-radius:10px; padding:1rem; box-shadow:0 1px 3px rgba(0,0,0,0.06); text-align:center; }}
.posture-stat .p-num {{ font-size:1.8rem; font-weight:700; font-family:inherit; }}
.posture-stat .p-label {{ font-size:0.8rem; color:#64748b; }}

.footer {{ text-align:center; padding:2rem; color:#94a3b8; font-size:0.82rem; border-top:1px solid #e2e8f0; margin-top:2rem; }}
.footer a {{ color:var(--sparkry-accent); text-decoration:none; }}
.footer a:hover {{ text-decoration:underline; }}
.footer-links {{ display:flex; justify-content:center; gap:1.5rem; margin:0.5rem 0; flex-wrap:wrap; }}
.footer-links a {{ display:inline-flex; align-items:center; gap:0.3rem; }}
.footer-links a svg {{ width:14px; height:14px; }}
.license {{ margin-top:0.75rem; padding-top:0.75rem; border-top:1px solid #e2e8f0; font-size:0.78rem; }}

@media (max-width:640px) {{
    .header {{ padding:1rem; }}
    .header h1 {{ font-size:1.3rem; }}
    .tab-bar {{ padding:0 0.5rem; overflow-x:auto; }}
    .tab-btn {{ padding:0.75rem 1rem; font-size:0.85rem; white-space:nowrap; }}
    .stats-grid {{ grid-template-columns:repeat(2,1fr); }}
    .verdict-card {{ flex-direction:column; text-align:center; }}
    .verdict-card svg {{ margin:0 auto; }}
    .finding-header {{ flex-direction:column; align-items:flex-start; }}
    .toolbar {{ flex-direction:column; align-items:stretch; }}
    .code-block {{ flex-direction:column; align-items:stretch; }}
}}
@media (prefers-reduced-motion: reduce) {{
    *, *::before, *::after {{ animation-duration:0.01ms !important; animation-iteration-count:1 !important; transition-duration:0.01ms !important; scroll-behavior:auto !important; }}
}}
.skip-link {{ position:absolute; left:-9999px; top:auto; width:1px; height:1px; overflow:hidden; z-index:1000; }}
.skip-link:focus {{ position:fixed; top:0; left:0; width:auto; height:auto; padding:0.75rem 1.5rem; background:var(--sparkry-dark); color:white; font-size:1rem; font-weight:600; z-index:1000; outline:2px solid var(--sparkry-accent); }}
</style>
</head>
<body>
<a href="#main-content" class="skip-link">Skip to main content</a>

<div class="header">
    <div class="header-left">
        <div class="header-logo">
            {_icon("shield", 28, 28)}
            <h1>SecureClaw Scan Report</h1>
        </div>
        <div class="header-tagline">by <a href="https://sparkry.ai" target="_blank" rel="noopener">Sparkry AI</a></div>
    </div>
    <div class="header-right">
        <span>v{_e(result.tool_version)}</span>
        <span>|</span>
        <span>{now}</span>
    </div>
</div>

<div class="tab-bar" role="tablist" aria-label="Report sections">
    <button class="tab-btn active" onclick="switchTab('dashboard')" id="tab-dashboard" role="tab" aria-selected="true" aria-controls="panel-dashboard">
        {_icon("layout-dashboard", 18, 18)} Dashboard
    </button>
    <button class="tab-btn" onclick="switchTab('findings')" id="tab-findings" role="tab" aria-selected="false" aria-controls="panel-findings">
        {_icon("file-search", 18, 18)} Findings
        <span class="tab-count">{total_findings}</span>
    </button>
    {posture_tab_btn}
</div>

<main id="main-content">
<!-- DASHBOARD -->
<div class="tab-panel active" id="panel-dashboard" role="tabpanel" aria-labelledby="tab-dashboard">
<div class="container">

    <div class="verdict-card {verdict_class}">
        {_icon(verdict_icon_name, 32, 32)}
        <div>
            <div class="verdict-text">{_e(verdict_text)}</div>
            <div class="verdict-sub">{_e(verdict_sub)}</div>
        </div>
    </div>

    <div class="stats-grid">
        <div class="stat-card clickable tooltip" tabindex="0" role="button" aria-label="Filter findings to Act Now priority" onclick="filterByTriage('act_now')" onkeydown="if(event.key==='Enter'||event.key===' '){{event.preventDefault();filterByTriage('act_now');}}">
            <div class="stat-icon act">{_icon("shield-alert", 24, 24)}</div>
            <div>
                <div class="stat-number act">{act_now_count}</div>
                <div class="stat-label">Act Now</div>
            </div>
            <span class="tip-text">Real threats we're highly confident about &mdash; like exposed API keys. Fix these first.</span>
        </div>
        <div class="stat-card clickable tooltip" tabindex="0" role="button" aria-label="Filter findings to Review priority" onclick="filterByTriage('review')" onkeydown="if(event.key==='Enter'||event.key===' '){{event.preventDefault();filterByTriage('review');}}">
            <div class="stat-icon rev">{_icon("eye", 24, 24)}</div>
            <div>
                <div class="stat-number rev">{review_count}</div>
                <div class="stat-label">Review</div>
            </div>
            <span class="tip-text">Patterns that look suspicious but may be intentional. Review when you have time.</span>
        </div>
        <div class="stat-card tooltip" tabindex="0">
            <div class="stat-icon files">{_icon("folder-search", 24, 24)}</div>
            <div>
                <div class="stat-number files">{s.total_files_scanned:,}</div>
                <div class="stat-label">Files Scanned</div>
            </div>
            <span class="tip-text">Total files analyzed. {s.total_files_skipped:,} files were skipped (binary, images, etc.).</span>
        </div>
        <div class="stat-card clickable tooltip" tabindex="0" role="button" aria-label="Filter findings to auto-fixable only" onclick="filterByAutofix()" onkeydown="if(event.key==='Enter'||event.key===' '){{event.preventDefault();filterByAutofix();}}">
            <div class="stat-icon fix">{_icon("zap", 24, 24)}</div>
            <div>
                <div class="stat-number fix">{auto_fix_count}</div>
                <div class="stat-label">Auto-Fixable</div>
            </div>
            <span class="tip-text">SecureClaw can fix these automatically &mdash; like redacting exposed credentials. See "How to Fix" below.</span>
        </div>
    </div>

    <div class="scan-meta">
        <div class="scan-meta-item">{_icon("clock", 16, 16)} Scan took {s.scan_duration_seconds:.1f}s</div>
        <div class="scan-meta-item">{_icon("search", 16, 16)} {s.patterns_checked} patterns checked</div>
        <div class="scan-meta-item">{_icon("eye-off", 16, 16)}
            <span class="tooltip" tabindex="0">{suppressed_count} suppressed
                <span class="tip-text">Matched a pattern but automatically downgraded &mdash; test files, archives, or placeholder values. Very unlikely to be real threats.</span>
            </span>
        </div>
    </div>

    {fix_section_html}

</div>
</div>

<!-- FINDINGS -->
<div class="tab-panel" id="panel-findings" role="tabpanel" aria-labelledby="tab-findings">
<div class="container">
    <div class="toolbar" id="toolbar">
        <div class="filter-group" style="flex:1;min-width:200px;">
            {_icon("search", 16, 16, "color:#94a3b8")}
            <input type="text" id="filter-search" placeholder="Search files, patterns, matches..." oninput="debouncedFilter()" style="flex:1;padding:0.4rem 0.6rem;border:1px solid #e2e8f0;border-radius:6px;font-size:0.85rem;font-family:inherit;outline:none;" onfocus="this.style.borderColor='var(--sparkry-accent)';this.style.boxShadow='0 0 0 2px rgba(233,69,96,0.15)';" onblur="this.style.borderColor='#e2e8f0';this.style.boxShadow='none';" aria-label="Search findings">
        </div>
        <div class="filter-group">
            <select id="filter-triage" onchange="applyFilters()" aria-label="Filter by priority">
                <option value="all">All Priority</option>
                <option value="act_now">Act Now</option>
                <option value="review">Review</option>
                <option value="suppressed">Suppressed</option>
            </select>
        </div>
        <div class="filter-group">
            <select id="filter-category" onchange="applyFilters()" aria-label="Filter by type">
                <option value="all">All Types</option>
                {category_options}
            </select>
        </div>
        <div class="filter-group">
            <select id="filter-context" onchange="applyFilters()" aria-label="Filter by file type">
                <option value="all">All Files</option>
                {context_options}
            </select>
        </div>
        <div class="filter-group">
            <select id="filter-autofix" onchange="applyFilters()" aria-label="Filter by auto-fix">
                <option value="all">All</option>
                <option value="yes">Auto-Fixable Only</option>
            </select>
        </div>
        <span class="filter-count" id="filter-count" aria-live="polite"></span>
        <button class="btn btn-reset" onclick="resetFilters()">{_icon("rotate-ccw", 16, 16)} Reset</button>
        <button class="btn btn-export" onclick="exportCSV()">{_icon("download", 16, 16)} Export CSV</button>
    </div>

    <div id="findings-list">
    {findings_html}
    </div>
    {empty_state_html}
    <div class="no-results" id="no-results">
        {_icon("search-x", 48, 48)}
        <p>No findings match the current filters.</p>
        <p style="font-size:0.85rem;margin-top:0.5rem;"><a href="#" onclick="resetFilters();return false;">Reset all filters</a></p>
    </div>
</div>
</div>

{posture_section_html}
</main>

<div class="footer">
    <div class="footer-links">
        <a href="https://secureclaw.sparkry.ai">{_icon("globe", 14, 14)} secureclaw.sparkry.ai</a>
        <a href="https://sparkry.ai">{_icon("sparkles", 14, 14)} Sparkry AI</a>
        <a href="https://github.com/sparkryai/secureclaw">{_icon("github", 14, 14)} GitHub</a>
    </div>
    <p style="margin-top:0.5rem;">SecureClaw v{_e(result.tool_version)} &mdash; Generated {now}</p>
    <p style="margin-top:0.25rem;">Run periodically to stay safe. Update: <code style="background:#f1f5f9;padding:0.1rem 0.3rem;border-radius:3px;font-size:0.78rem;">pip install -U secureclaw</code></p>
    <div class="license">
        <p>MIT License &copy; 2026 Sparkry AI LLC. Free to use, modify, and distribute.</p>
        <p>Your AI reads your files. Make sure those files aren't trying to hijack it.</p>
    </div>
</div>

<script>
/* Tab switching with ARIA */
function switchTab(name) {{
    document.querySelectorAll('.tab-btn').forEach(function(b) {{
        b.classList.remove('active');
        b.setAttribute('aria-selected', 'false');
    }});
    document.querySelectorAll('.tab-panel').forEach(function(p) {{ p.classList.remove('active'); }});
    var tabBtn = document.getElementById('tab-' + name);
    var tabPanel = document.getElementById('panel-' + name);
    if (tabBtn) {{ tabBtn.classList.add('active'); tabBtn.setAttribute('aria-selected', 'true'); tabBtn.focus(); }}
    if (tabPanel) {{ tabPanel.classList.add('active'); }}
}}

/* Keyboard navigation for tab bar */
document.querySelector('.tab-bar').addEventListener('keydown', function(e) {{
    var tabs = Array.prototype.slice.call(this.querySelectorAll('.tab-btn'));
    var current = tabs.indexOf(document.activeElement);
    if (current === -1) return;
    var next = -1;
    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {{
        next = (current + 1) % tabs.length;
    }} else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {{
        next = (current - 1 + tabs.length) % tabs.length;
    }} else if (e.key === 'Home') {{
        next = 0;
    }} else if (e.key === 'End') {{
        next = tabs.length - 1;
    }} else if (e.key === 'Enter' || e.key === ' ') {{
        e.preventDefault();
        tabs[current].click();
        return;
    }}
    if (next !== -1) {{
        e.preventDefault();
        tabs[next].focus();
        tabs[next].click();
    }}
}});

/* Debounced search (200ms) */
var _filterTimer = null;
function debouncedFilter() {{
    if (_filterTimer) clearTimeout(_filterTimer);
    _filterTimer = setTimeout(applyFilters, 200);
}}

/* Filter findings with null guards for clean scans */
function applyFilters() {{
    var triEl = document.getElementById('filter-triage');
    var catEl = document.getElementById('filter-category');
    var ctxEl = document.getElementById('filter-context');
    var fixEl = document.getElementById('filter-autofix');
    var searchEl = document.getElementById('filter-search');
    if (!triEl || !catEl || !ctxEl || !fixEl) return;
    var tri = triEl.value;
    var cat = catEl.value;
    var ctx = ctxEl.value;
    var fix = fixEl.value;
    var query = (searchEl ? searchEl.value : '').toLowerCase().trim();
    var findings = document.querySelectorAll('.finding');
    var shown = 0;
    var total = findings.length;
    findings.forEach(function(el) {{
        var matchTri = (tri === 'all' || el.getAttribute('data-triage') === tri);
        var matchCat = (cat === 'all' || el.getAttribute('data-category') === cat);
        var matchCtx = (ctx === 'all' || el.getAttribute('data-context') === ctx);
        var matchFix = (fix === 'all' || el.getAttribute('data-autofix') === fix);
        var matchSearch = true;
        if (query) {{
            /* Search visible text only, excluding tooltip text */
            var searchText = '';
            el.querySelectorAll('.pattern-name, .file-path, .finding-details code, .finding-action strong').forEach(function(s) {{
                searchText += ' ' + s.textContent;
            }});
            searchText += ' ' + (el.getAttribute('data-category') || '') + ' ' + (el.getAttribute('data-triage') || '');
            matchSearch = searchText.toLowerCase().indexOf(query) !== -1;
        }}
        if (matchTri && matchCat && matchCtx && matchFix && matchSearch) {{
            el.classList.remove('hidden');
            shown++;
        }} else {{
            el.classList.add('hidden');
        }}
    }});
    var countEl = document.getElementById('filter-count');
    if (countEl) countEl.textContent = shown + ' of ' + total + ' findings';
    var noResults = document.getElementById('no-results');
    if (noResults) noResults.style.display = (shown === 0 && total > 0) ? 'block' : 'none';
}}

function resetFilters() {{
    var ids = ['filter-triage', 'filter-category', 'filter-context', 'filter-autofix'];
    ids.forEach(function(id) {{
        var el = document.getElementById(id);
        if (el) el.value = 'all';
    }});
    var searchEl = document.getElementById('filter-search');
    if (searchEl) searchEl.value = '';
    applyFilters();
}}

/* Stat card filter helpers — reset all filters first, then apply specific one */
function filterByTriage(value) {{
    resetFilters();
    var el = document.getElementById('filter-triage');
    if (el) {{ el.value = value; applyFilters(); }}
    switchTab('findings');
}}
function filterByAutofix() {{
    resetFilters();
    var el = document.getElementById('filter-autofix');
    if (el) {{ el.value = 'yes'; applyFilters(); }}
    switchTab('findings');
}}

/* Copy to clipboard with event parameter (Firefox-safe) + fallback */
function copyText(evt, text) {{
    var btn = evt && evt.target ? evt.target.closest('.copy-btn') : null;
    if (navigator.clipboard && navigator.clipboard.writeText) {{
        navigator.clipboard.writeText(text).then(function() {{
            if (btn) showCopied(btn);
        }}).catch(function() {{
            fallbackCopy(text, btn);
        }});
    }} else {{
        fallbackCopy(text, btn);
    }}
}}
function fallbackCopy(text, btn) {{
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;left:-9999px';
    document.body.appendChild(ta);
    ta.select();
    try {{ document.execCommand('copy'); if (btn) showCopied(btn); }} catch(e) {{}}
    document.body.removeChild(ta);
}}
function showCopied(btn) {{
    var orig = btn.innerHTML;
    btn.innerHTML = '{check_icon_js} Copied!';
    setTimeout(function() {{ btn.innerHTML = orig; }}, 2000);
}}

/* CSV export — extracts text without tooltip content */
function exportCSV() {{
    var catNames = {{'exfiltration':'Exposed Credentials','instruction_override':'AI Instruction Tampering','role_confusion':'AI Role Manipulation','system_prompt_extraction':'System Prompt Leakage','tool_manipulation':'Tool Misuse','encoded_injection':'Hidden/Encoded Attacks','invisible_text':'Invisible Text','markdown_injection':'Markdown Injection','mcp_manipulation':'Plugin Manipulation'}};
    var ctxNames = {{'ai_config':'AI Configuration','user_content':'Your Documents','test_fixture':'Test Files'}};
    var triNames = {{'act_now':'Act Now','review':'Review','suppressed':'Suppressed'}};
    var findings = document.querySelectorAll('.finding:not(.hidden)');
    var rows = [['Priority','Confidence','Type','Where Found','File','Match','Why It Matters','How to Fix','Auto-Fixable']];
    findings.forEach(function(el) {{
        var tri = el.getAttribute('data-triage') || '';
        var cat = el.getAttribute('data-category') || '';
        var ctx = el.getAttribute('data-context') || '';
        var autofix = el.getAttribute('data-autofix') || '';
        /* Extract confidence number from badge text, excluding tooltip */
        var confBadge = el.querySelector('.confidence-badge');
        var conf = '';
        if (confBadge) {{
            confBadge.querySelectorAll('.tip-text').forEach(function(t) {{ t.style.display = 'none'; }});
            conf = confBadge.textContent.trim();
            confBadge.querySelectorAll('.tip-text').forEach(function(t) {{ t.style.display = ''; }});
        }}
        var filePath = el.querySelector('.file-path') ? el.querySelector('.file-path').textContent : '';
        var match = '', desc = '', fix = '';
        var codeEl = el.querySelector('.finding-details code');
        if (codeEl) match = codeEl.textContent.trim();
        var fixEl = el.querySelector('.action-fix');
        if (fixEl) {{
            fixEl.querySelectorAll('.tip-text').forEach(function(t) {{ t.style.display = 'none'; }});
            desc = fixEl.textContent.replace(/Why it matters:\\s*/, '').trim();
            fixEl.querySelectorAll('.tip-text').forEach(function(t) {{ t.style.display = ''; }});
        }}
        var revEl = el.querySelector('.action-review');
        if (revEl) {{
            revEl.querySelectorAll('.tip-text').forEach(function(t) {{ t.style.display = 'none'; }});
            fix = revEl.textContent.replace(/How to fix:\\s*/, '').trim();
            revEl.querySelectorAll('.tip-text').forEach(function(t) {{ t.style.display = ''; }});
        }}
        rows.push([triNames[tri]||tri, conf, catNames[cat]||cat, ctxNames[ctx]||ctx, filePath, match, desc, fix, autofix==='yes'?'Yes':'No']);
    }});
    var csv = rows.map(function(r) {{
        return r.map(function(c) {{ return '"' + String(c).replace(/"/g, '""') + '"'; }}).join(',');
    }}).join('\\n');
    var blob = new Blob([csv], {{ type:'text/csv;charset=utf-8;' }});
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'secureclaw-findings.csv';
    a.click();
    URL.revokeObjectURL(a.href);
}}

/* Initialize filter count */
(function() {{
    var el = document.getElementById('filter-count');
    if (el) {{
        var total = document.querySelectorAll('.finding').length;
        el.textContent = total + ' of ' + total + ' findings';
    }}
}})();
</script>
</body>
</html>"""
