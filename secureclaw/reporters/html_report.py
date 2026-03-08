"""Self-contained HTML report generator with Sparkry AI branding.

Tabbed interface (Dashboard / Findings / Security Posture).
Inline SVG icons, tooltips on all badges.
Type-ahead search + dropdown filters. CSV export.
All CSS, JS, and icons are inlined for fully offline operation.
User content escaped via html.escape().
"""

from __future__ import annotations

import html
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from secureclaw.core.models import (
    Finding,
    PostureCheck,
    ScanResult,
    Triage,
)


_LOGO_B64 = "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"

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

# Lucide-compatible inline SVG icons (viewBox "0 0 24 24", no CDN needed).
# Values are SVG inner elements; the wrapper is applied in _icon().
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
    "life-buoy": '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="4"/><line x1="4.93" y1="4.93" x2="9.17" y2="9.17"/><line x1="14.83" y1="14.83" x2="19.07" y2="19.07"/><line x1="14.83" y1="9.17" x2="19.07" y2="4.93"/><line x1="14.83" y1="9.17" x2="18.36" y2="5.64"/><line x1="4.93" y1="19.07" x2="9.17" y2="14.83"/>',
    "mail": '<rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/>',
    "circle": '<circle cx="12" cy="12" r="10"/>',
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


_WTD_TEXT = {
    "act_now": (
        "This file contains a hidden instruction that could manipulate your AI tools into "
        "ignoring your rules or leaking sensitive information. <strong>Do not share this file</strong> "
        "with anyone until it has been reviewed by your IT team or security contact. If you received "
        "this file from an outside source, notify the sender that it contains a security issue."
    ),
    "review": (
        "This file contains a pattern that could potentially be used to manipulate AI tools. "
        "Review it before using it with AI assistants like ChatGPT, Claude, or Copilot. "
        "If you\u2019re unsure, ask your IT contact to take a look."
    ),
    "suppressed": (
        "This is a low-risk observation. No action needed \u2014 we\u2019re just flagging it for awareness."
    ),
}


def _confidence_class(confidence: int) -> str:
    if confidence >= 60:
        return "confidence-high"
    if confidence >= 30:
        return "confidence-med"
    return "confidence-low"


_TRIAGE_CSS = {
    Triage.ACT_NOW: ("triage-act", "act_now"),
    Triage.REVIEW: ("triage-review", "review"),
    Triage.SUPPRESSED: ("triage-suppressed", "suppressed"),
}


def _triage_css_class(triage: Triage) -> str:
    return _TRIAGE_CSS[triage][0]


def _finding_border_class(triage: Triage) -> str:
    return _TRIAGE_CSS[triage][1]


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

        if f.confidence >= 90:
            conf_level = "= virtually certain"
        elif f.confidence >= 60:
            conf_level = "= likely real"
        elif f.confidence >= 30:
            conf_level = "= moderate, may be intentional"
        else:
            conf_level = "= very unlikely to be a real threat"
        conf_tip = f"Confidence: how sure we are this is a real threat. {f.confidence}% {conf_level}."

        wtd_text = _WTD_TEXT.get(tri_val, _WTD_TEXT["suppressed"])
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
                <p>{_icon("file", 14, 14, "color:#7a7670")} <span class="file-path">{_e(str(f.file_path))}{(":" + str(f.line_number)) if f.line_number is not None else ""}</span></p>
                <p><strong>Found:</strong> <code>{_e((f.matched_text or "")[:150])}</code></p>
            </div>
            <div class="finding-action">
                <p class="action-fix">{_icon("alert-circle", 16, 16)} <strong>Why it matters:</strong> {_e(f.description)}</p>
                <p class="action-review">{_icon("wrench", 16, 16)} <strong>How to fix:</strong> {_e(f.remediation)}</p>
            </div>
            <div class="what-to-do">
                <button class="wtd-toggle" onclick="this.parentElement.classList.toggle('open')">&#9658; What to do</button>
                <div class="wtd-content"><p>{wtd_text}</p></div>
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


def format_html_report(result: ScanResult, mode: str = "simple") -> str:
    """Generate a self-contained HTML report.

    Args:
        result: The scan result to render.
        mode: "simple" for single-page Lauren-friendly report,
              "detailed" for tabbed developer dashboard.
    """
    if mode == "simple":
        return _format_simple(result)
    return _format_detailed(result)


def _simple_css() -> str:
    """Return the <style> block for the simple report."""
    return """<style>
:root {
    --sparkry-dark: #1b1b1b;
    --sparkry-accent: #E8751A;
    --act-now-color: #cf5757;
    --review-color: #cfb357;
    --secure-color: #57cf7a;
}
*, *::before, *::after { box-sizing: border-box; }
body {
    margin: 0; padding: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    color: var(--sparkry-dark); background: #f8f7f5; line-height: 1.6;
}
.skip-link {
    position: absolute; left: -999px; top: auto;
    z-index: 100; padding: 8px 16px;
    background: var(--sparkry-accent); color: #fff;
}
.skip-link:focus { left: 8px; top: 8px; }
.header {
    background: var(--sparkry-dark); color: #fff;
    padding: 16px 24px; display: flex; align-items: center; gap: 16px;
}
.header-left { display: flex; align-items: center; gap: 12px; }
.header-logo { height: 28px; }
.header-tagline { font-size: 14px; opacity: 0.8; margin-left: auto; }
.container { max-width: 700px; margin: 0 auto; padding: 24px 16px; }
.verdict-hero {
    text-align: center; padding: 32px 16px; border-radius: 12px;
    margin-bottom: 24px; background: #fff;
}
.verdict-circle {
    width: 88px; height: 88px; border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    margin: 0 auto 16px;
}
.verdict-circle.danger { background: #fde8e8; color: var(--act-now-color); }
.verdict-circle.warning { background: #fdf5e1; color: var(--review-color); }
.verdict-circle.clean { background: #e5f9ea; color: var(--secure-color); }
.verdict-text { font-size: 20px; font-weight: 700; margin: 0 0 8px; }
.verdict-sub { font-size: 14px; color: #666; margin: 0; }
.summary-grid { display: flex; gap: 12px; margin-bottom: 24px; }
.summary-card {
    flex: 1; padding: 16px; border-radius: 8px; text-align: center;
    background: #fff;
}
.summary-card.danger { border-left: 4px solid var(--act-now-color); }
.summary-card.warning { border-left: 4px solid var(--review-color); }
.summary-num { font-size: 28px; font-weight: 700; }
.summary-card.danger .summary-num { color: var(--act-now-color); }
.summary-card.warning .summary-num { color: var(--review-color); }
.summary-label { font-size: 13px; color: #666; }
.section-heading {
    font-size: 18px; font-weight: 700; margin: 28px 0 12px;
    padding-bottom: 6px; border-bottom: 2px solid #eee;
}
.simple-finding {
    background: #fff; border-radius: 8px; padding: 16px;
    margin-bottom: 16px; border-left: 4px solid #ccc;
}
.simple-finding.act_now { border-left-color: var(--act-now-color); }
.simple-finding.review { border-left-color: var(--review-color); }
.finding-severity {
    display: flex; align-items: center; gap: 6px;
    font-size: 13px; font-weight: 600; margin-bottom: 6px;
}
.finding-severity .dot {
    width: 8px; height: 8px; border-radius: 50%; display: inline-block;
}
.act_now .finding-severity .dot { background: var(--act-now-color); }
.review .finding-severity .dot { background: var(--review-color); }
.act_now .finding-severity { color: var(--act-now-color); }
.review .finding-severity { color: var(--review-color); }
.finding-file { font-size: 13px; color: #888; margin-bottom: 8px; }
.finding-what { font-size: 14px; margin-bottom: 12px; }
.finding-action-box {
    background: #faf8f5; border-radius: 6px; padding: 12px;
    font-size: 14px; margin-bottom: 10px;
}
.finding-action-box strong { display: block; margin-bottom: 4px; }
details { margin-top: 8px; }
details summary {
    cursor: pointer; font-size: 13px; color: #888;
    padding: 4px 0; user-select: none;
}
details summary:hover { color: var(--sparkry-accent); }
.tech-detail { font-size: 13px; padding: 8px 0; color: #555; }
.tech-detail code {
    background: #f0efed; padding: 2px 6px; border-radius: 3px;
    font-size: 12px; word-break: break-all;
}
.tech-detail .file-path { color: #888; font-family: monospace; font-size: 12px; }
.checklist { background: #fff; border-radius: 8px; padding: 16px; }
.checklist-item {
    display: flex; align-items: flex-start; gap: 10px;
    padding: 10px 0; border-bottom: 1px solid #f0efed;
}
.checklist-item:last-child { border-bottom: none; }
.checklist-item.secure svg { color: var(--secure-color); }
.checklist-item.warning svg { color: var(--review-color); }
.checklist-item.insecure svg { color: var(--act-now-color); }
.checklist-item.not_found svg { color: #aaa; }
.get-help {
    background: #fff; border-radius: 8px; padding: 20px;
    margin-top: 24px;
}
.help-option { margin-bottom: 16px; }
.help-option:last-child { margin-bottom: 0; }
.help-btn {
    display: inline-block; padding: 10px 20px; border-radius: 6px;
    text-decoration: none; font-size: 14px; font-weight: 600;
    cursor: pointer; border: none;
}
.help-btn.primary {
    background: var(--sparkry-accent); color: #fff;
}
.help-btn.secondary {
    background: #f0efed; color: var(--sparkry-dark);
}
.copy-prompt {
    display: none; background: #f8f7f5; border-radius: 6px;
    padding: 12px; margin-top: 8px; font-size: 13px;
    font-family: monospace; white-space: pre-wrap; word-break: break-word;
}
.copy-prompt.visible { display: block; }
.footer {
    text-align: center; padding: 24px 16px; font-size: 12px;
    color: #999; border-top: 1px solid #eee; margin-top: 32px;
}
.footer a { color: var(--sparkry-accent); text-decoration: none; }
@media (max-width: 640px) {
    .header { flex-direction: column; align-items: flex-start; gap: 8px; }
    .header-tagline { margin-left: 0; }
    .summary-grid { flex-direction: column; }
    .verdict-hero { padding: 24px 12px; }
    .container { padding: 16px 12px; }
}
@media (prefers-reduced-motion: reduce) {
    *, *::before, *::after { animation-duration: 0.01ms !important; transition-duration: 0.01ms !important; }
}
</style>"""


def _simple_summary_counts(act_now: int, review: int) -> str:
    """Return summary cards HTML. Empty string if both are 0."""
    if act_now == 0 and review == 0:
        return ""
    parts = []
    parts.append('<div class="summary-grid">')
    if act_now > 0:
        parts.append(
            f'<div class="summary-card danger">'
            f'<div class="summary-num">{act_now}</div>'
            f'<div class="summary-label">Needs Action</div></div>'
        )
    if review > 0:
        parts.append(
            f'<div class="summary-card warning">'
            f'<div class="summary-num">{review}</div>'
            f'<div class="summary-label">Worth Reviewing</div></div>'
        )
    parts.append("</div>")
    return "\n".join(parts)


def _render_simple_findings(findings: List[Finding]) -> str:
    """Render finding cards grouped by triage (act_now first, then review)."""
    if not findings:
        return ""
    act_now_findings = [f for f in findings if f.triage == Triage.ACT_NOW]
    review_findings = [f for f in findings if f.triage == Triage.REVIEW]
    ordered = act_now_findings + review_findings

    parts = []
    for f in ordered:
        tri_val = f.triage.value
        if tri_val == "act_now":
            severity_label = "Needs Action"
        else:
            severity_label = "Worth Reviewing"

        filename = Path(f.file_path).name
        full_path = str(f.file_path)
        wtd_text = _WTD_TEXT.get(tri_val, _WTD_TEXT["review"])
        matched_truncated = _e((f.matched_text or "")[:120])

        parts.append(f"""<div class="simple-finding {_e(tri_val)}">
    <div class="finding-severity"><span class="dot"></span> {_e(severity_label)}</div>
    <div class="finding-file" title="{_e(full_path)}">{_e(filename)}</div>
    <div class="finding-what">{_e(f.description)}</div>
    <div class="finding-action-box">
        <strong>What to do</strong>
        {wtd_text}
    </div>
    <details>
        <summary>Technical details for your IT contact</summary>
        <div class="tech-detail">
            <p><strong>Pattern:</strong> {_e(f.pattern_name)}</p>
            <p><strong>File:</strong> <span class="file-path">{_e(full_path)}:{f.line_number}</span></p>
            <p><strong>Matched:</strong> <code>{matched_truncated}</code></p>
            <p><strong>Remediation:</strong> {_e(f.remediation)}</p>
        </div>
    </details>
</div>""")
    return "\n".join(parts)


def _render_simple_posture(checks: List[PostureCheck]) -> str:
    """Render posture checks as a collapsed checklist."""
    if not checks:
        return ""
    icon_map = {
        "secure": "check-circle",
        "warning": "alert-triangle",
        "insecure": "x-circle",
        "not_found": "info",
        "advisory": "info",
    }
    items = []
    for c in checks:
        status = c.status if c.status in ("secure", "warning", "insecure", "not_found") else "not_found"
        icon_name = icon_map.get(status, "info")
        rec_html = ""
        if c.recommendation:
            rec_html = f"<br><em>{_e(c.recommendation)}</em>"
        items.append(
            f'<div class="checklist-item {_e(status)}">'
            f'{_icon(icon_name, 18, 18)}'
            f'<div><strong>{_e(c.tool_name)}</strong> &mdash; {_e(c.check_name)}{rec_html}</div>'
            f'</div>'
        )
    return f"""<details>
    <summary class="section-heading" style="border-bottom:none;cursor:pointer">Your AI Tool Security Checklist</summary>
    <div class="checklist">
        {"".join(items)}
    </div>
</details>"""


def _render_get_help(findings: List[Finding], scan_target: str) -> str:
    """Render the Get Help section with mailto and Claude Code prompt."""
    if not findings:
        return ""

    # Build mailto
    top_findings = findings[:3]
    body_lines = [f"SecureClaw found {len(findings)} issue(s) in: {scan_target}", ""]
    for i, f in enumerate(top_findings, 1):
        body_lines.append(f"{i}. {f.pattern_name} in {Path(f.file_path).name} (line {f.line_number})")
    body_lines.append("")
    body_lines.append("Full report is attached.")
    subject = urllib.parse.quote(f"SecureClaw scan results - {len(findings)} issue(s) found")
    body = urllib.parse.quote("\n".join(body_lines))
    mailto = f"mailto:?subject={subject}&body={body}"

    # Build Claude Code prompt (only for findings with confidence >= 60)
    fixable = [f for f in findings if f.confidence >= 60]
    claude_section = ""
    if fixable:
        prompt_lines = ["Review and fix these SecureClaw findings:"]
        for f in fixable:
            prompt_lines.append(f"- {f.pattern_name} in {Path(f.file_path).name}:{f.line_number} -- {f.remediation}")
        prompt_text = _e("\n".join(prompt_lines))
        claude_section = f"""<div class="help-option">
        <p><strong>Fix with Claude Code</strong></p>
        <button class="help-btn secondary" onclick="var el=this.nextElementSibling;el.classList.toggle('visible')">Show prompt to copy</button>
        <div class="copy-prompt">{prompt_text}</div>
    </div>"""

    return f"""<div class="get-help">
    <h3>Get Help</h3>
    <div class="help-option">
        <p><strong>Share with your IT contact</strong></p>
        <a class="help-btn primary" href="{mailto}">{_icon("mail", 14, 14)} Email this report</a>
    </div>
    {claude_section}
</div>"""


def _format_simple(result: ScanResult) -> str:
    """Simplified single-page report for non-technical users."""
    s = result.summary
    now = datetime.now(timezone.utc).strftime("%b %d, %Y at %H:%M UTC")

    scan_target = ""
    if s.directories_scanned:
        scan_target = s.directories_scanned[0]
    elif result.file_results:
        paths = sorted({str(fr.path.parent) for fr in result.file_results})
        if paths:
            scan_target = paths[0]

    findings = result.findings or []
    # Exclude suppressed findings entirely
    visible_findings = [f for f in findings if f.triage != Triage.SUPPRESSED]
    act_now_count = sum(1 for f in visible_findings if f.triage == Triage.ACT_NOW)
    review_count = sum(1 for f in visible_findings if f.triage == Triage.REVIEW)

    # Verdict
    total_visible = act_now_count + review_count
    if act_now_count > 0:
        verdict_class = "danger"
        verdict_icon = _icon("shield-alert", 36, 36)
        verdict_text = f"{total_visible} issue{'s' if total_visible != 1 else ''} need{'s' if total_visible == 1 else ''} your attention"
        verdict_sub = "We found patterns that could let AI tools be manipulated. See details below."
    elif review_count > 0:
        verdict_class = "warning"
        verdict_icon = _icon("eye", 36, 36)
        verdict_text = f"{review_count} item{'s' if review_count != 1 else ''} need{'s' if review_count == 1 else ''} your attention"
        verdict_sub = "Nothing urgent, but a few things are worth a quick look."
    else:
        verdict_class = "clean"
        verdict_icon = _icon("shield-check", 36, 36)
        verdict_text = "Your files look clean"
        verdict_sub = "No issues found. Run SecureClaw periodically to stay safe."

    summary_html = _simple_summary_counts(act_now_count, review_count)
    findings_html = _render_simple_findings(visible_findings)
    posture_html = _render_simple_posture(result.posture_checks or [])
    help_html = _render_get_help(visible_findings, scan_target)

    findings_section = ""
    if findings_html:
        findings_section = f'<h2 class="section-heading">What We Found</h2>\n{findings_html}'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecureClaw Scan Report</title>
{_simple_css()}
</head>
<body>
<a class="skip-link" href="#main">Skip to content</a>
<header class="header">
    <div class="header-left">
        <img class="header-logo" src="data:image/png;base64,{_LOGO_B64}" alt="SecureClaw by Sparkry AI">
    </div>
    <span class="header-tagline">Scan Report &mdash; {_e(now)}</span>
</header>
<main id="main" class="container">
    <div class="verdict-hero">
        <div class="verdict-circle {verdict_class}">{verdict_icon}</div>
        <p class="verdict-text">{verdict_text}</p>
        <p class="verdict-sub">{verdict_sub}</p>
    </div>
    {summary_html}
    {findings_section}
    {posture_html}
    {help_html}
</main>
<footer class="footer">
    SecureClaw v{_e(result.tool_version)} by <a href="https://secureclaw.sparkry.ai">Sparkry AI</a><br>
    {s.total_files_scanned} files scanned &middot; {s.patterns_checked} patterns checked
</footer>
</body>
</html>"""


def _format_detailed(result: ScanResult) -> str:
    """Detailed tabbed report (original developer dashboard)."""
    s = result.summary
    now = datetime.now(timezone.utc).strftime("%b %d, %Y at %H:%M UTC")

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

    findings = result.findings or []
    act_now_count = sum(1 for f in findings if f.triage == Triage.ACT_NOW)
    review_count = sum(1 for f in findings if f.triage == Triage.REVIEW)
    suppressed_count = sum(1 for f in findings if f.triage == Triage.SUPPRESSED)
    auto_fix_count = sum(1 for f in findings if f.auto_fixable)
    total_findings = len(findings)

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

    posture_checks = result.posture_checks or []
    posture_secure = sum(1 for c in posture_checks if c.status == "secure")
    posture_warning = sum(1 for c in posture_checks if c.status in ("warning", "insecure"))
    posture_info = sum(1 for c in posture_checks if c.status in ("not_found", "advisory"))

    categories = sorted({f.category.value for f in findings}) if findings else []
    category_options = "\n                ".join(
        f'<option value="{_e(c)}">{_e(_CATEGORY_LABELS.get(c, c.replace("_", " ").title()))}</option>'
        for c in categories
    )

    contexts = sorted({f.file_context.value for f in findings}) if findings else []
    context_options = "\n                ".join(
        f'<option value="{_e(c)}">{_e(_CONTEXT_LABELS.get(c, c))}</option>' for c in contexts
    )

    findings_html = _render_findings(findings)
    posture_html = _render_posture(posture_checks)

    # Escape single quotes for safe JS embedding
    check_icon_js = _icon("check", 14, 14).replace("'", "\\'")

    posture_count = len(posture_checks)
    verdict_icon_name = (
        "shield-alert"
        if verdict_class == "danger"
        else "alert-triangle"
        if verdict_class == "warning"
        else "shield-check"
    )

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

    empty_state_html = ""
    if total_findings == 0:
        _shield_icon = _icon(
            "shield-check", 48, 48, "color:var(--secure-color);margin-bottom:0.75rem"
        )
        empty_state_html = f"""
    <div style="text-align:center;padding:3rem 1.5rem;color:#7a7670;">
        {_shield_icon}
        <p style="font-size:1.1rem;font-weight:600;color:#c5c1b9;margin-bottom:0.5rem;">No findings &mdash; your files look clean!</p>
        <p style="font-size:0.9rem;">SecureClaw scanned {s.total_files_scanned:,} files and found no hidden AI threats — your files look clean.</p>
        <p style="font-size:0.85rem;margin-top:0.5rem;">Run scans periodically to stay safe.</p>
    </div>
    """

    posture_section_html = ""
    if posture_checks:
        _info_icon = _icon("info", 16, 16)
        posture_section_html = f"""
<!-- SECURITY POSTURE -->
<div class="tab-panel" id="panel-posture" role="tabpanel" aria-labelledby="tab-posture">
<div class="container">
    <div style="margin-bottom:1rem;font-size:0.9rem;color:#7a7670;display:flex;align-items:center;gap:0.35rem;">
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
            <div class="p-num" style="color:#7a7670;">{posture_info}</div>
            <div class="p-label">Informational</div>
        </div>
    </div>
    {posture_html}
</div>
</div>
"""

    fix_section_html = ""
    if total_findings > 0:
        _wrench_icon = _icon("wrench", 20, 20)
        _shield_icon = _icon("shield", 16, 16)
        fix_section_html = f"""
    <div class="fix-section">
        <h2>{_wrench_icon} What To Do Next</h2>
        <ol class="fix-steps">
            <li><div><strong>Review each finding above</strong>
                <div style="font-size:0.82rem;color:#7a7670;margin-top:0.25rem;">Click any finding to expand it. Each one explains what was detected and why it matters. Findings marked <span style="color:var(--act-now-color);">Act Now</span> need immediate attention.</div>
            </div></li>
            <li><div><strong>Delete or quarantine suspicious files</strong>
                <div style="font-size:0.82rem;color:#7a7670;margin-top:0.25rem;">If a file contains hidden instructions targeting AI tools, move it to Trash. If you received it via email or download, do not open it in AI assistants like ChatGPT, Claude, or Copilot.</div>
            </div></li>
            <li><div><strong>Check files marked "Auto-Fixable"</strong>
                <div style="font-size:0.82rem;color:#7a7670;margin-top:0.25rem;">Some findings (like exposed API keys) can be automatically redacted. Look for the {_shield_icon} auto-fix badge on individual findings.</div>
            </div></li>
            <li><div><strong>Scan regularly</strong>
                <div style="font-size:0.82rem;color:#7a7670;margin-top:0.25rem;">New threats appear in downloads, email attachments, and shared documents. Run SecureClaw periodically on folders you use with AI tools.</div>
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
    --sparkry-dark: #1b1b1b;
    --sparkry-accent: #E8751A;
    --sparkry-blue: #242424;
    --sparkry-light: #2c2c2c;
    --act-now-bg: rgba(207,87,87,0.15); --act-now-color: #cf5757; --act-now-border: rgba(207,87,87,0.35);
    --review-bg: rgba(207,179,87,0.15); --review-color: #cfb357; --review-border: rgba(207,179,87,0.35);
    --suppressed-bg: rgba(122,118,112,0.15); --suppressed-color: #7a7670; --suppressed-border: rgba(122,118,112,0.35);
    --secure-color: #57cf7a; --warning-color: #cfb357; --insecure-color: #cf5757;
    --autofix-bg: rgba(87,207,122,0.12); --autofix-color: #57cf7a; --autofix-border: rgba(87,207,122,0.3);
}}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif; background:#1b1b1b; color:#c5c1b9; line-height:1.6; }}
h1,h2,h3,.tab-btn,.stat-number,.verdict-text {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif; font-weight:700; }}
svg {{ flex-shrink:0; }}

.header {{ background:linear-gradient(135deg,#1b1b1b 0%,#2c2c2c 100%); color:#ffffff; padding:1.5rem 2rem; display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:1rem; border-bottom:1px solid rgba(255,255,255,0.06); }}
.header-left {{ display:flex; align-items:center; gap:0.75rem; }}
.header-logo {{ display:flex; align-items:center; gap:0.5rem; }}
.header-logo svg {{ width:28px; height:28px; color:var(--sparkry-accent); }}
.header h1 {{ font-size:1.6rem; font-weight:600; letter-spacing:0.02em; }}
.header-tagline {{ font-size:0.85rem; color:#7a7670; }}
.header-tagline a {{ color:var(--sparkry-accent); text-decoration:none; font-weight:600; }}
.header-tagline a:hover {{ text-decoration:underline; }}
.header-right {{ display:flex; align-items:center; gap:1rem; font-size:0.8rem; color:#7a7670; }}

.tab-bar {{ background:#242424; border-bottom:2px solid rgba(255,255,255,0.06); display:flex; padding:0 2rem; position:sticky; top:0; z-index:100; box-shadow:0 1px 3px rgba(0,0,0,0.3); }}
.tab-btn {{ padding:0.85rem 1.5rem; font-size:0.95rem; font-weight:500; color:#7a7670; border:none; background:none; cursor:pointer; border-bottom:3px solid transparent; transition:all 0.2s; display:flex; align-items:center; gap:0.5rem; letter-spacing:0.02em; }}
.tab-btn svg {{ width:18px; height:18px; }}
.tab-btn:hover {{ color:#c5c1b9; background:rgba(255,255,255,0.04); }}
.tab-btn:focus-visible {{ outline:2px solid var(--sparkry-accent); outline-offset:-2px; }}
.tab-btn.active {{ color:#ffffff; border-bottom-color:var(--sparkry-accent); font-weight:600; }}
.tab-btn .tab-count {{ background:rgba(255,255,255,0.08); color:#7a7670; padding:0.1rem 0.5rem; border-radius:10px; font-size:0.75rem; font-family:inherit; }}
.tab-btn.active .tab-count {{ background:var(--sparkry-accent); color:white; }}
.tab-panel {{ display:none; }}
.tab-panel.active {{ display:block; }}

.container {{ max-width:1000px; margin:0 auto; padding:1.5rem; }}

.verdict-card {{ border-radius:12px; padding:1.5rem; margin-bottom:1.5rem; display:flex; align-items:center; gap:1rem; }}
.verdict-card.danger {{ background:var(--act-now-bg); border:1px solid var(--act-now-border); }}
.verdict-card.warning {{ background:var(--review-bg); border:1px solid var(--review-border); }}
.verdict-card.clean {{ background:rgba(87,207,122,0.1); border:1px solid rgba(87,207,122,0.3); }}
.verdict-card svg {{ width:32px; height:32px; flex-shrink:0; }}
.verdict-card.danger svg {{ color:var(--act-now-color); }}
.verdict-card.warning svg {{ color:var(--review-color); }}
.verdict-card.clean svg {{ color:var(--secure-color); }}
.verdict-text {{ font-size:1.15rem; font-weight:500; }}
.verdict-sub {{ font-size:0.9rem; color:#7a7670; margin-top:0.25rem; font-family:inherit; }}

.stats-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:1rem; margin-bottom:1.5rem; }}
.stat-card {{ background:#242424; border-radius:12px; padding:1.25rem; box-shadow:0 1px 3px rgba(0,0,0,0.3); display:flex; align-items:center; gap:1rem; position:relative; cursor:default; border:1px solid rgba(255,255,255,0.06); }}
.stat-card.clickable {{ cursor:pointer; }}
.stat-card:hover {{ box-shadow:0 4px 12px rgba(0,0,0,0.1); }}
.stat-icon {{ width:48px; height:48px; border-radius:10px; display:flex; align-items:center; justify-content:center; flex-shrink:0; }}
.stat-icon svg {{ width:24px; height:24px; }}
.stat-icon.act {{ background:var(--act-now-bg); color:var(--act-now-color); }}
.stat-icon.rev {{ background:var(--review-bg); color:var(--review-color); }}
.stat-icon.files {{ background:rgba(232,117,26,0.15); color:#E8751A; }}
.stat-icon.fix {{ background:var(--autofix-bg); color:var(--autofix-color); }}
.stat-number {{ font-size:2rem; font-weight:700; line-height:1; }}
.stat-number.act {{ color:var(--act-now-color); }}
.stat-number.rev {{ color:var(--review-color); }}
.stat-number.files {{ color:#E8751A; }}
.stat-number.fix {{ color:var(--autofix-color); }}
.stat-label {{ font-size:0.8rem; color:#7a7670; margin-top:0.15rem; }}

.tooltip {{ position:relative; }}
.tooltip .tip-text {{ visibility:hidden; background:var(--sparkry-dark); color:white; font-size:0.78rem; line-height:1.4; padding:0.6rem 0.75rem; border-radius:6px; position:absolute; z-index:200; width:240px; top:calc(100% + 8px); left:50%; transform:translateX(-50%); opacity:0; transition:opacity 0.15s; pointer-events:none; font-family:inherit; font-weight:400; }}
.tooltip .tip-text::after {{ content:''; position:absolute; bottom:100%; left:50%; margin-left:-5px; border:5px solid transparent; border-bottom-color:var(--sparkry-dark); }}
.tooltip:hover .tip-text, .tooltip:focus .tip-text, .tooltip:focus-within .tip-text {{ visibility:visible; opacity:1; }}
.tooltip[tabindex] {{ outline:none; }}
.tooltip[tabindex]:focus-visible {{ outline:2px solid var(--sparkry-accent); outline-offset:2px; border-radius:4px; }}

.fix-section {{ background:#242424; border-radius:12px; padding:1.5rem; margin-bottom:1.5rem; box-shadow:0 1px 3px rgba(0,0,0,0.3); border:1px solid rgba(255,255,255,0.06); }}
.fix-section h2 {{ font-size:1.1rem; margin-bottom:1rem; display:flex; align-items:center; gap:0.5rem; color:#ffffff; }}
.fix-section h2 svg {{ width:20px; height:20px; color:var(--sparkry-accent); }}
.fix-steps {{ list-style:none; counter-reset:fix-step; }}
.fix-steps li {{ counter-increment:fix-step; padding:0.75rem 0; border-bottom:1px solid rgba(255,255,255,0.06); display:flex; align-items:flex-start; gap:0.75rem; }}
.fix-steps li:last-child {{ border-bottom:none; }}
.fix-steps li::before {{ content:counter(fix-step); background:var(--sparkry-accent); color:white; width:24px; height:24px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:0.75rem; font-weight:700; flex-shrink:0; margin-top:2px; }}
.code-block {{ background:#111111; color:#c5c1b9; padding:0.75rem 1rem; border-radius:6px; font-family:'SF Mono','Fira Code',monospace; font-size:0.85rem; margin:0.5rem 0; display:flex; align-items:center; justify-content:space-between; gap:0.5rem; overflow-x:auto; border:1px solid rgba(255,255,255,0.08); }}
.code-block code {{ white-space:nowrap; }}
.copy-btn {{ background:rgba(255,255,255,0.08); border:1px solid rgba(255,255,255,0.15); color:#7a7670; padding:0.3rem 0.6rem; border-radius:4px; cursor:pointer; font-size:0.75rem; display:flex; align-items:center; gap:0.3rem; flex-shrink:0; transition:all 0.15s; }}
.copy-btn:hover {{ background:rgba(255,255,255,0.2); color:white; }}
.copy-btn:focus-visible {{ outline:2px solid var(--sparkry-accent); outline-offset:2px; background:rgba(255,255,255,0.2); color:white; }}
.copy-btn svg {{ width:14px; height:14px; }}

.scan-meta {{ background:#242424; border-radius:12px; padding:1rem 1.5rem; margin-bottom:1.5rem; box-shadow:0 1px 3px rgba(0,0,0,0.3); font-size:0.85rem; color:#7a7670; display:flex; flex-wrap:wrap; gap:1rem; align-items:center; border:1px solid rgba(255,255,255,0.06); }}
.scan-meta svg {{ width:16px; height:16px; }}
.scan-meta-item {{ display:flex; align-items:center; gap:0.35rem; }}

.toolbar {{ background:#242424; border-radius:12px; padding:1rem 1.5rem; margin-bottom:1rem; box-shadow:0 1px 3px rgba(0,0,0,0.3); display:flex; flex-wrap:wrap; gap:0.75rem; align-items:center; border:1px solid rgba(255,255,255,0.06); }}
.toolbar select {{ padding:0.4rem 0.6rem; border:1px solid rgba(255,255,255,0.1); border-radius:6px; font-size:0.85rem; background:#2c2c2c; color:#c5c1b9; cursor:pointer; font-family:inherit; }}
.toolbar select:focus {{ outline:none; border-color:var(--sparkry-accent); box-shadow:0 0 0 2px rgba(232,117,26,0.2); }}
.filter-group {{ display:flex; align-items:center; gap:0.35rem; }}
.spacer {{ flex:1; }}
.btn {{ padding:0.45rem 1rem; border:none; border-radius:6px; font-size:0.85rem; font-weight:600; cursor:pointer; transition:all 0.15s; display:inline-flex; align-items:center; gap:0.35rem; font-family:inherit; }}
.btn svg {{ width:16px; height:16px; }}
.btn-export {{ background:var(--sparkry-accent); color:white; }}
.btn-export:hover {{ background:#F08A3A; }}
.btn-reset {{ background:rgba(255,255,255,0.08); color:#c5c1b9; border:1px solid rgba(255,255,255,0.1); }}
.btn-reset:hover {{ background:rgba(255,255,255,0.14); }}
.btn:focus-visible {{ outline:2px solid var(--sparkry-accent); outline-offset:2px; }}
.filter-count {{ font-size:0.85rem; color:#7a7670; font-weight:500; }}

.finding {{ background:#242424; border-radius:10px; padding:1rem 1.25rem; margin:0.6rem 0; box-shadow:0 1px 2px rgba(0,0,0,0.3); transition:all 0.15s; border-left:4px solid transparent; border:1px solid rgba(255,255,255,0.06); border-left-width:4px; }}
.finding:hover {{ box-shadow:0 4px 12px rgba(0,0,0,0.4); }}
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

.confidence-badge {{ padding:0.15rem 0.4rem; border-radius:3px; font-size:0.72rem; font-weight:600; background:rgba(255,255,255,0.08); color:#7a7670; cursor:help; display:inline-flex; align-items:center; gap:0.2rem; }}
.confidence-badge svg {{ width:11px; height:11px; }}
.confidence-high {{ background:rgba(232,117,26,0.2); color:#E8751A; }}
.confidence-med {{ background:rgba(207,179,87,0.2); color:#cfb357; }}
.confidence-low {{ background:rgba(255,255,255,0.06); color:#7a7670; }}

.auto-fix-badge {{ padding:0.15rem 0.4rem; border-radius:3px; font-size:0.68rem; font-weight:700; background:var(--autofix-bg); color:var(--autofix-color); border:1px solid var(--autofix-border); display:inline-flex; align-items:center; gap:0.2rem; cursor:help; }}
.auto-fix-badge svg {{ width:11px; height:11px; }}

.context-badge {{ padding:0.15rem 0.4rem; border-radius:3px; font-size:0.68rem; font-weight:600; text-transform:uppercase; letter-spacing:0.03em; cursor:help; display:inline-flex; align-items:center; gap:0.2rem; }}
.context-badge svg {{ width:11px; height:11px; }}
.ctx-ai {{ background:rgba(87,207,122,0.12); color:#57cf7a; border:1px solid rgba(87,207,122,0.3); }}
.ctx-user {{ background:rgba(207,179,87,0.12); color:#cfb357; border:1px solid rgba(207,179,87,0.3); }}
.ctx-test {{ background:rgba(232,117,26,0.12); color:#E8751A; border:1px solid rgba(232,117,26,0.3); }}

.pattern-name {{ font-weight:600; font-size:0.9rem; }}

.finding-details {{ font-size:0.88rem; }}
.finding-details p {{ margin:0.35rem 0; display:flex; align-items:center; gap:0.35rem; }}
.finding-details code {{ background:rgba(255,255,255,0.06); color:#c5c1b9; padding:0.15rem 0.4rem; border-radius:3px; font-size:0.82rem; word-break:break-all; }}
.file-path {{ color:#E8751A; font-family:'SF Mono','Fira Code',monospace; font-size:0.82rem; word-break:break-all; }}
.finding-action {{ margin-top:0.75rem; padding-top:0.75rem; border-top:1px solid rgba(255,255,255,0.06); }}
.finding-action p {{ font-size:0.85rem; color:#7a7670; display:flex; align-items:flex-start; gap:0.4rem; margin:0.25rem 0; }}
.finding-action p svg {{ width:16px; height:16px; flex-shrink:0; margin-top:2px; }}
.finding-action .action-fix {{ color:var(--act-now-color); }}
.finding-action .action-review {{ color:var(--review-color); }}
.finding-action .action-info {{ color:#7a7670; }}

.no-results {{ text-align:center; padding:3rem; color:#7a7670; display:none; }}
.no-results svg {{ width:48px; height:48px; margin-bottom:0.5rem; }}

.posture-card {{ background:#242424; border-radius:10px; padding:1rem 1.25rem; margin:0.6rem 0; box-shadow:0 1px 2px rgba(0,0,0,0.3); border-left:4px solid transparent; display:flex; gap:1rem; align-items:flex-start; border:1px solid rgba(255,255,255,0.06); border-left-width:4px; }}
.posture-card.secure {{ border-left-color:var(--secure-color); }}
.posture-card.warning {{ border-left-color:var(--warning-color); }}
.posture-card.insecure {{ border-left-color:var(--insecure-color); }}
.posture-card.not_found {{ border-left-color:#7a7670; }}
.posture-icon {{ width:36px; height:36px; border-radius:8px; display:flex; align-items:center; justify-content:center; flex-shrink:0; }}
.posture-icon svg {{ width:20px; height:20px; }}
.posture-icon.secure {{ background:rgba(87,207,122,0.12); color:var(--secure-color); }}
.posture-icon.warning {{ background:var(--review-bg); color:var(--warning-color); }}
.posture-icon.insecure {{ background:var(--act-now-bg); color:var(--insecure-color); }}
.posture-icon.not_found {{ background:rgba(255,255,255,0.06); color:#7a7670; }}
.posture-content strong {{ font-size:0.95rem; color:#c5c1b9; }}
.posture-content p {{ font-size:0.85rem; color:#7a7670; margin-top:0.25rem; }}
.posture-rec {{ font-size:0.82rem; color:#7a7670; font-style:italic; margin-top:0.35rem; display:flex; align-items:flex-start; gap:0.35rem; }}
.posture-rec svg {{ width:14px; height:14px; flex-shrink:0; margin-top:2px; color:var(--sparkry-accent); }}
.posture-summary {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:1rem; margin-bottom:1.5rem; }}
.posture-stat {{ background:#242424; border-radius:10px; padding:1rem; box-shadow:0 1px 3px rgba(0,0,0,0.3); text-align:center; border:1px solid rgba(255,255,255,0.06); }}
.posture-stat .p-num {{ font-size:1.8rem; font-weight:700; font-family:inherit; color:#ffffff; }}
.posture-stat .p-label {{ font-size:0.8rem; color:#7a7670; }}

.footer {{ text-align:center; padding:2rem; color:#7a7670; font-size:0.82rem; border-top:1px solid rgba(255,255,255,0.06); margin-top:2rem; }}
.footer a {{ color:var(--sparkry-accent); text-decoration:none; }}
.footer a:hover {{ text-decoration:underline; }}
.footer-links {{ display:flex; justify-content:center; gap:1.5rem; margin:0.5rem 0; flex-wrap:wrap; }}
.footer-links a {{ display:inline-flex; align-items:center; gap:0.3rem; }}
.footer-links a svg {{ width:14px; height:14px; }}
.license {{ margin-top:0.75rem; padding-top:0.75rem; border-top:1px solid rgba(255,255,255,0.06); font-size:0.78rem; }}

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
.skip-link:focus {{ position:fixed; top:0; left:0; width:auto; height:auto; padding:0.75rem 1.5rem; background:#2c2c2c; color:white; font-size:1rem; font-weight:600; z-index:1000; outline:2px solid var(--sparkry-accent); }}

.what-to-do {{ margin-top:12px; }}
.wtd-toggle {{ background:none; border:none; color:#E8751A; cursor:pointer; font-size:14px; font-weight:600; padding:4px 0; font-family:inherit; }}
.wtd-toggle:hover {{ text-decoration:underline; }}
.wtd-content {{ display:none; padding:8px 0 0 16px; }}
.what-to-do.open .wtd-content {{ display:block; }}
.wtd-content p {{ color:#7a7670; line-height:1.6; font-size:0.85rem; }}
</style>
</head>
<body>
<a href="#main-content" class="skip-link">Skip to main content</a>

<div class="header">
    <div class="header-left">
        <div class="header-logo">
            <img src="data:image/png;base64,{_LOGO_B64}" alt="SecureClaw" style="height: 28px;">
            <h1>SecureClaw Scan Report</h1>
        </div>
        <div class="header-tagline">by <a href="https://sparkry.ai" target="_blank" rel="noopener">Sparkry AI</a></div>
    </div>
    <div class="header-right">
        <span>v{_e(result.tool_version)}</span>
        <span>|</span>
        <span>Last scanned: {now}</span>
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
            {_icon("search", 16, 16, "color:#7a7670")}
            <input type="text" id="filter-search" placeholder="Search files, patterns, matches..." oninput="debouncedFilter()" style="flex:1;padding:0.4rem 0.6rem;border:1px solid rgba(255,255,255,0.1);border-radius:6px;font-size:0.85rem;font-family:inherit;outline:none;background:#2c2c2c;color:#c5c1b9;" onfocus="this.style.borderColor='var(--sparkry-accent)';this.style.boxShadow='0 0 0 2px rgba(232,117,26,0.2)';" onblur="this.style.borderColor='rgba(255,255,255,0.1)';this.style.boxShadow='none';" aria-label="Search findings">
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
    <p style="margin-top:0.25rem;">Run periodically to stay safe. Get the latest version at <a href="https://secureclaw.sparkry.ai" style="color:var(--sparkry-accent);">secureclaw.sparkry.ai</a></p>
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
