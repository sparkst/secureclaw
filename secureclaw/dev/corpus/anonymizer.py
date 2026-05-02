"""Corpus anonymizer (spec §6.4, §7).

Pipeline:
1. ``_substitute(text)`` — deterministic structural substitution.
2. ``_residue_check(text)`` — entropy gate + shape check for survivors.
3. ``anonymize_tree(src, dst, ...)`` — orchestrates substitute, scanners
   (gitleaks/trufflehog/SecureClaw), and atomic-rename per file.

S5a (this layer): substitute + residue. Scanner orchestrator + tree walker
land in S5b/S5c.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from typing import Dict, Optional, Tuple

# Single source of truth for credential prefixes (spec constraint #4).
from secureclaw.core.credentials import REAL_TOKEN_PREFIXES  # noqa: F401


# --- helpers ---------------------------------------------------------------


def _hash(token: str) -> str:
    """Spec §7.2a — 16-char hex digest, blake2b, cross-process stable."""
    return hashlib.blake2b(token.encode("utf-8"), digest_size=8).hexdigest()


# --- substitution patterns -------------------------------------------------

# User-home substitutions.
_RE_MACOS_HOME = re.compile(r"/Users/([A-Za-z0-9._-]+)/")
_RE_LINUX_HOME = re.compile(r"/home/([A-Za-z0-9._-]+)/")
_RE_WIN_HOME = re.compile(r"C:\\Users\\([A-Za-z0-9._-]+)\\", re.IGNORECASE)
_RE_TILDE_DOCS = re.compile(r"~/Documents/([^/\s]+)/")

# Public IPv4 (octets 0-255). Excludes RFC1918 + loopback in code.
_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# MAC address (lower or upper case).
_RE_MAC = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")

# NANP phone (US/CA): optional +1, optional separators.
_RE_PHONE_NANP = re.compile(r"\+?1?[-. ]?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}")

# Email — captures local + domain.
_RE_EMAIL = re.compile(r"(?P<local>[A-Za-z0-9._%+-]+)@(?P<domain>[A-Za-z0-9.-]+\.[A-Za-z]{2,})")

# API key prefixes (spec §7.2 table). Order matters — more-specific first.
_KEY_PATTERNS = (
    ("anthropic", re.compile(r"sk-ant-[A-Za-z0-9_-]+")),
    ("stripe-live", re.compile(r"sk-live_[A-Za-z0-9_-]+")),
    ("stripe-test", re.compile(r"sk-test_[A-Za-z0-9_-]+")),
    ("github-pat", re.compile(r"github_pat_[A-Za-z0-9_]+")),
    ("github", re.compile(r"gh[pous]_[A-Za-z0-9]+")),
    ("slack", re.compile(r"xox[bp]-[A-Za-z0-9-]+")),
    ("aws", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
)

# Map secondary tags to spec-canonical type tags.
_KEY_TAG_NORMAL = {
    "stripe-live": "stripe",
    "stripe-test": "stripe",
    "github-pat": "github",
}

# PEM private-key block (multi-line; DOTALL).
_RE_PEM_BLOCK = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)

# Attack-context email triggers — restricted set per spec §7.4.
_ATTACK_VERBS = ("forward", "exfiltrate")

# Synthetic domain exclusions for residue + attack-context checks.
_SYNTHETIC_DOMAINS_SUFFIX = (".example", ".example.local")
_SYNTHETIC_DOMAINS_EXACT = ("scenario.local", "example.com")


def _is_synthetic_domain(domain: str) -> bool:
    domain_lower = domain.lower().rstrip(".")
    if domain_lower in _SYNTHETIC_DOMAINS_EXACT:
        return True
    for suffix in _SYNTHETIC_DOMAINS_SUFFIX:
        if domain_lower.endswith(suffix):
            return True
    return False


def _is_private_ipv4(ip: str) -> bool:
    """RFC1918 + loopback + link-local + multicast."""
    try:
        parts = [int(p) for p in ip.split(".")]
    except ValueError:
        return False
    if len(parts) != 4 or any(p > 255 or p < 0 for p in parts):
        return False
    if parts[0] == 10:
        return True
    if parts[0] == 127:
        return True
    if parts[0] == 192 and parts[1] == 168:
        return True
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return True
    if parts[0] == 169 and parts[1] == 254:
        return True
    if parts[0] == 0:
        return True
    if parts[0] >= 224:
        return True
    return False


# --- substitute ------------------------------------------------------------


def _substitute(text: str) -> Tuple[str, Dict[str, int]]:
    """Apply structural substitutions to ``text`` (spec §7.2).

    Returns the transformed text and a counter of replacements per category.
    """
    counts: Dict[str, int] = Counter()

    # PEM blocks first (line-count-preserving; multi-line) — must precede
    # API-key substitution since "ghp_..." inside a PEM block could
    # otherwise be doubly-redacted.
    def _pem_repl(m: re.Match) -> str:
        counts["pem"] = counts.get("pem", 0) + 1
        block = m.group(0)
        n_newlines = block.count("\n")
        if n_newlines < 2:
            # Defensive — replace with the minimal 2-line form.
            return "-----BEGIN FAKE PRIVATE KEY-----\n[REDACTED]\n-----END FAKE PRIVATE KEY-----"
        # 2 newlines accounted for in BEGIN line + REDACTED line; pad with
        # blank lines, then the END line carries no trailing newline.
        padding = "\n" * (n_newlines - 2)
        return (
            f"-----BEGIN FAKE PRIVATE KEY-----\n[REDACTED]\n{padding}-----END FAKE PRIVATE KEY-----"
        )

    text = _RE_PEM_BLOCK.sub(_pem_repl, text)

    # API-key tags.
    for tag, pat in _KEY_PATTERNS:
        normalized_tag = _KEY_TAG_NORMAL.get(tag, tag)

        def _key_repl(_m: re.Match, t: str = normalized_tag) -> str:
            counts["api_key"] = counts.get("api_key", 0) + 1
            return f"<KEY:{t}>FAKE0001"

        text = pat.sub(_key_repl, text)

    # Tilde Documents path before user-home (more specific).
    def _tilde_repl(m: re.Match) -> str:
        counts["path"] = counts.get("path", 0) + 1
        n = _hash(m.group(1))
        return f"~/Documents/scenario-{n}/"

    text = _RE_TILDE_DOCS.sub(_tilde_repl, text)

    # User-home substitutions.
    text = _RE_MACOS_HOME.sub(
        lambda m: counts.update({"path": counts.get("path", 0) + 1}) or "/Users/dev/", text
    )
    text = _RE_LINUX_HOME.sub(
        lambda m: counts.update({"path": counts.get("path", 0) + 1}) or "/home/dev/", text
    )
    text = _RE_WIN_HOME.sub(
        lambda m: counts.update({"path": counts.get("path", 0) + 1}) or r"C:\Users\dev" + "\\", text
    )

    # Email substitution. Decide attack-context per line.
    def _email_repl_line(line: str) -> str:
        def _email_repl(m: re.Match) -> str:
            local = m.group("local")
            domain = m.group("domain")
            counts["email"] = counts.get("email", 0) + 1
            n = _hash(f"{local}@{domain}")
            # Attack-context if a trigger verb appears on the same line AND
            # the domain isn't a synthetic substitution target.
            line_lower = line.lower()
            if any(v in line_lower for v in _ATTACK_VERBS) and not _is_synthetic_domain(domain):
                return f"exfil-{n}@attacker-domain.example"
            return f"team-{n}@scenario.local"

        return _RE_EMAIL.sub(_email_repl, line)

    # Apply per-line so attack-context detection is line-local.
    # Preserve existing line endings.
    transformed_lines = []
    parts = re.split(r"(\r\n|\n|\r)", text)
    for chunk in parts:
        if chunk in ("\r\n", "\n", "\r", ""):
            transformed_lines.append(chunk)
        else:
            transformed_lines.append(_email_repl_line(chunk))
    text = "".join(transformed_lines)

    # Phone (NANP).
    def _phone_repl(m: re.Match) -> str:
        token = m.group(0)
        # Skip 555-0xxx reserved range (already synthetic).
        if "555-0" in token:
            return token
        counts["phone"] = counts.get("phone", 0) + 1
        n = int(_hash(token), 16) % 1000
        return f"+1-555-0{n:03d}"

    text = _RE_PHONE_NANP.sub(_phone_repl, text)

    # IPv4 — only public.
    def _ipv4_repl(m: re.Match) -> str:
        ip = m.group(0)
        if _is_private_ipv4(ip):
            return ip
        counts["ip"] = counts.get("ip", 0) + 1
        n = (int(_hash(ip), 16) % 254) + 1
        return f"192.0.2.{n}"

    text = _RE_IPV4.sub(_ipv4_repl, text)

    # MAC — last group exactly 2 hex chars.
    def _mac_repl(m: re.Match) -> str:
        counts["mac"] = counts.get("mac", 0) + 1
        n = _hash(m.group(0))[:2]
        return f"00:00:00:00:00:{n}"

    text = _RE_MAC.sub(_mac_repl, text)

    return text, dict(counts)


# --- residue check ---------------------------------------------------------


def _shannon_entropy(token: str) -> float:
    """Bits per char."""
    if not token:
        return 0.0
    counter = Counter(token)
    length = len(token)
    return -sum((c / length) * math.log2(c / length) for c in counter.values())


# Shape patterns for residue check.
_RE_RESIDUE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_RE_RESIDUE_HOST_INTERNAL = re.compile(r"\b[A-Za-z0-9.-]+\.(?:internal|local)\b")
_RE_RESIDUE_PHONE = re.compile(r"\+?1?[-. ]?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}")
_RE_RESIDUE_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_RE_RESIDUE_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7,26}\b")


def _residue_check(text: str) -> Optional[str]:
    """Return a refusal reason if ``text`` still looks credentialed.

    Spec §7.3d — entropy gate + shape check. Returns one of:
    'entropy_gate', 'shape_check', or None.
    """
    # Shape check first (cheap regex sweep) — emails, SSN, IBAN.
    for email_match in _RE_RESIDUE_EMAIL.finditer(text):
        domain = email_match.group(1)
        if not _is_synthetic_domain(domain):
            return "shape_check"
    for phone_match in _RE_RESIDUE_PHONE.finditer(text):
        token = phone_match.group(0)
        if "555-0" in token:
            continue  # synthetic NANP reserved
        return "shape_check"
    if _RE_RESIDUE_SSN.search(text):
        return "shape_check"
    if _RE_RESIDUE_IBAN.search(text):
        return "shape_check"

    # Entropy gate: any contiguous non-whitespace token of length >=16.
    for token in re.findall(r"\S{16,}", text):
        # Filter known synthetic placeholders.
        if "FAKE0001" in token or "<KEY:" in token:
            continue
        # Filter synthetic emails / hosts that survived substitution legitimately.
        em = _RE_RESIDUE_EMAIL.search(token)
        if em and _is_synthetic_domain(em.group(1)):
            continue
        if _is_synthetic_domain(token):
            continue
        # If token contains a synthetic-domain suffix anywhere, also skip.
        token_lower = token.lower()
        if any(suf in token_lower for suf in (".example", ".example.local", "scenario.local")):
            continue
        entropy = _shannon_entropy(token)
        if entropy >= 4.0:
            return "entropy_gate"

    return None
