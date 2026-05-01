"""Single source of truth for credential prefix detection.

Both ``confidence.py`` (scoring) and the upcoming ``sc-corpus anonymize``
machinery (PR-C) import ``REAL_TOKEN_PREFIXES`` and ``PLACEHOLDER_PATTERNS``
from here. Drift between the two would cause anonymizer to leak prefixes
the scorer recognizes (or vice versa) — a privacy bug. CI test in
``tests/test_credentials_singleton.py`` enforces single-source-of-truth.
"""

from __future__ import annotations

import re

# Real credential prefixes — these are almost certainly live secrets.
# When extending, also extend the anonymizer's recognized prefix set so the
# bidirectional coverage test (PR-C) stays green.
REAL_TOKEN_PREFIXES = (
    "sk-ant-",
    "sk-proj-",
    "sk-",
    "ghp_",
    "gho_",
    "ghs_",
    "github_pat_",
    "glpat-",
    "xoxb-",
    "xoxp-",
    "AKIA",
    "eyJ",
    "AIza",
    "r8_",
    "hf_",
    "Bearer ",
)

# Placeholder values that are NOT real credentials. Anonymizers must NOT treat
# these as live secrets; the scorer demotes findings that match.
PLACEHOLDER_PATTERNS = re.compile(
    r"(not[_-]configured|your[_-]token|your[_-]key|xxx+|test[_-]secret|"
    r"fake[_-]|example[_-]|placeholder|changeme|TODO|REPLACE_ME|"
    r"insert[_-]|put[_-]your|sk-your|ghp_your|<your|dummy)",
    re.IGNORECASE,
)
