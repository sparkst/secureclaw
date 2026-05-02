"""Scaffold a new detection rule plus its corpus fixtures (spec §6.1, §9.3).

The public function :func:`scaffold_rule`:

1. Validates inputs (id format, license blocklist, attribution requirements
   for non-synthetic licenses).
2. Validates the assembled rule via :func:`secureclaw.dev.rule.schema.validate_rule`
   (with ``strict_attribution=True`` because new rules are not grandfathered).
3. Atomically appends the new rule to ``default_rules.json``.
4. Calls :func:`secureclaw.dev.corpus.add_fixture` to scaffold the positive
   fixture (since the adder accepts ``pattern_id`` for positives).
5. Calls the private :func:`_scaffold_negative` helper to write the negative
   fixture's content + paired ``expected.json`` directly, because the corpus
   adder rejects ``negative + pattern_id`` and has no ``forbidden_findings``
   parameter (the P1 fix per the revised spec).
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from secureclaw.dev.corpus.adder import add_fixture
from secureclaw.dev.corpus.schema import validate_against_schema
from secureclaw.dev.rule.schema import validate_rule

_PATTERN_ID_RE = re.compile(r"^PI-[A-Z0-9]+$")


def _slug_for(rule_id: str) -> str:
    """Filename slug — ``PI-N06`` -> ``pi-n06``."""
    return rule_id.lower()


def _is_first_party(license_str: str) -> bool:
    lower = license_str.lower()
    return lower.startswith("synthetic") or "(own work)" in lower


def _atomic_write_json(path: Path, data: Dict[str, Any]) -> None:
    """Write JSON atomically: tempfile + os.replace."""
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(parent), prefix=path.name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=False, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp_name, path)  # noqa: PTH105 — atomic rename per spec §13
    except BaseException:
        # Clean up the tempfile if anything went wrong before replace.
        try:
            os.unlink(tmp_name)  # noqa: PTH108 — tmp_name is a str from mkstemp
        except OSError:
            pass
        raise


def _build_rule_object(
    *,
    rule_id: str,
    name: str,
    category: str,
    severity: str,
    regex: str,
    description: str,
    remediation: str,
    source: str,
    license: str,
    upstream_url: Optional[str],
    upstream_commit: Optional[str],
    derived_from: Optional[str],
    examples: Optional[List[str]],
    applies_to: Optional[List[str]],
    region_kinds: Optional[List[str]],
) -> Dict[str, Any]:
    """Assemble the rule dict in the canonical default_rules.json shape."""
    sources_entry: Dict[str, Any] = {"source": source, "license": license}
    if upstream_url is not None:
        sources_entry["upstream_url"] = upstream_url
    if upstream_commit is not None:
        sources_entry["upstream_commit"] = upstream_commit
    if derived_from is not None:
        sources_entry["derived_from"] = derived_from

    return {
        "id": rule_id,
        "name": name,
        "regex": regex,
        "severity": severity,
        "category": category,
        "description": description,
        "remediation": remediation,
        "examples": list(examples) if examples else [],
        "introduced_in_version": "1.3.1",
        "applies_to": list(applies_to) if applies_to else ["any"],
        "region_kinds": list(region_kinds) if region_kinds else ["any"],
        "applies_in_string_literal": False,
        "applies_in_ai_config": False,
        "requires_same_sentence_with": [],
        "boost_on_high_entropy": False,
        "boost_on_invisible_chars": False,
        "large_file_safe": False,
        "sources": [sources_entry],
        "license_chain_audited": False,
        "severity_promotion_evidence": None,
        "owasp": None,
        "atlas": None,
    }


def _scaffold_positive(
    *,
    rule_id: str,
    corpus_root: Path,
    source_attestation: str,
    license: str,
) -> Path:
    """Write a positive fixture under ``corpus_root/positive/`` via add_fixture."""
    slug = _slug_for(rule_id)
    # Create a placeholder content file in a temporary location; add_fixture
    # copies it into corpus_root.
    content_dir = corpus_root / "_scaffold_tmp"
    content_dir.mkdir(parents=True, exist_ok=True)
    content_path = content_dir / f"{slug}_canonical.md"
    placeholder = (
        f"# Scaffolded positive fixture for {rule_id}\n"
        f"\n"
        f"Replace this body with realistic content that triggers the rule.\n"
    )
    content_path.write_text(placeholder, encoding="utf-8")
    try:
        fixture = add_fixture(
            content_path,
            klass="positive",
            source_attestation=source_attestation,
            license=license,
            pattern_id=rule_id,
            mode="superset",
            confidence_low=25,
            confidence_high=100,
            root=corpus_root,
        )
    finally:
        # Clean up the staging file regardless of outcome.
        try:
            content_path.unlink()
            content_dir.rmdir()
        except OSError:
            pass
    return fixture.path


def _scaffold_negative(
    content_path: Path,
    *,
    forbidden_findings: Tuple[str, ...],
    source_attestation: str,
    license: str,
    root: Path,
) -> Path:
    """Write a negative fixture (content file + expected.json) directly.

    We don't go through ``add_fixture`` because:
    - PR-C's ``add_fixture`` rejects ``negative`` paired with ``pattern_id``.
    - It also has no ``forbidden_findings`` parameter, which is required for
      negative fixtures asserting a specific rule must NOT fire.

    The emitted ``expected.json`` is schema-validated before write.
    """
    content_path = Path(content_path)
    if not content_path.exists():
        raise FileNotFoundError(f"content file not found: {content_path}")

    dst_dir = root / "negative"
    dst_dir.mkdir(parents=True, exist_ok=True)
    dst_content = dst_dir / content_path.name
    dst_meta = dst_dir / f"{content_path.name}.expected.json"

    if dst_content.exists() or dst_meta.exists():
        raise FileExistsError(f"refusing to overwrite {dst_content} or {dst_meta}")

    meta: Dict[str, Any] = {
        "schema_version": 2,
        "file": content_path.name,
        "mode": "exact",
        "source": source_attestation,
        "license": license,
        "added_in_pr": "#TBD-D",
        "anonymization": {"applied": False},
        "expected_findings": [],
        "forbidden_findings": list(forbidden_findings),
    }
    schema_errors = validate_against_schema(meta)
    if schema_errors:
        raise ValueError("negative metadata failed schema validation: " + "; ".join(schema_errors))

    # Copy the content file then atomically write the metadata.
    dst_content.write_bytes(content_path.read_bytes())
    _atomic_write_json(dst_meta, meta)
    return dst_meta


def scaffold_rule(
    rule_id: str,
    *,
    name: str,
    category: str,
    severity: str,
    regex: str,
    description: str,
    remediation: str,
    source: str,
    license: str,
    upstream_url: Optional[str] = None,
    upstream_commit: Optional[str] = None,
    derived_from: Optional[str] = None,
    examples: Optional[List[str]] = None,
    applies_to: Optional[List[str]] = None,
    region_kinds: Optional[List[str]] = None,
    rules_file: Path = Path("secureclaw/rules/default_rules.json"),
    corpus_root: Path = Path("tests/corpus"),
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Scaffold a new detection rule and its paired fixtures.

    Returns the rule dict that was (or would be) written. Refuses on any
    validation failure BEFORE any filesystem mutation.
    """
    rules_file = Path(rules_file)
    corpus_root = Path(corpus_root)

    # 1. id format.
    if not _PATTERN_ID_RE.match(rule_id):
        raise ValueError(f"rule_id {rule_id!r} must match ^PI-[A-Z0-9]+$")

    # 2. Build the rule object and validate it (strict — new rules are
    #    never grandfathered).
    rule = _build_rule_object(
        rule_id=rule_id,
        name=name,
        category=category,
        severity=severity,
        regex=regex,
        description=description,
        remediation=remediation,
        source=source,
        license=license,
        upstream_url=upstream_url,
        upstream_commit=upstream_commit,
        derived_from=derived_from,
        examples=examples,
        applies_to=applies_to,
        region_kinds=region_kinds,
    )
    schema_errors = validate_rule(rule, strict_attribution=True)
    if schema_errors:
        raise ValueError("rule failed validation: " + "; ".join(schema_errors))

    # 3. Read existing rules file (must exist).
    if not rules_file.exists():
        raise FileNotFoundError(f"rules file not found: {rules_file}")
    data = json.loads(rules_file.read_text(encoding="utf-8"))
    patterns = data.get("patterns", [])
    if any(p.get("id") == rule_id for p in patterns):
        raise ValueError(f"rule {rule_id!r} already exists in {rules_file}; choose a different id")

    if dry_run:
        print(
            f"[dry-run] would append {rule_id} to {rules_file}",
            file=sys.stderr,
        )
        print(
            f"[dry-run] would scaffold positive fixture under {corpus_root}/positive/",
            file=sys.stderr,
        )
        print(
            f"[dry-run] would scaffold negative fixture under {corpus_root}/negative/",
            file=sys.stderr,
        )
        return rule

    # 4. Atomic write of the updated rules file.
    new_data = dict(data)
    new_data["patterns"] = list(patterns) + [rule]
    _atomic_write_json(rules_file, new_data)

    # 5. Scaffold positive (via add_fixture).
    _scaffold_positive(
        rule_id=rule_id,
        corpus_root=corpus_root,
        source_attestation=source,
        license=license,
    )

    # 6. Scaffold negative (direct write — the P1 fix).
    slug = _slug_for(rule_id)
    neg_staging_dir = corpus_root / "_scaffold_tmp_neg"
    neg_staging_dir.mkdir(parents=True, exist_ok=True)
    neg_content = neg_staging_dir / f"{slug}_benign.md"
    neg_content.write_text(
        f"# Scaffolded negative fixture for {rule_id}\n\n"
        f"This benign content must NOT trigger {rule_id}.\n",
        encoding="utf-8",
    )
    try:
        _scaffold_negative(
            neg_content,
            forbidden_findings=(rule_id,),
            source_attestation=source,
            license=license,
            root=corpus_root,
        )
    finally:
        try:
            neg_content.unlink()
            neg_staging_dir.rmdir()
        except OSError:
            pass

    # 7. Hint for next step.
    print(
        f"Edit the scaffolded fixtures in {corpus_root}/positive/{slug}_canonical.md "
        f"and {corpus_root}/negative/{slug}_benign.md to be realistic, then run "
        f"`secureclaw dev rule test {rule_id}`.",
        file=sys.stderr,
    )

    return rule
