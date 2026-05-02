# Contributing to the SecureClaw Test Corpus

## When to add a fixture

| Class | Definition | Bar |
|---|---|---|
| `positive/` | Real-world attack documented in CVE, vendor advisory, or peer-reviewed research. | Must include `source` URL with date. |
| `negative/` | Benign content with surface-level similarity to attacks (e.g., marketing copy mentioning "system" or "ignore"). | Must NOT trigger any current rule with confidence ≥ 25. |
| `borderline/` | Judgment-call content where reasonable reviewers may disagree. | Used to exercise confidence-tier boundaries; `mode: "subset"` allowed. |
| `regression/` | Locked test for a specific reported bug or false positive. | Must reference the issue/PR or transcript timestamp that motivated it. |
| `dos/` | Adversarial input designed to exercise B.2 caps. | Must complete within the per-file budget; CI enforces. |

## How to add (v2 two-step workflow per PR-C)

### Step 1 — anonymize (separate operation)

If the source content originates from a real machine, run the anonymizer
first into a scratch directory you do not commit:

```bash
secureclaw dev corpus anonymize <src-dir> <scratch-dst>
```

This orchestrates:
- Structural substitution (paths, emails, phones, IPs, MACs, API-key
  prefixes, PEM blocks).
- Three independent scanner passes (SecureClaw self-scan, gitleaks,
  trufflehog) — file is refused if any pass finds a credential.
- Post-substitution residue checks (entropy gate + shape check).

Required scanner versions (installed by `tools/install-anonymizer-deps.sh`):

| Scanner | Minimum version |
|---|---|
| gitleaks | `v8.18.0` |
| trufflehog | `v3.63.0` |

### Step 2 — add the (already-clean) fixture

```bash
secureclaw dev corpus add \
    --class positive \
    --source-attestation "EchoLeak CVE-2025-32711 — published payload" \
    --license "MIT (own work)" \
    --pattern-id PI-005 \
    path/to/your/fixture.md
```

For regression fixtures, use `--regression-of` to record the
issue/PR/timestamp the regression locks in:

```bash
secureclaw dev corpus add --class regression \
    --regression-of "#42" --regression-group lauren \
    --source-attestation "Lauren-FP-em-dash" \
    --license "MIT (own work)" \
    path/to/fixture.md
```

The adder writes `<basename>.expected.json` with `added_in_pr: "#TBD-C"`,
which is later replaced via `secureclaw dev corpus set-pr-number <N>`
once the PR number is known.

## Two-person review

Every corpus PR requires:

- **Submitter**: opens PR with `--source-attestation` provenance note.
- **Reviewer (user)**: explicit checkbox on PR template: "no real customer
  data, no real credentials, no real identifying paths."

PRs without both signatures are blocked by CODEOWNERS on `tests/corpus/`.

## Disputes

Disputed classifications (positive vs negative vs borderline) follow:
1. 7-day discussion window in PR comments.
2. User decides; decision recorded in PR description.
3. Decision can be revisited via a follow-up PR if new evidence emerges.

## Anonymization rules

Replace, preserving structure:

| Real | Synthetic |
|---|---|
| `~/Documents/banking/...` | `~/Documents/scenario-finance/...` |
| `sk-ant-XXXX...` | `sk-ant-FAKE0001...` (tagged `anonymization.applied: true`) |
| `acme-corp@example.com` | `team-blue@scenario.local` |
| Phone numbers | `+1-555-0XXX` (NANP-reserved) |
| Real org names | `Scenario Inc`, `Demo Corp`, etc. |

## Privacy threat model

The corpus is committed to a public GitHub repo. Treat all entries as if a
motivated reader could de-anonymize via structural fingerprinting. For
fixtures where structure is itself sensitive, use `secureclaw dev corpus
add --perturb` to randomize file sizes and path-depths within tolerance.

Real-world incidents (CVEs, vendor advisories): fixture is generally OK as
that information is already public.
