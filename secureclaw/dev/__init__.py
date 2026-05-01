"""Internal developer CLI for SecureClaw.

These commands are not part of the customer-facing CLI and are used during
development to manage the test corpus, author detection rules, run benchmarks,
dispatch federated tests, and sync upstream rule sources.

Subcommands (skeleton stubs in v1.3.0 Foundation; full implementations land
in PR-C, PR-D, PR-E, PR-F):

  secureclaw dev corpus    Manage tests/corpus/ fixtures
  secureclaw dev rule      Author and validate detection rules
  secureclaw dev bench     Run benchmark suite (PINT, HackAPrompt, local corpus)
  secureclaw dev fed       Dispatch federated test runs (post-v1.3.0)
  secureclaw dev sync      Pull upstream rule updates (post-v1.3.0)
  secureclaw dev triage    Interactive finding classifier (post-v1.3.0)
"""

from __future__ import annotations
