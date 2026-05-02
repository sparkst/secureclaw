# Blog: Understanding DAN-style Attacks

Researchers documented a class of role-confusion attacks targeting AI
assistants. The published case studies note that detection systems flag
these patterns when scanning user content. We do not reproduce the exact
trigger phrasing in this overview because it would itself fire detectors
configured for blocklist behavior.

The defensive recommendation is to filter inputs before they reach the
model and to preserve the original system prompt as a separate channel.
