# TODO

## Move SecureClaw Website (`site/`)

The SecureClaw landing page currently lives in the exec-team monorepo at:
`projects/019-prompt-injection-attacks/secureclaw-site/`

There is also a copy at `projects/019-prompt-injection-attacks/secureclaw/site/` (untracked).

**Decision needed:** Move the website to either:
1. **Its own GitHub repo** (`sparkst/secureclaw-site`) — keeps concerns separated
2. **Into sparkry-website** — consolidates all Sparkry web properties

**Context:**
- The site is a Cloudflare Workers project (`wrangler.toml`, `src/`, `public/`)
- It serves at `secureclaw.sparkry.ai`
- It includes the standalone `secureclaw.py` download and SHA256SUMS
- After moving, update the standalone build script to publish artifacts to the new location
