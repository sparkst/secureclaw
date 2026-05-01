# Runner bootstrap scripts

Per-OS scripts to register a machine as a self-hosted GitHub Actions runner
for SecureClaw. See `docs/runners.md` for the runner roster and quorum rule.

## Usage

On the target machine (Tailscale-connected):

```bash
# macOS:
bash tools/runner-bootstrap/mac.sh

# Linux:
bash tools/runner-bootstrap/linux.sh
```

You'll be prompted for:

1. **Label** (Mac only): one of `mac-arm64-jarvis`, `mac-arm64-macbook`,
   `mac-sequoia-air`. Linux uses `linux-ubuntu`.
2. **Runner token**: from
   [Settings → Actions → Runners → New self-hosted runner](https://github.com/sparkst/secureclaw/settings/actions/runners/new).

The script:

1. Downloads the pinned GitHub Actions runner version (currently `v2.319.1`).
2. Configures with the chosen label and the dedicated `secureclaw-runner` user account.
3. Installs as a system service (`launchd` on Mac, `systemd` on Linux).
4. Starts the service.

## After all four runners are up

Enable cross-platform CI by setting the repo variable:

```bash
gh variable set RUNNERS_REGISTERED --body true
```

This flips the `if: ${{ vars.RUNNERS_REGISTERED == 'true' }}` guard in
`.github/workflows/cross-platform.yml`, activating the matrix and the
quorum-gate job (which becomes a required status check via branch protection).

## Prerequisites

Each runner machine must have:

- Tailscale connectivity to GitHub Actions (outbound only; runners poll out).
- A dedicated `secureclaw-runner` user account with no sudo.
- Python 3.9–3.13 available (each test job installs deps in a venv).
- Disk space for the runner workspace (~5 GB recommended).

## Trust model

Per `docs/runners.md`:

- Self-hosted runners process only `pull_request` from same-repo branches.
- Fork PRs run only on GitHub-hosted runners.
- `pull_request_target` is forbidden outside the dedicated `safe-bot.yml`
  workflow.
- Workspace cleanup hooks wipe `_work/` between jobs.
- `GITHUB_TOKEN` is rotated per job by GitHub Actions.

## Removing a runner

On the target machine:

```bash
cd ~secureclaw-runner/actions-runner
sudo ./svc.sh stop
sudo ./svc.sh uninstall
sudo -u secureclaw-runner ./config.sh remove
```

Then remove the entry at
[Settings → Actions → Runners](https://github.com/sparkst/secureclaw/settings/actions/runners).
