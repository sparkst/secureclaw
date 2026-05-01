# Federated Test Runners

SecureClaw's CI runs across **4 self-hosted runners on Tailscale** plus a
GitHub-hosted Linux runner, validated per the **quorum rule** in REQ-7.1.

## Runner roster

| Machine | Tailscale IP | OS | Python | Role | Required for merge |
|---|---|---|---|---|---|
| jarvis | 100.90.26.107 | macOS 26.3 arm64 | 3.9.6 | required | yes |
| macbook | 100.100.176.14 | macOS 26.3.1 arm64 | system | required | yes |
| ubuntu-4gb-nbg1-2 | 100.103.3.121 | Linux 6.8 x86_64 | 3.12.3 | required | yes |
| macair | 100.103.6.65 | macOS 15.7.4 | system | best-effort | **no** |
| GH-hosted ubuntu-24.04 | (managed) | Linux | matrix | required | yes |

## Quorum rule

A PR is mergeable only when:

- **≥ 3 of 4** self-hosted runners are GREEN, AND
- `[mac-arm64-jarvis OR mac-tahoe-book]` is GREEN, AND
- `linux-ubuntu` is GREEN.

macair is informational; macair offline does **not** block merge. A
`workflow_dispatch` includes a `wake_macair` job that pings via Tailscale
before the matrix kicks off.

## Permissions block

Every workflow declares minimum scopes:

```yaml
permissions:
  contents: read
  metadata: read
  # all other scopes default to none
```

`pull_request_target` is restricted to a separate dedicated workflow file
(`.github/workflows/safe-bot.yml`); `actionlint` rejects its use elsewhere.

## Runner registration

Each self-hosted runner is registered as a dedicated user account
(`secureclaw-runner`) with no sudo. Setup scripts:

- `tools/runner-bootstrap/mac.sh` — registers a macOS runner with appropriate labels.
- `tools/runner-bootstrap/linux.sh` — registers a Linux runner.

Labels are `[self-hosted, mac-arm64-jarvis | mac-arm64-macbook | mac-sequoia-air | linux-ubuntu]` so the matrix workflow can target each box.

## Tailscale ACL template

```json
{
  "acls": [
    { "action": "accept", "src": ["sparkst@gmail.com"], "dst": ["tag:secureclaw-runner:22"] }
  ],
  "tagOwners": { "tag:secureclaw-runner": ["sparkst@gmail.com"] }
}
```

Runner machines are tagged `tag:secureclaw-runner`. Removing or rotating
this tag has no effect on user devices.

## Trust model

- Self-hosted runners process only `pull_request` events from same-repo branches.
- External fork PRs run only on GitHub-hosted runners.
- `pull_request_target` from forks is forbidden.
- Workspace is wiped by pre/post-job cleanup script.
- `GITHUB_TOKEN` rotated per job.
- Future hardening (v1.4): ephemeral VMs (Multipass on Mac, LXC on Ubuntu).

## Adding a new runner

1. Provision the machine with Tailscale + `secureclaw-runner` user.
2. Run the appropriate `tools/runner-bootstrap/{mac,linux}.sh`.
3. Register with GitHub Actions and apply the OS-specific label.
4. Update this table in a follow-up PR.
5. Adjust quorum rule in workflow if the runner is required (separate PR with rationale).
