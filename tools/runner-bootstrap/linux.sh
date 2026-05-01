#!/usr/bin/env bash
# Register a Linux box as a GitHub Actions self-hosted runner for SecureClaw.
#
# Usage:
#   curl -fsSL .../linux.sh | bash -s -- <runner-label> <gh-runner-token>
# OR run interactively:
#   bash linux.sh
#
# Labels (pick one when prompted):
#   linux-ubuntu
#
# Prereqs:
#   - Linux x86_64 or arm64 with systemd.
#   - User account `secureclaw-runner` (no sudo) created beforehand:
#       sudo useradd -m -s /bin/bash secureclaw-runner
#   - Runner token from: https://github.com/sparkst/secureclaw/settings/actions/runners/new

set -euo pipefail

LABEL="${1:-linux-ubuntu}"
TOKEN="${2:-}"

if [ -z "$TOKEN" ]; then
  echo "Visit: https://github.com/sparkst/secureclaw/settings/actions/runners/new"
  read -rsp "Runner token: " TOKEN
  echo
fi

RUNNER_USER="${RUNNER_USER:-secureclaw-runner}"
RUNNER_HOME="/home/$RUNNER_USER"
RUNNER_DIR="$RUNNER_HOME/actions-runner"

if ! id "$RUNNER_USER" >/dev/null 2>&1; then
  echo "Error: user '$RUNNER_USER' does not exist. Create with: sudo useradd -m -s /bin/bash $RUNNER_USER"
  exit 1
fi

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) RUNNER_ARCH="linux-x64" ;;
  aarch64|arm64) RUNNER_ARCH="linux-arm64" ;;
  *) echo "Unsupported arch: $ARCH"; exit 1 ;;
esac

RUNNER_VERSION="2.319.1"
RUNNER_TARBALL="actions-runner-${RUNNER_ARCH}-${RUNNER_VERSION}.tar.gz"
RUNNER_URL="https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/${RUNNER_TARBALL}"

sudo -u "$RUNNER_USER" mkdir -p "$RUNNER_DIR"
cd "$RUNNER_DIR"
sudo -u "$RUNNER_USER" curl -fL -o "$RUNNER_TARBALL" "$RUNNER_URL"
sudo -u "$RUNNER_USER" tar xzf "$RUNNER_TARBALL"
sudo -u "$RUNNER_USER" rm "$RUNNER_TARBALL"

sudo -u "$RUNNER_USER" ./config.sh \
  --url "https://github.com/sparkst/secureclaw" \
  --token "$TOKEN" \
  --labels "self-hosted,$LABEL" \
  --name "$(hostname -s)-$LABEL" \
  --work _work \
  --unattended \
  --replace

# Install as systemd service
sudo ./svc.sh install "$RUNNER_USER"
sudo ./svc.sh start

echo
echo "Runner '$LABEL' registered and started."
echo "Verify at: https://github.com/sparkst/secureclaw/settings/actions/runners"
echo
echo "Next: enable RUNNERS_REGISTERED=true in repo variables once all 4 runners are up."
