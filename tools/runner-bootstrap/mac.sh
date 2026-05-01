#!/usr/bin/env bash
# Register a macOS box as a GitHub Actions self-hosted runner for SecureClaw.
#
# Usage:
#   curl -fsSL .../mac.sh | bash -s -- <runner-label> <gh-runner-token>
# OR run interactively:
#   bash mac.sh
#
# Labels (pick one when prompted):
#   mac-arm64-jarvis
#   mac-arm64-macbook
#   mac-sequoia-air
#
# Prereqs:
#   - macOS arm64 (M-series) or Intel.
#   - User account `secureclaw-runner` (no sudo) created beforehand:
#       sudo dscl . -create /Users/secureclaw-runner UserShell /bin/bash
#       sudo dscl . -create /Users/secureclaw-runner RealName "SecureClaw Runner"
#       sudo dscl . -create /Users/secureclaw-runner UniqueID "503"
#       sudo dscl . -create /Users/secureclaw-runner PrimaryGroupID 20
#       sudo dscl . -create /Users/secureclaw-runner NFSHomeDirectory /Users/secureclaw-runner
#       sudo createhomedir -c -u secureclaw-runner
#   - Runner token from: https://github.com/sparkst/secureclaw/settings/actions/runners/new
#
# What this script does:
#   1. Downloads the latest GitHub Actions runner.
#   2. Configures with the given label.
#   3. Installs as a launchd service running as secureclaw-runner.
#   4. Starts the service.

set -euo pipefail

LABEL="${1:-}"
TOKEN="${2:-}"

if [ -z "$LABEL" ]; then
  echo "Pick a label:"
  echo "  1) mac-arm64-jarvis"
  echo "  2) mac-arm64-macbook"
  echo "  3) mac-sequoia-air"
  read -rp "Label [1-3]: " choice
  case "$choice" in
    1) LABEL="mac-arm64-jarvis" ;;
    2) LABEL="mac-arm64-macbook" ;;
    3) LABEL="mac-sequoia-air" ;;
    *) echo "Invalid"; exit 1 ;;
  esac
fi

if [ -z "$TOKEN" ]; then
  echo
  echo "Visit: https://github.com/sparkst/secureclaw/settings/actions/runners/new"
  echo "Copy the token from the 'Configure' step:"
  read -rsp "Runner token: " TOKEN
  echo
fi

RUNNER_USER="${RUNNER_USER:-secureclaw-runner}"
RUNNER_HOME="/Users/$RUNNER_USER"
RUNNER_DIR="$RUNNER_HOME/actions-runner"

if ! id "$RUNNER_USER" >/dev/null 2>&1; then
  echo "Error: user '$RUNNER_USER' does not exist. Create it first (see header)."
  exit 1
fi

ARCH="$(uname -m)"
case "$ARCH" in
  arm64) RUNNER_ARCH="osx-arm64" ;;
  x86_64) RUNNER_ARCH="osx-x64" ;;
  *) echo "Unsupported arch: $ARCH"; exit 1 ;;
esac

# Latest stable runner — pin a version when bumping
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

# Install as launchd service
sudo ./svc.sh install "$RUNNER_USER"
sudo ./svc.sh start

echo
echo "Runner '$LABEL' registered and started."
echo "Verify at: https://github.com/sparkst/secureclaw/settings/actions/runners"
echo
echo "Next: enable RUNNERS_REGISTERED=true in repo variables once all 4 runners are up."
