#!/usr/bin/env bash
# Install gitleaks >= v8.18.0 and trufflehog >= v3.63.0 — the external
# scanners required by `secureclaw dev corpus anonymize`.
#
# Usage:
#   ./tools/install-anonymizer-deps.sh
#
# The anonymizer can run with --no-gitleaks and/or --no-trufflehog if a
# binary is unavailable, but the security guarantee weakens proportionally.
# CI machines should have both binaries installed.

set -euo pipefail

GITLEAKS_MIN_VERSION="v8.18.0"
TRUFFLEHOG_MIN_VERSION="v3.63.0"

uname_s="$(uname -s 2>/dev/null || echo unknown)"

case "${uname_s}" in
    Darwin*)
        echo "macOS detected — installing via Homebrew."
        if ! command -v brew >/dev/null 2>&1; then
            echo "ERROR: brew not found. Install Homebrew first: https://brew.sh" >&2
            exit 1
        fi
        brew install gitleaks trufflehog
        ;;
    Linux*)
        echo "Linux detected — fetching release tarballs."
        # gitleaks
        if ! command -v gitleaks >/dev/null 2>&1; then
            echo "Fetching gitleaks ${GITLEAKS_MIN_VERSION}..."
            tmpdir="$(mktemp -d)"
            wget -O "${tmpdir}/gitleaks.tgz" \
                "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_MIN_VERSION}/gitleaks_${GITLEAKS_MIN_VERSION#v}_linux_x64.tar.gz"
            tar -xzf "${tmpdir}/gitleaks.tgz" -C "${tmpdir}"
            sudo install -m 0755 "${tmpdir}/gitleaks" /usr/local/bin/gitleaks
            rm -rf "${tmpdir}"
        else
            echo "gitleaks already installed: $(gitleaks version)"
        fi
        # trufflehog — install via official script.
        if ! command -v trufflehog >/dev/null 2>&1; then
            echo "Fetching trufflehog ${TRUFFLEHOG_MIN_VERSION}..."
            curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
                | sudo sh -s -- -b /usr/local/bin "${TRUFFLEHOG_MIN_VERSION}"
        else
            echo "trufflehog already installed: $(trufflehog --version 2>&1 | head -n1)"
        fi
        ;;
    MINGW*|MSYS*|CYGWIN*|Windows_NT)
        echo "Windows detected — install via Scoop:"
        echo "    scoop install gitleaks"
        echo "    scoop install trufflehog"
        echo
        echo "Or download release binaries from:"
        echo "    https://github.com/gitleaks/gitleaks/releases (>= ${GITLEAKS_MIN_VERSION})"
        echo "    https://github.com/trufflesecurity/trufflehog/releases (>= ${TRUFFLEHOG_MIN_VERSION})"
        echo
        echo "Place each on PATH and re-run \`secureclaw dev corpus anonymize\`."
        ;;
    *)
        echo "Unsupported platform: ${uname_s}" >&2
        exit 1
        ;;
esac

echo
echo "Installed versions:"
gitleaks version 2>&1 || echo "(gitleaks not on PATH yet — restart your shell)"
trufflehog --version 2>&1 | head -n1 || echo "(trufflehog not on PATH yet — restart your shell)"
echo
echo "Done. Minimum versions required:"
echo "  gitleaks   >= ${GITLEAKS_MIN_VERSION}"
echo "  trufflehog >= ${TRUFFLEHOG_MIN_VERSION}"
