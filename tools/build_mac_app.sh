#!/bin/bash
# Build SecureClaw.app bundle and DMG
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DIST_DIR="$PROJECT_DIR/dist"
APP_NAME="SecureClaw"
APP_BUNDLE="$DIST_DIR/$APP_NAME.app"
DMG_NAME="$APP_NAME.dmg"
DMG_PATH="$DIST_DIR/$DMG_NAME"
BINARY="$DIST_DIR/$APP_NAME"
ICON="$PROJECT_DIR/assets/SecureClaw.icns"
PLIST="$SCRIPT_DIR/Info.plist"

echo "=== Building $APP_NAME.app ==="

# Step 1: Rebuild standalone from modular source
echo "Rebuilding standalone secureclaw.py..."
python3 "$SCRIPT_DIR/build_standalone.py"

# Step 2: Rebuild PyInstaller binary
echo "Building PyInstaller binary..."
"$PROJECT_DIR/.build-venv/bin/pyinstaller" "$PROJECT_DIR/SecureClaw.spec" --noconfirm

# Step 3: Ad-hoc code sign (required for app to launch)
# Without this, macOS refuses to run the app ("can't be opened").
# On Sequoia, downloaded ad-hoc apps trigger Gatekeeper — users bypass via
# System Settings > Privacy & Security > "Open Anyway".
# Full fix requires Apple Developer ID + notarization ($99/yr).
echo "Ad-hoc code signing..."
codesign --force --deep -s - "$APP_BUNDLE"

echo "  Created: $APP_BUNDLE"
echo "  Binary:  $(file "$APP_BUNDLE/Contents/MacOS/$APP_NAME" | cut -d: -f2)"

# Build DMG
echo ""
echo "=== Building $DMG_NAME ==="

# Remove old DMG
rm -f "$DMG_PATH"

# Stage DMG contents (app + setup instructions)
STAGING="$DIST_DIR/dmg-staging"
rm -rf "$STAGING"
mkdir -p "$STAGING"
cp -R "$APP_BUNDLE" "$STAGING/"
cp "$SCRIPT_DIR/READ_FIRST.txt" "$STAGING/"

BACKGROUND="$PROJECT_DIR/assets/dmg-background.png"

if command -v create-dmg &>/dev/null; then
    echo "Using create-dmg for professional layout..."
    CREATE_DMG_ARGS=(
        --volname "$APP_NAME"
        --volicon "$ICON"
        --window-pos 200 120
        --window-size 600 400
        --icon-size 100
        --icon "$APP_NAME.app" 175 190
        --hide-extension "$APP_NAME.app"
        --app-drop-link 425 190
        --icon "READ_FIRST.txt" 300 65
        --no-internet-enable
    )
    if [ -f "$BACKGROUND" ]; then
        CREATE_DMG_ARGS+=(--background "$BACKGROUND")
    fi
    create-dmg "${CREATE_DMG_ARGS[@]}" "$DMG_PATH" "$STAGING"
else
    echo "create-dmg not found, using hdiutil..."
    ln -s /Applications "$STAGING/Applications"

    hdiutil create -volname "$APP_NAME" \
        -srcfolder "$STAGING" \
        -ov -format UDZO \
        "$DMG_PATH"
fi

rm -rf "$STAGING"

echo "  Created: $DMG_PATH ($(du -h "$DMG_PATH" | cut -f1))"

# SHA256
SHA=$(shasum -a 256 "$DMG_PATH" | cut -d' ' -f1)
echo "$SHA  $DMG_NAME" > "$DIST_DIR/SHA256SUMS-dmg"
echo "  SHA256: $SHA"

# Copy to deployment directories
SITE_DIR="$PROJECT_DIR/../secureclaw-site/public"
SITE2_DIR="$(dirname "$(dirname "$PROJECT_DIR")")/024-sparkry-openclaw-security/site/public"

if [ -d "$SITE2_DIR" ]; then
    cp "$DMG_PATH" "$SITE2_DIR/$DMG_NAME"
    echo "  Copied to: $SITE2_DIR"
fi

echo ""
echo "=== Done ==="
echo "To test: open $APP_BUNDLE"
