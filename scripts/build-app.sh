#!/usr/bin/env bash
# Build Vogter.app: the SwiftUI menu bar app with vogterd and the vogter CLI inside.
#
#   scripts/build-app.sh                 # ad-hoc signed, for local use
#   SIGN_IDENTITY="Developer ID Application: …" scripts/build-app.sh
#   ENDPOINT_SECURITY=1 scripts/build-app.sh   # sign vogterd with the ES entitlement
#
# The ES entitlement only works with Apple's grant (provisioning profile), or on a
# test Mac/VM with SIP and AMFI relaxed. See docs/endpoint-security.md.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="$ROOT/build/Vogter.app"
IDENTITY="${SIGN_IDENTITY:--}"

cargo build --release --manifest-path "$ROOT/Cargo.toml" -p vogterd -p vogter-cli
swift build -c release --package-path "$ROOT/app"
BIN_DIR="$(swift build -c release --package-path "$ROOT/app" --show-bin-path)"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Helpers" "$APP/Contents/Resources"
cp "$ROOT/app/Info.plist" "$APP/Contents/Info.plist"
cp "$BIN_DIR/Vogter" "$APP/Contents/MacOS/Vogter"

# App icon: app/AppIcon.png (1024 px, artwork on Apple's 824 px grid) -> AppIcon.icns.
ICONSET="$(mktemp -d)/AppIcon.iconset"
mkdir -p "$ICONSET"
for size in 16 32 128 256 512; do
    sips -z "$size" "$size" "$ROOT/app/AppIcon.png" --out "$ICONSET/icon_${size}x${size}.png" >/dev/null
    sips -z $((size * 2)) $((size * 2)) "$ROOT/app/AppIcon.png" --out "$ICONSET/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"
rm -rf "$(dirname "$ICONSET")"

# Helpers live apart from MacOS/: the filesystem is case-insensitive, so `vogter` would overwrite `Vogter`.
cp "$ROOT/target/release/vogterd" "$ROOT/target/release/vogter" "$APP/Contents/Helpers/"

# Sign inside-out: helpers first, then the bundle.
DAEMON_ENTITLEMENTS=()
if [[ "${ENDPOINT_SECURITY:-0}" == 1 ]]; then
    DAEMON_ENTITLEMENTS=(--entitlements "$ROOT/packaging/vogterd.entitlements")
fi
# A real identity gets a secure timestamp (required for notarization); ad-hoc can't have one.
SIGN_FLAGS=(--force --options runtime --sign "$IDENTITY")
if [[ "$IDENTITY" != "-" ]]; then
    SIGN_FLAGS+=(--timestamp)
fi
codesign "${SIGN_FLAGS[@]}" ${DAEMON_ENTITLEMENTS[@]+"${DAEMON_ENTITLEMENTS[@]}"} "$APP/Contents/Helpers/vogterd"
codesign "${SIGN_FLAGS[@]}" "$APP/Contents/Helpers/vogter"
codesign "${SIGN_FLAGS[@]}" "$APP"

echo "Built $APP"
