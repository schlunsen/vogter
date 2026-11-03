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
# Helpers live apart from MacOS/: the filesystem is case-insensitive, so `vogter` would overwrite `Vogter`.
cp "$ROOT/target/release/vogterd" "$ROOT/target/release/vogter" "$APP/Contents/Helpers/"

# Sign inside-out: helpers first, then the bundle.
DAEMON_ENTITLEMENTS=()
if [[ "${ENDPOINT_SECURITY:-0}" == 1 ]]; then
    DAEMON_ENTITLEMENTS=(--entitlements "$ROOT/packaging/vogterd.entitlements")
fi
codesign --force --options runtime --sign "$IDENTITY" ${DAEMON_ENTITLEMENTS[@]+"${DAEMON_ENTITLEMENTS[@]}"} "$APP/Contents/Helpers/vogterd"
codesign --force --options runtime --sign "$IDENTITY" "$APP/Contents/Helpers/vogter"
codesign --force --options runtime --sign "$IDENTITY" "$APP"

echo "Built $APP"
