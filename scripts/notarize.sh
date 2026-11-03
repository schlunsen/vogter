#!/usr/bin/env bash
# Notarize and staple a Developer ID-signed Vogter.app.
#
#   scripts/notarize.sh [path/to/Vogter.app]      # default: build/Vogter.app
#
# Needs notarytool credentials saved once in your keychain (never in this repo):
#   xcrun notarytool store-credentials vogter-notary \
#       --apple-id <your Apple ID> --team-id 33HN83NDFB
# (it prompts for an app-specific password from https://account.apple.com)
#
# NOTARY_PROFILE picks the saved profile (default: vogter-notary).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="${1:-$ROOT/build/Vogter.app}"
PROFILE="${NOTARY_PROFILE:-vogter-notary}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

[[ -d "$APP" ]] || { echo "no app at $APP (run scripts/build-app.sh first)" >&2; exit 1; }

# Notarization only accepts Developer ID signatures with a secure timestamp.
SIGNER="$(codesign -dv --verbose=2 "$APP" 2>&1 | sed -n 's/^Authority=//p' | head -1)"
if [[ "$SIGNER" != "Developer ID Application:"* ]]; then
    echo "$APP is signed by '${SIGNER:-ad-hoc}', not a Developer ID." >&2
    echo "Rebuild with: SIGN_IDENTITY=\"Developer ID Application: …\" scripts/build-app.sh" >&2
    exit 1
fi
echo "Signed by: $SIGNER"
codesign --verify --strict --deep "$APP"

ZIP="$WORK/Vogter.zip"
ditto -c -k --norsrc --noextattr --keepParent "$APP" "$ZIP"

echo "Submitting to Apple (profile: $PROFILE); this usually takes a few minutes…"
OUT="$WORK/submit.json"
xcrun notarytool submit "$ZIP" --keychain-profile "$PROFILE" --wait --output-format json > "$OUT" || true
STATUS="$(/usr/bin/plutil -extract status raw -o - "$OUT" 2>/dev/null || echo unknown)"
ID="$(/usr/bin/plutil -extract id raw -o - "$OUT" 2>/dev/null || echo)"
echo "Notarization: $STATUS ${ID:+(submission $ID)}"
if [[ "$STATUS" != "Accepted" ]]; then
    cat "$OUT" >&2
    [[ -n "$ID" ]] && xcrun notarytool log "$ID" --keychain-profile "$PROFILE" >&2
    exit 1
fi

xcrun stapler staple "$APP"
xcrun stapler validate "$APP"
spctl --assess --type execute --verbose=2 "$APP"
echo "Notarized and stapled: $APP"
