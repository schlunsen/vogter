#!/usr/bin/env bash
# Package a Vogter release into build/dist/ (git-ignored).
#
#   scripts/release.sh                 # version from Cargo.toml, e.g. 0.1.0
#   scripts/release.sh 0.2.0           # explicit version (a leading "v" is stripped)
#   SKIP_BUILD=1 scripts/release.sh    # reuse an existing build/Vogter.app and target/release
#   scripts/release.sh --shas v0.1.0   # print the sha256 values to paste into the Homebrew tap
#
# Produces, for the host architecture (arm64 or x86_64):
#   build/dist/vogter-<version>-macos-<arch>.tar.gz   vogter + vogterd + README.md + LICENSE
#   build/dist/Vogter-<version>-macos-<arch>.zip      Vogter.app (built by scripts/build-app.sh)
#   build/dist/SHA256SUMS
#
# SIGN_IDENTITY and ENDPOINT_SECURITY are passed through to scripts/build-app.sh;
# NOTARIZE=1 (with NOTARY_PROFILE) notarizes the app first, see scripts/notarize.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO="${VOGTER_REPO:-schlunsen/vogter}"

# --shas <tag>: print the sha256 of the tag's source tarball and of the release assets,
# straight from GitHub, in the form the tap's formula and cask need.
if [[ "${1:-}" == "--shas" ]]; then
    TAG="${2:?usage: scripts/release.sh --shas vX.Y.Z}"
    [[ "$TAG" == v* ]] || TAG="v$TAG"
    VER="${TAG#v}"
    sha_of() { curl -fsSL "$1" | shasum -a 256 | cut -d' ' -f1; }
    SRC_URL="https://github.com/$REPO/archive/refs/tags/$TAG.tar.gz"
    ZIP_URL="https://github.com/$REPO/releases/download/$TAG/Vogter-$VER-macos-arm64.zip"
    echo "version  $VER"
    echo "formula  url    $SRC_URL"
    echo "formula  sha256 $(sha_of "$SRC_URL")"
    echo "cask     url    $ZIP_URL"
    echo "cask     sha256 $(sha_of "$ZIP_URL")"
    exit 0
fi

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
    VERSION="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version *= *"\(.*\)"/\1/p' "$ROOT/Cargo.toml")"
fi
VERSION="${VERSION#v}"
[[ -n "$VERSION" ]] || { echo "could not determine version" >&2; exit 1; }

case "$(uname -m)" in
    arm64 | aarch64) ARCH=arm64 ;;
    x86_64) ARCH=x86_64 ;;
    *) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

CARGO_VERSION="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version *= *"\(.*\)"/\1/p' "$ROOT/Cargo.toml")"
if [[ "$CARGO_VERSION" != "$VERSION" ]]; then
    echo "warning: release version $VERSION differs from Cargo.toml version $CARGO_VERSION" >&2
fi

if [[ "${SKIP_BUILD:-0}" != 1 ]]; then
    # build-app.sh builds vogter and vogterd in release mode too.
    "$ROOT/scripts/build-app.sh"
    # NOTARIZE=1: notarize and staple before packaging (needs a Developer ID
    # SIGN_IDENTITY and saved notarytool credentials, see scripts/notarize.sh).
    if [[ "${NOTARIZE:-0}" == 1 ]]; then
        "$ROOT/scripts/notarize.sh" "$ROOT/build/Vogter.app"
    fi
fi

APP="$ROOT/build/Vogter.app"
for f in "$ROOT/target/release/vogter" "$ROOT/target/release/vogterd" "$APP/Contents/MacOS/Vogter"; do
    [[ -e "$f" ]] || { echo "missing $f (run without SKIP_BUILD=1)" >&2; exit 1; }
done

DIST="$ROOT/build/dist"
NAME="vogter-$VERSION-macos-$ARCH"
TARBALL="$NAME.tar.gz"
ZIP="Vogter-$VERSION-macos-$ARCH.zip"
rm -rf "$DIST"
mkdir -p "$DIST/$NAME"

# CLI tarball: use the signed helpers from the app bundle so both downloads ship
# identical binaries.
cp "$APP/Contents/Helpers/vogter" "$APP/Contents/Helpers/vogterd" "$DIST/$NAME/"
cp "$ROOT/README.md" "$ROOT/LICENSE" "$DIST/$NAME/"
# COPYFILE_DISABLE keeps macOS from adding ._ AppleDouble files to the tarball.
COPYFILE_DISABLE=1 tar -C "$DIST" -czf "$DIST/$TARBALL" "$NAME"
rm -rf "${DIST:?}/$NAME"

# App zip: ditto keeps the bundle layout and symlinks intact. --norsrc --noextattr leaves
# out ._ AppleDouble entries (e.g. com.apple.provenance): the signature does not need them,
# and plain `unzip` (which Homebrew uses for casks) would put them inside the bundle as
# stray files and break the signature seal.
ditto -c -k --norsrc --noextattr --keepParent "$APP" "$DIST/$ZIP"

(cd "$DIST" && shasum -a 256 "$TARBALL" "$ZIP" > SHA256SUMS)

echo "Release $VERSION ($ARCH) in $DIST:"
cat "$DIST/SHA256SUMS"
