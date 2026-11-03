#!/usr/bin/env bash
# Install vogterd as a root LaunchDaemon.
#
#   sudo scripts/install-daemon.sh [path/to/vogterd]   # install / reinstall
#   sudo scripts/install-daemon.sh uninstall
#
# The binary is copied to /Library/PrivilegedHelperTools, root-owned and not
# writable by anyone else. It must never run from a user-writable location
# (like an app the user dragged to /Applications): any of that user's processes
# could replace it and get root on the next restart.
#
# The default source is /Applications/Vogter.app/Contents/Helpers/vogterd. It
# must have a valid Developer ID signature from VOGTER_TEAM_ID (default: the
# project's team). For local ad-hoc builds, pass ALLOW_ADHOC=1.
#
# Afterwards, give /Library/PrivilegedHelperTools/com.vogter.vogterd Full Disk
# Access in System Settings → Privacy & Security so it can read permission databases.
set -euo pipefail

LABEL=com.vogter.daemon
PLIST=/Library/LaunchDaemons/$LABEL.plist
HELPER_DIR=/Library/PrivilegedHelperTools
HELPER=$HELPER_DIR/com.vogter.vogterd
LOG=/Library/Logs/vogterd.log
TEAM="${VOGTER_TEAM_ID:-33HN83NDFB}"
PLIST_SRC="$(cd "$(dirname "$0")/.." && pwd)/packaging/$LABEL.plist"

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }

launchctl bootout system "$PLIST" 2>/dev/null || true
if [[ "${1:-}" == "uninstall" ]]; then
    rm -f "$PLIST" "$HELPER"
    echo "vogterd uninstalled (data kept in /Library/Application Support/Vogter)"
    exit 0
fi

SRC="${1:-/Applications/Vogter.app/Contents/Helpers/vogterd}"
[[ -f "$SRC" ]] || { echo "no vogterd at $SRC (copy Vogter.app to /Applications first)" >&2; exit 1; }

# Copy first, then verify the root-owned copy, so the file can't be swapped
# between the check and the install.
install -d -m 755 -o root -g wheel "$HELPER_DIR"
TMP="$(mktemp "$HELPER_DIR/.vogterd.XXXXXX")"
trap 'rm -f "$TMP"' EXIT
cat "$SRC" > "$TMP"
chown root:wheel "$TMP"
chmod 755 "$TMP"

codesign --verify --strict "$TMP" || { echo "vogterd's signature is invalid; refusing to install" >&2; exit 1; }
if codesign --verify --strict -R="anchor apple generic and certificate leaf[subject.OU] = \"$TEAM\"" "$TMP" 2>/dev/null; then
    echo "signature: Developer ID, team $TEAM"
elif [[ "${ALLOW_ADHOC:-0}" == 1 ]]; then
    echo "warning: installing a binary not signed by team $TEAM (ALLOW_ADHOC=1)" >&2
else
    echo "vogterd is not signed by team $TEAM; refusing to run it as root." >&2
    echo "For a local build you trust, rerun with ALLOW_ADHOC=1." >&2
    exit 1
fi
mv -f "$TMP" "$HELPER"
trap - EXIT

# Root-owned, private log (launchd also applies the plist's Umask).
touch "$LOG" && chown root:wheel "$LOG" && chmod 600 "$LOG"

install -m 644 -o root -g wheel "$PLIST_SRC" "$PLIST"
launchctl bootstrap system "$PLIST"
echo "vogterd installed at $HELPER; logs in $LOG"
