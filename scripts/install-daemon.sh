#!/usr/bin/env bash
# Install vogterd as a root LaunchDaemon. Requires /Applications/Vogter.app
# (copy build/Vogter.app there first). Afterwards, give
# /Applications/Vogter.app/Contents/Helpers/vogterd Full Disk Access in
# System Settings → Privacy & Security so it can read permission databases.
#
#   sudo scripts/install-daemon.sh            # install / reinstall
#   sudo scripts/install-daemon.sh uninstall
set -euo pipefail

PLIST=/Library/LaunchDaemons/com.vogter.daemon.plist
SRC="$(cd "$(dirname "$0")/.." && pwd)/packaging/com.vogter.daemon.plist"

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }

launchctl bootout system "$PLIST" 2>/dev/null || true
if [[ "${1:-}" == "uninstall" ]]; then
    rm -f "$PLIST"
    echo "vogterd uninstalled (data kept in /Library/Application Support/Vogter)"
    exit 0
fi

[[ -x /Applications/Vogter.app/Contents/Helpers/vogterd ]] || { echo "copy build/Vogter.app to /Applications first" >&2; exit 1; }
install -m 644 -o root -g wheel "$SRC" "$PLIST"
launchctl bootstrap system "$PLIST"
echo "vogterd installed; logs in /Library/Logs/vogterd.log"
