#!/usr/bin/env bash
# Render the README screenshots into docs/images from made-up demo data
# (app/Sources/Vogter/Demo.swift). Draws the app's real views offscreen: no daemon,
# no Screen Recording permission, nothing from this Mac ends up in the images.
#
#   scripts/screenshots.sh            # docs/images/{menu,findings,activity,trusted,status,hero}-{light,dark}.png
#   scripts/screenshots.sh out/dir    # somewhere else
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/docs/images}"

swift build -c release --package-path "$ROOT/app"
BIN_DIR="$(swift build -c release --package-path "$ROOT/app" --show-bin-path)"
"$BIN_DIR/Vogter" --render-screenshots "$OUT"

# Shrink to 256-colour PNGs (about a quarter of the size, no visible difference for UI
# shots) when Pillow is available; otherwise keep the full-colour files.
if python3 -c 'import PIL' 2>/dev/null; then
    python3 - "$OUT" <<'PY'
import glob, os, sys
from PIL import Image
names = ("menu-", "findings-", "activity-", "trusted-", "status-", "hero-")
for path in sorted(glob.glob(os.path.join(sys.argv[1], "*.png"))):
    if not os.path.basename(path).startswith(names):
        continue
    img = Image.open(path).convert("RGB")
    img.quantize(colors=256, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE).save(path, optimize=True)
    print(f"compressed {os.path.basename(path)}: {os.path.getsize(path) // 1024} KB")
PY
else
    echo "note: python3 with Pillow not found; PNGs left uncompressed (pip3 install pillow)" >&2
fi
