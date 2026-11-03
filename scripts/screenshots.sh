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

# Shrink to 256-colour PNGs (a fraction of the size, no visible difference for UI
# shots) when Pillow is available; otherwise keep the full-colour files.
# The background wash is drawn dithered (±1 noise that PNG can't compress), so first
# flatten each horizontal run of near-uniform pixels to its average: the wash is a
# vertical gradient, so rows stay exact and text, icons and edges are left alone.
if python3 -c 'import PIL' 2>/dev/null; then
    python3 - "$OUT" <<'PY'
import glob, os, re, sys
from PIL import Image, ImageChops, ImageFilter

def flatten(img):
    w, h = img.size
    gray = img.convert("L")
    spread = ImageChops.subtract(gray.filter(ImageFilter.MaxFilter(5)), gray.filter(ImageFilter.MinFilter(5)))
    flat = spread.point(lambda v: 255 if v <= 3 else 0).tobytes()
    rgb = bytearray(img.tobytes())
    run = re.compile(b"\xff{32,}")
    for y in range(h):
        for m in run.finditer(flat, y * w, y * w + w):
            a, b = m.start() * 3, m.end() * 3
            seg, n, fill = rgb[a:b], m.end() - m.start(), []
            for c in range(3):
                ch = seg[c::3]
                if max(ch) - min(ch) > 3:
                    break
                fill.append((sum(ch) + n // 2) // n)
            else:
                rgb[a:b] = bytes(fill) * n
    return Image.frombytes("RGB", (w, h), bytes(rgb))

names = ("menu-", "findings-", "activity-", "trusted-", "status-", "hero-")
for path in sorted(glob.glob(os.path.join(sys.argv[1], "*.png"))):
    if not os.path.basename(path).startswith(names):
        continue
    img = flatten(Image.open(path).convert("RGB"))
    # Half the palette from median cut (smooth greys and shadows), half from octree
    # (the small soft accent colours, which median cut alone washes out).
    halves = [img.quantize(colors=128, method=m, dither=Image.Dither.NONE).getpalette()[:128 * 3]
              for m in (Image.Quantize.MEDIANCUT, Image.Quantize.FASTOCTREE)]
    palette = Image.new("P", (1, 1))
    palette.putpalette(halves[0] + halves[1])
    img.quantize(palette=palette, dither=Image.Dither.NONE).save(path, optimize=True)
    print(f"compressed {os.path.basename(path)}: {os.path.getsize(path) // 1024} KB")
PY
else
    echo "note: python3 with Pillow not found; PNGs left uncompressed (pip3 install pillow)" >&2
fi
