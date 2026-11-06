"""Render assets/cyberdeck.png for the README and the TUI. Dev-time only; Pillow isn't a
dependency of Cyberdeck:

    uv run --no-project --with pillow python scripts/render_logo.py

Writes:
  assets/logo-dark.png    the logo cropped, as drawn (white "Cyber", cyan "deck"): dark pages
  assets/logo-light.png   the same with a dark "Cyber", for light pages (GitHub light mode)
  src/cyberdeck/ui/logo.py the logo as Unicode quadrant blocks (2x2 pixels per cell), in Textual
                          markup: "Cyber" in $foreground and "deck" in $accent, so it follows
                          the theme and works in any terminal and in the browser UI.
"""

from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "assets" / "cyberdeck.png"
LIGHT_INK = (11, 4, 24)  # "Cyber" on light pages: the neon theme's background colour
PAD = 24
# Terminal cells are about twice as tall as wide; a quadrant sub-pixel is half a cell wide and
# half a cell tall, so it is about 1:2 too, i.e. image rows are squashed by this factor.
CELL_ASPECT = 2.0
# (top-left, top-right, bottom-left, bottom-right) -> quadrant character
QUADRANTS = {
    (0, 0, 0, 0): " ",
    (1, 0, 0, 0): "▘",
    (0, 1, 0, 0): "▝",
    (1, 1, 0, 0): "▀",
    (0, 0, 1, 0): "▖",
    (1, 0, 1, 0): "▌",
    (0, 1, 1, 0): "▞",
    (1, 1, 1, 0): "▛",
    (0, 0, 0, 1): "▗",
    (1, 0, 0, 1): "▚",
    (0, 1, 0, 1): "▐",
    (1, 1, 0, 1): "▜",
    (0, 0, 1, 1): "▄",
    (1, 0, 1, 1): "▙",
    (0, 1, 1, 1): "▟",
    (1, 1, 1, 1): "█",
}


def is_accent(r: int, g: int, b: int) -> bool:
    return b > 150 and r < 120  # the cyan "deck"


def crop(im: Image.Image) -> Image.Image:
    box = im.getchannel("A").point(lambda v: 255 if v > 128 else 0).getbbox()
    if not box:
        raise SystemExit("the logo is empty")
    left, top, right, bottom = box
    return im.crop(
        (
            max(left - PAD, 0),
            max(top - PAD, 0),
            min(right + PAD, im.width),
            min(bottom + PAD, im.height),
        )
    )


def light_variant(im: Image.Image) -> Image.Image:
    out = im.copy()
    px = out.load()
    for y in range(out.height):
        for x in range(out.width):
            r, g, b, a = px[x, y]
            if a and not is_accent(r, g, b):
                px[x, y] = (*LIGHT_INK, a)
    return out


def blocks(im: Image.Image, cols: int) -> tuple[str, int, int]:
    """Textual markup for the logo, ``cols`` cells wide."""
    tight = im.crop(im.getchannel("A").point(lambda v: 255 if v > 128 else 0).getbbox())
    sub_w = cols * 2
    rows = max(1, round(tight.height / tight.width * sub_w / CELL_ASPECT / 2))
    sub_h = rows * 2
    alpha = tight.getchannel("A").resize((sub_w, sub_h), Image.Resampling.BOX)
    colour = tight.convert("RGB").resize((sub_w, sub_h), Image.Resampling.BOX)
    on = [[alpha.getpixel((x, y)) > 110 for x in range(sub_w)] for y in range(sub_h)]
    lines = []
    for row in range(rows):
        line, current = "", ""
        for col in range(cols):
            cells = [(col * 2 + dx, row * 2 + dy) for dy in (0, 1) for dx in (0, 1)]
            bits = tuple(int(on[y][x]) for x, y in cells)
            char = QUADRANTS[(bits[0], bits[1], bits[2], bits[3])]
            if char == " ":
                line += " "
                continue
            lit = [colour.getpixel((x, y)) for (x, y), bit in zip(cells, bits, strict=True) if bit]
            accent = sum(is_accent(*c) for c in lit) * 2 >= len(lit)
            part = "$accent" if accent else "$foreground"
            if part != current:
                line += ("[/]" if current else "") + f"[{part}]"
                current = part
            line += char
        lines.append(line + ("[/]" if current else ""))
    return "\n".join(lines), cols, rows


def main() -> None:
    cols = int(sys.argv[1]) if len(sys.argv) > 1 else 72
    im = Image.open(SOURCE).convert("RGBA")
    dark = crop(im)
    dark.save(ROOT / "assets" / "logo-dark.png", optimize=True)
    light_variant(dark).save(ROOT / "assets" / "logo-light.png", optimize=True)
    art, width, height = blocks(im, cols)
    rows = "".join(f"        {line!r},\n" for line in art.split("\n"))
    (ROOT / "src" / "cyberdeck" / "ui" / "logo.py").write_text(
        "# ruff: noqa: E501\n"
        '"""The Cyberdeck logo as Unicode quadrant blocks in Textual markup ("Cyber" in\n'
        '$foreground, "deck" in $accent). Generated from assets/cyberdeck.png by\n'
        'scripts/render_logo.py: edit the PNG and re-run it, don\'t edit this file."""\n\n'
        f'LOGO = "\\n".join(\n    (\n{rows}    )\n)\n'
        f"LOGO_WIDTH = {width}\nLOGO_HEIGHT = {height}\n",
        encoding="utf-8",
    )
    print(f"logo {width}x{height} cells; PNGs {dark.size}")


if __name__ == "__main__":
    main()
