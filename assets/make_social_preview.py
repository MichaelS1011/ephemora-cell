"""Social preview image (1280x640) — GitHub 'Social media preview'.

GitHub has no API for the social preview upload; this script regenerates
the asset deterministically, a human uploads it in repo Settings ->
General -> Social media preview. Palette matches assets/hero-dark.svg
(GitHub Primer dark) so link unfurls match the README look.
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

W, H = 1280, 640
BG = "#0d1117"
BORDER = "#30363d"
TEXT = "#e6edf3"
MUTED = "#9198a1"
ACCENT = "#4493f8"
ACCENT_FILL = "#121d2f"
OK = "#3fb950"

OUT = Path(__file__).resolve().parent / "social-preview.png"


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    candidates = [
        "/System/Library/Fonts/SFNS.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf" if bold
        else "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold
        else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ]
    for path in candidates:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def center(draw: ImageDraw.ImageDraw, y: int, text: str, f, fill: str) -> int:
    w = draw.textlength(text, font=f)
    draw.text(((W - w) / 2, y), text, font=f, fill=fill)
    return y


def main() -> None:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    # frame
    d.rectangle([16, 16, W - 16, H - 16], outline=BORDER, width=2)

    # title chip
    chip = "EPHEMORA CELL"
    f_title = font(84, bold=True)
    tw = d.textlength(chip, font=f_title)
    d.rounded_rectangle(
        [(W - tw) / 2 - 44, 96, (W + tw) / 2 + 44, 216],
        radius=16, fill=ACCENT_FILL, outline=ACCENT, width=3,
    )
    d.text(((W - tw) / 2, 112), chip, font=f_title, fill=TEXT)

    # subtitle
    f_sub = font(40)
    sub = "Secure execution for untrusted AI-generated code"
    center(d, 268, sub, f_sub, TEXT)

    # facts strip
    f_fact = font(30, bold=True)
    facts = "8/8 ATTACK VECTORS BLOCKED  ·  SUB-MS WARM EXECUTION  ·  MCP"
    fw = d.textlength(facts, font=f_fact)
    d.text(((W - fw) / 2, 380), facts, font=f_fact, fill=OK)

    # boundary line
    d.line([(W / 2 - 360, 470), (W / 2 + 360, 470)], fill=BORDER, width=2)

    # footer claim
    f_foot = font(26)
    center(d, 500, "capability boundary  ·  resource limits  ·  auditable execution records",
           f_foot, MUTED)

    img.save(OUT, optimize=True)
    print(f"wrote {OUT} ({OUT.stat().st_size / 1024:.0f} KB)")


if __name__ == "__main__":
    main()
