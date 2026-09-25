"""Build the 1.0.4 meme GIF for X: terminal comedy, legacy session pain
vs. the stateless 2026-07-28 era. GitHub-dark palette, Menlo, same visual
language as demo.gif. Output: assets/stateless-meme.gif (1200x675).
"""

import tempfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).parent
OUT = HERE / "stateless-meme.gif"

W, H = 1200, 675
MARGIN = 28
FONT_SIZE = 26
TITLE_SIZE = 17

BG = "#0d1117"
TITLEBAR = "#161b22"
TEXT = "#e6edf3"
MUTED = "#8b949e"
GREEN = "#3fb950"
CYAN = "#79c0ff"
RED = "#f85149"
PROMPT = "#3fb950"
BORDER = "#30363d"
ACCENT = "#4493f8"

FONT = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", FONT_SIZE)
TITLE_FONT = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", TITLE_SIZE)
LH = FONT_SIZE + 14

# (title, [(text, color), ...]) — the joke, six beats.
SCENES = [
    ("legacy MCP server — 2025", [
        ("$ initialize", PROMPT),
        ("negotiating capabilities ...", MUTED),
        ("session established — remember me", CYAN),
    ]),
    ("legacy MCP server — 2025", [
        ("^C  connection lost", RED),
        ("session gone.", MUTED),
        ("start over. every client. every time.", MUTED),
    ]),
    ("ephemora-cell — MCP 2026-07-28", [
        ("$ tools/call echo {\"message\":\"hi\"}", PROMPT),
        ("{\"echo\":{\"message\":\"hi\"}}", TEXT),
        ("ok — 12 ms, 20564 fuel, sandboxed", GREEN),
    ]),
    ("ephemora-cell — MCP 2026-07-28", [
        ("$ kill -9 $(pgrep ephemora-cell-mcp)", PROMPT),
        ("[server destroyed]", RED),
    ]),
    ("ephemora-cell — MCP 2026-07-28", [
        ("$ tools/call echo {\"message\":\"still there?\"}", PROMPT),
        ("{\"echo\":{\"message\":\"still there?\"}}", TEXT),
        ("no handshake. no session. no problem.", GREEN),
    ]),
    ("stateless. sandboxed. verified.", [
        ("pip install ephemora-cell", CYAN),
        ("github.com/MichaelS1011/ephemora-cell", MUTED),
    ]),
]


def frame(title: str, lines: list) -> Image.Image:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    # terminal chrome
    d.rounded_rectangle([8, 8, W - 8, H - 8], radius=14, outline=BORDER, width=2)
    d.rounded_rectangle([8, 8, W - 8, 8 + 46], radius=14, fill=TITLEBAR)
    d.rectangle([8, 8 + 24, W - 8, 8 + 46], fill=TITLEBAR)
    for i, c in enumerate(("#ff5f57", "#febc2e", "#28c840")):
        d.ellipse([30 + i * 26, 24, 44 + i * 26, 38], fill=c)
    d.text((W // 2 - 130, 20), title, font=TITLE_FONT, fill=MUTED)
    # body
    y = 8 + 46 + MARGIN
    for text, color in lines:
        d.text((MARGIN + 16, y), text, font=FONT, fill=color)
        y += LH
    return img


def main() -> None:
    frames = [frame(title, lines) for title, lines in SCENES]
    frames[0].save(
        OUT, save_all=True, append_images=frames[1:], duration=1100, loop=0,
        optimize=True,
    )
    print(f"{OUT} ({OUT.stat().st_size} bytes, {len(frames)} frames)")


if __name__ == "__main__":
    main()
