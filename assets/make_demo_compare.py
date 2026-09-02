"""Generate assets/same-boundary.gif — "Same Attack. Different Boundary."

Left column = live Docker probe, right column = live Ephemora Cell probe.
Every status string and both scores come from the measured JSONs, never
typed: the honesty gate asserts the on-screen "0/8" and "8/8" equal the
counts computed from the data. If either run changes, the GIF changes with
it -- it cannot quietly drift into a false claim.

Reuses the frame/palette/ffmpeg machinery from make_gif.py.
Requires: Pillow, ffmpeg on PATH. Regenerate inputs first:
  python3 assets/demo_attack_probe.py            # docker (left)
  python benchmarks/verify_8_vectors.py          # cell   (right)
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).parent
REPO = HERE.parent
CELL_JSON = REPO / "benchmarks/results/2026-09-02/02_cell_8_vector_verify.json"
DOCKER_JSON = REPO / "benchmarks/results/2026-09-02/01_docker_attack_probe.json"
OUT = HERE / "same-boundary.gif"

W, H = 980, 560
MARGIN = 16
FS = 21
BG, TITLEBAR, TEXT, MUTED = "#0d1117", "#161b22", "#e6edf3", "#8b949e"
GREEN, CYAN, RED, BORDER = "#3fb950", "#79c0ff", "#f85149", "#30363d"

FONT = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", FS)
FONT_B = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", FS)
FONT_SM = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", 15)
LH = FS + 11

# (display label, docker-json-key, cell-json-key) — pairing the two live runs.
ROWS = [
    ("shell", "shell", "shell_access"),
    ("fork", "fork", "fork"),
    ("socket", "socket", "network"),
    ("fsync", "fsync", "fsync"),
    ("/etc/passwd", "/etc/passwd", "host_fs"),
    ("symlink escape", "symlink escape", "symlink"),
    ("threads", "threads", "threading"),
    ("environment", "environment", "env"),
]


def load_status() -> list[tuple[str, str, str]]:
    """Return [(label, docker_status, cell_status)] read from measured data."""
    docker = json.loads(DOCKER_JSON.read_text())["results"]
    cell_raw = json.loads(CELL_JSON.read_text())
    cell = cell_raw.get("results", cell_raw)
    rows = []
    for label, dk, ck in ROWS:
        d = docker[dk]["status"]  # ALLOWED | BLOCKED
        b = cell[ck].get("blocked")
        c = "BLOCKED" if b is True else ("ALLOWED" if b is False else "?")
        rows.append((label, d, c))
    return rows


def build() -> tuple[list, int, int]:
    rows = load_status()
    docker_blocked = sum(1 for _, d, _ in rows if d == "BLOCKED")
    cell_blocked = sum(1 for _, _, c in rows if c == "BLOCKED")
    # HONESTY GATE — the numbers we render must equal the measured counts.
    assert docker_blocked == 0, f"docker blocked {docker_blocked}, demo assumes 0"
    assert cell_blocked == len(rows), f"cell blocked {cell_blocked}/{len(rows)}"
    return rows, docker_blocked, cell_blocked


def draw(row_count, show_score=False, show_tagline=False):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rounded_rectangle(
        [MARGIN, MARGIN, W - MARGIN, H - MARGIN], 12, fill=BG, outline=BORDER, width=2
    )
    d.text(
        (MARGIN + 24, MARGIN + 16),
        "Same Attack. Different Boundary.",
        font=FONT_B,
        fill=TEXT,
    )

    rows, d_blk, c_blk = build()
    col1 = MARGIN + 40
    col2 = W // 2 + 20
    y = MARGIN + 68
    d.text((col1, y), "DOCKER", font=FONT_B, fill=MUTED)
    d.text((col2, y), "EPHEMORA CELL", font=FONT_B, fill=CYAN)
    d.text((col1, y + LH), "same workload", font=FONT_SM, fill=MUTED)
    d.text((col2, y + LH), "same workload", font=FONT_SM, fill=MUTED)
    d.line([W // 2, y, W // 2, H - 150], fill=BORDER, width=1)

    y += LH * 2 + 6
    for label, dk, ck in rows[:row_count]:
        d.text((col1, y), label, font=FONT, fill=TEXT)
        d.text(
            (W // 2 - 150, y),
            "✓" if dk == "ALLOWED" else "BLOCKED",
            font=FONT,
            fill=RED if dk == "ALLOWED" else GREEN,
        )
        d.text((col2, y), label, font=FONT, fill=TEXT)
        d.text(
            (W - MARGIN - 210, y),
            "✓" if ck == "ALLOWED" else "BLOCKED",
            font=FONT,
            fill=RED if ck == "ALLOWED" else GREEN,
        )
        y += LH

    if show_score:
        y = H - 128
        d.text((col1 + 60, y), f"{d_blk} / {len(rows)}", font=FONT_B, fill=RED)
        d.text((col2 + 40, y), f"{c_blk} / {len(rows)}", font=FONT_B, fill=GREEN)
    if show_tagline:
        d.text(
            (W // 2 - 190, H - 88),
            "Live verified · Reproducible · Apache 2.0",
            font=FONT_SM,
            fill=MUTED,
        )
        d.text(
            (W // 2 - 130, H - 64),
            "0.46 ms median pooled end-to-end",
            font=FONT_SM,
            fill=MUTED,
        )
    return img


def main() -> None:
    total = len(ROWS)
    frames = [draw(n) for n in range(1, total + 1) for _ in range(5)]
    frames += [draw(total, show_score=True) for _ in range(12)]
    frames += [draw(total, show_score=True, show_tagline=True) for _ in range(70)]
    with tempfile.TemporaryDirectory() as td:
        for i, f in enumerate(frames):
            f.save(f"{td}/{i:04d}.png")
        subprocess.run(
            [
                "ffmpeg",
                "-y",
                "-loglevel",
                "error",
                "-framerate",
                "12",
                "-i",
                f"{td}/%04d.png",
                "-vf",
                "split[a][b];[a]palettegen=max_colors=64[p];[b][p]paletteuse=dither=bayer:bayer_scale=4",
                str(OUT),
            ],
            check=True,
        )
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB, {len(frames)} frames)")


if __name__ == "__main__":
    main()
