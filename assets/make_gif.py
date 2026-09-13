"""Generate assets/demo.gif — terminal demo rendered as macOS-style frames.

Every string shown is a verbatim capture from real runs (2026-09-12; see
README Quick Start and benchmarks/workloads/exploit.wasm). Deterministic:
rerunning with the same inputs produces identical frames; ffmpeg palette =
tiny, crisp GIF. elapsed_ms is deliberately NOT shown — wasmtime fuel and
wall time are platform-dependent (see SECURITY.md), and the demo must not
age into a false claim. The fuel-bomb scene's numbers (100/100) are exact
on every platform: the budget is enforced, not measured.

Requires: Pillow (.venv), ffmpeg on PATH.
"""
from pathlib import Path
import subprocess
import tempfile

from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).parent
OUT = HERE / "demo.gif"

W, H = 960, 620
MARGIN = 14
FONT_SIZE = 22
TITLE_SIZE = 15

# GitHub-dark palette
BG = "#0d1117"
TITLEBAR = "#161b22"
TEXT = "#e6edf3"
MUTED = "#8b949e"
GREEN = "#3fb950"
CYAN = "#79c0ff"
RED = "#f85149"
PROMPT = "#3fb950"
BORDER = "#30363d"

FONT = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", FONT_SIZE)
FONT_B = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", FONT_SIZE)
TITLE_FONT = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", TITLE_SIZE)
LH = FONT_SIZE + 12

# (command, [(text, color), ...]) — outputs are verbatim real-run captures.
SCENES = [
    ("pip install ephemora-cell", [
        ("Successfully installed ephemora-cell-1.0.1 wasmtime-47.0.1", GREEN),
    ]),
    ("ephemora-cell run examples/hello.wasm", [
        ("Hello from Ephemora Cell!", TEXT),
    ]),
    ("ephemora-cell run hello.wasm --isolated --json", [
        ("{", MUTED),
        ('  "status": "success",  "exit_code": 0,', TEXT),
        ('  "fuel_consumed": 16397,  "fuel_budget": 1000000,', TEXT),
        ('  "security_baseline": { "preopens": ["/sandbox"], ... }', CYAN),
        ("}", MUTED),
    ]),
    ("ephemora-cell run fuel_bomb.wasm --isolated --fuel 100 --json", [
        ("{", MUTED),
        ('  "status": "fuel_exhausted",', RED),
        ('  "fuel_consumed": 100,', GREEN),
        ('  "fuel_budget": 100,  "fuel_utilization": 1.0,', GREEN),
        ("}", MUTED),
        ("every unit accounted — see it live in every CI push", MUTED),
    ]),
    ("ephemora-cell run exploit.wasm", [
        ("Blocked WASI import: wasi_snapshot_preview1::fd_psync", RED),
        ("  fsync/sync operations are not allowed in sandbox", RED),
        ("", TEXT),
        ("8/8 attack vectors blocked — live-verified, with positive controls:", MUTED),
        ("  python benchmarks/verify_8_vectors.py", MUTED),
    ]),
]

PAUSE_CMD = 8
PAUSE_OUT = 5
TYPE_SPEED = 6  # chars per frame — long commands per-keystroke frames dominate GIF size


def frame(history, current_cmd, typed, out_lines, out_reveal):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    # window chrome
    d.rounded_rectangle([MARGIN, MARGIN, W - MARGIN, H - MARGIN], 12, fill=BG, outline=BORDER, width=2)
    d.rounded_rectangle([MARGIN, MARGIN, W - MARGIN, MARGIN + 44], 12, fill=TITLEBAR)
    d.rectangle([MARGIN, MARGIN + 26, W - MARGIN, MARGIN + 44], fill=TITLEBAR)
    for i, c in enumerate(("#ff5f57", "#febc2e", "#28c840")):
        d.ellipse([MARGIN + 18 + i * 26, MARGIN + 16, MARGIN + 34 + i * 26, MARGIN + 32], fill=c)
    d.text((MARGIN + 110, MARGIN + 14), "ephemora-cell — zsh", font=TITLE_FONT, fill=MUTED)

    # Soft scroll: build the full transcript, render only the lines that fit
    # (a 5-scene history overflows the frame — a real terminal scrolls too).
    lines = []
    for cmd, outs in history:
        lines.append(("prompt", cmd))
        lines += [("out", t, c) for t, c in outs]
        lines.append(("gap", ""))
    if current_cmd is not None:
        cursor = "▌" if (typed // TYPE_SPEED) % 2 else ""
        lines.append(("prompt", current_cmd[:typed] + cursor))
        lines += [("out", t, c) for t, c in out_lines[:out_reveal]]
    avail = H - (MARGIN + 64) - 14
    height = sum(LH if it[0] != "gap" else 8 for it in lines)
    while height > avail and lines:
        height -= LH if lines[0][0] != "gap" else 8
        lines.pop(0)
    visible = lines

    y = MARGIN + 64
    for item in visible:
        if item[0] == "prompt":
            d.text((MARGIN + 20, y), "➜ ~ " + item[1], font=FONT, fill=PROMPT)
            y += LH
        elif item[0] == "out":
            d.text((MARGIN + 34, y), item[1], font=FONT, fill=item[2] or TEXT)
            y += LH
        else:  # gap — the original 8 px scene spacing
            y += 8
    return img


def build_frames():
    frames = []
    history = []
    for cmd, outs in SCENES:
        for t in range(0, len(cmd) + 1, TYPE_SPEED):
            frames.append(frame(history, cmd, t, [], 0))
        frames += [frame(history, cmd, len(cmd), [], 0)] * PAUSE_CMD
        for r in range(1, len(outs) + 1):
            frames += [frame(history, cmd, len(cmd), outs, r)] * (PAUSE_OUT if r == len(outs) else 2)
        frames += [frame(history, cmd, len(cmd), outs, len(outs))] * 14
        history.append((cmd, outs))
        history = history[-1:]  # one-scene window: worst case (prev + current) always fits the frame, so reveal frames never shift the whole screen
    frames += [frame(history, None, 0, [], 0)] * 22  # hold final state
    return frames


if __name__ == "__main__":
    frames = build_frames()
    with tempfile.TemporaryDirectory() as td:
        for i, f in enumerate(frames):
            f.save(f"{td}/{i:04d}.png")
        subprocess.run(
            ["ffmpeg", "-y", "-loglevel", "error", "-framerate", "16",
             "-i", f"{td}/%04d.png", "-vf",
             "split[a][b];[a]palettegen=max_colors=64:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=5:new=1",
             str(OUT)],
            check=True,
        )
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB, {len(frames)} frames)")
