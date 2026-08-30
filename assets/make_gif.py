"""Generate assets/demo.gif — terminal demo rendered as macOS-style frames.

Every string shown is a verbatim capture from real runs (see README Quick
Start and benchmarks/workloads/exploit.wasm). Deterministic: rerunning with
the same inputs produces identical frames; ffmpeg palette = tiny, crisp GIF.

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
        ("Successfully installed ephemora-cell-1.0.0 wasmtime-47.0.1", GREEN),
    ]),
    ("ephemora-cell run examples/hello.wasm", [
        ("Hello from Ephemora Cell!", TEXT),
    ]),
    ("ephemora-cell run examples/hello.wasm --json", [
        ("{", MUTED),
        ('  "status": "success",', TEXT),
        ('  "exit_code": 0,', TEXT),
        ('  "elapsed_ms": 0.92,', TEXT),
        ('  "fuel_consumed": 16397,', TEXT),
        ('  "security_baseline": { "preopens": ["/sandbox"], ... }', CYAN),
        ("}", MUTED),
    ]),
    ("ephemora-cell run exploit.wasm", [
        ("Blocked WASI import: wasi_snapshot_preview1::fd_psync", RED),
        ("  fsync/sync operations are not allowed in sandbox", RED),
        ("", TEXT),
        ("8/8 attack vectors blocked — verify it yourself:", MUTED),
        ("  python benchmarks/verify_8_vectors.py", MUTED),
    ]),
]

PAUSE_CMD = 8
PAUSE_OUT = 5
TYPE_SPEED = 2  # chars per frame


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

    y = MARGIN + 64
    for cmd, outs in history:
        d.text((MARGIN + 20, y), "➜ ~ " + cmd, font=FONT, fill=PROMPT); y += LH
        for t, c in outs:
            d.text((MARGIN + 34, y), t, font=FONT, fill=c); y += LH
        y += 8
    if current_cmd is not None:
        d.text((MARGIN + 20, y), "➜ ~ " + current_cmd[:typed] + ("▌" if (typed // TYPE_SPEED) % 2 else ""), font=FONT, fill=PROMPT)
        y += LH
        for t, c in out_lines[:out_reveal]:
            d.text((MARGIN + 34, y), t, font=FONT, fill=c); y += LH
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
    frames += [frame(history, None, 0, [], 0)] * 22  # hold final state
    return frames


if __name__ == "__main__":
    frames = build_frames()
    with tempfile.TemporaryDirectory() as td:
        for i, f in enumerate(frames):
            f.save(f"{td}/{i:04d}.png")
        subprocess.run(
            ["ffmpeg", "-y", "-loglevel", "error", "-framerate", "20",
             "-i", f"{td}/%04d.png", "-vf",
             "split[a][b];[a]palettegen=max_colors=64[p];[b][p]paletteuse=dither=bayer:bayer_scale=4",
             str(OUT)],
            check=True,
        )
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB, {len(frames)} frames)")
