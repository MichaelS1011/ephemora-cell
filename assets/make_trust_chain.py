"""Generate assets/trust-chain.gif — "Verifying. Not claimed." in ~15 s.

Four scenes, every string a verbatim capture from real runs (2026-09-12):

  1. run --isolated --json          -> the attested security baseline
  2. run fuel_bomb.wasm --fuel 100  -> stopped, 100/100 units accounted
     (exact on every platform: budgets are enforced, not measured)
  3. examples/signed_record_demo.py -> signed record; one rewritten field
     breaks verification
  4. signed-tools mode              -> a tampered manifest is rejected
     fail-closed before the tool ever registers (ADR-006)

Reuse of the frame/palette machinery from make_gif.py; deterministic.
Requires: Pillow (.venv), ffmpeg on PATH.
"""
from pathlib import Path
import subprocess
import tempfile

from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).parent
OUT = HERE / "trust-chain.gif"

W, H = 960, 620
MARGIN = 14
FONT_SIZE = 22
TITLE_SIZE = 15

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
TITLE_FONT = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", TITLE_SIZE)
LH = FONT_SIZE + 12

SCENES = [
    ("ephemora-cell run tool.wasm --isolated --json", [
        ("{", MUTED),
        ('  "status": "success",  "exit_code": 0,', TEXT),
        ('  "fuel_consumed": 16397,  "fuel_budget": 1000000,', TEXT),
        ('  "security_baseline": {', CYAN),
        ('    "wasmtime_version": "47.0.1",', CYAN),
        ('    "memory_limit_bytes": 134217728,', CYAN),
        ('    "preopens": ["/sandbox"], "threads_enabled": false', CYAN),
        ("  }", CYAN),
        ("}", MUTED),
    ]),
    ("ephemora-cell run fuel_bomb.wasm --isolated --fuel 100 --json", [
        ("{", MUTED),
        ('  "status": "fuel_exhausted",', RED),
        ('  "fuel_consumed": 100,', GREEN),
        ('  "fuel_budget": 100,  "fuel_utilization": 1.0', GREEN),
        ("}", MUTED),
    ]),
    ("python examples/signed_record_demo.py", [
        ("record: success | fuel: 1", TEXT),
        ("verify(intact): True", GREEN),
        ("# ... one field rewritten ...", MUTED),
        ("verify(tampered): False", RED),
    ]),
    ("ephemora-cell-mcp --require-signed-tools pub.pem", [
        ("tool 'widget': sidecar failed manifest signature verification", RED),
        ("  (unsigned, tampered or malformed) - rejected", RED),
        ("  in signed-tools mode", RED),
        ("", TEXT),
        ("the agent proposes; the host disposes", MUTED),
    ]),
]

PAUSE_CMD = 8
PAUSE_OUT = 5
TYPE_SPEED = 2


def frame(history, current_cmd, typed, out_lines, out_reveal):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
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
