"""Shared terminal-GIF machinery for the assets/*.gif generators.

macOS-style terminal window, GitHub-dark palette, soft-scrolling transcript,
ffmpeg palette render. Deterministic: same scenes + same inputs produce
byte-identical frames. Importers define only their SCENES and OUT.
"""
import subprocess
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

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
TITLE_FONT = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", TITLE_SIZE)
LH = FONT_SIZE + 12

PAUSE_CMD = 8
PAUSE_OUT = 5


def frame(history, current_cmd, typed, out_lines, out_reveal, type_speed):
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
    # (a multi-scene history overflows the frame — a real terminal scrolls too).
    lines = []
    for cmd, outs in history:
        lines.append(("prompt", cmd))
        lines += [("out", t, c) for t, c in outs]
        lines.append(("gap", ""))
    if current_cmd is not None:
        cursor = "▌" if (typed // type_speed) % 2 else ""
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


def build_frames(scenes, type_speed, window=1):
    frames = []
    history = []
    for cmd, outs in scenes:
        for t in range(0, len(cmd) + 1, type_speed):
            frames.append(frame(history, cmd, t, [], 0, type_speed))
        frames += [frame(history, cmd, len(cmd), [], 0, type_speed)] * PAUSE_CMD
        for r in range(1, len(outs) + 1):
            frames += [frame(history, cmd, len(cmd), outs, r, type_speed)] * (PAUSE_OUT if r == len(outs) else 2)
        frames += [frame(history, cmd, len(cmd), outs, len(outs), type_speed)] * 14
        history.append((cmd, outs))
        history = history[-window:]  # one-scene window: worst case (prev + current) always fits the frame, so reveal frames never shift the whole screen
    frames += [frame(history, None, 0, [], 0, type_speed)] * 22  # hold final state
    return frames


def render_gif(frames, out):
    with tempfile.TemporaryDirectory() as td:
        for i, f in enumerate(frames):
            f.save(f"{td}/{i:04d}.png")
        subprocess.run(
            ["ffmpeg", "-y", "-loglevel", "error", "-framerate", "16",
             "-i", f"{td}/%04d.png", "-vf",
             "split[a][b];[a]palettegen=max_colors=64:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=5:new=1",
             str(out)],
            check=True,
        )
    print(f"wrote {out} ({Path(out).stat().st_size // 1024} KB, {len(frames)} frames)")
