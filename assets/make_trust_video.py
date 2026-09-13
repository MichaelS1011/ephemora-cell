"""Build assets/trust-chain.mp4 — "Verifying. Not claimed." social cut.

LinkedIn-square 1080x1080, silent, ~15 s, H.264. The terminal scenes are
imported verbatim from make_trust_chain.py (same builder — one source,
two formats), scaled to full width and narrated with a per-scene caption
(silent autoplay needs the story ON the frames). Deterministic; requires
Pillow and ffmpeg on PATH.
"""
from pathlib import Path
import importlib.util
import subprocess
import tempfile

from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).parent
OUT = HERE / "trust-chain.mp4"

_spec = importlib.util.spec_from_file_location(
    "make_trust_chain", HERE / "make_trust_chain.py"
)
mtc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mtc)

W = H = 1080
FPS = 24
BG = "#0d1117"
TEXT = "#e6edf3"
MUTED = "#8b949e"
GREEN = "#3fb950"
ORANGE = "#f0883e"

_MONO = "/System/Library/Fonts/Menlo.ttc"
FT = ImageFont.truetype(_MONO, 18)
FBIG = ImageFont.truetype(_MONO, 44)
FSUB = ImageFont.truetype(_MONO, 22)
FCAP = ImageFont.truetype(_MONO, 26)

SCENE_CAPTIONS = [
    "every run attests its own posture",
    "budgets are enforced — exactly",
    "records are tamper-evident",
    "the agent proposes; the host disposes",
]

FOOTER = "github.com/MichaelS1011/ephemora-cell  ·  pip install ephemora-cell"


def canvas(term_img: Image.Image, caption: str, footer: str) -> Image.Image:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.text(
        (30, 16),
        "Ephemora Cell · a verifiable trust chain around the sandbox",
        font=FT,
        fill=MUTED,
    )
    scaled = term_img.resize((W, round(term_img.height * W / term_img.width)))
    img.paste(scaled, (0, 54))
    cw = d.textlength(caption, font=FCAP)
    d.text(((W - cw) / 2, 54 + scaled.height + 44), caption, font=FCAP, fill=TEXT)
    fw = d.textlength(footer, font=FSUB)
    d.text(((W - fw) / 2, H - 42), footer, font=FSUB, fill=MUTED)
    return img


def card(title, sub, accent=ORANGE, sub2=None):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    tw = d.textlength(title, font=FBIG)
    d.text(((W - tw) / 2, H / 2 - 70), title, font=FBIG, fill=accent)
    sw = d.textlength(sub, font=FSUB)
    d.text(((W - sw) / 2, H / 2 + 5), sub, font=FSUB, fill=TEXT)
    if sub2:
        w2 = d.textlength(sub2, font=FSUB)
        d.text(((W - w2) / 2, H / 2 + 45), sub2, font=FSUB, fill=MUTED)
    return img


def rep(s, n):
    return [s] * n


def scene_frames():
    """The GIF builder's loop, but frames carry their scene index."""
    frames = []
    history = []
    for idx, (cmd, outs) in enumerate(mtc.SCENES):
        for t in range(0, len(cmd) + 1, mtc.TYPE_SPEED):
            frames.append((mtc.frame(history, cmd, t, [], 0), idx))
        frames += [(mtc.frame(history, cmd, len(cmd), [], 0), idx)] * mtc.PAUSE_CMD
        for r in range(1, len(outs) + 1):
            frames += [
                (mtc.frame(history, cmd, len(cmd), outs, r), idx)
            ] * (mtc.PAUSE_OUT if r == len(outs) else 2)
        frames += [(mtc.frame(history, cmd, len(cmd), outs, len(outs)), idx)] * 14
        history.append((cmd, outs))
        history = history[-1:]
    return frames


def build():
    frames = []
    frames += rep(
        card(
            "Verifying. Not claimed.",
            "signed manifests · governed loading · signed execution records",
        ),
        44,
    )
    frames += [
        canvas(f, SCENE_CAPTIONS[i], FOOTER) for f, i in scene_frames()
    ]
    frames += rep(
        card(
            "Verified. Not claimed.",
            "Apache-2.0 · 415 tests · 8/8 attack vectors blocked (live-verified)",
            GREEN,
            "github.com/MichaelS1011/ephemora-cell",
        ),
        60,
    )
    return frames


def encode(frames):
    size = len(frames)
    with tempfile.TemporaryDirectory() as td:
        for i, f in enumerate(frames):
            f.save(f"{td}/{i:04d}.png")
        subprocess.run(
            ["ffmpeg", "-y", "-loglevel", "error", "-framerate", str(FPS),
             "-i", f"{td}/%04d.png", "-vf", "format=yuv420p",
             "-c:v", "libx264", "-preset", "slow", "-crf", "20",
             "-movflags", "+faststart", str(OUT)],
            check=True)
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB, {size} frames = {size / FPS:.1f}s)")


if __name__ == "__main__":
    encode(build())
