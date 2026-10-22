"""Generate assets/demo.gif — one execution, start to finish, on the 1.2.0
release candidate (1.2.0rc2, wasmtime 49.0.3.post2+git.1d21c90f).

Every string in these frames is a verbatim capture from real runs on
2026-10-16: a fresh venv with the candidate installed from the release
wheelhouse, plus the v1.2.0 release source tree, so each scene's own command
reproduces its output. The arc is what the product boundary is today: install
-> fresh execution -> the explicit capability/resource boundary and the
runtime identity the run got -> a hostile module stopped by that boundary ->
capability and access denials measured live -> signed evidence that detects
tampering -> execution ends.

Deliberately absent:
* elapsed_ms / throughput — platform-dependent; a demo that shows them ages
  into a false claim. The fuel numbers (100 of 100) are exact everywhere
  because the budget is enforced, not measured.
* any claim the candidate does not actually show. The JSON scene prints the
  1.2.0 receipt fields (`wasmtime_version`, `execution_mode`,
  `sync_blockade_enforced`) exactly as the run emitted them.

The install scene shows the candidate's honest install path: the release
wheelhouse, not PyPI — PyPI still serves 1.1.0 until the candidate ships. The
README caption under the GIF names the recorded revision.

Every elision inside a frame is marked with "..." so an abridged scene never
reads as a complete transcript; a scene without "..." shows its output whole.

Requires: Pillow (.venv), ffmpeg on PATH.
"""

from pathlib import Path

from PIL import Image, ImageDraw
from terminal_gif import (
    BG,
    BORDER,
    CYAN,
    FONT,
    GREEN,
    MARGIN,
    MUTED,
    RED,
    TEXT,
    TITLEBAR,
    H,
    W,
    build_frames,
    render_gif,
)

HERE = Path(__file__).parent
OUT = HERE / "demo.gif"

# (command, [(text, color), ...]) — outputs are verbatim real-run captures
# from 2026-10-16 on the 1.2.0rc2 candidate. Scene 1 installs from the release
# wheelhouse; from scene 2 on, the terminal is a clone of the repo with the
# venv active.
SCENES = [
    # install — the candidate's honest install path: the release wheelhouse,
    # not PyPI (still 1.1.0 until the candidate ships).
    (
        "pip install --no-index --find-links wheelhouse ephemora-cell",
        [
            ("...", MUTED),
            (
                "Successfully installed ephemora-cell-1.2.0rc2 wasmtime-49.0.3.post2+git.1d21c90f",
                GREEN,
            ),
        ],
    ),
    # 1 — fresh execution: nothing of yours is reused, nothing of it is kept.
    (
        "ephemora-cell run examples/hello.wasm --isolated",
        [
            ("Hello from Ephemora Cell!", TEXT),
        ],
    ),
    # 2 — the same run names the boundary it ran under — and the runtime
    # identity: the patched 49.0.3 engine and the 1.2.0 execution fields.
    # Real keys, real values, real order; the "..." is where the report
    # continues past what fits here.
    (
        "ephemora-cell run examples/hello.wasm --isolated --json",
        [
            ("{", MUTED),
            ('  "status": "success",', TEXT),
            ('  "fuel_consumed": 16397,', TEXT),
            ('  "fuel_budget": 1000000,', TEXT),
            ('  "security_baseline": {', CYAN),
            ('    "wasmtime_version": "49.0.3.post2+git.1d21c90f",', CYAN),
            ('    "execution_mode": "subprocess",', CYAN),
            ('    "sync_blockade_enforced": true', CYAN),
            ("    ...", MUTED),
        ],
    ),
    # 3 — a runaway module, stopped by the budget it was given. The "..." is the
    # report's own timing fields, which this demo does not show on purpose.
    (
        "ephemora-cell run examples/fuel_bomb.wasm --fuel 100 --json",
        [
            ("{", MUTED),
            ('  "status": "fuel_exhausted",', RED),
            ("  ...", MUTED),
            ('  "fuel_consumed": 100,', GREEN),
            ('  "fuel_budget": 100,', GREEN),
            ('  "fuel_utilization": 1.0,', GREEN),
        ],
    ),
    # 4 — capability and access denials, measured against the live runtime.
    (
        "python benchmarks/verify_8_vectors.py",
        [
            ("[3/8] Network / socket", TEXT),
            ("  Result: BLOCKED — no socket API in WASI Preview1 surface", RED),
            ("...", MUTED),
            ("[5/8] Host FS (/etc/passwd)", TEXT),
            ("  Result: BLOCKED (status=error, errno=63)", RED),
            ("[6/8] Symlink escape", TEXT),
            ("  Positive control (real file): OPENED (good)", GREEN),
            ("  Symlink attack: BLOCKED (errno=32)", RED),
            ("...", MUTED),
            ("Summary: 8/8 attack vectors blocked", GREEN),
        ],
    ),
    # 5 — evidence: the receipt is signed, and one rewritten field breaks it.
    (
        "pip install 'ephemora-cell[tools-signing]'",
        [
            ("...", MUTED),
            (
                "Successfully installed cffi-2.1.1 cryptography-50.0.2 pycparser-3.11",
                TEXT,
            ),
        ],
    ),
    (
        "python examples/signed_record_demo.py",
        [
            ("record: success | fuel: 1", TEXT),
            ("verify(intact): True", GREEN),
            ("verify(tampered): False", RED),
            ("...", MUTED),
            ("dsse(intact): True", GREEN),
            ("...", MUTED),
            ("break after edit: entry 2: prev_hash does not seal entry 1", RED),
        ],
    ),
]

CARD = [
    "The evidence persists.",
    "The execution state does not.",
]

TYPE_SPEED = 6  # chars per frame — long commands per-keystroke frames dominate GIF size


def card_frame():
    """Closing card in the same window chrome, no prompt line."""
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rounded_rectangle(
        [MARGIN, MARGIN, W - MARGIN, H - MARGIN], 12, fill=BG, outline=BORDER, width=2
    )
    d.rounded_rectangle([MARGIN, MARGIN, W - MARGIN, MARGIN + 44], 12, fill=TITLEBAR)
    d.rectangle([MARGIN, MARGIN + 26, W - MARGIN, MARGIN + 44], fill=TITLEBAR)
    for i, c in enumerate(("#ff5f57", "#febc2e", "#28c840")):
        d.ellipse(
            [MARGIN + 18 + i * 26, MARGIN + 16, MARGIN + 34 + i * 26, MARGIN + 32],
            fill=c,
        )
    y = H // 2 - 2 * 34
    for i, line in enumerate(CARD):
        box = d.textbbox((0, 0), line, font=FONT)
        d.text(
            ((W - (box[2] - box[0])) / 2, y + i * 68),
            line,
            font=FONT,
            fill=CYAN if i == 0 else TEXT,
        )
    return img


if __name__ == "__main__":
    frames = build_frames(SCENES, TYPE_SPEED)
    frames += [card_frame()] * 90  # 5.6 s at 16 fps — the card has to be readable
    render_gif(frames, OUT)
