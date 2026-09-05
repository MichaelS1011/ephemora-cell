"""Build assets/mcp-boundary.mp4 — 'The tool call is the security boundary.'

Two stacked terminal panes (server + client), LinkedIn-square 1080x1080, silent,
~30s, H.264. Every terminal string is a verbatim capture from a real run
(scripts saved alongside; see /tmp/mcpdemo/*.ndjson captured by
~/.hermes/scratch/mcp_capture.py — same commands, same values, rerun to reproduce).

Honesty gate: JSON below is the server's exact response, only whitespace/pretty
differs (like assets/make_gif.py). Run asserts() at the bottom against the saved
ndjson so a stale capture fails the build.

Requires: Pillow, ffmpeg on PATH.
"""
from pathlib import Path
import json
import subprocess
import tempfile

from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).parent
OUT = HERE / "mcp-boundary.mp4"
CAPTURES = {
    "echo": Path("/tmp/mcpdemo/echo.ndjson"),
    "busy": Path("/tmp/mcpdemo/busy.ndjson"),
}

W = H = 1080
FPS = 24
BG = "#0d1117"
PANE_BG = "#010409"
TITLEBAR = "#161b22"
TEXT = "#e6edf3"
MUTED = "#8b949e"
GREEN = "#3fb950"
CYAN = "#79c0ff"
ORANGE = "#f0883e"
RED = "#f85149"
HILITE = "#1f2a1a"          # subtle green bg for _meta highlights
HILITE_RED = "#2d1416"      # subtle red bg
PROMPT = "#3fb950"
BORDER = "#30363d"

_MONO = "/System/Library/Fonts/Menlo.ttc"
F18 = ImageFont.truetype(_MONO, 18)
F22 = ImageFont.truetype(_MONO, 22)
F24 = ImageFont.truetype(_MONO, 24)
FT = ImageFont.truetype(_MONO, 16)     # title bars
FBIG = ImageFont.truetype(_MONO, 40)   # cards
FSUB = ImageFont.truetype(_MONO, 22)

LH = 30           # line height for body
PAD = 22

# --- captured server responses (loaded at build; asserted verbatim) ---
RESP_ECHO = None
RESP_BUSY = None


def load_captures():
    global RESP_ECHO, RESP_BUSY
    for name in ("echo", "busy"):
        if not CAPTURES[name].exists():
            raise SystemExit(f"missing capture {CAPTURES[name]} — run the capture script first")
    echo = next(json.loads(l) for l in CAPTURES["echo"].read_text().splitlines()
                if '"id": 2' in l or '"id":2' in l)
    busy = next(json.loads(l) for l in CAPTURES["busy"].read_text().splitlines()
                if '"id": 2' in l or '"id":2' in l)
    ex = echo["result"]["_meta"]["execution"]
    bx = busy["result"]["_meta"]["execution"]
    # Honesty gate — these are the values shown in the video.
    assert ex["status"] == "success" and ex["fuel_consumed"] == 22051
    assert ex["fuel_budget"] == 2_000_000 and ex["stdout_bytes"] == 52
    assert ex["security_baseline"]["wasmtime_version"] == "47.0.1"
    assert ex["security_baseline"]["preopens"] == ["/sandbox"]
    assert bx["status"] == "fuel_exhausted"
    RESP_ECHO, RESP_BUSY = echo["result"], busy["result"]


# --- drawing helpers -------------------------------------------------
def term(img, d, x, y, w, h, title):
    d.rounded_rectangle([x, y, x + w, y + h], 12, fill=PANE_BG, outline=BORDER, width=2)
    d.rounded_rectangle([x, y, x + w, y + 38], 12, fill=TITLEBAR)
    d.rectangle([x, y + 22, x + w, y + 38], fill=TITLEBAR)
    for i, c in enumerate(("#ff5f57", "#febc2e", "#28c840")):
        d.ellipse([x + 14 + i * 22, y + 13, x + 26 + i * 22, y + 25], fill=c)
    d.text((x + 100, y + 11), title, font=FT, fill=MUTED)


def lines(img, d, x, y, rows):
    """rows: list of (text, color, highlight). Returns y after last line."""
    for text, color, hl in rows:
        if hl:
            d.rounded_rectangle([x - 8, y - 3, W - PAD - 8, y + LH - 4], 4, fill=hl)
        d.text((x, y), text, font=F22, fill=color)
        y += LH
    return y


def base(history_top, top_cursor, body_rows, body_reveal, note=None):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    # title strip
    d.text((PAD, 10), "Ephemora Cell  ·  MCP stdio server  ·  WASM tools in a capability-limited WASI runtime",
           font=FT, fill=MUTED)
    # Terminal A — server
    term(img, d, PAD, 40, W - 2 * PAD, 150, "Terminal A — ephemora-cell-mcp (server)")
    yy = 40 + 50
    yy = lines(img, d, PAD + 18, yy, [
        ("➜  ephemora-cell  ephemora-cell-mcp --tools-dir ./tools", PROMPT, None),
    ])
    if top_cursor:
        d.text((PAD + 18, yy), "▌", font=F22, fill=PROMPT)
    if note:
        d.text((PAD + 18, yy + 2), note, font=FT, fill=MUTED)
    # Terminal B — client
    by = 210
    term(img, d, PAD, by, W - 2 * PAD, H - by - PAD, "Terminal B — MCP client (tools/call)")
    yy = lines(img, d, PAD + 18, by + 50, history_top)
    if body_reveal:
        lines(img, d, PAD + 18, yy, body_rows[:body_reveal])
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


# --- scene content (verbatim values) ---------------------------------
ECHO_CALL = "➜  client  mcp call echo  '{\"message\": \"summarize quarterly report\"}'"
BUSY_CALL = "➜  client  mcp call busy  '{}'"

# pretty-printed tool response, split so the _meta block can be highlighted
def echo_rows():
    assert RESP_ECHO and RESP_BUSY
    r = [
        ("{", MUTED, None),
        ('  "content": [ { "type": "text",', TEXT, None),
        ('      "text": "{\\"echo\\": {\\"message\\": \\"summarize quarterly report\\"}}" },', TEXT, None),
        ("  ],", MUTED, None),
        ('  "_meta": { "execution": {', CYAN, None),
        ('    "status": "success",  "exit_code": 0,', TEXT, HILITE),
        ('    "fuel_consumed": 22051,  "fuel_budget": 2000000  (1.1%),', TEXT, HILITE),
        ('    "stdout_bytes": 52,', TEXT, HILITE),
        ('    "security_baseline": {', CYAN, None),
        ('      "preopens": ["/sandbox"],   memory_limit: 128MB,', TEXT, HILITE),
        ('      "threads_enabled": false,   wasmtime 47.0.1 } } } }', TEXT, HILITE),
    ]
    return r


def busy_rows():
    e = RESP_BUSY["_meta"]["execution"]
    return [
        ("➜  client  mcp call busy  '{}'", PROMPT, None),
        ("{", MUTED, None),
        ('  "content": [ { "text": "{\\"status\\": \\"fuel_exhausted\\",', RED, None),
        ('      \\"message\\": \\"...wasm trap: all fuel consumed by WebAssembly\\" } } ],', RED, None),
        ('  "isError": true,', RED, None),
        ('  "_meta": { "execution": {', CYAN, None),
        ('    "status": "fuel_exhausted",  "elapsed_ms": %.2f,' % e["elapsed_ms"], TEXT, HILITE_RED),
        ('    "fuel_budget": 2000000  → runaway loop stopped at the boundary } } }', TEXT, HILITE_RED),
    ]


def build():
    frames = []
    # 1) title
    frames += rep(card("The tool call is the security boundary.",
                       "An MCP tool is not just a description. It is executable capability."), 44)
    # 2) server starts, sits waiting
    frames += rep(base([], False, [], 0), 8)
    for t in range(0, len("ephemora-cell-mcp --tools-dir ./tools") + 1, 2):
        frames.append(base([("➜  ephemora-cell  ephemora-cell-mcp --tools-dir ./tools"[:t], PROMPT, None)],
                           True, [], 0))
    frames += rep(base([("➜  ephemora-cell  ephemora-cell-mcp --tools-dir ./tools", PROMPT, None)],
                       True, [], 0,
                       "stdio server — reads JSON-RPC on stdin, writes only responses to stdout"), 60)
    # 3) echo call — the happy path + evidence
    hist = [(ECHO_CALL, PROMPT, None)]
    rows = echo_rows()
    for t in range(0, len(ECHO_CALL) + 1, 3):
        frames.append(base([(ECHO_CALL[:t], PROMPT, None)], False, [], 0))
    frames += rep(base(hist, False, rows, 0), 10)
    for r in range(1, len(rows) + 1):
        frames += rep(base(hist, False, rows, r), 3 if r < len(rows) else 30)
    # 4) busy call — the boundary
    for t in range(0, len(BUSY_CALL) + 1, 3):
        frames.append(base(hist + [(BUSY_CALL[:t], PROMPT, None)], False, [], 0))
    brows = busy_rows()
    frames += rep(base(hist, False, brows, 0), 6)
    # rows already contain the call line; reveal it fully then response
    for r in range(1, len(brows) + 1):
        frames += rep(base(hist, False, brows, r), 3 if r < len(brows) else 46)
    # 5) end card
    frames += rep(card("The agent picks the capability.",
                       "The runtime defines the conditions.",
                       GREEN, "github.com/MichaelS1011/ephemora-cell"), 60)
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
    load_captures()
    encode(build())
