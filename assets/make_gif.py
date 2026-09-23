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

from terminal_gif import CYAN, GREEN, MUTED, RED, TEXT, build_frames, render_gif

HERE = Path(__file__).parent
OUT = HERE / "demo.gif"

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

TYPE_SPEED = 6  # chars per frame — long commands per-keystroke frames dominate GIF size

if __name__ == "__main__":
    render_gif(build_frames(SCENES, TYPE_SPEED), OUT)
