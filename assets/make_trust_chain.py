"""Generate assets/trust-chain.gif — "Verifying. Not claimed." in ~15 s.

Four scenes, every string a verbatim capture from real runs (2026-09-12):

  1. run --isolated --json          -> the attested security baseline
  2. run fuel_bomb.wasm --fuel 100  -> stopped, 100/100 units accounted
     (exact on every platform: budgets are enforced, not measured)
  3. examples/signed_record_demo.py -> signed record; one rewritten field
     breaks verification
  4. signed-tools mode              -> a tampered manifest is rejected
     fail-closed before the tool ever registers (ADR-006)

Uses the shared frame/palette machinery (terminal_gif.py); deterministic.
Requires: Pillow (.venv), ffmpeg on PATH.
"""
from pathlib import Path

from terminal_gif import CYAN, GREEN, MUTED, RED, TEXT, build_frames, render_gif

HERE = Path(__file__).parent
OUT = HERE / "trust-chain.gif"

SCENES = [
    ("ephemora-cell run tool.wasm --isolated --json", [
        ("{", MUTED),
        ('  "status": "success",  "exit_code": 0,', TEXT),
        ('  "fuel_consumed": 16397,  "fuel_budget": 1000000,', TEXT),
        ('  "security_baseline": { "wasmtime_version": "47.0.1",', CYAN),
        ('    "preopens": ["/sandbox"], "threads_enabled": false },', CYAN),
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

TYPE_SPEED = 2

if __name__ == "__main__":
    render_gif(build_frames(SCENES, TYPE_SPEED), OUT)
