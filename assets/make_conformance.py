"""Generate assets/conformance.gif — "Verifying. Not claimed." (~16 s).

Four scenes, every string grounded in the real 2026-09-14 conformance work:

  1. CI trigger       -> wasi-conformance.yml runs the shared WASI Preview 1
                         suite against the execution boundary.
  2. suite result     -> 72 pass / 0 fail (sock_shutdown-invalid_fd is a
                         declared by-design xfail; preview 3 not declared ->
                         55 skip).
  3. the real finding -> the run did not just pass, it found two CLI bugs the
                         existing test suite had never caught (regression
                         pinned in tests/test_cli_inprocess.py).
  4. continuous guard -> benchmark_guard.py in ci.yml fails CI if a benchmark
                         assumption drifts -> reproducible, independently
                         testable, continuously verified.

Reuses the shared frame/palette machinery (terminal_gif.py, imported — not
duplicated); type_speed 6 keeps the cursor cadence make_conformance always
inherited from make_gif. Deterministic. Requires: Pillow (.venv), ffmpeg on PATH.
"""
import subprocess
import tempfile
from pathlib import Path

from terminal_gif import CYAN, GREEN, MUTED, PROMPT, RED, frame

HERE = Path(__file__).parent
OUT = HERE / "conformance.gif"

# Terminal content is grounded in the real artifacts:
#   .github/workflows/wasi-conformance.yml -> conformance/run_wasi_testsuite.py
#   conformance/results/summary-609c44613995-*.json (72/1/0 totals)
#   tests/test_cli_inprocess.py (regressions from the wasi-suite conformance
#   run 2026-09-14) -- the two CLI bugs
#   .github/workflows/ci.yml:70 -> benchmarks/benchmark_guard.py
SCENES = [
    ("git push origin main  # CI: wasi-conformance.yml", [
        ("conformance/run_wasi_testsuite.py  # shared WASI Preview 1 suite", CYAN),
        ("against the live execution boundary ...", MUTED),
    ]),
    ("wasi-testsuite — conformance summary", [
        ("  PASS   72   FAIL   0   (unexpected: 0)", GREEN),
        ("  xfail   1   sock_shutdown  [by-design, declared]", MUTED),
        ("  skip   55   preview3     [not declared]", MUTED),
        ("  => execution boundary conforms. not claimed.", GREEN),
    ]),
    ("# the run that earned the claim — it did NOT just pass:", [
        ("  it FOUND something. first run, 2 CLI bugs:", RED),
        ("  [1] repeated --allow-env/--allow-dirs flags overwrote each other", RED),
        ("  [2] allow_dirs had no host::guest preopen naming", RED),
        ("  fixed. regressions @ tests/test_cli_inprocess.py", GREEN),
    ]),
    ("python benchmarks/benchmark_guard.py  # ci.yml", [
        ("  fuel-budget + bench assumptions re-checked vs HEAD", CYAN),
        ("  0 drift  <- pinned, continuously verified", GREEN),
        ("  reproducible -> independently testable -> CI", GREEN),
        ("  Verifying. Not claimed.", PROMPT),
    ]),
]

PAUSE_CMD = 6
PAUSE_OUT = 3
HOLD_END = 28


def build_frames():
    frames = []
    history = []
    for cmd, outs in SCENES:
        for t in range(0, len(cmd) + 1, 2):
            frames.append(frame(history, cmd, t, [], 0, type_speed=6))
        frames += [frame(history, cmd, len(cmd), [], 0, type_speed=6)] * PAUSE_CMD
        for r in range(1, len(outs) + 1):
            hold = PAUSE_OUT * 3 if r == len(outs) else PAUSE_OUT
            frames += [frame(history, cmd, len(cmd), outs, r, type_speed=6)] * hold
        frames += [frame(history, cmd, len(cmd), outs, len(outs), type_speed=6)] * 10
        history.append((cmd, outs))
        history = history[-2:]  # window so long scenes still fit after scroll
    frames += [frame(history, None, 0, [], 0, type_speed=6)] * HOLD_END
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
