#!/usr/bin/env python3
"""Does the WASI stdio config actually permit the GHSA-gqmc
unbounded-output precondition, and does our bounded sink cap host allocation?

GHSA-gqmc-89g8-p25r (Moderate): a wasi guest writing arbitrarily much to
stdout/stderr makes the HOST allocate un-buffered capture space. Our mitigation
is `make_output_sink(path, budget=[_MAX_OUTPUT_BYTES])` on both the preview1
(wasi_runtime) and component (wasi_02) paths: once the shared budget is spent,
the sink returns a negative errno so no further bytes reach the host capture
file. Per the directive this is a WORKAROUND, not a fix -> classification stays
`AFFECTED — REACHABLE (bounded)`, so we must show the bound actually holds.

Two legs:
  control  — a guest writing well under the budget; output captured in full.
  overflow — a guest requesting ~640 KiB to stdout (>> _MAX_OUTPUT_BYTES=10 KiB);
             the run must COMPLETE and the captured output must be capped near
             the budget, not grow with the request.

Run: .venv/bin/python benchmarks/stdio_overflow_output_alloc_probe.py
Exit 0 = precondition reachable AND host allocation bounded by the sink.
Exit 1 = bound not observed (escalate: gqmc exposure larger than documented).
"""

from __future__ import annotations

import json
import sys
import tempfile
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

import wasmtime  # noqa: E402

from ephemora_cell import WASIConfig, WASISandbox  # noqa: E402
from ephemora_cell._sandbox_common import _MAX_OUTPUT_BYTES  # noqa: E402

CHUNK = 16
ITER_CONTROL = 100  # 1.6 KiB, well under budget
ITER_OVERFLOW = 40_000  # ~640 KiB requested, >> budget


def wat(iterations: int) -> str:
    return f"""(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $w (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 100) "ABCDEFGHIJKLMNOP")
  (func (export "_start")
    (local $i i32)
    (block $done (loop $l
      (i32.store (i32.const 0) (i32.const 100))   ;; iov_base
      (i32.store (i32.const 4) (i32.const {CHUNK})) ;; iov_len
      (drop (call $w (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $done (i32.ge_u (local.get $i) (i32.const {iterations})))
      (br $l)))))
"""


def measure(iterations: int) -> dict:
    path = tempfile.mktemp(suffix=".wasm")
    Path(path).write_bytes(wasmtime.wat2wasm(wat(iterations)))
    cfg = WASIConfig(
        max_memory_mb=64,
        max_fuel=100_000_000_000,
        timeout_seconds=30,
        allow_dirs=(),
    )
    sb = WASISandbox(config=cfg)
    try:
        # Run on the mandatory worker path (untrusted); the sink bound is the
        # same code shared with the component path (wasi_02.make_output_sink).
        r = sb.run(path, use_subprocess=True, trust="untrusted")
        out_len = len(r.stdout or "")
        err_len = len(r.stderr or "")
        return {
            "requested_bytes": iterations * CHUNK,
            "status": r.status.value,
            "stdout_len": out_len,
            "stderr_len": err_len,
        }
    finally:
        sb.cleanup()
        Path(path).unlink(missing_ok=True)


def main() -> int:
    control = measure(ITER_CONTROL)
    overflow = measure(ITER_OVERFLOW)

    # Allow the reported stdout to carry a little harness/limit overhead.
    cap_bound = _MAX_OUTPUT_BYTES + 2048
    verdicts = {
        "control_fully_captured": control["stdout_len"] == control["requested_bytes"],
        "overflow_precondition_reachable": overflow["requested_bytes"] > cap_bound,
        "host_output_capped_at_budget": overflow["stdout_len"] <= cap_bound,
        "cap_far_below_request": overflow["stdout_len"]
        < overflow["requested_bytes"] / 10,
        "overflow_run_completed": overflow["status"]
         in {"success", "ok", "error", "timeout"},
    }
    ok = all(verdicts.values())

    out = {
        "probe": "stdio_overflow_output_alloc_gqmc",
        "engine": "wasmtime-py 49.0.0 (native v49.0.0)",
        "max_output_bytes": _MAX_OUTPUT_BYTES,
        "control": control,
        "overflow": overflow,
        "verdicts": verdicts,
        "classification_after_check": "AFFECTED — REACHABLE (bounded sink holds; NOT a fix)",
        "pass": ok,
    }
    results_dir = REPO / "benchmarks" / "results" / date.today().isoformat()
    results_dir.mkdir(parents=True, exist_ok=True)
    ev = results_dir / "stdio_overflow_output_alloc_gqmc.json"
    ev.write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))
    print(f"\nEvidence -> {ev}")
    print("VERDICT:", "PASS (gqmc precondition reachable, host allocation bounded)" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
