"""Auto-grading untrusted submissions with Ephemora Cell.

Runnable companion to the docs/recipes.md section "Auto-grading
untrusted submissions". The point: infinite loops, memory hogs and
crashing submissions become a *grade*, never a host crash — the Cell
maps every failure mode to a status, and fuel_consumed doubles as a
cost meter.

Run: .venv/bin/python examples/auto_grader.py
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import wasmtime

from ephemora_cell import ExecutionResult, ExecutionStatus, WASIConfig, WASISandbox

# The budget a grader would hand every submission: same rules for all,
# set by the institution — never by the student.
GRADER_BUDGET = WASIConfig(max_fuel=1_000_000, max_memory_mb=128, timeout_seconds=5)


def grade_submission(
    wasm_path: str,
    *,
    config: WASIConfig = GRADER_BUDGET,
    expect_stdout: str | None = None,
) -> dict:
    """Run one submission under the budget and fold it into a grade."""
    sandbox = WASISandbox(config=config)
    try:
        result = sandbox.run(wasm_path)
    finally:
        sandbox.cleanup()
    verdict, reason = _verdict(result, expect_stdout)
    return {
        "verdict": verdict,
        "reason": reason,
        "status": result.status.value,
        "exit_code": result.exit_code,
        # cost meter: deterministic work the submission caused
        "fuel_consumed": result.fuel_consumed,
        "elapsed_ms": round(result.elapsed_ms, 2),
    }


def _verdict(result: ExecutionResult, expect_stdout: str | None) -> tuple[str, str]:
    if result.status is ExecutionStatus.SUCCESS:
        if expect_stdout is not None and result.stdout != expect_stdout:
            return "fail", "output mismatch"
        return "pass", "correct under budget"
    if result.status is ExecutionStatus.TIMEOUT:
        return "fail", "exceeded the wall-clock budget"
    if result.status is ExecutionStatus.FUEL_EXHAUSTED:
        return "fail", "exceeded the compute budget"
    if result.status is ExecutionStatus.MEMORY_EXCEEDED:
        return "fail", "exceeded the memory budget"
    return "fail", f"crashed or misbehaved (exit_code={result.exit_code})"


def main() -> None:
    # Three submissions a grader might receive: correct, compute bomb,
    # memory hog — each compiled from a WAT like a real toolchain would.
    submissions = {
        "correct.wasm": b'(module (func (export "_start")))',
        "compute_bomb.wasm": b'(module (func (export "_start") (loop $l br $l)))',
        "memory_hog.wasm": b'(module (memory 1) (func (export "_start") i32.const 70000 i32.load drop))',
    }

    with tempfile.TemporaryDirectory() as tmp:
        grades = []
        for name, wat in submissions.items():
            path = Path(tmp) / name
            path.write_bytes(wasmtime.wat2wasm(wat))
            grades.append({"submission": name, **grade_submission(str(path))})

    print(json.dumps(grades, indent=2))


if __name__ == "__main__":
    main()
