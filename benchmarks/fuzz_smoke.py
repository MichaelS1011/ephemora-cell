"""Ephemora Cell fuzz smoke test — random valid WASM modules.

Generates deterministic random WAT modules (simple i32 instructions, bounded
loops, max 50 instructions), compiles them with wasmtime.wat2wasm and runs
each through WASISandbox with max_fuel=10_000, timeout_seconds=2 and no
preopened directories. Reports crashes, unexpected exceptions and hangs.

This is a smoke test for host-side crashes/hangs, not a coverage-guided fuzzer.

Usage:
    python benchmarks/fuzz_smoke.py                    # 100 modules, default seed
    python benchmarks/fuzz_smoke.py --seed 42 --modules 500
    FUZZ_SEED=42 python benchmarks/fuzz_smoke.py
"""
from __future__ import annotations

import argparse
import os
import random
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import wasmtime

from ephemora_cell import WASISandbox, WASIConfig

DEFAULT_SEED = 20260813
MAX_INSTRUCTIONS = 50
WATCHDOG_SECONDS = 15


def _gen_if(rng, budget):
    then_b = _gen_balanced(rng, budget)
    else_b = _gen_balanced(rng, budget)
    cond = rng.randint(0, 1)
    budget["ops"] += 1
    return f"i32.const {cond} (if (then {then_b}) (else {else_b}))"


def _gen_loop(rng, budget):
    inner = _gen_balanced(rng, budget)
    iters = rng.randint(2, 10)
    budget["ops"] += 1
    return (
        f"i32.const 0 (local.set $l0) "
        f"(block $exit "
        f"(loop $l {inner} "
        f"(local.get $l0) (i32.const 1) (i32.add) (local.set $l0) "
        f"(local.get $l0) (i32.const {iters}) (i32.lt_s) (br_if $l)) "
        f"(br $exit))"
    )


def _gen_balanced(rng, budget):
    """Generate a stack-balanced instruction sequence (valid WAT body)."""
    depth = 0
    parts = []
    while budget["ops"] < MAX_INSTRUCTIONS and (not parts or rng.random() < 0.85):
        r = rng.random()
        if r < 0.40:
            parts.append(f"i32.const {rng.randint(0, 10_000)}")
            depth += 1
            budget["ops"] += 1
        elif r < 0.60 and depth >= 2:
            parts.append(
                rng.choice(["i32.add", "i32.sub", "i32.mul", "i32.and", "i32.or", "i32.xor"])
            )
            depth -= 1
            budget["ops"] += 1
        elif r < 0.70 and depth >= 1:
            parts.append("drop")
            depth -= 1
            budget["ops"] += 1
        elif r < 0.80 and depth >= 1:
            parts.append("i32.eqz")
            budget["ops"] += 1
        elif r < 0.88:
            parts.append(_gen_if(rng, budget))
        elif r < 0.95 and "has_locals" in budget:
            parts.append(_gen_loop(rng, budget))
        else:
            parts.append("nop")
            budget["ops"] += 1
    if depth > 0:
        parts.append(" ".join(["drop"] * depth))
    return " ".join(parts)


def gen_wat(seed: int) -> str:
    """Deterministic random WAT module exporting `_start`."""
    rng = random.Random(seed)
    n_locals = rng.randint(0, 3)
    budget = {"ops": 0}
    if n_locals:
        budget["has_locals"] = True
    body = _gen_balanced(rng, budget)
    locals_decl = " ".join(f"(local $l{i} i32)" for i in range(n_locals))
    return (
        "(module\n"
        f'  (func (export "_start") {locals_decl}\n'
        f"    {body}\n"
        "  )\n"
        ")"
    )


def run_module(wasm_bytes: bytes):
    """Execute one module in the sandbox (max_fuel=10000, 2s timeout, no dirs)."""
    tmp = tempfile.NamedTemporaryFile(suffix=".wasm", delete=False)
    tmp.write(wasm_bytes)
    tmp.close()
    try:
        config = WASIConfig(max_fuel=10_000, timeout_seconds=2)
        sandbox = WASISandbox(config=config)
        try:
            return sandbox.run(tmp.name)
        finally:
            sandbox.cleanup()
    finally:
        os.unlink(tmp.name)


def run_with_watchdog(wasm_bytes: bytes) -> dict:
    outcome = {"result": None, "exception": None, "hang": False}

    def target():
        try:
            outcome["result"] = run_module(wasm_bytes)
        except BaseException as e:
            outcome["exception"] = e

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(WATCHDOG_SECONDS)
    if thread.is_alive():
        outcome["hang"] = True
    return outcome


def main() -> int:
    parser = argparse.ArgumentParser(description="Ephemora Cell fuzz smoke test")
    parser.add_argument(
        "--seed", type=int,
        default=int(os.environ.get("FUZZ_SEED", DEFAULT_SEED)),
        help="Deterministic seed (default: %(default)s, env FUZZ_SEED)",
    )
    parser.add_argument("--modules", type=int, default=100, help="Modules to run")
    args = parser.parse_args()

    failures = []
    status_counts = {}
    generator_errors = 0

    for i in range(args.modules):
        wat = gen_wat(args.seed * 1000 + i)
        try:
            wasm = wasmtime.wat2wasm(wat)
        except Exception as e:
            generator_errors += 1
            print(f"[generator error] module {i}: {e}")
            continue

        outcome = run_with_watchdog(wasm)
        if outcome["hang"]:
            failures.append((i, "HANG", f"did not finish within {WATCHDOG_SECONDS}s"))
            continue
        if outcome["exception"]:
            exc = outcome["exception"]
            failures.append((i, "EXCEPTION", f"{type(exc).__name__}: {exc}"))
            continue
        r = outcome["result"]
        status_counts[r.status.value] = status_counts.get(r.status.value, 0) + 1

    print(f"Fuzz smoke: {args.modules} modules, seed={args.seed}")
    print(f"Status distribution: {status_counts or 'none'}")
    if generator_errors:
        print(f"[WARN] {generator_errors} module(s) failed WAT validation "
              f"(generator bug, not a sandbox issue)")

    if failures:
        print(f"FAILURES: {len(failures)}")
        for idx, kind, detail in failures[:10]:
            print(f"  module {idx}: {kind} — {detail[:200]}")
        return 1

    print("PASS — no crashes, exceptions or hangs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
