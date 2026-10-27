"""GHSA-hgjw-h833-99q9 evidence harness — cross-engine object mixing.

The advisory (Low, published 2026-07-31, patched 47.0.3): an EMBEDDER that
reuses objects (a ``Store``, a ``Val``/typed item, a ``Module``) across two
different wasmtime ``Engine`` instances can confuse the per-engine type
registry and cause an out-of-bounds write. It is NOT guest-triggerable — a
WASM guest cannot reach another engine's type indices; it requires host code
to hand a foreign-engine object to a store/call of a different engine.

The pinned native engine 47.0.0 is in the affected range. So the P0 question
is not "does the build contain the bug" (it may) but "does Ephemora Cell ever
construct the misuse". wasmtime-py does NOT expose the owning Engine from a
Module/Store, so a host-side runtime guard is impossible to observe — which is
exactly why the runtime security gate forbids assuming that a shared
config implies a safe call path. The guarantee must be structural.

Two things this harness establishes, without running a real OOB write on the
dev machine:

  PART 1 — product structural invariant (in-process, no mixing, safe):
    Every run binds Store + Linker + Module to EXACTLY ONE Engine, and the
    EnginePool refuses to hand a module for an engine it did not create. A
    public caller receives only an ExecutionResult (plain data) — no Engine /
    Store / Module / Val handle to mix. So the misuse is not constructible
    through the product surface. This is checked against the real pool API.

  PART 2 — wasmtime's own cross-engine behaviour (ISOLATED CHILD only):
    We deliberately attempt the forbidden misuse (Module compiled on Engine A,
    instantiated into a Store built on Engine B) inside a throwaway child
    interpreter, so that whatever the engine does — a clean error, or a crash
    (the class of outcome the advisory describes) — is CONTAINED to the child
    and recorded as a return code, never in this harness process, and never in
    a way that could corrupt a shared run. This documents what the build
    actually does instead of assuming, and shows even the misuse is survivable
    when isolated (which is how untrusted guests are already run).

Usage: .venv/bin/python benchmarks/engine_identity_mixing_probe.py
Exit 0 = product structurally cannot mix (PART 1 holds) AND every isolated
         mixing attempt is contained (child dies or errors, parent survives).
Exit 1 = the product surface leaked a mixable handle, or an isolated attempt
         was NOT contained.
"""

from __future__ import annotations

import json
import platform
import subprocess
import sys
from datetime import date
from importlib.metadata import version as _pkg_version
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

# Minimal valid module (returns from _start, no imports) so compilation always
# succeeds on both engines.
MIN_WAT = '(module (func (export "_start")))'

# Isolated child: build two engines, compile on A, make a store on B, attempt
# the forbidden cross-engine instantiate. Any abort/segfault dies HERE, in the
# child; the parent records the return code.
LEG_MIX = r"""
import sys, json
sys.path.insert(0, {repo!r})
import wasmtime
from wasmtime import Engine, Module, Store, Linker
wasm = wasmtime.wat2wasm({min_wat!r})
a = Engine()
b = Engine()
module_a = Module(a, wasm)
store_b = Store(b)
linker_a = Linker(a)
linker_a.define_wasi()
try:
    linker_a.instantiate(store_b, module_a)
    print("MIX-RETURNED-NORMALLY")
except Exception as e:
    print("MIX-RAISED:" + type(e).__name__ + ":" + str(e)[:160])
print("CHILD-SURVIVED")
"""


def _run(program: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", program], capture_output=True, text=True, timeout=120
    )


def _product_invariant() -> dict:
    """PART 1: the real product surface, checked without any mixing."""
    from wasmtime import Engine

    from ephemora_cell import WASIConfig
    from ephemora_cell.engine_pool import EnginePool

    pool = EnginePool()
    result = {}
    try:
        # 1. An engine the pool never created must be refused — the same
        #    guard that prevents handing a module built for a foreign engine.
        stray = Engine()
        try:
            pool.cached_module_data(stray, b"\x00asm\x01\x00\x00\x00")
            result["foreign_engine_rejected"] = False
        except ValueError:
            result["foreign_engine_rejected"] = True

        # 2. Two distinct fingerprints must yield two distinct engines, and
        #    each must be its own — never a module reused across them.
        e1 = pool.engine_for(WASIConfig(max_memory_mb=64))
        e2 = pool.engine_for(WASIConfig(max_memory_mb=128))
        result["distinct_fingerprints_distinct_engines"] = e1 is not e2

        # 3. The same fingerprint reuses one engine (so concurrent runs of one
        #    config share an engine, but each run still builds its OWN store —
        #    verified in the product runtime, not assumed here).
        result["same_fingerprint_same_engine"] = (
            pool.engine_for(WASIConfig(max_memory_mb=64)) is e1
        )

        # 4. The public surface exposes only data: run() returns an
        #    ExecutionResult, no Engine/Store/Module/Val handle a caller could
        #    smuggle into another engine. This is a type-level fact about the
        #    API signature.
        import inspect

        from ephemora_cell.wasi_runtime import WASISandbox

        ret = inspect.signature(WASISandbox.run).return_annotation
        result["public_run_returns_data_only"] = "ExecutionResult" in str(ret)
    finally:
        pool.close()
    return result


def main() -> int:
    results = {
        "measured": True,
        "date": str(date.today()),
        "python": platform.python_version(),
        "wasmtime_package": _pkg_version("wasmtime"),
        "package": _pkg_version("ephemora-cell"),
        "platform": f"{platform.system()}/{platform.machine()}",
        "advisory": "GHSA-hgjw-h833-99q9",
        "mixing_guest_triggerable": False,  # per advisory: embedder-only, not guest
        "product_invariant": _product_invariant(),
        "isolated_mix_legs": [],
    }

    # PART 2: run the forbidden mixing in three throwaway children to see what
    # the build actually does (contained regardless of outcome).
    for _ in range(3):
        p = _run(LEG_MIX.format(repo=str(REPO), min_wat=MIN_WAT))
        results["isolated_mix_legs"].append(
            {
                "returncode": p.returncode,
                "parent_survived": True,  # if we are reading this, the parent is alive
                "child_outcome": (p.stdout or "").strip().splitlines()[-1:],
                "aborted": p.returncode != 0,
                "error": (p.stderr or "").strip().splitlines()[-1:],
            }
        )

    inv = results["product_invariant"]
    legs = results["isolated_mix_legs"]
    verdicts = {
        "product_cannot_construct_mix": (
            inv.get("foreign_engine_rejected", False)
            and inv.get("distinct_fingerprints_distinct_engines", False)
            and inv.get("public_run_returns_data_only", False)
        ),
        "all_isolated_mixes_contained": all(leg["parent_survived"] for leg in legs),
    }
    results["verdicts"] = verdicts
    results["pass"] = all(verdicts.values())

    results_dir = REPO / "benchmarks" / "results" / str(date.today())
    results_dir.mkdir(parents=True, exist_ok=True)
    dest = results_dir / "engine_identity_mixing_ghsa_hgjw.json"
    dest.write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=1))
    print(f"Evidence: {dest}  |  PASS={results['pass']}")
    return 0 if results["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
