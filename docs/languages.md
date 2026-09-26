# Languages & Interpreters

Ephemora Cell executes pre-compiled `.wasm` modules — it does not ship language interpreters. For building from source, use `ephemora-cell build <source>` (see the [README](../README.md#architecture) and [ADR-005](decisions/ADR-005-build-pipeline.md)); this page covers which languages run in the Cell and how. Strategy reference: [ADR-009](decisions/ADR-009-language-support.md).

## Support tiers

| Tier | Languages | How | Status |
|---|---|---|---|
| 1 — AOT | Rust, Go, C, AssemblyScript, Zig | `ephemora-cell build` recipes (real builds; C needs WASI-SDK, AS needs `asc`, Zig needs `zig` — guidance points at the installer when missing) | shipped |
| 1 — AOT | Python | no AOT-to-WASM compiler exists — structural guidance, see below | guidance only |
| 2 — Component | any WASI 0.2 component toolchain, incl. componentized interpreters (JavaScript via jco/StarlingMonkey, Pure-Python via componentize-py) | run the component with `abi="component"` — **bring your own binary**, sha256-pinned in the recipes; Cell ships no interpreters | component execution shipped; per-language recipes: [docs/recipes.md](recipes.md) |
| 3 — Locked | GC/threads-based ports (Kotlin/Wasm, Dart, …) | blocked by a missing enforcement primitive, not by policy: the GC heap is not byte-bounded in the Python bindings (see [SECURITY.md](../SECURITY.md), "GC heap not byte-bounded") | locked until the gate trigger in SECURITY.md's LTS section fires |

Every tier runs under the same boundary: fuel, memory cap, wall-clock epoch timeout, canonical preopen allowlist, byte-budgeted output — and the [proposal policy](../SECURITY.md#proposal-policy--set-not-inherited-2026-09-25) keeps threads, GC, exceptions and stack-switching enforced off.

## WASI Preview1

Ephemora Cell currently uses **WASI Preview1** (`wasi_snapshot_preview1`), the stable WASI interface with:
- File I/O (`fd_read`, `fd_write`, `path_open`, etc.)
- Command-line arguments and environment variables
- Clock access and random data

**Preview1 limitations:**
- No network socket support — network stays closed by design; integration egress goes through the host-side patterns in [egress_patterns.md](egress_patterns.md)
- No process spawning
- Limited filesystem metadata operations
- No streaming I/O

**WASI 0.2 components are already supported** (opt-in via `abi="component"` or auto-detection — see [recipes](recipes.md#wasi-02-components)): command-world (`wasi:cli/run`) components run with the same security baseline as Preview1. Components get no `/sandbox` mount (the sandbox dir is host-owned and never preopened on the component path).

**WASI 0.3 position (explicit, 2026-09-25): gate-off.** WASI 0.3 shipped 2026-06-11 with native async on Component-Model primitives; Cell stays on the synchronous 0.2 surface for untrusted code. Support opens only when all three criteria in [ADR-009](decisions/ADR-009-language-support.md) hold: (a) the wasmtime Python bindings expose a 0.3 component-linker surface (today only `add_wasip2`/`add_wasi_http` — asserted in `tests/test_surface_audit.py`), (b) the engine pin carries the patch line for the wasip3 host-allocation advisory [GHSA-x84v-gj2h-g759](https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-x84v-gj2h-g759) (fixed in 47.0.4/46.0.3), and (c) the 0.3 surface gets its own budget qualification.

## Fuel semantics per ABI

Fuel counts guest machine instructions, so a limit always stops execution exactly at budget — but **what a budget measures depends on the ABI**. A component or an interpreter-in-WASM burns fuel in its own dispatch loop, so identical budgets mean different amounts of guest work across ABIs (the component path already notes that fuel *rates* differ from Preview1 calibration). Budgets are comparable within one ABI on one platform — the same caveat as the cross-platform fuel drift documented in [SECURITY.md](../SECURITY.md). For interpreter guests, size budgets by a measured factor (evidence in `benchmarks/results/`), not by intuition.

## Using Custom Interpreters

To run Python, JavaScript, Ruby, or other languages inside the sandbox, run their interpreter as a WASM module (or as a WASI 0.2 component) that you bring yourself — Cell executes it like any module and the full boundary applies to it.

**Python (CPython-WASI):**
```bash
# Build CPython for WASI (requires WASI SDK)
git clone https://github.com/singlestore-labs/python-wasi
cd python-wasi && ./run.sh  # Produces wasi-python-3.x.wasm (~150MB)

# Use with Ephemora Cell
from ephemora_cell import run_wasm
result = run_wasm("wasi-python-3.10.wasm", args=["-c", "print('Hello')"])
```

**Note:** Interpreter overhead (CPython: 17-140ms cold start) is not included in Ephemora Cell's performance metrics. Those measure the sandbox engine, not the guest interpreter.
