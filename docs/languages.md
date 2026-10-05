# Languages & Interpreters

Ephemora Cell executes pre-compiled `.wasm` modules — it does not ship language interpreters. For building from source, use `ephemora-cell build <source>` (see the [README](../README.md#api-cli-and-integrations) and [ADR-005](decisions/ADR-005-build-pipeline.md)); this page covers which languages run in the Cell and how. Strategy reference: [ADR-009](decisions/ADR-009-language-support.md).

## Support tiers

| Tier | Languages | How | Status |
|---|---|---|---|
| 1 — AOT | Rust, Go, C, AssemblyScript, Zig | `ephemora-cell build` recipes (real builds; C needs WASI-SDK, AS needs `asc`, Zig needs `zig` — guidance points at the installer when missing) | shipped |
| 1 — AOT | Python | no AOT-to-WASM compiler exists — structural guidance, see below | guidance only |
| 2 — Component | any WASI 0.2 component toolchain, incl. componentized interpreters (JavaScript via jco/StarlingMonkey, Pure-Python via componentize-py) | run the component with `abi="component"` — **bring your own binary**, sha256-pinned in the recipes; Cell ships no interpreters | component execution shipped; per-language recipes: [docs/recipes.md](recipes.md) |
| 3 — Locked | GC/threads-based ports (Kotlin/Wasm, Dart, …) | blocked by a missing enforcement primitive, not by policy: the GC heap is not byte-bounded in the Python bindings (see [SECURITY.md](../SECURITY.md), "GC heap not byte-bounded") | locked until the gate trigger in SECURITY.md's LTS section fires |

Every tier runs under the same boundary: fuel, memory cap, wall-clock epoch timeout, canonical preopen allowlist, byte-budgeted output — and the [proposal policy](../SECURITY.md#proposal-policy--set-not-inherited-2026-09-25) keeps threads, GC, exceptions and stack-switching enforced off.

## Compile recipes and CI gates

The tier-1 languages, with the exact command each recipe runs and what CI
proves about it. All five gates run in the `build-recipes` job on every push
([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)), and each one builds
a real module **and executes it in the sandbox**, asserting `SUCCESS` — a build
that yields a module Cell cannot run is a failed gate, not a passed build. Where
a host has no toolchain installed the corresponding test skips, which is the
toolchain-skip asymmetry documented in
[release_assurance.md](release_assurance.md).

| Language | Build command the recipe runs | Gate |
|---|---|---|
| Rust | `cargo build --target wasm32-wasip1` | compiled + executed (CI) |
| Go | `GOOS=wasip1 GOARCH=wasm go build` | compiled + executed (CI) |
| C | wasi-sdk `clang --target=wasm32-wasip1` | compiled + executed (CI) |
| AssemblyScript | `asc --runtime stub` | compiled + executed (CI) |
| Zig | `zig build-exe -target wasm32-wasi` | compiled + executed (CI) |
| Python | no AOT-to-WASM compiler exists | guidance only — the measured path is the pinned interpreter guest below |

`ephemora-cell build <source>` wraps these commands and, when a toolchain is
missing, names the installer instead of failing with "command not found".

**What does *not* run:** native Python, Node.js/npm packages, or Linux/ELF
binaries — Cell executes WASM modules and WASI 0.2 components, nothing else.
Scripting languages run only as interpreter binaries *you* compile to WASM (or
componentize — `componentize-py`, jco/StarlingMonkey) and bring yourself. Cell
ships no interpreters, and GC/threads-based ports stay locked for the reason in
the tier table above, not by policy.

**Where this is measured:** the language gates and the test matrix run on
`ubuntu-latest` and `macos-latest` across Python 3.10–3.13. Interpreter-guest
and performance numbers are measured on macOS (Apple M5) and on a DGX Spark
GB10 (Ubuntu 24.04, Grace arm64) — cross-platform detail in
[comparison-mcp-servers.md](comparison-mcp-servers.md#55-cross-platform-suite--scale-dgx-spark).

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

The budgets a compiled module needs are not the budgets an interpreter needs. An interpreter module is 10–150 MB, boots a whole runtime before user code runs, and burns fuel for its own dispatch loop, so the defaults (32 MiB module cap, 128 MB memory, 1 M fuel, 30 s wall clock) stop it before it gets anywhere. `--profile interpreter` / `get_profile("interpreter")` raises those four plus `io_cpu_seconds` — on the isolation path the worker must first compile a 22 MB guest, measured at 5.40 s of host CPU against a 2.0 s default wall — and nothing else: no preopens, no env, no synced-disk exception, no claim that Cell speaks Python.

**Python (CPython-WASI), measured with a pinned guest:**

```bash
# Prebuilt release (or build CPython for WASI with WASI-SDK yourself):
curl -sLO https://github.com/singlestore-labs/python-wasi/releases/download/v3.10-alpha/wasi-python-3.10.tgz
tar xzf wasi-python-3.10.tgz          # opt/wasi-python/bin/python3.10.wasm
sha256sum opt/wasi-python/bin/python3.10.wasm
# 8e40bfb538b390c1e8b652f4b4369d83d3fd6d1af6b3111631ad80bf0c5a0a02  (22 363 477 bytes)
```

```python
from dataclasses import replace
from ephemora_cell import WASISandbox, get_profile

STDLIB = "opt/wasi-python/lib/python3.10"   # this build ships no embedded stdlib
config = replace(
    get_profile("interpreter"),
    # CPython looks its stdlib up under the prefix it was configured with,
    # so the preopen has to land on that exact guest path.
    allow_dirs=(f"{STDLIB}::/opt/wasi-python/lib/python3.10",),
)
sandbox = WASISandbox(config=config)
result = sandbox.run(
    "opt/wasi-python/bin/python3.10.wasm",
    args=["-c", "import json; print(json.dumps({'ok': True}))"],
    use_subprocess=True,          # the isolation path — see the caveats below
)
print(result.stdout, result.fuel_consumed)
sandbox.cleanup()
```

CLI equivalent:

```bash
ephemora-cell run opt/wasi-python/bin/python3.10.wasm \
  --profile interpreter --isolated \
  --allow-dirs "$PWD/opt/wasi-python/lib/python3.10::/opt/wasi-python/lib/python3.10" \
  -- -c "print('hello from CPython in the Cell')"
```

**What the numbers say (evidence: `benchmarks/interpreter_guest/measure.py`,
results in `benchmarks/results/2026-10-02/interpreter_guest.json`):** an
interpreter guest is a different workload class from a compiled module, and it
does **not** inherit the sub-millisecond figure. Measured on macOS arm64 with
a pinned wasi-python 3.10 guest under the `interpreter` profile: four workloads
(boot, print, stdlib json round-trip, `sum(range(200000))`) × 2 paths, **25
in-process and 15 isolated runs per workload, every single one `success`** — the
table below is the median of those runs. **Evidence
scope:** the 22 MB guest is not committed (ADR-009 D2 ships no interpreter
binaries), so this table is reproducible on request — set
`EPHEMORA_BYO_PYTHON_ROOT` at your own guest and re-run `measure.py` — rather
than CI-enforced. The same measurement under Cell's *default* profile ends in
`fuel_exhausted` at 1 000 000 units during CPython startup, which is the whole
reason the `interpreter` preset exists.

| workload | Cell, in-process (median) | Cell, isolated (median) | fuel |
|---|---|---|---|
| `-c pass` (boot) | 607.2 ms | 859.9 ms | 71.7 M |
| `-c print('hello')` | 629.9 ms | 728.8 ms | 71.8 M |
| json round-trip | 635.2 ms | 732.8 ms | 128.0 M |
| `sum(range(200000))` | 673.6 ms | 709.4 ms | 194.4 M |

The same baseline on this machine: `docker run --rm python:3.12-slim python3
-c pass` — median **204.4 ms** (n=25, min 180.1, max 231.1). So for an
interpreter guest the Cell is about **3.0× slower than Docker in-process and
4.2× slower isolated** (859.9 ms / 204.4 ms), not faster — and the isolated
path is the one this page recommends for guests from outside your own build.
The cost is CPython starting inside wasm (no embedded stdlib, sources
compiled through a preopen), which no sandbox layer can amortize away. The
per-call advantage in [performance.md](performance.md) — ~0.4 ms warm — is a
*compiled-module* number, and that is the comparison to make when choosing
this design: AOT to wasm, or run the interpreter and accept interpreter
startup plus ~10⁸ fuel per call. Size interpreter budgets from the table
above, per the rule in [Fuel semantics per ABI](#fuel-semantics-per-abi).

**Caveats that belong to the guest, not to the Cell:**

- **The stdlib preopen is writable.** `allow_dirs` grants read-write, and
  CPython writes `__pycache__/*.pyc` back into it as it imports. Measured on a
  freshly extracted tree: boot fuel falls from **357 M** on the first call to
  the steady **71.5 M** by the sixth, as the guest adds 13 `.pyc` files
  (`warm_1…warm_12` in `benchmarks/results/2026-10-02/interpreter_guest.json`)
  — while wall time moves only from 756 ms to 654 ms, so the priming buys
  fuel, not milliseconds. Two consequences: cold and warm runs are not comparable
  budget-wise, and the guest modifies its own library tree. Point the preopen
  at a tree you are willing to have written to, or at a copy.
- **The sync wall stays closed — and the interpreter does not care.** CPython
  imports `fd_datasync` during startup, which the pre-1.1 blockade refused at
  the import layer; the blockade now refuses the CALL, and measurement shows
  this guest never makes one, on a cold or a warm stdlib tree
  (`benchmarks/interpreter_guest/probe_datasync.py`). So `allow_fsync` is not
  part of the interpreter profile and no run has to weaken the posture to boot
  Python. Should a future guest really sync, it will be refused and the opt-in
  is the answer — with the caveat from
  [SECURITY.md](../SECURITY.md) that host sync work is not bounded by
  `io_cpu_seconds`, which is why the knob is a capability grant and not a
  tuning dial.
- **No C extensions, no threads, no sockets.** This is wasm32-wasip1 CPython:
  wheels with native code do not load, `max_threads=1` stays, and Preview1 has
  no socket surface.

**Note:** Interpreter overhead is not included in Ephemora Cell's headline
performance metrics. Those measure the sandbox engine, not the guest runtime.
