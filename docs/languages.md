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
`macos-15` (arm64) across Python 3.10–3.13; `ubuntu-latest` carries only the
guest-toolchain build leg, which is not part of the required gate and fails
closed because Linux is not qualified for 1.2.x. Interpreter-guest
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

## What a language run actually carries

An adapter receives three things from the caller: the script, its arguments and
the budget config. Everything else on the `run` flag surface is either honoured
or refused — never ignored. Concretely:

| Flag | On a `--language` run (python / javascript) |
|---|---|
| `--profile`, `--fuel`, `--memory-mb`, `--timeout`, `--memory64` / `--no-memory64`, `--max-wasm-bytes`, `--allow-fsync` | honoured (they build the config the adapter receives) |
| `--allow-env` | honoured — the adapters replace `allow_dirs` only, so env pairs reach the guest |
| `--allow-dirs` | **refused (exit 2)** — the adapter mounts its own grant set (`/work`, plus the interpreter's stdlib on the legacy Python route); `policy check --language` lists what would be dropped |
| `--stdin` | **refused (exit 2)** — these guests read input through the library's `input_json`, not the CLI's stdin |
| `--tenant`, `--tenant-book`, `--tenant-max-runs`, `--tenant-max-fuel` | **refused (exit 2)** — per-tenant quota is not attributed on this path, and that stays true for a cap passed without `--tenant` |
| `--abi` | **refused when it contradicts the adapter**: a JavaScript run is always Preview1, a Python run's ABI comes from the guest's header bytes |
| `--isolated`, `--trust` | accepted — the adapter forces the disposable worker regardless, so these cannot lower anything |

Arguments follow the guest, and the two Python routes differ in one spot worth
knowing before a script depends on it: the caller's arguments occupy
`sys.argv[1:]` on both, but `sys.argv[0]` is `/work/<script>` on the legacy
Preview1 interpreter route (which also gets an injected `-B`, so do not pass
interpreter flags yourself) and the neutral `wasm-module` tag on the WASI 0.2
component route — the runner never leaks a host path into the guest. Use `--`
before an argument that starts with `-`. JavaScript runs take no positional
arguments at all. A plain `.wasm` run passes its arguments the same way: the
guest sees `sys.argv`-equivalent `["wasm-module", …caller args]`.
Every claim in this table is measured per branch in
[`benchmarks/results/2026-10-19/language_grant_views_measured.json`](../benchmarks/results/2026-10-19/language_grant_views_measured.json).

**One `run --json` document, whatever the guest.** The base of the document is the
execution record — `status`, `exit_code`, `elapsed_ms`, `fuel_consumed`,
`fuel_budget`, `fuel_utilization`, `memory_mb`, `stdout_bytes`, `stderr_bytes`,
`warnings`, `security_baseline` (with the attested `allow_env_names` — names, never
values), `exit_status_fidelity` — plus the CLI's `error_class`. Fields the run did
not measure are `null` rather than invented zeros: `memory_mb` is `null` on every
1.2.0 path, because no path measures resident memory. A Python or
JavaScript run is produced by the same `ExecutionReport` that backs a
`run module.wasm` record, so a consumer can read one shape; measured across the
three routes on real guests.

What differs, deliberately:

| key | wasm | python / javascript | why it differs |
| --- | --- | --- | --- |
| `stdout`, `stderr`, `output` | absent | present (the parsed JSON in `output` when the guest printed JSON) | a source run's program is the script the caller handed over; its text is part of the adapter result, while a module run's output streams to the terminal/`stderr` in `--json` mode |
| `language`, `script` | absent | present | names the route and the file that ran |
| `guest_reported_error` | absent | present on the two marker paths | a guest *claim*, never a host verdict (see above) |
| `stdin_capped` | present | absent | `--stdin` is refused on a language run, so there is no stdin to cap |
| `status` spelling | `success` / `error` / … | `ExecutionStatus.SUCCESS` in the **library** dict, `success` in every **document** | the adapter result is the library's own value, kept in its published form for callers who compare against `ExecutionStatus`; `run --json`, the signed record and MCP `_meta.execution` all carry the short word. Read `.value`-style or the document, never the enum repr, when comparing to a string |

### Exit-status fidelity per route

**Exit-status fidelity, per route — measured, and stated rather than hidden.**
The status of the program a caller handed over reaches the host only as far as the
guest's ABI and the guest's own loader let it, so `run --json` carries
`exit_status_fidelity` on every route:

| route | a guest exiting 3 measures as | `exit_status_fidelity` |
| --- | --- | --- |
| `run module.wasm` (Preview1 core module) | `error`, exit code 3, CLI 3 | `exact` |
| `run component.wasm` (WASI-0.2, `std::process::exit(3)`) | `error`, exit code 1, CLI 1 | `non_zero_only` |
| `run script.py` on the Preview1 CPython interpreter guest | `error`, exit code 3, CLI 3 | `exact` |
| `run script.py` on the WASI-0.2 component Python guest | `success`, exit code 0, CLI 0 | `none` |
| `run script.js` on the QuickJS guest (throw or `process.exit`) | `success`, exit code 0, CLI 0 | `none` |

The word is not hand-written per route. Wherever the guest *is* the program — a
`.wasm` module, a JavaScript module built from the caller's own source — the route
takes the same derivation the CLI and the signed record use, from `abi` plus the raw
`guest_exit_observed` fact, so a host-side stop reads `none` there instead of
reporting a channel nothing travelled through. The two source routes above are the
only ones that name the word, and they name it because their measurement says
something the derivation cannot: the guest can leave through its exit interface
while the script's status is already gone. No number is published here for the
pre-compiled JavaScript **module** route (Javy): that guest is behind an opt-in
gate (`EPHEMORA_JS_GUEST_QUALIFY=1`) and was not built on this host, so the route is
listed by its rule, not by a measurement it does not have.

Two different causes for the two guest routes, both measured on the qualified
`49.0.3` runtime:

* the component ABI delivers only the *fact* of a non-zero exit — `exit(3)` and
  `exit(7)` both reach wasmtime as `Exited with i32 exit status 1` — so the
  number is not available to the host and is not invented here;
* the WASI-0.2 Python guest's loader (`docs/language-guest-build.md`) catches
  `SystemExit` and returns normally, so a script's exit status never leaves the
  guest; the JavaScript guest's harness reports a thrown error through its
  `EPHEMORA_USER_ERROR` marker and returns cleanly. On that JavaScript route the
  marker appears for a `throw`, for `process.exit(5)` and for `process.exit(0)`
  alike — measured on the pinned interpreter guest, where any `process.exit`
  reaches the harness as an exception — so `guest_reported_error` is a guest
  claim on both directions and never a stand-in for an exit status here.

What the field never claims: that a guest ran. `exit_status_fidelity` reports the
guest's exit **as the host observed it**, so a run that stopped before the guest
could leave — a module the loader rejects (`run --abi preview1` on a component
binary is the measured case), a fuel/timeout/byte stop, a refused environment —
says `none` even though it still reports `error`, exit code 1 and CLI 1. The
failure is never softened, and no exit channel is attested that nothing travelled
through. (Until this contract was closed, that case read `exact`, describing the
width of the ABI that was routed rather than what the guest delivered —
`docs/cli-errors.md`.)

`status` and `exit_code` therefore describe what the **host** observed. A caller
that must branch on a script's own exit status must not read them on a `none`
route: pin the Preview1 interpreter guest, read the guest's stdout/stderr, or
use `guest_reported_error` — which stays a *guest claim*, never a host verdict
(one execution-record integrity rule across all four adapters). `ephemora run`
prints one note on stderr when its route reports `none`; stdout stays exactly
the guest's bytes.

Closing the `none` routes means changing the guests — propagating `SystemExit`
instead of returning on it — which is a rebuild and re-digest of the pinned
guest artefacts, not an adapter patch. It is stated here rather than papered
over by reporting an exit code the host never saw.

## Using Custom Interpreters

To run Python, JavaScript, Ruby, or other languages inside the sandbox, run their interpreter as a WASM module (or as a WASI 0.2 component) that you bring yourself — Cell executes it like any module and the full boundary applies to it.

The budgets a compiled module needs are not the budgets an interpreter needs. An interpreter module is 10–150 MB, boots a whole runtime before user code runs, and burns fuel for its own dispatch loop, so the defaults (32 MiB module cap, 128 MB memory, 1 M fuel, 30 s wall clock) stop it before it gets anywhere. `--profile interpreter` / `get_profile("interpreter")` raises those four plus `io_cpu_seconds` — on the isolation path the worker must first compile a 22 MB guest, measured at 5.40 s of host CPU against a 2.0 s default wall — and nothing else: no preopens, no env, no synced-disk exception, no claim that Cell speaks Python. On the shipped 19.8 MB Python component guest, the compile measured 7.71–7.89 s CPU in 1.14–2.10 s wall across the measured load profiles; the interpreter profile's 30 s `io_cpu_seconds` budget kept about 22 s of headroom ([release_assurance.md](release_assurance.md#host-load-the-python-guest-under-measured-contention)).

**Python (CPython-WASI), measured with a pinned guest:**

> **Modern component path (built + isolated-run qualified 2026-10-14).** Beyond the
> BYO interpreter above, a WASI-0.2 **command** component built with
> `componentize-py==0.25.1` from the pinned recipe `scripts/build_python_guest.py`
> was measured running `SUCCESS` through the isolated sandbox under the
> `interpreter` profile (digest-bound; opt-in gate
> `EPHEMORA_PY_GUEST_QUALIFY=1 pytest tests/test_python_guest.py`; evidence
> `benchmarks/results/2026-10-14/python_component_guest.json`). It is not yet a
> shipped language package: componentize-py is not bit-deterministic (pin a
> build-once digest), and the published `ephemora-cell[python]` / `[javascript]`
> extras with license/SBOM and install-against-the-published-package
> qualification remain open supply-chain tasks (ADR-009). The Cell component
> runner executes only `wasi:cli/run`-style command worlds; a reactor component
> (no `run` export) is refused with an ERROR.

**JavaScript, measured with a pinned guest:**

> **Reproducible recipe path (built + isolated-run qualified 2026-10-15).** A
> JavaScript Preview1 guest built with `javy==9.1.0` from the pinned recipe
> `scripts/build_js_guest.py` was measured running `SUCCESS` through the isolated
> `lang_js` subprocess path with its JSON round-trip verified against the exact
> installed 1.2.0 wheel (digest-bound; opt-in gate
> `EPHEMORA_JS_GUEST_QUALIFY=1 pytest tests/test_js_guest.py`; evidence
> `benchmarks/results/2026-10-15/js_component_guest.json`). The Javy toolchain is
> not auto-provisioned in CI (no npm/brew package) — it is supplied out-of-band via
> `EPHEMORA_JAVY_BIN` from a pinned local build, so nothing is downloaded at Cell
> execution time. Javy is not bit-deterministic either (consecutive builds differ at
> constant size), so a shipped package must pin one build-once digest. Publishing the
> `ephemora-cell[javascript]` extra with license/SBOM clearance remains an open ADR-009
> task.

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
