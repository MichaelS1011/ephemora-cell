# ADR-009: Language Support Strategy — Tiered Recipes, BYO Interpreter Components, Explicit Gates

- **Status:** Accepted
- **Date:** 2026-09-26
- **Predecessors:** ADR-005 (build pipeline instead of registry), ADR-007
  (out-of-scope-by-design pattern)
- **Basis:** Double-verified research pass (independent research agent +
  adversarial fact-check agent, 2026-09-26), including direct inspection of
  the installed `wasmtime` Python bindings and the Cell code paths cited
  below.

## Context (verified, not assumed)

"Compile from any language" remains the biggest adoption blocker (ADR-005
friction matrix). A second research pass in 2026-09 established the following
facts, each checked against primary sources or the local tree:

1. **WASI 0.3 shipped 2026-06-11** (bytecodealliance.org/articles/WASI-0.3).
   Wasmtime 46+ runs 0.3 components engine-side — **but the `wasmtime` Python
   bindings do not**: the component linker exposes only
   `add_wasip2`/`add_wasi_http`; a `wasip3` surface does not exist in the
   installed package (asserted in `tests/test_surface_audit.py`). WASI 0.3
   execution from Python is structurally unreachable today, independent of
   our engine pin. The gate-off position in `docs/recipes.md` (dated
   2026-09-25, incl. the wasip3 host-allocation advisory GHSA-x84v-gj2h-g759,
   patched in 47.0.4/46.0.3) is therefore correct as written;
   `docs/languages.md` was aligned with it in the same pass.
2. **Fuel under interpreter modules shifts semantics, it does not break.**
   Fuel counts guest machine instructions — including the interpreter's
   dispatch loop — so the limit still stops execution exactly at budget.
   What changes is *what a budget measures* (interpreter dispatch, not guest
   logic), making budgets comparable only within one ABI on one platform.
   Cell already documents the same class of caveat for cross-platform fuel
   drift (SECURITY.md, "fuel is not cross-platform deterministic") and for
   the component path (`ephemora_cell/wasi_02.py` "fuel consumption *rates*
   differ from Preview1 calibration").
3. **The proposal policy stays.** threads/GC/exceptions/stack-switching are
   enforced off in all three engine construction sites
   (`wasi_runtime.py`, `engine_pool.py`, `wasi_02.py`), compile-probe-tested
   per release (`tests/test_proposal_policy.py`) and attested in every
   `security_baseline` (`execution_report.py`). Other runtimes (Wassette,
   Spin) run engine defaults — they do not sell deterministic fuel
   accounting; the advisory record (GHSA-m63x-6p34-q65x: fuel accounting
   dropped across `call_ref`/`try_table`) shows exactly where default-on
   proposals diverge. The strictness is product-necessary.
4. **The hard blocker for GC languages is a missing binding, not a
   preference.** The GC heap is not byte-bounded: `Store.set_limits` covers
   linear memory only (SECURITY.md "GC heap not byte-bounded"). The official
   gate trigger is recorded in SECURITY.md's LTS section: when wasmtime-py
   exposes a GC-heap limiter (`ResourceLimiter`) or a `wasm_gc` engine flag,
   enforcement for `max_gc_heap_mb` follows on that upgrade's checklist.
5. **The market mechanism for language breadth is "interpreters as ordinary
   components".** Spin (componentize-py, componentize-js), Extism (PDKs) and
   Wassette (components over MCP) all widen languages this way; a component
   inherits the full Cell boundary (fuel, memory, preopens, output cap)
   without host-code changes. componentize-py is Pure-Python only (no
   NumPy/C-extensions); JS via jco/StarlingMonkey is the most mature path.
6. **Rejected alternatives:** WASIX (Wasmer-only, non-standard,
   fragmentation — and it would leave our Wasmtime basis); shipping
   interpreter binaries in the package (a CPython-wasi is ~150 MB against
   PyPI's per-file limit and the "one `pip install`" promise, and it creates
   the signing/version-treadmill ADR-005 deliberately deferred).

## Decision

**D1 — Tiered support (documented in `docs/languages.md`, evidenced per row):**

- **Tier 1 — AOT, shipped build recipes:** Rust, Go, C (WASI-SDK),
  AssemblyScript, Zig via `ephemora-cell build` (real builds; C/AS/Zig with
  toolchain preconditions, Python as structural guidance — ADR-005).
- **Tier 2 — WASI 0.2 components, bring your own binary:** any language with
  a 0.2 component toolchain, including componentized interpreters
  (JavaScript via jco/StarlingMonkey, Pure-Python via componentize-py).
  Cell runs them like any component; recipes pin downloads by SHA256.
  Cell ships no interpreter binaries.
- **Tier 3 — locked:** GC/threads-based language ports (Kotlin/Wasm, Dart,
  …) are locked until the GC-heap limiter binding exists (gate trigger in
  SECURITY.md). Not a design debate — a missing enforcement primitive.

**D2 — Standing rejections:** no WASIX; no interpreter binaries in the
package or release artifacts; no "any language" claim in public material.

**D3 — WASI 0.3 opens only when all three recipes.md criteria hold:** (a)
the wasmtime-py component linker ships a 0.3 surface, (b) the pin carries the
patch line for the wasip3 advisory, (c) 0.3 gets its own budget
qualification. Until then: gate-off, synchronous 0.2 surface for untrusted
code.

**D4 — Fuel semantics per ABI is a documented feature.** Budgets are
comparable within one ABI on one platform; interpreter guests get a measured
budget factor (evidence JSON), not a silent default.

## Consequences

- Language breadth grows through **recipes and evidence**, not runtime code:
  WPL1–WPL3 of the 2026-09-26 workplan measure per-ABI fuel boundaries and
  add JS/Python BYO recipes with sha256-pinned downloads.
- Component-path capability gaps are decided explicitly: no `/sandbox` mount
  for components (host-owned, unchanged), and a `wasi:http` import failure
  points to the egress-sidecar pattern instead of a raw engine error.
- A `scripts/watch_upstream.py` watcher tracks the three external gates
  (engine upgrade window, wasmtime-py 0.3 surface, GC-heap limiter binding)
  so the strategy re-opens on evidence, not on ad-hoc re-litigation.
- Reversible: Tier 2/3 widenings are additive; nothing in D1–D4 blocks a
  future 0.3 or GC enablement once the gates above fire.
