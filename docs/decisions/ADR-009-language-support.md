# ADR-009: Language Support Strategy — Tiered Recipes, BYO Interpreter Components, Explicit Gates

- **Status:** Accepted — **amended 2026-10-14 for 1.2.0** (the 1.2.0 language
  decision: Python and JavaScript are mandatory 1.2.0 components and the
  BYO-only position in D2 is narrowed to the optional-language-package /
  extras mechanism; see “Amendment — 1.2.0” below, which supersedes the
  “no interpreter binaries in the package or release artifacts” clause)
- **Date:** 2026-09-26 (amended 2026-10-14)
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

## Amendment — 1.2.0 (the language decision): Python and JavaScript are
## mandatory and must ship as installable guests, not BYO-only

**What the 1.2.0 decision changed.** D2’s standing rejection of
“interpreter binaries in the package or release artifacts” was written against
a BYO-only product goal. The language decision makes Python and JavaScript
**Pflichtbestandteile** of 1.2.0 and states plainly that **BYO-only does not
meet the product goal**: a developer must be able to run Python and JavaScript
examples after **one documented install command**, with **no manual hunting for
guest `.wasm` files**, **no hidden runtime downloads**, and **no execution of
foreign source through a host interpreter/compiler**.

**How this reconciles with the size/license reality that motivated D2.** The
~150 MB CPython-wasi figure and the PyPI per-file/wheel-size concern remain
true, so the mechanism is the one the language decision authorises when
“Größe, Plattformkompatibilität oder Lizenzbedingungen” block core-wheel
bundling: **official, versioned optional language packages / extras**, resolved
by a single documented command (e.g. `pip install "ephemora-cell[python]"` /
`[javascript]`, each pinning the guest artifact by digest). The amendment is
therefore:

- **Superseded:** “no interpreter binaries in the package or release artifacts”
  as a blanket rule, and Tier-2 “Cell ships no interpreter binaries.”
- **Retained (unchanged, and now load-bearing):** the modern variant is the
  starting point — the historical CPython-WASI **3.10** guest is research only
  (language decision, Python requirement 1); the interpreter/JS guest must be
  qualified on a
  **current** CPython-WASI / componentize-py line (Python requirement 2, JS
  via Javy) with
  version + build artifacts fixed after a security and compatibility check
  (Python requirement 3); guests are built reproducibly and digested (Python
  requirement 4); execution
  runs under the **mandatory protection profile** (isolation-mandate worker
  path, never in-process for untrusted/unknown — Python requirement 5, JS
  requirement 4); the old ADR-009
  safety rails (proposal policy D3/D4, BYO digest-pinning for *non-bundled*
  guests) all stay.
- **New invariants:** (a) no hidden runtime download at execution time — the
  guest is delivered at install time by a declared extra, its digest verified
  before first run; (b) no host-interpreter execution of guest code; (c) the
  final install + security qualification **must run against the actually built
  packages**, not a synthetic path.
- **Licensing gate (decision 1 explicit):** bundling/re-distribution of the
  guest is admitted only if the interpreter/runtime license permits
  redistribution (CPython/PSF-BSD and Javy/QuickJS-MIT are permissive, but the
  specific build’s full dependency tree must be SBOM-reviewed); where it does
  not, the optional-package route is used rather than embedding.

**Progress and what still remains gated (honest, updated 2026-10-14):** the
**Python half is now measured on this host.** A modern CPython WASI-0.2 command
component builds from a pinned recipe (`scripts/build_python_guest.py`,
`componentize-py==0.25.1`) and runs `SUCCESS` through the **isolated** Cell
sandbox under the `interpreter` profile, digest-bound, with an opt-in
qualification gate (`EPHEMORA_PY_GUEST_QUALIFY=1 pytest
tests/test_python_guest.py`; skipped by default so the standard suite never
depends on the heavy toolchain). Evidence:
`benchmarks/results/2026-10-14/python_component_guest.json`. Two honest limits
this measurement exposes: (a) componentize-py is **not bit-deterministic**
(consecutive builds differ even with `SOURCE_DATE_EPOCH=0`), so a shipped
package must pin the digest of one build-once artifact rather than a rebuild
hash; (b) the guest is not executed against a *published* package. Still
**NOT TESTED / gated** and not a `READY` claim: the **JavaScript** guest (no
cheaply-provisionable toolchain on this host — `javy` absent from npm/Homebrew,
`jco` missing, `cargo` build heavy under load), publishing the versioned
`ephemora-cell[python]` / `[javascript]` distributions (PyPI upload needs
separate authorization), the **license / SBOM** clearance for redistributing the
embedded CPython / JS-engine dependency tree inside the BUSL package, and the
“install against the real published package” end-to-end qualification. Those are
release- and supply-chain engineering tasks to run on the authorized
build environment. The direction, mechanism and safety invariants above are the
decided contract; the published artifacts are the open delivery item.

## Consequences

- Language breadth grows through **recipes and evidence**, not runtime code:
  three staged recipes of the 2026-09-26 workplan measure per-ABI fuel boundaries and
  add JS/Python BYO recipes with sha256-pinned downloads.
- Component-path capability gaps are decided explicitly: no `/sandbox` mount
  for components (host-owned, unchanged), and a `wasi:http` import failure
  points to the egress-sidecar pattern instead of a raw engine error.
- A `scripts/watch_upstream.py` watcher tracks the three external gates
  (engine upgrade window, wasmtime-py 0.3 surface, GC-heap limiter binding)
  so the strategy re-opens on evidence, not on ad-hoc re-litigation.
- Reversible: Tier 2/3 widenings are additive; nothing in D1–D4 blocks a
  future 0.3 or GC enablement once the gates above fire.
