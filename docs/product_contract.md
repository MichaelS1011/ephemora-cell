# Product contract — what Ephemora-cell v1.2.0 supports

This page is the short, human-readable form of
[`product_contract.json`](../product_contract.json). That file is machine-read by
`tests/test_product_contract.py`, which fails when a `supported` capability loses
its acceptance test, when the platform matrix contradicts `ephemora doctor`, or
when a Python version is claimed without having been measured. The file is
therefore the source; this page explains it.

## Platform and interpreter

| Dimension | Qualified | Not qualified |
|---|---|---|
| Operating system | **macOS arm64** | Linux, Windows, musl, Android |
| Python | **3.10, 3.11, 3.12, 3.13** | 3.14 (interpreter-guest only, no host claim) |

"Qualified" means: measured against the patched runtime
`49.0.4.post1+git.2c2970205f` on this release candidate, with the acceptance tests
in this repository. A platform outside the matrix is not forbidden — it is
simply not covered by any claim, and `ephemora doctor` says so instead of
pretending otherwise. The runtime wheel is `macosx_11_0_arm64` only, so on any
other platform the execution path fails closed rather than falling back to an
unpatched engine.

The 3.12 canonical row ran the whole suite in its own virtualenv on the
qualified runtime — **2171/44 (2215 collected), re-measured 2026-10-27**. The
3.10 / 3.11 / 3.13 matrix numbers are **stale**: last measured at 1847/32 on
2026-10-23, before the 1.2 tests were added, and not re-run since; they are kept
so the gap is visible, not as a current claim, and the 3.10/3.11/3.13 rows must
be re-run before they are quoted again. The split moves by a few legs depending
on which optional guests a virtualenv carries, so the per-run log is the
evidence rather than a constant.
3.10 and 3.11 did not pass that run until a real defect was fixed: CPython only
learned to intermix a `nargs="*"` positional with optionals in 3.12.5
([gh-61252](https://github.com/python/cpython/issues/61252)), so on those
interpreters `ephemora run s.py --json a b` exited with "unrecognized
arguments: a b" and the guest never saw its arguments. `cli._parse_argv` now
carries the leftovers on exactly those interpreters, the contract is pinned by
tests that run on every version, and the divergence that remains is stated in
that function's docstring rather than smoothed over.

## What the product does not promise

**A7 — native worker compromise — is outside the support claim for the native
worker.** If an engine escape turns untrusted input into arbitrary native code
inside that worker, the worker still runs with the invoking user's files,
environment and network. The worker contains guest behavior and host crashes; it
is not an operating-system sandbox, and no second kernel-enforced boundary is
claimed for it in 1.2.

The VM backend answers the same question with a different wall instead of
smoothing it over: there the job runs inside a separate Linux VM created through
Apple Virtualization.framework, so a compromise of the guest runtime is a
compromise *inside* that VM. That is why it exists — and why it is offered only
where it was measured (macOS arm64, CLI, operator-supplied VM assets), why it
carries no signed execution record yet, and why nothing in this package may call
a native-worker run "VM-isolated". **A8 — local write access to the installed
package — is outside both:** whoever can modify the installed code can modify the
gate itself. The measured scope and the Option A/Option B comparison are in
[docs/threat-model.md](threat-model.md#native-worker-compromise-a7); the backend
matrix is in [docs/platform_support.md](platform_support.md).

## What the four statuses mean

- **supported** — qualified on the platforms above; at least one executable
  acceptance test exists and is kept alive by the contract guard.
- **experimental** — usable, but a dependency or the operating procedure is not
  release-qualified. The limitation is stated in the contract.
- **unavailable** — advertised or prepared, but not deliverable today. The
  reason is stated; nothing is presented as working that is not.
- **unqualified** — deliberately outside the support claim (for example a
  platform, or the separate private Enterprise product).

## Capabilities

| Capability | Surface | Status |
|---|---|---|
| `ephemora run <module.wasm>` | CLI | supported |
| `ephemora run <script.py>` | CLI | experimental |
| `ephemora run <script.js>` | CLI | experimental |
| `ephemora run --backend vm` (WASM, Python, JavaScript; macOS arm64, operator-supplied VM assets) | CLI | experimental |
| Signed execution record on the VM backend | CLI | unavailable |
| MCP tool surface over the VM backend | MCP | unavailable |
| `ephemora tenant usage` / `ephemora tenant migrate` | CLI | supported |
| OS-level isolation backend on Linux | Runtime | unavailable |
| `ephemora inspect` | CLI | supported |
| `ephemora benchmark` | CLI | supported |
| `ephemora build` | CLI | experimental |
| `ephemora ledger` | CLI | supported |
| `ephemora doctor` | CLI | supported |
| `ephemora verify` | CLI | supported |
| `ephemora policy check` | CLI | supported |
| `WASISandbox`, `run_isolated`, `ExecutionResult` | Python SDK | supported |
| DSSE and detached JWS signing | Python SDK | supported |
| Ledger and record digests | Python SDK | supported |
| stdio MCP server (legacy and 2026-07-28 revisions) | MCP | supported |
| Loopback HTTP bridge | MCP | experimental |
| Agent code execution over MCP stdio (official SDK client) | Agent integration | supported |
| Patched Wasmtime 49.0.4 line, exact native digest on macOS arm64 | Runtime | supported |
| Python guest distribution | Distribution | unavailable |
| JavaScript guest distribution | Distribution | unavailable |
| LangGraph / LangChain tool execution | Agent integration | experimental |
| n8n agent loop | Agent integration | unavailable |
| GitHub Action | CI integration | unavailable |
| Ephemora Enterprise | Private product | unqualified (not part of this package) |

## What `build` does and does not do

`ephemora build <source>` detects the recipe from the file suffix
(`.rs`, `.go`, `.c`, `.ts`, `.zig`, `.py`) and shells out to the toolchain the
recipe names. **The compilers are not part of this package**: a Rust build needs a
cargo project and `cargo`, a Go build needs `go`, and so on. Measured on a host
without them, the command refuses as a caller error instead of pretending:

```
$ ephemora build x.rs
guidance: x.rs: no Cargo.toml found in any parent directory (a Rust build needs a cargo project)
$ echo $?
2
```

That is why the row above says `experimental`: the *detection* and the *error
contract* are tested, the toolchains are yours to provide.

## What the agent claim covers — and what it does not

The `supported` agent row is deliberately narrow, because it is the row most
easy to oversell. It means: an agent-authored WASM module, with an
agent-authored sidecar, is registered from a directory the agent hands over and
executed through the official MCP Python SDK client talking to the stdio server;
and in the same session a sidecar asking for `/etc` is given no preopen, and a
module that never returns is stopped by the fuel budget and returned as an
error. That test is `integration/test_agent_code_execution_mcp.py` and it runs
in the `mcp-sdk-interop` CI job; the contract guard fails if the job stops
running the file.

It does **not** mean that a model-driven autonomous loop has been demonstrated
for LangGraph, the OpenAI Agents SDK or n8n. LangGraph stays `experimental` (the
executor and a real `StateGraph` are exercised, the autonomous loop is reported
as skipped rather than faked), n8n stays `unavailable`, and the loopback HTTP
bridge stays `experimental` because no run through n8n's own client exists.

## The three limitations a user will actually meet

1. **The language guests are not published yet.** `ephemora run script.py`
   works when a guest is supplied — from a local wheelhouse, a recipe build or
   an explicit `EPHEMORA_*_GUEST` pin — and fails closed when it is not.
   `pip install "ephemora-cell[python]"` resolves only after the guest
   distribution is published; the extra exists, the public index entry does not.
2. **The GitHub Action has never run on a GitHub runner for this candidate.**
   The definition and its demo exist; the execution does not.
3. **n8n is not proven end to end.** The bridge, its token requirement and the
   node import are tested; a real agent-driven loop through n8n's own client is
   not, and is not claimed.

Everything else in the table above is either exercised by an acceptance test in
this repository or marked honestly as not.
