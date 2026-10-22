# Release assurance — what was measured, in which installation state

Moved out of the README on 2026-10-05. The README states the release gate in one
sentence; this file carries the numbers with their conditions, because the same
commit produces different counts depending on how it was installed and what the
host is doing. **A number without its conditions is not a measurement** — that is
the reason this page exists.

## v1.2.0 — five states, every one re-measured 2026-10-22 on the 1.2.0 tree

Qualified runtime `wasmtime 49.0.4.post1+git.2c2970205f`, `pytest 8.4.2`,
`pytest-cov 7.1.0`, Python 3.12.13, macOS arm64. **1,802 tests are collected in
every state below** — collection does not depend on the installation, only the
pass/skip split does. Reproduce row 1 with `python -m pytest tests/` in a fresh
checkout; reproduce rows 3–5 with the venv's own `pytest` console script (a
console script leaves the working directory off `sys.path`, so the code under
test is the installed wheel — `python -m pytest` there would silently test the
checkout's source instead, which is what the first measurement of this table did
and what its old "from `/tmp`" wording hid).

| Installation state | Result | Why it differs |
|---|---|---|
| Fresh checkout, no packaged language guest, no wheel in `dist/` — the shape CI runs | **1775 passed / 27 skipped** · 88.38 % of 6,599 statements (5,832 executed, 767 unexecuted) | the canonical number; `CHECK_TEST_COUNT_STRICT=1 python scripts/check_test_count.py` is the gate on it |
| The same checkout after the wheel and sdist were built into `dist/` | **1776 / 26** | `tests/test_distribution_guard.py` scans the built `dist/` instead of skipping |
| Wheelhouse install of core + qualified runtime + **both** packaged guest wheels, suite run by that venv's `pytest` against the installed wheel | **1773 / 29** | the three `test_lang_guest.py` resolver legs and `test_lang_unified.py`'s missing-entrypoint leg assert the refusal that happens only where NO packaged guest exists, so they skip there; one `test_cli_new_commands.py` leg goes the other way because the guest it expected to be missing is now installed |
| The same install with `EPHEMORA_PY_COMPONENT_GUEST` / `EPHEMORA_JS_INTERPRETER_GUEST` pinned (with their `_SHA256` pins) | **1785 / 17** | the bring-your-own-guest round-trips run for real |
| Unqualified `wasmtime 49.0.0` development venv **with** `EPHEMORA_ALLOW_UNQUALIFIED_RUNTIME=1` | **1772 / 30** | the runtime gate refuses guest execution on an engine outside the qualified line or on a native binary that is not the qualified build; the hatch is the one documented way such a machine runs at all, and every run it allows is stamped `unqualified_runtime_allowed: true` |

Without the hatch the last venv is red by design (the execution legs are refused),
and its count is not comparable to the release gate and is not offered as one. All five rows were
measured for this release rather than derived from one another; the earlier practice
of carrying a state forward by arithmetic is what this table exists to prevent.

Every row above was re-run after the last code change, in this order: matrix
(3.10.20, 3.11.15 and 3.13.14 — each **1775/27**, rc=0;
3.12.13 canonical **1775/27** in the clean 3.12 venv, while the guest-carrying
3.12 venv reads 1773/29), then A, B, C, D, E. Each matrix venv has the core
wheel installed: two legs exec the `ephemora` console script and
`examples/signed_record_demo.py` as a subprocess, so a venv that only carries the
engine fails those two for want of an installed package — a venv shape, not a
product defect. One row changed a test while being measured: the
hatch venv exposed two assertions that pinned the old version-only refusal; they
now accept the exact-binary refusal or the line refusal, and the row was re-run
from scratch.

Rows 3–5 are measured by that venv's own `pytest` console script run from a
checkout, not from `/tmp`: the console script leaves the working directory off
`sys.path`, so the code under test is the installed wheel while the repository
guards still find `scripts/` and the manifests. Running the suite from a `/tmp`
copy of `tests/` alone cannot work at all — the repository guards read `scripts/`
at import time and abort during collection (see "The sdist is a build input"
below); running it with `python -m pytest` from the checkout silently tests the
checkout's source instead of the installed wheel, which is what the first
measurement of this table did.

## The release gate, as measured on a fresh clone of the release commit

v1.1.0 (`75b7bc2`, signed tag, PyPI 1.1.0): **957 passed / 4 skipped**
(961 collected) · **89.98 %** statement coverage, shown as 90 % (Cell + MCP, CI
gate ≥ 80 %) · 8/8 attack vectors blocked (default posture, WASI Preview1 path) ·
71-pass official wasi-testsuite conformance (pinned, 1 documented expected-failure, 0 fail) · `pip-audit` clean
against the pinned `wasmtime==47.0.1` · statelessness probe at 0 leaks on the
three execution paths it sweeps (engine pool, per-run engine, isolated
subprocess — the MCP stdio path is not part of that probe) · wheel-only
smoke against the installed artifact (48/48 checks, result recorded in the v1.1.0
GitHub release body) · sdist clean-room container run. CI-enforced on every push:
tests, coverage, pip-audit, SBOM, bandit, official MCP SDK interop
([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)).

The pass counts below are **not** the suite weakening. Three figures describe three
installation states.

## CI runtime bootstrap and the macOS 15 runner (2026-10-22)

The five required CI legs used to resolve the qualified runtime through a
`--find-links` URL that did not exist. The replacement is one versioned HTTPS
asset plus a fail-closed script; the runner label moved off the image GitHub is
retiring.

**Runner.** GitHub retires `macos-14` (arm64) on **2026-11-02**, with brownout
windows from 2026-10-05 (including 2026-10-23/24) in which jobs on that label
fail on purpose — [actions/runner-images#13518](https://github.com/actions/runner-images/issues/13518).
The runner-images table lists `macos-15` as the **arm64** image;
`macos-15-intel` is the x64 label. Every macOS job in `ci.yml`,
`action-demo.yml`, `core-spec.yml`, `fuzz.yml` and `wasi-conformance.yml` now
uses `macos-15`. `build-recipes` stays on Ubuntu and stays deliberately red: it
is not in `release-gate`, and Linux is not qualified for 1.2.x.

**Runtime asset.** `scripts/ci_runtime_bootstrap.py` downloads exactly this
versioned asset (published 2026-10-22; a 404 is a red leg):

```
https://github.com/MichaelS1011/ephemora-cell/releases/download/wasmtime-runtime-49.0.4.post1/wasmtime-49.0.4.post1+git.2c2970205f-py3-none-macosx_11_0_arm64.whl
```

It accepts the download only when **all** of these hold, checked before pip sees
the file and again after installation:

| Check | Value |
|---|---|
| wheel name | `wasmtime-49.0.4.post1+git.2c2970205f-py3-none-macosx_11_0_arm64.whl` |
| wheel sha256 | `5d1ac8807b9d99d3d6824560d729bf11f93c8b348590d7547557d2345bd0865e` |
| embedded `_libwasmtime.dylib` sha256 | `247c1529445001f4b6ed1d46d4f3b4a2c67f8a0c568c9e6559500eb1a89ca30b` |
| version / licence | `49.0.4.post1+git.2c2970205f` / `Apache-2.0 WITH LLVM-exception` |
| interpreter | `platform.machine() == "arm64"` and the platform tag is `macosx-<version>-arm64` or `-universal2` (a native arm64 or universal2 build); the host must report macOS 11.0 or newer |

The URL must be HTTPS; the download is size-bounded; pip runs with
`--no-index --no-deps --force-reinstall`; the temporary wheel is deleted. There
is no index fallback, no local cache and no downgrade to 49.0.0. `--wheel` is
only for the local release audit and is subject to the same checks. A mirror
needs a reviewed change to the script's `DEFAULT_URL` and `ALLOWED_HOSTS`
constants — no URL is read from the environment — and the script still rejects
any wheel whose sha256 differs.

**Status, stated rather than assumed.** The `49.0.3.post2` asset remains
published under its immutable tag for history, but it is **withdrawn**: the
aarch64 `br_table` escape GHSA-mghf-wjfp-p5xm was confirmed on it with a native
crash on this hardware. The 49.0.4 wheel above is assembled and qualified
locally but **not published**; its planned tag is
`wasmtime-runtime-49.0.4.post1`, and the bootstrap pins that URL, so CI fails
closed (404) until a founder-authorized release exists. No completed
`macos-15` run is claimed as measured. The local
qualification host reports `sysconfig.get_platform() == macosx-26.0-arm64` and
the same wheel/native digests. Linux and DGX runs remain historical, dated
evidence — not a qualification of this build.

**Provenance limit.** Making the asset reachable proves where the bytes were
published, not how they were built. There is no committed native build recipe
and no byte-reproducible rebuild; [runtime_provenance.md](runtime_provenance.md)
keeps that limit explicit, and the release asset does not change it.

## Three installation states, three honest numbers

| Installation state | Result | Why it differs |
|---|---|---|
| Checkout with `requirements.txt` + the `tools-signing` extra (`cryptography>=42`) — the environment CI uses on both legs | **957 passed / 4 skipped** (961 collected), 89.98 % | every Ed25519 path runs |
| Checkout **without** `cryptography` | **850 passed / 66 skipped** (916 collected), 81 % | 62 skips are `importorskip("cryptography")` paths — signed tool manifests, governed loading, signed receipts, grant authentication. 61 are individual tests plus one module-level skip of `tests/test_grant_trust.py`, whose 46 tests leave the collection and are replaced by that one skip entry (961 − 46 + 1 = 916) |
| Unpacked **sdist** in a clean `python:3.12-slim` container (linux/amd64, root) | **773–778 passed / 138 skipped / 0 errors**, 0 failures on a quiet host | the sdist additionally skips nine repository-inspection modules by design; the range spans the last four commits of the 1.1 line deliberately — pinning it to one commit would make the sentence false the moment the commit changes |

Signing paths in the second row are *unverified-by-absence*, not passing. That is
the difference between a skip and a green.

## Published wheel vs. current source: which control is where

The two builds answer to the **same version string** and do not carry the same
controls. `1.1.0` was cut on 2026-10-05 (`75b7bc2`, signed tag, the wheel on
PyPI); the isolation-gate and attestation work merged to `main` afterwards
(`5d3650a` gate, `ec5d3d3` attestation, both 2026-10-12), and `main` keeps
reporting `1.1.0` until the next release bumps it. **A version number therefore
cannot tell the two apart — only a commit SHA can.** Anyone reproducing a
security claim installs from source at a pinned commit, never from the index.

Measured on 2026-10-12 by unpacking the published artifact
(`ephemora_cell-1.1.0-py3-none-any.whl`, sha256
`94cf392f8c984414dfe912d7f98b2aaf262758e49508ab9650748492ec989d58`, 30 Python
modules) and grepping it, against `git grep` on the same names at the tag:

| Control | Published `1.1.0` wheel | `main` after the release |
|---|---|---|
| Fuel / memory / wall-clock / output walls, Preview1 + component execution, egress grant signing (ADR-013) | present | present |
| Central enforcement gate — untrusted/unknown `component` forced to subprocess, run refused if the worker is gone (ADR-015) | **absent** (`TRUST_UNKNOWN`: 0 of 30 modules) | present |
| Host-owned trust allowlist, byte-bound, empty-by-default (`trusted_tools`) | **absent** | present |
| Receipt names the path/ABI that actually ran, and whether the sync blockade was effective (`execution_mode`, `abi`, `sync_blockade_enforced`) | **absent** | present |
| The gate's own negative test (`tests/test_isolation_gate.py`) | **not in the release tree** (added on `main`) | present |

Machine-checkable discriminator (exit `0` = source build with the gate, exit `1`
= published wheel). Note that no installed artifact ships tests — the wheel
contains `ephemora_cell/` and `ephemora_cell_mcp/` only — so every gate or
escape-matrix check needs a repository clone, whatever build is under test:

```bash
python -c "from ephemora_cell.execution_report import TRUST_UNKNOWN"; echo $?
```

This is a **documentation-and-evidence gap, not a defect in the release**: the
1.1.0 wheel does what its own release notes say. The gap matters only when a
claim written against `main` is read back onto the installed package — which is
why README's claims about the gate carry their build scope, and why the next
release must re-stamp this table with its own tag and digests.

One consequence cannot be fixed before that upload: the **published PyPI page for
1.1.0 still shows the old maturity metadata** (`Development Status :: 5 -
Production/Stable`, plus the README snapshot taken at upload time, which carried
the single green status badge). Release files are immutable once published, so
metadata and description change only with a new release — the repository at the
commit you are reading is the authoritative text, not the package index page.

## The four toolchain skips are not symmetric

Of the 4 toolchain skips in [`tests/test_builder.py`](../tests/test_builder.py),
three run because a toolchain element is **missing** (`WASI_SDK_PATH`, `asc`, `go`)
and one is **inverted**: the `.zig` *guidance* test skips when zig is *installed*,
because then the build is real and the guidance path is unreachable.

Measured 2026-10-05 with `zig` masked out of `PATH` and the rest of the toolchain
intact: `tests/test_builder.py` gives **20 passed / 4 skipped with zig present**
(the guidance test skips, `test_builder.py:337`) and **20 passed / 4 skipped
without zig** (the build-and-run test skips, `test_builder.py:232`). A different
test carries the fourth skip; the totals are invariant.

## Host load: the Python guest under measured contention

Measured 2026-10-21 on the then-qualified, now-withdrawn runtime (`wasmtime
49.0.3.post2+git.1d21c90f`; not re-measured on 49.0.4), with the
19,812,760-byte Python component guest and three runs per profile on a 10-core
macOS arm64 host:

| Profile | Added load | Wall per run | Worker CPU per run | Result |
|---|---|---|---|---|
| P0 background | none added (host already at load ~5.4 from an editor/UI and a headless browser) | 1.23–1.25 s | 7.87–7.99 s | 3/3 success |
| P1 | 6 × `nice -n 5` CPU hogs | 2.00–2.15 s | 8.00–8.12 s | 3/3 success |
| P2 | 10 × `nice -n 5` CPU hogs | 2.28–2.41 s | 8.01–8.08 s | 3/3 success |

The compile dominates: a standalone compile of the same guest takes **7.71–7.89 s
CPU** in **1.14–2.10 s wall** (parallel Cranelift), while execution and worker
startup add roughly **0.1–0.4 s CPU**. The wall growth from P0 to P2 is scheduling
wait, not extra CPU. The interpreter profile's `io_cpu_seconds=30.0` budget kept
about **22 s of headroom** in every measured run; no false rejection occurred in
9/9 runs.

The baseline report's much heavier profile (~4 GB of foreign `/tmp` traffic, load
~40 on 10 cores) did reject every run at 30.07 s absolute worker CPU, with 33.54 s
attributable to the run. That is a documented **operational limit**, not a normal
supported condition: under it the compile alone exceeds the 30 s CPU budget. A
compile cache is technically effective — `Component.serialize()` produced a 38.8 MB
blob in ~20–30 ms, and `Component.deserialize()` costs ~0.2–0.36 s wall and
~0.2–0.32 s CPU under the same load — but it is a behaviour and trust-boundary
change (host-owned, guest-inaccessible, digest-keyed, atomic) and is not part of
1.2.0. The execution budget was not loosened. The sdist container run can still
report up to **two failures under contention** for the same accounting reason;
those tests pass standalone and natively.

## What is machine-checked and what is not

[`scripts/check_test_count.py`](../scripts/check_test_count.py) checks the
documented counts against `pytest --collect-only`, so the release-count sentences
cannot drift from the code. **The prose figures around them — coverage %, the
minimal-install and container counts, and every latency number — are re-measured by
hand at each release, not by the guard.** That is a known limit of this file, and
the reason each of them carries its date and its conditions.

[`scripts/distribution_guard.py`](../scripts/distribution_guard.py) is the
confidentiality gate over the two surfaces the tracked-tree check cannot see:
the git history reachable from a ref, and the built wheel and sdist. In CI it
runs two ways — `history --ref <base>..HEAD` fails closed if any commit new to
a push or pull request introduces an internal path (a file committed and later
deleted stays publicly reachable through history), and `artifacts dist/*`
builds the wheel and sdist and fails if any forbidden internal path or content
rule is present inside a packaged member. A release must run `artifacts` after
building and before upload; a clean result is required evidence that the
distribution ships only product, engineering and public-safe tests.

## Integration paths: the command, the expected answer, and how deep the check goes

Every surface a caller can reach, with the command that exercises it and where the
proof lives. The distinction that matters is between a **suite leg** (runs on every
`pytest`, so a regression fails the build) and an **explicit integration gate**
(needs an extra package, a model endpoint or a second process; run by hand or in a
dedicated CI job, and stated as such rather than counted among the suite totals).

| path | command | what a correct answer looks like | depth |
| --- | --- | --- | --- |
| library, module | `WASISandbox().run(module.wasm)` | `ExecutionResult` with `status`, budgets and `guest_exit_observed`; refusal before any guest on an unqualified engine | suite (`tests/test_sandbox.py`, `tests/test_guest_exit_code_fidelity.py`) |
| library, language | `run_python(path)`, `run_javascript(path)` | adapter dict with the shared result base and `exit_status_fidelity` naming what the ABI can deliver | suite with stubs (`tests/test_adapter_result_shape.py`, `tests/test_lang_unified.py`); real guests behind `EPHEMORA_PY_COMPONENT_GUEST` / `EPHEMORA_JS_INTERPRETER_GUEST` |
| CLI, execution | `ephemora-cell run guest.wasm --json` | one document shape on every route, `error_class` + `exit_status_fidelity` inside it | suite (`tests/test_cli.py`, `tests/test_error_contract.py`), plus a clean-install smoke against the built wheel |
| CLI, diagnosis | `ephemora-cell doctor --json` | schema `ephemora-cell/doctor/1`; the runtime line reported by the same verdict the execution gate uses | suite (`tests/test_doctor.py`) |
| CLI, evidence | `ephemora-cell verify record.json [--signing-public-key]` | `0` verified, `1` failed verification, `3` signed-but-unverifiable-here | suite (`tests/test_execution_record_integrity.py`, `tests/test_error_contract.py`) |
| CLI, policy | `ephemora-cell policy check --json` | the same posture the next run attests; a refusal never reads as success | suite (`tests/test_policy_cli.py`) |
| MCP stdio, registered tools | `ephemora-cell-mcp --tools-dir DIR` + `tools/call` | a real WASM run with `_meta.execution` accounting; unknown tool is an error, never a fabricated result | suite in-process (`tests/test_mcp_adapter.py`); official SDK client as an explicit gate (`integration/test_mcp_sdk_client.py` and the agent-to-sandbox E2E `integration/test_agent_code_execution_mcp.py`, both in the `mcp-sdk-interop` job, both need `pip install "ephemora-cell[integration]"`) |
| MCP stdio, governed load | drop `<name>.tool.request.json` into `--tool-requests-dir` | host-signed, digest-matching modules install mid-session; unsigned, wrong-digest or outside-path proposals stay refused and stay on disk with a reason | suite (`tests/test_tool_signing.py`) + the SDK gate with a live server process |
| MCP over HTTP (n8n) | `python -m ephemora_cell_mcp.http_bridge …` | authenticated loopback; 401 anonymous/forged, `421` foreign Host, timeouts returned as errors with the socket alive | suite (`tests/test_mcp_http_bridge.py`); the n8n-side rows in [docs/n8n-integration.md](n8n-integration.md) |
| LangGraph | `python integration/agent_frameworks/test_langgraph.py --json` | a real `StateGraph` runs WASM per node; the heavy workload comes back `fuel_exhausted`, `blocked: true` | explicit gate (needs `langgraph`) |
| OpenAI Agents SDK | `python integration/agent_frameworks/test_openai_agents.py --json` | `tool_binding_verified: true`, tool execution `success`, arbitrary paths denied; the LLM loop reports `skipped` with its reason unless a model endpoint is configured | explicit gate (needs `openai-agents`; the model loop needs an authorized endpoint) |
| n8n agent loop | import `examples/n8n_ephemora_mcp_workflow.json`, chat → agent → tool | not proven: no authorized model endpoint on the test machine | **NOT VERIFIED** — stated in [docs/n8n-integration.md](n8n-integration.md), no mock substituted |
| GitHub Action | the composite run block of `action/action.yml`, read out of the file and executed with `bash` against real installs | benign module `success`; `fuel_bomb.wasm` at `fuel: 100` → `fuel_exhausted`, `fuel_consumed == 100`; a caller-class refusal and an engine outside the qualified line both fail the step, the latter as `error_class=environment` naming the runtime | explicit release check (the block executed verbatim on this host, evidence kept off-tree). `.github/workflows/action-demo.yml` runs the action against the **published** package on every push; no job of this candidate has executed on a GitHub-hosted runner |

A gate that could not run is reported as not run, with what it did prove in its
place. That is the difference between a green suite and a claim a reader can act on:
`pytest tests` never silently includes the framework gates, and none of them
disguises a missing dependency as a pass.

## The sdist is a build input, not a test target

Measured 2026-10-20 on the unpacked `ephemora_cell-1.2.0.tar.gz`: `pytest tests/`
**cannot start** there. Nine modules abort during collection because they read
`scripts/` at import time (`test_version_sync_guard`, `test_release_identity`,
`test_public_content_guard`, `test_distribution_guard`,
`test_benchmark_guard_routes`, `test_conformance_evidence_identity`,
`test_agent_executor_confinement`, `test_js_guest`, `test_python_guest`), and a
collection error is raised before `tests/conftest.py` can apply its
"requires a source checkout" skip — that hook runs on the collected items, not on
the import.

The two inputs two *other* acceptance modules read at import time
(`product_contract.json`, `examples/*.wasm`) are shipped in the sdist, so those
two are not part of the nine; without them the same run reported ten.

What this means in practice: the wheel is the test target (`pip install` it and
run the suite against the installed package), and the sdist is the input the
wheel is built from. The nine modules are repository guards — they check the
scripts, the git history and the release manifests, none of which exist in a
tarball. Anyone who wants to run them unpacks the tarball inside a checkout or
uses the repository itself. This paragraph exists because the MANIFEST used to
say the sdist ships "what the shipped tests need", which was true of the
fixtures and false of the guards.

## The two CycloneDX documents are reproducible — in the sense the property names

`sbom/ephemora-cell-1.2.0.deps.cdx.json` and `…runtime.cdx.json` carry
`cdx:reproducible: true` in `metadata.properties`. The CycloneDX property
taxonomy defines that property narrowly: *"whether the CycloneDX document has
been generated in a reproducible manner: if so, then time- or random-based
values MUST be omitted, and elements order SHOULD be reproducible."* It is a
statement about **the document**, not about the software build and not about the
qualified Wasmtime wheel (that one is pinned byte-for-byte in
`requirements.lock` and by the native-library digest in the release manifest).

Measured 2026-10-22 from the release set's own wheelhouse, with the generator CI
pins (`cyclonedx-bom==7.5.0`), twice per document:

```bash
# deps: core + qualified runtime only, from the set's own wheelhouse
uv venv /tmp/sbom_deps
uv pip install --python /tmp/sbom_deps/bin/python --no-index --require-hashes \
    --find-links <release set> -r <release set>/requirements-release-core.txt
# runtime: the same set plus both guest wheels and the CI test dependencies
uv venv /tmp/sbom_run
uv pip install --python /tmp/sbom_run/bin/python --no-index --require-hashes \
    --find-links <release set> -r <release set>/requirements-release.txt
uv pip install --python /tmp/sbom_run/bin/python pytest==8.4.2 pytest-cov==7.1.0 cryptography

cyclonedx-py environment --output-reproducible -o /tmp/deps.cdx.json    /tmp/sbom_deps
cyclonedx-py environment --output-reproducible -o /tmp/runtime.cdx.json /tmp/sbom_run
cmp /tmp/deps.cdx.json    sbom/ephemora-cell-1.2.0.deps.cdx.json
cmp /tmp/runtime.cdx.json sbom/ephemora-cell-1.2.0.runtime.cdx.json
```

Both documents regenerate **byte-identically** (sha256
`518edc1e475d4ef1616d73187eed55b000d4e9a498a06effd41af296dd6492d0` and
`0f0c34237a83841721aefd2e73cd84dca0ffedc45ae4064be3a2fb42482f9d95`), with no
`serialNumber` and no `timestamp`, and the bytes equal the tracked files — so the
property is not merely legal, it is reproduced. The documents identify components
by purl and version; the **byte** identity of the release artifacts lives in
`release_manifest.json` and `SHA256SUMS`, not here.
