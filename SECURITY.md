# Security Policy

## Public Security Release Status

One glanceable status for developers, customers and external security reviewers. It
consolidates what is **published**, what was **actually tested**, and what is **not yet
approved**. Each line points at committed, machine-checkable evidence — it is a signpost, not
a substitute for the section it links to. Nothing here is a production-security authorisation.

### At a glance

| What a reviewer needs to know | Status | Where to verify |
|---|---|---|
| Publicly available version | **`1.1.0`** on PyPI (wheel + sdist), BUSL-1.1 | [PyPI project page](https://pypi.org/project/ephemora-cell/) · [CHANGELOG](CHANGELOG.md) |
| Software actually tested | source at the frozen security-base commit **`284b577`** (product tree byte-identical to `7303274`) | `benchmarks/results/2026-10-14/release_identity.json` |
| Native runtime tested against | the **controlled build on the 49.0.4 fix line** (embedded `_libwasmtime.dylib` sha256 `247c1529…a30b`), assembled from the official Bytecode Alliance C-API 49.0.4 asset and pinned by wheel/native digest — engine patch parity for the async class **not independently verified** (see the GHSA-32h6 notes); CPython 3.12 CI/lab interpreter. The previously published `49.0.3.post2` build (`ab4f1ea6…0fb73`) is **withdrawn** and no longer accepted by the gate | `requirements.lock` · release-identity records → `native_runtime` |
| Conformance | pinned wasi-testsuite: 71 pass / 1 documented by-design expected-failure / 0 fail of 72 executed (55 preview-3 tests skipped) · official core spec: 31,896 pass with **81 failing commands across 15 files** (27 unsupported proposals, 51 harness gaps, 3 `local_init` cases still unclassified); those command totals cover the 157 of 257 files that produced per-command results, 684 test cases were skipped, and 100 files aborted before measurement (44 pinned `wast2json` parse refusals, 56 wasmtime-py v128 binding aborts) and contribute one file-level deviation each — re-measured on the qualified **49.0.4 runtime (2026-10-22)**; **standards conformance, not full-suite coverage and not a security certification** | [conformance/README.md](conformance/README.md) |
| Last reproduced Linux run | **2026-10-13** on a native Linux **aarch64** reference host (Ubuntu 24.04): blocked-worker OS-wall probe holds; plus an `sdist` clean-room `linux/amd64` container run — predates the 1.2.x qualification; not transferable | `benchmarks/results/2026-10-13/native_linux/` · `linux_reference_boundary_probe.json` · [docs/release_assurance.md](docs/release_assurance.md) |
| Supported workloads | untrusted code compiled to **WASM** — WASI Preview1 modules and WASI 0.2 components; the subprocess path (`run_isolated()` / `use_subprocess=True`) for guests that must not run in-process; MCP tool server | [Execution paths](#execution-paths--which-control-runs-where) |
| Platforms qualified for 1.2.x | **macOS arm64** only, measured against the 1.2.0 candidate runtime; Linux, Windows, musl/Android **NOT QUALIFIED** — no release evidence claimed there | “Supported platforms (1.2.x)” note below |
| Excluded / out of scope | **native worker compromise (A7): after an engine escape turns input into arbitrary native code, the worker has the same-user files, environment and network; the worker is a crash/containment boundary, not an OS sandbox**; local write access to the installed package (A8); multi-tenant isolation between concurrent modules in one process (single-tenant; a tenant is a billing identity, never a security boundary); guest network or process spawning (none exposed, by design); cryptographic memory zeroing; in-process execution of untrusted guests | [Scope](#scope) · [Known Limitations](#known-limitations) · [threat model](docs/threat-model.md#native-worker-compromise-a7) |
| Open risks (not closed) | on the **shipped artifact** (`247c1529…`, engine 49.0.4 fix line): the loader-excluded async component class (GHSA-32h6 — engine patch **not independently verified**) and the documented info/availability classes (GHSA-96f6, preview0/WASIp3 gates); I/O syscalls bypass fuel metering. The 2026-10 aarch64 `br_table` escape (GHSA-mghf-wjfp-p5xm) is **closed** by this build and was measured on the withdrawn one. The `49.0.0`-line statements below and their "no wheel on PyPI" notes document the intermediate `49.0.0` development pin (moved from `47.0.1` on 2026-10-12, after the 1.1.0 release) and the plain-`pip` path; they no longer describe the shipped runtime asset. | [Known Limitations](#known-limitations) · [Dependency & Upgrade Policy](#dependency--upgrade-policy) · [published vs. source](https://github.com/MichaelS1011/ephemora-cell/blob/main/docs/release_assurance.md#published-wheel-vs-current-source-which-control-is-where) |
| Independent external security audit | **None yet** — no third party has certified or audited Cell; the badge is *security-evaluation-pending* | [README](README.md) · this file |
| Production release | **NO-GO** — see *Why there is no production GO* below | — |

### 2026-10-22 P0 — aarch64 `br_table` escape, runtime withdrawn

GHSA-mghf-wjfp-p5xm (critical, CVSS 9.9, published 2026-10-19) affects
Wasmtime/Cranelift on aarch64: a `br_table` with more than roughly 256k targets
can branch to an incorrect target, i.e. to arbitrary code. The published
`49.0.3.post2` runtime was affected. Measured on this host: a 300,000-target
module compiled on that build and the default-index call killed the process
with SIGBUS, while index 0 returned correctly; the 49.0.4 build rejects the
same module at translation time (`exceeds the implementation limit of 65520`).
The 49.0.3.post2 asset remains published for history (immutable), but the gate
floor and the bootstrap pin have moved to 49.0.4; nothing accepts the old
runtime silently. Measurements in this file that name `ab4f1ea6…` are dated
evidence for the withdrawn build, not statements about the shipped runtime.

### Release identity — four distinct states, not one version string

A version number cannot tell these apart; only a commit SHA and an artifact digest can.
Anyone reproducing a security claim installs **from source at a pinned commit**, never from
the index ([why](https://github.com/MichaelS1011/ephemora-cell/blob/main/docs/release_assurance.md#published-wheel-vs-current-source-which-control-is-where)).

| State | What it is | Authorisation |
|---|---|---|
| **Published PyPI `1.1.0`** | the immutable wheel/sdist on the index (sha256 `94cf392f…` / `f4ec76bb…`) | shipped & published; its index page still carries stale `Production/Stable` metadata — the repository `4 - Beta` at the commit is the authoritative text |
| **Frozen security base `284b577`** | the commit every pilot/readiness decision binds to | technical build of record; **not** re-published (its rebuild digests differ from the index, as expected for a different commit) |
| **Evidence commit `a136745`** | the doc/evidence commit that tracks the release-identity JSONs for `284b577` | product code byte-identical to `284b577`; no functional change |
| **Planned 1.2.0 release candidate** | the next release candidate, **not yet released** | carries a PEP 440 label, so `release_identity.py` marks it `publishable: false` by design until it is cut clean |

### `publishable` — what the flag does and does not mean

In `scripts/release_identity.py`, `publishable` is **true only** when the working tree is
clean, all version sources agree, distribution artifacts are present, **and** the version
carries no PEP 440 pre-release/local label. It is a statement of *technical well-formedness*
(this build could be uploaded), computed from source state — **not** a release
authorisation, not an audit result, and not evidence that a pilot VM accepted anything. A
labelled candidate is deliberately `false` so a source-built verification artifact can never
be mistaken for the released one.

### Why there is no production GO

A green suite (2171 passing / 44 skipped, 85.08 % statement coverage, measured 2026-10-27 in a fresh checkout of this candidate on the qualified 49.0.4 runtime — on a 49.0.0 development venv the previous candidate reported 1772/30 only with the documented escape hatch set, and is red without it, because the gate refuses to run guest code on an engine outside the qualified line or on a native binary that is not the qualified build rather than pretending to be the audited configuration; the pre-run grant claims of `policy check --language` are backed by a tracked run-side measurement in `benchmarks/results/2026-10-19/language_grant_views_measured.json`), the conformance runs and the blocked-worker
probes establish **laboratory correctness of the tested commit** — they are not, and do not
automatically become, a production-security approval. General production stays NO-GO until,
at minimum: an independent external evaluation is completed; the newest isolation controls
ship in a published release; a dedicated pilot VM is provisioned and accepts the workload
(currently **NOT TESTED**); and an available runtime closes the pinned-line advisories. None
of those is cleared by CI passing. Known limitations and any `UNKNOWN` posture above stay
listed with their reason — they are not folded away by a summary badge. Every attack scenario
actually run — its class (blocked / bounded / contained / allowed / unresolved / unknown /
not-tested), boundary, commit, runtime and platform — is consolidated in
[docs/security_attack_matrix.md](docs/security_attack_matrix.md); the numbers there are per
boundary and are deliberately **not** summed into a single "vectors blocked" score.

**Supported platforms (1.2.x).** macOS arm64 is the qualified platform for this
release: the filesystem-escape counter-checks and the worker-containment tests
were measured against the shipped runtime on this platform, and the full test
suite is green there. Linux, Windows and musl/Android builds are **NOT
QUALIFIED** for 1.2.x — no release evidence is claimed for them, and evidence
measured on macOS is not transferred; the container reference for an
authorized Linux qualification lives in `deploy/linux-reference/`.

**CI runner.** The five required legs run on `macos-15` (arm64). GitHub retires
the `macos-14` image on 2026-11-02; `macos-15` is the arm64 image and
`macos-15-intel` is x64. The runtime bootstrap refuses an interpreter that does
not run natively on arm64 (arm64 or universal2 on Apple Silicon) and a host
older than macOS 11.0, so an x64 or Rosetta runner cannot pass. The first
`macos-15` run stopped in the runtime bootstrap before any test ran: the
runner's universal2 interpreter reports its 10.13 deployment target, not the
host version. On the release-candidate branch the GitHub run of the head commit
is the binding record; a local run is quoted with its environment and is not
offered as a substitute for it. The local qualification host is macOS arm64
(platform tag `macosx-26.0-arm64`).

**The VM backend is a second wall, not a stronger version of the first.** On
macOS arm64 the CLI can run a job inside a Linux VM created through Apple
Virtualization.framework (`--backend vm`), with the module or script crossing a
dedicated serial channel under a host mediator. It is off by default, needs the
operator's VM assets, refuses a run without them instead of falling back to the
native worker, and does **not** issue a signed execution record yet (`--evidence`
is refused on that path). Its security position, per backend and per profile, is
in [docs/platform_support.md](docs/platform_support.md) — including the Linux
side, where no OS-level isolation is claimed because the probe did not establish
the boundary on the tested host.

## Supported Versions

| Version | Supported | Notes |
| ------- | --------- | ----- |
| 1.1.x   | ✅ Yes | Current — source-available under BUSL-1.1 |
| 1.0.x   | ✅ Yes | Mixed licence inside the line: ≤ 1.0.4.3 Apache-2.0, 1.0.5 and later BUSL-1.1 |

Earlier internal milestones (pre-public, 2026-08) are not published and
not supported — upgrade to the current release. Fixes are developed on the
current release; where an advisory names an older version, that is because the
mitigation shipped there, not because the old line still receives updates.

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in Ephemora-cell, please report it responsibly.

**Do NOT open a public GitHub issue.**

### How to Report

**Preferred: GitHub Private Vulnerability Reporting** — open the
[Security tab](https://github.com/MichaelS1011/ephemora-cell/security/advisories/new)
and file a private report. It stays confidential (visible only to the
maintainers), supports the coordinated patch/disclose workflow, and credit
is handled inside the advisory.

**Secondary channel:** LinkedIn DM to Michael Soppa — https://www.linkedin.com/in/michael-soppa
(only if GitHub is not an option for you).

Please include:
- A clear description of the vulnerability
- Steps to reproduce the issue
- Potential impact assessment
- Any suggested mitigation (if applicable)

### What to Expect

- **Acknowledgment:** Within 48 hours
- **Initial Assessment:** Within 5 business days
- **Resolution Timeline:** Depends on severity (Critical: 7 days, High: 14 days, Medium: 30 days)
- **Credit:** We acknowledge responsible disclosers in our security advisories (unless you prefer anonymity)

These are the intervals we work to, not a contractual service level: the maintainer
is a single person, the Licensed Work is provided on an "AS IS" basis, and nothing in
this document creates a support obligation or a warranty of any kind.

### Scope

**In Scope:**
- WASM escape vulnerabilities (guest-to-host breakout)
- Preopen directory bypass (`/dev`, `/proc`, `/sys` access)
- Memory limit bypass
- Fuel metering bypass leading to DoS
- Network access through WASI Preview1 sandbox
- Path traversal attacks via preopened directories

**Out of Scope:**
- I/O rate limiting (I/O system calls bypass fuel metering) — known limitation, documented
- CPU-DoS within fuel budget — by design (guest must compute)
- Social engineering / phishing
- Missing features (e.g., no memory zeroing, no network proxying)

### Known Limitations

Ephemora-cell is an isolated WASM sandbox, not a full security enforcement platform. Documented limitations include:

- **I/O costs minimal fuel:** `fd_write` calls run on the host and consume ~27 fuel/write
  on the stdout path (~1.18MB theoretical before exhaustion at default 1M fuel); preopen
  *file* writes measure ~7.3 fuel/write (`benchmarks/io_dos/`) — in both cases the shared
  10 KB output byte-budget (ENOSPC) caps captured output far earlier. NOTE (2026-09-12):
  fuel is **not cross-platform deterministic** — wasmtime charges different per-instruction
  costs per backend/arch (e.g. one `fd_write` hello measured ~16.4k units on macOS arm64
  vs ~12 total on Linux x86_64). Fuel budgets are enforced correctly everywhere; they are
  only comparable within one platform.
- **GC heap not byte-bounded:** `Store.set_limits` limits linear memory only. `WASIConfig.max_gc_heap_mb` is recorded in the security baseline (observability); wasmtime-py 47 has no GC-heap limiter binding, so fuel remains the effective GC memory bound (see `benchmarks/pocs/README.md`)
- **No memory zeroing:** WASM memory is reclaimed by the Python GC, not cryptographically wiped
- **Single-tenant:** No multi-tenant isolation between concurrent modules in the same process. `--tenant`/`TenantStore` (ADR-012) attribute consumption to an account and refuse a run whose cumulative caps are spent — a tenant is a billing identity, never a security boundary, and nothing a guest can observe changes when one is attached
- **Default execution runs in the isolated worker:** since the 1.2.0 mandate (ADR-015), `run()`/`run_wasm()` route every guest the host has not explicitly marked `trusted` — `untrusted` and unspecified `unknown` alike — onto the subprocess path for BOTH ABIs; only an explicit `trusted` run executes inside the calling process. In-process runs enforce fuel, memory cap, timeout, 10 KB output cap and the `io_budget_bytes` wall; the OS-level walls (RLIMIT_NOFILE and RLIMIT_FSIZE; RLIMIT_AS/RSS are best-effort and macOS does not enforce RLIMIT_AS; per-file `disk_quota_bytes`, `io_cpu_seconds` rusage watchdog, 32 MB module cap, hard process kill) exist only on the subprocess path. The published 1.1.0 wheel still has the old in-process default; see "Isolation is enforced, not just offered" below.
- **No network, no process spawning:** WASI Preview1 exposes no socket creation or `connect` (the handle-only `sock_accept`/`recv`/`send`/`shutdown` imports exist but cannot obtain a socket), and neither ABI exposes process-spawn APIs (by design; pinned by `tests/test_preview1_socket_surface.py`)
- **Exit status reaches the host only as far as the guest's ABI and loader let it.** The WASI-0.2 component Python guest catches `SystemExit` in its own loader, so a script calling `sys.exit(3)` is observed as `status: success`, `exit_code: 0`; the JavaScript guest reports a thrown error through its `EPHEMORA_USER_ERROR` marker and also returns cleanly (both measured on the qualified runtime). A component that hard-exits non-zero is never read as success — `std::process::exit(3)` arrives as `error` — but the component ABI carries only the non-zero fact, not the number (`exit(3)` and `exit(7)` both arrive as exit status 1, measured). The Preview1 interpreter route and a plain Preview1 `.wasm` run propagate the exact code (measured: exit `3`/`7`). Every `run` report states this as `exit_status_fidelity` (`exact` / `non_zero_only` / `none`), and `ephemora run` prints a stderr note on a `none` route; branch on the guest's own output, or pin the Preview1 interpreter, when an exit status is load-bearing — a guest's `EPHEMORA_USER_ERROR` marker stays a *guest claim* and never becomes a host verdict
- **Disk quota is per-file:** `disk_quota_bytes` (default 256 MiB) is enforced via RLIMIT_FSIZE in the subprocess isolation path — a kernel per-file cap, not a per-run aggregate; in-process runs document it as a granted capability
- **A grant speaks for the tool its signature names — on every path.** The engine
  re-keys any caller-supplied grant mapping by `grant.tool` and refuses two grants
  claiming one tool. Before this, only the loader honoured the payload: an embedder
  (or a mis-keyed directory walk) could file echo's signature under another tool's
  name and that tool was mediated on it, spending the cap of the wrong grant
  (measured: `allowed` for a tool the document never named).
- **Grants are per tool; the server-wide allowlist is still the fallback.** A
  tool without a signed grant file is mediated by `--egress-allow` alone —
  allowlist, no window, no cap, no ledger. Renaming or deleting one grant file
  therefore downgrades one tool, and `get-policy` shows the per-tool grant list
  plus `ungranted_tools`, which names the posture ("fall back to the server-wide
  allowlist" or "denied (--egress-grants-required)") rather than leaving it to
  be inferred. The strict alternative is opt-in: `--egress-grants-required`
  denies an ungranted tool instead of falling back, which is why it is a flag and
  not the default — a partially configured deployment changes behaviour.
  Related: for its tool a grant is intersected with `--egress-allow` (see
  "Egress mediation"), so a signed grant can no longer be broader than the
  server-wide list; with no server-wide list configured the grant is the whole
  authority, and `grant_scope` says which of the two is in force.
- **The engine pool is only reached when the byte wall is lifted.**
  `io_budget_bytes` is set by default and a set budget forces a per-run engine, so
  pooled-path claims (module cache, engine reuse) are exercised in the suite by
  explicitly lifting the budget (`tests/test_execution_invariants.py`), not by the
  default configuration.
- **Grant-time preopen revalidation covers forbidden canonical locations:** entries are re-realpath'd immediately before `preopen_dir`; a swap in the milliseconds between config validation and grant is skipped with a warning **only when the new target resolves into a forbidden canonical location** (`/etc`, `/private`, `/usr`, …). A swap to a different canonically *allowed* directory is still inside the operator's `allow_dirs` trust and is granted — measured 2026-10-23 in `tests/test_fs_guest_symlink_matrix.py`. A swap DURING a run (while the guest holds the fd) is outside the sandbox's control.
- **I/O budget scope (measured 2026-10-16).** `io_budget_bytes` (default 64 MiB) is
  enforced on BOTH execution paths, each against the scope it really has.
  **Preview1:** a watcher sums the run's private, initially EMPTY `sandbox_dir`
  (absolute size, fixed 100 ms poll) and, on breach, interrupts the guest via
  `engine.increment_epoch()`. **Component (WASI 0.2):** a component has no
  `/sandbox` mount, so the wall covers the directories the run actually preopened
  (`effective_preopens`) — its only writable scope — measured as a **delta**
  against a baseline taken before the guest starts, so a caller-owned directory's
  pre-existing content is not charged to the guest. On BOTH paths the scope is
  ALSO re-measured once, after the guest has stopped (the end-of-run sample).
  A breach is `ExecutionStatus.ERROR` with `io_budget_exceeded=True`. The
  preview1 text is `I/O budget exceeded: guest wrote N bytes to the sandbox dir
  (io_budget_bytes=L)`; the component text is `I/O budget exceeded: guest wrote
  N bytes into the granted directories (io_budget_bytes=L)`.
  The end-of-run sample exists because a poller CANNOT see a write that begins and
  finishes inside one interval: the sustained overshoot is what the poller
  interrupts, and the sub-interval overshoot is what the sample DETECTS at the end
  of the run — detection, not prevention: the burst is not stopped while it runs.
  The sample measures a **footprint**, not a tally of every byte ever written: it
  judges the bytes still on disk once the guest has stopped, in the same scope the
  poller sums (see above). Bytes a guest writes and then deletes leave no footprint
  to measure, so a write-then-delete burst is not caught by that measurement
  (measured 2026-10-16: a component guest that wrote 1310720 bytes and immediately
  removed them exited `success` with 0 bytes left on disk). A burst whose bytes
  remain is reported as a breach at the end of the run instead of a silent
  success; the residual footprint is what the wall bounds, not the write volume.
  The byte wall therefore contains a sustained write flood (the poller) and the
  residual footprint a run leaves behind (the end-of-run sample); neither is a
  preventive cap on the bytes a guest may ever write. On the preview1 path, granted
  preopen trees stay OUTSIDE the byte wall (a `du` delta over preopen trees is the v2
  option noted in ADR-002, not implemented); their `write()` host cost is what the
  `io_cpu_seconds` CPU wall below covers. The two scopes are deliberately NOT
  symmetric: preview1 compares the absolute size of a private dir that starts
  empty, while the component path compares a delta over caller-owned directories.
  Both are locally correct; neither form is "stricter" than the other, and the
  byte count is only comparable within one path. Passing `io_budget_bytes=None`
  turns the wall off deliberately — no watcher and no end-of-run sample; the
  default is the 64 MiB above, so the wall is absent only when it is switched off
  explicitly.
- **Orphaned run directories are not swept at startup.** The isolated worker is
  killed with `SIGKILL` — by this release's own timeout path as well as by an
  external `kill -9` or the OOM killer — and `SIGKILL` cannot be trapped, so the
  worker cannot clear its own per-run sandbox and capture directories. A repeat run
  on the SAME sandbox object does clear that object's earlier directories, but
  nothing scans the scratch root for directories left behind by a process that is
  already gone. On a long-lived host that is unbounded **disk growth, not a
  boundary break**: those directories are outside every guest's reach. An operator
  running many isolated guests on one machine garbage-collects its own scratch root.
- **Every time bound reads the system clock.** Trust-root key windows
  (`not_before`/`not_after`) are validated at load against `datetime.now(UTC)`, and
  grant windows and cap windows are evaluated against the same wall clock at check
  time (the check takes an injectable moment for tests, which is how it is
  measured, not a second clock). A clock rolled backwards can therefore keep an
  expired key or grant live: the byte/count caps still bite per call, the *window*
  does not. There is no monotonic or leased bound — that is a design question this
  release does not answer. The practical rule with the startup-only key check above:
  rotate the key **and restart the process**.
- **Verification scope, stated plainly.** Scheduled CI fuzzing
  (`benchmarks/fuzz_smoke.py`, weekly plus manual dispatch) generates random valid
  **WASM modules** — bounded instruction counts, no preopened directories — and it
  is a smoke test, explicitly not a coverage-guided fuzzer. The grant envelope, the
  trust root, the egress URL parser and the receipt verifier are **not** fuzzed by
  anything in this repository. The resource, linkage and trust invariants are pinned
  by targeted tests, **not** by property-based tests (no property framework is in
  use). No hours-long soak run is part of the qualification — the longest soak in
  `benchmarks/results/` is ten minutes (`2026-08-25/12_soak_10min.json`). Read those
  surfaces as untested depth, not as covered: a claim of "fuzzed" or
  "property-tested" would overstate what was done.

### Execution paths — which control runs where

Cell has two isolation paths, and the difference is material. Under the current
source the default is the protected one: every guest the host has not explicitly
marked `trusted` — `untrusted` or unspecified `unknown` (fail-closed) — runs in
the disposable worker, for BOTH ABIs. The subprocess path (`run_isolated()` /
`use_subprocess=True`) adds OS-level walls around that worker; only an explicit
host `trusted` authorisation executes the guest **inside your process**, where
the kernel-level walls do not apply.

#### Isolation is enforced, not just offered (ADR-015)

Some host-side defects only a **process** wall contains. GHSA-j2g9 is measured:
a `component` guest calling `fd_filestat_set_times(u64::MAX)` raises `SIGABRT`
**in the host** on the in-process path (the host dies); the same guest under the
worker only kills the worker (`ERROR` naming the worker crash, parent survives).
Fuel/wall/memory do not bite on that host-side call. So for this class the
subprocess path is no longer a recommendation — a gate at the `WASISandbox.run()`
choke-point **enforces** it, before any guest execution, across every entry point
(CLI / MCP / `run_wasm` / `abi=auto`):

- Trust is a host-side classification `∈ {trusted, untrusted, unknown}`; an
  unspecified or unknown value is `unknown`, treated as untrusted (fail-closed).
- A `component` that is not `trusted` is forced to `use_subprocess=True`; the
  gate raises the flag, it never lowers it. If the worker is unavailable the run
  is **refused** (`ERROR`), never downgraded to in-process — **no silent fallback**.
- `trusted` in-process component execution requires **explicit host
  authorisation** (the MCP `trusted_tools` allowlist); a guest cannot elevate its
  own trust from its bytes or sidecar.
- Both ABIs are mandate classes. Preview1 was originally excluded because the
  measured GHSA-j2g9 host-side abort class is component-specific, but the 1.2.0
  decision extended the gate to Preview1 as well: an untrusted/unknown module is
  forced onto the worker exactly like a component, and the in-process path
  remains only for explicit `trusted` runs.
- The mandate guards the **guaranteed public paths** (`WASISandbox.run`,
  `run_wasm`, `run_isolated`, the MCP engine, the CLI). Calling the low-level
  `ComponentSandbox` primitive directly bypasses the gate **by design** — it is
  the internal engine the gate and worker drive, explicitly not a guaranteed
  execution path, and integrators must route untrusted components through the
  facade, not the primitive.
- The signed `execution_mode` proves **which path ran the guest**; it is not a
  standalone cryptographic proof that a `trusted` in-process exception was
  authorised — that authorisation lives in the host's `trusted_tools`
  configuration, never in the receipt.
- This is process isolation, **not** full OS sandboxing (no seccomp/pledge is
  claimed), and it does **not** add a component sync blockade — see the
  attestation truth table below. **No false guarantees.** In particular, it does
  not protect against **A7**, a native compromise of the worker after an engine
  escape: that process still has the invoking user's file, environment and
  network access. The v1.2 contract and the measured Option B research boundary
  are stated in [docs/threat-model.md](docs/threat-model.md#native-worker-compromise-a7).

**Build scope.** Every bullet above describes the **current source**, not the
published release: `1.1.0` was cut on 2026-10-05 (`75b7bc2`), before the gate
merged (`5d3650a`, 2026-10-12), and `main` still reports the version string
`1.1.0` until the next release bumps it. So the published wheel has no gate to
verify, and a version number cannot tell the two builds apart. Verifying this
section means cloning at a pinned commit and running the presence check — not
`pip install ephemora-cell`. Per-build control matrix and discriminator:
[docs/release_assurance.md](docs/release_assurance.md#published-wheel-vs-current-source-which-control-is-where).

```python
from ephemora_cell import run_isolated, WASIConfig

result = run_isolated("guest.wasm", WASIConfig(max_fuel=1_000_000))
# run_isolated returns a DICT (not an ExecutionResult object) with the same
# fields plus worker-bootstrap timing:
result["status"]        # ExecutionStatus.SUCCESS / TIMEOUT / ...
result["exit_code"]; result["stdout"]; result["stderr"]
result["fuel_consumed"]; result["io_cpu_used_seconds"]; result["io_budget_exceeded"]
result["security_baseline"]   # attested limits, incl. wasmtime_version
```

| Control | In-process (explicit `trusted` only) | Subprocess / worker (forced for untrusted/unknown; `run_isolated()`) |
|---|---|---|
| Fuel metering (guest CPU) | ✅ | ✅ |
| Memory cap (`Store.set_limits`) | ✅ | ✅ |
| Wall-clock timeout (epoch) | ✅ epoch at safepoints | ✅ outer wall (`communicate()` + `SIGKILL` at `max(timeout_seconds+5, 5)`) |
| 10 KB output cap | ✅ | ✅ |
| I/O byte wall (`io_budget_bytes`) | ✅ watcher + end-of-run sample + epoch interrupt (scope: private sandbox dir) | ✅ watcher + end-of-run sample (component scope: granted preopens, as a delta) |
| I/O CPU wall (`io_cpu_seconds`) | ❌ documented-trusted * | ✅ worker rusage watchdog |
| Disk quota (`disk_quota_bytes`) | ❌ trusted capability * | ✅ RLIMIT_FSIZE (per file) |
| RLIMIT_NOFILE / FSIZE, 32 MB module cap; RLIMIT_AS/RSS best-effort | ❌ | ✅ (AS/RSS best-effort) |
| Preopen deny + grant-time TOCTOU revalidation | ✅ | ✅ |
| Per-call module binding (`expected_sha256`) | ✅ | ✅ (worker verifies before compiling) |

\* In-process runs execute inside your own process — a kernel-level cap
there would cap your application itself, so these knobs are honored as
declared capabilities, not enforced walls (guest code is still fuel-,
memory-, timeout- and byte-wall-bounded in-process).

**RLIMIT scope (2026-10-23).** `RLIMIT_NOFILE`, `RLIMIT_FSIZE` and the 32 MB
module cap are enforced in the worker. `RLIMIT_AS` and `RLIMIT_RSS` are
best-effort: macOS does not enforce `RLIMIT_AS`, Linux treats `RLIMIT_RSS` as
advisory, and a rejected `setrlimit` is logged rather than reported as an
enforced wall. The byte-accurate memory wall is `Store.set_limits` inside the
sandbox; no row above claims otherwise.

**Timeout semantics (2026-10-12).** `timeout_seconds` is the *configured* budget,
not a hard kill instant. On the subprocess path the parent bounds the run with
`subprocess.communicate(timeout=max(timeout_seconds + 5, 5))` and only then
`SIGKILL`s the worker — so the enforced outer wall sits **up to 5 s above** the
configured value (measured: a `timeout_seconds=2` blocking-hostcall run was killed
at ≈7 s, `benchmarks/poll_oneoff_wall_hostcall_probe.py`, no fuel trap). No public
claim here should be read as a hard cutoff at the configured number. Tightening the
kill to fire exactly at the configured limit is **not** current behavior and is
treated as a separate security-design change. On the in-process path the epoch timer
interrupts only at WASM safepoints, so a guest blocked inside a single non-returning
host call is *not* guaranteed to be caught there — the guaranteed outer kill exists
only on the subprocess (worker) path.

Backed by tests: `tests/test_run_io_budgets.py` (byte wall on both paths,
CPU wall on the worker path), `tests/test_component_io_budget.py` (component
byte wall over granted preopens as a delta; preview1 end-of-run sample; positive
and boundary controls), `tests/test_disk_quota.py` (RLIMIT_FSIZE),
`tests/test_process_executor.py` (rlimits, timeout kill, module cap),
`tests/test_effective_preopens.py` (preopens),
`tests/test_load_guard.py` (atomic publication, settled-file load guard,
per-call digest binding on all paths — ADR-006 amendment, 2026-09-25).

For production and regulated deployments, the Ephemora enterprise offering builds on Cell's isolation.

## Security Design

Threat model (adversary model, trust boundaries, residual risks):
[docs/threat-model.md](docs/threat-model.md). What this release deliberately leaves
open — with the reason stated — is listed under
["Known Limitations"](#known-limitations) in this document; the evidence behind each
posture claim (including what is *not* proved by it) is in
[docs/security_posture.md](docs/security_posture.md).

Ephemora-cell relies on:
- **WASM Memory Safety:** Bounds-checked memory access (no buffer overflows)
- **WASI Preview1 / WASI 0.2:** Capability-based filesystem access (only preopened directories; the effective per-ABI grant is attested in the execution report's `security_baseline.preopens`)
- **Resource Limits:** Fuel metering (CPU), memory caps (128MB default), wall-clock timeout (30s default)
- **Sync refusal:** `fd_sync`, `fd_datasync` and `fd_psync` are shadowed with a trapping shim at the link layer, so a guest that CALLS one fails closed instead of driving a host `fsync(2)`. Importing them stays legal — every wasm32-wasi Zig binary imports `fd_sync` and every CPython-WASI guest imports `fd_datasync`, in both cases without calling it (measured: `benchmarks/interpreter_guest/probe_datasync.py`, cold and warm stdlib tree). The earlier design rejected these at the IMPORT layer, which refused interpreters and toolchains while `fd_sync` — the name its matcher never saw — still reached the host under the default configuration. `allow_fsync=True` is the opt-out for a caller that needs real durability; it is attested in the report's `security_baseline` and it is **not** bounded by `io_cpu_seconds`, because a sync storm is kernel and device work that keeps the guest under its own CPU budget while host I/O throughput collapses ([arXiv 2509.11242](https://arxiv.org/html/2509.11242v1), USENIX Security '25). `fd_psync` stays trapped either way — Preview1 has no implementation to serve it. **Scope: this covers the WASI Preview1 path. The WASI 0.2 component path carries no sync blockade today, and that is measured rather than inferred** — `benchmarks/component_sync_probe.py` runs a wasip2 guest that calls `wasi:filesystem/types` `sync` and `sync-data`: with an operator-granted directory both calls complete into the host (`SYNC-ALL:OK`, `SYNC-DATA:OK`, artifact written), and in the default posture the component route grants no preopen at all (`ephemora_cell/wasi_02.py:293-294`), so the surface needs an explicit `allow_dirs` before a guest can reach it. Closing it is planned follow-up work, not this release's (see the attack-vector table's path note and `docs/threat-model.md`).

### Host-side file boundaries — the host never follows what the guest can write (2026-10-05)

Capability-based filesystem access protects the **guest**: wasmtime refuses to
resolve a path out of a preopen, and Cell re-validates each preopen at grant time.
That does not protect the **host**, which also opens names inside the guest's own
sandbox — the sidecar request and response artifacts, the grant files, the audit
books. And WASI's symlink rule is asymmetric: `path_symlink` with an **absolute**
target is refused (ENOTCAPABLE), while a **relative** target is created, and
`../../../../…` resolves wherever the opening process resolves it. Measured on the
release candidate: a guest-created `sidecar.response.json` pointing outside the
sandbox made the mediator overwrite that file with host-written JSON as the MCP
server's own user — arbitrary file write, content partly steered by the guest.

The rule now enforced in code: every host-side read or write of a name that a
guest or a directory-writer can create goes through `ephemora_cell/_fsutil.py`
— `O_NOFOLLOW`, the descriptor it actually obtained must be a **regular file**,
reads come from that descriptor (so a rename race cannot move the bytes under the
check), and publications are atomic (`temp + os.replace`), which replaces the name
instead of writing through it. Applies to: the request artifact (refusal is an
**audited denial**, not silence, and the reason carries no absolute host path), the
response artifact, grant files and the trust root in `load_egress_grants` /
`GrantTrustRoot.load`, and the append-only books (`_appendlog.py`), because the
ledger **is** the enforcement — a swappable book silently resets caps, windows and
revocations. `Path.glob` swallows `OSError`, so the grants directory is enumerated
with `scandir`, and an **empty** grants directory refuses startup: behind
`--egress-grants-dir`, zero authorities is a misconfiguration, not a posture.

Residual, stated: the guest may still create symlinks inside its own sandbox (the
runtime does not strip that right); what changed is that no host code path follows
them. The request artifact is also bounded at 1 MiB **at the read**, so a host
parser cannot be made to allocate whatever a guest wrote.

### Signature semantics — what is signed, who may sign, what that proves

A signature is a claim about bytes, so the three questions get three answers:

- **What is signed:** `canonical_bytes(record)` — RFC 8785 (JCS) over the record's
  own fields, wrapped in a DSSE v1 PAE with the artifact's audience as the payload
  type. Not "the JSON next to it": `verify_execution_attestation` re-derives the
  canonical bytes from the execution object the caller is reading and requires
  payload type, payload bytes and signature to agree, so a signer cannot sign one
  object and present another. Grant envelopes are pinned the same way
  (`payload == canonical_bytes(grant)`), and a payload that is valid JSON but not
  canonical is refused rather than normalized.
- **Who may sign:** an operator-anchored key. Receipts use the deployment's signing
  key (`--receipt-signing-key`); grants use `GrantTrustRoot`, a key set loaded from
  a path **outside** the grants directory, with `active`/`transition`/`retired`
  status and per-key windows. An algorithm label on a signature is checked, and a
  key that travels with the artefact is never trusted for the artefact.
- **What a valid signature proves:** that a trusted signer attests these exact
  bytes at a stated time (`evidence.issued_at`, freshness optional). It does not
  prove the execution was safe, it does not prove the sandbox enforced more than the
  record itself states (`enforced` is inside the payload for that reason), and it is
  not authority when the audience is wrong — the receipt verifier accepts only Cell's
  own receipt audiences, so a grant envelope signed by the same operator key cannot
  pass as evidence about an execution, or the other way round. Replay detection stays
  with the verifier: **Cell proves uniqueness; the verifier decides whether it has
  been seen before** — the evidence persists, the execution state does not.
- **A bare execution receipt has no module or policy digest.** The signed
  `PreExecutionRecord` carries `module_sha256`, `config_fingerprint` and
  `input_hash`; `verify_chain` binds the receipt to exactly that record through
  `back_link`. A receipt verified alone therefore proves its own fields, not
  which module or policy ran — do not read it as that proof.
- **Output and resource limits are not inferred by the verifier.** `stdout_bytes`
  counts the bytes the host captured **after** the 10 KB capture cap; truncation
  is marked inside the captured text, not as a separate signed boolean. A `null`
  `memory_mb` means "not measured", never "0 MB". The signature covers those
  recorded facts, not the guest's total output or a measurement that was never
  made.
- **The ledger's tail is not self-authenticating.** `verify` detects reordering,
  edits and interior drops, but a chain shortened at the end needs an external
  head anchor; the verifier prints that limit explicitly. Freshness and single use
  of a receipt likewise stay with the caller.

### Effective enforcement attestation — claim vs configured intent

A signature proves the bytes it covers, but a *configured* knob is not the same as a
*wall that actually held* on the path the guest ran. Two host-side runtime facts are
therefore attested alongside the policy so a verifier reads EFFECTIVE enforcement,
not intent (ADR-014):

- **`execution_mode ∈ {in_process, subprocess}`** — which isolation path ran the
  guest. The OS walls (RLIMITs, per-file disk quota, rusage watchdog, hard kill)
  exist only under `subprocess`; an in-process receipt says so plainly instead of
  letting a reader assume the deployment isolated it.
- **`abi ∈ {preview1, component}`** and **`sync_blockade_enforced: bool`** — whether
  the WASI sync blockade was actually in effect. `allow_fsync` is a
  PREVIEW1 setting: the sandbox traps `fd_sync`/`fd_datasync`/`fd_psync` at the call
  layer only on that path. The WASI 0.2 component path links `wasi:filesystem`
  through `Linker.add_wasip2()`, where no such trap exists (measured, not inferred),
  so a component run that signed `allow_fsync: false` attested a guarantee its path
  never carried. The enforcement is derived, never trusted from the caller, over a
  fixed truth table:

  | Execution | `allow_fsync` | `sync_blockade_enforced` |
  |---|---|---|
  | preview1 | `false` | `true` |
  | preview1 | `true` | `false` |
  | component | `false` | `false` |
  | component | `true` | `false` |

  With `abi="auto"` the receipt records the ABI ACTUALLY resolved from the binary's
  magic bytes, never the requested mode.

**Verifier semantics (fail-closed).** The fields are additive and opt-in: a run that
resolved no ABI leaves them absent and its canonical bytes stay byte-identical to
earlier releases, so no historical record changes shape. But a record WITHOUT
`sync_blockade_enforced` predates enforcement attestation and may NEVER be read as
proof the blockade held — silence is not a guarantee; only an explicit `true` counts
as blocked.

**No silent downgrade.** A caller that REQUIRES a provably effective sync blockade
passes `require_sync_blockade=True`; a run on a path that cannot enforce it (any
component run, or preview1 with `allow_fsync=True`) is refused BEFORE it starts — no
guest executes, nothing is spawned. This is not a component ban: legitimate component
workloads (including `componentize-py`) run unchanged unless a caller names the
guarantee they cannot meet.

### Proposal policy — set, not inherited (2026-09-25)

Cell's wasmtime line ships several proposals **enabled by engine default** (Wasm GC,
exceptions, function-references — per the Bytecode Alliance's July 2026
default-on rollout). That default-on set is exactly where the 2025/26
divergence incidents cluster: fuel accounting dropped across
`call_ref`/`try_table` calls (GHSA-m63x-6p34-q65x), the Cranelift aarch64
heap escape (CVE-2026-34971), and the vm2 escape riding WebAssembly
`try_table`/JSTag handling (CVE-2026-26956, secondary sources). Cell's rule:

**Every proposal the shipped WASI surface does not need is enforced `False`
in the engine config at all construction sites** (`wasi_runtime`,
`engine_pool`, `wasi_02`, conformance harness) — compile-probe-tested per
release (`tests/test_proposal_policy.py`), attested in `security_baseline`
(`*_enabled` keys), and structurally guarded against silent default drift
(`tests/test_threads_baseline.py` SpyConfig assertions).

| Proposal | Posture | Rationale |
|---|---|---|
| `wasm_threads` | **off, frozen** | shared memories = covert channel + unsupported with `Store` limits (below) |
| `wasm_multi_memory` | **off, frozen** | no Cell workload needs it; baseline freeze (P1/K2) |
| `wasm_function_references` | **off, enforced** | `call_ref` drops callee fuel (GHSA-m63x-6p34-q65x) |
| `wasm_exceptions` | **off, enforced** | `try_table` catch drops fuel (same advisory); vm2-class escape surface |
| `wasm_gc` | **off, enforced** | not needed; GC heap not byte-bounded in the binding |
| `wasm_tail_call` | **off, enforced** | not needed by any Cell workload |
| `wasm_stack_switching` | **off, enforced** | WASI 0.3 native-async base — gate-off until the 0.3 surface is qualified (see [docs/recipes.md](docs/recipes.md#wasi-02-components)) |
| `wasm_memory64` | **opt-in** | per-config (`WASIConfig.memory64`), own pool fingerprint, `Store` limits still bind |
| `wasm_component_model` | **on** | required by the WASI 0.2 component path |
| SIMD / bulk-memory / multi-value / sign-extension / reference-types | **on** | spec-core; the wasip1/wasip2 surfaces and ordinary toolchain output build on them — compile-probe-tested as accepted |

Not exposed by the Python binding (documented posture, unreachable either
way): the **pooling allocator** (`allocation_strategy` has no binding — the
CVE-2026-34988 cache-pressure-residue class cannot be reached from Cell).
An explicit 4 GiB `memory_guard_size` was tried and **reverted**: it broke
`run_isolated` in constrained Linux VMs (mmap ENOMEM on the combined
reservation+guard, caught end-to-end by the arm64 container gate).
`tests/test_memory_hygiene.py` proves sequential instances observe only
zeroed memory and remains the standing guard. Also unreachable:
**Spectre mitigations** (engine default, no binding toggle —
always on), and **Pulley/Winch backends** (`Config.strategy` accepts only
auto/cranelift; "never Winch" by policy; `Engine.is_pulley()` asserted
`False` in `tests/test_surface_audit.py`).

### Egress mediation: transport walls and the file boundary (2026-10-05)

Two classes a red-team pass found on the release candidate, both closed with
gates (`tests/test_egress_sidecar.py::TestTransportWalls`,
`tests/test_host_file_boundaries.py`, `tests/test_transport.py`,
`tests/test_mcp_adapter.py`):

- **A mediated fetch must end in a decision.** `http.client`'s own failures
  (`InvalidURL` from a tab inside an authority the allowlist still matched, a
  response with more than 100 headers, a junk status line) subclass neither
  `OSError` nor `ValueError`, so they escaped the mediator entirely: no audit
  line, no `_meta.egress`. They are audited denials now (`limit: "transport"`).
  `timeout_seconds` bounded **one socket operation**, so a peer dribbling one
  byte every 20 ms pinned a host thread — per hop, up to ten — and the body read
  blocked until `n` bytes arrived; the fetch now reads in chunks against one
  wall-clock deadline (`read1`) and returns nothing when it expires
  (`limit: "timeout"`; measured: 8 s of trickle refused against a 1 s budget).
  Empty userinfo (`http://:@host`) was accepted because an empty username is
  falsy and the `:@` still reached the wire; any `@` in the netloc is refused.
- **A policy decision is not a transfer.** An allowlisted request whose TLS
  handshake, DNS lookup or connection fails keeps `decision: "allowed"` (the
  policy did allow it) but carries `transport_ok: false` and a failing response
  document; a delivered response carries `transport_ok: true`. Policy and grant
  denials leave it `null` because no socket was attempted. This stops "allowed"
  from reading as "successfully transmitted" in `_meta.egress`.
- **The audit trail cannot claim a hop it never opened.** The stdlib calls
  `redirect_request()` *before* applying its own loop limit, so the last hop of a
  long chain was recorded as followed while the entry read `allowed, fetch
  failed`. The limit is mirrored before recording; reaching it is a denial naming
  the refused hop, and the recorded set is asserted against what the test origin
  actually served.
- **The host does not follow names the guest can create.** WASI refuses an
  absolute `path_symlink` target and accepts a relative one, so
  `sidecar.response.json -> ../../../../…` made the mediator overwrite a file
  outside the sandbox with host-written JSON as the server's own user. Artifact
  reads/writes now go through `O_NOFOLLOW` + a regular-file check on the
  descriptor actually obtained + atomic publication; refusals are audited and
  carry no absolute host path; the request document is bounded (1 MiB) at the
  read. `SplitResult.port` validates lazily, so a guest-chosen
  `http://allowlisted-host:70000/…` split fine and raised on the port read — outside
  the guard, past the mediator, into a JSON-RPC -32603 with no audit entry and no
  `_meta.egress`; the whole match is guarded now, because a refusal that leaves no
  trace is a fail-open. The same rule covers grant files, the trust root, the append-only
  books and the governed tool-loading path — proposals are enumerated with
  `os.scandir` (not `Path.glob`, which swallows `OSError` and reads as an empty
  inbox), every `*.tool.request.json` is refused **with a reason** unless it is a
  regular file reachable without following a link, and the settled-check reads the
  same way; a link there would otherwise have made the host parse an arbitrary file
  of the writer's choosing, and deferring it as "pending" forever is worse than a
  rejection because nothing is ever decided. A swappable ledger silently resets
  caps, windows and revocations — and
  an unreadable ledger now refuses the **call with an audit line** instead of
  raising past the mediator (`limit: "ledger"`).
- **The grants directory is not allowed to be empty or unreadable.** `Path.glob`
  swallows `OSError`, so an unreadable directory used to yield zero grants with
  zero errors while `get-policy` attested every grant file as verified.
  Enumeration is `os.scandir` now, and zero grant files behind
  `--egress-grants-dir` refuses startup.
- **The stdio transport is not crashable by one byte, and cannot lie.** A text
  stdin under a utf-8 locale raised `UnicodeDecodeError` inside `readline()`
  where nothing could catch it (traceback, exit 1, buffered responses lost);
  bytes are read and decoded with replacement, so malformed input is a `-32700`
  and the next message is still answered. The oversized-line cap applies while
  reading rather than after buffering, leftover bytes after a line boundary are
  carried (one read holding two messages used to answer only the first), and
  non-finite request ids are refused because `json.loads` accepts `NaN` and the
  echoed id produced a frame strict parsers reject.
- **Grant authority is an intersection — per hop and per byte, not per URL
  (2026-10-05).** A signed grant narrows what a tool may reach; it no longer widens
  it. `mediate_with_grant` validates the request against the grant AND against the
  server-wide `--egress-allow` ceiling before anything is charged, so an endpoint
  outside the operator's list is denied with `limit: "server-policy"` and spends no
  grant slot — a grant that was broader than the allowlist used to be the whole
  authority for its tool. The check is not a one-URL fence: every redirect hop is
  revalidated against the ceiling too (an origin answering `302` into a prefix the
  operator had excluded was the escape a red-team pass found in this code the day it
  landed), and the resource envelope takes the STRICTEST of the two — a grant's
  `EgressPolicy` is rebuilt from endpoints and methods, so without that its byte and
  time limits were the dataclass defaults (measured: 8 203 bytes delivered against a
  256-byte ceiling). `get-policy` discloses which scope is live (`grant_scope`).
  Separately, `--egress-grants-required` flips the ungranted-tool case from fallback
  to denial (`limit: "grant-required"`, disclosed as `ungranted_tools`): off by
  default, so a tool with no grant file is still mediated by the allowlist alone
  (allowlist, no window, no cap, no ledger) and renaming or deleting one grant file
  still downgrades that one tool. The flag requires grants AND a ledger at
  construction — a posture that denies every call while `get-policy` reports
  `mediation: disabled` is worse than no posture — and its denial is issued only
  after the guest actually wrote a request artifact, so it changes what may be
  reached, not what a run reports.
- **The MCP handshake is ordered, and that is conformance, not authority
  (2026-10-05).** A handshake-era request (one that names no protocol version
  in `params._meta`) is refused with `-32600` before `initialize` and on a
  repeated `initialize`, and the refusal happens before the engine is reached
  (`tests/test_mcp_adapter.py::TestHandshakeOrder`). The stateless `2026-07-28`
  path is deliberately exempt — that revision has no handshake — as is
  `server/discover`, the probe a dual-era client sends before it knows whether
  to initialize. The exemption is the revision's, not the JSON key's: naming a
  HANDSHAKE-era version in `params._meta` does not buy a handshake-free
  `tools/call` (it was served that way for one review round), while an unsupported
  version stays exempt so the caller still gets the -32022 that identifies the era. No client capability adds or removes authority in this server,
  so nothing a caller can claim through the handshake changes what it may run.
- **The artefact cannot out-argue its own claims.** A declared `alg` on a
  signature is checked against the expected algorithm, and the receipt verifier
  accepts only Cell's own receipt audiences — so a grant envelope signed by the
  same operator key cannot be confirmed as evidence about an execution, or the
  reverse (see "Signature semantics" below). `get-policy` no longer dies on a
  corrupt ledger (it reports `ledger_state: "unreadable-for-some-grants"`), the
  error document merges host facts LAST so a guest printing
  `{"status":"success-fake"}` cannot overwrite them, and a host traceback lives in
  `ExecutionResult.host_traceback` instead of the `stderr` the client is served.

### Threading

Shared-everything threads (shared memory + atomics + WASI threads) are **disabled
by default and treated as an attack surface**, not a feature:

- `wasm_threads = False` and `wasm_multi_memory = False` are enforced on every
  engine at all three construction sites: `WASISandbox` (pooled and inline),
  `EnginePool._new_entry`, and `ComponentSandbox`. This is asserted
  behaviorally in `tests/test_security.py` and structurally in
  `tests/test_threads_baseline.py`.
- **memory64 is a per-config opt-in** (`WASIConfig.memory64` / `--memory64`,
  default `False`): opted-in engines enable `wasm_memory64`, get their own
  engine-pool fingerprint entry, and remain bound by `Store.set_limits`
  (`memory_size=`) on committed bytes. Multi-memory and threads stay frozen
  even when memory64 is on.
- A guest module with a shared memory is rejected **at parse/compile time**:
  `wasm_threads = False` makes the wasmtime parser refuse `shared`
  memories immediately. (Verified on the 47 line and re-attested on the 49.0.0 pin:
  threads defaults to *True*
  — without our flag the module compiles; instantiation would then still be
  blocked by wasmtime's separate `Config.shared_memory = False` default, a
  second host-side barrier.) `max_threads` > 1 in `WASIConfig` is currently
  inert; enabling it is gated behind a future, security-reviewed opt-in
  phase with thread-aware fuel and wall-clock accounting.
- If threads are ever enabled (opt-in only), shared memories are a covert
  channel and cross-instance memory state; fuel metering does not bound
  `memory.atomic.wait` spin/blocking, so the wall-clock timeout (epoch
  interruption) and process-level rlimits are the binding DoS backstops.
- This freeze is not an engine limitation: wasmtime supports shared memory +
  atomics server-side (the core threads proposal is Phase 4), but its own
  stability docs mark it "Finished: 🚧" — **shared memories are not well
  integrated with `Store` resource limits and unsupported in the pooling
  allocator**, the exact primitives Cell's memory/fuel accounting relies on.
  WASI-level thread *spawning* is not standardized in 2026 at all
  (`wasi-threads` withdrawn Aug 2023; shared-everything-threads unimplemented
  in the shipped wasmtime line; not part of WASI 0.3).

The thread posture is phased: Phase 0 (shipped) = disabled by default;
any opt-in phase requires its own security review covering the
concurrency threat model, the Wasm 3.0 feature posture and thread-aware
fuel/wall accounting before it can ship.

## Dependency & Upgrade Policy

**Runtime dependency:** `wasmtime` is the only runtime dependency. It is declared
as a **fix-line range** in `pyproject.toml` (`>=49.0.4,<50`); `requirements.txt`
carries that declared specifier, and `requirements.lock` pins the **exact**
controlled build — `wasmtime==49.0.4.post1+git.2c2970205f`
(`macosx_11_0_arm64`, wheel sha256 `5d1ac880…0865e`) — installed with
`pip install --require-hashes -r requirements.lock`, which is how the
release set installs it; CI downloads the same wheel from its versioned asset
and verifies the digest before install. The bare pin `wasmtime==49.0.4` is deliberately
not used: per PEP 440 it can never match the `49.0.4.post1+git.2c2970205f` build, and
the hash-pinned lock is what keeps a `.dirty` build sharing the `49.0.4` prefix
from being selected. PyPI carries no `49.0.4` wheel, so the lock is satisfied from
the release set/asset rather than from the index.

**Fail-closed install guarantee (updated 2026-10-22).** PyPI carries no wasmtime
49.0.4 wheel, so a plain `pip install` of this package **fails to resolve
instead of silently installing a vulnerable 49.0.0–49.0.3 engine** — fail-closed
by declared contract. The patched engine (49.0.4 fix line) ships as a versioned
release asset and in the release set as a controlled build: the
official Bytecode Alliance C-API asset
`wasmtime-v49.0.4-aarch64-macos-c-api.tar.xz` (tarball sha256 `f83147d1…5460`,
verified before embedding), assembled with the byte-identical PyPI 49.0.0 Python
bindings; embedded `_libwasmtime.dylib` sha256 `247c1529…a30b`. The wheel is platform-tagged
`macosx_11_0_arm64`, so non-macOS resolution refuses it by tag — no platform
silently receives an unverified engine. The same rule is stated for the core
wheel: an install by name from a local index selects a file, not an artifact —
version and filename are identical across builds — so the digest published with
the release is the thing to verify before installing. `doctor` reports the
module path and the digest of the exact native file the bindings load, and
`run` refuses a different file on the qualified platform with
`error_class=environment` before any guest code executes. Re-qualify any new wheel against
the fuel / epoch / egress invariants before relaxing the range.

> **Version scope of this section (added 2026-10-16).** Every "pinned `49.0.0`" statement below
> describes the intermediate development pin (moved from `47.0.1` to `49.0.0` on 2026-10-12,
> after the 1.1.0 release) and the plain-`pip`-installable line — not the published 1.1.x wheel
> (pinned `47.0.1`) and not the 1.2.0 candidate, which ships a controlled build on the 49.0.4 fix
> line (`_libwasmtime.dylib` sha256 `247c1529…a30b`, macOS arm64). Where those differ, the
> shipped artifact's re-measurement governs; the PyPI fix-wheel situation still governs what an
> unconfigured `pip install` resolves to.

**Dependency upgrade truth (2026-10-12).** The runtime dependency was moved
from `47.0.1` to `49.0.0` to reduce exposure to specific previously affected engine
vulnerabilities. This is **not** a claim that all Wasmtime vulnerabilities are fixed —
that statement would be false. What the new pin changes, by category:
- **Classes closed by this pin:** advisories patched in engine 47.0.3/47.0.4 (the
  47.0.0 window) are now behind the pin — GHSA-vqjp-4c8c-hfgg (wasmtime-wasi
  filesystem sandbox escape via trailing-slash/symlink `path_open`) and
  GHSA-x84v-gj2h-g759 (WASIp3 stream heap allocation). No CVE ID is asserted for
  GHSA-vqjp: CVE-2026-47261 belongs to the distinct `GHSA-2r75-cxrj-cmph`
  (`path_open` TRUNCATE bypass), documented under the 2026 advisories below.
- **Paths still affected:** every advisory whose fix line is 48.0.3/49.0.1 or
  48.0.4/49.0.2 still applies, because `49.0.0` predates both patch releases and no
  Python wheel exists for them (PyPI carries one wheel per major). That set includes
  GHSA-j2g9 (datetime overflow), GHSA-m63x (fuel amplification) and the 2026-10-02
  wave (GHSA-gqmc, GHSA-96f6). GHSA-j366 is also unpatched in the engine at this
  line, but it is a WASI **Preview0** advisory and Cell does not link preview0, so
  it is an unpatched-but-unreachable class rather than a live path (see the
  advisory triage below).
- **Functions effectively excluded:** engine-default proposals (function-references /
  exceptions / GC / tail-call / threads, WASIp3 worlds, wasi-http) stay enforced-off or
  unlinkable through the Cell configuration regardless of version — independent of this
  bump (proposal-policy table above).
- **Additional worker mitigation:** mandatory subprocess isolation for untrusted
  components contains host-side aborts (GHSA-j2g9 class) that no in-process resource
  wall can bound; unchanged by the version move.
- **Open native sandbox risks:** an in-process engine 0-day remains part of the threat
  surface; the version pin and the worker boundary reduce but do not eliminate it.
  GHSA-32h6-97mm-8q3c (Critical; identical to RUSTSEC-2026-0327 — **native stack
  buffer overflow** in async-lifted component callback result-count validation) is
  **unpatched in the engine** at this pin (IN BAND, fix 49.0.2, no wheel on PyPI).
  As of this commit its execution path is **technically enforced-excluded at the
  loader boundary**: `ephemora_cell/component_guard.py` independently walks the
  component bytes and refuses any component-model async construct (async-lift /
  future / stream) before the single `wasmtime.component.Component()` site in
  `wasi_02.py` is reached — fail-closed, on both the in-process trusted path and
  the protected worker. This is loader-boundary avoidance backed by regression
  tests (negative async reproduction + positive controls against the real guest
  corpus), **not** a claim the upstream overflow is patched: the worker boundary
  and the config posture remain containment, and definitive closure still needs a
  corrected wasmtime wheel or a controlled source build (see the advisory triage
  below).

Full regression against the new pin is required by the engine-upgrade gate (below).

**Upgrade windows:**
- Security/CVE fixes: within **14 days** of upstream release
- Feature/minor releases: within **30 days**
- Major releases: within **90 days** after regression validation against the full
  test suite and benchmarks

**CVE scanning in CI:**
- `pip-audit -r requirements.txt` runs on every push/PR and weekly (Monday 03:00 UTC)
- Any known vulnerability fails the CI job (blocking merge)
- CycloneDX SBOM (`sbom.json`) is generated and uploaded as a CI artifact per run

**LTS review:**
- The `wasmtime` release train is reviewed quarterly against the sandbox
  requirements (fuel metering, epoch interruption, WASI Preview1)
- Next scheduled LTS review: **Q3/2027**
- **GC-heap gate trigger:** when a wasmtime-py release exposes a GC-heap
  limiter (`ResourceLimiter`) or a `wasm_gc` engine flag in the Python
  bindings, add the corresponding enforcement for `max_gc_heap_mb`
  (recorded only today — see Known Limitations) to that upgrade's
  validation checklist

**Engine advisories (wasmtime):** the engine itself is part of the threat surface.
The April 2026 Bytecode Alliance advisory batch (2026-04-09; 12 advisories, two
critical sandbox escapes, both aarch64-specific: RUSTSEC-2026-0096 / CVE-2026-34971,
a Cranelift miscompiled guest heap access enabling host memory access, and
RUSTSEC-2026-0095, a Winch-backend memory access — fixed in 36.0.7 / 42.0.2 / 43.0.1
/ 24.0.7; the pinned 49.0.0 contains the fixes) demonstrated that engine 0-days are
a real in-process risk. Cell's answer is layered: security claims are bound to the
tested engine version (`requirements.txt` pin, `wasmtime_version` attested in every
execution record), CI reads the GitHub security-advisory feed for Wasmtime alongside pip-audit, and
`run_isolated()` is the mitigation layer for untrusted guests (disposable worker
process, hard kill). Confirmation artifacts (2026-09-25): a version-floor
test pins the engine at `>= 43.0.1` so the "contains the fixes" claim
cannot silently regress; the memory64 opt-in and the unselectable Winch
backend are asserted alongside (proposal-policy table above).

**Evidence fixtures.** The dated measurements below name guest binaries under
`benchmarks/`. The WASI 0.2 probe binaries (`benchmarks/component_probes/*.wasm`)
are build artifacts and are deliberately NOT committed — `.gitignore` excludes
`*.wasm` and carries no exception for that directory, so a clone does not contain
them. Each one the evidence cites is therefore identified by the sha256 pinned in
`benchmarks/component_probes/fixtures.json`, together with its source crate, build
command and the date it was measured; `benchmarks/component_probes/rebuild.sh`
rebuilds from source into `.rebuilt/` (never over the pinned bytes unless
`--install`) and fails on drift, and `tests/test_component_probe_fixtures.py`
gates the manifest against the sources, the citations and the wording of the
scripts. Those hashes say WHICH bytes a measurement ran on, not that any toolchain
reproduces them — a rebuild that differs is a different experiment, so the
measurement has to be re-run and re-dated rather than the hash quietly replaced.
CI does not rebuild them (the builder job installs `wasm32-wasip1` only, not
`wasm32-wasip2` + `wasm-tools`). The committed fixtures elsewhere
(`tests/fixtures/`, `benchmarks/workloads/`, `ephemora_cell_mcp/tools/`,
`examples/`) are tracked files, and those citations are to bytes in the clone.

- **GHSA-m9f7-9w4p-gv38** (High, CVSS 8.8, CWE-61, no CVE — advisory published
  2026-10-14; wasmtime-wasi filesystem sandbox escape: a relative symlink plus a
  `path_rename` whose source carries a trailing slash moves a directory from
  outside the preopens into the sandbox area). **Advisory scope (counter-checked
  against the published advisory on 2026-10-16):** affected `wasmtime-wasi`
  `<= 36.0.17`, `>= 37.0.0, <= 48.0.5` and `>= 49.0.0, <= 49.0.2`; fixed in
  `36.0.18`, `48.0.6` and `49.0.3`. Affected platforms are macOS and FreeBSD
  (Linux and Windows are **not** affected). The advisory lists **no workaround** —
  the only remediation is an engine upgrade. **Cell's exposure
  at the shipped artifact (engine 49.0.4 fix line, embedded `_libwasmtime.dylib`
  sha256 `247c1529…a30b`, macOS arm64; first measured on the now-withdrawn
  49.0.3 build 2026-10-16 and rechecked on 49.0.4): not reachable** —
  `path_rename("up/" -> "grabbed")` is denied with errno 54 (ENOTDIR); the target
  directory stays untouched and no host byte is readable. In a "continue" variant
  the follow-up guest `path_open` is denied as well (errno 44 / ENOENT). The
  measurement was counter-checked: (i) the same harness on
  upstream `wasmtime 49.0.0` (dylib `2cc7e377…`) reproduces the escape (the guest
  reads the host secret content), and (ii) the host layer (`renameat` with a
  trailing-slash source) does follow the symlink — so the block is attributable
  to the shipped engine artifact, not to a harmless kernel quirk. This holds for
  macOS arm64 only; the evidence is not transferred to Linux or Windows, which
  remain **NOT QUALIFIED**. The published **1.1.x** line pins `wasmtime 47.0.1`,
  which falls inside `>= 37.0.0, <= 48.0.5`: for that line this class is **open**
  (fixed only at `48.0.6`/`49.0.3`) and is the subject of the prepared 1.1.0
  advisory notice — it is not closed by anything in this section.

- **GHSA-x84v-gj2h-g759** (WASIp3 streams, CVSS 6.9 — added 2026-09-25):
  guest-controlled-size host heap allocation when writing to WASIp3
  streams; affects wasmtime 46.0.0–46.0.2 and 47.0.0–47.0.3, patched in
  47.0.4 — **closed by the 49.0.0 development pin and still closed by the `49.0.4` build** (49.0.0 is past
  47.0.4, which supersedes the earlier "wheel pending" state tracked by
  `scripts/check_wasmtime_patch.py`). **Cell's exposure: the surface is
  structurally unreachable** — WASIp3 worlds cannot be linked through the
  Python binding (component linker exposes only `add_wasip2`/
  `add_wasi_http`, asserted in `tests/test_surface_audit.py`), and the
  async base is gated off (`wasm_stack_switching=False`). The version-boundary
  fix landed with the 49.0.0 pin; the WASI 0.3 position stays gate-off
  until that line ships and the 0.3 surface gets its own budget
  qualification ([docs/recipes.md](docs/recipes.md#wasi-02-components)).

**September 2026 advisories — exposure statement (updated 2026-10-12):** two wasmtime
advisories were raised against the 47.0.x line; under the `49.0.0` development pin (now superseded by 49.0.4)
GHSA-vqjp is closed (fixed in 47.0.4) and GHSA-m63x still applies (fix line 48.0.3 /
49.0.1, no wheel):

- **GHSA-m63x-6p34-q65x** (fuel amplification via `call_ref`/`try_table`,
  CVSS 5.7): with fuel metering on (Cell always enables it), a guest using
  these opcodes can run exponentially longer than its budget on wasmtime
  47.0.x. **Cell's exposure:** real — the proposals ride engine defaults and
  every Cell run meters fuel. **Mitigation shipped in v1.0.4.2:** the engine
  config enforces `wasm_function_references=False` and `wasm_exceptions=False`
  (plus `wasm_gc=False`, `wasm_tail_call=False`) at every Config construction
  site, so guest modules using the affected opcodes fail to compile
  (fail-closed; empirically verified) and the posture is attested in
  `security_baseline` (`function_references_enabled`, `exceptions_enabled`,
  `gc_enabled`, `tail_calls_enabled`). Guests that legitimately need
  exceptions/GC cannot run until the engine upgrade — this is the documented
  trade-off for keeping "deterministic fuel accounting" honest. Full fix:
  upgrade to wasmtime 48.0.3/49.0.1 (Python wheels pending on PyPI — tracked
  by `scripts/check_wasmtime_patch.py`), then re-qualify fuel determinism. The
  watcher's upgrade target line is **48.0.4 / 49.0.2**, one step above this
  advisory's own fix, because the 2026-10-02 wave below is not closed at
  48.0.3.
- **GHSA-vqjp-4c8c-hfgg** (CVSS 7.5, wasmtime-wasi filesystem sandbox escape via
  trailing-slash/symlink paths in `path_open`; no CVE ID is asserted for this
  advisory — CVE-2026-47261 belongs to the distinct `GHSA-2r75-cxrj-cmph`
  documented immediately below): **Cell's exposure:**
  every Preview1 run grants the `/sandbox` scratch preopen by design, so the
  affected code path is reachable even in the default posture; operator-granted
  `allow_dirs` widen the reachable scope. No config-level workaround exists
  upstream. **Closed by `49.0.0` and still closed by the current `49.0.4` build** — the fix landed in
  engine 47.0.4, which 49.0.0 carries, so the shipped runtime is now past the
  affected window. **The preopen test matrix exists** (2026-09-25):
  `tests/test_fs_escape_matrix.py` + `benchmarks/probe_classes_2026.py` run the
  trailing-slash/hardlink/rename/TRUNCATE companion vectors with positive
  controls — measured on the pinned engine, **none of the escape shapes
  reproduce through Cell's preopen grant path** (all blocked, dated evidence in
  `benchmarks/results/2026-09-25/probe_classes_2026.json`). **Since 2026-10-04
  the matrix is a strict gate, not an xfail note:** the markers were removed,
  so a vector that re-opens (engine bump, profile change, weaker preopen
  grant) turns CI red instead of landing as a silent "xfailed". Re-measured
  green on the second CI leg (linux/amd64, 2026-10-04), and re-run green on
  the 49.0.0 pin (macOS arm64, 2026-10-12); red-capability was proven
  by injecting a successful vector — it FAILS. The version-boundary exposure is
  closed by the pin; the strict escape matrix stays wired as a regression tripwire
  so a future engine move that re-opens the shape turns CI red rather than relying
  on the version number alone.
- **GHSA-2r75-cxrj-cmph** (CVE-2026-47261, RUSTSEC-2026-0149, CVSS 7.5 HIGH —
  `path_open` / `open-at` opened with only the `TRUNCATE` oflag set bypasses the
  `FilePerms::WRITE` host restriction and truncates a read-only file): verified
  against the public OSV / GitHub advisory record. This is a **distinct** advisory
  from GHSA-vqjp; the two were previously conflated on the shared CVE. **Not
  applicable to Cell:** the fix shipped in wasmtime-wasi 24.0.9 / 36.0.10 / 44.0.2,
  so the pinned 49.0.0 engine sits well past the affected range, and the bug needs
  an embedding that grants `DirPerms::MUTATE` together with `FilePerms::READ`, which
  the Cell preopen posture does not. The `TRUNCATE`-without-write-right shape in the
  escape matrix is this advisory's subject (not a GHSA-vqjp companion), and it is
  measured denied on the pinned engine.

**2026-09-24 advisory batch, second wave — triage (2026-09-29):** three further
wasmtime advisories published 2026-09-24 (none carries a CVE ID — upstream marked
them "No known CVE"). All three are patched only in **36.0.16 / 48.0.3 / 49.0.1** —
there is **no 47.x patch**; re-verified against the PyPI JSON API on 2026-09-29
(47.0.4 / 48.0.3 / 48.0.4 / 49.0.1 all 404), so the engine-upgrade gate (below)
remains the only closure path and the pinned 49.0.0 still sits inside every affected
range (49.0.0 < 49.0.1, and no 48.0.3/49.0.1 wheel exists). Triage per advisory:

- **GHSA-j2g9-4prp-pf6h** (wasmtime-wasi filesystem datetime overflow, Moderate,
  CVSS 6.2, availability-only): a guest-supplied timestamp whose
  seconds+nanoseconds record overflows Rust's `Duration::new` panics the host,
  on the wasip1/2/3 `set-times` surfaces. **Cell's exposure: YES —
  availability-only, default in-process path. Measured, not inferred:** on the
  component (WASI 0.2) path a guest calling `descriptor.set-times` with
  `Datetime { seconds: u64::MAX, nanoseconds: 1_000_000_000 }` aborts the
  embedding process (Rust panic `overflow in Duration::new`, SIGABRT); fuel,
  epoch timeout and `Store.set_limits` do not apply — the panic happens inside
  the host call, before any guest instruction can be charged. The positive
  control (same call with `NewTimestamp::Now`) succeeds, so the only gate is
  the filesystem preopen grant: the component ABI grants **no** preopen by
  default (`ephemora_cell/wasi_02.py:251-253` — no `/sandbox` mount on
  components) and the MCP server grants a component tool only
  profile-narrowed `allow_dirs` (`ephemora_cell_mcp/engine.py`, `_config_for`;
  MCP in-process execution: `engine.py:190`), so the vector requires an
  operator-granted filesystem preopen. On the **Preview1 path the advisory's
  wasip1 surface did NOT reproduce** on 47.0.1: scalar `u64::MAX`-nanosecond
  timestamps through `fd_filestat_set_times`/`path_filestat_set_times` return
  errno 0/44 with no panic (a single u64 nanoseconds value cannot overflow the
  host's seconds+subsecond split). The advisory page does not detail the
  wasip1 mechanics, so the advisory stays authoritative. **Re-measured on the
  49.0.0 pin (2026-10-12): the component in-process abort still
  reproduces — the `48.0.3 / 49.0.1` fix line is not in `49.0.0`, so this
  advisory is NOT closed by the current pin; it stays open with the worker
  boundary as the containment.** **Mitigation:** the subprocess path
  contains the abort — measured: worker dies, parent survives with a clean
  `ExecutionStatus.ERROR` ("worker crashed: … overflow in Duration::new");
  for untrusted guests use `run_isolated()`. **Patch plan: engine upgrade to
  a 48.0.3+/49.0.1+ wheel (still pending on PyPI as of 2026-10-12).** Evidence:
  `benchmarks/results/2026-09-29/datetime_overflow_ghsa_j2g9.json` and its
  49.0.0 re-run `benchmarks/results/2026-10-12/datetime_overflow_ghsa_j2g9.json`
  (measured:true; fixture `benchmarks/component_probes/times_probe.wasm`, source
  under `benchmarks/component_probes/src/times_probe/`, harness
  `benchmarks/datetime_overflow_probe.py`). The probe is deliberately NOT wired
  into `mcp_cve_replay.py` — its default in-process run aborts the harness
  process, so the harness isolates each leg in its own interpreter.
  **Re-measurement 2026-10-16 at the shipped artifact (`ab4f1ea6…0fb73`, macOS
  arm64):** the wasip2 `descriptor.set-times` overflow **no longer reproduces** —
  the in-process run survives without a panic, and the positive control
  (`NewTimestamp::Now`) succeeds. On upstream `49.0.0` the same harness still
  reproduces (SIGABRT, "overflow in Duration::new") with containment in the
  worker. The class remains an engine detail externally; from here on the
  "unpatched" statement refers explicitly to the **PyPI 49.0.0 line**, not to the
  shipped artifact.
- **GHSA-c9gc-w9vx-w86p** (wasmtime-wasi-http outgoing-body host memory
  exhaustion, Moderate, CVSS 6.2, availability-only): the host fails to enforce
  the allowance returned by `wasi:io/streams.check-write` for WASIp2 outgoing
  HTTP bodies; a guest creating outgoing-request/outgoing-response resources
  pins host allocations. **Cell's exposure: NO — structurally unreachable.**
  Exploitation requires a guest that can invoke WASIp2 outgoing-HTTP APIs (the
  advisory does not spell the linkage precondition out; invoking those APIs
  requires a wasi:http world in the guest — our reading), and Cell's
  guest-facing component linker registers **wasip2 only**:
  `ephemora_cell/wasi_02.py:260-261` calls `linker.add_wasip2()` and never
  `add_wasi_http`; a component importing `wasi:http/outgoing-handler` fails at
  instantiate time with "a matching implementation was not found in the
  linker" (`wasi_02.py:262-269`, verified empirically). The `add_wasi_http`
  METHOD exists on the wasmtime-py `Linker` class — existence is not use.
  Egress is host-mediated (`ephemora_cell/egress_sidecar.py`: the
  guest has no sockets; a tool writes a request artifact that the host
  mediates and policy-gates). With `--egress-allow` the MCP engine is that
  host: it mediates after the run and reports the decision under
  `_meta.egress`. Off by default. The `--egress-allow` path enforces the
  endpoint/method allowlist only. A grant's expiry, usage cap and revocation are
  enforced through a `GrantLedger`, reachable from the CLI with
  `--egress-trust ROOT --egress-grants-dir DIR --grant-ledger PATH` (loaded
  fail-closed and authenticated by `egress_sidecar.load_egress_grants`; `egress_sidecar.mediate_with_grant`,
  `ephemora_cell/grant_ledger.py`, ADR-013): cap inclusive, decided and charged
  in one critical section, and a ledger-less grant fails closed at construction
  rather than silently downgrading. DNS-rebinding is closed at resolve time (Prio
  2): every mediated connect resolves hostnames through a filter that drops
  loopback/RFC1918/CGNAT/link-local/multicast/reserved addresses,
  validate-and-connect in one step; an IP-literal allowlist entry is operator
  intent and stays reachable. **The classification is Cell's own special-use
  registry (`_V4_REFUSED` / `_V6_REFUSED`), not `ipaddress.is_private` /
  `is_reserved`.** That is a measured requirement, not a preference: those
  properties changed meaning across CPython patch releases — 3.10.11, 3.11.8 and
  3.11.9 answered "global" for `2002:7f00:1::` (6to4 embedding 127.0.0.1) while
  refusing `::ffff:8.8.8.8`, and 3.12.10+ refused the whole `2002::/16`
  including public-embedded addresses. A boundary built on them moved when the
  interpreter was patched, and CI on macOS + 3.10.11 caught exactly that on
  2026-10-05. Now the embedded IPv4 is read from the packed bytes for the three
  families that carry one (`::ffff:0:0/96`, `2002::/16`, `64:ff9b::/96`) and
  judged against the IPv4 registry — the notation is never the authority — and
  every other address is judged against the IPv6 registry. Gated by a frozen
  67-address decision set (50 refused / 17 reachable) whose decision vector is
  byte-identical across ten CPython builds: 3.10.11, 3.10.20, 3.11.8, 3.11.9,
  3.11.15, 3.12.10, 3.12.13, 3.13.0, 3.13.14, 3.14.7. A further gate flips
  `is_private`/`is_reserved`/`is_global` on `IPv6Address` to the opposite answer
  and requires every decision to hold, which is what proves the stdlib is not
  being consulted. Reverting the classification to stdlib semantics = 6 red on
  3.10.11. Hardened 2026-10-04 on three fronts: (a) the
  filtered families now include scoped IPv6 (`fe80::1%eth0`), both metadata
  addresses, IPv4-mapped IPv6 (`::ffff:127.0.0.1`) and 6to4/NAT64 forms that
  embed a private v4 address — described then, actually delivered by the
  registry above, which also refuses `2001::/23` (Teredo: its embedded address
  is obfuscated, so it is not decidable) and `3fff::/20`, `5f00::/8`,
  `192.88.99.0/24`; (b) **an ambient `http_proxy` used to defeat the
  guard** — urllib resolves the PROXY, never the URL host, so the filter vetted
  the wrong address and the real resolution happened on a third party's box; the
  mediated fetch now builds its opener with `ProxyHandler({})` and goes direct;
  (c) the pinning claim is tested at the OS boundary — a spy below the guard
  shows `connect()` only ever receives the vetted address (one resolution per
  hop). Cap and revocation are additionally tested under 20 simultaneous
  mediated calls: exactly `max_calls` fetches leave the process, and no call line
  can be booked after a revoke line. Grants are now AUTHENTICATED before anything
  is enforced: `--egress-grants-dir` requires `--egress-trust`, an
  operator-maintained trust root that lives OUTSIDE the grants directory
  (`ephemora_cell/grant_trust.py`, ADR-013). Each file must be a DSSE v1 envelope
  over the grant's canonical bytes, signed by a key the root names, for the grant
  audience `https://ephemora.dev/egress-grant.v1`; a missing or unknown signature,
  a retired key, a key outside its own validity window, an algorithm the root does
  not name, an edited payload, a `key_id` that diverges from the document, or an
  already-expired grant refuses startup — the same all-or-nothing rule as a
  malformed grant set, because a half-loaded authority set would enforce some caps
  and silently ignore others. An unsigned legacy document is refused too: there is
  no downgrade path. Two honest edges: authentication is a STARTUP property, so a
  key that is retired or falls out of its window mid-run keeps the grants already
  loaded in that process (the ledger's cap/window/revocation still bite per call;
  the key state is re-checked on restart), and it is the CLI loader that
  authenticates — an embedder constructing `Server(egress_grants=…)` in-process
  installs what it is handed, by design. What this does NOT do is distribute the
  root: where that file
  comes from, and which issuer keys a caller trusts for receipts, stay the
  operator's trust channel (ADR-013 Roadmap). The no-socket
  boundary stays enforced. Three further walls were added
  2026-10-05 after a red-team pass: a mediated fetch is bounded by **one
  wall-clock deadline** (per-op `timeout_seconds` let a peer trickling a byte every
  20 ms pin a host thread, once per hop), `http.client`'s own failures
  (`InvalidURL` from a tab inside an allowlisted authority, >100 headers, a junk
  status line) are **audited denials** with `limit: "transport"` instead of
  escaping the mediator, and the redirect audit records only hops that were
  **actually opened** — reaching the stdlib's loop limit is a denial naming the
  refused hop. `http://:@host` is refused (an empty username is falsy, and the
  wire carried `:@…`). Pinned in `tests/test_surface_audit.py`,
  `tests/test_grant_ledger.py`, `tests/test_grant_trust.py`,
  `TestTransportWalls`, `tests/test_host_file_boundaries.py`,
  `TestEngineGrantEnforcement`, `TestSSRFGuard`,
  `TestSSRFAdversarialFamilies`, `TestResolvePinningTOCTOU` and
  `TestGrantConcurrency`
  (structural: the linker construction site never calls `add_wasi_http`;
  behavioral: a wasi:http-importing component fails closed) so an upgrade
  that starts linking wasi-http for guests fails loudly.
- **GHSA-jqpg-j7w6-42pr** (component-model dynamic record lifting allocates
  beyond the hostcall fuel limit, Low, CVSS 4.0 score 1.0): lifting a guest
  value into a host `wasmtime::component::Val` performs host allocations not
  counted against fuel (~100x). **Cell's exposure: NO for practical
  purposes.** The advisory affects hosts using the dynamic `component::Val`
  API — "hosts that use bindgen! and otherwise statically-typed APIs are
  unaffected". wasmtime-py 49.0.0 exposes no component-model `Val` type (the
  `wasmtime.Val` it does export is the core-wasm type; the component package
  marshals values through typed C-repr converters,
  `wasmtime/component/_func.py` `convert_to_c`/`convert_from_c`), and the
  WASIp2 host functions Cell links via `add_wasip2()` are Rust-side,
  statically-typed implementations, not Python host callbacks lifting guest
  records. The only guest-to-host lift on Cell's component path is the fixed
  `wasi:cli/run` return (`ephemora_cell/wasi_02.py:307` — a scalar
  result/exit code; no guest-shaped records); guest linear memory stays
  bounded by `Store.set_limits` (`wasi_02.py:221`). Honesty note: whether
  wasmtime's C API routes component calls through `component::Val` internally
  is a Rust-internal detail not verifiable from the Python package — the
  class is re-checked at the planned engine upgrade. No config change required now.

**2026-10-02 advisory wave — triage (2026-10-03).** Four further `wasmtime-wasi`
advisories were published on 2026-10-02 (RustSec `RUSTSEC-2026-0321…0324`). All
four are patched only in **36.0.17 / 48.0.4 / 49.0.2**, and none of those exist
as a `wasmtime` Python wheel: re-checked against the PyPI JSON API on
2026-10-03 and again on **2026-10-14** (`python scripts/check_wasmtime_patch.py`,
exit 1 = still waiting), the binding's release line is still **47.0.1, 48.0.0,
49.0.0** — one wheel per major, no patch releases; the PyPI `latest` field is
`49.0.0`. So the pinned 49.0.0 still sits inside every affected
range of this wave (49.0.0 < 49.0.2) and the engine-upgrade gate stays the only
closure path. Sources here are
RustSec's own database files plus the GitHub advisory pages; the GitHub
global-advisory REST endpoint returned 404 for several of these IDs even though
the advisories exist, which is why the citations name RustSec.

- **GHSA-j366-h8gg-77pm** (WASI **Preview0** `poll_oneoff`: the preview0 host call
  performs O(n) host work over the subscription array without consuming fuel or
  checking exhaustion, **Low, CVSS 4.0, availability-only**; patched in
  36.0.17 / 48.0.4 / 49.0.2): **Cell's exposure to the preview0 advisory: NO —
  the surface is not linked.** Cell's Preview0 review is bounded to the interfaces
  it actually exports/links, and it links `wasi_snapshot_preview1` and the WASI 0.2
  component world — never preview0. The advisory's own named workaround
  (`-Spreview0=n`) is not even reachable from wasmtime-py (neither `Config` nor
  `WasiConfig` exposes a preview-version switch — re-probed against the installed
  49.0.0 binding), which confirms the preview0 path sits outside the shipped
  runtime's reach. **Version-boundary note:** `49.0.0` still predates the
  48.0.4 / 49.0.2 fix line, so the engine is unpatched for this advisory — but
  unpatched-and-unreachable is not the same as exposed, and Cell does not carry
  the preview0 surface.
- **Preview1 `poll_oneoff` host-work observation (separate from GHSA-j366).** The
  probes previously cited under this advisory measure the **preview1** host call,
  not the preview0 vulnerability: they establish a hostcall resource/deadline
  characteristic, not reachability of GHSA-j366. Two facts, each with its own
  artifact:
  - **Fuel-vs-wall** (`benchmarks/poll_oneoff_fuel_probe.py`, dated JSON): on
    preview1 the same guest instruction count (400 rounds) against a growing
    subscription array holds fuel flat — **5 605 at n = 0, 1, 500, 5 000 and
    20 000** — while wall time on the same run grows ≈1.5 ms → ≈1.25 s. So a
    preview1 host call that scales with guest-supplied data is not covered by
    "deterministic fuel accounting" (accounting is deterministic for *guest
    instructions*).
  - **Outer-deadline under a blocking host call**
    (`benchmarks/poll_oneoff_wall_hostcall_probe.py`, dated JSON): a guest stuck
    inside one long preview1 `poll_oneoff` clock call is still terminated by the
    worker's outer wall (`communicate()` + `SIGKILL`, delivered by the OS
    regardless of WASM safepoints); the epoch timer in the in-process path cannot
    interrupt a blocking host call. On the isolation path the process wall bounds
    the uncharged *host work* even though fuel does not.
  This is a preview1 accounting/deadline finding kept separate so it is never
  read as proof of the preview0 advisory. The probes are interim evidence and are
  not in CI (no guest binary, but they need the pinned engine version to be
  meaningful).
- **GHSA-gqmc-89g8-p25r** (unbounded host allocation when a guest has **no
  configured stdout**, via the default `SinkOutputStream` write-zeros path,
  Moderate, CVSS 5.9): **Cell's exposure: NO — by construction.** Every run
  installs our own bounded sinks for both streams, on either path
  (`ephemora_cell/wasi_runtime.py:638-639`,
  `ephemora_cell/wasi_02.py:271-272`), and the advisory itself notes that
  configured streams carry their own limits. **Upgraded from a code-level to a
  measured claim on 49.0.0 (2026-10-12):**
  `benchmarks/stdio_overflow_output_alloc_probe.py` drives a Preview1 guest that
  requests 640 000 bytes of stdout through the bounded sink; the host captures only
  the 10 000-byte budget (`_MAX_OUTPUT_BYTES`), returns a negative `NOSPC` on
  exhaustion (a positive errno is not usable — wasmtime-py misreads it as a byte
  count), and writes no further bytes to the host file; the component path uses the
  same `_make_output_sink`. The construction site stays covered by the existing output
  cap tests, so a change that drops a sink would fail there.
- **GHSA-96f6-r43r-8c24** (`fd_readdir` copies **three uninitialized host
  padding bytes per directory entry** into guest memory, Low, CVSS 2.1,
  confidentiality-only, WASIp1 only, needs a preopen): **Cell's exposure: YES
  wherever a directory listing is possible** — the Preview1 `/sandbox` scratch
  preopen exists in every default run, and operator `allow_dirs` widen it. This
  is disclosure *into* the guest, not an escape: the guest still cannot read a
  host path it was not granted, but what it can read from a granted directory is
  no longer only file data. Upstream states there is **no workaround** short of
  the patch, so this is documented exposure with the engine upgrade as the fix, not a config
  claim. Guests that never call `fd_readdir` do not hit it; Cell does not
  dispatch directory listings on a guest's behalf.
- **RUSTSEC-2026-0324** (host panic on a filesystem timestamp before the epoch,
  wasip3 surface): **Cell's exposure: NO** — WASI 0.3 is gate-off by decision
  (ADR-009 D3) and no wasip3 surface is linked for guests.

**rustls 0.23.37** (GHSA-2mjx-qc3c-rqvc / RUSTSEC-2026-0285, fixed in 0.23.45) ships inside the `wasmtime-wasi-http` component of the runtime artifact (measured 2026-10-16, dylib `ab4f1ea6…`). No shipped execution path wires it in (no `add_wasi_http` call sites in the product); tracked on the fix line.

**Critical memory-safety advisory, unresolved — GHSA-32h6-97mm-8q3c.** Corrected
2026-10-14 against the fetched primary sources
(`benchmarks/results/2026-10-13/native_runtime_advisory_coverage.json`, GH advisory API):
GHSA-32h6-97mm-8q3c and RUSTSEC-2026-0327 are **the same advisory** (alias-confirmed),
and the vulnerability is **not** a host panic — it is a **native stack buffer overflow**:
*“Wasmtime component async-lifted callback result count is unvalidated, causing a native
stack buffer overflow.”* Its CVSS 4.0 vector carries **integrity HIGH and
confidentiality LOW/HIGH with a changed scope**, i.e. a memory-corruption class, so it
must be treated as a potential engine-escape, not an availability-only defect. The
pinned `49.0.0` sits **IN BAND (fix 49.0.2)** and the fix wheel is not yet published to
PyPI (re-confirmed 2026-10-14), so **this pin does not fix it and it is not closed.**
- **What the configuration evidence shows (a control, not a proof of unreachability):**
  the `wasmtime` Python binding exposes no async component entrypoint and Cell never
  enables an async store/future (`wasm_stack_switching=False`, `component-model-async`
  not enabled), attested by `tests/test_surface_audit.py`,
  `tests/test_async_component_reachability.py`, and the engine-config assertions.
- **What the lab measurement does and does NOT establish (2026-10-13,**
  `async_component_validation_ghsa_32h6.json`):** a hostile async-lifted component fed
  under the async-disabled config aborts at an `unreachable!()` validation arm
  (`SIGABRT`, returncode −6) *before the async-lifted export is instantiated*. That is a
  **different code path than the unvalidated-result-count overflow**; we have **not**
  shown that abort reliably prevents the overflow. That lab observation, on its own,
  is why we earlier refused to call the memory-safety class *configuration*-excluded.
  The reachability of the overflow is now addressed by a different, enforced mechanism
  at the loader (see the closure-route bullet below): the component bytes are refused
  before the native parser is ever reached. It is **not** closed by a config assumption,
  and the corrected-wheel upgrade gate stays open (public 1.2.0 release approval remains
  a gated maintainer decision regardless).
- **Containment (not closure):** the mandatory worker subprocess (ADR-015) keeps
  even the observed `SIGABRT` out of the parent (fail-closed `ERROR`, no in-process
  fallback, pinned by
  `tests/test_isolation_gate.py::test_forced_run_never_falls_back_to_in_process_on_worker_crash`).
  Worker containment and the config assumption
  are **explicitly not a full fix.** Closure requires one of: the corrected wheel, a
  controlled corrected runtime build, an AOT security-checked component validation with
  a corrected parser, or a technically enforced exclusion of vulnerable components
  before they reach the vulnerable native runtime — each proven by negative reproduction,
  positive controls, artifact digests, and regression tests.
- **What that does NOT prove (residual risk):** whether wasmtime's internal C API can
  route a *synchronous* component through an async callback is a Rust-internal detail,
  but the loader guard does not depend on answering it: it refuses the async *input
  class* (async-lift / future / stream) before `Component()` runs, so the unvalidated
  async-callback result-count path has no product-loadable component that reaches it.
  The **upstream engine defect itself is still unpatched at 49.0.0** — that remains a
  dependency risk for any direct `wasmtime` use outside Cell and keeps the
  corrected-wheel upgrade gate open; the loader exclusion is defense at Cell's own
  boundary, not a patch of the engine.
- **Testing boundary:** no exploit-style reproduction is attempted on a normal
  development machine; the negative validation runs in the isolated lab harness where a
  native abort is the *result*, not a harness failure. Full closure depends on an
  upstream fix line past 49.0.0 (48.0.4 / 49.0.2 — **confirmed still absent from PyPI on
  2026-10-14**) plus a reachability re-check at the engine-upgrade gate.
- **Remediation progress (enforced-exclusion route WIRED 2026-10-15):** the "technically
  enforced exclusion" route is implemented and now wired into the loader as
  `ephemora_cell/component_guard.py`, an **independent** component-binary reader (it
  never calls the native `wasmtime` parser, which *is* the vulnerable code). It
  positively detects and refuses every component-model async construct that anchors the
  overflow — async `functype` (0x43), `future` (0x65), `stream` (0x66) — including inside
  nested components and inside `componenttype`/`instancetype` declarators, and fails
  closed on any byte stream it cannot confidently walk. It is called in
  `wasi_02.ComponentSandbox.run` at the **single** `wasmtime.component.Component()`
  construction site in the shipped source, so it guards both the in-process trusted path
  and the protected worker. The accept side was certified against the repository's real
  component corpus (WASI p2 Rust probes, `componentize-py` lifted guests, WAT fixtures —
  every one walks cleanly, none over-rejected), proven by
  `tests/test_component_guard.py` (async detection + real-guest acceptance + loader
  integration: an async component is refused through `run()` with a `GHSA-32h6-97mm-8q3c`
  error before the native parser, a real guest is not). Remaining grammar boundary,
  stated honestly: the reader does not parse an embedded core WebAssembly-GC `type`
  declarator, so a component placing a core type inside its type section is refused
  fail-closed (a conservative over-reject, never a bypass). This closes the
  *product-execution* path for the overflow; it does **not** patch the engine — the
  corrected 49.0.2 wheel / controlled source build stays the definitive fix and the
  engine-upgrade gate stays open. Release approval for 1.2.0 remains a gated maintainer
  decision.

**Loader exclusion vs. engine patch — clarification (2026-10-16).** The loader guard
excludes the **product execution path**; it does not patch the engine. For the shipped
artifact (engine 49.0.4 fix line, `_libwasmtime.dylib` sha256 `247c1529…a30b`, macOS
arm64), no evidence is held that the native overflow itself is fixed there — an engine
patch parity in the artifact is **not independently verified**. Until a negative
reproduction of the overflow form, a positive control, the artifact digest and a dated
record exist, the class counts as **open**, bounded by the loader guard plus the worker
boundary.

**Engine-upgrade gate:** any wasmtime bump re-runs the security evidence suite —
`benchmarks/verify_8_vectors.py`, `benchmarks/mcp_cve_replay.py`, and the wasi
conformance job — before security claims are re-attested. CI watch *detects* new
advisories; this gate prevents claims from silently carrying across an engine
version with changed enforcement behavior.

**Process:** Bumping the pinned `requirements.txt` revision requires a passing
`pytest` run plus a clean `pip-audit` before merge.