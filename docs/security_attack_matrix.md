# Attack & containment matrix

**Applies to:** `1.2.0` source (public release on HOLD).
**Native runtime under test:** each row names the pin it was measured on; the shipped candidate is on the 49.0.4 fix line.
**Last live re-verification of the attack rows:** 2026-10-15, macOS arm64, commit `e11fcfb`. The suite count in section G was re-measured on 2026-10-23, not on that commit.

> **Version scope.** The rows below were measured on the intermediate `49.0.0`
> development pin. The 1.2.0 candidate ships a controlled build on the **49.0.4**
> fix line from the release wheelhouse and floors the dependency at
> `wasmtime>=49.0.4,<50`, so the "no wheel on PyPI" statements describe what was
> true of the plain-`pip` path at measurement time, not of the shipped artifact.
> The suite and the fidelity/guard legs were re-run on the 49.0.4 build; the
> attack rows were **not** all re-run on it, and each row keeps the runtime it
> was actually observed on.

This is the single place that lists every attack scenario this repository has
actually run, what each one proves, and under which boundary, platform, commit and
runtime. It exists so that a headline like "8/8 blocked" is read against the exact
test that produced it rather than as a global security score.

**Reading rules (why the totals are not additive):**

- A scenario is counted **once**, under the one boundary it actually exercises.
  The same primitive tested on two platforms is two *observations of one row*, not
  two defences.
- `NOT-EXPRESSIBLE` (no API surface at all) and `BLOCKED` (surface present, call
  refused) are kept apart. A capability that does not exist was never "defeated at
  runtime".
- A run that **completes inside a budget** is `BOUNDED` / `CONTAINED`, not `BLOCKED`.
  A module that simply fails to **load** is not a blocked attack either — it is
  recorded `UNKNOWN` when a harness reported it as denied.
- Historical runs are labelled with their own commit + runtime. A number from an
  older wasmtime is not restated as a current one.

## Classification vocabulary

| Class | Meaning |
|---|---|
| **BLOCKED** | The primitive is reachable but the call/entry is refused at the WASM capability or call layer, so the escape cannot complete. |
| **BOUNDED** | The attack is expressible; its impact is capped to within-sandbox work by a resource ceiling (fuel / memory cap / output byte-budget / timeout). The run is stopped or contained, not denied at the call. |
| **CONTAINED** | A native failure (crash/abort) is confined to the disposable worker process; the parent/host is unaffected. This is second-boundary damage-limitation, **not** a fix to the underlying defect. |
| **ALLOWED (by design)** | The primitive stays available to guest code *inside* the sandbox; nothing reached the host. Availability to the guest is not a host escape. |
| **FAILED / UNRESOLVED** | A known defect is not closed in the pinned runtime (advisory without an available fix wheel). Never counted as a defence. |
| **UNKNOWN** | The harness result is inconclusive or was mislabelled; not claimed as blocked. |
| **NOT TESTED** | No reproducible evidence on this line (e.g. a dedicated pilot VM). |

---

## A. Eight documented attack intents — WASM capability boundary (Preview1, default config)

Harness: `benchmarks/verify_8_vectors.py`. Live check against the runtime the sandbox
links, positive controls included; exit 0 means no vector was VULNERABLE / NOT VERIFIED /
INVALID TEST. Reproduced **4 BLOCKED BY POLICY + 4 REJECTED AS UNSUPPORTED, 0
vulnerable/unverified/invalid** on the 2026-10-23 candidate tree (macOS arm64, wasmtime
49.0.4): vectors 1-3 (shell, fork, network) and 7 (threading) are structural ABI or
proposal refusals and are deliberately not counted as capability blocks. Historical
dated artifacts: macOS arm64 (2026-09-18) and DGX Spark GB10 / Linux arm64 (2026-09-20).
Comparative controls on the same intents: stock `python:3.12-slim` **0/8**, hardened
Docker **2/8** (live Docker probes — host-dependent, run only where Docker is present).

This is the statement behind the old "8/8 blocked" headline, now corrected: **eight
specific intents against one boundary on the WASI Preview1 path**, of which four are
blocked by policy and four are rejected as unsupported, not an aggregate across every
test below, and not a claim about the WASI 0.2 component path.

| # | Intent | Class | Mechanism proven |
|---|--------|-------|------------------|
| 1 | Shell / `exec` | REJECTED AS UNSUPPORTED | Real module import of exec/system/spawn through `WASISandbox`; WASI Preview1 defines no such entry point, so instantiation fails with unknown import. |
| 2 | Fork | REJECTED AS UNSUPPORTED | Same product-path instantiation for fork/vfork/clone: no such import exists. |
| 3 | Network / socket | REJECTED AS UNSUPPORTED | Same product-path instantiation for socket creation/connect: WASI Preview1 defines none. Handle-only accept/recv/send/shutdown exist, but `sock_accept` on the preopened directory fd fails with NOTSOCK — no socket can be obtained. Product-path test: `tests/test_preview1_socket_surface.py`. |
| 4 | fsync / fdatasync / psync | BLOCKED BY POLICY | Call-layer trap on all three sync entry points (import stays legal by design); `allow_fsync=True` releases fd_sync/fd_datasync as the positive control. |
| 5 | Host file read (`/etc/passwd`) | BLOCKED BY POLICY | `path_open` with no preopen → errno ≠ 0 (denied); a real file read inside a granted preopen succeeds as the positive control. |
| 6 | Symlink escape from a preopen | BLOCKED BY POLICY | Preopen capability boundary: a symlink whose target resolves outside the granted directory is refused; positive control (a real file) still opens. |
| 7 | Multi-threading (shared memory) | REJECTED AS UNSUPPORTED | The module is refused at validation (`wasm_threads=False`); the same shared-memory + atomics bytes compile and instantiate on a threads-enabled engine, proving the payload valid and the refusal structural. Not counted as a capability block. |
| 8 | Environment leak | BLOCKED BY POLICY | `allow_env=()` → guest sees 0 variables; `allow_env` with one variable makes it see exactly 1. |

---

## B. Eleven exploitation strategies from arXiv 2509.11242 (Preview1)

Table in `docs/security_posture.md` ("arXiv 2509.11242 — Tested Attack Surface").
The **per-technique verdicts** are authoritative and sum to:

- **7 BLOCKED** — fsync/fdatasync, inode exhaustion, `/dev/random` read,
  `/dev/ptmx` exhaustion, network bandwidth, small-packet flood, multi-threading.
- **3 BOUNDED** — Disk-DoS (large writes), high-frequency small I/O, memory
  exhaustion. Each is expressible and capped by a resource ceiling; memory
  exhaustion carries a known caveat (the linear-memory byte cap holds, but the
  WasmGC heap is **not** byte-bounded in the Python bindings — fuel is the effective
  GC bound).
- **1 ALLOWED within budget** — CPU-DoS / infinite loop: the guest must compute; fuel
  caps the work, the computation itself is legitimate guest activity.

**Correction recorded:** the summary line under that table originally
stated "8 blocked, 2 bounded, 1 permitted" (echoed in a whitepaper draft). That
count silently promoted the *third* bounded row (memory exhaustion) into "blocked".
The table itself marks memory exhaustion `⚠️ Bounded`. The faithful aggregate is
**7 / 3 / 1**, and it is a **Preview1 resource/capability assessment of eleven named
strategies** — not the same set as section A and not a global score.

---

## C. Resource-DoS block-rate — 4 vectors × 10 runs (wasmtime 49.0.0, 2026-10-12)

Harness: `benchmarks/pov_benchmark.py` → `benchmarks/results/2026-10-12/pov_benchmark.json`.
The harness counts a run as "blocked" when `status != SUCCESS`. Read against the
vocabulary above that metric is deliberately narrower than "defeated":

| Vector | Raw harness | Faithful class | Why |
|--------|-------------|----------------|-----|
| `cpu_dos` | 10/10 non-SUCCESS | BOUNDED | Fuel trips `FUEL_EXHAUSTED`; work was real, then capped. |
| `memory_exhaust` | 10/10 non-SUCCESS | BOUNDED | Linear-memory cap trips; GC heap caveat as in B. |
| `infinite_loop_timeout` | 10/10 non-SUCCESS | BOUNDED | Epoch/timeout interrupt stops the loop. |
| `write_flood` | **0/10** non-SUCCESS | **BOUNDED, not blocked** | The guest run **completes** because output is contained by the 10 KB byte-budget (ENOSPC) before fuel is exhausted — containment, not denial. Reporting it as a "block" would be wrong; reporting the whole group as "blocked" would be wrong. |

---

## D. Eighteen container-escape scenarios (UK AISI `sandbox_escape_bench`) mapped to WASI

Harness: `benchmarks/sandbox_escape_18.py`. This maps documented **container** escape
mechanisms onto their WASI equivalents — a structural attack-surface comparison, not
a reproduction of the agentic eval.

Cell run, `benchmarks/results/2026-09-24/04_sandbox_escape_18.json` (wasmtime 47.0.1):
**8 EXECUTION-DENIED + 10 NOT-EXPRESSIBLE, 0 open findings.** The 10 NOT-EXPRESSIBLE
rows (privileged, host-PID/ptrace, CAP_SYS_ADMIN, CAP_SYS_MODULE, cgroup
release-agent, BPF privesc, dirty-pipe, CRI-O sysctl, kubectl-cp tar, RBAC) have no
WASI surface at all — they are `BLOCKED`-by-design/absent-capability, **not** runtime
blocks, and must not be summed with A.

Two honesty flags on this benchmark:

1. The **`dirty_cow` row is reported EXECUTION-DENIED but the detail is a module
   parse error** ("threads must be enabled") — a load failure, not a defence that
   stopped an exploit. Reclassified **UNKNOWN** here; not counted as blocked.
2. The **public evidence bundle** (`benchmarks/sandbox_escape_18_evidence/`,
   2026-09-10, wasmtime 46.0.1) was run against **Ephemora Enterprise**, and states
   in its own provenance that *"the open-source Cell … was NOT scored by this run"*.
   Any "18/18 BLOCKED" claim for the OSS product is unsupported by that
   bundle; the OSS-backed result is the 2026-09-24 run above.

---

## E. Native-Linux compromised-worker OS/container wall (2026-10-13, aarch64 Ubuntu)

Harness: `deploy/linux-reference/escape_probe.py`. This is the **second boundary**:
with native code inside the worker treated as fully attacker-controlled, does the
OS/container wall still hold? It is `CONTAINMENT` evidence, not proof that the WASM
runtime blocked an escape. Two **distinct** dated runs exist and they differ, so both
are reported rather than merged:

| Scenario | `native_linux/06_escape_probe.json` (12) | `linux_reference_boundary_probe.json` (11) |
|---|---|---|
| runs as nonroot (uid 10001) | BLOCKED | BLOCKED |
| capabilities dropped (CapEff 0) | BLOCKED | BLOCKED |
| no setuid(0) | BLOCKED | BLOCKED |
| read-only rootfs | BLOCKED | BLOCKED |
| tmpfs writable | ALLOWED *(positive control)* | ALLOWED *(positive control)* |
| `/etc/shadow` read | BLOCKED | BLOCKED |
| `/root` read | BLOCKED | BLOCKED |
| egress 8.8.8.8:443 | BLOCKED | BLOCKED |
| egress 1.1.1.1:53 | BLOCKED | BLOCKED |
| DNS resolution | BLOCKED | BLOCKED |
| memory cgroup limit | **ALLOWED** — `memory.max=n/a` (limit **not observable**) | **BLOCKED** — `memory.max=536870912` (512 MiB readable) |
| pids limit (fork) | BLOCKED at 127 children | *(row absent)* |

The two runs **disagree on the memory cgroup**: one observed the limit, the other
could not read it. Faithful statement: *the container memory limit was confirmed
in force in one native run and was not observable in the other* — it is not claimed
as uniformly enforced. `tmpfs writable = ALLOWED` is a required positive control (it
proves the probe can write when it legitimately may); it is not an escape. Counting
either of these as a "blocked attack" would inflate the tally.

The `05_deep_probe.json` dump behind these rows records no_new_privs=1, Seccomp=2
(1 filter), AppArmor `docker-default (enforce)`, all capability sets zero, no
`docker.sock`, and refused writes to `/proc/sys/*` — the hardening the wall rests on.

---

## F. CVE replay (comparison benchmark)

`benchmarks/mcp_cve_replay.py` / `docs/comparison-mcp-servers.md` §5.1: CVE-2025-53110
(prefix-collision read) and CVE-2025-53109 (symlink → `/etc/passwd`) are **BLOCKED**
for Cell (no pre-opened fd / `os error 63`) while a vulnerable reference filesystem
server leaks both. The 2-replay experiment block_rate is 1.0 for the Cell arm. This is
two filesystem-escape CVEs, not a broad CVE score.

---

## G. Regression gates (WP security tests)

`tests/test_fs_escape_matrix.py`, `tests/test_host_file_boundaries.py`,
`tests/test_grant_trust.py`, `tests/test_grant_ledger.py`, `tests/test_transport.py`,
`tests/test_signed_receipt.py`, `tests/test_execution_invariants.py` and the rest of
the suite pin the behaviours above as executable gates. On the 2026-10-27 candidate tree: **2171 passing
/ 44 skipped / 85.09 % statement coverage** (gate 80 %). These are **gates, not a scored
attack matrix** — they keep the mechanisms from regressing and are not added to any
"vectors blocked" total.

---

## H. Open advisories — FAILED / UNRESOLVED, never counted as defences

The `49.0.0` development pin these runs used (see the version-scope note above)
carries advisories whose fixes were **not available as a PyPI wheel** at that
commit. They are release blockers and residual risk, not blocked attacks:

| Advisory | Nature | Status on 49.0.0 |
|---|---|---|
| GHSA-32h6-97mm-8q3c (RUSTSEC-2026-0327) | native stack-buffer overflow in async-lifted component callback result-count validation | **engine defect UNRESOLVED at the measured pin** — fix is 49.0.2, no 49.0.2 wheel on PyPI at measurement time → **release blocker** for the plain-`pip` dependency. The 1.2.0 candidate instead ships a controlled build on the **49.0.4** fix line (embedded `_libwasmtime.dylib` sha256 `247c1529…a30b`); patch parity for this specific class is **not independently verified**, so the line is treated as fixed upstream, not as proven fixed here. The product *execution* path stays **enforced-excluded at the loader**: `component_guard.py` refuses any component-model async construct (async-lift / future / stream) before the single `Component()` site, fail-closed (regression-tested). On native Linux the same abort is additionally *contained* by the worker boundary (worker crashes, parent survives). Loader exclusion + containment are **not** an engine patch. |
| GHSA-j2g9 | datetime overflow | OPEN — documented mitigation |
| GHSA-m63x | fuel amplification | OPEN — documented mitigation |
| GHSA-2r75 | TRUNCATE bypass | distinct, limited/mitigated |
| GHSA-j366 · GHSA-gqmc · GHSA-96f6 (2026-10-02 wave) | per-advisory class | OPEN — each with a documented mitigation |
| GHSA-vqjp | filesystem escape | closed by the 49 pin |
| GHSA-x84v | WASIp3 stream heap | closed in 47.0.4 |

Counting an unresolved native crash as a "blocked vector" is exactly the inflation
this document exists to prevent. See [SECURITY.md](../SECURITY.md) for the full
advisory inventory and per-ABI / per-trust / per-mode boundaries.

---

## What this matrix does **not** claim

- It does **not** roll the sections above into one "N of M blocked" number; several
  rows measure the *same* intent on a *different* boundary or platform, and BOUNDED /
  CONTAINED are not BLOCKED.
- It does **not** certify the WASI 0.2 component path with the Preview1 classification
  result (4 blocked by policy + 4 rejected as unsupported; the component sync blockade
  is absent and attested as such in [SECURITY.md](../SECURITY.md)).
- It does **not** claim a dedicated pilot-VM result (**NOT TESTED**), a completed
  independent external audit (**none yet**), or production approval (**NO-GO**).
- Native-crash **containment** is not presented as remediation of the underlying
  defect.
