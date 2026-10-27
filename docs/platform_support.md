# Platform support and security profiles — what is proven, where, and by which test

**Status: live, stamped per release.** Last stamped against the `1.2.0` release
candidate source on 2026-10-27. This page exists because the product is
cross-platform by design while a *guarantee* is only true where it has been
tested. It separates three things that are easy to collapse into one sentence:

1. **The core capability** — the WASM/WASI boundary, the policy and capability
   model, the resource contracts, the execution record, the library, CLI and MCP
   surfaces. This code is operating-system independent.
2. **The isolation backend** — the piece of the host that keeps the guest away
   from the host's own resources: the native subprocess worker, a hypervisor VM,
   or an OS-level sandbox. This is deliberately a swappable seam, not the
   product's identity.
3. **The platform where a claim was actually tested** — no function or security
   profile is offered as supported on a platform it was not verified on, and no
   run silently falls back from a stronger backend to a weaker one.

Read the labels this way:

| Label | Meaning |
|---|---|
| **supported** | Runs on the documented public install path, and a test that CI executes keeps the claim alive. |
| **measured** | A real-machine run exists and is named below with what it covered. |
| **open** | A gate that has not passed. Nothing may be promised on it yet. |
| **not claimed** | Outside what Ephemora-cell says it does, stated so a reader does not infer it. |

---

## 1. Core capabilities — the same code on every platform

Each row is enforced in the shipped Python package; nothing here is a
platform-specific binary.

| Capability | Enforced by | Kept alive by |
|---|---|---|
| Fuel (CPU), memory, wall-clock and output budgets | engine configuration per run | the suite plus the benchmark guard's fuel-invariance assertion |
| Default-deny filesystem, access only through revalidated preopens | `WASIConfig` + the preopen revalidation at grant time | `tests/test_fs_guest_symlink_matrix.py`, `tests/test_host_file_boundaries.py` |
| Default-deny network (Preview1 exposes no socket handle source; WASI 0.2 denies `connect` at call time) | link configuration + call-time refusal | the egress and socket refusal legs of the suite |
| Untrusted guests forced onto the disposable worker; refusal instead of downgrade | the central enforcement gate at the run entry point | `tests/test_cli_no_native_fallback.py`, `tests/test_isolation_gate.py` |
| WASI Preview1 modules and WASI 0.2 components | both ABIs in the same boundary | the ABI-split legs of the suite, `conformance/` |
| Capability grants, signed manifests, egress grants | the grant loader and the verifier | `tests/test_grant_trust.py`, `tests/test_egress_sidecar.py` |
| Cumulative per-tenant accounting: reserve → settle → refuse, with the crashed attempt booked conservatively instead of as zero | `TenantStore` | `tests/test_d2_resource_contract.py`, `tests/test_r37_resource_settlement.py`, `tests/test_r40_first_attempt_accounting.py` |
| Tamper-evident execution record, signable, hash-chained ledger | the record and ledger modules | `tests/test_cli_execution_evidence.py`, `tests/test_ledger_chain.py`, `tests/test_grant_ledger.py` |
| v1.1 ledger books stay readable, and become writable again only through an explicit migration | `TenantStore.usage(...)` read-only legacy path, `migrate_to` | `tests/test_tenant_legacy_migration.py` |

**Tested platform for the core:** macOS 15 on Apple Silicon with the qualified
runtime (`wasmtime 49.0.4.post1+git.2c2970205f`), Python 3.10–3.13, in the CI
shape (`git clone` plus the pinned requirements, no packaged language guest).
The full-suite and coverage numbers for that run are stamped in
[release_assurance.md](release_assurance.md) and quoted from there by
`README.md`, `SECURITY.md` and `docs/security_attack_matrix.md`; the
`CHECK_TEST_COUNT_STRICT=1` guard fails CI if a quoted count drifts from the
collection.

**Other operating systems:** the core is pure Python plus the Wasmtime
dependency, so it is portable, and the project intends to support it. It is
listed here as **open** rather than supported because the runtime build that the
release gates on exists for macOS arm64 only: a Linux or Windows leg could only
run an engine the release does not qualify, so CI carries no such leg. That is a
gap to close, not a claim to make.

---

## 2. Isolation backends — what each one actually proves

| Backend | Platform | Label | What the boundary is | What it does **not** prove |
|---|---|---|---|---|
| **Native worker** — a disposable subprocess running the Wasmtime engine | macOS 15 arm64 (tested); other OSes open | **supported** | The guest is a WASM sandbox with the budgets and capabilities above; the worker is thrown away per run. | A second, OS-level boundary behind the worker. If the worker process itself were compromised, the host is the same user's context. Cell does not claim otherwise. |
| **VM backend** — Apple Virtualization.framework, the product worker running inside the guest, the job and its result crossing a dedicated `hvc1` serial channel under a host mediator | macOS 15+ arm64, CLI path, operator-supplied VM assets | **supported on the CLI path / experimental as a distribution** | The guest job runs in a separate Linux VM: no host filesystem share, loopback-only networking inside the VM, the module or script bound by a host-computed digest and chunked through the channel, host actions reachable only through mediator grants the guest can ask for but never issue, a reservation that covers every restart attempt, and a settlement that books an unmeasured attempt conservatively instead of as zero. | Signed execution evidence (the VM path refuses `--evidence` rather than issuing an unsigned one and calls it out), the MCP surface over the VM backend, and any claim about VM-escape resistance. Also not distributable with this source: the kernel, initramfs and probe are third-party or locally built binaries and their redistribution is a separate, still-open clearance. |
| **Linux/other OS sandbox backends** (bubblewrap-style namespaces, or a Linux VM) | Linux, DGX-class hosts | **open** | — | Nothing yet. On the tested DGX host the OS-level isolation probe failed to establish the expected boundary (unprivileged user namespaces were not available to the harness), so **no A7-style OS isolation is claimed on Linux** and none may be advertised until a passing run exists. |

The backend is chosen explicitly — `--backend host` (the default) or
`--backend vm`. Selecting the VM backend without the assets it needs refuses the
run; it does not quietly continue on the native worker. `--trust` and
`--isolated` change nothing on the VM path, and the CLI says so, because a flag
that silently loses its meaning across backends is how a weaker boundary gets
used by accident.

What the VM record attests is separated by source, not merged into one number:
what the **guest reported** (its own fuel and output counters, `host_verified:
false` because the host did not measure them), what the **host booked** against
the tenant reservation (a conservative ceiling that is deliberately larger than
an unmeasured attempt's report, and is labelled as booked), and what the **host
observed** (boot time, wall time, transitions, cleanup). A booked ceiling is
never printed as measured consumption.

---

## 3. Security profiles by platform and backend

| Profile surface | Native worker, macOS arm64 | VM backend, macOS arm64 | Linux (any backend) |
|---|---|---|---|
| Named default-deny profiles (`code-interpreter`, `data-analysis`, …) with their budgets and declared capabilities | supported — `ephemora profile list` / `ephemora profile inspect` | budgets travel with the job into the guest runtime; the profile's host-side capabilities (`allow_dirs`, `allow_env`, egress) are **not** wired to the VM mediator, so a VM run takes none of them | open with the platform |
| Filesystem preopens | supported | not available on the VM path: the CLI refuses `--allow-dirs` there rather than mounting a host directory into a VM the operator cannot inspect | open |
| Mediated egress | supported | not available on the VM path (refused) | open |
| Tenant attribution, reservation, settlement | supported | **mandatory** — `--tenant` and `--tenant-book` are required on the VM path | open |
| Signed execution record | supported | not available on the VM path — refused with an explanation, so no unsigned file can be mistaken for an attestation | open |
| MCP tool surface over the boundary | supported (host worker) | not supported and not claimed; the MCP path does not reach the VM backend | open |

---

## 4. Open platform gates, stated as work

* **A qualified runtime for Linux and Windows.** Until a build of the qualified
  engine line exists for those platforms and runs the suite, CI carries no leg
  for them and no claim is made.
* **OS-level isolation on Linux.** The failed probe on the tested DGX-class host
  is a specific, reproducible result, not a theoretical concern. It needs a
  host configuration where the boundary can be established and then measured.
* **The VM backend's release capability.** Two pieces are missing before the VM
  path can be offered as an out-of-the-box product rather than an operator
  build: the distribution rights for the third-party VM assets, and a signed
  host-side execution record for runs that went through the VM.
* **Independent security review.** Nothing on this page is the result of an
  external audit; the separation between self-tested and externally reviewed is
  stated in [SECURITY.md](SECURITY.md).

*One line for the reader who wants the short version: the boundary logic is the
product and runs everywhere the engine is qualified; the OS-level wall is a
backend, and each backend is only promised where a run proved it.*
