# Security Posture — Detail

Detail page for [README.md](../README.md#security). Policy and reporting: [SECURITY.md](SECURITY.md).

## Security Posture

| Risk | Status | Detail |
|------|--------|--------|
| CPU-DoS | ✅ | Fuel metering per execution (~13 fuel/iteration, **R² = 1.000**) |
| Memory-DoS | ✅ | `Store.set_limits` enforced (default 128MB; `Config.memory_max_bytes` is a no-op in wasmtime-py 47) |
| Preopen-DoS | ✅ | 14 dangerous dirs blocked (`/dev`, `/proc`, `/sys`, etc.) |
| Thread-DoS | ✅ | Single-thread only (`wasm_threads = False`) |
| fsync | ✅ | Blocked at WASI import layer — `fd_psync` → trap |
| I/O-DoS | ⚠️ Path-dependent | Host syscalls bypass fuel metering — guest output capped at 10 KB (ENOSPC); sandbox-dir writes walled by `io_budget_bytes` (both paths); the `io_cpu_seconds` CPU wall is enforced in the **subprocess path only** (default in-process is documented-trusted — see the execution-path matrix in [SECURITY.md](../SECURITY.md)) |
| Network | ✅ | No socket imports available (WASI Preview1, no network) |

## 8/8 attack vectors — verification method

5/8 vectors are executed live through the sandbox run path; 3/8 (exec, fork, socket) are verified by WASI import-surface scan — those APIs do not exist in WASI Preview1, so rejection happens at instantiate. Reproduce:

```bash
python benchmarks/verify_8_vectors.py       # 8/8 BLOCKED (live wasmtime)
python benchmarks/compile_workloads.py      # rebuild workloads/*.wasm from WAT (reproducible)
```

## arXiv 2509.11242 — Tested Attack Surface

We evaluated 11 exploitation strategies from [arXiv 2509.11242](https://arxiv.org/abs/2509.11242) against the Ephemora Cell sandbox:

| Technique | Result | Detail |
|-----------|--------|--------|
| CPU-DoS (infinite loop) | ⚠️ Within Budget | Fuel metering caps computation; set `max_fuel` conservatively |
| Disk-DoS (large writes) | ⚠️ Bounded | I/O costs minimal fuel (~1.18MB at default 1M fuel) — always capped by the 10 KB output budget (ENOSPC) |
| fsync / fdatasync | ✅ Blocked | Import-layer rejection at WASI layer |
| Inode exhaustion | ✅ Blocked | Preopen-deny + sandbox dir isolation |
| `/dev/random` read | ✅ Blocked | Preopen-deny blocks `/dev` |
| `/dev/ptmx` exhaustion | ✅ Blocked | Preopen-deny blocks `/dev` |
| High-frequency small I/O | ⚠️ Bounded | ~1.18MB theoretical before fuel exhaustion; 10 KB output budget caps capture |
| Network bandwidth | ✅ Blocked | No socket imports in WASI Preview1 |
| Small-packet flood | ✅ Blocked | No socket imports in WASI Preview1 |
| Multi-threading | ✅ Blocked | `wasm_threads = False` enforced |
| Memory exhaustion | ⚠️ Bounded | Linear memory byte-capped (`Store.set_limits`, 128MB default); the WasmGC heap is **not** byte-bounded in wasmtime-py 47 — fuel remains the effective GC bound |

**Summary:** 8 attack techniques fully blocked. 2 bounded by design (Disk-DoS, High-frequency I/O: host I/O bypasses fuel metering, ~1.18 MB theoretical before exhaustion at default fuel — and the 10 KB output budget caps captured output; the I/O budgets add host-work walls on top). 1 permitted within budget (CPU-DoS: the guest must compute).

## Fuel metering boundary (characterized)

| Workload | Fuel per unit | Exhaustion at max_fuel=1,000,000 | Linearity |
|----------|--------------|----------------------------------|-----------|
| CPU (i32.add) | ~13 fuel/iteration | 76,923 iterations | R² = 1.000000 |
| I/O (fd_write 32B, stdout path) | ~27 fuel/write | 36,985 writes (1.18 MB) — then the 10 KB output budget (ENOSPC) caps capture | Host-side syscalls (preopen file writes: ~7.3 fuel, see `benchmarks/io_dos/`) |

**I/O-DoS is a bounded boundary.** I/O system calls execute on the host and consume minimal WASM fuel (~27 fuel/write, measured), so at `max_fuel=1,000,000` a guest could theoretically emit ~1.18 MB. In practice the shared 10 KB output byte-budget (`fd_write` → ENOSPC) caps all captured output far earlier — the guest can never ship more than ~10 KB regardless of fuel. *Note:* the earlier reported "70,258 writes / 2.14 MB / ~0 fuel/call" figure was a measurement artifact — the benchmark's iovec struct overlaid its own data segment at address 0, every `fd_write` returned EFAULT and wrote 0 bytes. Fixed via proper iovec layout in [`benchmarks/fuel_boundary.py`](../benchmarks/fuel_boundary.py).

**Isolation model:** WASM memory bounds + WASI Preview1 capability-based access. See [arXiv 2509.11242](https://arxiv.org/abs/2509.11242) for a comprehensive analysis of WASM resource isolation gaps.

## Related Research

- **[arXiv 2601.01241](https://arxiv.org/abs/2601.01241)** — *MCP-SandboxScan: WASM-based Secure Execution and Runtime Analysis for MCP Tools* (SandScope): executes portable MCP tools under WASI (or drives unmodified MCP servers over stdio), extracts LLM-visible sinks and reports auditable source-to-sink witnesses — WASI as the execution/audit substrate for tool-augmented LLM agents.
- **[arXiv 2604.03081](https://arxiv.org/abs/2604.03081)** — *Supply-Chain Poisoning Attacks Against LLM Coding Agent Skill Ecosystems*: agent skills from open marketplaces run as operational directives with system-level privileges; the DDIPE attack achieves 11.6–33.5% bypass rates and 2.5% evade static analysis + alignment. Execution isolation (as provided by WASI Preview1) limits the blast radius when detection fails.
