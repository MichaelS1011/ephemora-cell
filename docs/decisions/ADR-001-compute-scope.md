# ADR-001: Compute Scope — No NN/GPU Compute in Cell; Generic Host Import as an Extension Point

- **Status:** Accepted
- **Date:** 2026-08-28

## Context

An external review (2026-08-27) classifies Cell as a "CPU-focused tooling sandbox project":
as long as LLM agents can reach local models (embeddings, tokenizers, small LLMs) and
vector compute only via the CPU inside the sandbox, Cell opens no compute bottleneck —
an NN spike and an NN opt-in interface for Cell were therefore proposed.

## Research Status (2026-08-28, source-backed)

| Criterion | WASI-NN (host import) | WebGPU-in-WASM |
|---|---|---|
| Maturity | wasi-nn in wasmtime (Rust) is **Tier-3/"unsafe"**; ONNX backend only CPU execution provider ([wasmtime#8547](https://github.com/bytecodealliance/wasmtime/issues/8547)); **no binding in wasmtime-py 47** (verified locally: no submodules) | WASI-WebGPU 0.3 RC exists ([webgpu.com](https://www.webgpu.com/news/wasi-webgpu-03-rc-gpu-compute/)); browser context is mature: WebLLM (arXiv 2412.15803), WgPy (arXiv 2503.00279) |
| Isolation depth | Controlled host functions, capability principle implementable | GPU access is broader; isolation via host bridge not yet consolidated |
| Hardware | CPU execution provider today; GPU provider open | wgpu bridge conceivable natively, but no wasmtime-py path |
| Cell effort | NN spike + interface = a new feature area in the sandbox core | the same, plus the driver/bridge question |

## Decision

1. **Compute (NN/GPU inference) is not in Cell's scope.** Cell builds neither an NN spike nor an
   NN interface; the scope remains isolation + deterministic execution.
2. **Cell commits only to the interface:** the generic, controlled
   opt-in host-import mechanism (`linker.define`, capability principle as with memory64,
   default-OFF). It comes into existence anyway, in generic form, through the I/O-budget
   and state work — a later compute host import could use the same mechanism without
   having to fork Cell.
3. **Documentation discipline:** compute claims in the Cell docs carry only `measured` numbers
   from existing CPU benchmarks.

## Consequences

- Positive: Cell keeps its clear scope (isolation, no feature drift toward an
  inference engine); the only point that was open before the release is eliminated.
- Risk: Cell remains without its own compute differentiator — accepted, because Cell's
  differentiation is isolation + the MCP channel (see MCP-SandboxScan, arXiv 2601.01241).
- Reversible? Yes — a later Cell NN spike would be a new ADR with the same
  host-import mechanism.
