# Recipes

Additional usage recipes beyond the [README](../README.md#use-cases) examples.

## Choosing preopen directories (`allow_dirs`)

`allow_dirs` entries are realpath-canonicalized and denied if they resolve
into a blocked root (`/etc`, `/usr`, `/proc`, ...). The macOS temp roots are
allowed explicitly for Linux parity: `/tmp` and `tempfile.mkdtemp()`
directories resolve to `/private/tmp` / `/private/var/folders/...` and are
accepted. Everything else under `/private` (e.g. `/private/etc`) stays
forbidden, as do entries swapped into a forbidden location between
validation and grant (grant-time revalidation):

```text
ValueError: allow_dirs entry '/private/etc' is forbidden: canonical path
'/private/etc' resolves into blocked location '/private'
```

The canonical check is the authority — a symlink that resolves outside the
allowed roots is rejected.

## Reading `run --json` output

`--json` prints exactly one JSON document on **stdout** (the
`ExecutionReport` schema plus `stdin_capped`); guest stdout and stderr are
routed to **stderr** so the document stays parseable:

```bash
ephemora-cell run tool.wasm --json 1>report.json 2>guest.log
python -m json.tool report.json
```

Without the redirections the report is still the only thing on stdout — the
guest output appears on the terminal's stderr channel, which trips up
`ephemora-cell run tool.wasm --json | python -m json.tool` only if the guest
writes to stderr *and* the shell merges streams (`2>&1`).

## Troubleshooting

The usual suspects the README's Quick Start warns about, with the mechanism
behind each failure:

**`externally-managed-environment` on `pip install`** — the interpreter is
system-managed (PEP 668; Ubuntu ≥ 23.04, Fedora) and refuses packages
installed outside a virtualenv. Create one and install inside it:

```bash
python3 -m venv .venv && source .venv/bin/activate
python -m pip install ephemora-cell
```

**`python3` not found on Windows** — Windows installs the launcher as
`python`; a bare `python3` may resolve to the Microsoft Store stub. Use
`python -m venv .venv` and `python -m pip ...` there, while Git Bash and WSL
behave like Linux (`python3` works) — the same note as the README Quick
Start.

**Tool not found / wrong `.wasm` path in an MCP client** — the server
resolves a relative `--tools-dir` against its own process working directory
(whatever the client spawned it with), not against your shell's. Point
`--tools-dir` at an absolute path (see [docs/mcp.md](mcp.md)). For the
build side: `ephemora-cell build` writes `<crate>.wasm` into the cargo
project root (Rust) or `<stem>.wasm` next to the source (Go, C,
AssemblyScript, Zig); `--out` overrides. `ephemora-cell inspect <module>`
confirms the file is where you think it is.

**`fuel_exhausted` / `timeout` on a legitimate workload** — the run hit its
budget, it did not crash. `run --json` reports `fuel_consumed` against
`fuel_budget`; raise `--fuel` / `--timeout` / `--memory-mb` (or the matching
`WASIConfig` fields, or a larger profile, e.g. `--profile analytical`), and
read back the effective posture via the MCP `get-policy` tool or the
report's `security_baseline` block.

**stdout ends with `[... truncated]`** — the guest wrote past the 10 KB
output cap (10,000 bytes; stdout and stderr share one budget). There is no
fuller copy on the host: writes past the budget are rejected at the guest's
write call, so large results belong in a preopened file (`--allow-dirs`),
not in stdout.

## Serverless Functions (Edge/Cloud)

Replace Docker with WASM for faster, safer function execution:

```python
from ephemora_cell import run_wasm

# 0.66ms cold start — measured in the historical Docker comparison (2026-08-06,
# see docs/performance.md)
result = run_wasm("transform.wasm", max_fuel=100_000)
return {"data": result.stdout}
```

## Offline Code Validation (Air-Gapped)

Self-hosted validation without internet access or third-party SaaS:

```python
from ephemora_cell import WASISandbox, WASIConfig

# No API keys, no network calls — runs locally
sandbox = WASISandbox(config=WASIConfig(
    max_memory_mb=64,
    max_fuel=1_000_000,
    timeout_seconds=10
))
result = sandbox.run("supplier_module.wasm")
```

## WASI 0.2 Components

Run stable Component-Model components (Rust `wasm32-wasip2`, `cargo component`, jco):

```python
from ephemora_cell import run_wasm
result = run_wasm("my_component.wasm")  # abi="auto" detects components by magic bytes
# or explicitly:
result = run_wasm("my_component.wasm", abi="component", max_fuel=5_000_000)
```

Command-world (`wasi:cli/run`) components only. Same security baseline as
Preview1 (memory64 opt-in per config — default off; multi-memory and threads
frozen, canonical preopen allowlist, byte-budgeted output, fuel + epoch
timeout).

**WASI 0.3 position (explicit, 2026-09-25): gate-off.** WASI 0.3 shipped
2026-06-11 with native async on Component-Model primitives; Cell stays on
the synchronous 0.2 surface for untrusted code — both because the engine's
WASIp3 streams implementation has a fresh host-allocation advisory
([GHSA-x84v-gj2h-g759](https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-x84v-gj2h-g759),
patched in 47.0.4/46.0.3) and because native async buys nothing for
budgeted synchronous calls while adding overhead. Structurally, the surface
is unreachable today (the Python binding's component linker exposes only
`add_wasip2`/`add_wasi_http` — asserted in
`tests/test_surface_audit.py`) and the async base is gated off in the
engine config (`wasm_stack_switching=False`, attested in the security
baseline). WASI 0.3 support is deferred until the Component Model 1.0 spec
is final (target late 2026/2027), the wasmtime patch line ships in the
Python wheels, and the 0.3 surface gets its own budget qualification.

## Interpreter guests (bring your own)

ADR-009 Tier 2: Cell ships no interpreters, but it will run one as the guest —
the interpreter is just a module, and the same boundary applies to it. The
default budgets are calibrated for a compiled module, so an interpreter needs
the `interpreter` profile (or the same four knobs by hand):

| Knob | Default | Interpreter profile | Why the interpreter needs more |
|---|---|---|---|
| `max_wasm_bytes` | 32 MiB | 512 MiB | interpreter binaries are 10–150 MB |
| `max_memory_mb` | 128 | 1024 | runtime heap + the guest's own module table |
| `max_fuel` | 1 000 000 | 1 000 000 000 | boot alone burns ~10⁸ (measured, see below) |
| `timeout_seconds` | 30 | 120 | startup is not instant |
| `io_cpu_seconds` | 2.0 | 30.0 | the ISOLATED worker must first compile a 22 MB guest — measured 5.40 s of host CPU per run, which the 2.0 s default wall kills before CPython starts |

That is the whole profile — five values, and no change to the security
posture. In particular `allow_fsync` stays `False`: CPython imports
`fd_datasync` at startup but never calls it, which is measured
(`benchmarks/interpreter_guest/probe_datasync.py`), so the sync wall stays
closed for interpreter guests exactly as it is for compiled ones.

Pinned example — CPython-WASI 3.10 (`python3.10.wasm`, sha256
`8e40bfb538b390c1e8b652f4b4369d83d3fd6d1af6b3111631ad80bf0c5a0a02`,
22 363 477 bytes, from the `v3.10-alpha` release of
`singlestore-labs/python-wasi`):

```bash
ephemora-cell run opt/wasi-python/bin/python3.10.wasm \
  --profile interpreter --isolated \
  --allow-dirs "$PWD/opt/wasi-python/lib/python3.10::/opt/wasi-python/lib/python3.10" \
  -- -c "print('hello from CPython in the Cell')"
```

That build carries no embedded stdlib, hence the stdlib preopen on the guest
path CPython was configured with. Two consequences worth knowing before you
depend on this: the preopen is **writable**, so CPython creates
`__pycache__/*.pyc` inside it and an unprimed tree costs up to 5× the fuel per
boot (357 M → 71.5 M over six boots, measured) while wall time moves only by
about 100 ms —
so budget by fuel, not by latency; and the profile raises budgets only — it
grants no filesystem or environment access and no language claim.
Measured cost per call and the memory breakpoint:
`benchmarks/interpreter_guest/measure.py` →
`benchmarks/results/2026-10-02/interpreter_guest.json`. Full caveats and both
API and CLI forms: [languages.md](languages.md).

## FastAPI Integration

The engine is synchronous. Run in a thread pool for async environments:

```python
from fastapi import FastAPI
from pydantic import BaseModel
import asyncio
from ephemora_cell import run_wasm

app = FastAPI()

class WASMRequest(BaseModel):
    wasm_path: str
    max_fuel: int | None = 500_000
    timeout_seconds: int = 10
    allow_dirs: tuple[str, ...] = ()  # Empty = no filesystem access

@app.post("/execute")
async def execute_wasm(req: WASMRequest):
    result = await asyncio.to_thread(
        run_wasm,
        req.wasm_path,
        max_fuel=req.max_fuel,
        timeout_seconds=req.timeout_seconds,
        allow_dirs=req.allow_dirs
    )
    return {"status": result.status, "stdout": result.stdout, "elapsed_ms": result.elapsed_ms}
```

**Trusted fast path (pooled).** The snippet above builds a fresh sandbox
per request — the honest default for untrusted input, carrying the
ADR-002 I/O wall and its per-run engine (1.06 ms median, measured,
`benchmarks/results/`). For modules you *trust* (your own, signed — see
the governed-loading section in [docs/mcp.md](mcp.md)), keep one sandbox
with a pooled engine and skip the byte wall:

```python
from ephemora_cell import WASIConfig, WASISandbox
from dataclasses import replace

pooled_config = replace(WASIConfig(max_fuel=500_000), io_budget_bytes=None)
sandbox = WASISandbox(config=pooled_config)  # module-level, one per process

@app.post("/execute-trusted")
async def execute_trusted(req: WASMRequest):
    result = await asyncio.to_thread(sandbox.run, req.wasm_path)
    return {"status": result.status, "stdout": result.stdout, "elapsed_ms": result.elapsed_ms}
```

Pooled warm runs measured 0.48 ms end-to-end (median, n=1000) — roughly
2,000 sequential runs per core per second derived from that figure; with
a shared engine, concurrent calls on one sandbox instance are not
isolated from each other (single-tenant process), so keep one sandbox
per worker process and route untrusted input through the walled path.

## Verifiable execution records (sign/verify)

Every run folds into an `ExecutionReport` — status, fuel, timing and the
attested `security_baseline`. `sign()` turns that record into a
tamper-evident audit artifact: the signing input is the RFC 8785 (JCS)
canonicalization of the whole record (deterministic bytes — same record,
same signature, regardless of key order), and `verify()` recomputes it.
Any rewrite of a signed record breaks verification:

```python
from ephemora_cell import ExecutionReport, WASIConfig, WASISandbox
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

key = Ed25519PrivateKey.generate()  # BYO keys — Cell is signer-agnostic

def _ed25519_verify(key):                     # the operator's verifier:
    from cryptography.exceptions import InvalidSignature

    public = key.public_key()

    def _verify(canonical: bytes, signature: bytes) -> bool:
        try:
            public.verify(signature, canonical)
            return True
        except InvalidSignature:
            return False

    return _verify

config = WASIConfig(max_fuel=1_000_000)
sandbox = WASISandbox(config=config)
result = sandbox.run("tool.wasm")
sandbox.cleanup()

report = ExecutionReport(
    status=result.status.value,
    exit_code=result.exit_code,
    elapsed_ms=result.elapsed_ms,
    fuel_consumed=result.fuel_consumed,
    fuel_budget=config.max_fuel,
).apply_config(config, effective_preopens=result.effective_preopens)

signed = report.sign(key.sign, alg="EdDSA")
assert ExecutionReport.verify(signed, _ed25519_verify(key)) is True

signed["fuel_consumed"] += 1            # someone rewrites the history ...
assert ExecutionReport.verify(signed, _ed25519_verify(key)) is False  # caught
```

### Pre-exec / receipt split (ADR-008)

Sign what a run *will* do before it runs, then bind the receipt to it:

```python
from ephemora_cell import PreExecutionRecord, verify_chain

pre = PreExecutionRecord.build(module_path="tool.wasm", config=config)
signed_pre = pre.sign(key.sign, alg="EdDSA")

# ... run the sandbox ...
report.back_link = {
    "pre_exec_id": signed_pre["id"],
    "pre_exec_digest": pre_exec_digest,  # sha256 of the JCS payload
}
assert verify_chain(signed_pre, report.sign(key.sign, alg="EdDSA"),
                    _ed25519_verify(key))
```

For ecosystem interop the same records wrap into DSSE v1 envelopes
(`report.to_dsse(key.sign, alg="EdDSA")`, verified with
`dsse_verify`) or detached JWS (`detached_jws_sign`, RFC 7797) — all
over the same RFC 8785 JCS bytes, so digests agree across formats.

A complete runnable demo lives in `examples/signed_record_demo.py`
(needs the optional `tools-signing` extra):

```text
$ python examples/signed_record_demo.py
record: success | fuel: 1
verify(intact): True
verify(tampered): False
```

Design notes:

- **Cell is signer-agnostic** — `sign()`/`verify()` take opaque
  bytes→bytes callables. The Ed25519 helper shown above (optional
  `tools-signing` extra) is one option; a KMS-backed signer is another.
  The signature covers every field including `security_baseline`, so the
  attested posture (wasmtime version, limits, preopens) is signed with
  the outcome.
- **What it is good for:** record-keeping/audit-trail duties (for
  example the EU AI Act's Art. 12 logging requirement for high-risk
  systems) — it makes a run's attested posture verifiable after the
  fact. This is a building block, not a compliance statement; custody
  and evidence workflows are Ephemora-enterprise territory.

## Auto-grading untrusted submissions (education / hiring)

Grading student or candidate code is running untrusted code with a
budget — exactly what the Cell enforces. Every failure mode maps to a
status, so an infinite loop becomes a *grade*, never a host crash, and
the 10 KB output cap bounds what a submission can exfiltrate:

| Status | Verdict |
|---|---|
| `success` | pass (optionally: output must match an expectation) |
| `fuel_exhausted` | fail — exceeded the compute budget |
| `timeout` | fail — exceeded the wall-clock budget |
| `memory_exceeded` | fail — exceeded the memory budget |
| `error` | fail — crashed or exited non-zero |

`fuel_consumed` doubles as a cost/effort meter: deterministic work the
submission caused, comparable across runs. Give every submission the
same `WASIConfig` (e.g. `max_fuel=1_000_000`, `max_memory_mb=128`,
`timeout_seconds=5`) — the budget is set by the institution, never by
the student.

A runnable grader lives in `examples/auto_grader.py`; its live output
over three submissions (correct / compute bomb / memory hog):

```text
correct.wasm         pass  success          fuel=1 — correct under budget
compute_bomb.wasm    fail  fuel_exhausted   fuel=1000000 — exceeded the compute budget
memory_hog.wasm      fail  memory_exceeded  fuel=None — exceeded the memory budget
```

## Throughput scale-check (single core)

The README's throughput claim regenerates from a fresh clone with this
snippet (same workload, `examples/hello.wasm`, n=500):

```python
from ephemora_cell import run_wasm
import time

t0 = time.perf_counter()
for _ in range(500):
    run_wasm("examples/hello.wasm", max_fuel=1_000_000)
per_hour = 500 / (time.perf_counter() - t0) * 3600
print(f"{per_hour/1e6:.1f}M executions/hour on this core (one-liner path)")
```

Reuse one `WASIConfig`/sandbox across calls in a hot loop to reach the
pooled path (~5.5M/hour measured). Raw evidence:
`benchmarks/results/` (`measured:true`), more scenarios in
[docs/performance.md](performance.md).
