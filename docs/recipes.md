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
timeout). WASI 0.3 is deferred until the
Component Model 1.0 spec is final (target late 2026/2027).

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
