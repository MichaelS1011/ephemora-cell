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
