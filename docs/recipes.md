# Recipes

Additional usage recipes beyond the [README](../README.md#use-cases) examples.

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
