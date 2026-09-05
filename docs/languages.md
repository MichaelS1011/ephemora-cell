# Languages & Interpreters

Ephemora Cell executes pre-compiled `.wasm` modules — it does not ship language interpreters. For building from source, use `ephemora-cell build <source>` (see the [README](../README.md#any-language-that-compiles-to-wasm) and [ADR-005](decisions/ADR-005-build-pipeline.md)); this page covers running interpreted languages inside the sandbox.

## WASI Preview1

Ephemora Cell currently uses **WASI Preview1** (`wasi_snapshot_preview1`), the stable WASI interface with:
- File I/O (`fd_read`, `fd_write`, `path_open`, etc.)
- Command-line arguments and environment variables
- Clock access and random data

**Preview1 limitations:**
- No network socket support (requires WASI Preview2 / Component Model)
- No process spawning
- Limited filesystem metadata operations
- No streaming I/O

**WASI 0.2 components are already supported** (opt-in via `abi="component"` or auto-detection — see [recipes](recipes.md#wasi-02-components)): command-world (`wasi:cli/run`) components run with the same security baseline as Preview1. WASI 0.3 / Preview2 network sockets remain deferred until the Component Model 1.0 spec is final (target late 2026/2027).

## Using Custom Interpreters

To run Python, Rust, Go, or other languages inside the sandbox, compile the interpreter (or your application) to WASM and execute it like any module.

**Python (CPython-WASI):**
```bash
# Build CPython for WASI (requires WASI SDK)
git clone https://github.com/singlestore-labs/python-wasi
cd python-wasi && ./run.sh  # Produces wasi-python-3.x.wasm (~150MB)

# Use with Ephemora Cell
from ephemora_cell import run_wasm
result = run_wasm("wasi-python-3.10.wasm", args=["-c", "print('Hello')"])
```

**Rust (wasm32-wasip1):**
```bash
rustup target add wasm32-wasip1
cargo build --target wasm32-wasip1 --release
```
```python
from ephemora_cell import run_wasm
result = run_wasm("target/wasm32-wasip1/release/myapp.wasm")
```

**Go:**
```bash
GOOS=wasip1 GOARCH=wasm go build -o myapp.wasm main.go
```

**Note:** Interpreter overhead (CPython: 17-140ms cold start) is not included in Ephemora Cell's performance metrics. Those measure the sandbox engine, not the guest interpreter.
