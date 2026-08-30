# Compile Friction per Language (measured)

`build_friction.py` → `results_2026-08-29.json` (`measured:true`), macOS arm64.

| Language | Toolchain (probe) | Hello-World → .wasm | Error Class (measured verbatim) |
|---|---|---|---|
| **Rust** | cargo 1.92 + wasm32-wasip1 installed | ✅ **2.9 s** | — |
| **Go** | not installed | — | `toolchain not installed` → hint: Go ≥ 1.21, `GOOS=wasip1 GOARCH=wasm` |
| **C** | Apple clang 17 (without wasi-sysroot) | ❌ | `fatal error: 'stdio.h' file not found` → missing WASI-SDK/wasi-sysroot |
| Python | no AOT (structural) | — | runs on the wasi-python interpreter — recipe, not a compiler (guidance) |
| AssemblyScript | npm, not installed | — | `npm i -g assemblyscript` |

## Top Error Classes `ephemora-cell build` Must Intercept

1. **Toolchain not installed** (Go, asc, rustup) → install hint with the exact command.
2. **Rust WASM target missing** → `rustup target add wasm32-wasip1`.
3. **C without wasi-sysroot** (measured: `stdio.h not found`) → WASI-SDK hint or
   a freestanding recipe (`-nostdlib --no-entry`) for guests without WASI imports.
4. **No AOT for Python** → wasi-python interpreter guidance instead of a compiler invocation.
5. **GOOS/GOARCH set incorrectly** → exact environment recipes in the recipe definition.

## `ephemora-cell build` (implemented)

`ephemora_cell/builder.py`: recipe detection (Rust/Go real builds; C/Python
guidance), `hint_for` table from this matrix, CI job `build-recipes`
(Rust target + Go installed, tests with real builds). Gate: Rust hello-world
→ .wasm 2.9 s (measured), executed in the cell; Go in CI.
