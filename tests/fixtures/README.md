# WASI 0.2 (component) test fixtures

## Rust-built (wasm32-wasip2, Rust 1.92.0, wasm-tools strip -a)

- hello02.wasm — command component: prints hello, arg1=<argv[1]>,
  env_ephemora_test=<EPHEMORA_TEST>, exits ok
- fs02.wasm — command component: same output plus writes "pwned-by-component"
  into <argv[1]>/out.txt (filesystem test vector)

**Sources are in `src/` (hello02/, fs02/) and rebuildable byte-identically:**
run `./rebuild.sh` (requires cargo with `wasm32-wasip2` target +
`wasm-tools`). Verified: `cargo build --release --target wasm32-wasip2`
then `wasm-tools strip -a` reproduces the committed `*.wasm` (sha256 match).

## Hand-written (wasm-tools parse)

- wat_run.wasm — direct `run` export, returns 0 (no WASI imports)
- wat_loop.wasm — infinite loop `run` (fuel / epoch timeout vectors)
- wat_no_run.wasm — exports `other` only (entry-point rejection vector)

Regenerate:  wasm-tools parse wat_*.wat -o wat_*.wasm
