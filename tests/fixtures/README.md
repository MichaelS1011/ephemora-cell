# WASI 0.2 (component) test fixtures

## Rust-built (wasm32-wasip2, Rust 1.92.0, wasm-tools strip -a)

- hello02.wasm — command component: prints hello, arg1=<argv[1]>,
  env_ephemora_test=<EPHEMORA_TEST>, exits ok
- fs02.wasm — command component: same output plus writes "pwned-by-component"
  into <argv[1]>/out.txt (filesystem test vector)
- exitwrite02.wasm — command component: writes exactly <argv[2]> bytes of "A"
  as ONE `std::fs::write` into <argv[1]>/out.bin (default 19 bytes when argv[2]
  is absent) and then leaves through `std::process::exit(0)`, i.e. through
  `wasi:cli/exit` instead of a normal `wasi:cli/run` return value. It therefore
  exercises the hard-exit path of the component sandbox — the route on which the
  ADR-002 I/O byte wall is enforced by the end-of-run sample (the component
  hard-exit budget case).
- exit3_02.wasm — command component: leaves through `std::process::exit(3)` and
  touches nothing else. It exists to test the ONE thing the component ABI can
  still attest: a non-zero guest exit must never be reported as success, and
  the code the host reports (1) is the code wasmtime actually observed — the
  guest's own number does not survive `wasi:cli/exit` on this ABI (measured:
  `exit(3)` and `exit(7)` both arrive as `exit status 1`). See
  `docs/languages.md` and `tests/test_guest_exit_code_fidelity.py`.

**Sources are in `src/` (hello02/, fs02/, exitwrite02/, exit3_02/) and rebuildable
byte-identically:** run `./rebuild.sh` (requires cargo with `wasm32-wasip2`
target + `wasm-tools`). Verified: `cargo build --release --target
wasm32-wasip2` then `wasm-tools strip -a` reproduces the committed `*.wasm`
(sha256 match).

`exitwrite02.wasm` (rustc 1.99.0, cargo 1.99.0, wasm-tools 1.255.0) —
sha256 `86f6142062c648eefe6008138ee5af75539609d8e6a498aafc1863da68da6b75`,
85743 bytes. NOTE (honesty): the byte-identity of hello02.wasm/fs02.wasm was
verified with the older Rust 1.92.0 toolchain named in this header; a rebuild of
those two with rustc 1.99.0 was NOT checked here. exitwrite02.wasm is a
*resource/attestation* probe (one oversized burst write under a deliberately
small `io_budget_bytes`); it is not an exploit and it does not touch anything
outside the granted directory.

`exit3_02.wasm` (rustc 1.99.0, cargo 1.99.0, wasm-tools 1.255.0) —
sha256 `ea23554173a6ee9ce44d96515faa8abe3e574b2b2bfabcb59b8c04b77f13c55d`,
52899 bytes. Byte-identity was re-verified for this fixture the strong way: a
separate copy of `src/exit3_02/` built into a fresh `CARGO_TARGET_DIR` produced
the committed bytes exactly (`cmp` clean).

## Hand-written (wasm-tools parse)

- wat_run.wasm — direct `run` export, returns 0 (no WASI imports)
- wat_loop.wasm — infinite loop `run` (fuel / epoch timeout vectors)
- wat_no_run.wasm — exports `other` only (entry-point rejection vector)

Regenerate:  wasm-tools parse wat_*.wat -o wat_*.wasm
