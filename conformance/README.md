# WASI Conformance — wasi-testsuite against Ephemora Cell

Runs the official [WebAssembly/wasi-testsuite](https://github.com/WebAssembly/wasi-testsuite)
preview-1 suite against the shipped `ephemora-cell` CLI via a runtime
adapter. This is the standards-conformance evidence for the WASI Preview 1
sandbox: every test either passes, is a documented by-design deviation
(`expectations.toml`), or is excluded by the runner because Cell does not
declare that WASI version (preview 3).

## Run

```bash
.venv/bin/python conformance/run_wasi_testsuite.py
```

The orchestrator:

1. checks out the suite at the **pinned commit** into
   `.conformance_cache/wasi-testsuite` (gitignored — never vendored),
2. invokes the suite's own `run-tests` with `adapters/ephemora_cell.py`
   and `expectations.toml`,
3. writes the raw JSON plus a `summary-*.json` digest into `results/`.

Latest run (2026-09-14, pinned `609c44613995`, macOS arm64, wasmtime 47.0.1,
ephemora-cell 1.0.1): **72 pass, 1 xfail (documented), 0 fail**; 55 preview-3
tests skipped (Cell declares preview 1 only).

## Adapter

`adapters/ephemora_cell.py` maps every test onto the real CLI execution
path — conformance exercises the shipped command, not a private shortcut:

```
ephemora-cell run <test.wasm> --fuel 100000000 --timeout 30 \
    --stdin /dev/null [--allow-env K=V ...] \
    [--allow-dirs <root>::/] [-- --args]
```

Policy knobs are raised above CLI defaults (fuel 100M) so a failure means
WASI non-conformance, never Cell's default resource budgets. The
`host::guest` preopen mapping (guest name `/`) matches wasmtime's
`--dir host::/` convention that wasi-libc-built tests rely on for
relative-path resolution; validation stays on the host side. stdin is
bound to `/dev/null` (the runner holds its pipe open; Cell's piped-stdin
auto-capture would otherwise block until timeout).

## By-design deviations (`expectations.toml`)

Uses the suite's native TOML expectations (`expected = "fail"` / `action =
"skip"`), not a fork of the runner. Current entries:

- `sock_shutdown-invalid_fd` (C suite): the test asserts `EBADF` for
  `shutdown(fd=3)` assuming a runtime with **no preopens**. Cell always
  preopens its sandbox scratch dir as fd 3 (default-deny filesystem
  posture), so fd 3 is a directory and the call returns `ENOTSOCK`. The
  network surface itself stays closed — no socket APIs are granted — which
  is the property Cell claims; only the errno of this negative test differs.

Entries must always carry a reason tied to a documented policy. Real
conformance bugs do not belong here — they are fixed or reported as
findings. Two real bugs found and fixed during the first triage run:
repeated `--allow-env`/`--allow-dirs` flags silently overwrote each other
(argparse `nargs="*"` replaces instead of accumulating), and `allow_dirs`
had no way to express a guest-side preopen name.
