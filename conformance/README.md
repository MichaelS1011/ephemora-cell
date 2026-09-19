# WASI Conformance — wasi-testsuite against Ephemora Cell

Runs the official [WebAssembly/wasi-testsuite](https://github.com/WebAssembly/wasi-testsuite)
preview-1 suite against the shipped `ephemora-cell` CLI via a runtime
adapter. This is the standards-conformance evidence for the WASI Preview 1
sandbox: every test either passes, is a documented by-design deviation
(`expectations.toml`), or is excluded by the runner because Cell does not
declare that WASI version (preview 3).

## Core spec suite (W3C Wasm 3.0 era)

`conformance/run_core_spec.py` runs the **official WebAssembly core spec
suite** ([WebAssembly/testsuite](https://github.com/WebAssembly/testsuite),
pinned commit, `wast2json` + harness) against the exact engine
configuration Cell ships. Files execute in isolated subprocesses, so a
native upstream abort on one module cannot kill the suite. Every deviation
is a documented class — memory64/multi-memory modules sit outside the
shipped config by design, v128 cannot pass through the wasmtime-py 47
binding (valkind 4), relaxed-simd modules abort natively upstream,
text-format asserts are skipped (wabt parser domain) — and the remainder
is listed verbatim in the evidence JSON rather than swept into a pass
count.

```bash
.venv/bin/python conformance/run_core_spec.py   # requires wast2json (wabt)
```

Latest run (2026-09-18, pinned `b464a4cd100d`, 257 files / ~36k commands,
macOS arm64, wasmtime 47.0.1): **31,931 pass** — 3,282 classified
deviations/limitations, 684 text-format skips, 46 documented binding-level
NaN-bit remainder; zero unexpected sandbox-policy failures.

## WASI suite

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

## Known runner-level instability (ubuntu CI)

The weekly CI runs on `ubuntu-latest` x86_64 and has shown rare
wasmtime-py 47.0.1 engine aborts (exit -6, "panic in a function that
cannot unwind") on **varying** filesystem tests: `path_open_dirfd_not_dir`
(run 2026-09-15) and `fopen-with-no-access` (run 2026-09-17) — each 71/72,
each a different test, neither reproducible locally on macOS arm64 nor in
a clean linux/amd64 container against the same binary. This is engine-level
instability on shared runners, not a Cell conformance defect; the failing
test changes, so no per-test expectation entry is made (that would pin the
wrong test and add xpass noise on macOS). Tracked as watch-item for the
next wasmtime upgrade; the committed per-date result JSONs record the raw
outcomes.

Entries must always carry a reason tied to a documented policy. Real
conformance bugs do not belong here — they are fixed or reported as
findings. Two real bugs found and fixed during the first triage run:
repeated `--allow-env`/`--allow-dirs` flags silently overwrote each other
(argparse `nargs="*"` replaces instead of accumulating), and `allow_dirs`
had no way to express a guest-side preopen name.
