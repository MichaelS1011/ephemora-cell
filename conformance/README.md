# WASI Conformance — wasi-testsuite against Ephemora Cell

Runs the official [WebAssembly/wasi-testsuite](https://github.com/WebAssembly/wasi-testsuite)
preview-1 suite against the shipped `ephemora-cell` CLI via a runtime
adapter. This is the standards-conformance evidence for the WASI Preview 1
sandbox: every test either passes, is a documented by-design deviation
(`expectations.toml`), or is excluded by the runner because Cell does not
declare that WASI version (preview 3).

**Honest scope.** This is standards conformance, not a security
certification: it measures whether Cell speaks WASI the way the spec says,
and no third party certifies Cell. What makes it evidence rather than a claim
is the pinned upstream commit, the committed per-date result JSON, and the
weekly CI re-run that surfaces drift within a week. The security posture of
the same sandbox is argued separately — see
[docs/security_posture.md](../docs/security_posture.md) and
[SECURITY.md](../SECURITY.md).

## Core spec suite (W3C Wasm 3.0 era)

`conformance/run_core_spec.py` runs the **official WebAssembly core spec
suite** ([WebAssembly/testsuite](https://github.com/WebAssembly/testsuite),
pinned commit, `wast2json` + harness) against the exact engine
configuration Cell ships. Files execute in isolated subprocesses, so a
native upstream abort on one module cannot kill the suite. Per-file results
are cached, and a cached entry is reused only when it carries the identity of
the runtime version, engine configuration and pinned suite it was measured
under — an entry without that stamp is re-measured, because unknown
provenance is not evidence.

```bash
.venv/bin/python conformance/run_core_spec.py   # requires wast2json (wabt)
```

Latest run (2026-10-21, pinned `b464a4cd100d`, 257 files, 35,942 harness
outcomes from the 157 files that completed,
macOS arm64, wasmtime `49.0.3.post2+git.1d21c90f` — the then-qualified runtime,
withdrawn 2026-10-22; conformance was **not** re-run on 49.0.4):
**31,896 pass / 3,281 classified deviations-and-limitations / 684 text-format
skips / 81 failures the harness does not classify**, so the harness exits `1`.
This job is evidence, not a release gate, and the 81 are itemised in the
evidence JSON rather than swept into a pass count. Their composition, measured
case by case:

- **29 on modules the shipped posture refuses by design.** 14 are parse-time
  refusals: 9 name the exceptions proposal directly, 5 name the constant-expression
  and table-initializer forms that only exist inside the proposals Cell enforces
  off (GHSA-m63x-6p34-q65x). The other 15 are later assertions of the same files
  that depend on those modules having registered (7 `KeyError` on a name no module
  exported, 7 “no module to resolve”, 1 `register` on an unknown module).
- **29 exact-bit float comparisons.** In 24 the engine's NaN payload is not
  recoverable through the Python binding (the value arrives as a plain float), in
  5 wasmtime propagates a different payload than the reference interpreter's bit
  pattern. Neither is a Cell behaviour claim; both are harness/binding limits on
  reading the result.
- **12 where a module imports an item the harness's spectest environment does
  not provide** (`test.func*`, `test.global*`, `spectest.print`).
- **8 table and bulk-operation cases** (7 traps where the spec expects a value,
  1 differing trap text) and **3 `local_init` validation cases**, all long-standing
  and unchanged by the current runtime.

The **3,281 classified** figure deserves one caveat: 100 of the 257 files are
counted as deviations because the process running them died in the upstream
engine, and an aborted file has **no per-command measurement at all**. Their
sources contain about 31,330 command-shaped forms (against 69,853 across all
257 `.wast` sources by the same pattern count), so neither the pass count nor
the deviation count is a full-suite measurement. The
harness labels every abort as an upstream native abort without inspecting the
cause (`aborted_files` in the evidence JSON records the count), so those 100 are
an upstream outcome report, not a conformance measurement.

None of them is a sandbox-policy outcome: this harness drives the engine
directly, and the policy layer is measured by the WASI suite below and by the
security harnesses. The earlier published figure — 31,931 pass / 46 fail — was
measured under wasmtime 47.0.1 and before the proposal lockdown entered this
harness's engine configuration; the corrected numbers above are what the
shipped configuration measures today.

## WASI suite

The rest of this file is the preview-1 wasi-testsuite run: the orchestrator, the
runtime adapter, the by-design deviation list and the runner-instability note.

### Run

```bash
.venv/bin/python conformance/run_wasi_testsuite.py
```

The orchestrator:

1. checks out the suite at the **pinned commit** into
   `.conformance_cache/wasi-testsuite` (gitignored — never vendored) and
   **verifies the checkout is on that commit** before measuring — a cache left on
   another revision aborts the run instead of labelling its results with the pin,
2. invokes the suite's own `run-tests` with `adapters/ephemora_cell.py`
   and `expectations.toml`,
3. writes the raw JSON plus a `summary-*.json` digest into `results/`, counting
   each test by its own recorded outcome and reporting the runner's per-suite
   header alongside whenever the two disagree.

Latest run (2026-10-21, pinned `609c44613995`, observed revision identical to the
pin, macOS arm64, wasmtime `49.0.3.post2+git.1d21c90f` (withdrawn; not re-run
on 49.0.4), ephemora-cell 1.2.0):
**71 pass, 1 documented by-design expected-failure, 0 fail** across the 72 tests
the preview-1 suites execute; 55 preview-3 tests skipped (Cell declares preview 1
only). The run needed no engine-abort retry at all (`engine_abort_retries: []`).
An earlier version of this document said **72 pass / 1 xfail** for the same 72
tests: the upstream runner's per-suite header counts an expected failure inside
its `passed` column, and this harness copied the header, so the two figures
described 73 results from 72 executions. The summary now counts the per-test
outcomes (71 + 1) and keeps the diverging header in the evidence file.
Evidence: `conformance/results/summary-609c44613995-2026-10-21.json`.

### Adapter

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

**Absorbing the flake without hiding it.** CI runs the suite through
[`adapters/cell_retry_wrapper.py`](adapters/cell_retry_wrapper.py): a
test whose process dies with SIGABRT (exit -6) is rerun once; every
other exit code — including genuine conformance failures — passes
through untouched, and a second abort still fails the test. Each retry
is appended to `results/engine_abort_retries.jsonl` and echoed into the
run's `summary-*.json` under `engine_abort_retries`, so the committed
evidence shows exactly which runs needed a retry and for which test.
The wrapper never decides an outcome; it only absorbs the documented
engine abort.

Entries must always carry a reason tied to a documented policy. Real
conformance bugs do not belong here — they are fixed or reported as
findings. Two real bugs found and fixed during the first triage run:
repeated `--allow-env`/`--allow-dirs` flags silently overwrote each other
(argparse `nargs="*"` replaces instead of accumulating), and `allow_dirs`
had no way to express a guest-side preopen name.
