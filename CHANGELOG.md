# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- **Three operator commands: `doctor`, `verify`, `policy check`.**
  `ephemora doctor` checks the installation, platform, runtime line and engine
  identity and then runs one real smoke execution; `--json` emits a schema-tagged
  report and the exit code follows the verdict, so a runtime outside the qualified
  line fails the command instead of warning and passing. `ephemora verify
  <artefact>` re-checks existing execution evidence — a JSONL ledger, a DSSE
  envelope, a signed record or a pre-exec/receipt chain — and states which half of
  the claim it actually proved: linkage needs no key, authorship needs `--key`, and
  a signed artefact checked without one exits `3` rather than reading as a pass.
  `ephemora policy check` shows the permissions and isolation a run WOULD carry
  (budgets, effective vs. refused preopens, the ADR-015 isolation path per ABI, the
  sync blockade, the policy fingerprint) from the same authoritative primitives the
  runtime reads, and exits non-zero when a requested directory would be refused, so
  `policy check && run` composes as a gate. `--language python|javascript` views the
  interpreter-profile budgets a source guest really gets, and it also names what the
  adapters add — per artifact, because the grant set is not one fixed answer: a
  Python run replaces the caller's `allow_dirs` either way, but the installed
  WASI-0.2 component guest gets a single throwaway per-run `/work` directory and
  no `/sandbox` scratch, while a legacy Preview1 interpreter guest also mounts its
  own stdlib and the script's own directory at `/work` plus the run's ephemeral
  `/sandbox`; a JavaScript source run replaces the grants with one private `/work`
  and a pre-compiled JavaScript module run keeps them. Replaced entries are listed
  as `dropped_allow_dirs`, a caller directory an adapter branch would drop is
  reported under `allowed (pre-adapter)`, and each branch names the ABI it runs
  under — so an `--abi` that
  contradicts a language adapter (any concrete one for Python, whose ABI the guest
  bytes decide; `component` for JavaScript, which is always Preview1) is refused
  with exit `2` instead of answered with a snapshot of a run that cannot happen.
  Both guests are forced into the disposable worker — an explicit `trusted`
  posture does not open an in-process path for a source run — and a language
  view's `fingerprint` carries a `fingerprint_note` saying it digests the caller's
  configuration, not the adapter's.
  `--isolated` raises the view the way the run gate raises isolation — never lowers it.
- **One entry point and one flag surface across WASM, Python and JavaScript.**
  `run` takes a `.wasm` module or a `.py`/`.js` source file
  (`--language auto|wasm|python|javascript`, detected by extension when `auto`) with
  the same budget, preopen and trust flags throughout. A missing language guest fails
  closed with the single documented install command: nothing is downloaded and no host
  interpreter is ever executed. The `ephemora` console script is declared in the
  packaging metadata alongside `ephemora-cell`, so a fresh install of this release's
  build puts it on the PATH.
- **The language grant claims are measured, not asserted.**
  `benchmarks/language_grant_evidence.py` runs all four adapter entries with real
  guests and compares, per branch, the `allow_dirs` the adapter builds (guest and
  host path), the ABI it passes, the worker flag, the run-side `effective_preopens`
  including `/sandbox`, and the guest's own `argv`. Guest digests are pinned, so a
  substituted guest cannot silently stand in for the measurement; a missing guest is
  reported `NOT-MEASURED`. `benchmarks/results/2026-10-19/language_grant_views_measured.json`
  is the recorded run (five claims, all `MATCH`, on the qualified 49.0.3 runtime).
  Machine-specific prefixes in that artefact are replaced by `<repo>`/`<tmpdir>`
  labels at serialisation time only — the comparison itself still runs against
  resolved real paths.
- **Exit-status fidelity is a field on the record, not a footnote.** The
  WASI-0.2 Python guest does not carry its script's exit status to the host
  (`sys.exit(3)` reads as `success`), and the JavaScript guest reports a thrown
  error through its marker and returns cleanly. A component that hard-exits
  non-zero is never read as success, but its ABI delivers only the non-zero
  fact: `std::process::exit(3)` and `exit(7)` both arrive to wasmtime as
  `exit status 1` (measured on `49.0.3`). Every `run` result now carries
  `exit_status_fidelity` — `exact` (Preview1 `.wasm` and the Preview1 CPython
  interpreter), `non_zero_only` (component `.wasm`), `none` (the component
  Python guest, the QuickJS source route) — `ephemora run` prints one stderr
  note on a `none` route instead of leaving `success` unqualified, and nothing
  invents a code the host did not observe. `docs/languages.md` carries the
  measured table and `docs/language-guest-build.md` names the loader line that
  causes the gap; closing it is a guest rebuild with a new digest, not an
  adapter patch. Pinning it:
  `tests/test_guest_exit_code_fidelity.py` characterises all routes — including
  a committed WASI-0.2 fixture that exits 3, so the component route needs no
  bring-your-own guest to be tested — and `tests/test_adapter_result_shape.py`
  pins the per-path value. On the QuickJS source route the pinned interpreter
  guest is now measured directly: a `throw`, a `process.exit(5)` and a
  `process.exit(0)` all leave as `success`/`0` carrying the guest's own marker,
  because that harness treats any `process.exit` as an exception — so
  `guest_reported_error` is a guest claim in both directions and the record says
  `none` rather than implying an attested zero. Who can be misled is pinned too:
  `tests/test_agent_executor_confinement.py` shows a model-supplied source script
  is refused as `not_a_wasm_module` before any adapter runs it, that a component
  hard-exit still arrives `blocked` with the code wasmtime observed, and that the
  shipped MCP package routes no script to a language adapter at all.
- **The distribution guard now sees a stale build.** `scripts/distribution_guard.py
  artifacts` checked only what must NOT be inside an artefact, so a wheel built
  before this release's CLI surface landed passed every rule while being unusable.
  It now asserts, from the artefact's own contents, that every 1.2.0rc2-and-later
  distribution carries `doctor.py`, `verify_cli.py`, `policy_cli.py` and all three
  console scripts in its `entry_points.txt` — and fails closed on an unparsable
  version or an unreadable `entry_points.txt`. Verified non-vacuous against the
  stale wheel it was written for.
- **Behavioural pins replace four measurement-backed claims that had no test.**
  `--allow-env` reaching the guest, caller arguments arriving at `argv` through
  `run --language` (recording boundary plus a real guest round-trip), the full
  ABI accept/refuse matrix including the positive cases that an over-eager
  refusal would break, and the complete `--tenant` family refusal — in
  `tests/test_language_env_args_cli.py`, `tests/test_run_abi_and_tenant_matrix.py`
  and `tests/test_test_count_guard.py` (the guard's own non-vacuity, exercised in
  a farm copy so `__file__` cannot point back at the real checkout). Suite:
  1539 passed / 28 skipped (1567 collected), 89 % statement coverage (5587/6304),
  measured on a fresh clone and reproduced identically on the qualified `49.0.3`
  interpreter.
- **The agent-framework examples became assertable.**
  `integration/verify_agent_frameworks.py` runs the LangGraph, LangChain, OpenAI
  Agents SDK, CrewAI, AutoGen and Semantic Kernel examples and asserts what each one
  reports, plus the untrusted-input contract of the shared executor (non-string,
  empty, whitespace, NUL-bearing, outside-allowlist, symlink-escape and
  digest-mismatch inputs are all refused without executing anything). A skipped
  framework is printed as a SKIP and never counted as a pass; any failed claim exits
  `1`.

- **`ephemora_cell_mcp.http_bridge` — an authenticated, loopback-only MCP
  streamable-HTTP bridge in front of the stdio server.** n8n's MCP Client node
  can only dial `httpStreamable`/`sse` endpoints (measured across
  `@n8n/n8n-nodes-langchain` 1.122.60 and 2.43.4: no stdio option exists in any
  shipped version), so the stdio transport alone is unreachable from a workflow
  engine. The bridge spawns the same `python -m ephemora_cell_mcp` server and
  forwards `tools/list`/`tools/call` verbatim, keeping the host-observed
  `_meta.execution` record authoritative. It refuses to start without a bearer
  token (read from the environment, never argv), requires an explicit override
  for a non-loopback bind, compares credentials in constant time, and pins
  Host/Origin against a DNS-rebinding allowlist. Served by the existing
  `integration` extra; documentation in `docs/n8n-integration.md`.
- **Running guest code on an unqualified engine is refused, not warned about.**
  `ephemora_cell.runtime_qualification` decides once, from distribution metadata
  plus an import probe, whether this process is on the audited Wasmtime line
  (`wasmtime>=49.0.3,<50`), and the decision is read at every entry that can start
  a guest: `WASISandbox.run` (the documented facade, and with it `run_wasm`, the MCP
  `CellToolEngine`, the Python/JavaScript adapters), `process_executor.run_isolated`
  (public API that reaches the worker without passing the facade) and the CLI. A
  refusal spawns no worker, compiles nothing, bills no tenant, says
  `refused: unqualified runtime — <reason>`, and `ephemora run` leaves status `4`
  with an `ephemora-cell/run-refusal/1` document instead of a traceback or a quiet
  run on the unpatched public build. An operator who knowingly runs elsewhere says
  so out loud with `EPHEMORA_ALLOW_UNQUALIFIED_RUNTIME=1`; that prints a `note:` on
  stderr, stamps `"unqualified_runtime_allowed": true` into the JSON document, and
  is named by `ephemora doctor` so a forgotten hatch cannot read as a clean install.
  The whole contract — the five error classes, what each one means and who decided
  it — is published in `docs/cli-errors.md`.
- **The GitHub Action reports who decided.** Its step outputs
  gained `error_class`, read from the report the CLI wrote: `execution` (a guest
  failed, or the sandbox stopped it) and `environment` (nothing executed, because
  the runner's engine sits outside the qualified runtime line) are different events
  for whoever gates on them, and `status=error` alone conflated them — an
  uncovered-engine refusal used to read as though the module had failed. The
  environment case now fails with a message naming the runtime, and the pin
  guidance in `action/README.md` asks for the release commit's SHA, the same rule
  this repository's own workflows follow (41 SHA-pinned refs, no floating version
  names).

### Changed

- **`exit_status_fidelity` is derived from the run, not guessed from the ABI.** The
  language adapters each declared their own word, and the JavaScript module route
  declared `exact` unconditionally — so a run the host stopped at its fuel budget
  attested an exit status the host had never observed, the exact case
  `docs/languages.md` says reads `none`. Routes where the guest IS the program the
  caller handed over (a `.wasm` module, a caller-built JavaScript module) now take
  the same derivation the CLI and the signed record use (`abi` + the raw
  `guest_exit_observed` fact): a guest that exits through Preview1 still reads
  `exact`, a host stop reads `none`. The two harness-mediated routes — a Python
  source run through the component guest's loader, a JavaScript source run through
  the QuickJS harness — name `none` on purpose, because there the guest can leave
  through its exit interface while the SCRIPT's status is still discarded; a test
  pins that distinction (`guest_exit_observed` true, claim still `none`). Both
  poles are pinned in `tests/test_adapter_result_shape.py`.
- **The grant-evidence harness pins the guest the release actually ships.**
  `benchmarks/language_grant_evidence.py` carried the superseded JavaScript
  interpreter-guest digest (`53037972…`, the build that still contained local
  build paths) as its canonical value while the packaged guest is the clean
  rebuild (`a192e230…`, `docs/language-guest-build.md` §3). Pinned to the wrong
  bytes, the harness would have accepted the old artifact and flagged the shipped
  one as a substitution — the opposite of what a digest pin is for. The pin now
  names the release guest, and the measurement was re-run with all four guests
  digest-verified on the qualified engine
  (`benchmarks/results/2026-10-19/language_grant_views_measured.json`, five claims,
  all `MATCH`); the 2026-10-17 run remains on disk as the historical record of the
  artifact it used.
- **`ComponentSandbox` checks the runtime line too.** The low-level component
  primitive is reachable from the package surface and carried no engine decision,
  so skipping the facade was a route around the gate — measured running a guest on
  an unpatched engine while `WASISandbox` refused it. The decision now happens
  before a byte is read, compiled or billed; process isolation stays the facade's
  business, as documented.
- **The escape-hatch stamp travels on the record.** `unqualified_runtime_allowed`
  is a field of the execution report rather than a key the CLI bolted onto its own
  output, so a signed record, MCP `_meta.execution` and `run --json` all carry it
  and none of them can quietly drop it. An ordinary run carries no such key.
- **A tool sidecar asking for more than its profile grants is answered in the
  result.** The intersection rule (a sidecar can narrow, never widen) held, and the
  run attested only what it actually got — but the dropped request lived solely in
  a host log line. The record's own `warnings` now names the preopens that did not
  apply, the same rule the CLI follows for a flag whose value would be discarded.
- **The language route answers the engine question before the argument question.**
  On an engine outside the qualified line, a language run carrying a flag it cannot
  honour left `caller` (`2`) while the same configuration on a module run left
  `environment` (`4`) — one configuration, two classes, decided by which code was
  written first. The gate now decides first on every route.
- **`elapsed_ms` degrades honestly on a language run.** The shared document said
  `0.0` where the run had no measurement to report; an absent number stays absent
  rather than attesting "measured, zero milliseconds".
- **Legs that describe a machine now say when the machine disagrees.** Four
  resolver legs asserted that an uninstalled language guest fails closed — on a
  host that has the packaged guest installed (any wheelhouse qualification venv)
  they could only fail, which reads like a product defect and is none. They take
  a `no_packaged_guest` fixture that skips them with the reason naming what it
  found, and two CLI legs that check a flag is *carried* were passing only
  because the script path they handed over did not exist: they create the file
  now, so the outcome is about the flag on any host. Both counts are published
  with their conditions (1683/26 in a fresh checkout with no packaged guest, 1684/25 once a wheel exists in that checkout, 1681/28 with the guest wheels installed, 1692/17 with those guests pinned for a real round-trip — all four measured for this release, and the escape-hatch state measured separately at 1682/27).
- **The wheelhouse install rule says to verify the digest, not the filename.** An
  install by name from a local index picks whichever file it finds for that
  version, and three different `ephemora_cell-1.2.0rc2-py3-none-any.whl` files
  existed on the release machine during qualification — one of them an older
  build, which is what a measurement venv picked up before the ambiguity was
  caught (a `49.0.3` install that did not contain `allow_env_names` at all).
  `README.md` and `SECURITY.md` now state: one core wheel per install directory,
  check it against the published release digest, and let `doctor` name the module
  path and engine identity actually loaded.
- A `caller`-class refusal emits no JSON document, and `docs/cli-errors.md` says
  that instead of implying every command's document carries `error_class`.

- **`run --json` answers with one document shape on every route.** A Python or
  JavaScript run used to return the adapter's own dict — no `security_baseline`, no
  `fuel_budget`, no byte counts, no `warnings` — while `run module.wasm` returned the
  full execution record, so one command had two documents and the language one could
  not show what posture its run actually carried. Both now come from the same
  `ExecutionReport`; the library adapters' result dicts gained those base keys
  (a labelled contract change, pinned in
  `tests/test_adapter_result_shape.py` / `tests/test_lang_unified.py`), and the
  deliberate differences — `stdout`/`stderr`/`output`, `language`, `script`,
  `guest_reported_error`, `stdin_capped` — are stated in `docs/languages.md`.
- **A tenant book or cap without an account is refused on the module route too.**
  `--tenant-book`/`--tenant-max-runs`/`--tenant-max-fuel` reached the engine and were
  then dropped, because there was no account to attribute the run to; the language
  route already refused exactly that in 1.2.0rc2. Both routes now leave status `2`
  (`caller`) and name the missing `--tenant`, so no run reports a guard that does not
  exist.
- **A malformed `--allow-env` value leaves the caller class.** `--allow-env FOO`
  (no `=`) and `--allow-env =bar` (empty name) refused with status `1`, which the
  contract reserves for a run the sandbox reported; nothing had run, so they now
  leave `2`. An empty value (`NAME=`) still warns and carries, as before.
- **`security_baseline` attests `allow_env_names`.** The variable NAMES a guest could
  read are recorded in the signed posture — never the values, which stay out of the
  baseline, the fingerprint and every output. Without them a record could not tell
  "this run had no host environment" from "the run did not say".
- **`exit_status_fidelity` is now an attested field of the record.** The claim is
  derived by one function (`execution_report.exit_status_fidelity`) and set on
  `ExecutionReport`, so it travels inside the JCS payload a signature covers —
  rewriting `"none"` into `"exact"` in a signed record now fails verification — and
  the MCP `_meta.execution` an agent reads carries the same value as the CLI
  document. A report that never sets it serializes byte-identically to an earlier
  one.
- **`exit_status_fidelity` reports what the host observed, not which ABI was
  routed.** A run that never reached a guest exit — a module the loader rejected
  (`run --abi preview1` on a component binary), a fuel/timeout/byte stop, a refused
  environment — now says `none`; it used to say `exact` or `non_zero_only` by
  reading the width of a channel nothing travelled through, which let the host's own
  `1` be mistaken for the guest's verdict. The fact is carried from the worker across
  the process boundary (`ExecutionResult.guest_exit_observed`), so a subprocess run
  attests its own observation rather than an inference by the parent.
- **`run` statuses now carry their class in the document as `error_class`, and two
  refusals moved to the class that describes them.** A call the CLI cannot honour as
  stated — `--tenant` without `--tenant-book`, an unreadable `--stdin`, a grant the
  sandbox refuses before anything starts — leaves `2` (`caller`) instead of `1`. The
  refusals that already left `2` (a flag value an adapter would discard, a
  contradicted `--abi`) keep their status and are now named as the same class.
  A language run whose guest is not installed or not
  the pinned artefact leaves `4` (`environment`) instead of `1`. A guest's own exit
  number still travels in the process status — `run` of a Preview1 guest that exits
  `3` still leaves `3` — which is why the class is stated in the document, where it
  cannot be confused with a number the guest chose.

### Fixed

- **The two conformance harnesses can no longer report a number they did not
  measure, and one of them was double-counting.** Both publish evidence JSON into
  this repository, so both are part of the release claim.
  - `conformance/run_wasi_testsuite.py` wrote `pinned_commit` into its summary as
    a constant and never compared it with the checkout, so a cache left on another
    revision produced evidence labelled with a revision it had not run — the same
    defect class closed in `run_core_spec.py` earlier in this cycle. The
    orchestrator now verifies the revision on the cold path *and* the warm path
    and aborts otherwise, and the summary records `observed_commit` beside the
    declared pin. It also counts each test by its own recorded outcome instead of
    copying the upstream runner's per-suite header — and that header counts an
    expected failure inside `passed`: measured on the 2026-10-20 run, the C suite
    reports `passed: 14, xfailed: 1` over 14 entries that are 13 passes and one
    xfail. The published "72 pass / 1 xfail" therefore described 73 results from
    72 executions; the honest figure is **71 pass / 1 documented expected-failure
    / 0 fail of 72 executed**, and the diverging header is kept in the evidence
    file rather than reconciled away. An outcome the harness does not recognise is
    counted as a failure, never dropped.
  - `conformance/run_core_spec.py` compared cache identity against declared fields
    only, so a version string and an engine dict could describe a measurement from
    another toolchain. The identity now carries three observed facts — the sha256
    of the native runtime library actually loaded, the sha256 of the harness
    itself, and the `wast2json` tool and version — so a bumped wabt or an edited
    harness invalidates the cache instead of inheriting it. A synthetic abort result
    is stamped like any other result, and the evidence reports
    `aborted_files: 100` with the meaning spelled out: those files carry no
    per-command measurement, and classing them as deviations is a statement about
    the upstream engine, not a conformance result. `measured` now answers
    provenance only — a run in which nothing ran, or in which every file aborted,
    cannot raise the flag — and the exit code stays strict.
- **The benchmark guard's numbers now have to be measurements.** Review measured
  that after the route binding landed, the guard could still report "pass" for a
  machine where nothing executed: `measure()` ignored `result.status`, so a refused
  run (unqualified runtime) produced a 0.08 ms median inside every budget, and the
  declared route was never compared with the path the host recorded. Each sample is
  now checked for `SUCCESS` and for `execution_mode`, a route with no timed runs is
  a failure, and a declared budget above 2500 ms fails the guard outright —
  "loose by design" is a bound, not an open cheque.
- **Two High CodeQL findings in the published tooling are closed by code.** The
  local CodeQL 2.27.2 default suite (`codeql/python-queries@1.8.12` — the suite
  `codeql.yml` runs) still carried four findings on the previous candidate after
  the capture-file round; two were real:
  - `py/insecure-temporary-file` (CWE-377, security-severity 7.0) in
    `benchmarks/poll_oneoff_wall_hostcall_probe.py` and
    `benchmarks/stdio_overflow_output_alloc_probe.py`. Both called the deprecated
    `tempfile.mktemp`, which only *names* a path — the gap between guessing it
    and opening it is the race. Both now use `mkstemp`, which creates the file
    with `O_EXCL`, and a repository-wide test forbids the deprecated call from
    returning. Each probe was re-run after the change and produces the same
    result it produced before (164-byte module written; `measure(1000)` →
    `{requested_bytes: 16000, status: success, stdout_len: 10000}`).
  - `py/incomplete-url-substring-sanitization` (CWE-20, security-severity 7.8) in
    `scripts/metrics_snapshot.py`, which picked the GitHub request shape with a
    prefix test on the raw URL string. A prefix test on a URL is not a host check:
    `https://api.github.com.evil.test` passes it. The decision now comes from
    `urlparse`, with userinfo and port removed and the scheme compared apart from
    the host; seven cases pin the behaviour, including the shapes the old test
    accepted. Neither file ships in the wheel and neither is reachable from guest
    code, but both are published — and a High finding here is either fixed or
    refuted with reproducible evidence, never closed by writing about it.
- **The last High finding of the default suite is refuted by its own dataflow.**
  `py/clear-text-logging-sensitive-data` (CWE-312/359, 7.5) at
  `benchmarks/invariant_model.py:241` says the printed model result logs a
  secret. The trace names its source: the string literal `"trusted"` at
  `ephemora_cell/execution_report.py:110`, reaching the print through the
  `VALID_TRUST` frozenset as the `trust_levels` field. Running the program shows
  that field is exactly `["trusted", "unknown", "untrusted"]` — the three fixed
  labels of the ADR-015 posture enumeration, not a runtime value, not read from
  the environment or a file — and the whole 1,085-character output matches six
  credential shapes (PEM block, AWS-style key, GitHub token, bearer value,
  password-shaped assignment, long base64) zero times. No query configuration
  was touched and nothing was suppressed: the alert is left visible so a reader
  can re-check it against the run.
- **The benchmark guard now judges each execution route on its own scale.** The
  guard is a blocking step in the `test` job, and on the release candidate it
  was red: `pooled_wall_median_ms: 127.967 ms (limit 5.0) [FAIL]`,
  `default_wall_median_ms: 126.607 ms (limit 20.0) [FAIL]`. The engine had not
  slowed down. `timed_scenario()` called `sandbox.run()` with no posture and no
  isolation argument, and since ADR-015 the documented default posture routes an
  untrusted Preview1 run through the disposable worker — so the guard had been
  timing a full process spawn against budgets calibrated on a pooled in-process
  execution. The thresholds are unchanged where they were meaningful, and each is
  now bound to the route it measures: `pooled_inprocess` (wall 5 ms, guest 5 ms,
  measured 1.30 / 0.41 ms), `default_inprocess` (wall 20 ms, measured 2.50 ms)
  and the route an ordinary caller actually gets, `worker_default_posture`, with
  its own spawn-inclusive budget of 1500 ms against a measured 115-134 ms median
  — an order of magnitude, consistent with what this guard was always for.
  Metrics measured without a threshold are printed instead of dropped, so
  removing a leg cannot quietly shrink the gate. Seven regression tests cover the
  binding (including a negative control that a breached budget still exits `1`);
  all seven were red before the change.
- **A core-spec run can no longer claim a measurement it did not take.** Two
  defects in `conformance/run_core_spec.py`, both found by reproducing the CI
  scope locally on the release candidate. (a) The suite was cloned with
  `--depth 1`, which carries only the branch tip, so `git checkout <pin>` fails
  with `pathspec 'b464a4cd100d' did not match any file(s) known to git` as soon
  as upstream moves past the pin — measured on a cold cache; GitHub also refuses
  `fetch --depth 1 <sha>` (`couldn't find remote ref`), so the job simply could
  not run. The clone is now complete, the pinned revision is fetched when the
  cache lacks it, and the run ends with a self-evidencing assertion that aborts
  if the suite is at any other revision. (b) Per-file results are cached under
  `gen/` and reused whenever the file existed, with no record of what produced
  them, so a run inherited numbers from a different runtime and a different
  engine configuration. Measured: the published `core_spec_2026-10-12.json`
  (header `wasmtime: 49.0.0`, `measured: true`) contains the `data`, `global`
  and `imports` records of the 2026-09-19 cache — measured under wasmtime
  47.0.1 and before the proposal lockdown of GHSA-m63x-6p34-q65x entered the
  harness's engine configuration. Every cached entry now carries that identity
  (runtime version + engine configuration + pinned suite) and is reused only on
  an exact match; an unstamped entry is re-measured, because unknown provenance
  is not evidence. Four regression tests name both defects; all four were red
  against the previous commit before the fix.
- **The published core-spec conformance figure states what the shipped
  configuration actually measures.** Re-measured end to end on a cold cache
  against the qualified runtime (`49.0.3.post2+git.1d21c90f`, suite pinned
  `b464a4cd100d`, macOS arm64): **31,896 pass / 3,281 classified
  deviations / 684 text-format skips / 81 failures the harness does not
  classify**, so the harness exits `1`. The previously published 31,931 pass /
  46 fail predated the proposal lockdown. The 81 are triaged case by case in
  `conformance/README.md`: 29 sit on modules the shipped posture refuses — 14
  parse-time refusals (9 naming the exceptions proposal, 5 naming the
  constant-expression and table-initializer forms those proposals require) and 15
  later assertions that depend on those modules having registered; 29 are
  exact-bit float comparisons the Python binding cannot read back or where a
  different payload propagates; 12 ask the harness's spectest environment for
  imports it does not provide; 11 are long-standing table/bulk and `local_init`
  cases. None is a sandbox-policy outcome, and nothing was reclassified into an
  xfail to make the job read green. One caveat is now stated in both the evidence
  and the document: 100 of the 3,281 classified are files where the upstream
  engine killed the process, and an aborted file carries no per-command
  measurement at all — `aborted_files` is reported in the JSON, so "classified"
  cannot be read as "measured".
- **A component run through the facade no longer orphans its capture directory.**
  `WASISandbox.run()` answers a component by building a private `ComponentSandbox`,
  running it and dropping the object — and the capture directory belongs to that
  inner object, so the facade's own `cleanup()` cannot reach it. Measured on the
  release candidate: after a documented `run()` + `cleanup()` cycle of a component
  with stdin, `ephemora_host_*` survived with `stdin.txt` and `stdout.txt` inside it,
  while the published promise says a run leaves nothing behind. Every other internal
  caller (the disposable worker, the CLI, the language adapters, the MCP engine)
  already pairs its run with `cleanup()`; the delegation was the one that did not,
  and it now does. The lifecycle itself is unchanged on purpose —
  `tests/test_io_budget.py` requires the capture file to still exist after a run, so
  cleaning inside `run()` would have broken a documented contract instead of fixing
  one. A regression test names the residue case.
- **Capture files are created owner-only.** The run's directory comes from
  `mkdtemp` (`0700`), but the files inside were opened with the plain built-in, which
  applies the process umask, so `stdin.txt` (the caller's own input) and `stdout.txt`
  landed at `0644` — group and world read bits on content the host writes for exactly
  one consumer. Measured before the change: `0o644`, other-readable, with only the
  parent directory hiding it. One shared helper (`open_private`) now creates every
  capture file with `0600`, used by both ABI routes and by the output sink, and a
  test asserts no group or other bit survives on any file in the capture directory.
  This is the product-side half of what the CodeQL `clear-text-storage` alert pointed
  at: writing the guest's stdin to disk is not avoidable on these routes (wasmtime's
  WASI config takes a *path* for stdin, not a pipe), so the exposure is bounded —
  private bits, owner-only directory, removed by `cleanup()`.
- **A guest exit number that is a multiple of 256 can no longer read as success.**
  Both `run` routes handed the reported code straight to `sys.exit`, and the shell
  keeps one byte of that argument: measured, `sys.exit(256)` leaves process status
  `0` — a failure a caller would read as a clean run while the document says `error`.
  One shared helper now reports any code collapsing to zero as `1` and keeps a real
  number below 256 exact. Reachability differs by route: the Preview1 wasm path
  normalises `proc_exit(256)` to `1` inside the runtime (measured), while a
  guest-reported code on a language route reaches the CLI unchanged.
- **A nested component is validated, not sliced.** The component guard checked four
  bytes of a nested component section and then sliced off eight, so a nested section
  carrying nothing but the magic walked as an "empty component" and was accepted with
  no version or layer check. The nested header now carries the same invariant as the
  outer bytes (magic, version byte `0x0d`, component layer `0x0001`); the refusal is
  fail-closed, and the new tests are measured to fail on the pre-fix tree.
- **Two security tests that could not run outside one machine are fixed.**
  `tests/test_agent_executor_confinement.py` loads
  `benchmarks/workloads/hello_rust.wasm` unconditionally, but that workload was
  gitignored while its siblings (`code_review.wasm`, `coremark.wasm`,
  `exploit.wasm`, …) are tracked — so on a fresh clone of this release both
  allowlist-execution tests died with `FileNotFoundError` instead of testing the
  confinement boundary (measured: `2 failed` on `git clone` of `09210f0`), and
  `ci.yml` never compiled it either. The fixture now travels with the repo, and
  the fresh clone reports `1517 passed / 23 skipped`, the stamped number.
- **`run --json` now answers one status vocabulary for every guest.** The wasm branch
  reported `"status": "success"` while a `--language` run handed back the enum's
  own spelling (`"ExecutionStatus.SUCCESS"`) under the same key, so a consumer
  reading one schema broke on the other. Language runs now carry the same
  host-observed short status; the exit code was already derived from the host
  observation and is unchanged. The two documents are still **different shapes**
  and the docs now say so: a language report is narrower — it does not carry
  `stdin_capped`, `fuel_budget`, `fuel_utilization`, `memory_mb`,
  `stdout_bytes`/`stderr_bytes`, `warnings` or `security_baseline`.
- **`run --language python|javascript` stopped swallowing flags it cannot carry.**
  The adapters receive only the script, its arguments and the budget config, so
  `--allow-dirs`, `--stdin`, the whole `--tenant` family (`--tenant`,
  `--tenant-book`, `--tenant-max-runs`, `--tenant-max-fuel`, including a cap
  passed without `--tenant`) and an `--abi` the adapter would override were
  accepted and silently dropped: an operator could believe a directory was
  preopened, an input delivered or a run attributed to a tenant when none of that
  happened. Those flags are now refused with exit `2` and a reason naming what
  replaces them. The ABI refusal states who actually decides (a Python run's ABI
  comes from the guest's own bytes; a JavaScript run is always preview1) rather
  than claiming the run could not be the requested ABI — with a bring-your-own
  legacy interpreter that run really would be preview1. `--allow-env` is
  deliberately not in that set — the adapters rebuild only
  `allow_dirs` over the interpreter profile, so environment pairs do reach the
  guest — and `--isolated` stays accepted because the adapter already satisfies it.
  `policy check --language` is intentionally NOT symmetric on `--allow-dirs`: it
  answers the view (exit `0`) and names the dropped directories, so a
  `policy check && run` shell gate is not the documented sequence on a language
  path.
- **`run --language python` no longer discards the script's arguments on the
  component path.** `lang_py.run_python_script` forwarded `args` only to the
  legacy Preview1 interpreter; the WASI-0.2 branch — the installed product guest —
  dropped them silently, so `run s.py -- a b` executed a different program than
  the one asked for. Measured against the real guest, the component runner's argv
  does reach the exec'd script, so the branch now passes them through (the runner
  supplies `argv[0]`; the caller's arguments occupy the guest's `sys.argv[1:]`).
- **`lang_js.run_javascript_source`'s own docstring claimed the staged `/work`
  directory was "the only preopen".** Measured on both interpreters, a preview1
  source run additionally gets its ephemeral `/sandbox` scratch — the same
  exclusivity error the policy view had, surviving in the shipped API doc.
  Corrected.
- **`doctor`'s `cli-entrypoints` check stopped warning on a good installation.** It
  searched only `PATH`, so a clean-room install of the built wheel reported
  `WARN not on PATH: ephemora` while `ephemora` sat ready beside the interpreter
  (measured in the wheelhouse install). It now searches the running interpreter's
  own script directory as well, reports `ok` with the location and keeps the
  "not on PATH" advice as advice, and warns only when a script is found nowhere —
  naming the directory it looked in. `WARN` that fires on a correct install is a
  false alarm that trains an operator to ignore the real one.
- **`distribution_guard artifacts` now verifies a wheel's own RECORD, and `doctor`
  stopped crediting another installation's console script.** The completeness rule
  added in this cycle only proved that member NAMES were present, so an artefact
  carrying the right names with stale bytes passed (measured: a wheel with a
  replaced `doctor.py` and an unchanged RECORD → `clean`, exit 0). Every project
  wheel is now checked against its own RECORD digests and sizes, and a missing
  RECORD is a finding rather than a blind spot. `doctor`'s `cli-entrypoints` check
  counted any PATH hit, including one whose `#!` names a different interpreter —
  on this machine an older Homebrew install satisfied it while the environment
  under test had no such script; a foreign hit is now reported and never counted
  as this installation's entry point.
- **`verify` now says what it can read.** Pointing it at an ordinary run report
  answered only "no verifiable evidence found in <file>", which leaves the reader
  guessing whether the file, the format or the tool is at fault. The refusal now
  names the four artefact kinds `verify` accepts (JSONL execution ledger, DSSE
  envelope, signed execution record, pre-exec/receipt chain). Exit status is
  unchanged: `1`, because nothing was verified.
- **The Semantic Kernel example stopped masking a real defect as a skip.** Its
  plug-in was registered under a display name containing a space, which the kernel's
  name schema rejects; the resulting error was reported as "framework absent" with
  exit `0`. The name now follows the schema (`EphemoraCell`) and a registration
  failure exits non-zero, so a broken integration cannot read as an untested one.
- **`verify` no longer misstates the caller's key or its signatures.** With
  `--key` supplied, a broken or unsigned ledger reported "this path holds no key" —
  the exit code was right, the sentence was not; and "signed" was read off the last
  entry only, so a ledger with two signed entries and one unsigned head was described
  as if nothing in it were signed. The report now names the actual situation (the
  walk stopped at a chain break, the supplied key found no signature at all, or a
  specific entry could not be authenticated) and carries the signed-entry count,
  because that wording is what an operator reads to decide what was proved.
- **The preview1 I/O-budget refusal guarded its stdout capture.** The breach result
  passed a `str | None` path to a helper that requires a `str`: a breach seen before
  the capture file existed would raise `TypeError` inside the watcher and mask the
  refusal the run is supposed to report. The call now uses the same
  `if stdout_path else ""` guard the neighbouring result paths already use, and the
  type check over both shipped packages is clean (40 source files, mypy 2.4.0).

### Security

- **The HTTP bridge can no longer be composed without a token.** An independent
  pre-push review measured that `ephemora_cell_mcp/http_bridge.py` enforced its
  documented "no token, no start" posture only in the CLI's `main()`. The
  composition function `build_app()` assembled the gate with
  `policy.token or ""`, so a library caller passing an empty token got a bearer
  middleware whose secret was the empty string — and `Authorization: Bearer `
  (empty value) compared equal to it. Measured through a real HTTP request to a
  real stdio child: `tools/call` of the `echo` tool returned `status: "success"`
  with a genuine `fuel_consumed` record — arbitrary WASM execution behind an
  unauthenticated loopback port. Three defences now sit where each claim belongs:
  `build_app()` refuses any posture its own `violations()` rejects, before
  importing anything optional; the middleware refuses an empty or whitespace
  secret at construction; and the refusal is proven reachable without the SDK
  installed. The same review found the bridge handing its bearer token to the
  child process (`env={**os.environ, ...}`) and `tools/list` awaiting an upstream
  with no time bound while `tools/call` had one — both closed: the child
  environment drops the token variable by name and keeps everything else, and
  both upstream calls run under the bridge's own wall bound, with a timed-out
  `tools/call` still reported as a failed tool result and never as a success.
  Eight tests, all red against the previous candidate.
- **Capture-file permission bits are set on every open, and a failed cleanup can
  no longer be silent on the component route.** Two findings on the hardening
  itself. `open_private` relied on `O_CREAT`'s mode, which the kernel ignores for a
  path that already exists — measured, a pre-existing `0644` stayed `0644`
  through the helper (unreachable in the shipped layout, where every capture path
  lives in a fresh `0700` `mkdtemp`, but the docstring claimed more than the code
  did); the bits are now set with `fchmod` on the descriptor just opened. And
  `ComponentSandbox.cleanup()` deleted with `ignore_errors=True` and returned
  nothing, so a capture directory that could not be removed (measured with an
  unremovable directory) read as cleaned while the facade answered `[]` — it
  returns the surviving paths like the facade does, and the facade's component
  delegation carries that residue into its own `cleanup()` report. Five tests,
  three of them red against the previous candidate.
- **The import-cycle alerts over the shipped package are measured, not trusted in
  either direction.** CodeQL's `security-and-quality` and `code-quality` suites
  (neither is run by `codeql.yml`) report `py/cyclic-import` (3) and
  `py/unsafe-cyclic-import` (2) around `egress_sidecar` / `grant_ledger`, plus
  `py/unused-import` at `process_worker.py:39`. The runtime edges were checked
  directly: `egress_sidecar.py:54` is a `TYPE_CHECKING`-only import and
  `process_worker.py:39` serves an annotation under
  `from __future__ import annotations`, so the only runtime edge between the two
  modules runs in one direction. Importing `grant_ledger` first and importing
  `egress_sidecar` first each resolve `GrantLedger` and `EgressGrant` in a fresh
  interpreter, and both entry points import cleanly behind each order. Recorded
  as an observation about the queries' handling of `TYPE_CHECKING` — neither a
  defect to fix nor a suppression.
- **Agent-executor confinement hardened against a model-supplied path.**
  `integration/ephemora_cell_agent_executor.py` now refuses
  malformed input instead of raising — a non-string or NUL-bearing path from
  model output returns `policy_denied` rather than escaping the tool call as a
  `TypeError`/`ValueError`; the module is opened with `O_NOFOLLOW` and
  `O_NONBLOCK` after an `lstat` regular-file and size check, so a symlink out of
  the allowlist and a FIFO that would have blocked the call are both refused;
  the authorized bytes are hashed once, bound onto the run as
  `expected_sha256`, and re-materialised into a private `0700` directory before
  execution, which closes the check-to-use window (swapping the allowlisted
  file after authorization can no longer change what runs); an operator may pin
  exact module digests via `allowed_sha256`. Counterexample tests added.
- **MCP startup fails closed on a misconfigured tool set.** A nonexistent
  `--tools-dir` used to start a fully working server that advertised only
  `get-policy` (exit 0, no diagnostic): every real tool call answered
  `unknown tool`, and behind the HTTP bridge that is a live, authenticated
  endpoint with nothing executable behind it. `python -m ephemora_cell_mcp` now
  exits 2 when `--tools-dir` is not a directory, and the bridge refuses to serve
  an upstream that lists no WASM tool — `--allow-no-tools` is the explicit
  opt-out. The timeout path was also measured end to end: an exceeded
  `--call-timeout` returns a tool error and leaves the session usable rather than
  hanging the caller.
- **Execution-record integrity: a guest error marker can no longer forge
  the host status.** The language adapters previously promoted the untrusted
  `EPHEMORA_USER_ERROR` stderr marker into a fabricated non-zero `exit_code`.
  Because that marker is content the sandboxed user's own code can print, it is
  now recorded only as the separate, explicitly-untrusted `guest_reported_error`
  diagnostic; `status` and `exit_code` always reflect exactly what the isolated
  worker observed. Counterexample and regression tests added for both the Python
  component and JavaScript interpreter guests.
- **GHSA-32h6-97mm-8q3c async execution path enforced-excluded at the loader.**
  The `component_guard.py` async-component detector (prepared 2026-10-14, not
  wired) is completed and now enforced in the load path. Its accept-side grammar
  was finished against the authoritative Component Model binary spec
  (`nameattributes`, `alias` export/outer, `externtype`/`typebound`/`valuebound`,
  `componentdecl`/`instancedecl`), and it is certified against the repository's
  real component corpus — every WASI p2 Rust probe, `componentize-py` lifted
  guest and WAT fixture (38 components) walks cleanly with zero over-rejection.
  `guard_component_bytes` is called at the **single** `wasmtime.component.Component()`
  site in `wasi_02.ComponentSandbox.run`, before the native parser, so any
  component-model async construct (async-lift / future / stream — the surface the
  unvalidated async callback result count overruns) is refused fail-closed on both
  the in-process trusted path and the protected worker. Any byte the reader cannot
  confidently walk (e.g. an embedded core WasmGC `type` declarator, still
  unimplemented) is refused, never accepted — over-reject only, never a bypass.
  `tests/test_component_guard.py` adds real-guest acceptance, an async-inside-
  `instancetype` control, and loader-integration tests (async refused with a
  `GHSA-32h6-97mm-8q3c` error through `run()`; a real guest not blocked). This
  closes the *product-execution* path; it does **not** patch the engine — the
  corrected 49.0.2 wheel / controlled source build stays the definitive fix and the
  engine-upgrade gate stays open.

- **Public security numbers reconciled to a per-scenario attack & containment
  matrix.** The README "8/8 blocked" line was verified against the live runtime
  on this commit (still `exit 0`, WASI Preview1 default path) and reframed as the
  specific eight-intents-vs-one-boundary result it is, not a current aggregate.
  The arXiv 2509.11242 eleven-strategy table was found to disagree with its own
  summary prose (table `7 blocked / 3 bounded / 1 permitted`; prose said `8 / 2 /
  1`, silently promoting memory exhaustion — a bounded row with a WasmGC-heap gap —
  into "blocked"); the summary and its two marketing mirrors are corrected to the
  row-for-row `7 / 3 / 1`. A consolidated
  [`docs/security_attack_matrix.md`](docs/security_attack_matrix.md)
  (+ machine-readable `benchmarks/results/2026-10-15/security_attack_matrix.json`)
  now lists every scenario actually run — capability set (A), 11 strategies (B),
  resource-DoS sweeps (C, `write_flood` correctly BOUNDED not blocked), the UK-AISI
  18 mapping (D, `NOT-EXPRESSIBLE` kept apart from runtime blocks; `dirty_cow`
  reclassified UNKNOWN on a module-load error; the public evidence bundle noted as
  an Enterprise run that did **not** score OSS Cell), the two **differing**
  native-Linux containment runs (E, memory-cgroup confirmed in one, unobservable in
  the other → CONTAINMENT, not runtime blocks), the CVE replays (F), the regression
  gates (G) and the open advisories (H, GHSA-32h6 as `FAILED`/release-blocker, never
  a defence) — each with class, boundary, commit, runtime and platform, and no
  cross-boundary addition. `SECURITY.md`'s stale suite figure was synced
  (1105/90 % → 1168/9/88 % on this commit). A new CI guard
  `scripts/check_security_claims.py` fails the build if the table and its summary
  drift again, if an unsupported OSS "18/18 blocked" claim reappears, or if the
  matrix link is dropped from the public docs.

- **Runtime dependency moved to wasmtime 49.0.0.** The single runtime
  dependency was raised from `47.0.1` to `49.0.0` (pyproject floor `>=43.0.1` →
  `>=49.0.0`, ceiling `<48` → `<50`, requirements pin + regenerated hash-locked
  `.lock`) so the improvement also holds for the supported install path — PyPI ships
  one wheel per major, so `>=49.0.0,<50` resolves only to 49.0.0 — to **reduce exposure to
  specific previously affected engine vulnerabilities**. This is not a claim that
  all Wasmtime vulnerabilities are fixed. The 49.0.0 pin closes the advisories
  patched in engine 47.0.3/47.0.4 (the 47.0.0 window) — GHSA-vqjp-4c8c-hfgg
  (wasmtime-wasi filesystem sandbox escape; no CVE asserted — CVE-2026-47261 is the
  distinct GHSA-2r75-cxrj-cmph TRUNCATE bypass) and GHSA-x84v-gj2h-g759 (WASIp3 stream heap
  allocation). Advisories whose fix line is 48.0.3/49.0.1 or 48.0.4/49.0.2 remain
  **open** because 49.0.0 predates both patch releases and no Python wheel exists
  for them (PyPI ships one wheel per major): GHSA-j2g9 (datetime overflow),
  GHSA-m63x (fuel amplification), and the 2026-10-02 wave (GHSA-j366, GHSA-gqmc,
  GHSA-96f6) — each still carries its documented mitigation (worker isolation,
  proposals enforced-off, bounded output sinks). The Critical GHSA-32h6-97mm-8q3c
  (identical to RUSTSEC-2026-0327 — a native stack buffer overflow in async-lifted
  component callback result-count validation) is **not** touched by this pin — the pinned
  engine stays IN BAND (fix 49.0.2, no wheel on PyPI) and the overflow's reachability is
  UNPROVEN (open memory-safety risk; public 1.2.0 on HOLD), documented in SECURITY.md. Full test suite, lint/type, guards,
  wasi-testsuite conformance and the security evidence probes were re-run green on
  the new pin; see SECURITY.md "Dependency upgrade truth".

- **Worker process-management repaired (759-incident root cause) + enforced-exclusion
  detector prepared.** The isolation gate recursed: an isolated worker calling
  `sandbox.run()` under the default `unknown` posture re-triggered the mandate and
  spawned its own sub-worker in an unbounded fan-out. Fixed with a thread-local
  isolation-boundary guard (suppresses only the re-spawn, never raises trust), a
  bounded concurrency cap (`EPHEMORA_MAX_CONCURRENT_WORKERS`, default ≤8), process-group
  `killpg` reaping, and a worker payload-stdin deadline; `tests/test_process_executor.py`
  proves 0 lingering workers after a 24-burst and after the full suite (default posture
  suite re-validation: 1148 passed / 0 failed). The GHSA-32h6 "technically enforced
  exclusion" path is prepared as `ephemora_cell/component_guard.py` — an independent
  component-binary reader (never the vulnerable native parser) that fail-closed refuses
  component-model async constructs (async functype / future / stream, incl. nested),
  proven by `tests/test_component_guard.py`; it is **not yet wired** because the
  accept-side grammar for real WASI p2 guests needs full Component-Model + core-GC type
  parsing and broad-corpus certification, which this host cannot provide. The advisory
  stays **UNRESOLVED and a release blocker** (no 49.0.2 wheel on PyPI, re-confirmed
  2026-10-14); loader behaviour is unchanged and worker containment remains the active
  mitigation, not closure.

- **Modern Python guest: reproducible build recipe + isolated-run proof
  (Python half of the 1.2.0 language deliverability, still open).** The
  documented recipe `scripts/build_python_guest.py` pins `componentize-py==0.25.1`,
  lays down a `wasi:cli/run`-style command world (the only component entry point the
  runner executes) and builds a CPython WASI-0.2 component; measured on this host it
  runs `SUCCESS` through the **isolated** sandbox under the `interpreter` profile,
  digest-bound, with an opt-in qualification gate
  (`EPHEMORA_PY_GUEST_QUALIFY=1 pytest tests/test_python_guest.py`, skipped by default)
  and evidence in `benchmarks/results/2026-10-14/python_component_guest.json`. This is
  **not yet a shippable language package**: componentize-py is not bit-deterministic
  (consecutive builds differ, so a package must pin one build-once artifact digest),
  and publishing the versioned `ephemora-cell[python]` / `[javascript]` distributions
  with license/SBOM clearance and an end-to-end install-against-the-published-package
  qualification remain **NOT TESTED / gated** supply-chain tasks — no
  package is published and 1.2.0 public release stays on HOLD. See ADR-009 and the
  JavaScript-half bullet below.

- **Modern JavaScript guest: reproducible build recipe + isolated-run proof
  (JavaScript half of the 1.2.0 language deliverability, still open).** The
  documented recipe `scripts/build_js_guest.py` pins the `bytecodealliance/javy 9.1.0`
  CLI (operator-installed — a native binary, not a pip/npm package, discovered on PATH
  or via `EPHEMORA_JAVY_BIN`), lays down a tiny self-contained stdin-JSON→stdout-JSON ES
  program and builds a standalone QuickJS-in-WASM Preview1 core module; measured on this
  host it round-trips `SUCCESS` through the **isolated** `lang_js` adapter, digest-bound,
  with an opt-in qualification gate
  (`EPHEMORA_JS_GUEST_QUALIFY=1 pytest tests/test_js_guest.py`, skipped by default) and a
  negative control that a mismatched `expected_sha256` fails closed before execution. Like
  Python this is **not a shippable language package**: javy 9.1.0 is not bit-deterministic
  (back-to-back builds differ by a couple of bytes, so a package pins one build-once
  artifact digest), and the publish/license/SBOM/install-against-published-package tasks
  stay gated exactly as for the Python half. No package is published; 1.2.0 public release
  stays on HOLD. See ADR-009.

- **Language-level API is now first-class and lazy.** `from ephemora_cell
  import run_python, run_javascript, run_language, available_languages` resolve
  through a PEP 562 `__getattr__`, so importing `ephemora_cell` never pulls a
  language adapter or interpreter module eagerly (enforced by a subprocess import
  test). Each entry resolves an installed optional guest or an explicit
  `EPHEMORA_BYO_*` pin and **fails closed** with the single documented install
  command when none is present — no manual guest hunting, no hidden download, and
  the run is isolated.

- **Agent-framework integrations exercised against real SDKs.** The
  `integration/agent_frameworks/` examples were run on **installed** LangChain
  1.6.10 / LangGraph 1.2.15 / CrewAI 1.15.28 / OpenAI Agents 0.20.0 wheels
  (isolated venv, core wheel + wasmtime 49.0.0): a LangGraph `StateGraph` and a
  new LangChain `@tool` drive several real WASM executions end to end, and the
  Cell function registered as a CrewAI `BaseTool` / OpenAI `FunctionTool` executes
  real WASM through the framework's own tool wrapper. The autonomous LLM decision
  loop (`crew.kickoff()` / `Runner.run`) is **not** exercised here — it needs a
  model endpoint or `OPENAI_API_KEY` and is reported `skipped`, never faked; these
  remain standalone scripts, not part of the CI pytest suite. Evidence:
  `benchmarks/results/2026-10-14/agent_frameworks.json`.

- **Untrusted WASI 0.2 components now run isolated — enforced, not
  recommended.** A central gate at the single execution choke-point (every
  entry point: CLI, MCP server, `run_wasm`, `abi="auto"`) forces any component
  the host has not explicitly marked `trusted` into the isolated subprocess
  worker; an unspecified classification counts as untrusted. If the worker is
  unavailable the run is refused instead of silently downgrading to in-process.
  The trigger is measured: a GHSA-j2g9-class guest aborts the host process on
  the in-process component path — a runtime resource wall cannot bite on that
  call, a process wall contains it ([ADR-015](docs/decisions/ADR-015-central-enforcement-gate.md)).
  Preview1 keeps its in-process default (measured unaffected). The mandated
  worker path costs roughly +66 ms per run (reproducible:
  `benchmarks/isolation_overhead_probe.py`).
- **Trust exceptions are host-owned and byte-bound.** The MCP engine takes a
  `trusted_tools` allowlist only as a construction argument — tool requests,
  client params, `ToolSpec` fields and manifests can never carry trust, and an
  empty allowlist (the default) is the strict posture. A trusted in-process run
  is bound to the registered module digest: a module swapped under a still-
  trusted name fails closed. A component that also needs host-sidecar egress
  is refused before it runs rather than losing the capability silently.
- **Signed receipts now attest what actually held.** Every record names the
  isolation path that actually ran the guest (`execution_mode`), the ABI
  actually executed, and whether the sync blockade was *effective* on that
  path — a component run honestly reports `sync_blockade_enforced: false`
  instead of the previous situation where a configured-but-not-enforced knob
  was signed as a guarantee. Callers who require a provable blockade can pass
  `require_sync_blockade=True` and get a controlled refusal up front.
  Records without the new fields stay byte-identical
  ([ADR-014](docs/decisions/ADR-014-effective-enforcement-attestation.md)).

### Infrastructure

- **Coverage trajectory explained (90 % → 88 % → 89 %) and the relevant gaps
  closed.** The historical 90 % was measured on the smaller tree at the last
  freeze (1105 tests); as the release line added the ~500-line component-model
  grammar walker (`component_guard.py`), the loader wiring, the reworked worker
  reaper and the Python/JavaScript guest adapters and build recipes, statement
  coverage fell to 88 % — the uncovered mass was concentrated in the new
  modules' defensive fail-closed branches and in the opt-in heavy paths
  (the ~18 MB CPython component build and the Javy build) that a default `pytest`
  run never executes. That is growth of the denominator, not removed tests. The
  gaps that *matter* were then closed with deterministic, non-heavy tests:
  `process_executor.py` 71 % → 99 % (the 759-incident hardening paths — `_reap`
  force-reap on a stuck descendant, `_kill_worker_group` child-kill fallback,
  malformed-worker-report refusal, spawn-OSError fail-closed with no in-process
  fallback, and the `measure_overhead` temp-dir hygiene fix) and
  `component_guard.py` 78 % → 87 % (every fail-closed rejection branch now proven
  to actually raise — unknown sort/nameattributes/attribute/valtype/externtype/
  valuebound/typebound/alias tags, truncated header, non-component layer and the
  unimplemented embedded core-type declarator — so the "over-reject only, never
  bypass" guarantee is executable, not just asserted). Suite grew to 1191 passing
  / 11 skipped (1202 collected), overall coverage back to 89 % (4559/5102). The
  remaining uncovered lines are the opt-in heavy build gates and the deliberately
  unimplemented core WasmGC type grammar (refused, not parsed) — not silent holes.

- **1.2.0 release artifacts rebuilt and qualified from source HEAD.** The
  previously built `dist/` wheel+sdist (2026-10-14) predated the GHSA-32h6 loader
  wiring and the worker/language fixes, so they did **not** contain the shipped
  security enforcement; both artifacts were rebuilt with `uv build` (isolated,
  PEP 517) from a clean `--no-hardlinks` clone of the release commit
  (`4a4ac51`), giving a wheel whose `wasi_02.py` carries the `guard_component_bytes`
  call and whose sdist ships `component_guard.py` + its tests. Fresh-install
  qualification against **only the installed wheel** (external venv, site-packages
  resolution, scratch CWD — no source shadowing) confirmed: an async-lifted
  component is refused at the loader with a `GHSA-32h6-97mm-8q3c` error before the
  native parser, a real WASI p2 guest is not blocked, and the `lang_js` adapter
  round-trips a freshly built Javy guest. The native engine bundled with the
  install resolves to the same `_libwasmtime` digest the security advisories were
  measured against. Identity (commit + artifact + engine digests) is recorded in
  `benchmarks/results/2026-10-15/release_identity.json` and the run in
  `fresh_install_qualification.json`. **Mechanical publishability is not a
  release approval**: the 49.0.0 engine stays unpatched for GHSA-32h6, the pilot VM
  is `NOT TESTED` and the independent audit is pending, so the public release
  remains on HOLD and no push/upload was performed.

- **Public-content guard in CI.** A new gate (`scripts/check_public_content.py`,
  rules in `scripts/public_content_guard.json`) scans the tracked tree on every
  push and PR for private-environment leaks — personal home paths, credential
  shapes, accidentally committed working documents — so the repository keeps
  carrying product, engineering and verifiable evidence only. The rules are
  structural and generic by design; stricter project-private patterns can be
  overlaid locally without ever entering the public repo, and findings are
  classified by a human, never blind-deleted.
- **Guard vocabulary extended.** The internal-wording rules now also catch
  decision codes, work-package phrasing, audit-finding codes, defect-ledger
  numbers and milestone shorthand in public text, and the corresponding
  references in shipped docstrings, comments, CI labels and security documents
  were rewritten into plain engineering language — no technical statement
  changed.
- **The guard now catches the classes a release sweep actually found.** Measured
  against the pre-sanitisation tree, the widened identifier rules report 142
  internal references in 54 files where the shipped rules reported none, and a
  second round added four more families the sweep surfaced but no rule named:
  work-branch values recorded inside evidence JSON (`internal-branch-ref`),
  laboratory host and build-tree names inherited by raw captures
  (`internal-build-label-ref`), artifact labels encoding a gate build or a
  milestone (`internal-artifact-label-ref`) and work-stream labels used as
  docstring headers (`internal-workstream-ref`). The `personal-home-path` rule
  also stopped pre-trusting one account name that turned out to belong to a real
  reference host, which had been silencing that host's build paths. Every new
  rule ships with a positive fixture, and
  `tests/test_public_content_guard.py::test_every_configured_rule_can_fire` fails
  if any configured rule could never fire — a guard nobody can prove works is a
  guard that is quietly dead.
- **The CI history scan checks commit CONTENT of the range a push introduces.**
  `scripts/distribution_guard.py history --content --strict-ids` applies the
  contextual identifier rules to the blobs a push would newly publish (universal
  secret shapes stay repo-wide), so a squashed or replayed branch cannot smuggle
  an internal work identifier that full-history scanning would bury in noise.
  Measured on the accumulated release branch, that range carries 375 findings
  across 9 rule classes — which is precisely why the release is pushed as a
  cleaned, re-qualified state rather than as 69 intermediate commits.

### Documentation

- **README aligned with the enforced isolation posture.** The enforcement
  section now states plainly that a WASI 0.2 component the host has not marked
  `trusted` is forced onto the subprocess path by the central gate — refused,
  not silently downgraded, when the worker is unavailable — while Preview1
  modules keep the caller-chosen `--isolated` boundary, and that driving the
  `ComponentSandbox` primitive directly bypasses the gate by design. A new
  "evaluate it yourself" entry points an independent reviewer at the committed
  verification scripts and their reproduce commands. Quick-start commands were
  re-checked against the current CLI flags and the public Python API. No runtime
  behavior changed and no new guarantee is claimed beyond what the tests show.
- **Release-vs-source claim consistency gate for the docs.** The published
  `1.1.0` wheel predates the enforcement gate and the attestation fields, while
  `main` still reports the same version string — so the docs now name the build
  each claim belongs to. The README hero replaces the single `status-stable`
  badge with `api-stable` plus `security evaluation pending` (a stable API is not
  a production-security approval for untrusted workloads); the quick start and the
  evaluation entry point install from a pinned commit and carry a machine-checkable
  presence check (`TRUST_UNKNOWN` import) that tells the two builds apart;
  SECURITY.md's ADR-015 section states its build scope; and
  [docs/release_assurance.md](docs/release_assurance.md) adds the per-control
  matrix measured against the unpacked published artifact (wheel sha256 recorded).
  `pyproject.toml` moves the PyPI classifier to `Development Status :: 4 - Beta`
  so the next release stops publishing a production-readiness signal the project's
  own gate withholds — an already-uploaded release file cannot be re-labelled
  retroactively, and the live PyPI page for 1.1.0 keeps its old metadata and README
  snapshot until the next upload (stated in docs/release_assurance.md so reviewers
  read the repository, not the index page). No runtime behavior changed; no
  release was cut.
- **README/docs figures and examples re-verified against the exact built 1.2.0
  artifacts.** Every CLI/API example was re-run against the installed 1.2.0 wheel
  from a clean out-of-tree directory (no source shadowing): `run --isolated` prints
  `Hello from Ephemora Cell!`, `run_wasm(max_fuel=100)` returns `FUEL_EXHAUSTED /
  fuel_consumed=100 / stdout=''`, the `--json` receipt matches, the five CLI verbs
  (`run/inspect/benchmark/build/ledger`) match, and `run_python` fails closed with
  the single documented `pip install` command. Four accuracy drifts were corrected:
  the version-string framing (published `1.1.0` vs source/`1.2.0`-in-preparation,
  which are no longer the same string — README quick start and the isolation
  paragraph); the `fuel_bomb --json` sample is now labelled an abridgement of the
  real (richer, `security_baseline`-carrying) receipt rather than shown as its full
  body; `run_isolated()` is documented as returning the same `ExecutionResult` type
  (attribute access plus backwards-compatible dict-style) rather than "a dict", with
  the raw dict reserved for `process_executor.run_isolated`; and the JavaScript
  support text now reflects that a reproducible Javy 9.1.0 recipe
  (`scripts/build_js_guest.py`) exists and was qualified against the installed
  wheel — a new `benchmarks/results/2026-10-15/js_component_guest.json` evidence
  artifact records it, and the 2026-10-14 Python evidence snapshot carries a
  labelled supersession note for its two overtaken outcome claims (component_guard
  wiring, JS not-provisionable). Only documentation/evidence changed; no runtime
  behavior changed and no release was cut.

## [1.1.0] - 2026-10-05

Interpreter-blocker release. ADR-009 Tier 2 says a bring-your-own interpreter
runs under the same boundary — but two hard refusals made that unreachable in
practice, and both turned out to be implementation problems rather than
policy: the 32 MiB module cap could not be raised through a profile, the
library API or the CLI (it was enforced only in the subprocess worker), and
the sync blockade rejected CPython-WASI at the **import** layer for a
symbol the guest never calls. The cap is a knob now; the blockade moved to the
call layer, where the interpreter needs no exception at all. No default got
weaker.

### Security

- **The resolve-time SSRF filter classified by CPython patch release, and on
  3.10.11 / 3.11.8 / 3.11.9 a 6to4 address embedding 127.0.0.1 was reachable.**
  `_ip_blocked` delegated the whole decision to `ipaddress.is_private` /
  `is_reserved`, whose coverage of 6to4, NAT64 and IPv4-mapped space changed
  across patch releases: 3.10.11, 3.11.8 and 3.11.9 answered "global" for
  `2002:7f00:1::` — 127.0.0.1 written as 6to4 — and simultaneously refused
  `::ffff:8.8.8.8`, so the same build both under-blocked a loopback spelling and
  over-blocked a public one. 3.12.10 and 3.13.0 refused the entire `2002::/16`,
  including public-embedded addresses. Measured across ten CPython builds before
  the fix: three distinct decision sets. Classification now comes from Cell's own
  special-use registry, and the three families that carry an IPv4 destination
  (`::ffff:0:0/96`, `2002::/16`, `64:ff9b::/96`) are decoded from the packed
  bytes and judged by that destination — the notation is never the authority.
  Refused additionally: `2001::/23` (Teredo — its embedded address is
  obfuscated, so it is not decidable), `3fff::/20`, `5f00::/8`,
  `192.31.196.0/24`, `192.88.99.0/24`. Gates: a frozen 67-address decision set
  (50 refused / 17 reachable) that is byte-identical on 3.10.11, 3.10.20, 3.11.8,
  3.11.9, 3.11.15, 3.12.10, 3.12.13, 3.13.0, 3.13.14 and 3.14.7, plus a gate
  that flips `is_private`/`is_reserved`/`is_global` on `IPv6Address` to the
  opposite answer and requires every decision to hold. Reverting the
  classification to stdlib semantics = 6 red on 3.10.11. Found by the release CI
  matrix, not by the local gate: the local suite ran 3.12 and 3.13 builds where
  the hole did not exist.

- **The host followed a symlink the guest planted — arbitrary file write as the
  server's own user.** WASI refuses an **absolute** `path_symlink` target
  (ENOTCAPABLE) and accepts a **relative** one, so a guest could create
  `sidecar.response.json -> ../../../../../../../../tmp/victim`. The egress
  mediator then opened that name with ordinary `write_text()`, which resolves the
  link: the host truncated and overwrote a file outside the sandbox with
  host-written JSON whose content the guest partly steers (the denial reason
  echoes the requested method/URL). The request artifact was readable the same
  way. Measured before the fix: the victim file's bytes became the host's response
  document. Now both names are opened through one helper that uses `O_NOFOLLOW`,
  requires the descriptor it actually got to be a **regular file**, and reads from
  that descriptor; the response is published atomically, so the name is replaced
  instead of written through. A refused artifact is an **audited denial**, not
  silence, and the client-facing reason carries no absolute host path. Gates:
  `tests/test_host_file_boundaries.py`.
- **The grants loader could install nothing and still attest "verified".**
  `Path.glob` swallows `OSError`: on an unreadable grants directory it yields no
  entries and no error, so the server started with zero grants while `get-policy`
  said every grant file in that directory had been verified against the root.
  `load_egress_grants` now enumerates with `os.scandir`, surfaces the failure,
  refuses a **grant file that is a symlink or not a regular file**, and refuses an
  **empty grants directory** — behind `--egress-grants-dir`, an authority set of
  none is a misconfiguration, not a valid posture. Same rule for the trust root:
  read with `O_NOFOLLOW` from a checked descriptor.
- **The audit book was outside the boundary it enforces.** Caps, windows and
  revocation live in the grant ledger, so a symlinked or swapped ledger silently
  reset them; `AppendLog` now opens with `O_NOFOLLOW` for reading and writing and
  replays through the same descriptor. A book that cannot be read or written
  refuses the **call with an audit line** (`limit: "ledger"`) instead of raising
  past the mediator — the fetch was already denied, but the exception lost the
  audit entry and `_meta.egress`, and one corrupt record switched off every grant
  in the process.
- **A hostile or broken peer produces decisions, not crash paths.** (a)
  `http.client`'s own failures — `InvalidURL` from a **tab inside the authority**
  that the allowlist still matched, a response with **more than 100 headers**, a
  junk status line — subclass neither `OSError` nor `ValueError`, so they escaped
  `mediate()` and the caller got no audit at all; now audited denials with
  `limit: "transport"`. (b) `timeout_seconds` bounds **one socket operation**, so
  a peer trickling a byte every 20 ms outlived it indefinitely — once per hop, up
  to ten — while pinning a host thread; the mediated fetch now reads in chunks
  against **one wall-clock deadline** (`read1`) and delivers nothing when it
  expires (`limit: "timeout"`, measured 8 s of trickle refused at 1 s). (c)
  `http://:@host` passed the userinfo check because an empty username is falsy,
  and the wire carried `:@…` in the `Host:` header; any `@` in the netloc is
  refused now.
- **The redirect audit no longer claims hops it never opened.** The stdlib calls
  `redirect_request()` **before** applying its own loop limits, so an undispatched
  hop was recorded as followed while the entry still read `allowed, fetch failed`.
  The limit is mirrored before recording: reaching it is a **denial naming the
  refused hop**, and `followed` contains only hops the peer actually served
  (asserted against the server's own request log).
- **One undecodable byte no longer kills the stdio server.** The transport read
  text-mode `sys.stdin`; under a utf-8 locale `readline()` raises
  `UnicodeDecodeError` inside the stdlib where nothing in the loop can catch it —
  traceback on stderr, exit 1, buffered responses lost. It reads **bytes** and
  decodes with replacement, so malformed input is a `-32700` and the next message
  is still answered. Two further transport bugs from the same probe: the
  oversized-line cap was applied **after** buffering the whole line (40 MB with no
  newline → ~87 MB RSS), now while reading; and leftover bytes after a line
  boundary were **dropped**, so one read carrying two messages answered only the
  first.
- **The wire format stopped leaking and stopped lying.** A module that fails to
  instantiate used to return `traceback.format_exc()` as `stderr`, which the MCP
  error response embeds verbatim — absolute paths, interpreter layout, the
  site-packages tree of the machine running the sandbox; it now lives in
  `ExecutionResult.host_traceback`. And because `json.loads` accepts
  `NaN`/`Infinity` while the request `id` is echoed back, the server could emit a
  frame strict parsers reject: non-finite ids are refused at the edge (`-32600`)
  and the transport serialises with `allow_nan=False`.
- **"Ephemeral" became a checked property.** `cleanup()` used
  `shutil.rmtree(..., ignore_errors=True)` and reported success while an
  undeletable sandbox survived (demonstrated with a directory the user may not
  write to); it now removes without swallowing and **returns the residue**. An
  unreadable output capture was reported as empty output — a lost result
  presented as a result — and now says so in the string the caller reads.
- **The request artifact is bounded at the read** (1 MiB), so a host parser is
  never handed an arbitrarily large document the guest decided to write; the
  denial happens before the allocation, not after.

- **A signed grant could out-rank the operator's own allowlist.** For its tool a
  grant REPLACED `--egress-allow`, so one signature broader than the server-wide
  list widened what a tool could reach — the allowlist was a floor nobody checked.
  `mediate_with_grant` now takes the server-wide policy as a `ceiling` and
  validates against it BEFORE the ledger charges: an endpoint outside the
  operator's list is denied with `limit: "server-policy"` and spends no slot, and
  `get-policy` discloses the live scope as `grant_scope` (with no server-wide list
  the grant alone decides, and it says so). Gate:
  `TestEngineGrantEnforcement.test_a_grant_never_widens_the_server_wide_allowlist`
  plus a positive control that a granted endpoint inside the policy still fetches.
- **The MCP handshake was not ordered, and one CLI guard was dead code.** A
  handshake-era client that skipped `initialize` was served `tools/call`
  anyway — spec-wise "other requests are not possible until initialization has
  completed" (2025-03-26), and a malicious-client case rather than an accident.
  Requests that name no protocol version in `params._meta` are now refused with
  `-32600` before the engine is reached, and a second `initialize` on the same
  process too; the stateless `2026-07-28` path and the `server/discover` era-probe
  stay reachable, because that revision has no handshake and the probe is sent
  before one. Gates: `tests/test_mcp_adapter.py::TestHandshakeOrder` (11). Along the
  way the new CLI test for `--egress-grants-required` caught that its own
  validation guard could never fire — it was nested inside the `if
  args.egress_grants_dir:` branch whose condition it negated. It now runs before
  that branch and exits 2.
- **The ceiling was a fence around one URL, not around the fetch.** A
  red-team pass against the code that had just landed found both halves of that
  sentence. (a) The ceiling was validated for the URL the guest wrote, while
  `execute_request` handed the redirect revalidator the GRANT policy alone — so an
  origin answering `302` to a sibling prefix the operator had deliberately left out
  of `--egress-allow` was fetched, audit reading `allowed, fetched, status 200`.
  Measured before the fix: 2 served paths for one mediated request. Every hop is
  revalidated against both now, and a hop refused by the ceiling is audited as
  `limit: "server-policy"`. (b) `EgressGrant.policy()` is rebuilt from endpoints and
  methods, so its byte and time limits were the *dataclass defaults* — an operator's
  `--egress-max-response-bytes 256` was silently replaced by 64 KiB the moment a
  grant existed (measured: 8 203 bytes delivered against a 256-byte ceiling). The
  strictest of the two now wins, including the ceiling's resolver. A signed
  document may narrow the endpoint scope; it may not lift a resource envelope.
- **A grant authorized the tool it was FILED UNDER, not the tool its signature
  names.** `load_egress_grants` keys grants by the `tool` field inside the signed
  payload for exactly this reason, but the engine looked up whatever dict key a
  caller passed — so `CellToolEngine(egress_grants={"victim-tool": grant_for_echo})`
  mediated `victim-tool` on echo's signature and charged echo's cap slot (measured
  before the fix: `decision: allowed` for the wrong tool). The engine now re-keys by
  `grant.tool` and refuses two documents claiming one tool, so on every path —
  loader or library — the signed document is the only thing that decides which tool
  a grant speaks for. Gate:
  `test_a_grant_authorizes_the_tool_its_payload_names` (book-based: the mis-keyed
  mediation leaves the grant's slot at 0, the payload-named tool spends it).
  Fixing it also exposed four tests whose setups had relied on the key being
  authoritative (`{"other": grant_for_t}`) — they now name a genuinely different
  tool instead of a mismatched key.
- **Three smaller fail-open and disclosure paths, same pass.** `SplitResult.port`
  validates lazily, so `http://allowlisted-host:70000/…` split fine and then raised
  OUTSIDE the guard — past `validate_request`, past the mediator, into a JSON-RPC
  -32603 with no audit entry and no `_meta.egress`: a guest-steered silence in the
  one place the design promises a recorded decision. The handshake exemption keyed
  on the presence of `params._meta` rather than on its value, so a client naming a
  HANDSHAKE-era version there (`2025-03-26`) was served `tools/call` before
  `initialize` — the exact malicious-client case the gate was built for;
  per-request metadata is the `2026-07-28` model, so a legacy version no longer buys
  the exemption (unsupported versions keep answering -32022, which is how a modern
  client identifies the era). And `CellToolEngine(grants_required=True,
  grant_ledger=…)` built with NO grants, denied every call, and left `get-policy`
  reporting `mediation: disabled` — a posture nothing could see; the guard now
  demands grants AND a ledger. Strict-mode denial also moved AFTER the
  request-artifact check, so an ungranted tool that attempted no egress no longer
  grows an `_meta.egress`: the flag changes what may be reached, not what a run
  reports.
- **The governed-loading path followed links the way the sidecar used to.** The
  host-boundary rule this release ships says no host read follows a name someone else
  can create — and one path still did: proposals were enumerated with `Path.glob`
  (which swallows `OSError`, so an unreadable directory reads as an empty inbox), the
  settled-check used `Path.read_bytes()` and the request itself `Path.read_text()`. A
  writer of the proposals directory could plant `x.tool.request.json -> ../../../../…`
  and the MCP server parsed the TARGET as a proposal. Deferring was the worse failure
  mode: a link can never settle, so it would sit in `pending` forever — nothing
  decided, nothing reported. Now `os.scandir` with the failure surfaced as `error` in
  the report, an explicit refusal **with a reason** unless the entry is a regular file
  reachable without following a link, the authoritative read through
  `read_regular_nofollow`, and `read_stable_bytes` itself no-follows. From the same
  audit: `AppendLog`'s no-`O_NOFOLLOW` fallback was dead code (opening a symlink on
  such a platform does not raise, so a check inside `except OSError` never ran) — it
  is a pre-open check now; `--egress-grants-required` was unreachable in a grant-only
  deployment because `policy is None → return ()` sat in front of it, while
  `get-policy` attested the denial; the ceiling's `timeout_seconds` narrowing had no
  test; and "the ceiling's resolver wins" was decorative, since `EgressGrant` has no
  resolver field — the order now makes resolution available only to the operator and
  the claim is pinned structurally. Gates: 7 tests (3 proposals, 1 stability seam, 1
  strict denial, 1 resolver, 1 timeout), each reverted to count its own red (2 + 2 + 3
  + 0 + 1).
- **The artefact's own claims now bind verification.** Three pins, all
  fail-closed: a DSSE signature entry that DECLARES an `alg` is checked against
  the expected algorithm (Ed25519 bytes labelled `ES256` used to verify happily as
  long as the caller supplied the right key, which is how an algorithm claim on an
  artefact stops meaning anything; the receipt path pins `EdDSA`),
  `verify_execution_attestation` accepts only Cell's own receipt audiences
  (`execution-report.v1`, `pre-execution-record.v1`) so a caller cannot be talked
  into confirming a **grant** envelope — signed by the same operator key for a
  different purpose — as evidence about an execution, and the shipped receipt call
  sites stop inheriting `to_dsse`'s legacy `ES256` default: the signer is Ed25519
  and the envelope says so. A grant payload that cannot be reconstructed (lone
  surrogate, integer beyond float range) raises `GrantTrustError` instead of an
  untyped `ValueError` escaping a caller that catches only the grant error.
- **The control plane stays up, and stops being spoofable from inside a run.**
  `get-policy` read grant state straight from the ledger, so one torn line took
  down the surface an operator uses to inspect the damage; it now reports
  `revoked: null` plus `ledger_state: "unreadable-for-some-grants"` and logs the
  reason. The error document merged guest stdout over the host's own fields, so a
  guest printing `{"status":"success-fake"}` overwrote the host status inside the
  document the caller parses — host facts are merged last now. And governed
  tool-request evaluation logs instead of `except Exception: pass`, so a broken
  proposal directory no longer looks like an empty inbox.
- **Measured rather than assumed:** the reviewer's case-trick question
  (`/ETC` slipping past a textual denylist on a case-insensitive filesystem) is
  already closed, because the filter compares canonical paths and
  `realpath("/ETC")` returns the stored case on APFS. Pinned by a test that also
  proves the comparison is not a naive lowercase match (`/TMP` stays allowed for
  the documented exception reason).

- **An ambient `http_proxy` silently moved the SSRF guard off its target.** With
  a proxy in the operator's environment, urllib resolves and connects to the
  PROXY host and never asks for the URL hostname — measured: the resolve-time
  shim was called with `('proxy.internal', 8080)` for a request aimed at
  `api.example.com`. So the filter vetted an address that had nothing to do with
  where the bytes went, and the actual name resolution happened on a third
  party's box; both the "private addresses are dropped" claim and the "checked IP
  == connected IP" claim were void on that path. `execute_request` now builds its
  opener with `ProxyHandler({})` — a mediated egress goes direct to the
  allowlisted origin, and a deployment that needs a proxy has to say so
  explicitly instead of inheriting it from the shell.
- **The FS escape matrix is a strict CI gate now.** The five FS-escape vectors in
  `tests/test_fs_escape_matrix.py` (trailing-slash `path_open`, mixed dot-dot +
  trailing slash, hardlink and rename across the preopen boundary — the GHSA-vqjp
  class — plus TRUNCATE without the set-size right, the GHSA-2r75-cxrj-cmph class)
  ran `xfail(condition=engine < 47.0.4, strict=False)`. On the pinned 47.0.1
  they measure **blocked**, so the marker's only remaining effect was to hide
  a future regression: a vector that re-opened would report `xfailed` and CI
  would stay green. The markers are gone and the vectors are plain asserts.
  Both CI legs were measured before the switch (macOS arm64 and linux/amd64
  via `python:3.12-slim` + wasmtime 47.0.1 — five denied, controls granted),
  and the gate was proven to bite by injecting a successful vector: it FAILS.
  The upstream advisory stays open and is still tracked by
  `scripts/check_wasmtime_patch.py`; nothing about the exposure claim changed.
- **`fd_sync` reached the host under the default config (gap closed).** The
  original blockade matched import names on the substrings
  `fsync`/`psync`/`datasync`, which never matched `fd_sync` — WASI Preview1's
  own sync entry point, the one a guest calls through `os.fsync`, and the one
  `define_wasi` wires to a real `fsync(2)`. Measured before the change: a
  module that created a file and called `fd_sync` on it exited `success` with
  the host sync performed, while SECURITY.md and `docs/threat-model.md` both
  stated it was rejected at instantiate.
- **The sync blockade refuses calls, not imports.** `fd_sync`, `fd_datasync`
  and `fd_psync` are now all shadowed with a trapping shim at the link layer.
  Refusing the import was the wrong instrument twice over: every
  `wasm32-wasi` binary Zig emits imports `fd_sync` and every CPython-WASI
  guest imports `fd_datasync`, in both cases without ever calling it — so the
  import rule rejected Tier 1 toolchains and interpreters while the harm it
  meant to stop passed beside it. Measured:
  `benchmarks/interpreter_guest/probe_datasync.py` boots the pinned guest
  behind the full trap set on a cold and a warm stdlib tree (the cold tree is
  where `.pyc` writing happens), and the default profile now stops that guest
  on `fuel_exhausted` instead of on an import. This is also where the
  published attack lives: a sync storm offloads work into the host kernel and
  its flushers, staying under 5 % guest CPU while host I/O throughput drops by
  more than 99 % ([arXiv 2509.11242](https://arxiv.org/html/2509.11242v1),
  USENIX Security '25) — it cannot be metered, only refused.
  `verify_8_vectors.py` vector 4 covers the call path (it previously covered
  `fd_psync` only — an import no real guest emits).
- **Scope stated, and now measured.** The blockade is a WASI Preview1 control.
  The WASI 0.2 component path carries no sync blockade today, and
  `benchmarks/component_sync_probe.py` establishes that against a real wasip2
  guest instead of leaving it as a code-reading sentence: with a granted
  directory both `wasi:filesystem/types` sync calls complete into the host
  (`SYNC-ALL:OK`, `SYNC-DATA:OK`), and with the default config the component
  route grants no preopen at all, so no guest reaches the surface without an
  explicit `allow_dirs`. SECURITY.md and the attack-vector summary now say so
  with the probe behind them instead of implying both paths are equal.
- **Two attestation holes that made the signature weaker than it looked.**
  `policy_fingerprint()` enumerated twelve policy keys and neither new knob was
  among them, while its own docstring promised "every wall the guest
  experiences" — so `WASIConfig(allow_fsync=True)` produced the SAME
  fingerprint as the closed default. And `PreExecutionRecord.build()` took its
  baseline from the hardcoded default instead of the config it was handed, so a
  signed pre-execution record certified `allow_fsync: false` for a run whose
  config had it on: the two attestations of one run could disagree, and the one
  a verifier reads first was the wrong one. Both knobs are now in the
  fingerprint, and `security_baseline_for(config)` is the single source both
  records derive from. `max_wasm_bytes: 0` means *no cap*, which a bare number
  reads as the strictest possible limit, so the baseline carries
  `max_wasm_bytes_unlimited` alongside it.
- **The engine-upgrade gate would have opened one patch too early, and it never failed.**
  `scripts/watch_upstream.py` and `scripts/check_wasmtime_patch.py` watched
  48.0.3/49.0.1 as the "fully patched" targets — true for the advisories known
  on 2026-09-24, false after the 2026-10-02 wave, which is patched only from
  48.0.4/49.0.2. Both target lists now name 48.0.4/49.0.2 first and keep 47.0.4
  as informational, with `tests/test_watch_upstream.py` pinning the order so a
  future edit cannot demote the gate again. Separately, the patch watcher fell
  off the end of `main()` in the waiting branch, so it exited **0** while
  reporting "still waiting" — its documented contract (0 = open, 1 = waiting)
  and any CI that trusted it were both inverted. It returns 1 now.

Sensitivity — every one of these is a gate, not documentation, and each was
proved by deleting the enforcement and counting what went red: reverting the
no-follow read, the wall-clock deadline or the byte stdin turns the matching
graders red; removing the `ceiling` argument costs exactly
`test_a_grant_never_widens_the_server_wide_allowlist`; the per-hop ceiling check
costs `test_a_redirect_hop_must_also_clear_the_server_wide_allowlist` (1) and the
strictest-wins envelope costs
`test_the_server_wide_resource_caps_narrow_a_grant_too` (1); neutering the
`grants_required` denial costs 2 (its own test plus "no egress attempted, no
`_meta.egress`"), its construction guard 2; moving the port read back outside the
guard costs 2; disabling the pre-initialize gate costs 4 tests (both refusals, the
"no WASM ran" proof and the lifecycle-vs-lookup distinction), the
duplicate-`initialize` refusal 1, and the stateless-revision-only exemption 1, and the payload re-key (a grant filed
under another tool's dict key no longer mediates that tool) 1. Re-running the whole
round is what turned up the seventh finding, which was NOT in the day's code but in
how the engine consumed the day's grant objects.

### Added

- **`--egress-grants-required`: the strict grant posture is reachable.** With it,
  a tool that has no signed grant file is DENIED mediation (`limit:
  "grant-required"`, audited like every other denial) instead of falling back to
  the server-wide allowlist without a window, cap or ledger. Off by default —
  flipping the default would change what a partially configured deployment does —
  and `get-policy` states the live posture as `ungranted_tools`, so "we run the
  strict form" is checkable rather than inferred. The flag refuses startup (exit
  2) without `--egress-grants-dir` and `--grant-ledger`, and
  `CellToolEngine(grants_required=True)` without grants raises at construction.
  Gates: `TestEngineGrantEnforcement` (2), `TestGrantScopeDisclosure` (4),
  `TestGrantsRequiredFlag` in `tests/test_mcp_main.py` (3).
- **Signed receipts are bound to one execution, not to a shape.** The signing
  path now writes an `evidence` block INSIDE the canonical bytes
  (`ephemora-execution-evidence.v1`): a fresh `report_id` per receipt, an aware
  UTC `issued_at`, and the `tool` the receipt answers for. Without it, two
  identical calls canonicalize identically, so a captured receipt was evidence
  for "some call that looked like this" — replayable against a different call,
  including a different tool. `verify_execution_attestation` gained
  `max_age_seconds` (fail-closed: no evidence block, naive stamp, older than the
  window, or more than 60 s in the future all refuse), and `get-policy` discloses
  the schema under `receipt_signing.evidence`. Reports without a signer never
  receive the block, so their `_meta` is byte-for-byte what it was. Deduping a
  `report_id` that shows up twice stays the caller's job — this path remains
  stateless ([ADR-008](docs/decisions/ADR-008-record-split-and-standard-envelopes.md)).
- **`max_wasm_bytes` is a `WASIConfig` field** (default `32 MiB`, `0` = no
  cap, negative refused at construction) and is enforced on all three paths
  that load a module: in-process, component and isolation. The cap travels to
  the worker in the stdin payload, so parent and worker enforce one value.
  Reachable from `run_wasm(max_wasm_bytes=…)`,
  `run_isolated(max_wasm_bytes=…)`, `WASISandbox.run(use_subprocess=True)`
  via config, and `--max-wasm-bytes` on the CLI. Not an engine knob — the
  pooled-engine fingerprint is unchanged, so raising a cap cannot shard the
  engine pool.
- **`allow_fsync` opt-in** (`False` by default, CLI `--allow-fsync`). Restores
  the real `fd_sync`/`fd_datasync` implementations `define_wasi` wires to host
  syncs; `fd_psync` stays trapped either way because Preview1 has no such call
  to serve. Documented as a capability grant rather than a tuning dial:
  `io_cpu_seconds` does not bound host sync work, because that work is not
  guest CPU. Default posture unchanged, and the setting is attested.
- **`interpreter` profile** — five values raised for an interpreter-scale
  guest (512 MiB module, 1 GiB memory, 1 G fuel, 120 s, 30 s `io_cpu_seconds`),
  each set from the measured wasi-python 3.10 guest; the last one because an
  isolated worker spends 5.40 s of host CPU just compiling a 22 MB binary,
  which the 2.0 s default wall kills before the guest starts. No sync
  exception, no filesystem or env grant, no interpreter binary, no language
  claim (ADR-009 posture unchanged).
- **Both knobs are attested** in the signed `security_baseline`
  (`max_wasm_bytes`, `max_wasm_bytes_unlimited`, `allow_fsync`), so a run that
  lifted them cannot read like a run that had them on — from one shared
  builder used by the receipt and the pre-execution record alike.
- `benchmarks/interpreter_guest/measure.py` +
  `benchmarks/results/2026-10-02/interpreter_guest.json`: pinned-guest
  latency/fuel per workload on both paths, the memory boot breakpoint, the
  stdlib-priming curve, and a live Docker baseline for the same Python
  workload. `probe_datasync.py` is the import-versus-call measurement behind
  the blockade change.
- `benchmarks/component_sync_probe.py` + `benchmarks/component_probes/sync_probe.wasm`
  (crate in `src/sync_probe/`, added to `rebuild.sh`): a WASI 0.2 component
  that calls `descriptor/sync` and `descriptor/sync-data`, so the component
  path's sync surface is measured rather than asserted. Self-checking like the
  other probes — it exits non-zero if the documented posture stops holding.
- `benchmarks/poll_oneoff_fuel_probe.py` + the **2026-10-02 advisory triage**
  in SECURITY.md: a **preview1** `poll_oneoff` host-work observation (the host
  work charges no fuel) is measured on our own pinned engine — 5 605 fuel at every
  subscription count (n = 0 … 20 000) while wall time on the same run goes
  ≈1.5 ms → ≈1.25 s — which is the qualifier "deterministic fuel accounting"
  needs: guest instructions are accounted, host work inside a WASI call is not.
  This is a preview1 finding, kept separate from GHSA-j366-h8gg-77pm (a preview0
  advisory Cell does not link).
  The probe is self-checking: it exits non-zero the day the flat fuel line
  disappears, i.e. when an engine patch closes it. GHSA-gqmc-89g8-p25r does not
  apply (our runs always install bounded stdout/stderr sinks);
  GHSA-96f6-r43r-8c24 (`fd_readdir` leaks three uninitialized host padding
  bytes per directory entry into the guest) does apply wherever a preopen
  exists and has no upstream workaround short of the patch. The patched lines
  are 48.0.4 / 49.0.2, and the Python binding has published no patch release
  at all — 47.0.1, 48.0.0 and 49.0.0 are the only wheels on PyPI.
- **Cross-run evidence chain (`ephemora_cell/ledger.py`, ADR-011).** A signed
  `LedgerEntry` envelope hash-links one run's pre-execution record and receipt
  to the run before it: `sequence` plus `prev_hash` over the previous entry's
  signed digest, genesis at 64 zero bytes. Linkage verifies with no key at all;
  authorship only when a verifier is supplied, through the same
  `ExecutionReport.verify` implementation and `expected_alg` pin the records
  use. The chain is default-off and host-side, positions are assigned by one
  writer under `flock` with `O_APPEND` and `fsync`, and existing record bytes
  are unchanged — pinned by test rather than argued. `ephemora-cell ledger
  <path>` prints what it proves and, in the same breath, that authorship is not
  proved and a chain truncated at its end is invisible from the file alone.
- **Tenant attribution and cumulative budgets (`ephemora_cell/tenant.py`,
  ADR-012).** `--tenant ID --tenant-book PATH [--tenant-max-runs N
  --tenant-max-fuel N]`, or `WASISandbox.run(tenant=…, tenant_budget=…,
  tenant_store=…)`. A tenant is a billing and aggregation identity, not an
  isolation boundary, and nothing a guest can observe changes when one is
  attached. Admission reserves the ceiling the sandbox itself will enforce
  (`WASISandbox.reservation()` — a caller cannot pad it), settlement books what
  the run actually consumed, and an exception hands the reservation back
  instead of letting a crash bill the account. Caps are inclusive: a cap of N
  admits exactly N runs, also under 20 contending threads. The check lives in
  `run()`, which is the one place all three execution paths converge, so the
  subprocess and component paths cannot bypass it — and the worker payload
  carries no tenant at all. Receipt and pre-execution record attest
  `tenant`/`tenant_budget_ref` inside `security_baseline` and fold both into
  `policy_fingerprint`, with the keys present only when a tenant was attached,
  so unaccounted records keep exactly their previous bytes.
- **Egress mediator, closed where it leaked (`ephemora_cell/egress_sidecar.py`).**
  Two defects, both proven against local servers before being fixed: redirects
  were followed without re-checking the policy (an allowlisted URL answering
  `302` to an off-policy host reached it once and was audited as `allowed`), and
  the path allowlist matched by string prefix, so `/v1` admitted `/v1-admin/keys`
  and `/v1/../v1-admin`. Matching is now per segment with dot-segments refused
  raw and percent-decoded, ports are normalised, and every hop is revalidated
  through a policy-bound redirect handler that refuses a scheme change. Entry
  documents with a query, a dot segment or a stray `%` are rejected at policy
  construction.
- **Egress now has a real caller: the MCP engine, opt-in (`ephemora_cell_mcp/`,
  ADR-013).** The mediator used to be a library surface nothing executed; now
  `ephemora-cell-mcp --egress-allow URL_PREFIX` runs it. `execute()` mediates a
  guest's `sidecar.request.json` AFTER the run but BEFORE `cleanup()` erases the
  sandbox, and attaches the decision (allowlist match or refusal, reason, hops,
  response document) to that call's `_meta.egress`. No policy, or no artifact,
  produces exactly the old `_meta` — the key appears only when a decision
  happened; a malformed artifact denies loudly rather than going quiet.
  `EgressGrant` freezes the grant ENVELOPE (id, tool, endpoints, methods,
  `not_before`/`not_after`/`max_calls`, key id, JCS bytes) with `"enforced":
  "allowlist-only"` in its own payload — true of the grant read on its own, on
  the `--egress-allow` path. The next bullet adds the consumer that enforces
  expiry, usage cap and revocation; at that point DNS-rebinding was still open
  (the check was on the URL, not the resolved IP) — the resolve-time filter
  further down closes it.
- **`get-policy` discloses the egress posture (ADR-013).** Both get-policy
  shapes now carry a server-wide `egress` block: `{"mediation": "disabled"}`
  by default, and with `--egress-allow` the enabled endpoints, response cap and
  timeout alongside `enforced: "allowlist-only"`. An operator can read from the
  control plane whether the mediator runs at all — and that its scope is the
  allowlist, not a grant.
- **Egress grants are now enforced, not just described (ADR-013, Prio 1).**
  `ephemora_cell/grant_ledger.py` is the shipped consumer that reads an
  `EgressGrant`'s `not_before`/`not_after`/`max_calls` and honours a revocation:
  `egress_sidecar.mediate_with_grant` gates a request (allowlist first, so a
  denied endpoint spends no slot; then one critical-section charge; then the
  fetch), and `CellToolEngine`/`Server` route a tool's grant through it. The cap
  is inclusive under 20 contending threads; window bounds parse fail-closed (a
  naive timestamp is refused, not assumed local); each booked line carries
  `calls_after` so an edited or dropped call is caught on replay (a truncated
  tail is not — stated, tested). `get-policy` flips to
  `grant_enforcement: ledger-backed` with the per-grant state. `CellToolEngine`
  refuses `egress_grants` without a `grant_ledger` rather than silently
  downgrading a cap to nothing. At this step a grant was still trusted because the
  host passed the file in; authenticating it is the next bullet.
- **DNS-rebinding closed at resolve time (ADR-013, Prio 2).** Every mediated
  connect — the request and each followed redirect — resolves its hostname
  through a thread-local `socket.getaddrinfo` shim
  (`egress_sidecar._guarded_getaddrinfo`) that drops loopback, RFC1918, CGNAT
  (`100.64/10`), link-local, multicast, reserved and unspecified addresses and
  refuses a name with no public answer. Validate and connect share the one
  resolution, so there is no window for the answer to rebind between the URL
  check and the socket — the residual the redirect revalidation left open. An
  allowlist entry that is an IP **literal** is operator intent and stays
  reachable. `EgressPolicy.resolver` makes the resolution injectable (an
  internal resolver in production, a fake in tests); get-policy attests
  `ip_resolution_guard: filter-names-block-private`.
- **Grant enforcement is reachable from the shipped CLI (ADR-013).**
  `ephemora-cell-mcp --egress-grants-dir DIR --grant-ledger PATH` loads
  `*.egress.grant.json` (`egress_sidecar.load_egress_grants` +
  `EgressGrant.from_document`, the schema-tag-checked inverse of `to_dict`) and
  routes each tool's grant through the ledger, so window/cap/revocation are now
  operator-usable, not only library-injectable. It fails closed twice: a grants
  dir without `--grant-ledger` is a clean startup error (exit 2), and any
  malformed or duplicate grant file refuses the whole startup rather than
  enforcing some caps and silently skipping others. At this stage the load path
  still trusted the file it read — the authentication bullet below closes that.
- **Grants are authenticated against an out-of-artefact trust root (ADR-013,
  P0).** A grant confers authority, so the loader may not take the file's word
  for it. `ephemora_cell/grant_trust.py` adds `GrantTrustRoot` — an
  operator-maintained JSON file (`egress-trust-root.v1`) that lists trusted
  Ed25519 keys with `active`/`transition`/`retired` status, per-key validity
  windows and `replaced_by`, so rotation is a fact on disk rather than in someone's
  head. The rule it encodes: **a key delivered with the artefact proves nothing
  about the artefact** — the root is passed by path (`--egress-trust FILE`,
  REQUIRED with `--egress-grants-dir`; exit 2 before a server exists) and never
  read from inside the grants directory. `load_egress_grants` now takes the root
  and, per file, checks in order: DSSE shape and the grant audience
  `https://ephemora.dev/egress-grant.v1` (so a receipt signed by the same operator
  key cannot load as a grant); THEN, before the payload is parsed at all, every
  signature against the key its OWN `keyid` names — unknown key, retired key, key
  outside its window, an algorithm the root does not name, invalid or
  non-canonical base64 (an alias decoding to the same bytes is refused, so one
  authority keeps exactly one textual identity), failing Ed25519; only then is the
  payload read, and it must be `canonical_bytes(grant)` with a usable window and
  cap (an edited or dropped field, an unknown key in the document, or a value the
  ledger could not read is a refusal); the grant's `key_id` must be present and
  among the signing keys; and the grant must not already be expired. Any failure
  is a startup error for the WHOLE directory:
  half-loaded authority would enforce some caps and silently ignore others. An
  unsigned legacy document is refused with a message that names the issuing
  command — no silent downgrade path. `python -m ephemora_cell.grant_trust
  --grant … --key … --key-id … --out …` issues an envelope and refuses to sign a
  document that names a different key. Verification runs signature FIRST, then
  payload parsing, so no unauthenticated byte drives grant construction and parse
  errors are not an oracle for whoever can write into the directory; a key entry
  with an unknown field is refused, because `notAfter` where `not_after` was meant
  would load a key that never expires; and a grant whose `max_calls` or window
  bound the ledger could not read is refused at startup instead of surfacing as an
  internal error on the first mediated call. `load_egress_grants` also refuses a
  root whose resolved path sits INSIDE the grants directory — the design said the
  anchor lives outside what it anchors, and a claim that is not checked is not a
  control. `get-policy` discloses the root SUMMARY
  (key ids, statuses, windows — no key material) under
  `egress.grant_authentication`, and each grant under its `key_id`. The disclosure
  carries its own provenance — `verified: true` plus a `verified_by` naming the
  loader that did the work — so `get-policy` cannot imply authentication that some
  other path skipped. Without
  `cryptography` (extra `tools-signing`) the error is actionable at startup, never
  a grant that loads unverified.
- **Component-probe evidence is now hash-identified, not asserted.** The dated
  security measurements cite `benchmarks/component_probes/*.wasm` as their fixture,
  and those binaries are deliberately not committed (`.gitignore`: `*.wasm`, no
  exception for that directory) — so a clone contained a citation to bytes that
  existed nowhere in the repository, while `rebuild.sh` claimed "the committed
  .wasm binaries are the evidence". `benchmarks/component_probes/fixtures.json`
  pins each probe's sha256, size, source crate, build command, measurement date and
  the dependencies pinned at that build, and states the policy: a hash identifies
  WHICH bytes were measured, it is not a reproducibility promise, and a rebuild that
  differs means re-running the measurement rather than editing the pin. `rebuild.sh`
  now builds into `.rebuilt/`, verifies against the manifest, fails on on-disk
  drift, and only overwrites the working fixtures with an explicit `--install`.
  CI does not rebuild these (its builder job installs `wasm32-wasip1`, not
  `wasm32-wasip2` + `wasm-tools`) — stated in the manifest, the script and
  SECURITY.md, and checked by `tests/test_component_probe_fixtures.py` so the claim
  cannot rot into a contradiction again.
- **Per-call receipts are now cryptographically verifiable (ADR-008).** The MCP
  spec says `_meta` is "not verified by the protocol" and callers "SHOULD NOT
  rely on them for security decisions". With `--receipt-signing-key PEM`
  (+ `--receipt-key-id`) the host signs each call's receipt into a DSSE v1
  envelope over the SAME canonical bytes as `_meta.execution`, emitted as
  `_meta.attestation`. A caller holding the matching public key verifies it with
  `execution_report.verify_execution_attestation`, which fails closed unless the
  envelope's `payloadType`, its payload (exactly `canonical_bytes(execution)`)
  and the signature all agree — so the receipt is bound to the fields shown, not
  merely signed. `get-policy` reports the posture (`receipt_signing`). Off by
  default: an unaccounted call's `_meta` is byte-for-byte unchanged. The private
  key never leaves the operator (needs the optional `cryptography` package).

- `benchmarks/statelessness_probe.py` + dated evidence
  `benchmarks/results/2026-10-05/statelessness_invariants.json` — the product
  promise measured rather than asserted: 1000 consecutive run-pairs where A writes
  a marker into its scratch, onto stdout, and into a generated identifier and B
  tries to see it, on all three execution paths, plus 40 SIGKILLs landing at
  random points inside an audit-book append. Result: **0 leaks across 1000 pairs on
  the pooled path (2000 distinct sandbox directories, 1.16 ms/pair), 0 on the
  per-run-engine path (1.995 ms/pair), 0 across 40 isolated-subprocess pairs
  (107 ms/pair), and 40/40 books self-consistent after a killed writer with 0
  silently wrong.** Cost is part of the finding: isolation by subprocess costs
  ~90× the per-pair wall time of the in-process path at this guest size. A
  positive control asserts the reader DOES detect a legitimately present marker —
  without it, "0 leaks" could just mean the detector is blind.

### Changed

- **The `io_cpu_seconds` refusal now quotes the number it actually compared.** The
  watchdog compares the worker's ABSOLUTE process CPU (that is the design: the wall
  bounds every host syscall the guest induces, and it is metered in the worker's own
  CPU), while the error string reported the run-attributable DELTA. The result was a
  message like `worker used 0.47s CPU (io_cpu_seconds=2.0)` — naming a figure BELOW
  the budget it claimed to have exceeded, measured in the emulated clean-room leg.
  Enforcement is unchanged (still conservative: it refuses), the message now names
  the absolute value and labels the delta as what it is, so the audit a operator
  reads is the decision that was made. Gate:
  `tests/test_process_executor.py::TestIoCpuWallReporting` (spin-loop guest, asserts
  the cited number is >= the budget it cites) — reverting the message to the delta
  form turns it red on native hardware, not only under emulation. Whether the wall
  SHOULD exclude worker startup is an enforcement question and is recorded as open,
  not answered here.
- **One client-visible protocol behavior, on purpose:** a handshake-era request
  that arrives before `initialize` is answered with `-32600` instead of being
  served, and a repeated `initialize` on the same stdio process too. Real clients
  are unaffected (every MCP client initializes before listing or calling, and the
  `2026-07-28` stateless path plus the `server/discover` probe are exempt by
  design), but a hand-rolled script that fired `tools/call` at a fresh process
  now has to send the handshake first. Rationale and the spec quotes that justify
  the asymmetry: [ADR-013](docs/decisions/ADR-013-egress-host-mediation-and-grant-form.md)
  ("Decided on 2026-10-05") and `docs/mcp.md`.
- **The sdist can now run the tests it ships.** It contained `tests/*.py` but
  neither `conftest.py` nor the `tests/fixtures/*.wasm` those tests need, so an
  unpacked sdist produced 65 failures that looked like product regressions and
  were packaging gaps (`MANIFEST.in` now ships the inputs). Modules that inspect
  REPOSITORY files — project metadata, `scripts/`, module source text — skip with
  an explicit reason when no checkout is present (`tests/conftest.py`); nothing is
  skipped in a checkout, so CI keeps every gate. Measured in a clean
  `python:3.12-slim` container (linux/amd64, running as root, `HOME=/root`) that
  installed ONLY the sdist: **803 passed, 102 skipped, 0 failed**, against
  901/4/0 from a checkout — the difference is the repo-inspection modules and the
  environment gates (missing toolchains, root ignoring file permissions).
  **That container number could not have been produced by the tree it described**,
  and re-measuring it is what said so: shipping `tests/fixtures/*.wasm` made the
  checkout detector in `tests/conftest.py` answer TRUE inside an unpacked sdist, so
  the repository-inspection modules were never skipped. The predicate now keys on
  `docs/` + `scripts/` — directories a Python distribution never ships — and the
  re-measurement at this commit is **753 passed, 136 skipped, 0 errors**, with the
  native linux/amd64 control run at 763/127/0 — and measured again two commits
  later, where a quiet host takes the clean room to **770 passed / 138 skipped / 0
  failures** (`7f9e860`) and a loaded host to 772 / 138 with one isolated-run failure
  (`3e3d32c`) from the same watchdog. The leg is therefore reported with its conditions, not as a constant. The one remaining container failure is
  `test_100_parallel_runs_no_fd_exhaustion`, which passes natively and fails only
  under amd64-on-arm64 QEMU emulation: the `io_cpu_seconds` watchdog charges the
  emulated worker's interpreter+wasmtime startup (~0.25 s) to the guest, so 5 of 100
  runs tripped a 2.0 s limit that the same runs clear in 12 ms natively. Recorded as
  an emulation artefact and an open accounting question, not as a passed gate.
- **Test fixtures stopped pretending `$HOME` is grant-safe.** Six modules created
  their "grant-safe" scratch directory under `Path.home()`, which passes on a
  laptop and fails in a container: `HOME=/root`, `/root` is a blocked canonical
  location, and the runtime correctly refuses `allow_dirs` under it
  (`ValueError: … resolves into blocked location '/root'`). They use a temp root
  now — the product was right, the fixture location was wrong. Related:
  `test_mcp_adapter` and `test_mcp_2026_07_28` resolve the shipped tool directory
  from the IMPORTED package instead of the repository layout, so those gates test
  what ships rather than what the checkout happens to contain.
- `run_isolated(..., max_wasm_bytes=None)` now means "use the config's cap"
  instead of silently collapsing to 32 MiB, so a raised cap in a config is no
  longer overridden by the API layer.

### Tests

- 12 gates from the round that audited this branch's documentation against its code:
  a symlinked proposal is refused and its target never parsed, a directory at the
  proposal name is a refusal rather than a permanent "pending", an unreadable
  proposals directory reports an error (skipped for root), `read_stable_bytes`
  refuses a link, the strict denial is reachable in a grant-only deployment (with
  no-artifact silence as the positive control), the operator's resolver is the one
  asked on the grant path plus the structural half (`EgressGrant.policy().resolver`
  is None), the ceiling's timeout stops a 2 s origin under a 0.4 s budget, the
  changelog list-structure gate (proved by re-breaking the line), and two answers to
  the duplicate-key question: `json.loads` keeps the LAST duplicate, so a repeated
  `"payload"` may only repeat the signed bytes — a same-value repeat verifies, an
  edited one is a bad signature — and a second `max_calls` inside the signed bytes,
  which would parse to the larger number, is refused because the payload is compared
  as bytes. Three more pin the URL-parser
  question the review asked: `2130706433`, `0x7f000001`, `0177.0.0.1` and `127.1` all
  name 127.0.0.1, and none of them matches an allowlist entry written as
  `127.0.0.1` — nor in the reverse direction, which is the one that matters, because
  IP literals are operator intent and are not filtered at resolve time. An
  exact-spelling positive control keeps the rule a string comparison, not a blanket
  ban.
- 31 gates for the three post-review decisions plus the round that audited them:
  `TestHandshakeOrder` in `tests/test_mcp_adapter.py` (11 — pre-initialize
  `tools/list`/`tools/call` refused with `-32600` and, proved separately, without
  reaching the engine; unknown method is a lifecycle error before the handshake and
  `-32601` after; the stateless `_meta` path and the `server/discover` probe served;
  a request naming a HANDSHAKE-era version in `_meta` does NOT buy the exemption; an
  unsupported version still answered `-32022`; second `initialize` refused;
  pre-handshake notifications still silent; normal service after the handshake),
  `TestEngineGrantEnforcement` in `tests/test_egress_sidecar.py` (8 additions —
  a redirect hop outside the ceiling is denied with `limit: "server-policy"` and the
  excluded path is never served, with a positive control that a hop INSIDE the
  ceiling still fetches; the server-wide byte cap beats a grant's default envelope;
  an out-of-range port is an audited denial on both the policy and the grant path;
  the construction guard demands grants AND a ledger; strict mode stays silent when
  the guest attempted no egress and denies audited when it did),
  `TestGrantScopeDisclosure` (4 — both `grant_scope` strings and both
  `ungranted_tools` strings), `TestGrantsRequiredFlag` in `tests/test_mcp_main.py`
  (3 — the two startup refusals and the flag reaching the engine, default `False`
  asserted in the same test), and `tests/test_checkout_skip_policy.py` (5 — this run
  must be recognised as a checkout or the repository-inspection modules go silent in
  CI, a fixture-carrying sdist must NOT be, an export without `.git` must be,
  `MANIFEST.in` may not start shipping either marker, and every skip-list name must
  exist). The seventh finding's own gate — `test_a_grant_authorizes_the_tool_its_payload_names`
  (counted in the eight above) — is a separate Security bullet below, and the
  `io_cpu_seconds` reporting gate is one more in Changed.
- `tests/test_execution_invariants.py` (4) — the product promise as four named
  gates: `test_ephemeral_invariant`, `test_stateless_invariant`,
  `test_capability_invariant`, `test_verifiable_execution_invariant`. Written
  against real guests and the real engine pool — the statelessness gate lifts
  `io_budget_bytes` on purpose, because the default byte wall forces a per-run
  engine and a test that never reaches the pool proves nothing about reuse — and
  each carries its own positive control (a granted directory must be reachable, a
  planted marker must be detectable) so they cannot pass by testing a harness that
  detects nothing.
- `tests/test_host_file_boundaries.py` (9) — the host-side symlink class: request
  artifact as a link, response artifact as a link (the arbitrary-file-write case,
  asserted on the victim's bytes), a directory at the artifact name, an oversized
  request, an absent artifact staying silent, the `read_regular_nofollow` helper
  itself, cleanup residue being reported instead of hidden, an unreadable capture
  not reported as empty output, and a host-side instantiation failure keeping its
  traceback out of the client's error content.
- `tests/test_egress_sidecar.py` gains `TestTransportWalls` (7): junk status line,
  >100 headers and a tab inside an allowlisted authority each return an audited
  denial instead of escaping the mediator; a peer trickling one byte every 20 ms is
  refused at the wall-clock deadline (measured: 8 s of dribble against a 1 s
  budget); a redirect chain records only the hops the server actually served, and
  reaching the loop limit names the hop it refused to dispatch; `http://:@host` is
  denied by policy.
- `tests/test_transport.py` gains 6 byte-level transport gates: an undecodable byte
  is a `-32700` and the NEXT message is still answered, several messages in one read
  are each answered (leftovers are carried), the oversized-line cap holds while
  reading, the transport never emits a NaN, and a non-finite request id is a
  structural error. `tests/test_mcp_adapter.py` adds the same byte test against the
  real subprocess (it used to die: rc=1, buffered responses lost) and a gate that a
  host traceback never reaches the client. `tests/test_grant_trust.py` (44) and
  `tests/test_grant_ledger.py` (20) cover the new file-boundary rules: symlinked
  grant file, symlinked trust root, unreadable grants directory, empty grants
  directory (also at CLI level in `tests/test_mcp_main.py`), a symlinked ledger, and
  an unwritable ledger refusing the call WITH an audit line.
- `tests/test_egress_sidecar.py` gains 12 adversarial egress tests: the address
  families a rebinding name can answer with (`TestSSRFAdversarialFamilies` —
  scoped IPv6, both metadata addresses, CGNAT edges, IPv4-mapped IPv6, 6to4 and
  NAT64 forms, multicast, unspecified, documentation ranges, with a public
  positive control that includes `::ffff:8.8.8.8`), the ambient-proxy case, a
  real 302 into an allowlisted name resolving to the metadata address, and
  multi-A ordering/all-private behaviour. `TestResolvePinningTOCTOU` (3) spies on
  the socket the stdlib builds below the guard and asserts `connect()` only ever
  sees the vetted address. `TestGrantConcurrency` (3) releases 20 mediated
  engine calls through one barrier against a real local origin: exactly
  `max_calls` fetches leave the process, a single slot cannot be taken twice, and
  no call line can be booked after a revoke line. Sensitivity was checked by
  degrading the filter — five of these turn red — and the concurrency run is
  stable over five repeats.
- `tests/test_signed_receipt.py` gains 7 replay-binding tests: per-receipt nonce
  uniqueness, the tool binding, the nonce being inside the signed bytes (rewriting
  it invalidates), the freshness window accepting a new receipt and refusing one
  signed two hours earlier, fail-closed behaviour with no evidence block or a
  naive stamp, the 60 s future-skew allowance, and that an unsigned report
  receives no `evidence` key at all.
- `tests/test_grant_trust.py` (39) — the grant authentication gate: happy path,
  payload equals canonical bytes, an edited payload and a non-canonical payload, a
  flipped signature, an unsigned legacy document, a signature from a key outside the
  root, a signature re-labelled under a stranger's `keyid`, retired and `transition`
  keys, a key outside its window, an algorithm mismatch, a receipt envelope replayed
  onto the grant audience, an already-expired grant, a grant whose `key_id` diverges
  from or is absent in the document, every trust-root validation refusal (version,
  audience, empty or duplicate keys, unknown status or alg, self- or dangling
  `replaced_by`, bad PEM), `summary()` carrying no key material, loader integration,
  and the issuing round-trip including its refusal to sign for another key.
  `tests/test_mcp_main.py` drives the same through the CLI: an unsigned, tampered or
  foreign-signed grant file and a broken root each refuse startup, and the server
  receives the root summary — never key material.
- `tests/test_component_probe_fixtures.py` (9) — the dated evidence names four WASI
  0.2 probe binaries that are deliberately NOT committed. The gate checks the sha256
  manifest against the source crates, that any bytes present on disk ARE the pinned
  bytes, that every probe the docs cite is hash-identified, that no doc or script
  claims the binaries are committed, that `rebuild.sh` verifies against the manifest
  and cannot overwrite the evidence by default, and that CI's claim not to rebuild
  them is still true.

- `tests/test_module_size_cap.py` (40 tests) covers cap configurability,
  enforcement on all three paths, config→worker marshalling, the public API
  and CLI surface, the profile's five raises and its non-grants (including
  that `allow_fsync` stays off), that all three sync entry points trap on the
  call while their imports stay legal, and the attestation of both knobs.
- `tests/test_ledger_chain.py` (28 tests) — the ADR-011 chain: a gapless
  sequence under 8 concurrent writers, keyless linkage, an edited or reordered
  entry reported with its position, the entry digest computed by the same
  recipe `verify_chain` uses, and that existing record bytes do not change when
  no ledger is in use. Also that a truncated tail is NOT detectable from the
  file alone (the limit is tested, not just documented), and the CLI verdict's
  `proves`/`cannot_see` split.
- `tests/test_tenant_budgets.py` (49 tests) — the ADR-012 book and its
  enforcement: reservation equals the config's own wall, caps are inclusive
  under 20 contending threads, refusal happens before anything is started,
  every dispatch (preview1, subprocess, component, auto-unpooled) is billed
  exactly once, a raising run returns its reservation, a crashed worker is
  flagged rather than free, the worker payload carries no tenant, edited or
  reordered totals do not silently pass, and a budget below one run's wall
  refuses everything.
- `tests/test_records_envelope.py` gains `TestTenantAttestation` (4 tests):
  records of an unaccounted run keep their exact signing bytes, the account
  moves both the fingerprint and the baseline, and two tenants under one config
  cannot share an agreement.
- `tests/test_cli_inprocess.py` gains `TestTenantFlags` (3 tests) — two
  invocations against one book accumulate and the third is refused, and
  `--tenant` without `--tenant-book` is a clean error.
- `tests/test_egress_sidecar.py` (29) now includes `TestAllowlistPrefixSemantics`
  and `TestRedirectRevalidation`, which fail against the pre-fix code: the
  off-policy redirect target is never fetched, a scheme change is refused, and
  sibling paths (`/v1-admin`) no longer match a `/v1` entry. `TestEngineEgressTrace`
  proves the mediator has a real caller — `execute()` mediates before
  `cleanup()` (asserted via the response artifact present at cleanup time),
  on-policy is fetched, off-policy and malformed artifacts deny rather than go
  silent, and no policy means no read at all. `TestServerMetaEgress` pins that
  `_meta` is unchanged with no egress and carries the decision under
  `_meta.egress` when present. `TestEgressGrantForm` fixes the grant envelope's
  canonical bytes and pins that only the allowlist is the enforced part.
- `tests/test_mcp_main.py` (16 tests) — the `python -m ephemora_cell_mcp`
  entrypoint, previously at 0% coverage: no flag builds no policy, `--egress-allow`
  builds the exact `EgressPolicy` the engine enforces, an unusable endpoint
  is a fail-closed startup error (exit 2) rather than a half-wired server,
  `--egress-trust` + `--egress-grants-dir` + `--grant-ledger` wire authenticated,
  real grants into the server, and a grants dir without a ledger, without a trust
  root, with an unsigned legacy document, with a tampered grant, with a grant signed
  by a key the root does not name, with a broken trust root, or with a malformed
  grant file are each clean exit-2 refusals that construct no server, while
  `--receipt-signing-key` wires a signer (unreadable key =
  exit 2, default = no signer).
- `tests/test_signed_receipt.py` (7 tests) — the ADR-008 signed receipt with a
  real Ed25519 keypair through the shipped signer/verifier helpers: the
  attestation verifies and is bound to the shown execution dict, a foreign key
  or an edited field fails, the envelope payload is exactly
  `canonical_bytes(execution)`, no signer leaves `_meta` unchanged, get-policy
  reports the posture, and the verify helper fails closed on malformed input.
- `tests/test_mcp_adapter.py` gains `test_get_policy_reports_egress_disabled`
  and `..._enabled_as_allowlist_only` — both get-policy shapes attest the
  mediation state, and an enabled policy discloses endpoints and the
  allowlist-only scope. `..._attests_grant_enforcement_as_ledger_backed` pins
  the ledger-backed shape with per-grant state.
- `tests/test_grant_ledger.py` (18 tests) — the ADR-013 enforcement core: an
  inclusive cap under 20 contending threads, a refusal spending no slot,
  `not_before`/`not_after` boundaries (expiry exclusive), `Z` accepted and a
  naive timestamp refused, revocation biting inside an open window, an edited or
  dropped call line caught by replay, and a truncated tail NOT detectable from
  the file alone (the limit tested, not claimed).
- `tests/test_egress_sidecar.py` gains `TestEngineGrantEnforcement` (5 tests) —
  the engine charges each fetched call and stops at the cap, revocation refuses,
  an off-allowlist request spends nothing, grants are keyed by tool name, and
  `egress_grants` without a `grant_ledger` fails closed at construction.
- `tests/test_egress_sidecar.py` gains `TestSSRFGuard` (5 tests) — the
  blocked-address matrix incl. CGNAT, the shim dropping forbidden IPs and
  raising when none are safe, an IP-literal host passing unfiltered, and
  `mediate` refusing a name that rebinds to `169.254.169.254` (opens no socket).
- `tests/test_egress_sidecar.py` gains `TestGrantLoader` (5 tests) —
  `EgressGrant.from_document` round-trips `to_dict` and refuses an unknown
  schema tag or a missing field, and `load_egress_grants` reads a directory,
  names every malformed/duplicate file (never silent), and refuses a missing
  directory.

## [1.0.5] - 2026-09-29

Licensing, security-readiness and evidence release. The license changes
from Apache-2.0 to the Business Source License 1.1 (BUSL-1.1) —
source-available, free for non-production use, converting back to
Apache-2.0 four years after each version's first public release; all
versions ≤ 1.0.4.3 remain Apache-2.0 (ADR-010). The 2026-09-24 wasmtime
advisory wave — three GHSAs this repo did not previously track — is
triaged against the 47.0.1 pin with measured evidence, the sandbox
receives three security fixes, and the engine-config construction is
consolidated so the blocked engine upgrade touches one site instead
of three.

### Security

- **Denylist drift on the component path (fix + regression test).**
  Mapping-style `host:guest` preopen grants bypassed the string denylist
  on the component ABI: `ComponentSandbox._filter_dangerous_dirs` checked
  the raw `"host:guest"` string where the Preview1 path splits the
  mapping first — an entry like `/etc::guest-etc` passed the component
  filter. One shared dir-guard (`ephemora_cell/_sandbox_common.py`) now
  serves both ABI paths. Guarded by `tests/test_dir_guard.py` (verified
  to fail on the pre-fix implementation) and the component security
  matrix.
- **Verifier alg pinning (audit finding, closed).** `ExecutionReport.verify`
  and `PreExecutionRecord.verify` accept `expected_alg` (forwarded by
  `verify_manifest`): a record whose `alg` field is missing or differs
  fails closed. Calls without the parameter behave exactly as before.
- **JCS safe-integer guard (audit finding, closed).** Canonicalization
  rejects integers beyond ±(2^53−1) instead of silently serializing them
  as strings — third-party verifiers (Rust/JS) would read such records
  differently. Fail-closed on sign and verify.
- **2026-09-24 advisory wave triaged (measured, 2026-09-29):**
  GHSA-j2g9-4prp-pf6h reproduces on the in-process component path — a
  guest can panic the host (`SIGABRT`) via filesystem datetime overflow;
  fuel, epoch and memory caps do not apply inside the host call. Measured
  containment: the subprocess path survives (worker dies, parent reports
  a clean error) — run untrusted guests with `use_subprocess=True` until
  the planned engine upgrade. GHSA-c9gc-w9vx-w86p is structurally unreachable:
  guests are never linked against wasi-http (pinned in
  `tests/test_surface_audit.py`). GHSA-jqpg-j7w6-42pr does not apply as
  read (statically-typed host, no dynamic-Val lifting); re-check at the upgrade.
  Full table in SECURITY.md; fresh evidence in
  `benchmarks/results/2026-09-29/` (Preview1 + component CVE replays
  PASS, `datetime_overflow_ghsa_j2g9.json` PASS).

### Added

- Root `.mcp.json` (project-scope MCP config): launches the server via
  `uvx --from ephemora-cell ephemora-cell-mcp` — the same start command
  as `smithery.yaml`. Clients that honor project-scope `.mcp.json`
  offer the server with a one-time user approval, and agent-plugin
  scanners (Open Plugins / Cursor Directory) now detect the repo as
  carrying an MCP component. Floating PyPI version, no secrets, no
  config required (bundled tool set).
- `scripts/watch_upstream.py` — watches the three ADR-009 external gates
  (patched wasmtime wheels on PyPI, wasmtime-py `add_wasip3` surface,
  GC-heap limiter binding) with `--json` output; offline unit tests in
  `tests/test_watch_upstream.py`. The ADR-009 watcher statement is now
  true.
- Component-path security matrix (`tests/test_component_security.py`,
  10 tests): fuel bomb stops budget-exact (1k / 1M / 0 boundary), memory
  bomb faults exactly at the cap, 10 KB output cap, 9,216 B stdin cap,
  dangerous-dir fail-closed end-to-end (incl. the mapping regression),
  named-state gap pinned explicitly. WAT-generated fixtures — runs in CI
  without a toolchain. Evidence for the dual-ABI claim.
- CI test-count guard (`scripts/check_test_count.py` + ci.yml step, run
  in strict mode): the static test-count claims in README and the
  comparison doc must match the real pytest collection — mechanizes
  "CI counter = README number".
- Project-meta pins: `tests/test_project_meta.py` (SPDX BUSL-1.1 headers
  on every shipped file, LICENSE copies byte-equal, license parameters
  present) and `tests/test_mcp_config.py` (`.mcp.json`/smithery command
  parity).
- Python 3.13: CI matrix, classifiers, SUPPORT.md/requirements.txt
  (smoke-tested locally on 3.13.14: surface/policy + component/state/
  security suites green).
- Troubleshooting section in docs/recipes.md (fulfils the README promise:
  venv/PEP 668, Windows `python`, tool-path resolution, fuel/timeout
  tuning, 10 KB output cap) and documented `--abi` / `--no-memory64`
  flags.

### Fixed

- Test-count drift across public docs: badge/freshness (532), "Testing &
  Verification" (470) and the comparison doc (424) disagreed — now
  single-sourced from the pytest collection and CI-guarded (589 passing,
  4 skipped, 87% coverage).
- `ephemora_cell/LICENSE` shipped with the unfilled
  `Copyright [yyyy] [name of copyright owner]` placeholder since 1.0.0 —
  replaced by the canonical license text (see Changed).

### Changed

- **License: Apache-2.0 → BUSL-1.1.** Ephemora Cell is now
  source-available under the Business Source License 1.1: free for
  non-production use (evaluation, development, research, testing);
  business/production use requires a license from Ephemora; every version
  converts back to Apache-2.0 four years after its first public release.
  All versions ≤ 1.0.4.3 remain Apache-2.0 permanently. Decision and
  consequences in ADR-010; contribution terms (BUSL-1.1 + relicensing
  grant) in CONTRIBUTING.md. SPDX headers unified on all 23 package files
  (`BUSL-1.1`, Michael Soppa — resolving the header/LICENSE copyright
  mismatch). GitHub license detection will show BUSL-1.1; the
  Glama license grade is expected to drop and is no longer claimed in the
  README.
- **Engine-config single-sourcing (behavior-identical).** One
  `build_engine_config` (`ephemora_cell/_engine_config.py`) serves
  `wasi_runtime`, `engine_pool` and `wasi_02` — the next advisory
  hardening edits one site instead of three; shared sandbox helpers
  replace the component path's private imports from the runtime.
  `tests/test_proposal_policy.py` (SpyConfig) stays green untouched.

## [1.0.4.3] - 2026-09-25

First release carrying the 2026-09-25 hardening line (load-path TOCTOU
closure, 2026 probe classes, ADR-008 record split) and the review-driven
README reorientation. The 2026-09-24 full-functional audit found H-1
(missing register-time re-hash) and M-1 (oversized-line transport bug);
both were fixed, regression-tested and released in 1.0.4.2 — this
release carries the follow-up hardening the same audit→fix→regression
cycle produced.

### Security

- **Explicit proposal policy (set, not inherited):** the engine also
  enforces `wasm_stack_switching=False` (WASI 0.3 native-async base —
  gate-off until the 0.3 surface is qualified; WASIp3 streams of
  GHSA-x84v-gj2h-g759 are structurally unreachable: the Python binding
  cannot link a WASIp3 world, asserted in `tests/test_surface_audit.py`).
  The full proposal posture is documented in SECURITY.md and locked by a
  compile-probe matrix (`tests/test_proposal_policy.py`) plus SpyConfig
  assertions at every engine construction site — an engine upgrade that
  silently flips a proposal default fails tests instead of production.
- **CVE-2026-34988 class guard:** the pooling allocator is not exposed by
  the Python binding (the cache-pressure-residue class is unreachable).
  An explicit 4 GiB `memory_guard_size` was evaluated and **reverted** —
  it broke `run_isolated` in constrained Linux VMs (mmap ENOMEM on
  reservation+guard; caught by the arm64 container gate).
  `tests/test_memory_hygiene.py` proves sequential instances observe only
  zeroed memory (secret-writer → residue-reader, same sandbox and pooled
  engine) and is the standing guard.
- **CVE-2026-34971 confirmation artifacts:** a version-floor test pins
  wasmtime `>= 43.0.1` (April 2026 advisory fixes), the Winch backend is
  asserted unselectable ("never Winch"), and `Engine.is_pulley()` is
  asserted `False` — no interpreted fallback in the shipped posture.
- **Atomic publication + per-call module binding (load-path TOCTOU
  closed):** all producers (governed-load install, `sign_tool`, rust
  builder) publish via temp + fsync + `os.replace` — a partially-written
  module is never visible under its final name, and the governed install
  publishes exactly the bytes it verified. The registry load-guard
  registers only settled, magic-prefixed modules within the size cap; in
  signed-tools mode every execution is bound to the register-time digest
  (`WASISandbox.run(expected_sha256=...)`, preview1/component/subprocess
  alike) — a swapped on-disk file fails closed instead of executing. The
  engine-pool module cache is keyed by content hash (no stat-then-open
  race, no stale-serve for mtime-preserving swaps). ADR-006 amendment
  documents the full model.
- **Version-sync guard:** CI machine-checks that pyproject.toml, both
  package `__version__` modules, both server.json fields and the latest
  git tag agree (release checklist in CONTRIBUTING) — the single-source
  versioning invariant is now proven, not remembered.

### Added

- **2026 probe classes with measured evidence:** FS escape matrix (the
  GHSA-vqjp FS-escape shapes plus the GHSA-2r75 / CVE-2026-47261 TRUNCATE
  vector — trailing-slash/hardlink/rename/TRUNCATE — denied on the pinned engine, with positive controls; dated
  JSON `benchmarks/results/2026-09-25/`), persistence/worm (a marker
  written by run N is invisible to run N+1), supervisor/control-plane
  reachability (env deny-by-default, request injection not reachable, no
  policy-writing tool on the MCP surface), trust-handoff (verification
  never inherits across delegation hops). Harness:
  `benchmarks/probe_classes_2026.py`; pytest counterparts in
  `tests/test_fs_escape_matrix.py`, `tests/test_persistence_worm.py`,
  `tests/test_control_plane_reachability.py`,
  `tests/test_tool_signing.py::TestTrustHandoff`.
- **ADR-008 record split + open-standard envelopes:** `PreExecutionRecord`
  signs what a run *will* do before it runs (module digest, policy
  fingerprint with allow_env names only, input digest); the receipt's
  optional `back_link` binds it to exactly that attestation
  (`verify_chain()`, fail-closed). DSSE v1 envelopes (PAE-signed,
  in-toto/TUF-interoperable) and detached JWS (RFC 7797) wrap the same
  RFC 8785 JCS payload bytes; a transparency-log inclusion proof is a
  signature-covered payload field — no network client, no dependency.
  Plain report schemas are unchanged (compat-pinned).
- docs/threat-model.md: dedicated resource-exhaustion section with a
  per-syscall budget matrix (arXiv 2509.11242 framing, measured
  `benchmarks/io_dos/` numbers)
- docs/performance.md: backend-transparency section (every published
  number is a Cranelift number; Pulley/Winch unreachable), "Fuel is
  per-platform" section with cross-platform measured examples
- docs/recipes.md: WASI 0.3 gate-off stance, throughput scale-check
- docs/security_posture.md: 2026 probe-classes section; probe
  equivalence detail and sandbox-surface diagram
- README: start-here navigation, freshness block (release/audit/
  evidence/tests), content tiering 760 → 601 lines total, −21%
  (non-blank −23%), with zero evidence loss (probe-equivalence detail,
  enforcement-stack diagram and throughput scale-check moved to docs;
  sales rhetoric damped)

## [1.0.4.2] - 2026-09-24

### Security

- **Fuel-determinism hardening for GHSA-m63x-6p34-q65x** (wasmtime fuel
  amplification via `call_ref`/`try_table`, CVSS 5.7): the Cell engine now
  enforces `wasm_function_references=False`, `wasm_exceptions=False`,
  `wasm_gc=False` and `wasm_tail_call=False` at every Config construction
  site (`wasi_runtime`, `engine_pool`, `wasi_02`, conformance harness) —
  guest modules using the affected opcodes fail to compile (fail-closed,
  empirically verified on the pinned wasmtime 47.0.1). Breaking for guests
  that legitimately need exceptions/GC; the upgrade path to wasmtime
  48.0.3/49.0.1 (where the engine fix lands) is tracked by
  `scripts/check_wasmtime_patch.py` and re-opens those proposals for
  re-evaluation.
- **`security_baseline` attests the enforced posture**: new keys
  `function_references_enabled`, `exceptions_enabled`, `gc_enabled`,
  `tail_calls_enabled` (all `false`) — a signed record cannot claim
  features the engine would reject. Exposure statement for both September
  2026 advisories (GHSA-m63x fuel amplification, GHSA-vqjp filesystem escape) in SECURITY.md.
- `scripts/check_wasmtime_patch.py` added: watches PyPI for the pending
  patch wheels (48.0.3/49.0.1/47.0.4; all absent as of this release) and
  signals when the full engine upgrade opens.

### Fixed

- **Signed-tools mode now enforces the module binding at load** (ADR-006
  register-time re-hash). `ToolRegistry._build_spec` previously verified
  only the manifest signature; a `.wasm` swapped after signing — even a
  fully valid different module (MCPoison class) — was registered and
  executed. Sidecars without `wasm_sha256` are now rejected in
  `--require-signed-tools` mode as well (same rule the governed-load path
  always applied). Found in the 2026-09-24 full-functional audit; verified
  fixed on macOS arm64 and DGX Spark aarch64.
- **MCP stdio transport no longer drops the message after an oversized
  line.** The old drain loop read the line FOLLOWING an oversized one
  (text-stream `readline()` had already consumed the whole oversized line)
  and re-parsed the transport's own error string as input, so a client got
  a generic `-32600 invalid request` instead of the transport-limit error
  and silently lost a request. The limit reply is now sent immediately and
  reading continues at the next message boundary.
- `ephemora-cell run --stdin <path>` with an unreadable file prints a clean
  one-line error (exit 1) instead of a `FileNotFoundError` traceback.
- `_HybridExecutionResult` (the unified `run_isolated()` return) now
  supports `dict(result)`, `len(result)` and `**result` unpacking via
  `keys()`/`__iter__`/`__len__` — dict-style access no longer crashes on
  the sequence protocol.

### Added

- Governed loading works on the shipped stdio server: with
  `--tool-requests-dir` configured, the serve loop evaluates dropped
  requests before each incoming message (install +
  `notifications/tools/list_changed` + request consumed). Rejections are
  reported on stderr ("never silent", ADR-006) and the request stays on
  disk. Previously only embedding hosts could call
  `Server.process_tool_requests()`.
- Container hygiene: `.dockerignore` keeps dev environments, git history
  and local caches (`.conformance_cache` alone is ~537 MB) out of the
  image — image size 1.45 GB → 271 MB — and the `Dockerfile` runs as a
  non-root user (`uid=1000 cell`).

### Changed

- CI installs `pytest<9` in every job (matching the `pyproject.toml`
  dev-extra pin and its Python 3.11 rationale) instead of unversioned
  `pytest`, which drifted to pytest 9.
- `pytest` collects only `tests/` (`testpaths` no longer lists
  `benchmarks/`, which holds evidence scripts, not pytest tests).
- `docs/performance.md` documents that fuel counts are per-platform with
  measured cross-platform examples (hello.wasm: 16 397 on macOS arm64 vs.
  12 on DGX GB10; spread 0 per platform).

## [1.0.4.1] - 2026-09-23

### Fixed

- MCP `server/discover` now reports the same registry freshness as
  `tools/list` via a shared `Server._registry_ttl_ms`. Previously
  `server/discover` hard-coded the 1 h static TTL while advertising
  `listChanged`; a host that cached that discover result for the advertised
  hour would ignore `notifications/tools/list_changed` for a full hour after a
  governed install (`--tool-requests-dir`, ADR-006) and keep issuing stale
  tool schemas against the live server — schema drift with no invalidation
  path. Under governed loading both endpoints now drop to 60 s together.
  Stdio in-place updates remain drift-free by construction (process lifetime =
  connection lifetime, a restart forces a fresh `tools/list`); `docs/mcp.md`
  adds an "Updating a running server (schema drift)" section naming `ttlMs` as
  a client hint and the three cases honestly. Guarded by
  `tests/test_mcp_2026_07_28.py::test_discover_ttl_tracks_governed_registry`.

## [1.0.4] - 2026-09-21

### Fixed

- `get-policy` now attests the filesystem surface a run will ACTUALLY
  grant, closing the last policy/enforcement drift: the security
  baseline previously reported only the profile's configured
  `allow_dirs` (empty for the default profile), while every core-module
  (Preview1) execution additionally preopens the ephemeral sandbox dir
  as `/sandbox` — a caller diffing `get-policy` against an execution
  record's `effective_preopens` saw two different filesystem stories.
  `policy_for` now derives the preopen set from the same truth as the
  run witness (configured grants + `/sandbox`; WASI 0.2 components
  excluded, matching the component path, via `is_component_binary`).
  A new `sandbox_lifecycle` field attests the execution topology
  (`fresh-per-call` default vs. `pooled` fast path), so "fresh sandbox
  per call" is a reported fact, not an inference from latency. Guarded
  by `tests/test_policy_agreement.py`: the reported preopen set must
  equal the executed run's `effective_preopens`.
- Version is now single-sourced and CI-guarded: the released 1.0.3
  wheel carried a `serverInfo`/`get-policy` version of 1.0.1 while
  `--version` said 1.0.3 — three signals for one install.
  `tests/test_policy_agreement.py` asserts `pyproject.toml` and the
  runtime `__version__` never diverge again.

### Added

- Second-platform evidence for the boundary and startup claims: the
  same-attack matrix (stock Docker 8/8 ALLOWED, hardened Docker 2/8
  blocked with all 8 pre-declared expectations matched, Cell 8/8 BLOCKED)
  and the cold/warm-start contrast (stock `python:3.12-slim` 311.8 ms /
  `node:24-alpine` 313.2 ms mean per 100 docker runs vs. Cell cold
  0.745 ms / warm 0.727 ms, pure wasmtime floor 0.006 ms) were measured
  on a DGX Spark GB10 (aarch64 Linux, idle host, load 0.73) and committed
  under `benchmarks/results/2026-09-20/*-dgx-aarch64.json` following the
  CoreMark platform-suffix convention. The macOS arm64 results are
  unchanged and remain on file (2026-09-14 / 2026-09-18): Docker is
  ~68% slower on the GB10 while Cell stays sub-millisecond on both
  platforms, so the advantage claim now carries stamped numbers on two
  architectures instead of a single-host figure.

- `benchmarks/competitive_benchmark.py` now derives its platform label
  from the actual host (`platform.system()`/`platform.machine()`,
  same as `coremark_wasi.py`) unless `BENCH_LABEL` pins one — the
  previous hardcoded default ("macOS-M5") could stamp a foreign platform
  onto evidence measured elsewhere.

- MCP `2026-07-28` stateless revision support in `ephemora-cell-mcp`
  (dual-era, per the specification's "Versioning and Compatibility"):
  the new mandatory `server/discover` method reports supported versions,
  capabilities and identity; requests carrying
  `_meta["io.modelcontextprotocol/protocolVersion": "2026-07-28"]` are
  served statelessly — no initialize handshake, `resultType: "complete"`
  envelope, per-response `_meta["io.modelcontextprotocol/serverInfo"]`,
  and CacheableResult fields (`ttlMs`/`cacheScope`) on `tools/list`.
  Unsupported per-request versions are rejected with
  `UnsupportedProtocolVersion` (`-32022`) naming the supported list;
  modern requests missing the required `clientCapabilities` get
  `-32602`. The `initialize` handshake keeps negotiating the legacy
  revisions only (2025-06-18 / 2025-03-26 / 2024-11-05) with unchanged
  response shapes, and this server issues no server-initiated requests
  (sampling/elicitation/roots are deprecated in 2026-07-28), so MRTR
  interim results cannot occur. Covered by
  `tests/test_mcp_2026_07_28.py`; the official-SDK interop job proves
  both eras against the reference implementation: the existing
  handshake-path test and a new stateless round-trip where MCP SDK 2.1.1
  probes `server/discover`, adopts the modern per-request stamp without
  ever sending `initialize`, and completes stateless `tools/list` +
  `tools/call` with the 2026-07-28 envelope (`resultType`, serverInfo)
  and the execution `_meta` intact
  (`integration/test_mcp_sdk_client.py`).

- Test-bench CI job (`test-bench` in ci.yml): the documented
  eight-attack-vector suite (`benchmarks/verify_8_vectors.py`, 8/8
  boundary gate) and the auto-grader verdict contract
  (`examples/auto_grader.py --strict`, new flag — exact expected
  pass/compute-budget/memory-budget mapping, exit 1 on drift) now run on
  every push and pull request on the pinned wasmtime baseline, so the
  README's 8/8 claim is continuously re-proven instead of asserted once.

- Deterministic conformance CI despite a documented engine flake:
  `conformance/adapters/cell_retry_wrapper.py` wraps the Cell CLI in the
  weekly WASI conformance job and reruns a test once when its process
  dies with SIGABRT (exit -6) — the rare wasmtime engine abort observed
  on shared ubuntu runners on varying filesystem tests (see
  `conformance/README.md`). Every other exit code passes through
  untouched; a second abort still fails. Each retry is recorded in
  `results/engine_abort_retries.jsonl` and echoed into the run's
  summary JSON under `engine_abort_retries`, so committed evidence shows
  exactly which runs needed a retry.

- EEMBC CoreMark benchmark (`benchmarks/coremark_wasi.py`, evidence
  `benchmarks/results/2026-09-19/09_coremark_wasi_*.json`): CoreMark 1.01
  built to wasm32-wasi (wasm3/wasm-coremark build.sh, wasi-sdk-34, CoreMark
  pinned at eembc/coremark `1f483d5b`) run interleaved under three
  configurations — bare wasmtime, the Cell sandbox, and the Cell sandbox
  with fuel metering on. Measured on macOS arm64 and DGX Spark GB10
  (aarch64): the sandbox reduces the CoreMark score by **8.1-10.0%**, fuel
  metering by a further **12.5-14.6%** — on the industry-standard CPU
  workload, self-validated per run, interleaved against thermal drift.
  External engine control columns (same binary, interleaved, versioned
  in the evidence): wasmer 7.4.2 scored +9.98%/+15.57% vs bare wasmtime,
  wasm3 0.9.0 (interpreter) −88.24%/−89.92% on DGX/macOS — engine choice
  spans a ~12× range; the Cell layer sits close to the bare engine.
  Binary committed under `benchmarks/workloads/coremark.wasm`.

- gVisor (runsc) boundary column — measured in CI: new job
  `gvisor-boundary` (ubuntu runner, pinned gVisor release 20260914.0 via
  apt, `runsc install` runtime registration, smoke container, probe run
  twice for determinism) executes the same eight attack intents with
  `--runtime runsc`. Expectation matrix pre-declared: 8/8 ALLOWED — gVisor
  protects the host from the container; the guest sees a Linux ABI, so
  guest primitives stay available. Positive control fails the run before
  any evidence is written. Evidence lands as run artifact; README/docs
  gain the column after the first measured run (nothing unmeasured
  claimed). Locally reproducible for anyone with runsc installed:
  `python benchmarks/gvisor_docker_probe.py`.

- Official WebAssembly core spec conformance
  (`conformance/run_core_spec.py` + weekly CI job `core-spec.yml`): the
  consolidated [WebAssembly/testsuite](https://github.com/WebAssembly/testsuite)
  (W3C Wasm 3.0 era, pinned `b464a4cd100d`, 257 files / ~36k commands)
  executed via `wast2json` against the exact engine configuration Cell
  ships, with per-file subprocess isolation and epoch-bounded commands.
  First run: **31,931 pass** — 3,282 documented deviations/limitations
  (memory64/multi-memory by design, v128 blocked by the wasmtime-py 47
  binding, relaxed-simd native upstream aborts), 684 text-format skips,
  46 binding-level NaN-bit remainder listed verbatim in the evidence
  (`conformance/results/core_spec_2026-09-19.json`). Cell now reports
  conformance against both official suites (WASI + core).

- README "vs Microsoft Wassette" positioning box: same Wasmtime engine
  family, OCI pull model moves the trust decision to install time; Cell adds
  what a caller can verify per call. Neutral framing, date-stamped pointer
  to the comparison doc.
- Weekly Linux-native Docker benchmark job
  (`.github/workflows/benchmark-linux.yml`, ubuntu runner — Docker without
  the Desktop VM; Mondays 06:00 UTC + dispatch, non-blocking, evidence as
  artifact + step summary; main stays bot-commit-free). Gives the canonical
  performance tables a measured Linux row once it has run.

- Smithery deployment manifest (`smithery.yaml`): stdio start command via
  `uvx --from ephemora-cell ephemora-cell-mcp`, optional `toolsDir` config;
  governance note included (governed loading, ADR-006).
- Daily metrics snapshots now carry conversion-context fields — `git_head_sha`
  + commit subject, latest release tag, latest PyPI version — so demand spikes
  in the public JSONL history can be attributed to the change/release that
  shipped the day before, without archaeology. Null-tolerant like every
  other source; live-tested.

### Changed

- README frames the existing CLI as the local devtools loop for agent
  tools: a new section after Quick Start walks the edit → `build` →
  `run --json` → `inspect`/`benchmark` cycle, shows failures arriving as
  graded statuses (`fuel_exhausted`, `memory_exceeded`) with receipts
  instead of a crashed terminal, and points at the auto-grader and the
  CI test-bench job as consumers of the same statuses. Documentation
  only — no code or claims beyond the already-published measurements.

- Claim wording aligned with the facts-only posture across README and the
  comparison doc: statements now describe what Cell does and what the
  measurements show (e.g. "What every Cell tool call carries", measured
  install footprints, per-response fields recorded for every candidate) —
  without comparative superlatives; quality judgments are left to the
  reader, who can reproduce every number.
- PyPI metadata: Documentation and Changelog URLs added to `[project.urls]`
  (previously only Homepage + Issues); keywords extended to match the GitHub
  topics (wasmtime, code-execution, capability-based-security, untrusted-code,
  mcp-server). Takes effect with the next upload.

- Fuel vs epoch vs wall-clock mechanism benchmark
  (`benchmarks/fuel_epoch_wall.py`, evidence
  `benchmarks/results/2026-09-18/07_fuel_epoch_wall.json`): the three ways to
  stop a WASM run, measured on overhead (10M-iter mixed loop, raw wasmtime,
  n=30: epoch +1.4%, fuel +35.2% — corroborating the cited 28–40% anchor),
  precision (overshoot at T=0.1 s, n=20: per-run epoch 5.3 ms median,
  pooled 10.0 ms, subprocess kill 53.9 ms incl. spawn/teardown) and
  determinism (fuel stop-point identical across runs; time-based stops
  jitter). Platform-bound numbers, claim-separated from the 0.376 ms
  per-call overhead. Documented in docs/performance.md.

- Per-call evidence + attack-surface audits (comparison doc §4.1/§4.2,
  measured 2026-09-18): the same call to every locally measurable candidate —
  ephemora-cell-mcp returns text content plus a full `_meta.execution`
  receipt (fuel, memory, output bytes, security baseline; sign-ready), the
  pinned reference server returns content only, docker/subprocess return
  stdout + exit code. Install footprints measured fresh: ephemora-cell = 2
  distributions (package + wasmtime), 36.2 MB; server-filesystem@2025.3.28 =
  52 package dirs / 22.2 MB node_modules (corrects the earlier "118" figure,
  which counted an unpinned install). Evidence:
  `benchmarks/results/2026-09-18/05_per_call_evidence.json` +
  `06_attack_surface_audit.json`; repro scripts
  `benchmarks/per_call_evidence.py` + `benchmarks/attack_surface_audit.py`.

- SandboxEscapeBench-18 harness rebuilt as an honest structural comparison
  (supersedes the 2026-08-25 run, which counted a trivially succeeding
  proc_exit module as "BLOCKED by design"): 8 of the 18 externally defined
  container/K8s escape scenarios are now execution-tested against the live
  boundary (preopen traversal toward /etc, sock_accept capability call,
  shared-memory engine rejection, live import-surface scan) and denied; the
  other 10 are labeled NOT-EXPRESSIBLE (no WASI counterpart exists) instead
  of a padded "blocked" count. Granted-preopen positive control, MIT
  attribution header (UK AISI + Oxford, arXiv 2603.02277), dated evidence
  output, `measured:true`. README now leads with an evidence ladder, the
  scenario provenance note, and a "what we do not compare" scope statement.
- WASI 0.2 component branch for the MCP CVE replay: the same attack intents
  (CVE-2025-53109/53110 symlink + traversal, CVE-2025-54136 governed-load
  tamper) are replayed against the ComponentSandbox boundary with prebuilt
  component probes (`benchmarks/component_probes/`, sources + rebuild.sh
  committed; CI does not rebuild). Verdicts (2026-09-18, deterministic across
  3 runs, `abi: "component"`): symlink escape blocked (EPERM), traversal
  blocked (no preopen base), governed-load tamper fails closed — and the
  audit-required **network intent is measured**: the WASI 0.2 world links
  `wasi:sockets` (unlike Preview1), a TCP connect is refused at call time
  while the granted-read control passes in the same run.
  Evidence: `benchmarks/results/2026-09-18/mcp_cve_replay_component.json`.

- Hardened-container baseline for the 8-vector security matrix: the same eight
  attack intents against `python:3.12-slim` with a declared flag set
  (`--network none --read-only --cap-drop=ALL --security-opt no-new-privileges
  --pids-limit 64 --user 65534:65534`) — measured 2026-09-18: 6/8 still allowed,
  both blocks are `--read-only` EROFS effects, not a guest-facing boundary.
  New probe `benchmarks/hardened_docker_probe.py` with pre-declared expectation
  matrix (deviations documented, never silently edited), positive control and a
  digest-pinned arm64 image (evidence: `benchmarks/results/2026-09-18/`).

### Changed

- MCP CVE replay: the component governed-load run uses its own registry state
  directory (the Preview1 class-3 run registers "widget" first; a shared
  state dir made the full-run component branch fail closed on a name
  collision — found by the first full-run after the component branch landed);
  internal plan-item reference removed from the harness header.
- Network claim corrected where it overclaimed ("no socket APIs in WASI" was
  Preview1-true but 0.2-false): README and threat model now state — Preview1:
  no socket APIs; WASI 0.2: linked, denied at call time (measured).
  `wasi_02` docstring corrected likewise (unknown imports fail at instantiate
  time; they are not defined as traps).
- Performance surfaces harmonized on the current measurement (2026-09-14, n=100
  per image, arm64): whitepaper and LinkedIn one-pager now carry 383× (was
  427× from the n=7 2026-08-30 run) with a fixed scope caveat and a citation
  of the differing academic measurement for Wasm-based container runtimes
  (Liu et al., ACM TOSEM 34(6), 2025). `docs/performance.md` states the caveat
  for every multiplier on the page. PDFs rebuilt and text-verified.
- README: the standard path shown for untrusted code is now the isolated one —
  Quick Start runs `--isolated` (in-process stays for modules you build and
  trust), and "no opt-in security" is restated precisely: enforced limits are
  never opt-in; the only choice is the process boundary. The fuel-bomb receipt
  demo runs isolated as well; CLI `--json` output is schema-identical between
  paths (verified against a fresh PyPI install).
- README security table compares stock Docker, hardened Docker and Cell with
  per-row boundary-layer attribution (Layer 1 WASI surface · Layer 2 sandbox
  policy · Layer 3 process wall) and an intent-equivalence table mapping every
  `python3 -c` probe body to its WASM guest equivalent.
- `assets/demo_attack_probe.py` writes dated evidence with image digest and
  architecture (no more hardcoded result directory).
- SECURITY.md: engine-advisory paragraph (April 2026 wasmtime advisories —
  12 advisories, two critical sandbox escapes, both aarch64-specific, fixed
  before the pinned 47.0.1) and an engine-upgrade gate: any wasmtime bump
  re-runs the security evidence suite before claims are re-attested.

## [1.0.3] - 2026-09-17

### Fixed

- Black formatting for `ephemora_cell/__init__.py` hybrid wrapper (long line split).

## [1.0.2] - 2026-09-17

### Added

- MCP Registry publication as `io.github.MichaelS1011/ephemora-cell-mcp` (`server.json`, PyPI `mcp-name` in README). Published to `registry.modelcontextprotocol.io` (1.0.2 active).
- GitHub Topics expanded 11 -> 17 (`wasmtime`, `wasi-preview1`, `wasm-sandbox`, `mcp-server`, `capability-based-security`, `code-execution`).

### Fixed

- Repeated `--allow-env` / `--allow-dirs` CLI flags no longer overwrite each
  other (argparse accumulation bug; found by the first external
  wasi-testsuite conformance run, fixed with regression tests).
- `allow_dirs` entries now support wasmtime-style `host::guest` preopen
  naming so wasi-libc-built binaries resolve relative paths against `/`;
  host-side validation and TOCTOU revalidation are unchanged.
- CLI `--no-memory64` to override `analytical` profile (`memory64=True`).
- `allow_dirs` non-existent paths now warn (`RuntimeWarning`) instead of silent skip.
- `_HybridExecutionResult` unifies `run_isolated` return type (`result.status` + `result["status"]`).
- Builder unified Rust default output to `project/<crate>.wasm` like Go/C/Zig.
- WASI preview-1 conformance harness against the official, pinned
  wasi-testsuite (`conformance/`, 72 pass / 1 documented xfail / 0 fail)
  with a weekly non-blocking CI job.
- Order-of-magnitude benchmark guard in CI (latency thresholds + fuel
  invariance within a run).

## [1.0.1] - 2026-09-11

Release metadata and MCP surface hardening. Repo-committed code is
unchanged in behavior except where listed; published to PyPI on
2026-09-11 (the 1.0.0 PyPI metadata publicly exposes a personal email
that the repository itself no longer carries — this upload replaces it).

### Added

- **Bundled `clock` MCP tool** — second tool alongside `echo`, sourced in
  `tools_src/clock` (dependency-free Rust, `wasm32-wasip1`): returns current
  UTC time (ISO-8601 + Unix ms) from the WASI real-time clock only — no
  filesystem, no network, no environment. Gives agent clients an immediately
  useful capability the model itself lacks (current time), with every call
  fuel-metered and reported via `_meta.execution`.
- **Native `get-policy` meta tool** — read-only: reports the effective
  sandbox policy per tool or for the whole registry (fuel budget, memory
  limit, threads, preopens as configured, network policy, wasmtime
  version), derived from the same `_config_for()` path execution uses, so
  reported policy and enforced policy cannot drift. Capability changes
  remain host decisions (ADR-006); policy reads are tools, policy writes
  are not.
- **`code --add-mcp` one-liner** for GitHub Copilot in VS Code (README +
  docs/mcp.md VS Code section); bundled-tools line updated to `clock + echo`.
- **Wassette row** in the MCP comparison latency table (qualitative, sourced,
  not measured): same Wasmtime engine family, per-component permission grants,
  OCI component distribution — with the Cell differentiators stated
  (per-call fuel metering, execution witness, CI-verified SDK interop).
- **ADR-006** (governed dynamic tool loading: request-file +
  verify-before-register; no agent-callable permission grants) and
  **ADR-007** (browser interaction is out of scope by design; mediated
  capability via host sidecar) recorded as decision documents.
- **Daily metrics snapshot workflow** (`metrics.yml` +
  `scripts/metrics_snapshot.py`): PyPI downloads (pypistats, one call/day
  per etiquette), GitHub stars/forks/traffic appended as JSONL to the
  `metrics` branch. Public distribution channels only — no in-package
  telemetry; Cell never phones home.
- **MCP SDK interop CI gate** (`mcp-sdk-interop` job): the shipped stdio
  server is verified in CI against the official MCP Python SDK 2.0 —
  initialize, `tools/list`, and a real `tools/call` with execution
  `_meta` (`integration/test_mcp_sdk_client.py`, new `integration` extra).

### Changed

- **Release metadata**: version 1.0.0 → 1.0.1 (`ephemora_cell`,
  `ephemora_cell_mcp` — the MCP server version now shares the package
  version via `ephemora_cell_mcp/_version.py`), classifier
  "Development Status :: 4 - Beta" → "5 - Production/Stable", README
  status badge → stable, plus PyPI downloads and stars badges. The git
  identity for project commits is now the GitHub noreply address.

### Test coverage

- Statement coverage 74% → 85% measured over `ephemora_cell` +
  `ephemora_cell_mcp` (`--cov-fail-under` gate 70 → 80; 84.55% measured):
  new in-process characterization tests for `cli.py` (17% → 86%) and
  `process_worker.py` (30% → 81%) — payload validation at the worker
  trust boundary, run/inspect/build/benchmark command paths, previously
  only exercised via subprocesses invisible to coverage. Coverage now
  counts the shipped `ephemora_cell_mcp` package, which was previously
  measured at 0% despite being installed and documented.

### Fixed (15-user field study findings, 2026-09-05)

- **Fuel classification (code):** an out-of-fuel trap firing inside a host
  function or during `linker.instantiate` surfaced as generic ERROR;
  it now classifies as `FUEL_EXHAUSTED` (regression test added).
- **`run_isolated()` return contract** documented (dict with
  `status`/`exit_code`/`stdout`/`stderr`/`fuel_consumed`/`security_baseline`/
  io counters) with a usage example in SECURITY.md; README links to it.
- **macOS `allow_dirs` trap** documented: `/tmp`/`/var` are symlinks into
  blocked `/private` — the rejection is the symlink-escape defense working;
  use a real directory (recipes.md).
- **`build` README line** aligned with builder reality: a cargo project
  context is required for Rust; bare files get guidance.
- **Zig build failures** now hint at version skew (CI verifies with zig
  0.13.0; newer zig can fail differently) before pointing at the raw error.
- **`--tools-dir` semantics** documented: it replaces the bundled
  `clock`/`echo` set entirely.

### Fixed (repository-wide audit, 2026-09-05)

- **Privacy:** redacted the local home-directory prefix from captured stdout
  in `benchmarks/pocs/componentize_poc/results.json` and rewrote the
  cross-platform results note that named a user path.
- **English-only surface:** translated the remaining German text in
  `tests/test_security.py` (incl. assert messages), the result artifacts
  `13_sandbox_escape_18.json` / `cross-platform-results.json` /
  `scale-results.json`, and the scripts `setup_firecracker.sh`,
  `sandbox_escape_18.py`, `security_comparison.py`, `pov_benchmark.py`.
- **Package license:** `ephemora_cell/LICENSE` contained a stray 9-line
  source-header fragment instead of a license; replaced with the canonical
  Apache-2.0 text (identical to the root `LICENSE`).
- **Claim precision:** "signed execution records" softened to
  "sign-ready" (RFC 8785 JCS canonicalization + `sign()`/`verify()`
  primitives ship; records are not signed by default) across README,
  threat-model, enterprise page and MCP docs.
- **Evidence alignment:** `benchmarks/BENCHMARK_RESULTS.md` relabelled as the
  historical 2026-08-06 baseline (raw JSONs not retained; tracked agentic
  JSONs are the 2026-08-25 cell-side re-runs) and the dead
  `agentic-full-results.json` pointer removed; `build_friction` re-measured
  (0.4 s warm, new committed evidence `results_2026-09-05.json`; earlier
  snapshots explained); io_dos pre-fix attack figures labelled as
  single-run historical context with untracked raws; DGX hardware figures
  aligned with the recorded measurement (20 cores / 121 GiB); GC-PoC and
  componentize figures aligned with their tracked JSONs; cost-density
  figures marked as uncommitted order-of-magnitude.
- **Drift & hygiene:** whitepaper test count 379 → 386 (PDF re-rendered);
  stale "347 tests" and unevidenced "17/17 acceptance scenarios" removed;
  MCP protocol table de-pinned from a hardcoded version; broken README
  anchor and dead artifact references (`cross-platform-m11.json`,
  `scale-d14.json`, `scale_probe.py`) fixed; the empty `11_pip_freeze.txt`
  artifact and the byte-identical `competitive-firecracker-macos.json`
  duplicate removed; internal milestone/CI-run references in test
  docstrings replaced with descriptive text; `test_wvm_wasm_runtime.py`
  renamed to `test_wasm_runtime.py`; personal Ollama model list de-personalized;
  wrong AutoGen install hint corrected.

## [1.0.0] - 2026-08-30

**First public release** — first version published to PyPI. Internally
developed across August 2026 (internal milestones 1.0.0 → 2.2.0, referenced
in some docs); public versioning starts at 1.0.0.

### I/O-DoS hardening

**Fixed (security)**

- **Fuel meters guest compute, not host work — unmetered host I/O
  closed (High, CWE-770 / CWE-400):** measured inventory
  (`benchmarks/io_dos/`): a real file write costs 7.3 fuel at 5.8 µs
  host time; a stat costs 3 fuel at 9.7 µs; with `max_fuel=None` a
  guest sustained 172k–233k host syscalls/s per run, repeatable
  without bound, and zero-byte attacks (stat/open churn) defeat every
  byte-based wall. Two new first-class `WASIConfig` budgets enforce
  per-run limits (ADR-002):
  - **`io_cpu_seconds`** (default 2.0): worker-side rusage watchdog —
    bounds ALL guest-induced host work (writes, stat/open churn),
    interrupts the guest via epoch; breaks attacks at the budget, not
    at the host (re-run of the attack harness: 10–11 s floods now end
    at ~2 s, canary jitter degradation 1.18× → 1.05×).
  - **`io_budget_bytes`** (default 64 MiB): aggregate byte wall for the
    guest sandbox dir, enforced in BOTH paths by a watcher; breach ends
    the run with a dedicated "I/O budget exceeded" error.
- Both knobs accept `None` (documented trusted capability, like
  `max_fuel=None`); in-process runs remain documented-trusted for the
  CPU wall (rusage would measure the host process).
- Auditability: reports now carry `io_cpu_used_seconds`,
  `io_bytes_written`, `io_budget_exceeded`.

**Changed**

- WASI 0.2 components honor the CPU wall (same epoch-interrupt
  mechanism); budget-guarded runs use a per-run engine (deadline=1
  semantics — `set_epoch_deadline` from a watcher thread does not
  affect a running guest; verified experimentally).
- **Egress decision (ADR-002):** host-mediated proxy model with
  allowlist; WASI 0.3 sockets not exposed until stable in wasmtime-py;
  free-egress profile tier rejected (breaks deny-by-default). User-
  facing pattern: host-sidecar (`docs/egress_patterns.md`).

### Build pipeline

**Added**

- **`ephemora-cell build <source>` (ADR-005):** one-command WASM builds —
  recipe detection per file suffix with real toolchain builds for Rust
  (`cargo build --target wasm32-wasip1`, manifest searched upward like
  cargo) and Go (`GOOS=wasip1 GOARCH=wasm`), and fail-closed actionable
  guidance for C (WASI-SDK required — Apple clang has no wasm32 target,
  measured) and Python (no AOT-to-WASM exists; wasi-python interpreter
  guidance). Failed builds map verbatim toolchain errors to hints from
  the measured friction matrix (`benchmarks/build_friction/`: missing
  toolchains, missing rust target, missing wasi-sysroot, wrong
  GOOS/GOARCH). Registry deferred (YAGNI) with rationale in the ADR.
- Measured: Rust hello-world → .wasm in 2.9 s and executed in the cell;
  Go recipe exercised in CI (new `build-recipes` job installing Go +
  the rust WASM target).

### Named state

**Added**

- **Named state across isolated runs (ADR-004):** `ephemora_cell.state.StateStore`
  — a host-side, session-scoped, bounded key/value store. Passing it into
  `WASISandbox.run(..., state_store=store)` IS the capability grant: the guest
  imports `ephemora_state.get/set/del` (fail-closed — without the grant the
  imports do not exist). Caps are host-enforced (256 KiB per value, 1 MiB
  total, 64 entries; breach returns a WASI-style errno to the guest, including
  required-length reporting for undersized read buffers). The run result
  attests the footprint via `state_bytes`. Nothing persists to disk; two
  stores never share keys (leakage test included).
- Measured basis (`benchmarks/state_overhead/`): filesystem state costs only
  ~0.3 ms/run — the gap is semantics (no caps, no session namespace), which
  the StateStore closes.
- Demo: three consecutive isolated runs passing a counter through
  the state imports (get → +1 → set) — green.

### Analytical profile

**Added**

- **`analytical` profile (ADR-003, opt-in):** for data-analysis workloads
  beyond the 128 MB wall — 64-bit memories (`memory64=True`), 4.5 GiB
  linear memory, 50 M fuel, 120 s timeout, 10 s host-I/O CPU budget.
  Threads deliberately remain off (phase 1 of the planned thread rollout); no ambient
  FS/env grants; all isolation budgets (disk quota, I/O
  walls) stay active. Engine-pool fingerprint separates analytical
  engines automatically.
- Measured basis (`benchmarks/analytical_breakpoint/`): the memory wall
  is enforced byte-exactly at the cap (over-cap growth refused in ~2 ms
  across 32–256 MiB caps), and a 64-bit-memory guest grew past the
  32-bit 4 GiB boundary under the 4.5 GiB cap (708 ms) — the mechanism
  proof behind the profile. numpy/pandas wheels for wasm32-wasip1 are
  unpublished; dataframe workloads wait for a wasi-python recipe
  (documented as literature, `measured:false`).

### Egress patterns

**Added**

- **Egress pattern documentation** (`docs/egress_patterns.md`): catalog of
  six community workarounds for "sandboxed tool calls an API" with
  isolation/audit/budget assessments (filesystem tunneling, stdio RPC,
  sidecar proxies, runtime forks, config softening, host-agent abuse),
  plus the full specification of the recommended **P1 host-sidecar
  pattern** and the WASI 0.3 outlook (P2). Decision basis: ADR-002.
- **Host-sidecar egress mediator** (`ephemora_cell.egress_sidecar`,
  dependency-free): guest writes `sidecar.request.json` into its
  sandbox dir; the host validates it against an `EgressPolicy`
  (scheme+host+path-prefix allowlist, method allowlist, header
  allowlist, response size cap, timeout) — fail-closed, request
  artifacts are untrusted input, credentials stay host-side — executes
  the call and returns a machine-readable response doc plus an audit
  entry for the execution report. End-to-end test: a real preview1 WASM
  guest produces the artifact in `/sandbox`, the host mediates against
  a local API (loopback); policy/parse/allowlist denial paths covered.

### Release preparation

**Changed**

- **SECURITY.md** brought up to date: supported-version table reflects
  2.2.x; documents the per-file semantics of the new disk quota, the
  grant-time TOCTOU revalidation (and its boundary), and WASI 0.2
  component execution in scope/design sections.
- **SUPPORT.md** added (channels, report checklist, supported platforms,
  release cadence).

**Verified (release readiness — publishing is a maintainer decision)**

- `python -m build` produces sdist + wheel; `twine check` passes for both.
- Wheel contains the MCP `echo.wasm` tool fixture and package metadata.

**Decisions**

- **ADR-001 (docs/decisions/):** Compute (NN/GPU inference) is out of Cell scope —
  Cell commits only to the generic opt-in host-import mechanism (emerging via the
  I/O-budget and State work). Cell compute claims are limited to existing measured
  CPU benchmarks.

### CI

**Fixed**

- **Coverage measured nothing** — `pyproject.toml` pytest addopts pointed
  at the misspelled `--cov=ephemera_cell`; every "70 % coverage" claim ran
  on an empty measurement. Corrected to `ephemora_cell` and the CI
  coverage job now passes `--cov=ephemora_cell` explicitly with a hard
  `--cov-fail-under=70` gate (current coverage: 74 %).
- **Integration tests could not fail CI** — both integration steps ran
  with `continue-on-error: true`; regressions were silently green.
  Removed.
- **Benchmark used an unpinned wasmtime** — `pip install wasmtime` made
  Firecracker-benchmark results non-comparable across runs; pinned to the
  tested 47.0.1. The benchmark workflow also now only triggers on `main`.

**Added**

- pip dependency caching in all CI jobs.
- SBOM is generated from the installed environment metadata
  (`cyclonedx-py environment`), reflecting the true dependency tree
  including the package itself, instead of parsing `requirements.txt`.

### MCP server hardening

**Fixed (security)**

- **One bad call could kill the server** — an unhandled exception inside a
  request handler propagated out of the stdio loop and terminated the
  process. Handlers are now wrapped: unexpected failures answer JSON-RPC
  `-32603` and the loop continues; `BrokenPipeError` on send shuts down
  cleanly when the client disconnects.
- **JSON-RPC request validation** — `jsonrpc` must be `"2.0"` and `id`
  must be string/number/null; violations answer `-32600` (structurally
  invalid) instead of being lumped in with `-32700` (unparseable JSON),
  which is now correctly reserved for malformed JSON.
- **Sidecar could widen permissions** — a sidecar `allow_dirs` entry
  REPLACED the profile's grants; it is now intersected with the profile,
  so a sidecar can narrow but never widen filesystem access. Non-empty
  grants are logged for auditability.
- **Advertised tool name could differ from callable name** — a sidecar
  `name` was advertised via `tools/list` while `tools/call` resolved by
  file stem. The stem is now the enforced identity; mismatching sidecar
  names are overridden with a warning, and duplicate tool definitions
  raise at scan time.
- **Transport line limit** — lines beyond 10 MB are rejected with a
  JSON-RPC error instead of being read into memory unbounded.
- **`protocolVersion` negotiation** — `initialize` echoes a supported
  client-requested version and falls back to the server's own.

**Added**

- Fuzz gate: 100 random/malformed JSON-RPC lines per run must all be
  answered specification-conform, with the server serving valid requests
  afterwards (regression test `test_fuzz_100_malformed_lines_survive`).

### Correctness

**Fixed**

- **WASI 0.2 epoch traps were misclassified as ERROR** — the component
  sandbox only recognized `"interrupt"` as a timeout message; wasmtime
  reports `"epoch deadline reached"`. Epoch traps now classify as
  TIMEOUT (mirroring the preview1 sandbox).
- **`ComponentSandbox.run` UnboundLocalError on early failure** — the
  `except (Trap, WasmtimeError)` handler referenced `store` and
  `timeout_event` before assignment when a component failed to parse;
  both are now pre-bound and the epoch timer is stopped on exit.
- **`fuel_utilization` semantics** — division by a zero budget no longer
  raises (0/0 → 0.0, >0/0 → 1.0), a genuine 0.0 utilization is no longer
  falsified to `None` in `to_dict`, and utilization is clamped to 1.0.
- **Sandbox dir leaks on repeated `run()`** — calling `run()` twice on
  one sandbox instance leaked one sandbox/host dir pair per call; the
  previous run's dirs are now removed before creating new ones (skipped
  when the module lives inside them).
- **`run_wasm` returned a deleted `sandbox_dir` path** — the result now
  reports `sandbox_dir=None` after the internal cleanup.
- **Output budget is byte-based everywhere** — the in-memory truncation
  counted characters while the fd_write sink counted UTF-8 bytes; both
  now enforce the same 10 KB byte budget, and the redundant double
  truncation (`_limit_output(_read_capped_output(...))`) was removed.
- **`exceptions.py` deleted** — the seven exception classes were exported
  but never raised anywhere (including a `TimeoutError` that shadowed the
  builtin); failures are reported via `ExecutionResult.status`.
- Lint: `ruff check` is now clean (0 errors) across package, MCP package,
  and tests.

### Security hardening

**Fixed (security)**

- **Guest run payload leaked via worker argv (High, CWE-200):**
  `run_isolated` passed the full WASIConfig — including `allow_env` secret
  values, guest argv, and stdin data — as `--config <json>` on the worker
  command line, readable by any local user via `ps`/`/proc/<pid>/cmdline`
  for the whole run duration. The payload now travels as JSON over the
  worker's stdin pipe (`--payload-stdin`); argv carries only non-sensitive
  parameters (wasm path, size cap, ABI). Regression tests assert argv
  cleanliness and run a live `ps` poll with a positive control.
- **Engine-pool epoch crossfire / false timeouts (High, CWE-362):**
  `config_fingerprint` included `timeout_seconds`, sharding the pool per
  timeout value, and each run incremented the shared engine's epoch on its
  own timer — a slow run's timer fired the epoch deadline of every
  concurrent run sharing that engine, producing spurious TIMEOUT results.
  The pool now runs one daemon ticker per engine (50 ms tick); each store
  sets its own epoch deadline from its config timeout; the fingerprint no
  longer includes `timeout_seconds`; a refcount lease keeps live engines
  from LRU eviction mid-run. Regression test: concurrent fast+slow runs on
  a shared engine both succeed.
- **TOCTOU — preopen path swap between validation and grant (High,
  CWE-367):** `allow_dirs` entries were realpath-validated at config time
  only; a path swapped to a symlink into a forbidden location before the
  preopen grant was still mounted. Each entry is now re-resolved
  immediately before `preopen_dir` and skipped with a warning on mismatch.
- **Security baseline attested configured, not effective, preopens
  (Medium, CWE-757):** `security_baseline.preopens` listed the configured
  `allow_dirs` plus an unconditional `/sandbox`, even for entries filtered
  out, never-existent, or for component runs (which get no `/sandbox`).
  `ExecutionResult` now carries `effective_preopens` (post-filter, per
  ABI); `apply_config(config, effective_preopens=...)` attests exactly
  what was granted; config-only baselines no longer claim grants.

**Added**

- **Disk quota for guest file writes (Medium, CWE-400):** new
  `WASIConfig.disk_quota_bytes` (default 256 MiB, `None` = unlimited) is
  enforced in the subprocess isolation path via `RLIMIT_FSIZE` with
  `SIGXFSZ` ignored — an over-quota guest write fails with EFBIG (WASI
  errno 22) instead of filling host disk. Kernel semantics make the cap
  per-file; documented as such. Regression test: guest write flood capped
  exactly at the quota with EFBIG, positive control writes through.
- Worker is launched via a direct `-c` import instead of `python -m`
  (runpy module resolution is unreliable for editable installs on some
  hosts); `effective_preopens` is part of the worker report contract.

### Benchmarks

- **Docker comparison re-measured live (2026-08-30, Mac M5, Docker 28.5.1):**
  `docker run --rm python:3.12-slim` 170.6 ms / node:24-alpine 167.8 ms vs
  Cell 0.400 ms cold / 0.376 ms warm = **427×/454×** (n=7 per image, warmup
  pull excluded). Evidence committed:
  `benchmarks/results/2026-08-30/competitive_benchmark.json`
  (`docker_measured:true`); README and `docs/performance.md` now quote the
  reproducible live number — the 191× figure stays labeled as the 2026-08-06
  historical reference.

- **Enterprise page (IP-neutral):** new `docs/enterprise.md` — when Cell is
  enough, the operational questions an enterprise conversation answers, and
  contact channels (LinkedIn for enterprise inquiries, GitHub for OSS).
  Linked from the README "Relationship to Ephemora" paragraph. No feature
  claims, no SLAs, no roadmap details. GitHub Discussions enabled (was
  promised in SUPPORT.md but disabled).

### Documentation

- **Visual assets:** adaptive hero diagram (`assets/hero-light/dark.svg`,
  GitHub light/dark via `<picture>`, regenerated deterministically by
  `assets/make_hero.py`) and a terminal demo GIF (`assets/demo.gif`, 40 KB,
  generated by `assets/make_gif.py` from verbatim real-run outputs —
  install, first run, `--json` report, attack module blocked).
- **Threat model published (`docs/threat-model.md`):** consolidated
  adversary model (the guest is the adversary), protected assets, trust
  boundaries with their enforcement points, and documented residual risks —
  referencing the control matrix and measured evaluations instead of
  duplicating numbers. Linked from README and SECURITY.md.
- **`--version` flag for the CLI** (`ephemora-cell --version`), matching
  the MCP server and the `__version__` attribute SUPPORT.md documents.
- **Architecture diagram modernized:** ASCII box art in the README replaced
  with a native Mermaid flowchart (GitHub renders it inline; syntax
  validated with mermaid-cli) — same content parity (enforcement knobs,
  WASI Preview1 syscall surface, blocked-by-design list), diffable and
  mobile-readable.
- **First-run UX fixes from a fresh-clone user test:** CLI stderr now
  always ends with a newline (host diagnostics like "WASM module not
  found" and fuel traps no longer glue onto the shell prompt — stdout
  stays verbatim for programmatic use); successful `build` prints a
  copy-paste `run it: ephemora-cell run …` hint next to the output path;
  the stale `build` help/error texts now list all five real recipes
  (.rs/.go/.c/.ts/.zig, guidance: .py). Regression tests added.
- **CONTRIBUTING:** documented the `benchmarks/results/<date>/`
  convention — commit dated evidence dirs that back a claim, delete
  throwaway runs (no blanket gitignore, evidence culture preserved).
- **README restructured for GitHub-first reading** (~35 KB / 623 lines →
  ~15 KB / 241 lines): short hero + Quick Start, 8 feature bullets,
  single performance and security tables; detail moved instead of
  deleted — execution-path control matrix → SECURITY.md, arXiv
  2509.11242 evaluation + fuel boundary + related research →
  `docs/security_posture.md`, FastAPI + serverless/air-gapped/component
  recipes → `docs/recipes.md`, interpreter guidance + Preview1
  limitations → `docs/languages.md`. Marketing duplication (Why Now /
  Why Enterprises Switch) removed; measured facts retained in
  Performance/Security.
- **Docker 191× figure caveated** in `docs/performance.md`: historical
  2026-08-06 measurement, no committed `docker_measured: true` JSON —
  treated as order-of-magnitude indicator, not a verified claim
  (`benchmarks/competitive_benchmark.py` measures Docker live per run).

### Earlier internal development (2026-08-04 → 2026-08-26)

Pre-public milestones (internal labels 1.0.0 → 2.2.0) established the
sandbox core, WASI 0.2 component support, execution records (RFC 8785),
the MCP server, the control matrix (in-process vs subprocess), profiles,
named state and the first security hardening passes. Their detailed
entries live in the pre-public development history and are summarized in
[README.md](README.md) and [SECURITY.md](SECURITY.md).
