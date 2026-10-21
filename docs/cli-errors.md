# CLI error contract

Every `ephemora` command leaves a process status, and `run --json` names the same
verdict in its document as `error_class`. The other commands carry their own
machine-readable verdicts — `doctor` reports per-check `ok`/`warn`/`fail`,
`verify` distinguishes verified from unverifiable, `policy check` answers whether
the configuration would run — and none of them stamps a refusal as a success. A
caller that branches without reading prose gets five classes from the status.
Each class names **who decided the failure**, which is what a caller branches on.

| Status | `error_class` | Who decided | What it means |
| --- | --- | --- | --- |
| `0` | `none` | — | the operation succeeded |
| `1` | `execution` | the sandbox | a run was attempted and the sandbox reported a failure: a trap, a timeout, a fuel/memory/byte stop, a non-zero guest exit, a module the loader rejected |
| `2` | `caller` | the CLI, before the sandbox | the call cannot be honoured as stated, so nothing was executed: a flag whose value the adapter would discard, `--tenant` without `--tenant-book` (or a `--tenant-book`/`--tenant-max-*` without `--tenant`), an `--abi` that contradicts the language adapter, a malformed `--allow-env` value, an unreadable `--stdin` file |
| `3` | `attestation` | the verifier | the evidence cannot be checked the way it reads: `verify` of a signed artefact run without the key that would prove authorship — "not verifiable here", never "verified" |
| `4` | `environment` | the gate | this machine is not the audited execution configuration: the Wasmtime engine is missing or outside the qualified line, or the guest a language run needs is not installed / not the pinned artefact |

```json
{ "status": "error", "error_class": "environment", … }
```

## One caveat a status-only reader must know

When a guest actually ran, its own exit number travels in the process status —
that is what `exit_status_fidelity: exact` means, and it is deliberate: `run
module.wasm` leaving a Preview1 guest's `3` is the behaviour a shell script
expects. Such a number is **not** a class. So a bare `2`, `3` or `4` from `run`
can be either a class the CLI took or a guest that deliberately exited with that
number. The two are never confused by the document, which is the authoritative
form for an agent:

```sh
ephemora run guest.wasm --json | jq -r .error_class   # execution | environment | none
```

`caller` is deliberately absent from that list: a call the CLI refuses before the
sandbox exists prints its reason on stderr and emits **no document** — there was
no run to describe. Branch on the status for that class, and treat an absent
document plus a non-zero status as a refusal, never as an empty success.

What the classes guarantee unconditionally: a refusal, a crash or an unverified
artefact never leaves status `0`, and no class is ever reported as a success.

## `environment`: the runtime is a precondition, not a label

The release is qualified against one controlled Wasmtime line
(`wasmtime>=49.0.3,<50`). Guest code does not run on an engine outside it on any
execution route the package offers — the CLI, the `WASISandbox.run` facade,
`run_isolated` at its spawn point, and the low-level `ComponentSandbox` primitive
each make that decision before a byte is read, compiled or billed — because the
unpatched public build is not the configuration the security work was done
against: a build that merely shares the version prefix, or metadata that names a
version the interpreter cannot import, is not the audited artifact either.
`ephemora doctor` names the loaded engine and its digest instead of
hiding it.

An operator who knowingly runs elsewhere — during development, or on a platform
without a qualified wheel — says so out loud:

```sh
EPHEMORA_ALLOW_UNQUALIFIED_RUNTIME=1 ephemora run guest.wasm
```

That is an explicit opt-out, never a silent fallback. It prints a `note:` on
stderr and stamps `"unqualified_runtime_allowed": true` into the JSON document, so
a recorded run can always be told apart from a qualified one.

A refusal writes nothing to the sandbox, spawns no worker, compiles no module and
bills no tenant.

## `exit_status_fidelity`: how much of the guest's own exit reached us

| Value | Meaning |
| --- | --- |
| `exact` | the guest's own exit number reached the host (Preview1 `proc_exit`, or a language run on a guest whose ABI carries it) |
| `non_zero_only` | the guest left, but its ABI carries only the fact of a non-zero exit (WASI-0.2 `wasi:cli/exit`: `exit(3)` and `exit(7)` both arrive as `1`) |
| `none` | no guest exit status reached the host at all — a language guest whose loader swallows `SystemExit`, a run the host stopped (fuel, timeout, byte budget), a load rejected before the guest started, a refused environment |

`none` is the answer whenever nothing left the guest, so the field never attests
a channel nothing travelled through. The CLI invents no number the channel did
not deliver and never reports a run it did not perform. Per-route measurements
are in [`languages.md`](languages.md).

The claim is part of the record, not decoration on one command: one function
(`execution_report.exit_status_fidelity`, reading `abi` and the raw
`guest_exit_observed` fact) fills the CLI document, the signed execution record
(so it sits inside the JCS payload the signature covers — rewriting `"none"` to
`"exact"` breaks verification) and the MCP `_meta.execution` an agent reads. Where
a route's own measurement already decides the word, that route names it instead of
deriving it, and exactly two do: the Python source run through the component guest's
loader and the JavaScript source run through the QuickJS harness. On both, the guest
may leave through its exit interface while the status of the script the caller
handed over is discarded — and this field describes the caller's program, not the
guest's bookkeeping. A report built without the field stays byte-identical to
earlier records, so nothing about an existing artefact changes.

## Refusal documents

An environment refusal is one small, schema-tagged document rather than a partial
run report, because there is no run to describe:

```json
{
  "schema": "ephemora-cell/run-refusal/1",
  "status": "error",
  "error_class": "environment",
  "exit_status_fidelity": "none",
  "runtime_qualification": "wasmtime 49.0.0 is outside the controlled line — …"
}
```

## Reading the classes as an integrator

* Treat `0` as success and everything else as failure — never as "no output".
* `2` and `4` are not retryable by changing the guest: they are about the call and
  about the machine.
* `1` says the sandbox did its job and reported a failure; the receipt in `status`,
  `exit_code` and `exit_status_fidelity` says what was actually observed.
* `3` says the artefact may be fine but the claim was not verifiable as asked.
* `policy check` and `doctor` report their verdict as `1` with the reason in the
  document; their `--json` payloads (`ephemora-cell/policy-check/1`,
  `ephemora-cell/doctor/1`) carry the per-check detail.
