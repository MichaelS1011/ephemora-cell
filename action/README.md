# Sandboxed WASM execution for GitHub Actions

A composite action that runs one `.wasm` module inside the Ephemora-cell
sandbox and hands the workflow machine-readable outputs: fuel metering, memory
cap, wall-clock timeout, I/O walls, deny-by-default preopens, and — for modules
you did not build — an OS-level process wall around a disposable worker.

It exists for one situation: **your workflow has to execute code that a pull
request, an agent, or a third party supplied.** The step either succeeds or
returns a graded status; a module that burns its budget or trips the memory cap
cannot take the runner with it.

## Usage

```yaml
- id: run-tool
  uses: MichaelS1011/ephemora-cell/action@v1.1.0   # pin a release tag, not a branch
  with:
    module: path/to/module.wasm   # relative to the workspace, required
    profile: llm                  # plugin | llm | edge | default | analytical
    fuel: 500000                  # override the profile's guest-CPU budget
    args: --input data.json       # space-separated guest arguments
    allow-dirs: ''                # space-separated preopens — grants full read/write
    isolated: 'true'              # default; see below
  # outputs: status, exit_code, fuel_consumed, elapsed_ms

- run: echo "status=${{ steps.run-tool.outputs.status }} fuel=${{ steps.run-tool.outputs.fuel_consumed }}"
```

Pin a **release tag** (`@v1.1.0`) rather than `@main`: a tag is what you can
trace to a signed release, and a mutable branch ref is what a compromised
repository would rewrite. This repo's own demo workflow uses `./action` from
the checked-out tree, which is the same code the tag points at.

## Inputs

| Input | Default | What it does |
|---|---|---|
| `module` | — (required) | Path to the `.wasm` module, relative to the workspace |
| `args` | `''` | Arguments for the guest. Space-separated; word splitting applies |
| `profile` | `default` | Budget preset: `plugin`, `llm`, `edge`, `default`, `analytical` |
| `fuel` | profile | Guest-CPU budget in fuel units |
| `memory-mb` | profile | Linear-memory cap in MiB |
| `timeout` | profile | Wall-clock timeout in seconds (epoch interruption) |
| `allow-dirs` | `''` | Directories preopened for the guest. **Read/write, so use sparingly** — the default is no filesystem at all |
| `isolated` | `'true'` | Run in a disposable worker subprocess with OS-level rlimits and a hard kill |
| `fail-on` | `non-success` | `non-success` fails the step on any status other than `success`; `never` reports the status and leaves the step green |
| `package-version` | latest | `ephemora-cell` version to install from PyPI |

## Outputs

| Output | Values |
|---|---|
| `status` | `success` \| `error` \| `timeout` \| `fuel_exhausted` \| `memory_exceeded` |
| `exit_code` | the guest's exit code |
| `fuel_consumed` | fuel units used (`null` when unmetered) |
| `elapsed_ms` | wall time of the run |

`elapsed_ms` is a runner number, not a benchmark number — shared CI hardware
makes it noisy. `fuel_consumed` is deterministic on a given host architecture
and is the value worth gating on.

## What `isolated` changes

With `isolated: 'true'` (the default) the module runs in a separate worker
process under OS-level limits: `RLIMIT_NOFILE`/`RLIMIT_AS`/`RLIMIT_FSIZE`, the
disk-quota wall, and a hard kill when the wall-clock deadline fires. With
`isolated: 'false'` the guest runs in the CLI's own process; fuel, memory,
wall-clock and output caps still apply, but the kernel-level walls do not —
they would limit the runner's own process, not the guest. The full
per-control matrix is the execution-path table in
[SECURITY.md](../SECURITY.md#execution-paths--which-control-runs-where).

For anything you did not build — PR-contributed modules, agent output,
third-party plugins — leave `isolated` on.

## Failure semantics, precisely

- The CLI writes its JSON report to **stdout**, so guest stdout is not the
  report channel. Guest stderr is surfaced in a `::group::` block in the step
  log.
- If the CLI exits non-zero **and** produced no parseable report, the action
  emits `::error::` and fails — that is an install/usage failure, not a sandbox
  verdict, and it should not read as one.
- `fail-on: non-success` (default) fails the step when `status != success`.
  A `fuel_exhausted` run therefore turns the workflow red — which is what you
  want when a module is supposed to finish, and what you override with
  `continue-on-error: true` when the *refusal* is the thing under test.

## How this repo tests it

[`.github/workflows/action-demo.yml`](../.github/workflows/action-demo.yml)
runs on every push, with two jobs and **two different modules** — deliberately,
because fuel costs are not cross-platform deterministic and one module cannot
be both proofs:

| Job | Module | Assertion |
|---|---|---|
| `smoke` (ubuntu-latest + macos-latest) | `examples/hello.wasm`, `profile: llm` | `status == success` — the action runs a benign module and accounts it |
| `enforcement` (ubuntu-latest) | `examples/fuel_bomb.wasm`, `profile: llm`, `fuel: 100` | the step **fails**, `status == fuel_exhausted`, `fuel_consumed == 100` — the sandbox stopped it and accounted every unit |

`hello.wasm` cannot serve as the enforcement case: it burns 16 397 fuel units
on macOS arm64 and 12 on Linux x86_64, so a 100-unit budget stops it on one
platform and not the other. `fuel_bomb.wasm` is an infinite loop, so it
exhausts any budget on any platform, which is what makes the assertion stable.

## See also

- [README.md](../README.md) — the library, the CLI, the MCP server
- [SECURITY.md](../SECURITY.md) — what each control enforces and what it
  explicitly does not
- [docs/recipes.md](../docs/recipes.md) — CI gating, FastAPI, serverless,
  air-gapped validation
- [LICENSE](../LICENSE) — BUSL-1.1, no warranty. The Action enforces the limits
  this file documents and is provided on an "AS IS" basis.
