# Release assurance — what was measured, in which installation state

Moved out of the README on 2026-10-05. The README states the release gate in one
sentence; this file carries the numbers with their conditions, because the same
commit produces different counts depending on how it was installed and what the
host is doing. **A number without its conditions is not a measurement** — that is
the reason this page exists.

## The release gate, as measured on a fresh clone of the release commit

v1.1.0 (`75b7bc2`, signed tag, PyPI 1.1.0): **957 passed / 4 skipped**
(961 collected) · **89.98 %** statement coverage, shown as 90 % (Cell + MCP, CI
gate ≥ 80 %) · 8/8 attack vectors blocked (default posture, WASI Preview1 path) ·
72-pass official wasi-testsuite conformance (pinned, 0 fail) · `pip-audit` clean
against the pinned `wasmtime==47.0.1` · statelessness probe at 0 leaks on the
three execution paths it sweeps (engine pool, per-run engine, isolated
subprocess — the MCP stdio path is not part of that probe) · wheel-only
smoke against the installed artifact (48/48 checks, result recorded in the v1.1.0
GitHub release body) · sdist clean-room container run. CI-enforced on every push:
tests, coverage, pip-audit, SBOM, bandit, official MCP SDK interop
([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)).

The pass counts below are **not** the suite weakening. Three figures describe three
installation states.

## Three installation states, three honest numbers

| Installation state | Result | Why it differs |
|---|---|---|
| Checkout with `requirements.txt` + the `tools-signing` extra (`cryptography>=42`) — the environment CI uses on both legs | **957 passed / 4 skipped** (961 collected), 89.98 % | every Ed25519 path runs |
| Checkout **without** `cryptography` | **850 passed / 66 skipped** (916 collected), 81 % | 62 skips are `importorskip("cryptography")` paths — signed tool manifests, governed loading, signed receipts, grant authentication. 61 are individual tests plus one module-level skip of `tests/test_grant_trust.py`, whose 46 tests leave the collection and are replaced by that one skip entry (961 − 46 + 1 = 916) |
| Unpacked **sdist** in a clean `python:3.12-slim` container (linux/amd64, root) | **773–778 passed / 138 skipped / 0 errors**, 0 failures on a quiet host | the sdist additionally skips nine repository-inspection modules by design; the range spans the last four commits of the 1.1 line deliberately — pinning it to one commit would make the sentence false the moment the commit changes |

Signing paths in the second row are *unverified-by-absence*, not passing. That is
the difference between a skip and a green.

## Published wheel vs. current source: which control is where

The two builds answer to the **same version string** and do not carry the same
controls. `1.1.0` was cut on 2026-10-05 (`75b7bc2`, signed tag, the wheel on
PyPI); the isolation-gate and attestation work merged to `main` afterwards
(`5d3650a` gate, `ec5d3d3` attestation, both 2026-10-12), and `main` keeps
reporting `1.1.0` until the next release bumps it. **A version number therefore
cannot tell the two apart — only a commit SHA can.** Anyone reproducing a
security claim installs from source at a pinned commit, never from the index.

Measured on 2026-10-12 by unpacking the published artifact
(`ephemora_cell-1.1.0-py3-none-any.whl`, sha256
`94cf392f8c984414dfe912d7f98b2aaf262758e49508ab9650748492ec989d58`, 30 Python
modules) and grepping it, against `git grep` on the same names at the tag:

| Control | Published `1.1.0` wheel | `main` after the release |
|---|---|---|
| Fuel / memory / wall-clock / output walls, Preview1 + component execution, egress grant signing (ADR-013) | present | present |
| Central enforcement gate — untrusted/unknown `component` forced to subprocess, run refused if the worker is gone (ADR-015) | **absent** (`TRUST_UNKNOWN`: 0 of 30 modules) | present |
| Host-owned trust allowlist, byte-bound, empty-by-default (`trusted_tools`) | **absent** | present |
| Receipt names the path/ABI that actually ran, and whether the sync blockade was effective (`execution_mode`, `abi`, `sync_blockade_enforced`) | **absent** | present |
| The gate's own negative test (`tests/test_isolation_gate.py`) | **not in the release tree** (added on `main`) | present |

Machine-checkable discriminator (exit `0` = source build with the gate, exit `1`
= published wheel). Note that no installed artifact ships tests — the wheel
contains `ephemora_cell/` and `ephemora_cell_mcp/` only — so every gate or
escape-matrix check needs a repository clone, whatever build is under test:

```bash
python -c "from ephemora_cell.execution_report import TRUST_UNKNOWN"; echo $?
```

This is a **documentation-and-evidence gap, not a defect in the release**: the
1.1.0 wheel does what its own release notes say. The gap matters only when a
claim written against `main` is read back onto the installed package — which is
why README's claims about the gate carry their build scope, and why the next
release must re-stamp this table with its own tag and digests.

## The four toolchain skips are not symmetric

Of the 4 toolchain skips in [`tests/test_builder.py`](../tests/test_builder.py),
three run because a toolchain element is **missing** (`WASI_SDK_PATH`, `asc`, `go`)
and one is **inverted**: the `.zig` *guidance* test skips when zig is *installed*,
because then the build is real and the guidance path is unreachable.

Measured 2026-10-05 with `zig` masked out of `PATH` and the rest of the toolchain
intact: `tests/test_builder.py` gives **20 passed / 4 skipped with zig present**
(the guidance test skips, `test_builder.py:337`) and **20 passed / 4 skipped
without zig** (the build-and-run test skips, `test_builder.py:232`). A different
test carries the fourth skip; the totals are invariant.

## Host load: the container leg under contention

The sdist container run above can report up to **two failures when the host runs
other work at the same time**, because the `io_cpu_seconds` watchdog charges worker
startup CPU to the guest; each such test passes standalone and natively. The
underlying accounting question — should a guest be charged for the interpreter and
engine it made the host load? — is open and recorded in
[security_review_2026-10-05.md](security_review_2026-10-05.md), not smoothed over.

## What is machine-checked and what is not

[`scripts/check_test_count.py`](../scripts/check_test_count.py) checks the
documented counts against `pytest --collect-only`, so the release-count sentences
cannot drift from the code. **The prose figures around them — coverage %, the
minimal-install and container counts, and every latency number — are re-measured by
hand at each release, not by the guard.** That is a known limit of this file, and
the reason each of them carries its date and its conditions.
