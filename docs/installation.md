# Installation (v1.2.0)

**Status:** this page describes the v1.2.0 release layout. Until that release is
published, the same layout carries the `1.2.0` artifacts but no public URL —
substitute whichever directory or release page you received them from. The steps
themselves are the ones exercised for the release candidate; nothing here depends
on a development checkout.

v1.2.0 is qualified on **macOS arm64** with **Python 3.10, 3.11, 3.12 and
3.13** — each version ran the full suite against the qualified runtime. Other
platforms may install, but no execution claim is made there and `ephemora
doctor` will say so. See [product_contract.md](product_contract.md) for the full
matrix.

## What the release set contains

| File | What it is |
|---|---|
| `ephemora_cell-1.2.0-py3-none-any.whl` | the package |
| `ephemora_cell-1.2.0.tar.gz` | the source distribution it was built from |
| `wasmtime-49.0.4.post1+git.2c2970205f-py3-none-macosx_11_0_arm64.whl` | the qualified native runtime |
| `ephemora_cell_python_guest-1.2.0-py3-none-any.whl` | the CPython (WASI 0.2) language guest |
| `ephemora_cell_javascript_guest-1.2.0-py3-none-any.whl` | the QuickJS language guest |
| `SHA256SUMS` | every artifact's digest, one line each |
| `release_manifest.json` | the commit and tree the set was built from, every artifact digest, and the runtime identity read out of the runtime wheel (version, licence, native library digest) |
| `requirements-release.txt` | all four distributions pinned by version **and** `--hash` |
| `requirements-release-core.txt` | the same pins without the two language guests |

`scripts/release_manifest.py` in the repository writes and re-checks these three
manifests (`write` / `verify`); it refuses a set that is missing a role or that
contains an unexpected file.

## Why the runtime is not a normal dependency

The security floor for 1.2.0 is `wasmtime>=49.0.4,<50`, and the qualified build is
a controlled patched build (`49.0.4.post1+git.2c2970205f`, wheel tag
`macosx_11_0_arm64`, embedded `_libwasmtime.dylib` sha256 `247c1529…a30b`). The
public Python index does not carry a 49.0.4 wheel, so `pip install ephemora-cell`
alone cannot satisfy the requirement. The dependency contract therefore **fails
closed**: it will not silently fall back to the unpatched 49.0.0 line.

The runtime ships as a wheel next to the Cell wheel in the v1.2.0 release set.
The wheel sha256 is `5d1ac880…`; the embedded native library is `247c1529…`.
Both are checked by `scripts/ci_runtime_bootstrap.py` before and after install.

PR CI does **not** need a separate public runtime release. A dedicated macOS
`runtime-wheel` job downloads the two pinned upstream inputs — the official
Bytecode Alliance v49.0.4 C-API tarball (sha256 `f83147d1…5460`) and the official
`wasmtime` 49.0.0 macOS arm64 bindings wheel (sha256 `de98d628…ec2f`) — rebuilds
the wheel with the checked-in recipe, verifies all hashes and the arm64 Mach-O,
and passes the wheel to every dependent job as a workflow artifact. Any input,
build, architecture or digest mismatch is a red leg; there is no public-asset
404 and no 49.0.0–49.0.3 fallback.

## Install from the release artefacts

```bash
# 1. Put every file of the set in one directory (the "wheelhouse") and enter it.
mkdir -p wheelhouse && cd wheelhouse

# 2. Verify the digests before installing anything. Every line must say OK.
shasum -a 256 -c SHA256SUMS

# 3. A clean interpreter (3.10–3.13 are qualified; 3.12 shown).
python3.12 -m venv .venv

# 4. Install offline from these bytes only. Both flags are load-bearing:
#    --no-index  keeps an unpinned engine (e.g. 49.0.0) out of the resolution
#    --require-hashes makes pip refuse any wheel whose digest differs from the pin
.venv/bin/python -m pip install --no-index --require-hashes \
    --find-links . -r requirements-release.txt
```

What the two flags buy you, measured: a wheel with a single flipped byte is
refused with `THESE PACKAGES DO NOT MATCH THE HASHES FROM THE REQUIREMENTS
FILE`; a directory without the runtime wheel ends in `Could not find a version
that satisfies the requirement wasmtime==49.0.4.post1+git.2c2970205f (from
versions: none)` and installs nothing. Neither case falls back.

If you want the core without the language guests, use
`requirements-release-core.txt` in step 4; the guests are a separate decision
(see [product_contract.md](product_contract.md)).

## CI install path (repository tool, not shipped)

CI does not use a public runtime asset and does not use a wheelhouse directory
for the test jobs. One job builds the wheel from the pinned upstream inputs and
uploads it; dependent jobs install exactly that artifact:

```bash
# build job
python scripts/ci_runtime_bootstrap.py --prepare --out "$RUNNER_TEMP/runtime-wheel"

# dependent job (after actions/download-artifact)
python scripts/ci_runtime_bootstrap.py --wheel \
  "$RUNNER_TEMP/runtime-wheel/wasmtime-49.0.4.post1+git.2c2970205f-py3-none-macosx_11_0_arm64.whl"
```

The script is a repository tool — it is not part of the wheel or sdist. It
rejects a non-HTTPS input URL, a substituted input, a truncated download, a
wheel whose sha256 is not `5d1ac880…`, a native library whose sha256 is not
`247c1529…`, a non-arm64 Mach-O, an exact-version mismatch, a
non-`Apache-2.0 WITH LLVM-exception` declaration, and an interpreter that does
not run natively on arm64 macOS (arm64 or universal2) on a host of macOS 11.0 or
newer. pip runs with `--no-index --no-deps`, so an unvetted PyPI engine cannot
enter the environment. `--url` exists only for an explicit local/release audit
of a prebuilt wheel; it is not the CI path.

## First checks

```bash
.venv/bin/ephemora doctor          # exit 0 = no failed check
.venv/bin/ephemora policy check    # the effective budgets before any run
.venv/bin/ephemora run hello.wasm  # a real module through the sandbox
```

`doctor --json` names the runtime it actually loaded (`runtime-import`), the
digest of the exact native file the bindings load (`runtime-identity`, which
must be `247c1529445001f4b6ed1d46d4f3b4a2c67f8a0c568c9e6559500eb1a89ca30b`) and
whether the engine sits on the qualified line (`runtime-floor`). A successful
install shows `PASS` on all three. `run` checks the same exact-file digest on
the qualified platform before any guest code executes; a different file is
refused with `error_class=environment`.

The JSON forms are the ones to script against:

```bash
.venv/bin/ephemora doctor --json
.venv/bin/ephemora run hello.wasm --json
.venv/bin/ephemora inspect hello.wasm --json
.venv/bin/ephemora policy check --json
```

## Language guests

`ephemora run script.py` and `ephemora run script.js` execute through a language
guest. Both guest wheels are part of the set, so step 4 above installs them.

Whether the guests may be **published** is a separate, still open decision
([why](product_contract.md)): the wheels embed CPython (PSF-2.0) and QuickJS
(MIT) with their licence texts, and the redistribution clearance for this
project's BUSL-1.1 work is a founder/counsel question, not a packaging gap. Until
that clearance exists, do not document or rely on
`pip install "ephemora-cell[python]"` — the extra exists, the public index entry
does not.

A guest can also be supplied explicitly instead of installed:

```bash
export EPHEMORA_PY_COMPONENT_GUEST=/path/to/guest.wasm
```

Without a guest the route fails closed with a clear message — there is no
fallback to a host interpreter.

## What failure looks like

The error classes are part of the contract and are meant to be checked, not
grepped:

| Situation | What you see |
|---|---|
| Runtime missing from the set | step 4 fails: `No matching distribution found for wasmtime==49.0.4.post1+git.2c2970205f` |
| Tampered artifact | step 2 fails on `FAILED`, step 4 fails on the hash mismatch |
| Unpatched runtime (49.0.0) present in the environment | `doctor`: `runtime-floor` fails; `run` refuses with error class `environment` — no silent fallback |
| Tampered native library | `doctor`: `runtime-identity` fails against the qualified digest; `run` refuses with `error_class=environment` before any guest code executes |
| Wrong platform | step 4 cannot resolve the runtime wheel (`No matching distribution` for the `macosx_11_0_arm64` tag) |
| Guest missing | `run --language python` refuses with a message naming the missing guest |
| Budget exceeded | `run` exits non-zero, `status: fuel_exhausted`, `fuel_consumed == fuel_budget` |
| Unverifiable evidence | `verify` exits non-zero, `verified: false`, with the reason in `errors` |

`--json` reports carry `security_baseline.wasmtime_version`; a run whose engine
is outside the qualified line is refused rather than reported as a success.

## Building from the source distribution

The sdist is a build input, not a test target.

**Measured, not assumed:** building a wheel from it needs the build backend in
the environment. In a clean venv that carries only the release set, the offline
build fails with `BackendUnavailable: Cannot import 'setuptools.build_meta'` —
Python 3.12 venvs no longer ship setuptools. With `setuptools>=77` and `wheel`
present it works and the result is the same package:

```bash
# once, and only if the environment does not already carry a build backend
.venv/bin/python -m pip install "setuptools>=77" wheel

# build the wheel from the sdist, offline, without build isolation
.venv/bin/python -m pip wheel --no-index --no-build-isolation \
    --find-links . -w out ephemora_cell-1.2.0.tar.gz

# install and check what came out
.venv/bin/python -m pip install --no-index --find-links out \
    --find-links . ephemora_cell-1.2.0-py3-none-any.whl
.venv/bin/ephemora doctor
```

Measured on this release: the wheel built from the sdist (`setuptools 84.2.1`)
has **the same members with the same bytes** as the released wheel, except
`WHEEL` and `RECORD` — the `WHEEL` file stamps the generator version
(`84.2.0` in the release build, `84.2.1` in the rebuild) and `RECORD` hashes
that file. Installed from the rebuild, `run hello.wasm` reports `success`,
`exit_status_fidelity: exact` and the qualified engine.

Running `pytest` inside an unpacked sdist does not work and is not claimed: nine
modules in the shipped suite are repository guards that read `scripts/` at import
time. [release_assurance.md](release_assurance.md) names them.
