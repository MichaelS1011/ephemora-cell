# Runtime provenance — the qualified Wasmtime build

The engine is the security boundary. This page states exactly which bytes are
shipped, where they came from, how they were built — and what an external party
**cannot** verify, which is the part most provenance pages leave out.

## Identity

| Field | Value |
|---|---|
| Distribution | `wasmtime` (the official Python bindings, `bytecodealliance/wasmtime-py`) |
| Version string | `49.0.3.post2+git.1d21c90f` |
| Wheel | `wasmtime-49.0.3.post2+git.1d21c90f-py3-none-macosx_11_0_arm64.whl` |
| Wheel sha256 | `cee4bb220d5f58fe68a67a1e6bbe92ff5c5f9a95671e0eb1e4142cbfbae55356` |
| Embedded native library | `wasmtime/darwin-aarch64/_libwasmtime.dylib` |
| Native library sha256 | `ab4f1ea6e77c30cf4458bed9e4c94ccb103c7b3f2ceb49681c721c985e80fb73` |
| Licence (declared in METADATA) | `Apache-2.0 WITH LLVM-exception` |
| Platform tag | `macosx_11_0_arm64` — no other platform is qualified |

`ephemora doctor --json` reports the *loaded* library digest under
`runtime-identity`. On the qualified platform a digest that does not match is a
**failed check** (`doctor` exits 1) — added 2026-10-20 after an independent
review showed that a 49.0.0 library placed under a 49.0.3 `dist-info` was
reported as the qualified version with only a warning.

**What the execution gate itself checks:** the declared version, and on the
qualified platform the sha256 of the exact native file the bindings load
(`wasmtime/darwin-aarch64/_libwasmtime.dylib`, **25,462,560 bytes**). The gate
hashes the file before its import probe and refuses a mismatch before any guest
code executes. Importing `ephemora_cell` in the current layout already imports
`wasmtime`, so this is **not** a guarantee that the native library was never
mapped; the narrower window belongs to a process that has not imported the
engine yet. Measured on this host: **7.94–8.03 ms** per hash (5 runs). A digest
that differs from the qualified build fails with `error_class=environment`.

This is a **file-identity check, not a tamper-proof boundary**: a local actor
who can write `site-packages` can patch the check as easily as the library, and
a file swapped between the hash and the load is a residual TOCTOU window. The
verdict follows the exact file the loader uses — a qualified copy elsewhere in
the package does not make a swapped loaded file look qualified. `doctor` and
`release_manifest.py verify` report the same identity from the artifact side;
this paragraph is the boundary of the claim.

## Where it comes from

- **Engine source:** the official Bytecode Alliance C-API release asset
  `wasmtime-v49.0.3-aarch64-macos-c-api.tar.xz`, tarball sha256
  `0c853eb1715b3730304f926d111d4b4a3605b961c5693753bfeeb6b19332c41b`
  (recorded in `requirements.lock` and `SECURITY.md`). 49.0.3 is the upstream
  release on the fix line, not a locally patched fork.
- **Bindings:** the official `wasmtime-py` source at git `1d21c90f`.
- **Local part:** the wheel is built here, not downloaded. The wheel's ZIP
  entries carry the timestamp `2026-10-16 00:00:00`, i.e. it was produced with
  `SOURCE_DATE_EPOCH=1792108800`; that epoch is what the digest above belongs to
  and `requirements.lock` records it. **Whether a second build reproduces the
  same digest byte-for-byte was not measured** — without a committed recipe (see
  below) there is nothing to rebuild with, so this page does not claim
  reproducibility, only the epoch that was used.

The `.post2` in the version is a **packaging revision stamp** of that local
build. No patch file is part of this repository and none ships in the wheel.

**Publication path.** The wheel is published as an immutable release asset under
the dedicated tag `wasmtime-runtime-49.0.3.post2` (2026-10-22), not as PyPI
`wasmtime`. The immutable release locks the asset and its tag after publication;
the CI input is the direct asset URL, and `scripts/ci_runtime_bootstrap.py`
checks the wheel sha256 and the native digest before pip sees the file. The
runtime tag is separate from the product release tag.

## What an external party can verify

| Question | How |
|---|---|
| Is the installed engine the qualified one? | `ephemora doctor --json` → `runtime-floor` (version on the line) and `runtime-identity` (digest of the exact native file the bindings load); `run` enforces the same exact-file digest on the qualified platform |
| Is the wheel in my download the one this project built? | `shasum -a 256 -c SHA256SUMS` and `--require-hashes` on install; both compare against the digests above |
| Does the wheel really contain that library? | `scripts/release_manifest.py verify --set <dir>` reads the digest out of the archive |
| Which commit is this release? | `release_manifest.json` → `source.commit` / `source.tree` |

## What an external party can **not** verify — and why it matters

1. **There is no committed build recipe.** The runtime was built from the
   official sources with the parameters above, but the repository carries no
   script, container file or CI job that reproduces the wheel bit-for-bit. A
   reviewer can therefore check *what* was shipped and that it is internally
   consistent, but cannot rebuild it and compare. Closing this would mean a
   committed, pinned build recipe (toolchain, target, epoch) plus a CI job that
   reproduces the digest — infrastructure work, not a documentation fix.
2. **"No source modification" is a documented statement, not a proof.** Nothing
   in the artifacts proves the source tree was unmodified; the evidence is the
   recorded tarball digest and the absence of any patch in the repository. For
   Apache-2.0 §4(b) this matters: if the build *had* modified files without a
   notice, the distribution would be non-compliant. [license_matrix.md](license_matrix.md)
   records the obligation; this paragraph records the limit of the evidence.
3. **The published PyPI `wasmtime` is a different artifact.** PyPI carries no
   49.0.3 wheel, which is why the package depends on `wasmtime>=49.0.3,<50` and
   fails closed instead of resolving to 49.0.0. Do not expect
   `pip install wasmtime==49.0.3.post2+git.1d21c90f` to work from the index — it
   is a release asset of this project, not an upstream publication.

## Advisory state

The 1.2.0 advisory reasoning — which GHSA/RUSTSEC classes 49.0.3 closes, which
classes remain open at this line, and what the runtime gate refuses — is
maintained in `SECURITY.md` (“Dependency upgrade truth” and the 2026 advisory
sections). This page does not duplicate it; it only binds the bytes.
