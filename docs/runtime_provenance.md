# Runtime provenance — the qualified Wasmtime build

The engine is the security boundary. This page states exactly which bytes are
shipped, where they came from, how they were built — and what an external party
**cannot** verify, which is the part most provenance pages leave out.

## Identity

| Field | Value |
|---|---|
| Distribution | `wasmtime` (the official Python bindings, `bytecodealliance/wasmtime-py`) |
| Version string | `49.0.4.post1+git.2c2970205f` |
| Wheel | `wasmtime-49.0.4.post1+git.2c2970205f-py3-none-macosx_11_0_arm64.whl` |
| Wheel sha256 | `5d1ac8807b9d99d3d6824560d729bf11f93c8b348590d7547557d2345bd0865e` |
| Embedded native library | `wasmtime/darwin-aarch64/_libwasmtime.dylib` |
| Native library sha256 | `247c1529445001f4b6ed1d46d4f3b4a2c67f8a0c568c9e6559500eb1a89ca30b` |
| Licence (declared in METADATA) | `Apache-2.0 WITH LLVM-exception` |
| Platform tag | `macosx_11_0_arm64` — no other platform is qualified |

`ephemora doctor --json` reports the *loaded* library digest under
`runtime-identity`. On the qualified platform a digest that does not match is a
**failed check** (`doctor` exits 1) — added 2026-10-20 after an independent
review showed that a 49.0.0 library placed under a 49.0.4 `dist-info` was
reported as the qualified version with only a warning.

**What the execution gate itself checks:** the declared version, and on the
qualified platform the sha256 of the exact native file the bindings load
(`wasmtime/darwin-aarch64/_libwasmtime.dylib`, **25,478,368 bytes**). The gate
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
  `wasmtime-v49.0.4-aarch64-macos-c-api.tar.xz`, tarball sha256
  `f83147d18f6089bfb0c5f01b8158f051fe98d26fb0a0e0dbb40a6b8cd8045460`
  (upstream tag `v49.0.4`, commit `2c2970205f`, released 2026-10-19). The dylib
  is taken unchanged from that asset — there is no local compile of Wasmtime.
  49.0.4 contains the aarch64 `br_table` fix (`994549891c`,
  GHSA-mghf-wjfp-p5xm) and the 2026-10 wasi-http fixes.
- **Bindings:** the PyPI `wasmtime` 49.0.0 wheel
  (`de98d6282c61d5dd4dc1ff1b410936ceb6fff3a27439e9cab51a375b8da2ec2f`); its
  `wasmtime/*.py` files are byte-identical to the bindings the withdrawn
  49.0.3.post2 build carried. No binding source was edited.
- **Local part:** the wheel is assembled here by the committed
  [`scripts/build_runtime_wheel.py`](../scripts/build_runtime_wheel.py), with
  fixed ZIP timestamps and sorted entries. Two runs from the pinned inputs
  produced the same wheel sha256 (`5d1ac880…`) — the **assembly** is
  reproducible. The native dylib is an upstream binary; this page does **not**
  claim that the native build itself is byte-reproducible.

The `.post1+git.2c2970205f` version is a packaging stamp: `.post1` keeps this
locally assembled wheel distinct from a future official PyPI 49.0.4, and
`git.2c2970205f` names the upstream tag commit it was assembled from.

**Publication path.** The wheel is **not published yet**. The planned dedicated
tag is `wasmtime-runtime-49.0.4.post1`, separate from the product release tag;
`scripts/ci_runtime_bootstrap.py` already pins this wheel sha256 and the native
digest, so CI fails closed (404) until a founder-authorized release exists. The
older immutable release `wasmtime-runtime-49.0.3.post2` remains public for
history, but both the bootstrap pin and the version floor have moved: nothing
silently treats that asset as qualified any more.

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
   49.0.4 wheel, which is why the package depends on `wasmtime>=49.0.4,<50` and
   fails closed instead of resolving to a vulnerable 49.0.0–49.0.3. Do not
   expect `pip install wasmtime==49.0.4.post1+git.2c2970205f` to work from the
   index — it is a release asset of this project, not an upstream publication.

## Advisory state

49.0.4 closes the 2026-10 wave: the critical aarch64 Cranelift `br_table`
escape (GHSA-mghf-wjfp-p5xm), the component stream/future panic
(GHSA-9pvw-hwfg-92h5) and the three wasi-http issues
(GHSA-9prg-84vf-g5fc, GHSA-r8xh-cgf7-392j, GHSA-jxcf-8qw5-5c33). The macOS
filesystem escape GHSA-m9f7-9w4p-gv38 was already fixed in 49.0.3 and is
verified by a behavioural probe on this host (the escape succeeds on 49.0.0 and
is refused on 49.0.4). The withdrawn 49.0.3.post2 build is **affected** by
GHSA-mghf-wjfp-p5xm: a 300,000-target `br_table` module compiled on it and
killed the process with SIGBUS on the default branch, while 49.0.4 rejects the
module at translation time.

Two watchers keep this current: `scripts/check_wasmtime_advisories.py` reads the
upstream GitHub security advisories and fails closed when a range matches the
pinned version; `scripts/check_wasmtime_patch.py` still reports whether a plain
PyPI install can reach a patched engine. The CI `security` job runs the
advisory watcher.
