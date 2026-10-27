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

`ephemora doctor --json` reports the native file digest under
`runtime-identity`. On the qualified platform a digest that does not match is a
**failed check** (`doctor` exits 1) — added 2026-10-20 after an independent
review showed that a 49.0.0 library placed under a 49.0.4 `dist-info` was
reported as the qualified version with only a warning.

**What the execution gate itself checks:** the declared version; the sha256 of
the exact native file the bindings load
(`wasmtime/darwin-aarch64/_libwasmtime.dylib`, **25,478,368 bytes**); and, on
macOS, a byte comparison of the mapped `__TEXT` and `__LINKEDIT` segments against
the same ranges of that file. The mapped check closes the swap-and-restore gap
that a file-only gate cannot see: importing `ephemora_cell` maps the library
before the gate runs, so an attacker who can write the wheel could put 49.0.0 at
the loader path, let it be mapped, restore the qualified bytes, and present a
matching file hash. Measured 2026-10-23: the mapped check accepts the honest
image and refuses that swap (`match=False`, `mapped_match=False`). Measured cost
of the file hash on this host: **7.94–8.03 ms** (5 runs); the mapped comparison
is cached once per process. A mismatch fails with `error_class=environment`.

This is a **detection control, not a tamper-proof boundary**: a local actor who
can write `site-packages` can patch the check as easily as the library. The
mapped check is implemented for darwin; other platforms have no qualified engine
and remain outside the qualified claim. The verdict follows the exact file the
loader uses — a qualified copy elsewhere in the package does not make a swapped
loaded file look qualified. `doctor` and `release_manifest.py verify` report the
same identity from the artifact side; this paragraph is the boundary of the
claim.

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

**Publication path.** The wheel is **not published as a separate runtime
release** and there is no intermediate release. PR CI rebuilds it from the two
pinned upstream inputs with the committed recipe and passes it to the test jobs
as a workflow artifact. The wheel is part of the final v1.2.0 product release.
The older immutable release `wasmtime-runtime-49.0.3.post2` remains public for
history, but both the bootstrap source and the version floor have moved:
nothing silently treats that asset as qualified any more.

## What an external party can verify

| Question | How |
|---|---|
| Is the installed engine the qualified one? | `ephemora doctor --json` → `runtime-floor` (version on the line) and `runtime-identity` (digest of the exact native file the bindings load); `run` enforces the same exact-file digest on the qualified platform |
| Is the wheel in my download the one this project built? | `shasum -a 256 -c SHA256SUMS` and `--require-hashes` on install; both compare against the digests above |
| Does the wheel really contain that library? | `scripts/release_manifest.py verify --set <dir>` reads the digest out of the archive |
| Which commit is this release? | `release_manifest.json` → `source.commit` / `source.tree` |

## What an external party can **not** verify — and why it matters

1. **The native build is not bit-for-bit reproducible here.** A committed,
   pinned recipe exists (`scripts/build_runtime_wheel.py`,
   `.github/workflows/runtime-wheel.yml`): it downloads the official 49.0.4
   C-API asset and the official 49.0.0 Python bindings, verifies their SHA-256
   values, assembles the wheel and re-reads the embedded native digest. What it
   cannot do is rebuild the upstream native binary from source and prove the
   same bytes; the upstream artifact is accepted by digest. A reviewer can
   therefore verify *what* was shipped and that the recipe would assemble the
   same inputs, but not derive the native bytes independently.
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
   index — it is the runtime wheel in the v1.2.0 release set, not an upstream
   publication.

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
