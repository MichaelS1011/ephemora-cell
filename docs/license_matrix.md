# Licence and redistribution matrix — v1.2.0

Every statement on this page is read out of the artifacts that will be shipped,
not from memory. Reproduce it with:

```bash
python scripts/license_matrix.py --set <release-directory>
```

The script is mechanical on purpose: it reports the declared licence, the licence
and notice files *inside* each artifact with their digests, and fails when a
distribution carries no licence file at all. **It does not decide whether a
licence permits redistribution** — that is the counsel question in
[Open questions](#open-questions-that-are-not-mine-to-answer), and no script can
answer it.

## The matrix

| Distribution | Version | Declared licence | Licence / notice files in the artifact | Obligation | Status |
|---|---|---|---|---|---|
| `ephemora-cell` | 1.2.0 | `BUSL-1.1` | `licenses/LICENSE` (5 751 B, `eab36ac9…`), `licenses/THIRD_PARTY_NOTICES.md` (10 942 B, `d58d7638…`) | BUSL-1.1 requires the licence text to accompany every copy; the notices file names what is installed alongside, in extras, and in the repository | **met** |
| `wasmtime` (qualified runtime) | `49.0.4.post1+git.2c2970205f` | `Apache-2.0 WITH LLVM-exception` (PEP 639 expression in METADATA) | `licenses/LICENSE` (12 243 B, `268872b9…`) | Apache-2.0 §4(a) ship the licence — met; §4(b) mark modified files — **no file was modified locally** (see the vocabulary note below), so the notice duty does not arise; §4(d) propagate a `NOTICE` — **upstream ships none**, so there is nothing to propagate | **met, with a documented evidence limit** |
| `certifi` | 2026.10.19 | `MPL-2.0` (PEP 639 expression in METADATA) | `licenses/LICENSE` (989 B, `e93716da…`) | MPL-2.0 requires the licence text with the distribution; the wheel carries it and the core notices file names it. It is a separate installed distribution, not embedded in the core wheel | **met** |
| `ephemora-cell-python-guest` | 1.2.0 | wrapper `BUSL-1.1`, embedded CPython `PSF-2.0` | `licenses/LICENSE`, `licenses/licenses/PSF-2.0.txt`, `licenses/THIRD_PARTY_NOTICES.md` | PSF-2.0 requires the agreement and the PSF copyright notice in all copies — the full text ships inside the wheel; the notice names the embedded binary's digest (`42984274…`), which matches `guest.wasm` byte for byte | **met** |
| `ephemora-cell-javascript-guest` | 1.2.0 | wrapper `BUSL-1.1`, embedded QuickJS-ng / `rquickjs` / Rust std under MIT (or MIT OR Apache-2.0) | `licenses/LICENSE`, `licenses/licenses/RUST-MIT.txt`, `licenses/THIRD_PARTY_NOTICES.md` | MIT requires the copyright notice and permission text in all copies — reproduced **verbatim inside the notice file** for QuickJS-ng and `rquickjs`, and in `RUST-MIT.txt` for the Rust standard library; the binary digest named in the notice (`a192e230…`) matches `guest.wasm` | **met** |
| `ephemora_cell-1.2.0.tar.gz` | 1.2.0 | `BUSL-1.1` | `LICENSE`, `THIRD_PARTY_NOTICES.md` | as the core wheel | **met** |

### “Patched” means upstream-fixed, not locally modified

The word appears throughout this project (“the patched 49.0.4 line”, “the
unpatched 49.0.0”) and it names a **property of the upstream release**: 49.0.4 is
the version in which the 2026-10 advisory wave is fixed (49.0.3 closed the
earlier wave), 49.0.0 is a version in which neither is fixed. It does **not** mean that this project edits Wasmtime's source.

That reading is what the license assessment rests on: no patch file exists in the
repository, none ships in the wheel, and the source is the official upstream
tarball. The evidence for “no local modification” is therefore documentary (the
recorded tarball digest and the absence of any patch), not cryptographic — the
limit is stated in [runtime_provenance.md](runtime_provenance.md). If a future
build ever does carry a local patch, §4(b) applies and every modified file must
carry a notice of change.

### What each artifact deliberately does *not* contain

- **No `NOTICE` file for wasmtime.** Apache-2.0 §4(d) only obliges you to
  propagate a NOTICE that the work actually carries. Wasmtime's wheel carries
  `LICENSE` only; adding a NOTICE of our own would attach an attribution that
  upstream did not make. If a future upstream build starts shipping one, it must
  be propagated and this row changes.
- **No third-party code inside the core wheel.** The core is pure Python
  (`py3-none-any`); `THIRD_PARTY_NOTICES.md` says so and lists what pip installs
  *beside* it, which is a statement about the installation, not about the archive.
- **No interpreter binaries inside the core.** CPython and QuickJS live only in
  the two guest distributions, which is why their notices are per-artifact rather
  than global.

## What is checked, and what is not

| Checked mechanically | How |
|---|---|
| every distribution carries at least one licence file | `scripts/license_matrix.py` exits 1 otherwise |
| the guest binaries match the digests their notices claim | digest of `guest.wasm` inside each wheel vs. the notice |
| the runtime's native library matches the qualified digest | `ephemora doctor` (`runtime-identity`) and `scripts/release_manifest.py` read it from the wheel |
| the licence texts are the ones shipped | sha256 of each licence file is in `results/license_matrix_120.json` |

**Not checked mechanically, and not claimed:** whether BUSL-1.1 permits *your*
use of the package (that is a licence question for you and your counsel), and
whether the guest redistributions are cleared for publication (below).

## Open questions that are not mine to answer

These are isolated deliberately: each one is a decision with an owner, not a gap
that a technical step could close.

| # | Question | Why it is open | What it blocks |
|---|---|---|---|
| **L1** | May the two guest wheels be distributed publicly under a BUSL-1.1 wrapper that embeds PSF-2.0 / MIT payloads? | The payload licences permit redistribution *with their texts* (done). The wrapper's BUSL-1.1 adds its own terms on top; whether that combination needs a legal opinion before publication is a business-risk question, and the project has **no written clearance**. | Public upload of `ephemora-cell-python-guest` and `ephemora-cell-javascript-guest`; therefore also the `[python]` / `[javascript]` extras |
| **L2** | May the patched runtime wheel be redistributed as a release asset? | Apache-2.0 WITH LLVM-exception permits binary redistribution with the licence and without a modification notice when the source is unmodified — both hold. This is a confirmation, not a legal analysis. | Publication of `wasmtime-49.0.4.post1+git.2c2970205f-…whl` as a GitHub release asset (not as PyPI `wasmtime`, a name owned by someone else) |
| **L3** | Does the core package's BUSL-1.1 (Additional Use Grant: *None*) match the intended commercial model? | The licence permits copying, modification and non-production use and converts to Apache-2.0 on the Change Date; production use needs a commercial licence. That is a product/monetisation decision. | Nothing technical — the artifacts are consistent with the licence as written |

`THIRD_PARTY_NOTICES.md` states the same conclusion in its own words: *“As of
1.2.0 no such legal clearance exists; it is an open, founder/counsel-gated
precondition to publishing.”* This page does not contradict it.
