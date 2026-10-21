# Third-party notices

Third-party components, dependencies and tooling around Ephemora Cell, and what
their own terms require. The root [LICENSE](LICENSE) covers the Licensed Work;
it does not relicense, amend or overrule anything listed here.

**Read the grouping, not the list.** A component named in this file is *not*
thereby embedded in the wheel you installed. The sections below separate what
the wheel itself contains, what pip installs next to it, what only an optional
extra pulls in, and what lives in the repository without reaching any artifact.
Measured 2026-10-06 from a clean build, re-verified 2026-10-16 against the 49.0.3 runtime line; dependency licenses were read from each
package's PyPI metadata (`info.license_expression` / `info.license`), not from
memory — the lockfiles in this repo carry no license fields at all, so they
cannot answer this question.

## What the wheel itself contains

Python modules of the two `ephemora_cell*` packages and two self-built WASM
tools. No third-party source, binary, font or icon is embedded in the wheel.

| Item | License | Note |
|---|---|---|
| `ephemora_cell_mcp/tools/echo.wasm` | BUSL-1.1 (ours) | our own Rust, dependency-free; `sha256 3650d415…` |
| `ephemora_cell_mcp/tools/clock.wasm` | BUSL-1.1 (ours) | our own Rust, dependency-free; `sha256 e00c4197…` |
| `LICENSE`, `THIRD_PARTY_NOTICES.md` | — | shipped as license files under `*.dist-info/licenses/` |

`clock.wasm` re-implements Howard Hinnant's `civil_from_days` date algorithm
(`tools_src/clock/src/main.rs:18-31`). The author released it with
*"Consider these donated to the public domain"*
(<https://howardhinnant.github.io/date_algorithms.html>), so the source-comment
credit is courtesy, not a licence obligation.

## Installed alongside the package by pip

Separate distributions, each carrying its own license; not part of our wheel.

| Component | How it arrives | License |
|---|---|---|
| `wasmtime` 49.0.3 (fix line; controlled build, not on PyPI — see [SECURITY.md](SECURITY.md)) | required runtime dependency (`pyproject.toml:19`, `wasmtime>=49.0.3,<50`; pinned in `requirements.txt`) | Apache-2.0 WITH LLVM-exception |

## Installed only with an optional extra

| Component | Extra | License | Default install |
|---|---|---|---|
| `cryptography` | `tools-signing` | Apache-2.0 OR BSD-3-Clause | not installed; imported lazily for Ed25519 sign/verify (`grant_trust.py:458`, `tool_registry.py:168`) |
| `mcp` (official MCP Python SDK) | `integration` | MIT | not installed; interop gate only |

## Language-guest packages (optional extras `python` / `javascript`)

Separate distributions, installed **only** when the user opts into a language
extra (`pip install "ephemora-cell[python]"` / `[javascript]`); never pulled in
by a default install and not part of the core wheel. Each ships one prebuilt
WASI guest binary that the core sandbox treats as untrusted module input.

| Package | Embeds | License of the embedded runtime |
|---|---|---|
| `ephemora-cell-python-guest` | a CPython 3.14 WASI component whose binary **statically links the `componentize-py` 0.25.1 runtime** together with its Rust dependencies (`pyo3`/`pyo3-ffi` 0.28.3, `anyhow`, `num-bigint`, `once_cell`, `rustc-demangle`, `wasm-tools` `wit-dylib`) and the Rust standard library — established by a `strings` scan of the shipped binary (2026-10-16) | CPython: PSF-2.0; `componentize-py` runtime: Apache-2.0; the Rust crates: Apache-2.0 OR MIT (**declared**, not verified against the registries); Rust `std`/`core`: MIT OR Apache-2.0 |
| `ephemora-cell-javascript-guest` | QuickJS (the `quickjs-ng` fork) compiled to `wasm32-wasip1` via `rquickjs` 0.14.0, plus the Rust standard library and its toolchain dependency `hashbrown` 0.17.1 | quickjs-ng: MIT; rquickjs: MIT; `hashbrown` 0.17.1: MIT OR Apache-2.0; Rust `std`/`core`: MIT OR Apache-2.0 |

Each guest wheel ships the corresponding third-party texts: `LICENSE`,
`THIRD_PARTY_NOTICES.md`, and `licenses/` (`RUST-MIT.txt`, `APACHE-2.0.txt`; the
Python guest additionally `PSF-2.0.txt`). `serde`/`serde_json` appear in the
JavaScript guest's committed `Cargo.lock` graph but are **not** present in the
shipped binary (0 `strings` hits) and are therefore not listed here.

Both packages carry a `guest.digest` (SHA-256) that the adapter verifies before
running; at run time the sandbox mounts only a throwaway `/work` directory
holding the user's own source, executes the guest in the isolated subprocess
worker, and never runs anything in the host interpreter. Guests are built from
the public recipes in [`docs/language-guest-build.md`](docs/language-guest-build.md);
that file carries the exact toolchain pins and the honest caveat that the guest
builds are toolchain-and-recipe pinned but **not** byte-deterministic, so the
supply-chain guarantee is the digest-pinned shipped artifact plus
bring-your-own recompute-and-verify, not rebuild bit-parity.

## In the repository, reaching no artifact

**EEMBC CoreMark 1.01** — `benchmarks/workloads/coremark.wasm` (39 582 bytes,
`sha256 5acb1c0e9c73b468072b575859462d10b0b6686107d9996edf53567d2978846c`).

- Upstream: `https://github.com/eembc/coremark.git`, sources pinned at commit
  `1f483d5b8316753a742cbf5590caf5bd0a4e4777`; build recipe and protocol are in
  `benchmarks/coremark_wasi.py:5-7` and its `PROVENANCE` block (`:69-77`).
- Its terms are two instruments in one file: the **COREMARK® Acceptable Use
  Agreement** and, for the code, **Apache-2.0**. GitHub's licence API reports
  `NOASSERTION` for the repository, i.e. neither OSI nor SPDX — so the terms are
  not something a recipient can infer from the binary, and a verbatim copy from
  the pinned commit sits next to it:
  [`benchmarks/workloads/COREMARK-LICENSE.md`](benchmarks/workloads/COREMARK-LICENSE.md).
  That copy is deliberately not packaged: `benchmarks/` reaches no wheel, sdist
  or image, and neither does the binary it licenses.
- What we do to satisfy it: the sources are unmodified, the target differs
  (`wasm32-wasi`, built with the unmodified `wasm3/wasm-coremark` `build.sh`
  under wasi-sdk-34 / clang 23.1.0); the mark appears only to name the benchmark
  whose result is measured; ownership of the mark is stated here and in
  `docs/performance.md`.
- `COREMARK®` is a registered trademark of Embedded Microprocessor Benchmark
  Consortium (Ser. No. 85/487,290; Reg. No. 4,179,307). Nothing in this repo
  suggests EEMBC endorses or produced these measurements.

**Upstream conformance suites** — wasi-testsuite and the WebAssembly
core-testsuite are cloned at run time into `.conformance_cache/` (gitignored,
`.gitignore:59`), never vendored and never shipped; see `conformance/README.md`.
Their results are published as counts, not as redistributed test files.

**Dev and CI tooling** — `pytest`, `pytest-cov`, `black`, `ruff`, `mypy` (MIT),
`bandit`, `cyclonedx-bom`, `pip-audit` (Apache-2.0). Hash-pinned in
`requirements-dev.lock`, installed only in CI, not distributed.

**GitHub Actions** — `actions/checkout`, `actions/setup-python`,
`actions/upload-artifact`, `github/codeql-action`, `ossf/scorecard-action`, all
pinned to commit SHAs. They execute on the runner; they are not part of any
artifact.

**Contributor Covenant 2.1** — `CODE_OF_CONDUCT.md` is adapted from it; the
attribution with the version URL is in that file (`:36-38`).

**Business Source License text** — `LICENSE:84-85`: license text copyright
(c) 2017 MariaDB Corporation Ab; "Business Source License" is a trademark of
MariaDB Corporation Ab. Used under the Covenants of Licensor, with the four
parameters filled in and no other modification.

## The container image is a different composition

`Dockerfile` builds on `python:3.12-slim` pinned by digest (`Dockerfile:12`,
`sha256:02108f5d…d9155d`) and runs `pip install .`. So the image contains Debian,
CPython and the installed `wasmtime` distribution under their own licenses —
present because they were installed, not because we bundled them. A CycloneDX
SBOM is generated for every CI run (`.github/workflows/ci.yml:212-220`). The
BUSL text and this file travel with the installed package at
`site-packages/ephemora_cell-*.dist-info/licenses/`.

## Fonts, icons and generated visuals

No font file, icon set or stock image is distributed by this repository. The SVG
and PNG assets are generated by the scripts in `assets/`, which render with
system font stacks at build time (`-apple-system, Segoe UI, Helvetica, Arial`,
`SF Mono, Menlo`); only the rasterised output is committed. The `shield` icon in
`action/action.yml:8-9` is a GitHub Actions branding keyword, not an icon file.

## Trademarks

Ephemora and Ephemora Cell are identifiers of Michael Soppa, the Licensor. No
trademark or logo is granted by the BUSL-1.1 license (`LICENSE:43-45`).

WebAssembly, WASI, Wasmtime, Bytecode Alliance, Model Context Protocol/MCP,
Anthropic, OpenAI, NVIDIA and DGX Spark, Docker, gVisor, Kubernetes, FastAPI,
PyPI, GitHub, Zig, AssemblyScript, Emscripten, CPython, MariaDB, LinkedIn,
Smithery and Glama are trademarks of their respective holders. They are named
descriptively — as a dependency, a standard, a comparison, a test target or a
place where something is listed — and the naming implies no partnership,
sponsorship, endorsement or certification by any of them.

## What this file deliberately does not claim

It is a notice, not legal advice, and it does not classify anything for export
control. The repository contains no encryption implementation of its own: the
only cryptographic primitives in shipped code are SHA-256 digests
(`engine_pool.py:29`, `execution_report.py:15`) and Ed25519 sign/verify through
the optional `cryptography` extra.

**This is licence *identification*, not legal clearance.** A CycloneDX SBOM and
this notices file record what components are present and how they were
measured; they are **not** a legal approval to distribute. Before any public
PyPI/GitHub release, counsel must formally clear the embedded third-party
runtimes carried inside the optional language-guest binaries — CPython 3.14
(PSF-2.0), the `componentize-py` 0.25.1 runtime and its Rust dependencies
(Apache-2.0 / MIT, as identified above), quickjs-ng and its Rust bindings (MIT),
`hashbrown` 0.17.1 (MIT OR Apache-2.0), and the statically linked Rust standard
library (MIT OR Apache-2.0) — for the intended licence mix against
this project's BUSL-1.1 work. As of 1.2.0 **no such legal clearance exists**; it
is an open, founder/counsel-gated precondition to publishing, listed among the
release blockers, and this file must not be read as satisfying it.
