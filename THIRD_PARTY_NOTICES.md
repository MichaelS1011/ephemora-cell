# Third-party notices

Third-party components, dependencies and tooling around Ephemora Cell, and what
their own terms require. The root [LICENSE](LICENSE) covers the Licensed Work;
it does not relicense, amend or overrule anything listed here.

**Read the grouping, not the list.** A component named in this file is *not*
thereby embedded in the wheel you installed. The sections below separate what
the wheel itself contains, what pip installs next to it, what only an optional
extra pulls in, and what lives in the repository without reaching any artifact.
Measured 2026-10-06 from a clean build; dependency licenses were read from each
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
| `wasmtime` 47.0.1 | required runtime dependency (`pyproject.toml:15`, pinned in `requirements.txt`) | Apache-2.0 WITH LLVM-exception |

## Installed only with an optional extra

| Component | Extra | License | Default install |
|---|---|---|---|
| `cryptography` | `tools-signing` | Apache-2.0 OR BSD-3-Clause | not installed; imported lazily for Ed25519 sign/verify (`grant_trust.py:458`, `tool_registry.py:168`) |
| `mcp` (official MCP Python SDK) | `integration` | MIT | not installed; interop gate only |

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
