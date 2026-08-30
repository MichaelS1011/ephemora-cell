# ADR-005: `ephemora-cell build` — Recipe Pipeline Instead of a Registry

- **Status:** Accepted
- **Date:** 2026-08-29
- **Context:** Friction matrix (`benchmarks/build_friction/`)

## Context (measured)

"Compile from any language" is the biggest adoption blocker for end users. The
friction measurement shows the top classes: toolchain not installed (Go, asc),
Rust WASM target missing, C without wasi-sysroot (`stdio.h not found`, measured
verbatim), no Python AOT (structural), wrong GOOS/GOARCH combination.

## Decision

**(a) Build pipeline as a one-command CLI — yes; (b) registry — no (deferred).**

1. `ephemora-cell build <source>` with recipe detection by file suffix:
   - **Rust:** a real build (`cargo build --release --target wasm32-wasip1`),
     manifest search upward like cargo, artifact path from `[package].name`.
   - **Go:** a real build (`GOOS=wasip1 GOARCH=wasm go build`).
   - **C:** guidance instead of guessing (WASI-SDK needed; Apple/Xcode clang has no
     wasm32 target — measured verbatim).
   - **Python:** guidance instead of guessing — no AOT exists; scripts run on
     a wasi-python interpreter. Structural, no feature promise.
2. **Errors → hint table** (`hint_for`): verbatim toolchain errors are
   mapped to actionable hints (the measurement as source).
   Fail-closed: unknown errors are passed through unchanged, never
   "guessed".
3. **Registry (b) deferred** (YAGNI): a curated, signed tool registry
   is distribution infrastructure with trust/signing problems (see the
   MCP-SandboxScan critique, arXiv 2601.01241) — only on adoption signals,
   then its own ADR.

## Consequences

- Gate criterion met: Rust hello-world → .wasm in 2.9 s (measured), executed
  in the Cell; Go recipe checked in CI (setup-go job), skipif locally. CI job
  `build-recipes` sets the gates.
- Risk: toolchain volatility — recipes are versioned in code and
  CI-checked; error hints are tied to verbatim measurements, not to
  guesswork.
- Reversible: a registry can later build on the recipes (the same
  build commands, curated + signed).
