#!/usr/bin/env bash
# Regenerate the Rust-built WASI 0.2 fixtures (hello02.wasm, fs02.wasm)
# from their sources in src/.
#
# Requirements:
#   cargo with the wasm32-wasip2 target   (rustup target add wasm32-wasip2)
#   wasm-tools                            (brew install wasm-tools)
#
# Output is byte-identical to the committed fixtures (verified via sha256
# when they were imported).

set -euo pipefail

FIXTURES="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for crate in hello02 fs02; do
  (
    cd "$FIXTURES/src/$crate"
    cargo build --release --target wasm32-wasip2
  )
  wasm-tools strip -a \
    "$FIXTURES/src/$crate/target/wasm32-wasip2/release/$crate.wasm" \
    -o "$FIXTURES/$crate.wasm"
done

echo "fixtures regenerated: hello02.wasm, fs02.wasm"