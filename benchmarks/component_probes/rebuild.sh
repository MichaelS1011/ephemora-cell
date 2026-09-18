#!/usr/bin/env bash
# Regenerate the WASI 0.2 component probes for the CVE replay
# (benchmarks/mcp_cve_replay.py, component branch):
#   fs_probe.wasm  — EscapeRoute intents (CVE-2025-53109/53110)
#   net_probe.wasm — network intent (fail-closed check) + FS control
#
# Requirements:
#   cargo with the wasm32-wasip2 target   (rustup target add wasm32-wasip2)
#   wasm-tools                            (brew install wasm-tools)
#
# The committed .wasm binaries are the evidence the harness runs; CI does
# not rebuild them (same policy as tests/fixtures/rebuild.sh).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for crate in fs_probe net_probe; do
  (
    cd "$HERE/src/$crate"
    cargo build --release --target wasm32-wasip2
  )
  wasm-tools strip -a \
    "$HERE/src/$crate/target/wasm32-wasip2/release/$crate.wasm" \
    -o "$HERE/$crate.wasm"
done

echo "component probes regenerated: fs_probe.wasm, net_probe.wasm"
