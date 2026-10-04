#!/usr/bin/env bash
# Regenerate the WASI 0.2 component probes for the CVE replay
# (benchmarks/mcp_cve_replay.py, component branch) and the advisory
# evidence harness (benchmarks/datetime_overflow_probe.py):
#   fs_probe.wasm    — EscapeRoute intents (CVE-2025-53109/53110)
#   net_probe.wasm   — network intent (fail-closed check) + FS control
#   times_probe.wasm — GHSA-j2g9-4prp-pf6h datetime overflow (its
#                      default in-process run aborts the host process,
#                      so it must never be executed inside a shared
#                      harness process — see the evidence harness)
#   sync_probe.wasm  — WASI 0.2 sync surface (descriptor/sync +
#                      /sync-data through std), measured by
#                      benchmarks/component_sync_probe.py
#
# Requirements:
#   cargo with the wasm32-wasip2 target   (rustup target add wasm32-wasip2)
#   wasm-tools                            (brew install wasm-tools)
#
# These .wasm files are BUILD ARTIFACTS and are NOT committed (.gitignore
# excludes *.wasm with no exception here). SECURITY.md and CHANGELOG.md cite
# them as the fixture of DATED measurements, so fixtures.json records the
# sha256 of exactly the bytes those measurements ran on, and this script
# checks against it rather than silently replacing them:
#
#   * the default run writes into .rebuilt/ and never touches the artifacts
#     the evidence names — rebuilding is not allowed to destroy evidence;
#   * a hash mismatch is reported, not treated as permission to edit
#     fixtures.json. Different bytes are a different experiment: re-run the
#     measurement and re-date it, or restore the source.
#   * CI does NOT rebuild these (the builder job installs wasm32-wasip1
#     only, not wasm32-wasip2 + wasm-tools). The gate CI runs is
#     tests/test_component_probe_fixtures.py, which checks the manifest
#     against the sources, the docs and the words in this script.
#
# --install moves the rebuilt bytes over benchmarks/component_probes/*.wasm.
# Only do that when you intend the rebuilt binaries to become the working
# fixtures, and expect fixtures.json to report drift afterwards.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="$HERE/fixtures.json"
OUT="$HERE/.rebuilt"

INSTALL=0
for arg in "$@"; do
  case "$arg" in
    --install) INSTALL=1 ;;
    *) echo "usage: rebuild.sh [--install]" >&2; exit 2 ;;
  esac
done

command -v python3 >/dev/null || { echo "rebuild.sh needs python3" >&2; exit 1; }

pin() { # pin <fixture-name> <field>
  python3 -c '
import json, sys
doc = json.load(open(sys.argv[1]))["fixtures"]
name = sys.argv[2]
if name not in doc:
    sys.exit("fixtures.json has no entry for " + name)
print(doc[name][sys.argv[3]])
' "$MANIFEST" "$1" "$2"
}

sha() { # sha <file>
  python3 -c '
import hashlib, sys
print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())
' "$1"
}

mkdir -p "$OUT"
drift=0

for crate in fs_probe net_probe times_probe sync_probe; do
  (
    cd "$HERE/src/$crate"
    cargo build --release --target wasm32-wasip2
  )
  wasm-tools strip -a \
    "$HERE/src/$crate/target/wasm32-wasip2/release/$crate.wasm" \
    -o "$OUT/$crate.wasm"

  want="$(pin "$crate.wasm" sha256)"
  got="$(sha "$OUT/$crate.wasm")"

  if [ -f "$HERE/$crate.wasm" ]; then
    on_disk="$(sha "$HERE/$crate.wasm")"
    if [ "$on_disk" = "$want" ]; then
      echo "$crate.wasm: on-disk bytes match the pin"
    else
      echo "$crate.wasm: DRIFT — on-disk bytes are $on_disk, fixtures.json pins $want" >&2
      drift=1
    fi
  else
    echo "$crate.wasm: not present (never committed); fixtures.json pins $want"
  fi

  if [ "$got" = "$want" ]; then
    echo "$crate.wasm: rebuild matches the pin"
  else
    echo "$crate.wasm: rebuild differs from the pinned evidence bytes ($got)" >&2
    echo "  That is expected across toolchain revisions. Do NOT edit fixtures.json" \
         "to match; re-run the measurement and re-date it." >&2
  fi

  if [ "$INSTALL" = 1 ]; then
    cp "$OUT/$crate.wasm" "$HERE/$crate.wasm"
    echo "$crate.wasm: installed over the working fixture"
  fi
done

if [ "$drift" = 1 ]; then
  echo "rebuild.sh: the artifacts on disk are not the bytes the dated evidence names." >&2
  exit 1
fi

echo "component probes rebuilt into $OUT: fs_probe.wasm, net_probe.wasm, times_probe.wasm, sync_probe.wasm$([ "$INSTALL" = 1 ] && echo ' (installed)')"
