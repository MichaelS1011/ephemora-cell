#!/usr/bin/env bash
# Ephemora Cell — Protected Linux Reference Environment: hardened runner
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
#
# The reference OUTER boundary for the worker process. These flags ARE the
# documented profile; `escape_probe.py` and the protected-worker run below are
# the measurement that the profile is real, not aspirational.
#
#   --network none                     OS-level egress kill (no netns route)
#   --read-only                        immutable rootfs (guest/worker cannot
#                                      persist or tamper image files)
#   --cap-drop=ALL                     no Linux capabilities (no mount, no
#                                      override uid/gid, no raw socket)
#   --security-opt no-new-privileges   setuid/file-cap escalation is blocked
#   --pids-limit                       fork-bomb ceiling (cgroup pids controller)
#   --memory / --memory-swap           cgroup RSS ceiling
#   --cpus                             cgroup CPU bandwidth ceiling
#   --user 10001:10001                 the dedicated unprivileged `cell` UID
#   --tmpfs /tmp:size=64m              bounded worker scratch (no host leak)
#   -v fixtures:/input:ro              the ONLY mounted path: read-only test data
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

# The image name carries the source revision, because a version STRING alone
# cannot tell a released build from a locally built one (`1.1.0` from the
# release branch and `1.1.0` from PyPI are different bytes). Override with IMAGE=...
# when you are deliberately testing a specific prebuilt image.
SRC_SHA="$(cd "${HERE}/../.." && git rev-parse --short=7 HEAD 2>/dev/null || echo unknown)"
IMAGE="${IMAGE:-ephemora-cell-ref:1.1.0-ref.${SRC_SHA}}"

HARDENED=(
  --network none
  --read-only
  --cap-drop=ALL
  --security-opt no-new-privileges:true
  --pids-limit 128
  --memory 512m
  --memory-swap 512m
  --cpus 1.0
  --user 10001:10001
  --tmpfs /tmp:size=64m,mode=1777
  -v "${HERE}/fixtures:/input:ro"
  -v "${HERE}/escape_probe.py:/probe/escape_probe.py:ro"
)

case "${1:-probe}" in
  tag)
    # Print the image tag this harness would test — the string to put in the
    # release-identity manifest so the measurement names its bytes.
    echo "$IMAGE"
    ;;
  probe)
    # Compromised-worker boundary negation tests.
    exec docker run --rm --entrypoint python "${HARDENED[@]}" "$IMAGE" /probe/escape_probe.py
    ;;
  worker)
    # Protected-component worker run driven by a stdin payload (inner wall
    # exercised behind the outer boundary).
    shift
    exec docker run --rm -i "${HARDENED[@]}" "$IMAGE" \
      --wasm /input/hello02.wasm --abi component --payload-stdin
    ;;
  *)
    echo "usage: $0 {tag|probe|worker}" >&2
    exit 2
    ;;
esac
