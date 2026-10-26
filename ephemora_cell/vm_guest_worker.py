# Ephemora Cell — guest entrypoint for the hvc1 product channel
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Run the real product worker behind the dedicated hvc1 console.

The guest never chooses its identity or job: the host sends both over the
console, and the host mediates every frame. This entrypoint only opens the
channel, runs the worker, and reports the worker's JSON.
"""

from __future__ import annotations

import os
import sys
import tty

from .vm_hvc1 import SerialFrameTransport, run_guest_agent


def main() -> int:
    fd = os.open("/dev/hvc1", os.O_RDWR)
    try:
        tty.setraw(fd)
    except OSError:
        pass
    transport = SerialFrameTransport(
        lambda count: os.read(fd, count),
        lambda data: os.write(fd, data),
    )
    try:
        report = run_guest_agent(transport)
    except Exception as exc:
        print(f"GUEST_AGENT_ERROR {exc!r}", file=sys.stderr, flush=True)
        return 2
    print(f"GUEST_WORKER_STATUS {report.get('status', 'error')}", flush=True)
    print("GUEST_DONE", flush=True)
    return 0 if report.get("status") == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
