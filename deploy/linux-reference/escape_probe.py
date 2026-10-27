# Ephemora Cell — Protected Linux Reference Environment: boundary probe
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""Negativtests der ÄUSSEREN Host-Grenze, gemessen von einem vollständig
kompromittierten Worker aus.

Der Worker-Prozess ist die INNERE Wand (WASI-Sandbox + RLIMITs + Budgets).
Dieses Skript modelliert das Worst-Case-Szenario, das ein reiner Worker-Prozess
NICHT abfängt: der native Code im Worker ist bereits kompromittiert (z. B. ein
Engine-Speicherfehler, der zu arbiträren Syscalls führt). Dann ist die
Betriebssystem-Grenze des Containers die letzte Instanz.

Jede Prüfung meldet ALLOWED (Grenze durchlässig = Fund) oder BLOCKED
(Grenze hält = erwartet). Positivkontrolle: ein erlaubter Lese-/Schreibzugriff
auf das tmpfs muss gelingen — schlägt er fehl, ist das Harness defekt und der
Lauf zählt nicht.

Ausführung NUR innerhalb des gehärteten Containers (see run.sh):
    python /probe/escape_probe.py
"""

from __future__ import annotations

import json
import os
import socket
import sys
import time

VERDICTS: dict[str, dict] = {}


def _record(name: str, allowed: bool, detail: str) -> None:
    # allowed=True => the compromised worker REACHED something (a finding).
    VERDICTS[name] = {
        "status": "ALLOWED" if allowed else "BLOCKED",
        "detail": detail[:180],
    }


def check_identity() -> None:
    # The worker must NOT be uid 0; a non-root uid cannot read shadow.
    _record(
        "runs_as_nonroot",
        os.getuid() == 0,
        f"uid={os.getuid()} gid={os.getgid()}",
    )


def check_capabilities() -> None:
    capeff = "n/a"
    try:
        with open("/proc/self/status") as fh:
            for line in fh:
                if line.startswith("CapEff:"):
                    capeff = line.split()[1]
                    break
    except OSError as exc:
        capeff = f"unreadable:{exc.errno}"
    # cap-drop=ALL => CapEff is 0000000000000000
    full = capeff != "n/a" and not capeff.startswith("unreadable")
    has_caps = full and capeff.strip("0") != ""
    _record("capabilities_dropped", has_caps, f"CapEff={capeff}")


def check_privilege_escalation() -> None:
    # A compromised worker must not be able to setuid back to root.
    try:
        os.setuid(0)
        allowed = True  # escaping to root — a finding
        detail = f"setuid(0) succeeded, now uid={os.getuid()}"
    except OSError as exc:
        allowed = False
        detail = f"setuid(0) refused: errno {exc.errno} ({exc.strerror})"
    _record("no_setuid_to_root", allowed, detail)


def check_read_only_rootfs() -> None:
    path = "/opt/cell/pwn.txt"
    try:
        with open(path, "w") as fh:
            fh.write("x")
        allowed = True
        detail = "wrote to rootfs (image layer is writable)"
    except OSError as exc:
        allowed = False
        detail = f"rootfs write refused: errno {exc.errno} ({exc.strerror})"
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    _record("rootfs_read_only", allowed, detail)

    # tmpfs /tmp IS writable (needed by the worker scratch) — positive control:
    # a permitted operation, so ALLOWED is the expected verdict here.
    tmp = "/tmp/_pc.txt"
    try:
        with open(tmp, "w") as fh:
            fh.write("ok")
        with open(tmp) as fh:
            ok = fh.read() == "ok"
        _record("tmpfs_writable_positive_control", ok, f"writable={ok}")
    except OSError as exc:
        _record("tmpfs_writable_positive_control", True, f"tmpfs failed: {exc}")
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def check_host_filesystem() -> None:
    # The container sees its OWN /etc/passwd, not a host bind. There is no host
    # path mounted read-write; try to reach a host-only artifact.
    for probe_path in ("/etc/shadow", "/root"):
        try:
            with open(probe_path):
                allowed = True
                detail = f"read {probe_path}"
        except OSError as exc:
            allowed = False
            detail = f"{probe_path} refused: errno {exc.errno}"
        _record(
            f"host_secret_{probe_path.strip('/').replace('/', '_')}", allowed, detail
        )


def check_network_egress() -> None:
    # --network none: no routable interface. Any connect must fail immediately.
    for target in (("8.8.8.8", 443), ("1.1.1.1", 53)):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        try:
            s.connect(target)
            allowed = True
            detail = f"connected to {target}"
        except OSError as exc:
            allowed = False
            detail = f"{target} refused: errno {exc.errno} ({exc.strerror})"
        finally:
            s.close()
        _record(f"egress_{target[0]}", allowed, detail)

    # DNS should also be unavailable (no resolv path off a real netns).
    try:
        socket.getaddrinfo("example.com", 443)
        allowed = True
        detail = "resolved example.com"
    except OSError as exc:
        allowed = False
        detail = f"resolution refused: {exc.args}"
    _record("egress_dns", allowed, detail)


def check_pid_limit() -> None:
    limit = os.path.join("/sys/fs/cgroup", "pids.max")
    cap = "n/a"
    try:
        with open(limit) as fh:
            cap = fh.read().strip()
    except OSError:
        # cgroup v1 path
        try:
            with open("/sys/fs/cgroup/pids/pids.max") as fh:
                cap = fh.read().strip()
        except OSError as exc:
            cap = f"unreadable:{exc.errno}"
    # Fork until EAGAIN; must be bounded well below an unbounded fork bomb.
    children = 0
    try:
        for _ in range(2000):
            pid = os.fork()
            if pid == 0:  # child
                time.sleep(0.2)
                os._exit(0)
            children += 1
    except OSError as exc:
        detail = f"fork blocked at {children} children: errno {exc.errno}"
    else:
        detail = f"forked {children} without EAGAIN"
    # BLOCKED (good) if the kernel refused before we could burn the host.
    bomb_unbounded = "blocked" not in detail
    _record("pids_limit", bomb_unbounded, f"{cap=} ; {detail}")
    # reap our children
    for _ in range(children):
        try:
            os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            break


def check_memory_limit() -> None:
    cap = "n/a"
    for p in (
        "/sys/fs/cgroup/memory.max",
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
    ):
        try:
            with open(p) as fh:
                cap = fh.read().strip()
            break
        except OSError:
            continue
    _record("memory_cgroup_present", cap in ("n/a", "max"), f"memory.max={cap}")


def main() -> int:
    check_identity()
    check_capabilities()
    check_privilege_escalation()
    check_read_only_rootfs()
    check_host_filesystem()
    check_network_egress()
    check_memory_limit()
    check_pid_limit()  # last: it forks
    blocked = sum(1 for v in VERDICTS.values() if v["status"] == "BLOCKED")
    allowed = sum(1 for v in VERDICTS.values() if v["status"] == "ALLOWED")
    doc = {
        "measured": True,
        "date": time.strftime("%Y-%m-%d"),
        "note": (
            "Compromised-worker boundary probe: BLOCKED = the OS/container wall "
            "still holds even with native code in the worker fully attacker-"
            "controlled. The positive control (tmpfs writable) must be ALLOWED."
        ),
        "results": VERDICTS,
        "blocked_count": blocked,
        "allowed_findings": allowed,
    }
    sys.stdout.write(json.dumps(doc, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
