"""Live-measure the 8 attack vectors inside a gVisor (runsc) container.

Fourth boundary column of the "Same Attack. Different Boundary." matrix:
identical guest bodies to assets/demo_attack_probe.py (imported, not
copied — the bodies must never drift), identical measurement rule: the
measured exit code decides ALLOWED vs BLOCKED. The only variable is the
runtime: stock Docker runs runc, this probe runs gVisor's userspace
kernel.

    gVisor = exactly this flag — tell us if we should measure another
    combination: --runtime runsc (Docker defaults otherwise)

gVisor protects the HOST from the container via a userspace kernel
(systrap platform); the GUEST still sees a full Linux ABI. Pre-declared
expectation: all 8 guest primitives stay ALLOWED — the matrix column
documents that difference of direction, not a ranking. A deviation from
the expectation is a finding to investigate, never a reason to silently
edit the expectation (CORRECTIONS are documented, like every probe run).

Positive control: a plain payload under the same runtime MUST succeed —
if it fails, the harness is broken, not the boundary, and the run does
not count (exit 1, no evidence written).

Evidence: benchmarks/results/<date>/08_gvisor_docker_attack_probe.json
(measured:true). Docker image digest is RECORDED (not pinned into the
run command); runsc version recorded alongside.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEST = REPO / "benchmarks/results" / time.strftime("%Y-%m-%d")

GVISOR_FLAGS = ["--runtime", "runsc"]

POSITIVE_CONTROL = "print('SANDBOX_ALIVE')"

# Pre-declared verdict matrix. The gVisor syscall table (amd64) documents
# execve/fork/socket/fsync/open/symlink/clone as supported; the guest sees
# a Linux ABI, so these guest primitives stay available to it.
CORRECTIONS: list[str] = []

EXPECTED = {
    "shell": (
        "ALLOWED",
        "gVisor implements execve in its userspace kernel (Full Support) — "
        "the guest sees a working /bin/sh",
    ),
    "fork": (
        "ALLOWED",
        "fork/vfork Full Support per the gVisor syscall table",
    ),
    "socket": (
        "ALLOWED",
        "socket() creation is Full Support; runsc ships its own netstack — "
        "raw sockets are off by default, our TCP-socket creation is not raw",
    ),
    "fsync": (
        "ALLOWED",
        "fsync Full Support; the stock-gVisor column carries no --read-only "
        "flag, so no EROFS effect",
    ),
    "/etc/passwd": (
        "ALLOWED",
        "container's OWN /etc/passwd, world-readable — the guest sees the "
        "container world gVisor presents",
    ),
    "symlink escape": (
        "ALLOWED",
        "symlink/readlink Full Support; symlinks inside the container FS "
        "work for the guest",
    ),
    "threads": (
        "ALLOWED",
        "clone/clone3 supported (partial only for CLONE_NEWTIME/"
        "CLONE_SYSVSEM, unused here); gVisor is regression-tested against "
        "Python",
    ),
    "environment": (
        "ALLOWED",
        "environment passes through the container config; no documented "
        "gVisor restriction",
    ),
}


def _load_stock() -> tuple[str, dict[str, str]]:
    """Import IMAGE and VECTORS from the stock probe so bodies cannot drift."""
    spec = importlib.util.spec_from_file_location(
        "demo_attack_probe", REPO / "assets/demo_attack_probe.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.IMAGE, mod.VECTORS


def probe(image: str, body: str) -> dict:
    try:
        p = subprocess.run(
            ["docker", "run", "--rm", *GVISOR_FLAGS, image, "python3", "-c", body],
            capture_output=True,
            text=True,
            timeout=120,
        )
        allowed = p.returncode == 0
        return {
            "status": "ALLOWED" if allowed else "BLOCKED",
            "exit_code": p.returncode,
            "detail": (p.stderr.strip().splitlines() or [""])[-1][:120],
        }
    except subprocess.TimeoutExpired:
        return {"status": "BLOCKED", "exit_code": None, "detail": "timeout"}


def _image_digest(image: str) -> str | None:
    """Record-only: the digest of the image the daemon resolved (never a
    pin inside the run command). Empty on inspect failure — surfaced."""
    try:
        p = subprocess.run(
            [
                "docker",
                "image",
                "inspect",
                image,
                "--format",
                "{{index .RepoDigests 0}}",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        d = p.stdout.strip()
        return d if p.returncode == 0 and d else None
    except Exception as e:
        return f"inspect-error: {e}"[:80]


def _tool_version(cmd: list[str]) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return (p.stdout.strip().splitlines() or [p.stderr.strip()])[0][:120]
    except Exception as e:
        return f"version-error: {e}"[:80]


def main() -> int:
    image, vectors = _load_stock()

    control = probe(image, POSITIVE_CONTROL)
    if control["status"] != "ALLOWED":
        print("POSITIVE CONTROL FAILED — harness broken, run does not count")
        print(json.dumps(control, indent=2))
        return 1

    out: dict = {}
    matched = 0
    for name, body in vectors.items():
        r = probe(image, body)
        exp_status, attribution = EXPECTED[name]
        r["expected"] = exp_status
        r["attribution"] = attribution
        r["matches_expectation"] = r["status"] == exp_status
        matched += r["matches_expectation"]
        out[name] = r
        print(f"  {name:<16} {r['status']:<8} (expected {exp_status})")

    blocked = sum(1 for r in out.values() if r["status"] == "BLOCKED")
    doc = {
        "measured": True,
        "date": time.strftime("%Y-%m-%d"),
        "image": image,
        "image_digest": _image_digest(image),
        "gvisor_flags": GVISOR_FLAGS,
        "runsc_version": _tool_version(["runsc", "--version"]),
        "docker_version": _tool_version(
            ["docker", "version", "--format", "{{.ServerVersion}}"]
        ),
        "note": (
            "gVisor (userspace kernel, systrap platform) protects the HOST "
            "from the container; the guest sees a Linux ABI, so guest "
            "primitives stay available. This column documents that "
            "direction, not a ranking. Digest is recorded, not pinned."
        ),
        "positive_control": control,
        "results": out,
        "blocked_count": blocked,
        "expectation_matches": matched,
        "expectation_total": len(EXPECTED),
        "corrections": CORRECTIONS,
    }
    DEST.mkdir(parents=True, exist_ok=True)
    path = DEST / "08_gvisor_docker_attack_probe.json"
    path.write_text(json.dumps(doc, indent=2))
    print(
        f"gVisor (runsc): {8 - blocked}/8 ALLOWED ({blocked}/8 blocked, "
        f"{matched}/{len(EXPECTED)} expectations matched)"
    )
    print(f"Saved: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
