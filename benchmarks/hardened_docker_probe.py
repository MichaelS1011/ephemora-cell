"""Live-measure the 8 attack vectors inside a HARDENED Docker container.

Middle column of the "Same Attack. Different Boundary." matrix: identical
guest bodies to assets/demo_attack_probe.py (imported, not copied — the
bodies must never drift), identical measurement rule: the measured exit code
decides ALLOWED vs BLOCKED. The only variable is the host-side flag set.

    hardened = exactly these flags — tell us which to add:
      --network none --read-only --cap-drop=ALL
      --security-opt no-new-privileges --pids-limit 64 --user 65534:65534

Docker's default seccomp profile is active in BOTH the stock and the
hardened column. A positive control (a plain payload under the same flags)
must succeed — if it fails, the harness is broken, not the boundary, and the
run does not count.

Pre-declared expectations (attribution): hardening flags wall the container
OFF, not the guest IN. With these flags only the fsync vector is expected to
change (EROFS from --read-only); socket CREATION needs no capability and no
network, so it stays allowed (denial would happen at connect, and the shared
body only creates the socket).
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEST = REPO / "benchmarks/results/2026-09-18"

HARDENED_FLAGS = [
    "--network",
    "none",
    "--read-only",
    "--cap-drop=ALL",
    "--security-opt",
    "no-new-privileges",
    "--pids-limit",
    "64",
    "--user",
    "65534:65534",
]

POSITIVE_CONTROL = "print('SANDBOX_ALIVE')"

# Pre-declared verdict matrix (see module docstring). If measurement deviates,
# that is a finding to investigate — never a reason to edit the expectation.
# Corrections are documented, never silent.
CORRECTIONS = [
    "2026-09-18: initial run expected symlink escape=ALLOWED, measured BLOCKED. "
    "Root cause (committed evidence, detail field): the shared body CREATES the "
    "symlink in /tmp first — --read-only fails that with EROFS (Errno 30) before "
    "any escape attempt. Same flag effect as fsync, so the expectation was "
    "corrected the same day the deviation was measured."
]

EXPECTED = {
    "shell": (
        "ALLOWED",
        "exec + /bin/id available to nobody; cap-drop does not remove exec",
    ),
    "fork": ("ALLOWED", "pids-limit 64 >> 2 processes; fork needs no capability"),
    "socket": (
        "ALLOWED",
        "socket() creation needs no capability and no network; body does not connect",
    ),
    "fsync": (
        "BLOCKED",
        "--read-only: O_CREAT in /tmp fails EROFS (flag effect, not sandbox policy)",
    ),
    "/etc/passwd": (
        "ALLOWED",
        "container's OWN /etc/passwd, world-readable — the guest sees the container world",
    ),
    "symlink escape": (
        "BLOCKED",
        "--read-only: the body creates the symlink in /tmp first — EROFS (Errno 30) "
        "blocks creation before any escape attempt (flag effect, not sandbox policy)",
    ),
    "threads": ("ALLOWED", "threading is a guest-internal primitive"),
    "environment": ("ALLOWED", "env vars are still set; nobody may read them"),
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
            ["docker", "run", "--rm", *HARDENED_FLAGS, image, "python3", "-c", body],
            capture_output=True,
            text=True,
            timeout=60,
        )
        allowed = p.returncode == 0
        return {
            "status": "ALLOWED" if allowed else "BLOCKED",
            "exit_code": p.returncode,
            "detail": (p.stderr.strip().splitlines() or [""])[-1][:80],
        }
    except subprocess.TimeoutExpired:
        return {"status": "BLOCKED", "exit_code": None, "detail": "timeout"}


def main() -> int:
    image, vectors = _load_stock()

    control = probe(image, POSITIVE_CONTROL)
    if control["status"] != "ALLOWED":
        print("POSITIVE CONTROL FAILED — harness broken, run does not count")
        print(json.dumps(control, indent=2))
        return 1

    digest = subprocess.run(
        ["docker", "image", "inspect", image, "--format", "{{index .RepoDigests 0}}"],
        capture_output=True,
        text=True,
    ).stdout.strip()

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
        "image_digest": digest,
        "hardened_flags": HARDENED_FLAGS,
        "seccomp": "Docker default seccomp profile active in both stock and hardened columns",
        "positive_control": control,
        "results": out,
        "blocked_count": blocked,
        "expectation_matches": matched,
        "expectation_total": len(EXPECTED),
        "corrections": CORRECTIONS,
        "docker_version": subprocess.run(
            ["docker", "version", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
        ).stdout.strip(),
    }
    DEST.mkdir(parents=True, exist_ok=True)
    path = DEST / "01_hardened_docker_attack_probe.json"
    path.write_text(json.dumps(doc, indent=2))
    print(
        f"Hardened Docker: {8 - blocked}/8 ALLOWED ({blocked}/8 blocked, "
        f"{matched}/{len(EXPECTED)} expectations matched)"
    )
    print(f"Saved: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
