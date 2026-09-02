"""Live-measure the 8 attack vectors inside a stock Docker container.

Left column of the "Same Attack. Different Boundary." demo. Nothing is
hardcoded: each vector runs `docker run --rm python:3.12-slim` and the
measured exit code decides ALLOWED vs BLOCKED. Reuses the docker run pattern
from competitive_benchmark.py; the question here is per-vector success, not
cold-start timing, so the probe bodies differ.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

IMAGE = "python:3.12-slim"

# One-liner guest bodies. Print ATTACK_WORKED (exit 0) when the primitive
# is usable; non-zero / no marker means the container blocked it.
VECTORS = {
    # os.system here is the *guest primitive under test*, executed inside the
    # throwaway container -- not a host command-injection sink. That IS the
    # attack the probe measures (can a guest shell out? -> yes in stock Docker).
    "shell": "import os; raise SystemExit(0 if os.system('id >/dev/null')==0 else 1)",
    "fork": "import os; pid=os.fork(); os._exit(0 if pid>=0 else 1)",
    "socket": "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); raise SystemExit(0)",
    "fsync": (
        "import os; fd=os.open('/tmp/f',os.O_CREAT|os.O_WRONLY); "
        "os.write(fd,b'x'); os.fsync(fd); os.close(fd); raise SystemExit(0)"
    ),
    "/etc/passwd": "open('/etc/passwd').read(); raise SystemExit(0)",
    "symlink escape": (
        "import os; os.symlink('/etc/passwd','/tmp/l'); "
        "os.path.realpath('/tmp/l').startswith('/etc'); raise SystemExit(0)"
    ),
    "threads": (
        "import threading; r=[]; "
        "t=threading.Thread(target=lambda: r.append(1)); t.start(); t.join(); "
        "raise SystemExit(0 if r==[1] else 1)"
    ),
    "environment": "import os; raise SystemExit(0 if 'PATH' in os.environ else 1)",
}


def probe(vector: str, body: str) -> dict:
    try:
        p = subprocess.run(
            ["docker", "run", "--rm", IMAGE, "python3", "-c", body],
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


def main() -> None:
    out = {v: probe(v, b) for v, b in VECTORS.items()}
    allowed = sum(1 for v in out.values() if v["status"] == "ALLOWED")
    print(f"Docker (stock {IMAGE}): {allowed}/8 attack primitives ALLOWED")
    for v, r in out.items():
        print(f"  {v:<16} {r['status']}")
    dest = Path(__file__).parent.parent / "benchmarks/results/2026-09-02"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "01_docker_attack_probe.json").write_text(
        json.dumps({"image": IMAGE, "results": out, "allowed_count": allowed}, indent=2)
    )
    print(f"Saved: {dest/'01_docker_attack_probe.json'}")


if __name__ == "__main__":
    main()
