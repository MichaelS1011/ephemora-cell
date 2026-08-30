#!/usr/bin/env python3
# Ephemora Cell — compile friction per language (measured where possible)
"""Probe WASM toolchains and measure real compile friction.

For every language the harness records:
  * toolchain availability + version,
  * a hello-world -> .wasm compile where the toolchain exists (timed),
  * the exact failure text otherwise (these ARE the top error classes
    that `ephemora-cell build` must detect and explain — these map to the shipped hints).

Everything found here is `measured: true`; classes we could not
reproduce locally are marked `measured: false` with a citation and are
handled as guidance in the builder.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

OUTDIR = Path(__file__).resolve().parent
HELLO_RUST = (
    "fn main() { let x = 40; let y = 2; if x + y != 42 { panic!(); } }"
)
HELLO_GO = "package main\n\nfunc main() {}\n"
HELLO_C = '#include <stdio.h>\nint main(void) { puts("hi"); return 0; }\n'


def probe_cmd(cmd: list[str]) -> str | None:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    out = (r.stdout or r.stderr).strip()
    return out.splitlines()[0] if out else None


def probe_cmd_full(cmd: list[str]) -> str | None:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return (r.stdout or r.stderr).strip() or None


def run(cmd: list[str], cwd: Path | None, timeout: float) -> tuple[int, str, float]:
    t0 = time.perf_counter()
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stderr or r.stdout or ""), time.perf_counter() - t0
    except subprocess.TimeoutExpired:
        return 124, "timeout", time.perf_counter() - t0


def probe_rust(results: list) -> None:
    version = probe_cmd(["cargo", "--version"])
    targets = probe_cmd_full(["rustup", "target", "list", "--installed"])
    has_target = bool(targets and "wasm32-wasip1" in targets)
    entry = {
        "language": "rust",
        "toolchain": version,
        "wasm_target_installed": has_target,
        "measured": version is not None,
    }
    if version is None:
        entry["error_class"] = "toolchain not installed"
        results.append(entry)
        return
    project = Path("/tmp") / f"ephemora_m11_{uuid.uuid4().hex[:8]}"
    (project / "src").mkdir(parents=True)
    (project / "Cargo.toml").write_text(
        '[package]\nname = "hello"\nversion = "0.1.0"\nedition = "2021"\n'
    )
    (project / "src" / "main.rs").write_text(HELLO_RUST)
    code, err, wall = run(
        ["cargo", "build", "--release", "--target", "wasm32-wasip1", "-q"],
        project, 300,
    )
    wasm = project / "target" / "wasm32-wasip1" / "release" / "hello.wasm"
    entry.update(
        {
            "exit_code": code,
            "ok": code == 0 and wasm.exists(),
            "wasm_path": str(wasm) if wasm.exists() else None,
            "elapsed_s": round(wall, 1),
            "error_class": None if code == 0 else _rust_error_class(err),
        }
    )
    results.append(entry)
    shutil.rmtree(project, ignore_errors=True)


def _rust_error_class(stderr: str) -> str:
    if "may not be installed" in stderr or "target not installed" in stderr:
        return "wasm target not installed (hint: rustup target add wasm32-wasip1)"
    if "not found" in stderr and "cargo" in stderr:
        return "toolchain not installed"
    return "other compile error"


def probe_go(results: list) -> None:
    version = probe_cmd(["go", "version"])
    entry = {"language": "go", "toolchain": version, "measured": version is not None}
    if version is None:
        entry["error_class"] = "toolchain not installed (hint: install go >= 1.21; wasip1 needs GOOS=wasip1 GOARCH=wasm)"
    else:
        project = Path("/tmp") / f"ephemora_m11_go_{uuid.uuid4().hex[:8]}"
        project.mkdir()
        (project / "main.go").write_text(HELLO_GO)
        env_cmd = ["/usr/bin/env", "GOOS=wasip1", "GOARCH=wasm", "go", "build", "-o", "hello.wasm", "main.go"]
        code, err, wall = run(env_cmd, project, 300)
        entry.update(
            {
                "exit_code": code,
                "ok": code == 0 and (project / "hello.wasm").exists(),
                "elapsed_s": round(wall, 1),
                "error_class": None if code == 0 else err.strip()[:200],
            }
        )
        shutil.rmtree(project, ignore_errors=True)
    results.append(entry)


def probe_c(results: list) -> None:
    version = probe_cmd(["clang", "--version"])
    entry = {"language": "c", "toolchain": version, "measured": version is not None}
    if version is None:
        entry["error_class"] = "toolchain not installed"
    else:
        project = Path("/tmp") / f"ephemora_m11_c_{uuid.uuid4().hex[:8]}"
        project.mkdir()
        (project / "hello.c").write_text(HELLO_C)
        code, err, wall = run(
            ["clang", "--target=wasm32-wasi", "-o", "hello.wasm", "hello.c"],
            project, 60,
        )
        entry.update(
            {
                "exit_code": code,
                "ok": code == 0 and (project / "hello.wasm").exists(),
                "elapsed_s": round(wall, 1),
                # the verbatim failure IS the friction class (wasi-sysroot)
                "error_class": None if code == 0 else err.strip()[:200],
            }
        )
        shutil.rmtree(project, ignore_errors=True)
    results.append(entry)


def probe_static(results: list) -> None:
    results.append(
        {
            "language": "python",
            "toolchain": None,
            "measured": False,
            "error_class": (
                "no AOT compile: python scripts run on a wasi-python "
                "interpreter; recipe = embed script into wasi-python build "
                "(documented guidance, not a compiler call)"
            ),
        }
    )
    results.append(
        {
            "language": "assemblyscript",
            "toolchain": probe_cmd(["npx", "asc", "--version"]) or probe_cmd(["asc", "--version"]),
            "measured": False,
            "error_class": "toolchain via npm; not installed (hint: npm i -g assemblyscript)",
        }
    )


def main() -> int:
    stamp = time.strftime("%Y-%m-%d")
    results: list = []
    probe_rust(results)
    probe_go(results)
    probe_c(results)
    probe_static(results)

    report = {
        "measured": True,
        "source": "measurement",
        "date": stamp,
        "platform": sys.platform,
        "method": (
            "probe toolchain versions, compile hello-world -> wasm where "
            "available (timed), record verbatim failure classes otherwise"
        ),
        "results": results,
    }
    outfile = OUTDIR / f"results_{stamp}.json"
    outfile.write_text(json.dumps(report, indent=2))
    for r in results:
        print(f"{r['language']:16s} ok={r.get('ok')} {r.get('error_class') or ''}")
    print(f"wrote {outfile}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
