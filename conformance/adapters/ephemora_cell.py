"""Ephemora Cell runtime adapter for the WebAssembly/wasi-testsuite runner.

The suite invokes each test in a fresh subprocess by building a command
line from ``compute_argv``. We map every test onto the real CLI path:

    ephemora-cell run <test.wasm> --allow-env K=V --allow-dirs <root> \
        --fuel <FUEL> --timeout <T> [-- --args...]

so the conformance run exercises the shipped command, not a private
integration shortcut.

Policy knobs are raised above CLI defaults (fuel) so that tests fail on
WASI semantics, never on Cell's default resource budgets. Deliberately
blocked surfaces (import-level rejection, output cap, preopen
default-deny) are declared in conformance/expectations.toml as
``expected = "fail"`` with a reason — the suite's native expectations
mechanism, not a fork of the runner.
"""

import os
import shlex
import subprocess
import sys
from importlib.metadata import version as _pkg_version
from pathlib import Path

# EPHEMORA_CELL overrides the command; default is the console script
# installed next to the interpreter running the test-runner.
_CELL = shlex.split(os.getenv("EPHEMORA_CELL", ""), posix=os.name != "nt")
if not _CELL:
    _sibling = Path(sys.executable).parent / "ephemora-cell"
    _CELL = [_sibling.name if not _sibling.exists() else str(_sibling)]

# 100M fuel: headroom for compute-heavy tests (e.g. big_random_buf) so a
# failure means WASI non-conformance, not budget exhaustion.
_FUEL = os.getenv("EPHEMORA_CELL_FUEL", "100000000")
_TIMEOUT = os.getenv("EPHEMORA_CELL_TIMEOUT", "30")


def get_name() -> str:
    return "ephemora-cell"


def get_version() -> str:
    try:
        return _pkg_version("ephemora-cell")
    except Exception:
        result = subprocess.run(
            [*_CELL, "--version"], encoding="UTF-8", capture_output=True, check=True
        )
        return result.stdout.split()[-1]


def get_wasi_versions() -> list[str]:
    # Cell implements WASI Preview 1 (snapshot preview1) and WASI 0.2
    # components; the suite's preview-1 tests are the conformance target.
    return ["wasm32-wasip1"]


def get_wasi_worlds() -> list[str]:
    return ["wasi:cli/command"]


def get_timeout_seconds() -> float:
    return float(_TIMEOUT)


def compute_argv(
    test_path: str,
    args_env_root: tuple[list[str], dict[str, str], str | None],
    proposals: list[str],
    wasi_world: str,
    wasi_version: str,
) -> list[str]:
    args, env, root = args_env_root
    argv = [*list(_CELL), "run"]
    # test_path first: argparse assigns anything after a trailing
    # nargs="*" option (--allow-dirs/--allow-env) to that option, not to
    # the module positional.
    argv.append(test_path)
    argv += ["--fuel", _FUEL, "--timeout", _TIMEOUT]
    # The runner holds the guest's stdin pipe open; Cell's piped-stdin
    # auto-capture would block on it until the timeout. /dev/null gives
    # immediate EOF (tests that need real stdin content fail and are
    # triaged, instead of every test stalling).
    argv += ["--stdin", os.devnull]
    for k, v in env.items():
        argv += ["--allow-env", f"{k}={v}"]
    if root:
        # wasi-libc resolves relative paths against the preopen named "/"
        # (wasmtime's --dir host::/ convention) — use the host::guest
        # mapping so the suite's C/Rust binaries see the fixture at "/".
        argv += ["--allow-dirs", f"{root}::/"]
    if args:
        argv += ["--", *args]
    return argv
