# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""No unsafe execution fallback (v1.2 v1.2).

A native binary, a script, or a bare command name must never be executed by
``run`` — and must never be silently reinterpreted as a guest. These cases drive
the real CLI process so the exit code is the one a user gets.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ECHO_WASM = os.path.join(REPO, "ephemora_cell_mcp", "tools", "echo.wasm")


def _run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "ephemora_cell.cli", *args],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=REPO,
    )


def _write(path, data: bytes) -> str:
    with open(path, "wb") as handle:
        handle.write(data)
    return str(path)


# --- negatives: a native target is refused, never run ----------------------


@pytest.mark.skipif(not os.path.exists("/bin/echo"), reason="no /bin/echo to point at")
def test_a_system_binary_is_refused_by_name():
    result = _run_cli("run", "/bin/echo")
    assert result.returncode == 2, result.stdout + result.stderr
    assert "not a WebAssembly module" in result.stderr
    assert "never executes native" in result.stderr


def test_a_fake_elf_is_refused(tmp_path):
    elf = _write(tmp_path / "a.out", b"\x7fELF\x02\x01\x01" + b"\x00" * 60)
    result = _run_cli("run", elf)
    assert result.returncode == 2
    assert "ELF executable" in result.stderr


def test_a_fake_macho_is_refused(tmp_path):
    macho = _write(tmp_path / "a.bin", b"\xcf\xfa\xed\xfe" + b"\x00" * 60)
    result = _run_cli("run", macho)
    assert result.returncode == 2
    assert "Mach-O" in result.stderr


def test_a_shebang_script_is_refused(tmp_path):
    script = tmp_path / "s.sh"
    script.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    result = _run_cli("run", str(script))
    assert result.returncode == 2
    assert "script with a shebang" in result.stderr


def test_a_bare_command_name_is_not_executed():
    result = _run_cli("run", "claude")
    assert result.returncode != 0
    assert "WASM module not found" in (result.stdout + result.stderr)


def test_the_language_route_never_falls_back_to_a_host_interpreter(tmp_path):
    """--language python with a native target refuses; it does not run python."""
    target = _write(tmp_path / "tool", b"\x7fELF" + b"\x00" * 60)
    result = _run_cli("run", target, "--language", "python")
    assert result.returncode != 0
    joined = result.stdout + result.stderr
    assert "no python guest is installed" in joined
    # No fallback of any kind: nothing is downloaded and no host interpreter runs.
    assert "nothing was downloaded" in joined


# --- positive control: a real module is NOT refused ------------------------


def test_a_real_wasm_module_still_runs():
    """The guard must not over-block: a valid guest keeps working."""
    assert os.path.exists(ECHO_WASM)
    result = _run_cli("run", ECHO_WASM)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "not a WebAssembly module" not in result.stderr
    # It really executed: the echo tool answers with a JSON object.
    assert json.loads(result.stdout.strip().splitlines()[-1]) == {"echo": None}


# --- the guard itself (mutation-style unit check) --------------------------


def test_the_guard_fires_on_native_magic_and_not_on_wasm(tmp_path):
    from ephemora_cell.cli import _refuse_native_executable

    for index, payload in enumerate(
        (
            b"\x7fELF" + b"\x00" * 16,
            b"\xcf\xfa\xed\xfe" + b"\x00" * 16,
            b"#!/bin/sh\n",
        )
    ):
        candidate = tmp_path / f"native_{index}.bin"
        candidate.write_bytes(payload)
        with pytest.raises(SystemExit):
            _refuse_native_executable(str(candidate))

    # A real module's magic must pass the guard untouched.
    assert _refuse_native_executable(ECHO_WASM) is None
