# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""The remaining write-side failure paths around the 75_536-byte capture cap.

The established tests cover the normal flood, the exact cap, the empty second
stream and FIFO creation failure. This file adds the paths that used to rely on
a worker report: simultaneous streams, a worker killed at the cap, a parent
killed while the guest is writing, a closed reader, and the component
timeout/memory routes. The host-owned capture file, not the guest and not the
worker report alone, decides whether the cap was hit.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
import wasmtime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import WASIConfig, WASISandbox
from ephemora_cell._sandbox_common import (
    OUTPUT_FILE_HARD_LIMIT,
    make_output_fifo,
    start_output_cap_reader,
)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HARD = OUTPUT_FILE_HARD_LIMIT


def _flood_both(tmp_path) -> Path:
    size = 8 * 1024 * 1024
    pages = (2 * size + 65535) // 65536 + 2
    wat = f"""(module
      (import "wasi_snapshot_preview1" "fd_write"
        (func $fd_write (param i32 i32 i32 i32) (result i32)))
      (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
      (memory (export "memory") {pages})
      (func (export "_start")
        (i32.store (i32.const 0) (i32.const 65536))
        (i32.store (i32.const 4) (i32.const {size}))
        (i32.store (i32.const 8) (i32.const {65536 + size}))
        (i32.store (i32.const 12) (i32.const {size}))
        (drop (call $fd_write (i32.const 1) (i32.const 0)
          (i32.const 1) (i32.const 32)))
        (drop (call $fd_write (i32.const 2) (i32.const 8)
          (i32.const 1) (i32.const 36)))
        (call $proc_exit (i32.const 0))))"""
    path = tmp_path / "both.wasm"
    path.write_bytes(wasmtime.wat2wasm(wat))
    return path


def _flood_then_yield(tmp_path) -> Path:
    """One 8-MiB stdout flood, then yield forever (stays alive to be killed)."""
    size = 8 * 1024 * 1024
    pages = (size + 65535) // 65536 + 2
    wat = f"""(module
      (import "wasi_snapshot_preview1" "fd_write"
        (func $fd_write (param i32 i32 i32 i32) (result i32)))
      (import "wasi_snapshot_preview1" "sched_yield"
        (func $yield (result i32)))
      (memory (export "memory") {pages})
      (func (export "_start")
        (i32.store (i32.const 0) (i32.const 65536))
        (i32.store (i32.const 4) (i32.const {size}))
        (drop (call $fd_write (i32.const 1) (i32.const 0)
          (i32.const 1) (i32.const 32)))
        (loop $l (drop (call $yield)) (br $l))))"""
    path = tmp_path / "yield.wasm"
    path.write_bytes(wasmtime.wat2wasm(wat))
    return path


def _flood_until_error(tmp_path) -> Path:
    """Write 1-MiB chunks; exit non-zero as soon as the sink refuses a write."""
    size = 1024 * 1024
    pages = (size + 65535) // 65536 + 1
    wat = f"""(module
      (import "wasi_snapshot_preview1" "fd_write"
        (func $fd_write (param i32 i32 i32 i32) (result i32)))
      (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
      (memory (export "memory") {pages})
      (func (export "_start")
        (i32.store (i32.const 0) (i32.const 65536))
        (i32.store (i32.const 4) (i32.const {size}))
        (loop $l
          (if (i32.ne (call $fd_write (i32.const 1) (i32.const 0)
                        (i32.const 1) (i32.const 32)) (i32.const 0))
            (then (call $proc_exit (i32.const 1))))
          (br $l))))"""
    path = tmp_path / "error.wasm"
    path.write_bytes(wasmtime.wat2wasm(wat))
    return path


def _peak_monitor(base: Path):
    peak = {"stdout": 0, "stderr": 0}
    stop = threading.Event()

    def monitor() -> None:
        while not stop.is_set():
            for name, key in (("stdout.txt", "stdout"), ("stderr.txt", "stderr")):
                path = next(base.rglob(name), None)
                if path is not None:
                    try:
                        peak[key] = max(peak[key], path.stat().st_size)
                    except OSError:
                        pass
            time.sleep(0.001)

    thread = threading.Thread(target=monitor, daemon=True)
    thread.start()
    return peak, stop, thread


def _sandbox(base: Path, **overrides) -> WASISandbox:
    kwargs = {
        "max_memory_mb": 512,
        "max_fuel": 50_000_000,
        "timeout_seconds": 30,
        "sandbox_base_dir": str(base),
    }
    kwargs.update(overrides)
    return WASISandbox(WASIConfig(**kwargs))


def test_simultaneous_stdout_and_stderr_flood_hits_both_caps(tmp_path, monkeypatch):
    monkeypatch.setenv("EPHEMORA_WORKER_OUTPUT_SINK", "1")
    base = tmp_path / "sandbox"
    base.mkdir()
    peak, stop, monitor = _peak_monitor(base)
    try:
        result = _sandbox(base).run(
            str(_flood_both(tmp_path)), use_subprocess=True, trust="unknown"
        )
    finally:
        stop.set()
        monitor.join(timeout=1)

    assert result.output_files_exceeded is True
    assert peak["stdout"] <= HARD and peak["stderr"] <= HARD
    # The monitors are 1 ms samplers; under load they can miss a stream that
    # is already capped. The result markers are the deterministic proof that
    # BOTH captures reached the write-side bound; the peak remains the
    # no-overshoot witness.
    assert result.stdout and result.stderr
    assert result.stdout.endswith("\n[... truncated]")
    assert result.stderr.endswith("\n[... truncated]")
    assert "sink-epoch" not in result.stderr


def test_a_worker_killed_at_the_cap_still_attests_the_cap(tmp_path, monkeypatch):
    monkeypatch.setenv("EPHEMORA_WORKER_OUTPUT_SINK", "1")
    import ephemora_cell.process_executor as pe

    base = tmp_path / "sandbox"
    base.mkdir()
    module = _flood_then_yield(tmp_path)
    original = pe._spawn_worker

    def kill_at_cap(cmd, payload, process_timeout, env):
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            env=env,
        )
        proc.stdin.write(payload)
        proc.stdin.close()
        proc.stdin = None
        deadline = time.monotonic() + 2.0
        cap_seen = False
        while time.monotonic() < deadline:
            for path in Path(env["TMPDIR"]).rglob("stdout.txt"):
                try:
                    if path.stat().st_size >= HARD:
                        cap_seen = True
                        break
                except OSError:
                    pass
            if cap_seen:
                break
            time.sleep(0.002)
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass
        out, err = proc.communicate()
        assert cap_seen, "the guest never reached the capture cap"
        return proc.returncode, out, err

    pe._spawn_worker = kill_at_cap
    peak, stop, monitor = _peak_monitor(base)
    try:
        result = _sandbox(base).run(str(module), use_subprocess=True, trust="unknown")
    finally:
        pe._spawn_worker = original
        stop.set()
        monitor.join(timeout=1)

    assert result.worker_crashed is True
    # No report survived the SIGKILL; the parent's scan of the host-owned
    # capture file is what proves the cap.
    assert result.output_files_exceeded is True
    assert peak["stdout"] <= HARD
    assert "panic" not in result.stderr


def test_a_missing_worker_flag_is_overridden_by_the_host_capture(tmp_path, monkeypatch):
    import ephemora_cell.process_executor as pe

    def report_but_hide_the_cap(cmd, payload, process_timeout, env):
        capture = Path(env["TMPDIR"]) / "ephemora_cell_fake"
        capture.mkdir()
        (capture / "stdout.txt").write_bytes(b"x" * HARD)
        report = {
            "status": "success",
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
            "elapsed_ms": 1.0,
            "fuel_consumed": 1,
            "output_files_exceeded": False,
            "execution_started": True,
        }
        return 0, __import__("json").dumps(report).encode(), b""

    monkeypatch.setattr(pe, "_spawn_worker", report_but_hide_the_cap)
    module = tmp_path / "clean.wasm"
    module.write_bytes(wasmtime.wat2wasm("""(module (memory (export "memory") 1)
                 (func (export "_start")))"""))
    result = pe.run_isolated(str(module), WASIConfig(max_fuel=1000))
    assert result["output_files_exceeded"] is True


def test_a_guest_printed_marker_is_not_a_cap_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("EPHEMORA_WORKER_OUTPUT_SINK", "1")
    module = tmp_path / "marker.wasm"
    text = b"\n[... truncated]"
    module.write_bytes(wasmtime.wat2wasm(f"""(module
              (import "wasi_snapshot_preview1" "fd_write"
                (func $fd_write (param i32 i32 i32 i32) (result i32)))
              (memory (export "memory") 1)
              (func (export "_start")
                (i32.store (i32.const 0) (i32.const 64))
                (i32.store (i32.const 4) (i32.const {len(text)}))
                (i32.store8 (i32.const 64) (i32.const 10))
                (i32.store8 (i32.const 65) (i32.const 91))
                (i32.store8 (i32.const 66) (i32.const 46))
                (i32.store8 (i32.const 67) (i32.const 46))
                (i32.store8 (i32.const 68) (i32.const 46))
                (i32.store8 (i32.const 69) (i32.const 32))
                (i32.store8 (i32.const 70) (i32.const 116))
                (i32.store8 (i32.const 71) (i32.const 114))
                (i32.store8 (i32.const 72) (i32.const 117))
                (i32.store8 (i32.const 73) (i32.const 110))
                (i32.store8 (i32.const 74) (i32.const 99))
                (i32.store8 (i32.const 75) (i32.const 97))
                (i32.store8 (i32.const 76) (i32.const 116))
                (i32.store8 (i32.const 77) (i32.const 101))
                (i32.store8 (i32.const 78) (i32.const 100))
                (i32.store8 (i32.const 79) (i32.const 93))
                (drop (call $fd_write (i32.const 1) (i32.const 0)
                  (i32.const 1) (i32.const 32)))))"""))
    base = tmp_path / "sandbox"
    base.mkdir()
    result = _sandbox(base).run(str(module), use_subprocess=True, trust="unknown")
    assert "truncated" in result.stdout
    assert result.output_files_exceeded is False


def test_a_closed_reader_gives_the_writer_epipe_without_overflow(tmp_path):
    fifo = tmp_path / "closed.fifo"
    capture = tmp_path / "closed.txt"
    make_output_fifo(str(fifo))
    exceeded = threading.Event()
    stop = threading.Event()
    ready = threading.Event()
    errors: list[BaseException] = []
    thread = start_output_cap_reader(
        str(fifo), str(capture), HARD, exceeded, stop, ready, errors
    )
    assert ready.wait(2), errors
    writer_error: list[BaseException] = []

    def write() -> None:
        try:
            fd = os.open(str(fifo), os.O_WRONLY)
            try:
                for _ in range(64):
                    os.write(fd, b"x" * (1024 * 1024))
                    time.sleep(0.001)
            finally:
                os.close(fd)
        except BaseException as exc:
            writer_error.append(exc)

    writer = threading.Thread(target=write)
    writer.start()
    time.sleep(0.01)
    stop.set()
    thread.join(timeout=2)
    writer.join(timeout=5)
    assert not thread.is_alive()
    assert capture.stat().st_size <= HARD
    assert writer_error, "the writer did not see the closed reader"
    assert isinstance(writer_error[0], OSError)


_CHILD = """
import sys
from ephemora_cell import WASIConfig, WASISandbox
module, base = sys.argv[1], sys.argv[2]
sandbox = WASISandbox(WASIConfig(max_memory_mb=512, max_fuel=50_000_000,
                                 timeout_seconds=30, sandbox_base_dir=base))
sandbox.run(module, use_subprocess=True, trust="unknown")
"""


def _worker_pids() -> set[int]:
    out = subprocess.run(
        ["ps", "-axo", "pid=,command="], capture_output=True, text=True
    ).stdout
    pids: set[int] = set()
    for line in out.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and "ephemora_cell.process_worker" in parts[1]:
            try:
                pids.add(int(parts[0]))
            except ValueError:
                pass
    return pids


def test_parent_sigkill_during_output_cannot_grow_the_capture(tmp_path, monkeypatch):
    monkeypatch.setenv("EPHEMORA_WORKER_OUTPUT_SINK", "1")
    base = tmp_path / "sandbox"
    base.mkdir()
    module = _flood_until_error(tmp_path)
    before = _worker_pids()
    peak, stop, monitor = _peak_monitor(base)
    child = subprocess.Popen(
        [sys.executable, "-c", _CHILD, str(module), str(base)],
        cwd=REPO,
        env={**os.environ, "PYTHONPATH": REPO},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    cap_seen = False
    deadline = time.monotonic() + 5.0
    try:
        while time.monotonic() < deadline:
            for path in base.rglob("stdout.txt"):
                try:
                    if path.stat().st_size >= HARD:
                        cap_seen = True
                        break
                except OSError:
                    pass
            if cap_seen:
                break
            time.sleep(0.002)
        assert cap_seen, "the child never reached the capture cap"
        child.kill()
        child.wait(timeout=30)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=30)
        stop.set()
        monitor.join(timeout=1)

    # The killed parent cannot run its cleanup. The worker must stop on its
    # own because its FIFO reader is gone; the capture must stay at the cap.
    time.sleep(0.7)
    sizes = [
        path.stat().st_size
        for path in base.rglob("*")
        if path.name in ("stdout.txt", "stderr.txt")
    ]
    assert peak["stdout"] <= HARD
    assert peak["stdout"] > 0
    assert all(size <= HARD for size in sizes)
    leftovers = _worker_pids() - before
    try:
        assert not leftovers, f"a worker outlived its SIGKILLed parent: {leftovers}"
    finally:
        for pid in leftovers:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass


_COMPONENT_ROUTE = """
import sys
from ephemora_cell import WASIConfig
from ephemora_cell.wasi_02 import ComponentSandbox
mode = sys.argv[1]
base = sys.argv[2]
sandbox = ComponentSandbox(WASIConfig(max_memory_mb=512, max_fuel=50_000_000,
                                      timeout_seconds=30, sandbox_base_dir=base))
real = ComponentSandbox._find_run_func

def wrapped(instance, store, comp):
    guest = real(instance, store, comp)
    def run(store):
        # Let the real guest flood first; its own stop (if any) is swallowed
        # so this probe reaches the timeout/memory branch with the host cap
        # already attested by the output reader.
        try:
            guest(store)
        except BaseException:
            pass
        import wasmtime
        if mode == "timeout":
            raise wasmtime.Trap("epoch timeout (route probe)")
        raise wasmtime.Trap("memory fault (route probe)")
    return run

ComponentSandbox._find_run_func = staticmethod(wrapped)
try:
    result = sandbox.run("tests/fixtures/hello02.wasm", args=["A" * 200_000])
finally:
    sandbox.cleanup()
print(result.status.value, result.output_files_exceeded, result.stderr[:60])
"""


@pytest.mark.parametrize(
    "mode,status", [("timeout", "timeout"), ("memory", "memory_exceeded")]
)
def test_component_timeout_and_memory_routes_keep_the_cap(
    tmp_path, monkeypatch, mode, status
):
    monkeypatch.setenv("EPHEMORA_WORKER_OUTPUT_SINK", "1")
    base = tmp_path / "sandbox"
    base.mkdir()
    proc = subprocess.run(
        [sys.executable, "-c", _COMPONENT_ROUTE, mode, str(base)],
        cwd=REPO,
        env={**os.environ, "PYTHONPATH": REPO},
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    fields = proc.stdout.split()
    assert fields[0] == status
    assert fields[1] == "True"
