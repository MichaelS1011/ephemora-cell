"""The output budget fills the documented limit, marks truncation,
and the worker's FIFO sink never lets the capture file grow past its hard cap."""

from __future__ import annotations

import os
import threading
import time

from ephemora_cell._sandbox_common import (
    _MAX_OUTPUT_BYTES,
    _OUTPUT_TRUNCATED,
    OUTPUT_FILE_HARD_LIMIT,
    make_output_fifo,
    make_output_sink,
    start_output_cap_reader,
)


def test_sink_splits_the_first_over_budget_chunk_and_marks_once(tmp_path):
    path = tmp_path / "stdout.txt"
    budget = [_MAX_OUTPUT_BYTES]
    sink = make_output_sink(str(path), budget)

    assert sink(b"A" * 4096) is None
    assert budget[0] == _MAX_OUTPUT_BYTES - 4096

    # 8192 does not fit into the remaining 5904: the sink keeps the part that
    # fits, then appends the marker and refuses the write.
    assert sink(b"B" * 8192) == -51
    assert budget[0] == _OUTPUT_TRUNCATED

    captured = path.read_bytes()
    assert len(captured) == _MAX_OUTPUT_BYTES + len(b"\n[... truncated]")
    assert captured[:4096] == b"A" * 4096
    assert captured[4096:_MAX_OUTPUT_BYTES] == b"B" * (_MAX_OUTPUT_BYTES - 4096)
    assert captured.endswith(b"\n[... truncated]")

    # One marker only; later writes are refused without touching the capture.
    assert sink(b"C") == -51
    assert path.read_bytes() == captured


def test_sink_accepts_exactly_the_budget_without_a_marker(tmp_path):
    path = tmp_path / "stdout.txt"
    budget = [_MAX_OUTPUT_BYTES]
    sink = make_output_sink(str(path), budget)

    assert sink(b"A" * _MAX_OUTPUT_BYTES) is None
    assert budget[0] == 0
    assert path.read_bytes() == b"A" * _MAX_OUTPUT_BYTES
    assert b"[... truncated]" not in path.read_bytes()


def test_sink_never_accepts_more_than_the_budget(tmp_path):
    path = tmp_path / "stdout.txt"
    budget = [10]
    sink = make_output_sink(str(path), budget)

    assert sink(b"A" * 11) == -51
    assert path.read_bytes() == b"A" * 10 + b"\n[... truncated]"


def test_truncation_marker_is_reserved_and_documented():
    from ephemora_cell._sandbox_common import _OUTPUT_TRUNCATION_MARKER

    assert _OUTPUT_TRUNCATION_MARKER == b"\n[... truncated]"
    assert _MAX_OUTPUT_BYTES == 10_000
    assert OUTPUT_FILE_HARD_LIMIT == 10_000 + 64 * 1024


def _drain_fifo(tmp_path, payload: bytes):
    fifo = tmp_path / "stream.fifo"
    capture = tmp_path / "stream.txt"
    make_output_fifo(str(fifo))
    exceeded = threading.Event()
    stop = threading.Event()
    ready = threading.Event()
    errors: list[BaseException] = []
    thread = start_output_cap_reader(
        str(fifo), str(capture), OUTPUT_FILE_HARD_LIMIT, exceeded, stop, ready, errors
    )
    assert ready.wait(2), errors
    writer_error: list[BaseException] = []

    def write() -> None:
        try:
            fd = os.open(str(fifo), os.O_WRONLY)
            try:
                if payload:
                    os.write(fd, payload)
            finally:
                os.close(fd)
        except BaseException as exc:  # EPIPE after the reader stops is expected
            writer_error.append(exc)

    writer = threading.Thread(target=write)
    writer.start()
    writer.join(timeout=5)
    stop.set()
    thread.join(timeout=2)
    assert not thread.is_alive(), "output reader did not stop"
    assert not errors, errors
    return capture.read_bytes(), exceeded.is_set(), writer_error


def test_fifo_reader_stops_at_the_hard_limit(tmp_path):
    captured, exceeded, _ = _drain_fifo(tmp_path, b"x" * (8 * 1024 * 1024))
    assert len(captured) == OUTPUT_FILE_HARD_LIMIT
    assert exceeded is True


def test_fifo_reader_does_not_invent_an_empty_second_stream(tmp_path):
    captured, exceeded, _ = _drain_fifo(tmp_path, b"")
    assert captured == b""
    assert exceeded is False


def test_fifo_reader_keeps_a_small_stream_verbatim(tmp_path):
    captured, exceeded, _ = _drain_fifo(tmp_path, b"hello")
    assert captured == b"hello"
    assert exceeded is False


def test_fifo_reader_does_not_call_the_exact_bound_a_breach(tmp_path):
    captured, exceeded, _ = _drain_fifo(tmp_path, b"x" * OUTPUT_FILE_HARD_LIMIT)
    assert len(captured) == OUTPUT_FILE_HARD_LIMIT
    assert exceeded is False


def test_clean_proc_exit_does_not_attest_guest_stderr(tmp_path, monkeypatch):
    """`proc_exit(0)` reaches the host as an ExitTrap; that is not guest output."""
    import wasmtime

    from ephemora_cell import WASIConfig, WASISandbox

    monkeypatch.setenv("EPHEMORA_WORKER_OUTPUT_SINK", "1")
    module = tmp_path / "exit0.wasm"
    module.write_bytes(wasmtime.wat2wasm("""(module
              (import "wasi_snapshot_preview1" "proc_exit"
                (func $exit (param i32)))
              (memory (export "memory") 1)
              (func (export "_start") (call $exit (i32.const 0))))"""))
    base = tmp_path / "sandbox"
    base.mkdir()
    result = WASISandbox(WASIConfig(sandbox_base_dir=str(base))).run(
        str(module), use_subprocess=False, trust="trusted"
    )
    assert result.status.value == "success"
    assert result.exit_code == 0
    assert result.stderr == ""
    assert result.output_files_exceeded is False


def test_worker_sink_fails_closed_when_the_fifo_cannot_be_created(
    tmp_path, monkeypatch
):
    import wasmtime

    from ephemora_cell import WASIConfig, WASISandbox
    from ephemora_cell import wasi_runtime as wr

    monkeypatch.setenv("EPHEMORA_WORKER_OUTPUT_SINK", "1")

    def _deny(path: str) -> None:
        raise PermissionError("mkfifo denied")

    monkeypatch.setattr(wr, "_make_output_fifo", _deny)
    module = tmp_path / "noop.wasm"
    module.write_bytes(wasmtime.wat2wasm("""(module
              (memory (export "memory") 1)
              (func (export "_start")))"""))
    base = tmp_path / "sandbox"
    base.mkdir()
    result = WASISandbox(WASIConfig(sandbox_base_dir=str(base))).run(
        str(module), use_subprocess=False, trust="trusted"
    )
    assert result.status.value == "error"
    assert "output sink could not be established" in result.stderr
    leaked = [
        t for t in threading.enumerate() if t.name.startswith("ephemora-output-cap")
    ]
    assert not leaked, f"a failed sink left reader threads behind: {leaked}"


def test_worker_fifo_sink_caps_disk_without_phantom_stderr(tmp_path, monkeypatch):
    import wasmtime

    from ephemora_cell import WASIConfig, WASISandbox

    size = 8 * 1024 * 1024
    pages = (size + 65535) // 65536 + 1
    wat = f"""(module
      (import "wasi_snapshot_preview1" "fd_write"
        (func $fd_write (param i32 i32 i32 i32) (result i32)))
      (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
      (memory (export "memory") {pages})
      (func (export "_start")
        (i32.store (i32.const 0) (i32.const 8))
        (i32.store (i32.const 4) (i32.const {size}))
        (drop (call $fd_write (i32.const 1) (i32.const 0)
          (i32.const 1) (i32.const 16)))
        (call $proc_exit (i32.const 0))))"""
    module = tmp_path / "flood.wasm"
    module.write_bytes(wasmtime.wat2wasm(wat))
    base = tmp_path / "sandbox"
    base.mkdir()
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

    sampler = threading.Thread(target=monitor, daemon=True)
    sampler.start()
    try:
        result = WASISandbox(
            WASIConfig(
                max_memory_mb=512,
                max_fuel=50_000_000,
                timeout_seconds=30,
                sandbox_base_dir=str(base),
            )
        ).run(str(module), use_subprocess=True, trust="unknown")
    finally:
        stop.set()
        sampler.join(timeout=1)

    assert peak["stdout"] <= OUTPUT_FILE_HARD_LIMIT
    assert peak["stderr"] == 0
    assert result.output_files_exceeded is True
    assert len(result.stdout) == _MAX_OUTPUT_BYTES + len("\n[... truncated]")
    assert result.stdout.endswith("\n[... truncated]")
    assert "\x00" not in result.stderr


def _flood_module(tmp_path, *, stream: int, size: int, code: int):
    import wasmtime

    pages = (size + 65535) // 65536 + 1
    wat = f"""(module
      (import "wasi_snapshot_preview1" "fd_write"
        (func $fd_write (param i32 i32 i32 i32) (result i32)))
      (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
      (memory (export "memory") {pages})
      (func (export "_start")
        (i32.store (i32.const 0) (i32.const 8))
        (i32.store (i32.const 4) (i32.const {size}))
        (drop (call $fd_write (i32.const {stream}) (i32.const 0)
          (i32.const 1) (i32.const 16)))
        (call $proc_exit (i32.const {code}))))"""
    module = tmp_path / f"flood_{stream}_{size}_{code}.wasm"
    module.write_bytes(wasmtime.wat2wasm(wat))
    return module


def test_error_route_keeps_the_output_verdict_and_the_guest_text(tmp_path, monkeypatch):
    """A run stopped non-zero after being cut off must still say so."""
    from ephemora_cell import WASIConfig, WASISandbox

    monkeypatch.setenv("EPHEMORA_WORKER_OUTPUT_SINK", "1")
    module = _flood_module(tmp_path, stream=2, size=8 * 1024 * 1024, code=3)
    base = tmp_path / "sandbox"
    base.mkdir()
    result = WASISandbox(
        WASIConfig(
            max_memory_mb=512,
            max_fuel=50_000_000,
            timeout_seconds=30,
            sandbox_base_dir=str(base),
        )
    ).run(str(module), use_subprocess=False, trust="trusted")

    assert result.status.value == "error"
    assert result.exit_code == 3
    assert result.output_files_exceeded is True
    assert "[... truncated]" in result.stderr


def test_component_iobudget_error_carries_verdict_and_guest_text(tmp_path):
    from ephemora_cell import WASIConfig
    from ephemora_cell.wasi_02 import ComponentSandbox

    sandbox = ComponentSandbox(WASIConfig(io_budget_bytes=1024))
    sandbox._output_files_exceeded = True
    result = sandbox._iobudget_error(4096, 12.0, (), stderr="guest said something")
    assert result.io_budget_exceeded is True
    assert result.output_files_exceeded is True
    assert "guest said something" in result.stderr


def test_component_variant_error_route_keeps_guest_output_and_verdict(
    tmp_path, monkeypatch
):
    from wasmtime import component as component

    from ephemora_cell import WASIConfig
    from ephemora_cell.wasi_02 import ComponentSandbox

    monkeypatch.setenv("EPHEMORA_WORKER_OUTPUT_SINK", "1")
    real_find = ComponentSandbox._find_run_func

    def find_then_fail(instance, store, comp):
        guest_run = real_find(instance, store, comp)

        def fail(store):
            guest_run(store)
            return component.Variant("err", "boom")

        return fail

    monkeypatch.setattr(
        ComponentSandbox, "_find_run_func", staticmethod(find_then_fail)
    )
    base = tmp_path / "sandbox"
    base.mkdir()
    result = ComponentSandbox(
        WASIConfig(
            max_memory_mb=512,
            max_fuel=50_000_000,
            timeout_seconds=30,
            sandbox_base_dir=str(base),
        )
    ).run("tests/fixtures/hello02.wasm")

    assert result.status.value == "error"
    assert "component run returned error" in result.stderr
    assert "hello from wasip2 component" in result.stdout
    assert result.output_files_exceeded is False


def test_component_trap_route_keeps_the_output_verdict(tmp_path, monkeypatch):
    """A real component that floods its output and then leaves non-zero."""
    from ephemora_cell import WASIConfig
    from ephemora_cell.wasi_02 import ComponentSandbox

    monkeypatch.setenv("EPHEMORA_WORKER_OUTPUT_SINK", "1")
    base = tmp_path / "sandbox"
    base.mkdir()
    result = ComponentSandbox(
        WASIConfig(
            max_memory_mb=512,
            max_fuel=50_000_000,
            timeout_seconds=30,
            sandbox_base_dir=str(base),
        )
    ).run("tests/fixtures/hello02.wasm", args=["A" * 200_000])

    assert result.status.value == "error"
    assert result.output_files_exceeded is True
    assert result.stdout.endswith("\n[... truncated]")
    assert result.stderr


def test_component_nonzero_exit_route_keeps_verdict_field(tmp_path, monkeypatch):
    from ephemora_cell import WASIConfig
    from ephemora_cell.wasi_02 import ComponentSandbox

    monkeypatch.setenv("EPHEMORA_WORKER_OUTPUT_SINK", "1")
    base = tmp_path / "sandbox"
    base.mkdir()
    result = ComponentSandbox(
        WASIConfig(
            max_memory_mb=512,
            max_fuel=50_000_000,
            timeout_seconds=30,
            sandbox_base_dir=str(base),
        )
    ).run("tests/fixtures/exit3_02.wasm")

    assert result.status.value == "error"
    assert result.output_files_exceeded is False
    assert "exit status" in result.stderr or "exited" in result.stderr.lower()
