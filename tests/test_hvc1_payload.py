# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""hvc1 payload transfer: host bytes reach the real worker, bounded and bound.

The product CLI hands a user's module or script to the VM. These tests pin the
transport contract: monotone chunks, a declared size, a digest checked before
execution, and a refusal when any of those disagree. The language dispatch is
tested with a fake adapter so it does not depend on an installed guest.
"""

from __future__ import annotations

import hashlib
import os
import socket
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import ipc_protocol as ipc
from ephemora_cell.vm_hvc1 import (
    GuestWorkerAgent,
    HVC1HostChannel,
    SerialFrameTransport,
    VMJob,
)

WAT = """
(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 8) "payload-ok")
  (data (i32.const 32) "\\08\\00\\00\\00\\0a\\00\\00\\00")
  (func (export "_start")
    i32.const 1 i32.const 32 i32.const 1 i32.const 40 call $write drop
    i32.const 0 call $exit))
"""


def _module_bytes() -> bytes:
    import wasmtime

    return wasmtime.wat2wasm(WAT)


def _payload_job(data: bytes, *, language: str = "wasm") -> VMJob:
    digest = hashlib.sha256(data).hexdigest()
    if language == "wasm":
        return VMJob(
            run_id="run-payload",
            subject="tenant:p",
            policy_digest="p" * 64,
            module_digest=digest,
            module_path="@payload",
            payload_bytes=data,
            payload_name="module.wasm",
            max_fuel=2_000_000,
            max_memory_mb=128,
            timeout_seconds=10,
            io_budget_bytes=64 * 1024,
            allowed_actions=("ready", "done"),
        )
    return VMJob(
        run_id="run-payload",
        subject="tenant:p",
        policy_digest="p" * 64,
        module_digest="a" * 64,
        module_path="/opt/ephemora/site-packages/ephemora_cell_python_guest/guest.wasm",
        payload_bytes=data,
        payload_name="main.py",
        language=language,
        max_fuel=2_000_000,
        max_memory_mb=128,
        timeout_seconds=10,
        io_budget_bytes=64 * 1024,
        allowed_actions=("ready", "done"),
    )


def _run(job: VMJob) -> tuple[dict, object]:
    host, guest = socket.socketpair()
    context = ipc.HostExecutionContext(
        run_id=job.run_id,
        subject=job.subject,
        policy_digest=job.policy_digest,
        module_digest=job.module_digest,
        allowed_actions=frozenset(job.allowed_actions),
        expires_at=time.monotonic() + 30.0,
    )
    mediator = ipc.HostMediator(
        context=context,
        handles=ipc.HostHandleRegistry(),
        actions={
            "ready": lambda _c, args: {"ready": True, "phase": args.get("phase", "")},
            "done": lambda _c, args: {"done": True, "phase": args.get("phase", "")},
        },
    )
    channel = HVC1HostChannel(host, job=job, context=context, mediator=mediator)
    result: list[dict] = []
    errors: list[BaseException] = []

    def run_guest() -> None:
        try:
            transport = SerialFrameTransport(guest.recv, guest.sendall)
            result.append(GuestWorkerAgent(transport).run())
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=run_guest, daemon=True)
    thread.start()
    thread.join(20)
    channel.close()
    guest.close()
    if errors:
        raise errors[0]
    assert result, "guest produced no report"
    return result[0], channel


def test_chunks_roundtrip_and_enforce_bounds():
    data = b"x" * (ipc.PAYLOAD_CHUNK_BYTES + 7)
    first = ipc.encode_chunk(
        run_id="r", seq=1, data=data[: ipc.PAYLOAD_CHUNK_BYTES], last=False
    )
    seq, chunk, last = ipc.decode_chunk(
        first,
        run_id="r",
        last_seq=0,
        received=0,
        total=len(data),
    )
    assert (seq, chunk, last) == (1, data[: ipc.PAYLOAD_CHUNK_BYTES], False)
    second = ipc.encode_chunk(
        run_id="r", seq=2, data=data[ipc.PAYLOAD_CHUNK_BYTES :], last=True
    )
    seq, chunk, last = ipc.decode_chunk(
        second,
        run_id="r",
        last_seq=1,
        received=len(data[: ipc.PAYLOAD_CHUNK_BYTES]),
        total=len(data),
    )
    assert (seq, chunk, last) == (2, data[ipc.PAYLOAD_CHUNK_BYTES :], True)

    with pytest.raises(ipc.IPCViolation, match="chunk_replay"):
        ipc.decode_chunk(second, run_id="r", last_seq=2, received=0, total=len(data))
    with pytest.raises(ipc.IPCViolation, match="run_id_mismatch"):
        ipc.decode_chunk(first, run_id="other", last_seq=0, received=0, total=len(data))
    with pytest.raises(ipc.IPCViolation, match="payload_overflow"):
        ipc.decode_chunk(
            first, run_id="r", last_seq=0, received=len(data), total=len(data)
        )
    with pytest.raises(ipc.IPCViolation, match="chunk_too_large"):
        ipc.encode_chunk(
            run_id="r", seq=1, data=b"x" * (ipc.PAYLOAD_CHUNK_BYTES + 1), last=True
        )


def test_the_real_worker_runs_the_uploaded_module():
    data = _module_bytes()
    job = _payload_job(data)
    report, channel = _run(job)
    assert report["status"] == "success", report
    assert report["stdout"] == "payload-ok"
    assert channel.violations == ()


def test_a_swapped_payload_digest_is_refused_before_the_worker():
    data = _module_bytes()
    job = _payload_job(data)
    forged = dict(job.payload())
    forged["payload"] = {
        "size": len(data),
        "sha256": "0" * 64,
        "name": "module.wasm",
    }
    host, guest = socket.socketpair()
    job_frame = ipc.encode_host_job(
        run_id=job.run_id,
        job=forged,
        subject=job.subject,
        policy_digest=job.policy_digest,
        module_digest=job.module_digest,
    )
    guest_transport = SerialFrameTransport(guest.recv, guest.sendall)
    host_transport = SerialFrameTransport(host.recv, host.sendall)
    agent = GuestWorkerAgent(guest_transport)
    error: list[BaseException] = []

    def run_guest() -> None:
        try:
            agent.run()
        except BaseException as exc:
            error.append(exc)

    thread = threading.Thread(target=run_guest, daemon=True)
    thread.start()
    # hello -> job; ready -> result; then the host must send the chunks.
    ipc.recv_frame(host_transport)
    ipc.send_frame(host_transport, job_frame)
    ready = ipc.decode_json_frame(ipc.recv_frame(host_transport))
    assert ready["action"] == "ready"
    ipc.send_frame(
        host_transport,
        ipc.encode_result(
            run_id=job.run_id, seq=1, status="ok", value={"accepted": True}
        ),
    )
    for offset in range(0, len(data), ipc.PAYLOAD_CHUNK_BYTES):
        chunk = data[offset : offset + ipc.PAYLOAD_CHUNK_BYTES]
        ipc.send_frame(
            host_transport,
            ipc.encode_chunk(
                run_id=job.run_id,
                seq=offset // ipc.PAYLOAD_CHUNK_BYTES + 1,
                data=chunk,
                last=offset + len(chunk) == len(data),
            ),
        )
    thread.join(10)
    host.close()
    guest.close()
    assert error and "payload_digest_mismatch" in str(error[0])


def test_a_python_job_stages_the_script_for_the_adapter(monkeypatch):
    seen: dict[str, object] = {}

    def fake_run_python_script(
        guest_path, *, script_path, args, config, expected_sha256
    ):
        seen["guest_path"] = guest_path
        seen["script"] = open(script_path, "rb").read()
        seen["sha"] = expected_sha256
        return {
            "status": "success",
            "exit_code": 0,
            "stdout": "python-ok\n",
            "stderr": "",
        }

    from ephemora_cell import lang_py

    monkeypatch.setattr(lang_py, "run_python_script", fake_run_python_script)
    job = _payload_job(b"print('python-ok')\n", language="python")
    report, channel = _run(job)
    assert report["status"] == "success", report
    assert report["stdout"] == "python-ok\n"
    assert seen["guest_path"] == job.module_path
    assert seen["script"] == b"print('python-ok')\n"
    assert seen["sha"] == job.module_digest
    assert channel.violations == ()


def test_a_language_job_without_a_payload_is_refused():
    with pytest.raises(ValueError, match="needs the user script as payload"):
        VMJob(
            run_id="r",
            subject="tenant:p",
            policy_digest="p" * 64,
            module_digest="a" * 64,
            module_path="/image/guest.wasm",
            language="python",
        )


def test_an_empty_chunk_is_refused():
    frame = ipc.encode_chunk(run_id="r", seq=1, data=b"", last=True)
    with pytest.raises(ipc.IPCViolation, match="chunk_empty"):
        ipc.decode_chunk(frame, run_id="r", last_seq=0, received=0, total=1)


def test_a_chunk_sequence_beyond_the_declared_size_is_refused():
    one = ipc.encode_chunk(
        run_id="r", seq=2, data=b"x" * ipc.PAYLOAD_CHUNK_BYTES, last=False
    )
    with pytest.raises(ipc.IPCViolation, match="chunk_seq_invalid"):
        ipc.decode_chunk(
            one,
            run_id="r",
            last_seq=0,
            received=0,
            total=ipc.PAYLOAD_CHUNK_BYTES,
        )
