# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""hvc1 product path: real worker, host mediation and D2 settlement."""

from __future__ import annotations

import hashlib
import os
import socket
import struct
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import ipc_protocol as ipc
from ephemora_cell.tenant import Charge, CumulativeBudget, TenantStore
from ephemora_cell.vm_hvc1 import (
    GuestWorkerAgent,
    HVC1HostChannel,
    ProductVMRunner,
    SerialFrameTransport,
    VMJob,
)
from ephemora_cell.vm_supervisor import (
    VMLimits,
    VMOutcome,
    VMStartRequest,
    VMSupervisor,
)
from ephemora_cell.wasi_runtime import ExecutionStatus

WAT = """
(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 8) "hello-hvc1")
  (data (i32.const 32) "\\08\\00\\00\\00\\0a\\00\\00\\00")
  (func (export "_start")
    i32.const 1 i32.const 32 i32.const 1 i32.const 40 call $write drop
    i32.const 0 call $exit))
"""


def _module(tmp_path) -> tuple[str, str]:
    import wasmtime

    data = wasmtime.wat2wasm(WAT)
    path = tmp_path / "hello.wasm"
    path.write_bytes(data)
    return str(path), hashlib.sha256(data).hexdigest()


def _job(tmp_path, **overrides) -> VMJob:
    path, digest = _module(tmp_path)
    values = dict(
        run_id="run-hvc1",
        subject="tenant:a",
        policy_digest="p" * 64,
        module_digest=digest,
        module_path=path,
        max_fuel=2_000_000,
        max_memory_mb=128,
        timeout_seconds=10,
        io_budget_bytes=64 * 1024,
        max_wasm_bytes=32 * 1024 * 1024,
        allowed_actions=("ready", "done", "echo"),
    )
    values.update(overrides)
    return VMJob(**values)


def _context(job: VMJob, *, expires_in: float = 30.0) -> ipc.HostExecutionContext:
    return ipc.HostExecutionContext(
        run_id=job.run_id,
        subject=job.subject,
        policy_digest=job.policy_digest,
        module_digest=job.module_digest,
        allowed_actions=frozenset(job.allowed_actions),
        expires_at=time.monotonic() + expires_in,
    )


def _mediator(context: ipc.HostExecutionContext) -> ipc.HostMediator:
    return ipc.HostMediator(
        context=context,
        handles=ipc.HostHandleRegistry(),
        actions={
            "ready": lambda _c, args: {"ready": True, "phase": args.get("phase", "")},
            "done": lambda _c, args: {"done": True, "phase": args.get("phase", "")},
            "echo": lambda _c, args: {"value": args.get("value")},
        },
    )


def _host_channel(sock, job, context):
    return HVC1HostChannel(sock, job=job, context=context, mediator=_mediator(context))


def _request_frame(
    job: VMJob,
    *,
    seq: int,
    action: str,
    arguments: dict,
    subject: str | None = None,
    run_id: str | None = None,
) -> bytes:
    return ipc.encode_request(
        run_id=run_id or job.run_id,
        seq=seq,
        action=action,
        arguments=arguments,
        subject=subject or job.subject,
        policy_digest=job.policy_digest,
        module_digest=job.module_digest,
    )


def test_the_real_worker_runs_over_the_product_channel(tmp_path):
    job = _job(tmp_path)
    host, guest = socket.socketpair()
    context = _context(job)
    channel = _host_channel(host, job, context)
    result: list[dict] = []

    def run_guest() -> None:
        transport = SerialFrameTransport(guest.recv, guest.sendall)
        result.append(GuestWorkerAgent(transport).run())

    thread = threading.Thread(target=run_guest, daemon=True)
    thread.start()
    assert channel.wait_boot(5.0) is True
    outcome = channel.wait_run(30.0)
    thread.join(10)
    assert outcome.ok is True
    assert outcome.host_verified is False
    assert outcome.report is not None
    assert outcome.report["status"] == ExecutionStatus.SUCCESS.value
    assert "hello-hvc1" in outcome.report["stdout"]
    assert result and result[0]["status"] == ExecutionStatus.SUCCESS.value
    assert channel.executed == ("ready", "done")
    assert channel._mediator.last_seq == 3
    channel.close()
    guest.close()


def _read_job(sock) -> tuple[SerialFrameTransport, dict]:
    transport = SerialFrameTransport(sock.recv, sock.sendall)
    ipc.send_frame(transport, ipc.encode_hello())
    doc = ipc.decode_host_job(ipc.recv_frame(transport))
    return transport, doc


def _send_request(transport, frame) -> dict:
    ipc.send_frame(transport, frame)
    return ipc.decode_json_frame(ipc.recv_frame(transport))


@pytest.mark.parametrize(
    ("label", "frame_factory", "reason"),
    [
        (
            "forged_run",
            lambda job, seq: _request_frame(
                job, seq=seq, action="ready", arguments={}, run_id="other"
            ),
            "run_id_mismatch",
        ),
        (
            "forged_subject",
            lambda job, seq: _request_frame(
                job, seq=seq, action="ready", arguments={}, subject="tenant:b"
            ),
            "subject_mismatch",
        ),
        (
            "unknown_action",
            lambda job, seq: _request_frame(
                job, seq=seq, action="host.read_file", arguments={}
            ),
            "action_not_allowed",
        ),
        (
            "path_argument",
            lambda job, seq: _request_frame(
                job, seq=seq, action="echo", arguments={"path": "/etc/passwd"}
            ),
            "argument_key_forbidden",
        ),
        (
            "unknown_handle",
            lambda job, seq: _request_frame(
                job, seq=seq, action="echo", arguments={"handle": "forged"}
            ),
            "unknown_handle",
        ),
    ],
)
def test_host_mediation_refuses_claims_and_handles(
    tmp_path, label, frame_factory, reason
):
    job = _job(tmp_path)
    host, guest = socket.socketpair()
    context = _context(job)
    channel = _host_channel(host, job, context)
    transport, _ = _read_job(guest)
    result = _send_request(transport, frame_factory(job, 1))
    assert result["status"] == "refused"
    assert result["reason"] == reason
    assert channel.executed == ()
    guest.close()
    channel.close()


def test_replay_is_refused_and_the_allowlisted_action_runs_once(tmp_path):
    job = _job(tmp_path)
    host, guest = socket.socketpair()
    channel = _host_channel(host, job, _context(job))
    transport, _ = _read_job(guest)
    first = _send_request(
        transport, _request_frame(job, seq=1, action="echo", arguments={"value": "a"})
    )
    assert first["status"] == "ok"
    replay = _send_request(
        transport, _request_frame(job, seq=1, action="echo", arguments={"value": "a"})
    )
    assert replay["status"] == "refused"
    assert replay["reason"] == "replay"
    assert channel.executed == ("echo",)
    guest.close()
    channel.close()


def test_disconnect_before_report_is_fail_closed(tmp_path):
    job = _job(tmp_path)
    host, guest = socket.socketpair()
    channel = _host_channel(host, job, _context(job))
    transport, _ = _read_job(guest)
    ok = _send_request(
        transport, _request_frame(job, seq=1, action="ready", arguments={})
    )
    assert ok["status"] == "ok"
    guest.close()
    outcome = channel.wait_run(2.0)
    assert outcome.ok is False
    assert outcome.report is None
    assert "report_missing" in outcome.error or "done_missing" in outcome.error
    channel.close()


def test_a_request_before_hello_is_refused(tmp_path):
    job = _job(tmp_path)
    host, guest = socket.socketpair()
    channel = _host_channel(host, job, _context(job))
    transport = SerialFrameTransport(guest.recv, guest.sendall)
    ipc.send_frame(transport, _request_frame(job, seq=1, action="ready", arguments={}))
    outcome = channel.wait_run(2.0)
    assert outcome.ok is False
    assert channel.executed == ()
    assert "hello_required" in channel.violations
    guest.close()
    channel.close()


def test_a_second_report_is_refused_and_cannot_overwrite_the_first(tmp_path):
    job = _job(tmp_path)
    host, guest = socket.socketpair()
    channel = _host_channel(host, job, _context(job))
    transport, _doc = _read_job(guest)
    ready = _send_request(
        transport, _request_frame(job, seq=1, action="ready", arguments={})
    )
    assert ready["status"] == "ok"
    first = ipc.encode_report(
        run_id=job.run_id,
        seq=2,
        report={"status": "error", "exit_code": 1},
        subject=job.subject,
        policy_digest=job.policy_digest,
        module_digest=job.module_digest,
    )
    ipc.send_frame(transport, first)
    ack = ipc.decode_json_frame(ipc.recv_frame(transport))
    assert ack["status"] == "ok"
    second = ipc.encode_report(
        run_id=job.run_id,
        seq=3,
        report={"status": "success", "exit_code": 0},
        subject=job.subject,
        policy_digest=job.policy_digest,
        module_digest=job.module_digest,
    )
    ipc.send_frame(transport, second)
    outcome = channel.wait_run(2.0)
    assert outcome.ok is False
    assert channel.report is not None
    assert channel.report["status"] == "error"
    assert "duplicate_report" in channel.violations
    guest.close()
    channel.close()


def test_oversized_frame_closes_the_channel(tmp_path):
    job = _job(tmp_path)
    host, guest = socket.socketpair()
    channel = _host_channel(host, job, _context(job))
    _read_job(guest)
    guest.sendall(struct.pack(">I", ipc.MAX_FRAME_BYTES + 1))
    outcome = channel.wait_run(2.0)
    assert outcome.ok is False
    assert outcome.report is None
    channel.close()
    guest.close()


class _FakeWorkerHandle:
    def __init__(self, report: dict) -> None:
        self._report = report
        self.killed = False
        self.cleaned = False

    def wait_boot(self, deadline_s: float) -> bool:
        return True

    def wait_run(self, deadline_s: float, abort_event=None) -> VMOutcome:
        return VMOutcome(
            ok=self._report.get("status") == "success",
            booted=True,
            marker=True,
            returncode=0,
            report=self._report,
        )

    def abort_ipc(self, reason: str) -> None:
        return None

    def kill(self) -> None:
        self.killed = True

    def cleanup(self) -> bool:
        self.cleaned = True
        return True


class _FakeWorkerBackend:
    def __init__(self, report: dict) -> None:
        self.report = report
        self.starts = 0

    def start(self, request):
        self.starts += 1
        return _FakeWorkerHandle(self.report)

    def reap_xpc(self) -> int:
        return 0


def _runner(tmp_path, report: dict, *, budget=None):
    backend = _FakeWorkerBackend(report)
    supervisor = VMSupervisor(
        backend,
        VMLimits(
            max_instances=2,
            max_guest_ram_mib=4096,
            max_host_overhead_mib=1024,
            guest_overhead_mib=128,
            boot_deadline_s=1,
            run_deadline_s=5,
            shutdown_grace_s=1,
            max_restarts=1,
        ),
    )
    store = TenantStore(tmp_path / "tenant.jsonl")
    job = _job(tmp_path)
    request = VMStartRequest(
        run_id=job.run_id,
        tenant=job.subject,
        guest_ram_mib=1024,
        boot_deadline_s=1,
        run_deadline_s=5,
    )
    runner = ProductVMRunner(supervisor)
    result = runner.run(request, job, store=store, tenant_budget=budget)
    return result, store, backend, job


def test_product_runner_books_conservatively_without_host_measurement(tmp_path):
    report = {
        "status": "success",
        "exit_code": 0,
        "stdout": "guest output",
        "stderr": "",
        "fuel_consumed": 123,
        "worker_attempts": 1,
    }
    result, store, backend, job = _runner(tmp_path, report)
    assert result.status == "success"
    assert result.accounting == "conservative"
    assert backend.starts == 1
    reserve = ProductVMRunner.reserve_for(
        job,
        VMStartRequest(
            run_id=job.run_id,
            tenant=job.subject,
            guest_ram_mib=1024,
            boot_deadline_s=1,
            run_deadline_s=5,
        ),
    )
    assert result.charge == Charge(
        fuel=reserve.fuel,
        output_bytes=reserve.output_bytes,
        wall_ms=result.charge.wall_ms,
    )
    usage = store.usage(job.subject)
    assert usage.unknown_fuel_charged == reserve.fuel
    assert usage.unknown_output_charged == reserve.output_bytes
    assert usage.charged.fuel == reserve.fuel
    assert usage.charged.output_bytes == reserve.output_bytes


def test_product_runner_refuses_before_start_when_the_tenant_budget_is_spent(
    tmp_path,
):
    report = {"status": "success", "exit_code": 0, "stdout": "", "stderr": ""}
    result, _store, backend, _job = _runner(
        tmp_path,
        report,
        budget=CumulativeBudget(max_total_fuel=1),
    )
    assert result.status == "refused"
    assert result.supervisor is None
    assert backend.starts == 0


def test_a_report_before_ready_is_refused(tmp_path):
    job = _job(tmp_path)
    host, guest = socket.socketpair()
    channel = _host_channel(host, job, _context(job))
    transport, _doc = _read_job(guest)
    report = ipc.encode_report(
        run_id=job.run_id,
        seq=1,
        report={"status": "success", "exit_code": 0},
        subject=job.subject,
        policy_digest=job.policy_digest,
        module_digest=job.module_digest,
    )
    ipc.send_frame(transport, report)
    outcome = channel.wait_run(2.0)
    assert outcome.ok is False
    assert outcome.host_verified is False
    assert channel.report is None
    assert "ready_required" in channel.violations
    guest.close()
    channel.close()


class _RaisingSupervisor:
    def run(self, request):
        raise RuntimeError("simulated supervisor fault")


def test_runner_books_the_whole_reservation_if_the_supervisor_raises(tmp_path):
    store = TenantStore(tmp_path / "tenant.jsonl")
    job = _job(tmp_path)
    request = VMStartRequest(
        run_id=job.run_id,
        tenant=job.subject,
        guest_ram_mib=1024,
        boot_deadline_s=1,
        run_deadline_s=5,
    )
    runner = ProductVMRunner(_RaisingSupervisor())
    with pytest.raises(RuntimeError, match="simulated supervisor fault"):
        runner.run(request, job, store=store)
    usage = store.usage(job.subject)
    reserve = ProductVMRunner.reserve_for(job, request)
    assert usage.charged.fuel == reserve.fuel
    assert usage.charged.output_bytes == reserve.output_bytes
    assert usage.charged.wall_ms == reserve.wall_ms
    assert usage.unknown_wall_runs == 1
    assert usage.unknown_wall_charged_ms == reserve.wall_ms


def test_a_done_before_ready_is_refused(tmp_path):
    job = _job(tmp_path)
    host, guest = socket.socketpair()
    channel = _host_channel(host, job, _context(job))
    transport, _doc = _read_job(guest)
    ipc.send_frame(transport, _request_frame(job, seq=1, action="done", arguments={}))
    outcome = channel.wait_run(2.0)
    assert outcome.ok is False
    assert channel.executed == ()
    assert "ready_required" in channel.violations
    guest.close()
    channel.close()
