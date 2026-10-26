# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""The public VM adapter: host-bound job, conservative booking, CLI refusals."""

from __future__ import annotations

import hashlib
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import cli
from ephemora_cell.lang_guest import GuestArtifact
from ephemora_cell.tenant import TenantStore
from ephemora_cell.vm_product import (
    VMProductConfig,
    build_vm_job,
    image_guest_path,
    run_vm_job,
)
from ephemora_cell.vm_supervisor import SupervisorResult
from ephemora_cell.wasi_runtime import WASIConfig

WAT = """
(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 8) "vm-product")
  (data (i32.const 32) "\\08\\00\\00\\00\\0a\\00\\00\\00")
  (func (export "_start")
    i32.const 1 i32.const 32 i32.const 1 i32.const 40 call $write drop))
"""


def _wasm(tmp_path) -> bytes:
    import wasmtime

    data = wasmtime.wat2wasm(WAT)
    (tmp_path / "hello.wasm").write_bytes(data)
    return data


def _config(**overrides) -> WASIConfig:
    values = dict(
        max_fuel=1_000_000,
        max_memory_mb=128,
        timeout_seconds=10,
        io_budget_bytes=64 * 1024,
    )
    values.update(overrides)
    return WASIConfig(**values)


def test_build_vm_job_binds_the_wasm_payload(tmp_path):
    data = _wasm(tmp_path)
    job = build_vm_job(
        module_path=str(tmp_path / "hello.wasm"),
        language="wasm",
        args=(),
        stdin="",
        config=_config(),
        tenant="tenant:a",
    )
    assert job.language == "wasm"
    assert job.module_path == "@payload"
    assert job.module_digest == hashlib.sha256(data).hexdigest()
    assert job.payload_bytes == data
    assert job.payload_name == "module.wasm"
    assert job.subject == "tenant:a"


def test_build_vm_job_binds_a_language_guest_and_script(tmp_path, monkeypatch):
    guest_bytes = b"fake-guest-bytes"
    guest_path = tmp_path / "guest.wasm"
    guest_path.write_bytes(guest_bytes)
    digest = hashlib.sha256(guest_bytes).hexdigest()
    monkeypatch.setattr(
        "ephemora_cell.vm_product.resolve_guest",
        lambda language: GuestArtifact(
            language=language,
            wasm_path=str(guest_path),
            stdlib_dir=None,
            expected_sha256=digest,
            version="test",
            source="test",
        ),
    )
    (tmp_path / "main.py").write_text("print('ok')\n")
    job = build_vm_job(
        module_path=str(tmp_path / "main.py"),
        language="python",
        args=("a",),
        stdin="",
        config=_config(),
        tenant="tenant:a",
    )
    assert job.language == "python"
    assert job.module_path == image_guest_path("python")
    assert job.module_digest == digest
    assert job.payload_bytes == b"print('ok')\n"
    assert job.payload_name == "main.py"
    assert job.args == ("a",)


def test_build_vm_job_refuses_an_unbounded_or_stdin_language_job(tmp_path):
    _wasm(tmp_path)
    with pytest.raises(ValueError, match="finite max_fuel"):
        build_vm_job(
            module_path=str(tmp_path / "hello.wasm"),
            language="wasm",
            args=(),
            stdin="",
            config=_config(max_fuel=None),
            tenant="tenant:a",
        )
    with pytest.raises(ValueError, match="stdin is not supported"):
        build_vm_job(
            module_path=str(tmp_path / "hello.wasm"),
            language="python",
            args=(),
            stdin="x",
            config=_config(),
            tenant="tenant:a",
        )


class _FakeSupervisor:
    def __init__(self, report: dict, *, status: str = "success") -> None:
        self._report = report
        self._status = status
        self.request = None

    def run(self, request):
        self.request = request
        return SupervisorResult(
            status=self._status,
            state="stopped",
            token=1,
            attempts=1,
            boot_ms=1200,
            wall_ms=1500,
            transitions=(
                "admitted",
                "starting",
                "booting",
                "running",
                "stopping",
                "stopped",
            ),
            cleanup_ok=True,
            started=True,
            report=self._report,
            host_verified=False,
        )


def _report() -> dict:
    return {
        "status": "success",
        "exit_code": 0,
        "stdout": "vm-product\n",
        "stderr": "",
        "fuel_consumed": 11,
        "io_bytes_written": 11,
        "worker_attempts": 1,
        "worker_started": True,
    }


def test_run_vm_job_books_the_reservation_and_marks_the_guest_claim(tmp_path):
    _wasm(tmp_path)
    store = TenantStore(tmp_path / "book.jsonl")
    supervisor = _FakeSupervisor(_report())
    result = run_vm_job(
        module_path=str(tmp_path / "hello.wasm"),
        language="wasm",
        args=(),
        stdin="",
        config=_config(),
        vm=VMProductConfig(probe="p", kernel="k", initrd="i"),
        store=store,
        tenant="tenant:a",
        supervisor=supervisor,
    )
    assert result.status == "success"
    assert result.host_verified is False
    assert result.accounting == "conservative"
    assert result.stdout == "vm-product\n"
    assert result.charge is not None
    assert result.charge["fuel"] == 2_000_000
    assert result.charge["output_bytes"] == 2 * (64 * 1024 + 2 * 75_536)
    assert result.usage is not None
    assert result.usage["unknown_fuel_charged"] == 2_000_000
    assert supervisor.request.guest_ram_mib == 1024
    # The reported fuel is still visible; it simply is not the booked number.
    assert result.report["fuel_consumed"] == 11


def test_run_vm_job_uses_two_gib_for_python(tmp_path, monkeypatch):
    guest_bytes = b"fake-guest-bytes"
    guest_path = tmp_path / "guest.wasm"
    guest_path.write_bytes(guest_bytes)
    digest = hashlib.sha256(guest_bytes).hexdigest()
    monkeypatch.setattr(
        "ephemora_cell.vm_product.resolve_guest",
        lambda language: GuestArtifact(
            language=language,
            wasm_path=str(guest_path),
            stdlib_dir=None,
            expected_sha256=digest,
            version="test",
            source="test",
        ),
    )
    (tmp_path / "main.py").write_text("print('ok')\n")
    store = TenantStore(tmp_path / "book.jsonl")
    supervisor = _FakeSupervisor(_report())
    result = run_vm_job(
        module_path=str(tmp_path / "main.py"),
        language="python",
        args=(),
        stdin="",
        config=_config(),
        vm=VMProductConfig(probe="p", kernel="k", initrd="i"),
        store=store,
        tenant="tenant:a",
        supervisor=supervisor,
    )
    assert result.status == "success"
    assert supervisor.request.guest_ram_mib == 2048


def _run_cli(monkeypatch, argv) -> int:
    monkeypatch.setattr(sys, "argv", argv)
    with pytest.raises(SystemExit) as exc:
        cli.main()
    return exc.value.code


def test_cli_vm_refuses_without_a_tenant_book(tmp_path, monkeypatch):
    code = _run_cli(
        monkeypatch,
        ["ephemora", "run", str(tmp_path / "x.wasm"), "--backend", "vm"],
    )
    assert code == cli.EXIT_CALLER


def test_cli_vm_refuses_missing_assets_before_any_run(tmp_path, monkeypatch, capsys):
    for name in ("EPHEMORA_VM_PROBE", "EPHEMORA_VM_KERNEL", "EPHEMORA_VM_INITRD"):
        monkeypatch.delenv(name, raising=False)
    book = tmp_path / "book.jsonl"
    code = _run_cli(
        monkeypatch,
        [
            "ephemora",
            "run",
            str(tmp_path / "x.wasm"),
            "--backend",
            "vm",
            "--tenant",
            "tenant:a",
            "--tenant-book",
            str(book),
        ],
    )
    assert code == cli.EXIT_CALLER
    assert "VM assets" in capsys.readouterr().err
    assert not book.exists()


def test_cli_vm_refuses_evidence_and_host_preopens(tmp_path, monkeypatch, capsys):
    code = _run_cli(
        monkeypatch,
        [
            "ephemora",
            "run",
            str(tmp_path / "x.wasm"),
            "--backend",
            "vm",
            "--evidence",
            str(tmp_path / "e.json"),
            "--allow-dirs",
            str(tmp_path),
        ],
    )
    assert code == cli.EXIT_CALLER
    err = capsys.readouterr().err
    assert "--evidence" in err and "--allow-dirs" in err


def _job_for_runner(tmp_path):
    from ephemora_cell.vm_product import build_vm_job

    _wasm(tmp_path)
    return build_vm_job(
        module_path=str(tmp_path / "hello.wasm"),
        language="wasm",
        args=(),
        stdin="",
        config=_config(),
        tenant="tenant:a",
    )


def test_a_settle_failure_is_not_a_success_and_keeps_the_lease(tmp_path):
    from datetime import datetime, timedelta, timezone

    from ephemora_cell.tenant import TenantStore
    from ephemora_cell.vm_hvc1 import ProductVMRunner
    from ephemora_cell.vm_supervisor import VMStartRequest

    store = TenantStore(tmp_path / "book.jsonl")
    job = _job_for_runner(tmp_path)
    supervisor = _FakeSupervisor(_report())
    runner = ProductVMRunner(supervisor)
    request = VMStartRequest(run_id=job.run_id, tenant=job.subject, guest_ram_mib=1024)
    original = store.settle

    def failing_settle(*args, **kwargs):
        raise RuntimeError("settle failed")

    store.settle = failing_settle  # type: ignore[method-assign]
    try:
        with pytest.raises(RuntimeError, match="settle failed"):
            runner.run(request, job, store=store)
    finally:
        store.settle = original  # type: ignore[method-assign]
    usage = store.usage("tenant:a")
    assert usage.runs == 0
    assert usage.inflight == 1
    assert usage.reserved.fuel == 2_000_000
    later = store.usage(
        "tenant:a", now=datetime.now(timezone.utc) + timedelta(seconds=1_000)
    )
    assert later.inflight == 0
    assert later.recovered.fuel == 2_000_000
    assert later.recovered_expired_runs == 1


def test_a_backend_start_error_releases_the_reservation(tmp_path):
    from ephemora_cell.tenant import TenantStore
    from ephemora_cell.vm_hvc1 import ProductVMRunner
    from ephemora_cell.vm_supervisor import VMStartRequest

    store = TenantStore(tmp_path / "book.jsonl")
    job = _job_for_runner(tmp_path)
    supervisor = _FakeSupervisor(_report(), status="backend_error")
    supervisor.run = lambda request: SupervisorResult(  # type: ignore[method-assign]
        status="backend_error",
        state="failed",
        token=None,
        attempts=1,
        reason="backend start failed: probe missing",
        started=False,
    )
    request = VMStartRequest(run_id=job.run_id, tenant=job.subject, guest_ram_mib=1024)
    result = ProductVMRunner(supervisor).run(request, job, store=store)
    assert result.accounting == "expired"
    usage = store.usage("tenant:a")
    assert usage.runs == 0
    assert usage.inflight == 0
    assert usage.charged.fuel == 0


def test_two_tenants_are_booked_separately(tmp_path):
    from ephemora_cell.tenant import TenantStore
    from ephemora_cell.vm_hvc1 import ProductVMRunner
    from ephemora_cell.vm_supervisor import VMStartRequest

    store = TenantStore(tmp_path / "book.jsonl")
    for tenant in ("tenant:a", "tenant:b"):
        job = _job_for_runner(tmp_path)
        job = type(job)(
            **{
                **job.__dict__,
                "run_id": f"run-{tenant}",
                "subject": tenant,
            }
        )
        request = VMStartRequest(run_id=job.run_id, tenant=tenant, guest_ram_mib=1024)
        result = ProductVMRunner(_FakeSupervisor(_report())).run(
            request, job, store=store
        )
        assert result.status == "success"
    a = store.usage("tenant:a")
    b = store.usage("tenant:b")
    assert a.runs == b.runs == 1
    assert a.charged.fuel == b.charged.fuel == 2_000_000


def test_a_reservation_written_by_one_store_is_seen_by_another(tmp_path):
    from ephemora_cell.tenant import Charge, TenantStore

    book = tmp_path / "book.jsonl"
    first = TenantStore(book)
    admission = first.admit(
        "tenant:a", reserve=Charge(fuel=1000, output_bytes=2000, wall_ms=3000)
    )
    second = TenantStore(book)
    usage = second.usage("tenant:a")
    assert usage.inflight == 1
    assert usage.reserved == Charge(fuel=1000, output_bytes=2000, wall_ms=3000)
    second.settle(
        "tenant:a",
        admission.admit_id,
        charge=Charge(fuel=10, output_bytes=20, wall_ms=30),
    )
    assert first.usage("tenant:a").charged == Charge(
        fuel=10, output_bytes=20, wall_ms=30
    )


@pytest.mark.parametrize(
    "extra",
    [
        ["--allow-env", "FOO=bar"],
        ["--memory64"],
        ["--abi", "preview1"],
        ["--language", "python", "--stdin", "/dev/null"],
        ["--language", "javascript", "--", "x"],
    ],
)
def test_cli_vm_refuses_every_unsupported_flag(tmp_path, monkeypatch, capsys, extra):
    code = _run_cli(
        monkeypatch,
        ["ephemora", "run", str(tmp_path / "x"), "--backend", "vm", *extra],
    )
    assert code == cli.EXIT_CALLER
    assert "cannot carry these flags" in capsys.readouterr().err


def test_build_vm_job_refuses_oversized_stdin(tmp_path):
    _wasm(tmp_path)
    with pytest.raises(ValueError, match="stdin exceeds the host cap"):
        build_vm_job(
            module_path=str(tmp_path / "hello.wasm"),
            language="wasm",
            args=(),
            stdin="x" * 9_217,
            config=_config(),
            tenant="tenant:a",
        )


def test_cli_tenant_without_a_subcommand_is_a_caller_error(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["ephemora", "tenant"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == cli.EXIT_CALLER
    assert "tenant usage" in capsys.readouterr().err


def test_the_reservation_tracks_the_supervisor_attempt_ceiling(tmp_path):
    from ephemora_cell.tenant import TenantStore
    from ephemora_cell.vm_hvc1 import ProductVMRunner
    from ephemora_cell.vm_supervisor import VMStartRequest

    class _WideSupervisor(_FakeSupervisor):
        max_attempts = 4

    store = TenantStore(tmp_path / "book.jsonl")
    job = _job_for_runner(tmp_path)
    supervisor = _WideSupervisor(_report())
    request = VMStartRequest(run_id=job.run_id, tenant=job.subject, guest_ram_mib=1024)
    result = ProductVMRunner(supervisor).run(request, job, store=store)
    assert result.charge is not None
    assert result.charge.fuel == 4 * 1_000_000
    assert result.charge.output_bytes == 4 * (64 * 1024 + 2 * 75_536)


def test_build_vm_job_refuses_an_oversized_argv(tmp_path):
    _wasm(tmp_path)
    with pytest.raises(ValueError, match="job frame is too large"):
        build_vm_job(
            module_path=str(tmp_path / "hello.wasm"),
            language="wasm",
            args=("x" * 1000,) * 80,
            stdin="",
            config=_config(),
            tenant="tenant:a",
        )


def test_cli_tenant_usage_refuses_a_missing_book(tmp_path, monkeypatch, capsys):
    code = _run_cli(
        monkeypatch,
        [
            "ephemora",
            "tenant",
            "usage",
            str(tmp_path / "nope.jsonl"),
            "--tenant",
            "tenant:a",
        ],
    )
    assert code == cli.EXIT_CALLER
    assert "not found" in capsys.readouterr().err
    assert not (tmp_path / "nope.jsonl").exists()
