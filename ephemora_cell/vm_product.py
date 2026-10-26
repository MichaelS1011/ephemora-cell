# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Public CLI adapter for the hvc1 VM product path.

This module is the product-facing join between a user's file and the VM
worker: it reads the bytes, binds the host-issued run context, starts the
supervisor, and returns the guest report plus the D2 booking. It deliberately
does not decide trust: the guest report stays a claim (``host_verified`` is
false) and the booking is conservative unless a separate operator decision
says otherwise.

No silent fallback exists here. If the VM assets are missing or the guest
digest does not match, the call raises; the CLI turns that into a caller-class
error and never runs the same bytes on a weaker path.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from dataclasses import dataclass, field
from typing import Any

from . import ipc_protocol as ipc
from ._sandbox_common import STDIN_MAX_BYTES
from .execution_report import jcs_canonicalize
from .lang_guest import resolve_guest
from .tenant import CumulativeBudget, TenantStore, TenantUsage
from .vm_hvc1 import (
    HVC1Backend,
    ProductVMRun,
    ProductVMRunner,
    VMJob,
)
from .vm_supervisor import (
    SupervisorResult,
    VMLimits,
    VMStartRequest,
    VMSupervisor,
)
from .wasi_runtime import WASIConfig

__all__ = [
    "VMProductConfig",
    "VMProductResult",
    "build_vm_job",
    "image_guest_path",
    "run_vm_job",
]

#: Where the wheel-installed guest sits inside the release image.
_IMAGE_GUEST = {
    "python": "/opt/ephemora/site-packages/ephemora_cell_python_guest/guest.wasm",
    "javascript": "/opt/ephemora/site-packages/ephemora_cell_javascript_guest/guest.wasm",
}
_PAYLOAD_NAME = {
    "wasm": "module.wasm",
    "python": "main.py",
    "javascript": "main.js",
}


@dataclass(frozen=True)
class VMProductConfig:
    """Paths and lifecycle ceilings for one local VM install."""

    probe: str
    kernel: str
    initrd: str
    vcpus: int = 2
    guest_ram_mib: int | None = None
    boot_deadline_s: float = 30.0
    run_deadline_s: float = 120.0
    limits: VMLimits = field(default_factory=VMLimits)

    def __post_init__(self) -> None:
        for label, value in (
            ("probe", self.probe),
            ("kernel", self.kernel),
            ("initrd", self.initrd),
        ):
            if not isinstance(value, str) or not value:
                raise ValueError(f"{label} must be a non-empty path")
        if self.guest_ram_mib is not None and self.guest_ram_mib <= 0:
            raise ValueError("guest_ram_mib must be positive")
        if self.vcpus <= 0:
            raise ValueError("vcpus must be positive")

    def ram_for(self, language: str) -> int:
        if self.guest_ram_mib is not None:
            return self.guest_ram_mib
        # The qualified Python shape is 2 GiB; the light shape is not a
        # Python guarantee.
        return 2_048 if language == "python" else 1_024


@dataclass(frozen=True)
class VMProductResult:
    status: str
    exit_code: int
    stdout: str
    stderr: str
    language: str
    backend: str = "vm"
    host_verified: bool = False
    accounting: str = ""
    reason: str | None = None
    wall_ms: int = 0
    boot_ms: int | None = None
    state: str = ""
    cleanup_ok: bool = True
    ipc_aborted: bool = False
    transitions: tuple[str, ...] = ()
    report: dict | None = None
    charge: dict | None = None
    usage: dict | None = None
    ipc_truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "language": self.language,
            "backend": self.backend,
            "host_verified": self.host_verified,
            "accounting": self.accounting,
            "reason": self.reason,
            "wall_ms": self.wall_ms,
            "boot_ms": self.boot_ms,
            "state": self.state,
            "cleanup_ok": self.cleanup_ok,
            "ipc_aborted": self.ipc_aborted,
            "transitions": list(self.transitions),
            "charge": self.charge,
            "usage": self.usage,
            "ipc_truncated": self.ipc_truncated,
            "report": self.report,
        }


def image_guest_path(language: str) -> str:
    try:
        return _IMAGE_GUEST[language]
    except KeyError as exc:
        raise ValueError(f"no VM guest for language {language!r}") from exc


def _read_user_bytes(path: str, *, limit: int) -> bytes:
    if not os.path.isfile(path):
        raise ValueError(f"not a regular file: {path}")
    size = os.path.getsize(path)
    if size <= 0:
        raise ValueError(f"empty file: {path}")
    if size > limit:
        raise ValueError(f"file exceeds {limit} bytes: {path}")
    with open(path, "rb") as handle:
        return handle.read(limit + 1)


def _policy_digest(
    *, language: str, module_digest: str, payload_digest: str, config: WASIConfig
) -> str:
    document = {
        "language": language,
        "module_digest": module_digest,
        "payload_digest": payload_digest,
        "config": {
            "max_fuel": config.max_fuel,
            "max_memory_mb": config.max_memory_mb,
            "timeout_seconds": config.timeout_seconds,
            "io_budget_bytes": config.io_budget_bytes,
            "io_cpu_seconds": config.io_cpu_seconds,
            "disk_quota_bytes": config.disk_quota_bytes,
            "max_wasm_bytes": config.max_wasm_bytes,
            "allow_fsync": config.allow_fsync,
        },
    }
    return hashlib.sha256(jcs_canonicalize(document).encode("utf-8")).hexdigest()


def build_vm_job(
    *,
    module_path: str,
    language: str,
    args: tuple[str, ...],
    stdin: str,
    config: WASIConfig,
    tenant: str,
    run_id: str | None = None,
) -> VMJob:
    """Bind one user file to a host-authored VM job.

    ``wasm`` uploads the module; ``python``/``javascript`` upload the script
    and name the wheel-installed guest inside the image. The digest the guest
    verifies against is the host's own hash, so a stale or swapped image fails
    closed rather than running different bytes.
    """
    if language not in _PAYLOAD_NAME:
        raise ValueError(f"unsupported VM language {language!r}")
    if config.max_fuel is None or config.io_budget_bytes is None:
        raise ValueError(
            "the VM product path needs finite max_fuel and io_budget_bytes"
        )
    if language != "wasm" and stdin:
        raise ValueError("stdin is not supported for Python/JavaScript VM runs")
    if stdin and len(stdin.encode("utf-8")) > STDIN_MAX_BYTES:
        raise ValueError(f"stdin exceeds the host cap of {STDIN_MAX_BYTES} bytes")
    payload = _read_user_bytes(module_path, limit=ipc.MAX_PAYLOAD_BYTES)
    payload_digest = hashlib.sha256(payload).hexdigest()
    if language == "wasm":
        entry_path = "@payload"
        module_digest = payload_digest
    else:
        guest = resolve_guest(language)
        with open(guest.wasm_path, "rb") as handle:
            guest_bytes = handle.read()
        module_digest = hashlib.sha256(guest_bytes).hexdigest()
        if guest.expected_sha256 and guest.expected_sha256.lower() != module_digest:
            raise ValueError(
                f"installed {language} guest digest mismatch: pinned "
                f"{guest.expected_sha256}, found {module_digest}"
            )
        entry_path = image_guest_path(language)
    job = VMJob(
        run_id=run_id or secrets.token_hex(16),
        subject=tenant,
        policy_digest=_policy_digest(
            language=language,
            module_digest=module_digest,
            payload_digest=payload_digest,
            config=config,
        ),
        module_digest=module_digest,
        module_path=entry_path,
        args=tuple(args),
        stdin=stdin,
        max_fuel=int(config.max_fuel),
        max_memory_mb=int(config.max_memory_mb),
        timeout_seconds=int(config.timeout_seconds),
        io_budget_bytes=int(config.io_budget_bytes),
        io_cpu_seconds=config.io_cpu_seconds,
        disk_quota_bytes=config.disk_quota_bytes,
        max_wasm_bytes=int(config.max_wasm_bytes),
        allow_fsync=bool(config.allow_fsync),
        language=language,
        payload_bytes=payload,
        payload_name=_PAYLOAD_NAME[language],
    )
    # The job frame is encoded once, after the probe has started. Check it
    # here so an oversized stdin/argv can never start a VM and then fail
    # outside the backend's cleanup path.
    try:
        ipc.encode_host_job(
            run_id=job.run_id,
            job=job.payload(),
            subject=job.subject,
            policy_digest=job.policy_digest,
            module_digest=job.module_digest,
        )
    except ipc.IPCViolation as exc:
        raise ValueError(
            f"VM job frame is too large ({exc.reason}); shorten stdin or argv"
        ) from exc
    return job


def _result_from_run(
    run: ProductVMRun, *, language: str, backend_error: str = ""
) -> VMProductResult:
    supervisor: SupervisorResult | None = run.supervisor
    report = run.report if isinstance(run.report, dict) else None
    if report is None and supervisor is not None:
        report = supervisor.report
    status = run.status
    reason = run.reason
    if reason is None and supervisor is not None and status != "success":
        reason = supervisor.reason or supervisor.state
    stdout = ""
    stderr = ""
    exit_code = 1
    ipc_truncated = False
    if report is not None:
        stdout = str(report.get("stdout", ""))
        stderr = str(report.get("stderr", ""))
        try:
            exit_code = int(report.get("exit_code", 0 if status == "success" else 1))
        except (TypeError, ValueError):
            exit_code = 1
        ipc_truncated = bool(report.get("ipc_truncated", False))
    if status != "success" and not stderr:
        stderr = (
            (supervisor.reason if supervisor and supervisor.reason else "")
            or backend_error
            or status
        )
    return VMProductResult(
        status=status,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        language=language,
        accounting=run.accounting,
        reason=reason,
        wall_ms=supervisor.wall_ms if supervisor else 0,
        boot_ms=supervisor.boot_ms if supervisor else None,
        state=supervisor.state if supervisor else "",
        cleanup_ok=supervisor.cleanup_ok if supervisor else True,
        ipc_aborted=supervisor.ipc_aborted if supervisor else False,
        transitions=supervisor.transitions if supervisor else (),
        report=report,
        charge=run.charge.to_dict() if run.charge is not None else None,
        usage=run.usage.to_dict() if isinstance(run.usage, TenantUsage) else None,
        ipc_truncated=ipc_truncated,
    )


def run_vm_job(
    *,
    module_path: str,
    language: str,
    args: tuple[str, ...],
    stdin: str,
    config: WASIConfig,
    vm: VMProductConfig,
    store: TenantStore,
    tenant: str,
    tenant_budget: CumulativeBudget | None = None,
    host_budget: CumulativeBudget | None = None,
    supervisor: VMSupervisor | None = None,
) -> VMProductResult:
    """Run one job over the real hvc1 VM path.

    The caller owns the tenant book. A supervisor can be injected for tests;
    the production path constructs the probe backend from ``vm``.
    """
    job = build_vm_job(
        module_path=module_path,
        language=language,
        args=args,
        stdin=stdin,
        config=config,
        tenant=tenant,
    )
    request = VMStartRequest(
        run_id=job.run_id,
        tenant=tenant,
        guest_ram_mib=vm.ram_for(language),
        vcpus=vm.vcpus,
        boot_deadline_s=vm.boot_deadline_s,
        run_deadline_s=vm.run_deadline_s,
    )
    backend_error = ""
    if supervisor is None:
        backend = HVC1Backend(
            job=job,
            probe=vm.probe,
            kernel=vm.kernel,
            initrd=vm.initrd,
        )
        supervisor = VMSupervisor(
            backend=backend,
            limits=vm.limits,
        )
    else:
        backend = None
    run = ProductVMRunner(supervisor).run(
        request,
        job,
        store=store,
        tenant_budget=tenant_budget,
        host_budget=host_budget,
    )
    if backend is not None:
        backend_error = backend.last_error
    return _result_from_run(run, language=language, backend_error=backend_error)
