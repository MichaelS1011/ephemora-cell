# Ephemora Cell — hvc1 product worker transport (local integration path)
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""The real product worker over the dedicated hvc1 virtio-console port.

The guest agent is a thin launcher: it receives a host-authored job, runs the
real isolated product worker (``run_isolated`` / ``process_worker``), and
sends the worker's JSON report back as a versioned frame. The host creates the
``HostExecutionContext`` from its own VM/run state, never from guest fields;
every action is mediated by :class:`ipc_protocol.HostMediator`, and every
report is checked for run binding, sequence, claims and frame size.

This is a local product integration, not an A7 claim by itself. The byte
transport is the dedicated second virtio console; the guest identity is the
host-bound run context, not the guest's claims.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import socket
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import ipc_protocol as ipc
from ._sandbox_common import OUTPUT_FILE_HARD_LIMIT
from .tenant import (
    Charge,
    CumulativeBudget,
    TenantId,
    TenantStore,
    TenantUsage,
)
from .vm_supervisor import (
    SupervisorResult,
    VMHandle,
    VMOutcome,
    VMStartRequest,
    VMSupervisor,
    VZProbeBackend,
    VZProbeHandle,
)
from .wasi_runtime import WASIConfig

__all__ = [
    "GuestWorkerAgent",
    "HVC1Backend",
    "HVC1HostChannel",
    "ProductVMRun",
    "ProductVMRunner",
    "SerialFrameTransport",
    "VMJob",
    "run_guest_agent",
]

_JOB_CONFIG_KEYS = frozenset(
    {
        "max_fuel",
        "max_memory_mb",
        "timeout_seconds",
        "io_budget_bytes",
        "io_cpu_seconds",
        "disk_quota_bytes",
        "max_wasm_bytes",
        "allow_fsync",
    }
)
_REPORT_DROP_KEYS = frozenset({"sandbox_dir", "host_traceback"})
_MAX_IPC_REPORT_TEXT = 8_000
_PAYLOAD_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_LANGUAGES = frozenset({"wasm", "python", "javascript"})


class SerialFrameTransport:
    """``ipc_protocol`` framing over base64 lines on a serial console.

    Kernel log lines on the same channel are ignored; only ``IPC1 <b64>``
    lines are frames. The 4-byte length and 64 KiB JSON limit stay in
    :mod:`ipc_protocol`; this class only adapts the byte stream.
    """

    def __init__(
        self,
        reader: Callable[[int], bytes],
        writer: Callable[[bytes], Any],
        *,
        max_line: int = 120_000,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._raw = bytearray()
        self._buffer = bytearray()
        self._max_line = max_line

    def sendall(self, data: bytes) -> None:
        if len(data) > ipc.MAX_FRAME_BYTES:
            raise ipc.IPCViolation("frame_too_large")
        line = b"IPC1 " + base64.b64encode(data) + b"\n"
        if len(line) > self._max_line:
            raise ipc.IPCViolation("line_too_long")
        self._writer(line)

    def _readline(self) -> bytes:
        while b"\n" not in self._raw:
            chunk = self._reader(4096)
            if not chunk:
                raise ipc.IPCDisconnected()
            self._raw += chunk
            if len(self._raw) > self._max_line:
                raise ipc.IPCViolation("line_too_long")
        line, _, self._raw = self._raw.partition(b"\n")
        return bytes(line) + b"\n"

    def recv(self, count: int) -> bytes:
        while len(self._buffer) < count:
            line = self._readline()
            if not line.startswith(b"IPC1 "):
                continue
            try:
                self._buffer += base64.b64decode(line[5:].strip(), validate=True)
            except Exception as exc:
                raise ipc.IPCViolation("frame_not_base64") from exc
        out = bytes(self._buffer[:count])
        del self._buffer[:count]
        return out


@dataclass(frozen=True)
class VMJob:
    """Host-authored job. ``module_path`` names a file inside the guest image."""

    run_id: str
    subject: str
    policy_digest: str
    module_digest: str
    module_path: str
    args: tuple[str, ...] = ()
    stdin: str = ""
    max_fuel: int = 1_000_000
    max_memory_mb: int = 128
    timeout_seconds: int = 30
    io_budget_bytes: int = 64 * 1024 * 1024
    io_cpu_seconds: float | None = 2.0
    disk_quota_bytes: int | None = 256 * 1024 * 1024
    max_wasm_bytes: int = 32 * 1024 * 1024
    allow_fsync: bool = False
    allowed_actions: tuple[str, ...] = ("ready", "done")
    #: ``wasm`` runs the uploaded module; ``python``/``javascript`` run the
    #: uploaded script on the guest runtime named by ``module_path``.
    language: str = "wasm"
    #: Host-supplied user bytes. For ``wasm`` this is the module and
    #: ``module_path`` is ``@payload``; for a language it is the script.
    payload_bytes: bytes | None = None
    payload_name: str = "module.wasm"

    def __post_init__(self) -> None:
        for name, value in (
            ("run_id", self.run_id),
            ("subject", self.subject),
            ("policy_digest", self.policy_digest),
            ("module_digest", self.module_digest),
            ("module_path", self.module_path),
        ):
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be a non-empty string")
        if len(self.module_digest) != 64 or any(
            ch not in "0123456789abcdef" for ch in self.module_digest.lower()
        ):
            raise ValueError("module_digest must be a 64-character hex digest")
        for field, amount in (
            ("max_fuel", self.max_fuel),
            ("max_memory_mb", self.max_memory_mb),
            ("timeout_seconds", self.timeout_seconds),
            ("io_budget_bytes", self.io_budget_bytes),
            ("max_wasm_bytes", self.max_wasm_bytes),
        ):
            if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0:
                raise ValueError(f"{field} must be a positive integer")
        if self.io_cpu_seconds is not None and self.io_cpu_seconds <= 0:
            raise ValueError("io_cpu_seconds must be positive or None")
        if self.disk_quota_bytes is not None and self.disk_quota_bytes <= 0:
            raise ValueError("disk_quota_bytes must be positive or None")
        actions = frozenset(self.allowed_actions)
        if "ready" not in actions or "done" not in actions:
            raise ValueError("allowed_actions must include ready and done")
        if any(not isinstance(action, str) or not action for action in actions):
            raise ValueError("allowed_actions must be non-empty strings")
        if self.language not in _LANGUAGES:
            raise ValueError(f"language must be one of {sorted(_LANGUAGES)}")
        if not isinstance(self.allow_fsync, bool):
            raise ValueError("allow_fsync must be a bool")
        if self.language != "wasm":
            if self.module_path == "@payload":
                raise ValueError("a language guest needs its image path, not @payload")
            if not self.module_path.startswith("/"):
                raise ValueError("a language guest path must be absolute")
        elif self.payload_bytes is None and self.module_path == "@payload":
            raise ValueError("module_path='@payload' requires a wasm payload")
        if self.payload_bytes is not None:
            if not isinstance(self.payload_bytes, (bytes, bytearray)):
                raise ValueError("payload must be bytes")
            if not self.payload_bytes:
                raise ValueError("payload must not be empty")
            if len(self.payload_bytes) > ipc.MAX_PAYLOAD_BYTES:
                raise ValueError("payload exceeds MAX_PAYLOAD_BYTES")
            if not _PAYLOAD_NAME.fullmatch(self.payload_name):
                raise ValueError(
                    "payload_name must be a plain file name (letters, digits, "
                    ". _ -), not a path"
                )
            if self.language == "wasm":
                if self.module_path != "@payload":
                    raise ValueError("a wasm payload must use module_path='@payload'")
                if self.module_digest != self.payload_digest:
                    raise ValueError(
                        "module_digest must be the digest of the wasm payload"
                    )
        elif self.language != "wasm":
            raise ValueError("a python/javascript job needs the user script as payload")

    @property
    def payload_digest(self) -> str | None:
        if self.payload_bytes is None:
            return None
        return hashlib.sha256(self.payload_bytes).hexdigest()

    def payload(self) -> dict[str, Any]:
        document = {
            "language": self.language,
            "module_path": self.module_path,
            "module_digest": self.module_digest,
            "args": list(self.args),
            "stdin": self.stdin,
            "config": {
                "max_fuel": self.max_fuel,
                "max_memory_mb": self.max_memory_mb,
                "timeout_seconds": self.timeout_seconds,
                "io_budget_bytes": self.io_budget_bytes,
                "io_cpu_seconds": self.io_cpu_seconds,
                "disk_quota_bytes": self.disk_quota_bytes,
                "max_wasm_bytes": self.max_wasm_bytes,
                "allow_fsync": self.allow_fsync,
            },
            "allowed_actions": list(self.allowed_actions),
        }
        if self.payload_bytes is not None:
            document["payload"] = {
                "size": len(self.payload_bytes),
                "sha256": self.payload_digest,
                "name": self.payload_name,
            }
        return document


def _normalise_report(raw: Mapping[str, Any]) -> dict[str, Any]:
    report = dict(raw)
    for key in _REPORT_DROP_KEYS:
        report.pop(key, None)
    status = report.get("status")
    value = getattr(status, "value", status)
    if not isinstance(value, str):
        value = "error"
    report["status"] = value
    try:
        report["exit_code"] = int(report.get("exit_code", 1))
    except (TypeError, ValueError):
        report["exit_code"] = 1
    report["stdout"] = str(report.get("stdout", ""))
    report["stderr"] = str(report.get("stderr", ""))
    return report


def _bounded_report(report: Mapping[str, Any]) -> dict[str, Any]:
    candidate = _normalise_report(report)
    if _fits(candidate):
        return candidate
    for key in ("stdout", "stderr"):
        text = candidate.get(key, "")
        data = text.encode("utf-8")
        if len(data) > _MAX_IPC_REPORT_TEXT:
            candidate[key] = data[:_MAX_IPC_REPORT_TEXT].decode(
                "utf-8", errors="replace"
            )
    candidate["ipc_truncated"] = True
    if _fits(candidate):
        return candidate
    for key in ("security_baseline", "effective_preopens", "io_cpu_used_seconds"):
        candidate.pop(key, None)
    if _fits(candidate):
        return candidate
    return {
        "status": candidate.get("status", "error"),
        "exit_code": candidate.get("exit_code", 1),
        "stdout": candidate.get("stdout", "")[:1024],
        "stderr": candidate.get("stderr", "")[:1024],
        "ipc_truncated": True,
    }


def _fits(report: Mapping[str, Any]) -> bool:
    try:
        return (
            len(
                json.dumps(report, sort_keys=True, separators=(",", ":")).encode(
                    "utf-8"
                )
            )
            <= ipc.MAX_FRAME_BYTES - 2048
        )
    except (TypeError, ValueError):
        return False


class GuestWorkerAgent:
    """Guest-side launcher for the real product worker."""

    def __init__(
        self,
        transport: SerialFrameTransport,
        *,
        worker: Callable[..., dict] | None = None,
        expected_run_id: str | None = None,
    ) -> None:
        self._transport = transport
        self._worker = worker
        self._expected_run_id = expected_run_id

    def run(self) -> dict[str, Any]:
        # The channel exists before the guest starts reading. A hello tells
        # the host the reader is ready; only then does the host send the job,
        # so no host→guest frame is lost during boot.
        ipc.send_frame(self._transport, ipc.encode_hello())
        job_doc = ipc.decode_host_job(ipc.recv_frame(self._transport))
        if self._expected_run_id is not None and (
            job_doc["run_id"] != self._expected_run_id
        ):
            raise ipc.IPCViolation("run_id_mismatch")
        claims = job_doc["claims"]
        client = ipc.GuestClient(
            self._transport,
            run_id=job_doc["run_id"],
            subject=claims["subject"],
            policy_digest=claims["policy_digest"],
            module_digest=claims["module_digest"],
        )
        ready = client.request("ready", {"phase": "job_received"})
        if ready.get("status") != "ok":
            raise ipc.IPCViolation(f"ready_refused:{ready.get('reason', 'unknown')}")
        report = self._run_job(job_doc["job"], run_id=job_doc["run_id"])
        payload = _bounded_report(report)
        seq = client._seq + 1
        client._seq = seq
        ipc.send_frame(
            self._transport,
            ipc.encode_report(
                run_id=job_doc["run_id"],
                seq=seq,
                report=payload,
                subject=claims["subject"],
                policy_digest=claims["policy_digest"],
                module_digest=claims["module_digest"],
            ),
        )
        ack = ipc.decode_json_frame(ipc.recv_frame(self._transport))
        if (
            ack.get("kind") != "result"
            or ack.get("seq") != seq
            or ack.get("status") != "ok"
        ):
            raise ipc.IPCViolation("report_refused")
        done = client.request("done", {"phase": "report_sent"})
        if done.get("status") != "ok":
            raise ipc.IPCViolation(f"done_refused:{done.get('reason', 'unknown')}")
        return payload

    def _receive_payload(self, run_id: str, meta: Mapping[str, Any]) -> tuple[str, str]:
        """Receive, verify and stage the host-supplied user bytes.

        The chunk sequence is independent of the request sequence: chunks are
        host→guest only, monotone, bounded by the declared size and checked
        against the digest before the worker sees the file.
        """
        if set(meta) != {"size", "sha256", "name"}:
            raise ipc.IPCViolation("payload_meta_invalid")
        size = meta.get("size")
        digest = meta.get("sha256")
        name = meta.get("name")
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or size <= 0
            or size > ipc.MAX_PAYLOAD_BYTES
        ):
            raise ipc.IPCViolation("payload_size_invalid")
        if not isinstance(digest, str) or len(digest) != 64:
            raise ipc.IPCViolation("payload_digest_invalid")
        if not isinstance(name, str) or not _PAYLOAD_NAME.fullmatch(name):
            raise ipc.IPCViolation("payload_name_invalid")
        buffer = bytearray()
        last_seq = 0
        while True:
            frame = ipc.recv_frame(self._transport)
            last_seq, data, last = ipc.decode_chunk(
                frame,
                run_id=run_id,
                last_seq=last_seq,
                received=len(buffer),
                total=size,
            )
            buffer.extend(data)
            if last:
                if len(buffer) != size:
                    raise ipc.IPCViolation("payload_size_mismatch")
                break
            if len(buffer) == size:
                raise ipc.IPCViolation("payload_incomplete")
        if hashlib.sha256(buffer).hexdigest() != digest.lower():
            raise ipc.IPCViolation("payload_digest_mismatch")
        # nosec B108 — mkdtemp creates this 0700; /tmp is used deliberately as
        # the shortest base so the staged name stays well inside PATH_MAX.
        work = tempfile.mkdtemp(prefix="ephemora-job-", dir="/tmp")  # nosec B108
        path = os.path.join(work, name)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(buffer)
        return path, work

    def _run_job(self, job: Mapping[str, Any], *, run_id: str) -> dict[str, Any]:
        if not isinstance(job, Mapping):
            raise ipc.IPCViolation("job_invalid")
        raw_config = job.get("config")
        if not isinstance(raw_config, Mapping):
            raise ipc.IPCViolation("job_config_invalid")
        unknown = set(raw_config) - _JOB_CONFIG_KEYS
        if unknown:
            raise ipc.IPCViolation("job_config_unknown")
        config = WASIConfig(
            max_fuel=int(raw_config["max_fuel"]),
            max_memory_mb=int(raw_config["max_memory_mb"]),
            timeout_seconds=int(raw_config["timeout_seconds"]),
            io_budget_bytes=int(raw_config["io_budget_bytes"]),
            io_cpu_seconds=raw_config.get("io_cpu_seconds"),
            disk_quota_bytes=raw_config.get("disk_quota_bytes"),
            max_wasm_bytes=int(raw_config["max_wasm_bytes"]),
            allow_fsync=bool(raw_config.get("allow_fsync", False)),
        )
        # Accounted untrusted work needs a finite ceiling in every dimension
        # the host will book. The host must not hand the guest an open one.
        if config.max_fuel is None or config.io_budget_bytes is None:
            raise ipc.IPCViolation("job_budget_unbounded")
        language = job.get("language", "wasm")
        if language not in _LANGUAGES:
            raise ipc.IPCViolation("job_language_invalid")
        module_path = job.get("module_path")
        module_digest = job.get("module_digest")
        if not isinstance(module_path, str) or not isinstance(module_digest, str):
            raise ipc.IPCViolation("job_module_invalid")
        args = job.get("args", [])
        if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            raise ipc.IPCViolation("job_args_invalid")
        stdin = job.get("stdin", "")
        if not isinstance(stdin, str):
            raise ipc.IPCViolation("job_stdin_invalid")
        if language != "wasm" and stdin:
            raise ipc.IPCViolation("stdin_not_supported")
        meta = job.get("payload")
        staged_path = None
        staged_dir = None
        try:
            if meta is not None:
                if not isinstance(meta, Mapping):
                    raise ipc.IPCViolation("payload_meta_invalid")
                staged_path, staged_dir = self._receive_payload(run_id, meta)
            worker = self._worker
            if language == "wasm":
                if worker is None:
                    from .process_executor import run_isolated

                    worker = run_isolated
                if staged_path is not None:
                    if module_path != "@payload":
                        raise ipc.IPCViolation("job_module_binding_invalid")
                    module_path = staged_path
                raw = worker(
                    module_path,
                    config,
                    args=list(args),
                    stdin_data=stdin,
                    expected_sha256=module_digest,
                )
            elif language == "python":
                if staged_path is None:
                    raise ipc.IPCViolation("job_payload_required")
                from . import lang_py

                raw = lang_py.run_python_script(
                    module_path,
                    script_path=staged_path,
                    args=tuple(args),
                    config=config,
                    expected_sha256=module_digest,
                )
            else:
                if staged_path is None:
                    raise ipc.IPCViolation("job_payload_required")
                from . import lang_js

                raw = lang_js.run_javascript_source(
                    module_path,
                    script_path=staged_path,
                    config=config,
                    expected_sha256=module_digest,
                )
            report = _normalise_report(raw)
            # The language adapters publish ``str(ExecutionStatus.X)``; the
            # host and the CLI speak the short status used by every report.
            status = report.get("status")
            if isinstance(status, str) and status.startswith("ExecutionStatus."):
                report["status"] = status.rsplit(".", 1)[-1].lower()
            if raw.get("exit_code") is None:
                report["exit_code"] = 0 if report.get("status") == "success" else 1
            return report
        except ipc.IPCViolation:
            raise
        except Exception as exc:
            return {
                "status": "error",
                "exit_code": 1,
                "stdout": "",
                "stderr": f"guest agent worker failed: {exc}",
                "execution_started": True,
                "worker_crashed": True,
            }
        finally:
            if staged_dir is not None:
                import shutil

                shutil.rmtree(staged_dir, ignore_errors=True)


def run_guest_agent(
    transport: SerialFrameTransport,
    *,
    worker: Callable[..., dict] | None = None,
    expected_run_id: str | None = None,
) -> dict[str, Any]:
    return GuestWorkerAgent(
        transport, worker=worker, expected_run_id=expected_run_id
    ).run()


class HVC1HostChannel:
    """Host side of one connected hvc1 channel and its report waiter."""

    def __init__(
        self,
        sock: socket.socket,
        *,
        job: VMJob,
        context: ipc.HostExecutionContext,
        mediator: ipc.HostMediator,
        close_callback: Callable[[], None] | None = None,
    ) -> None:
        self._sock = sock
        self._job = job
        self._context = context
        self._mediator = mediator
        self._close_callback = close_callback
        self._transport = SerialFrameTransport(sock.recv, sock.sendall)
        self._boot = threading.Event()
        self._report_event = threading.Event()
        self._done = threading.Event()
        self._closed = threading.Event()
        self._report: dict | None = None
        self._violations: list[str] = []
        self._violation_lock = threading.Lock()
        self._aborted = False
        self._job_sent = False
        self._ready = False
        self._job_frame = ipc.encode_host_job(
            run_id=job.run_id,
            job=job.payload(),
            subject=context.subject,
            policy_digest=context.policy_digest,
            module_digest=context.module_digest,
        )
        self._reader = threading.Thread(target=self._serve, daemon=True)
        self._reader.start()

    def _send_payload(self) -> bool:
        """Send the host-supplied user bytes after the guest's ready grant.

        The guest is already reading its channel at this point (it asked for
        ready), so no chunk can be lost behind kernel console output. The
        sequence is chunk-local and monotone; it never advances the request
        sequence the mediator replays.
        """
        payload = self._job.payload_bytes
        if payload is None:
            return True
        seq = 0
        try:
            for offset in range(0, len(payload), ipc.PAYLOAD_CHUNK_BYTES):
                chunk = payload[offset : offset + ipc.PAYLOAD_CHUNK_BYTES]
                seq += 1
                last = offset + len(chunk) == len(payload)
                ipc.send_frame(
                    self._transport,
                    ipc.encode_chunk(
                        run_id=self._context.run_id,
                        seq=seq,
                        data=chunk,
                        last=last,
                    ),
                )
        except (ipc.IPCViolation, OSError) as exc:
            with self._violation_lock:
                self._violations.append(f"payload_send:{type(exc).__name__}")
            return False
        return True

    @property
    def violations(self) -> tuple[str, ...]:
        return tuple(self._violations)

    @property
    def report(self) -> dict | None:
        return self._report

    @property
    def executed(self) -> tuple[str, ...]:
        return tuple(self._mediator.executed)

    def _serve(self) -> None:
        while not self._closed.is_set():
            try:
                frame = ipc.recv_frame(self._transport)
            except ipc.IPCViolation as exc:
                with self._violation_lock:
                    self._violations.append(f"transport:{exc.reason}")
                break
            except Exception as exc:
                with self._violation_lock:
                    self._violations.append(f"transport:{type(exc).__name__}")
                break
            try:
                doc = ipc.decode_json_frame(frame)
            except ipc.IPCViolation as exc:
                with self._violation_lock:
                    self._violations.append(exc.reason)
                break
            kind = doc.get("kind")
            if kind == "hello":
                if self._job_sent:
                    with self._violation_lock:
                        self._violations.append("duplicate_hello")
                    break
                try:
                    ipc.decode_hello(frame)
                    ipc.send_frame(self._transport, self._job_frame)
                except ipc.IPCViolation as exc:
                    with self._violation_lock:
                        self._violations.append(exc.reason)
                    break
                self._job_sent = True
                self._boot.set()
                continue
            if not self._job_sent:
                # A request or report before the guest has read its job has
                # no host-issued context; refuse rather than guess.
                with self._violation_lock:
                    self._violations.append("hello_required")
                break
            if kind == "report":
                if not self._ready:
                    with self._violation_lock:
                        self._violations.append("ready_required")
                    break
                if self._report is not None:
                    with self._violation_lock:
                        self._violations.append("duplicate_report")
                    break
                try:
                    seq, report = ipc.decode_report(
                        frame,
                        context=self._context,
                        last_seq=self._mediator.last_seq,
                    )
                except ipc.IPCViolation as exc:
                    with self._violation_lock:
                        self._violations.append(exc.reason)
                    break
                self._report = report
                self._mediator.last_seq = seq
                try:
                    ipc.send_frame(
                        self._transport,
                        ipc.encode_result(
                            run_id=self._context.run_id,
                            seq=seq,
                            status="ok",
                            value={"accepted": True},
                        ),
                    )
                except ipc.IPCViolation:
                    break
                self._report_event.set()
                continue
            if kind == "request":
                if doc.get("action") == "done" and not self._ready:
                    with self._violation_lock:
                        self._violations.append("ready_required")
                    break
                result = self._mediator.handle_frame(frame)
                try:
                    ipc.send_frame(self._transport, result)
                except ipc.IPCViolation:
                    break
                decoded = ipc.decode_json_frame(result)
                if decoded.get("status") != "ok":
                    with self._violation_lock:
                        self._violations.append(str(decoded.get("reason", "refused")))
                if doc.get("action") == "ready" and decoded.get("status") == "ok":
                    self._ready = True
                    self._boot.set()
                    if not self._send_payload():
                        break
                if doc.get("action") == "done" and decoded.get("status") == "ok":
                    self._done.set()
                    break
                continue
            with self._violation_lock:
                self._violations.append("unknown_frame_kind")
            break
        self._closed.set()
        self._boot.set()

    def wait_boot(self, deadline_s: float) -> bool:
        return self._boot.wait(deadline_s) and not self._aborted

    def wait_run(
        self, deadline_s: float, abort_event: threading.Event | None = None
    ) -> VMOutcome:
        deadline = time.monotonic() + deadline_s
        while time.monotonic() < deadline:
            if abort_event is not None and abort_event.is_set():
                self.abort_ipc("operator_abort")
                return VMOutcome(
                    ok=False,
                    booted=True,
                    marker=False,
                    returncode=None,
                    output_tail="",
                    error="ipc_aborted",
                    ipc_aborted=True,
                    report=self._report,
                )
            if self._done.is_set() or self._closed.is_set():
                break
            time.sleep(0.02)
        if self._aborted:
            return VMOutcome(
                ok=False,
                booted=True,
                marker=False,
                returncode=None,
                error="ipc_aborted",
                ipc_aborted=True,
                report=self._report,
            )
        if not self._done.is_set():
            self._closed.set()
            try:
                self._sock.close()
            except OSError:
                pass
            error = "run_timeout" if time.monotonic() >= deadline else "done_missing"
            return VMOutcome(
                ok=False,
                booted=True,
                marker=False,
                returncode=None,
                error=error,
                report=self._report,
            )
        report = self._report
        if report is None:
            return VMOutcome(
                ok=False,
                booted=True,
                marker=False,
                returncode=None,
                error="report_missing",
            )
        status = str(report.get("status", "error"))
        ok = status == "success"
        try:
            exit_code = int(report.get("exit_code", 1))
        except (TypeError, ValueError):
            exit_code = 1
        tail = (str(report.get("stderr", "")) or str(report.get("stdout", "")))[-800:]
        return VMOutcome(
            ok=ok,
            booted=True,
            marker=True,
            returncode=exit_code,
            output_tail=tail,
            error="" if ok else f"guest status: {status}",
            host_verified=False,
            report=report,
        )

    def abort_ipc(self, reason: str) -> None:
        self._aborted = True
        self._closed.set()
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self._sock.close()
        except OSError:
            pass
        if self._close_callback is not None:
            self._close_callback()

    def close(self) -> None:
        self._closed.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._reader.join(5.0)


class _NoConnectHandle:
    def __init__(self, probe: VZProbeHandle | None, reason: str) -> None:
        self._probe = probe
        self._reason = reason

    def wait_boot(self, deadline_s: float) -> bool:
        return False

    def wait_run(
        self, deadline_s: float, abort_event: threading.Event | None = None
    ) -> VMOutcome:
        return VMOutcome(
            ok=False,
            booted=False,
            marker=False,
            returncode=None,
            error=self._reason,
        )

    def abort_ipc(self, reason: str) -> None:
        return None

    def kill(self) -> None:
        if self._probe is not None:
            self._probe.kill()

    def cleanup(self) -> bool:
        if self._probe is not None:
            return self._probe.cleanup()
        return True


class _HVC1ConnectedHandle:
    def __init__(
        self,
        channel: HVC1HostChannel,
        probe: VZProbeHandle | None,
        socket_dir: Path,
    ) -> None:
        self._channel = channel
        self._probe = probe
        self._socket_dir = socket_dir

    def wait_boot(self, deadline_s: float) -> bool:
        return self._channel.wait_boot(deadline_s)

    def wait_run(
        self, deadline_s: float, abort_event: threading.Event | None = None
    ) -> VMOutcome:
        return self._channel.wait_run(deadline_s, abort_event)

    def abort_ipc(self, reason: str) -> None:
        self._channel.abort_ipc(reason)

    def kill(self) -> None:
        self._channel.abort_ipc("kill")
        if self._probe is not None:
            self._probe.kill()

    def cleanup(self) -> bool:
        self._channel.close()
        if self._probe is not None:
            ok = self._probe.cleanup()
        else:
            ok = True
        try:
            for child in self._socket_dir.iterdir():
                child.unlink(missing_ok=True)
            self._socket_dir.rmdir()
        except OSError:
            ok = False
        return ok


class HVC1Backend:
    """Launch a VZ VM, accept its hvc1 bridge, and mediate the worker job."""

    def __init__(
        self,
        *,
        job: VMJob,
        probe: str | Path,
        kernel: str | Path,
        initrd: str | Path,
        allowed_actions: tuple[str, ...] | None = None,
    ) -> None:
        self._job = job
        self._allowed_actions = frozenset(allowed_actions or job.allowed_actions)
        self._probe_backend = VZProbeBackend(probe, kernel, initrd)
        self.last_console_tail = ""
        self.last_error = ""
        self.last_probe: VZProbeHandle | None = None
        self.last_channel: HVC1HostChannel | None = None

    def start(self, request: VMStartRequest) -> VMHandle:
        if request.run_id != self._job.run_id or request.tenant != self._job.subject:
            raise ValueError("request does not match the host job binding")
        # AF_UNIX paths are capped at ~104 bytes. A temp dir under the
        # per-user /var/folders tree can exceed that with the run id; /tmp
        # keeps the binding short. mkdtemp creates the directory mode 0700.
        socket_root = Path(tempfile.mkdtemp(prefix="eh_", dir="/tmp"))  # nosec B108
        sock_path = socket_root / f"ipc-{request.run_id}.sock"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.bind(str(sock_path))
            server.listen(1)
            server.settimeout(request.boot_deadline_s)
        except BaseException:
            try:
                server.close()
            except OSError:
                pass
            self._cleanup_socket_root(socket_root)
            raise
        request_with_socket = VMStartRequest(
            run_id=request.run_id,
            tenant=request.tenant,
            guest_ram_mib=request.guest_ram_mib,
            vcpus=request.vcpus,
            boot_deadline_s=request.boot_deadline_s,
            run_deadline_s=request.run_deadline_s,
            ipc_socket_path=str(sock_path),
        )
        probe_handle: VZProbeHandle | None = None
        try:
            probe_handle = self._probe_backend.start(request_with_socket)
            self.last_probe = probe_handle
            conn, _ = server.accept()
        except (OSError, TimeoutError) as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            if probe_handle is not None:
                self.last_console_tail = probe_handle.output_tail
                probe_handle.kill()
                probe_handle.cleanup()
            else:
                self.last_error = "probe handle missing: " + self.last_error
            server.close()
            self._cleanup_socket_root(socket_root)
            return _NoConnectHandle(
                probe_handle, f"ipc_connect_failed:{type(exc).__name__}"
            )
        finally:
            try:
                server.close()
            except OSError:
                pass
        try:
            context = ipc.HostExecutionContext(
                run_id=request.run_id,
                subject=request.tenant,
                policy_digest=self._job.policy_digest,
                module_digest=self._job.module_digest,
                allowed_actions=self._allowed_actions,
                expires_at=time.monotonic() + request.run_deadline_s + 5.0,
            )
            mediator = ipc.HostMediator(
                context=context,
                handles=ipc.HostHandleRegistry(),
                actions={
                    "ready": lambda _c, args: {
                        "ready": True,
                        "phase": args.get("phase", ""),
                    },
                    "done": lambda _c, args: {
                        "done": True,
                        "phase": args.get("phase", ""),
                    },
                    "echo": lambda _c, args: {"value": args.get("value")},
                },
            )
            channel = HVC1HostChannel(
                conn,
                job=self._job,
                context=context,
                mediator=mediator,
                close_callback=(
                    (lambda: probe_handle.kill()) if probe_handle is not None else None
                ),
            )
        except BaseException as exc:
            # The probe is already running and the socket is accepted. Any
            # failure while building the channel must kill/clean both, not
            # leave an unbilled VM behind for the supervisor to forget.
            self.last_error = f"{type(exc).__name__}: {exc}"
            try:
                conn.close()
            except OSError:
                pass
            if probe_handle is not None:
                self.last_console_tail = probe_handle.output_tail
                probe_handle.kill()
                probe_handle.cleanup()
            self._cleanup_socket_root(socket_root)
            raise
        if probe_handle is not None:
            self.last_console_tail = probe_handle.output_tail
        self.last_channel = channel
        return _HVC1ConnectedHandle(channel, probe_handle, socket_root)

    def reap_xpc(self) -> int:
        return self._probe_backend.reap_xpc()

    @staticmethod
    def _cleanup_socket_root(root: Path) -> None:
        try:
            for child in root.iterdir():
                child.unlink(missing_ok=True)
            root.rmdir()
        except OSError:
            pass


@dataclass(frozen=True)
class ProductVMRun:
    status: str
    reason: str | None
    supervisor: SupervisorResult | None
    admit_id: str | None
    charge: Charge | None
    accounting: str
    report: dict | None = None
    usage: TenantUsage | None = None


class ProductVMRunner:
    """Admission + supervisor + D2 settlement for one hvc1 worker run."""

    def __init__(
        self, supervisor: VMSupervisor, *, trust_guest_measurement: bool = False
    ):
        self._supervisor = supervisor
        self._trust_guest = trust_guest_measurement

    @staticmethod
    def reserve_for(
        job: VMJob, request: VMStartRequest, *, attempts: int = 2
    ) -> Charge:
        attempts = max(1, int(attempts))
        output_ceiling = job.io_budget_bytes + 2 * OUTPUT_FILE_HARD_LIMIT
        wall_ceiling = int(
            max(request.boot_deadline_s + request.run_deadline_s + 10.0, 10.0) * 1000
        )
        return Charge(
            fuel=attempts * job.max_fuel,
            output_bytes=attempts * output_ceiling,
            wall_ms=attempts * wall_ceiling,
        )

    def run(
        self,
        request: VMStartRequest,
        job: VMJob,
        *,
        store: TenantStore,
        tenant_budget: CumulativeBudget | None = None,
        host_budget: CumulativeBudget | None = None,
    ) -> ProductVMRun:
        reserve = self.reserve_for(
            job,
            request,
            attempts=getattr(self._supervisor, "max_attempts", 2),
        )
        store.bind_host_budget(host_budget)
        ttl = request.boot_deadline_s + request.run_deadline_s + 60.0
        admission = store.admit(
            TenantId(request.tenant),
            reserve=reserve,
            budget=tenant_budget,
            host_budget=host_budget,
            ttl_seconds=max(ttl, 1.0),
        )
        if not admission.allowed or admission.admit_id is None:
            return ProductVMRun(
                status="refused",
                reason=admission.reason,
                supervisor=None,
                admit_id=None,
                charge=None,
                accounting="no_admission",
                usage=store.usage(request.tenant),
            )
        try:
            result = self._supervisor.run(request)
        except BaseException:
            # The supervisor releases its VM slot, but the tenant reservation
            # is owned here. The run may have started before the exception, so
            # book the full reservation conservatively rather than leave an
            # open lease.
            try:
                store.settle(
                    request.tenant,
                    admission.admit_id,
                    charge=reserve,
                    unknown=True,
                    unknown_fuel_charged=reserve.fuel,
                    unknown_output=True,
                    unknown_output_charged=reserve.output_bytes,
                    unknown_wall=True,
                    unknown_wall_charged_ms=reserve.wall_ms,
                )
            except Exception:
                pass
            raise
        started = result.started
        if not started:
            store.expire(request.tenant, admission.admit_id)
            return ProductVMRun(
                status=result.status,
                reason=result.reason,
                supervisor=result,
                admit_id=admission.admit_id,
                charge=None,
                accounting="expired",
                report=result.report,
                usage=store.usage(request.tenant),
            )
        report = result.report
        measured_fuel = None
        measured_output = None
        if self._trust_guest and isinstance(report, dict):
            fuel = report.get("fuel_consumed")
            if isinstance(fuel, int) and not isinstance(fuel, bool) and fuel >= 0:
                measured_fuel = min(
                    fuel * max(1, int(report.get("worker_attempts", 1))), reserve.fuel
                )
            io_bytes = report.get("io_bytes_written")
            if (
                isinstance(io_bytes, int)
                and not isinstance(io_bytes, bool)
                and io_bytes >= 0
            ):
                measured_output = min(io_bytes, reserve.output_bytes)
        fuel_unknown = measured_fuel is None
        output_unknown = measured_output is None
        charge = Charge(
            fuel=reserve.fuel if measured_fuel is None else measured_fuel,
            output_bytes=(
                reserve.output_bytes if measured_output is None else measured_output
            ),
            wall_ms=result.wall_ms,
        )
        store.settle(
            request.tenant,
            admission.admit_id,
            charge=charge,
            unknown=fuel_unknown,
            unknown_fuel_charged=reserve.fuel if fuel_unknown else 0,
            unknown_output=output_unknown,
            unknown_output_charged=reserve.output_bytes if output_unknown else 0,
        )
        return ProductVMRun(
            status=result.status,
            reason=result.reason,
            supervisor=result,
            admit_id=admission.admit_id,
            charge=charge,
            accounting=(
                "conservative" if (fuel_unknown or output_unknown) else "measured"
            ),
            report=report,
            usage=store.usage(request.tenant),
        )
