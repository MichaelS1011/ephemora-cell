# Ephemora Cell — Host/Guest IPC protocol (v1.2, isolated step)
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Host-authoritative IPC contract for a guest that may be compromised.

The guest is untrusted. Every field it sends is a *claim*, never a grant:
identity, policy digest, module digest and arguments are checked against the
host's own execution context, and the host decides whether an allowlisted
action may run. The transport is injected; the VM integration (VZ virtio-vsock)
is a separate step. Until that transport is in the active A7 sentinel matrix,
this module is not an A7 claim.

Frame: 4-byte big-endian length + RFC-8785 (JCS) JSON, max 64 KiB.
"""

from __future__ import annotations

import base64
import binascii
import json
import secrets
import socket
import struct
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from .execution_report import jcs_canonicalize

IPC_VERSION = 1
MAX_FRAME_BYTES = 64 * 1024
MAX_IN_FLIGHT = 8
#: A host→guest job payload (the user's module or script) travels in
#: chunks after ``ready``. 24 KiB of raw bytes stay well below the 64 KiB
#: frame cap once base64 and JSON overhead are added.
PAYLOAD_CHUNK_BYTES = 24 * 1024
MAX_PAYLOAD_BYTES = 32 * 1024 * 1024
_CHUNK_SEQ_MAX = 1_000_000
_FORBIDDEN_ARGUMENT_KEYS = frozenset(
    {
        "path",
        "file",
        "filepath",
        "filename",
        "socket",
        "url",
        "uri",
        "host",
        "hostname",
        "credential",
        "credentials",
        "token",
        "secret",
        "keyfile",
    }
)
_CLAIM_KEYS = frozenset({"subject", "policy_digest", "module_digest"})
_MAX_STRING = 1024
_MAX_ITEMS = 32
_MAX_DEPTH = 4


class IPCViolation(Exception):
    """A frame or a request violates the host-authoritative contract."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class IPCDisconnected(IPCViolation):
    """The transport ended before a complete frame arrived."""

    def __init__(self) -> None:
        super().__init__("disconnected")


@dataclass(frozen=True)
class HostExecutionContext:
    """Values the HOST issued for one run; never read from the guest."""

    run_id: str
    subject: str
    policy_digest: str
    module_digest: str
    allowed_actions: frozenset[str]
    expires_at: float  # time.monotonic() deadline
    max_in_flight: int = MAX_IN_FLIGHT


@dataclass(frozen=True)
class IPCRequest:
    seq: int
    action: str
    arguments: dict[str, Any]
    claims: dict[str, str]


class HostHandleRegistry:
    """Opaque host handles; guests reference an id, never a host object/path."""

    def __init__(self) -> None:
        self._values: dict[str, Any] = {}

    def issue(self, value: Any) -> str:
        handle = secrets.token_hex(16)
        self._values[handle] = value
        return handle

    def resolve(self, handle: str) -> Any:
        try:
            return self._values[handle]
        except KeyError as exc:
            raise IPCViolation("unknown_handle") from exc

    def revoke(self, handle: str) -> None:
        self._values.pop(handle, None)


def _check_value(value: Any, depth: int = 0) -> None:
    if depth > _MAX_DEPTH:
        raise IPCViolation("arguments_too_deep")
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise IPCViolation("arguments_not_finite")
        return
    if isinstance(value, str):
        if len(value.encode("utf-8")) > _MAX_STRING:
            raise IPCViolation("argument_string_too_long")
        return
    if isinstance(value, list):
        if len(value) > _MAX_ITEMS:
            raise IPCViolation("arguments_list_too_long")
        for item in value:
            _check_value(item, depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > _MAX_ITEMS:
            raise IPCViolation("arguments_map_too_large")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 64:
                raise IPCViolation("argument_key_invalid")
            if key.lower() in _FORBIDDEN_ARGUMENT_KEYS:
                raise IPCViolation("argument_key_forbidden")
            _check_value(item, depth + 1)
        return
    raise IPCViolation("argument_type_invalid")


def encode_request(
    *,
    run_id: str,
    seq: int,
    action: str,
    arguments: Mapping[str, Any],
    subject: str,
    policy_digest: str,
    module_digest: str,
) -> bytes:
    frame = {
        "ipc_version": IPC_VERSION,
        "kind": "request",
        "run_id": run_id,
        "seq": seq,
        "action": action,
        "arguments": dict(arguments),
        "claims": {
            "subject": subject,
            "policy_digest": policy_digest,
            "module_digest": module_digest,
        },
    }
    payload = jcs_canonicalize(frame).encode("utf-8")
    if len(payload) > MAX_FRAME_BYTES:
        raise IPCViolation("frame_too_large")
    return payload


def encode_result(
    *,
    run_id: str,
    seq: int,
    status: str,
    value: Any = None,
    reason: str | None = None,
) -> bytes:
    frame: dict[str, Any] = {
        "ipc_version": IPC_VERSION,
        "kind": "result",
        "run_id": run_id,
        "seq": seq,
        "status": status,
    }
    if reason is not None:
        frame["reason"] = reason
    if value is not None:
        frame["value"] = value
    payload = jcs_canonicalize(frame).encode("utf-8")
    if len(payload) > MAX_FRAME_BYTES:
        return encode_result(
            run_id=run_id, seq=seq, status="refused", reason="result_too_large"
        )
    return payload


def _claims_frame(
    kind: str,
    *,
    run_id: str,
    subject: str,
    policy_digest: str,
    module_digest: str,
    **extra: Any,
) -> bytes:
    frame = {
        "ipc_version": IPC_VERSION,
        "kind": kind,
        "run_id": run_id,
        "claims": {
            "subject": subject,
            "policy_digest": policy_digest,
            "module_digest": module_digest,
        },
        **extra,
    }
    payload = jcs_canonicalize(frame).encode("utf-8")
    if len(payload) > MAX_FRAME_BYTES:
        raise IPCViolation("frame_too_large")
    return payload


def encode_host_job(
    *,
    run_id: str,
    job: Mapping[str, Any],
    subject: str,
    policy_digest: str,
    module_digest: str,
) -> bytes:
    """Host→guest job descriptor. The host controls every field."""
    return _claims_frame(
        "job",
        run_id=run_id,
        subject=subject,
        policy_digest=policy_digest,
        module_digest=module_digest,
        job=dict(job),
    )


def encode_hello() -> bytes:
    """Guest readiness signal; carries no identity and grants nothing."""
    return jcs_canonicalize({"ipc_version": IPC_VERSION, "kind": "hello"}).encode(
        "utf-8"
    )


def decode_hello(payload: bytes) -> None:
    doc = decode_json_frame(payload)
    if doc.get("kind") != "hello":
        raise IPCViolation("not_a_hello")


def decode_host_job(payload: bytes) -> dict[str, Any]:
    """Guest-side parse of the host job. Claims are correlation, not grants."""
    doc = decode_json_frame(payload)
    if doc.get("kind") != "job":
        raise IPCViolation("not_a_job")
    run_id = doc.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise IPCViolation("run_id_invalid")
    job = doc.get("job")
    if not isinstance(job, dict):
        raise IPCViolation("job_invalid")
    claims = doc.get("claims")
    if not isinstance(claims, dict) or not set(claims) == _CLAIM_KEYS:
        raise IPCViolation("claims_invalid")
    for _key, value in claims.items():
        if not isinstance(value, str):
            raise IPCViolation("claims_invalid")
    return doc


def encode_chunk(*, run_id: str, seq: int, data: bytes, last: bool) -> bytes:
    """Host→guest payload chunk. The host is the only sender of this kind."""
    if not isinstance(data, (bytes, bytearray)) or len(data) > PAYLOAD_CHUNK_BYTES:
        raise IPCViolation("chunk_too_large")
    frame = {
        "ipc_version": IPC_VERSION,
        "kind": "chunk",
        "run_id": run_id,
        "seq": seq,
        "data": base64.b64encode(bytes(data)).decode("ascii"),
        "last": bool(last),
    }
    payload = jcs_canonicalize(frame).encode("utf-8")
    if len(payload) > MAX_FRAME_BYTES:
        raise IPCViolation("frame_too_large")
    return payload


def decode_chunk(
    payload: bytes,
    *,
    run_id: str,
    last_seq: int,
    received: int,
    total: int,
) -> tuple[int, bytes, bool]:
    """Guest-side parse of one payload chunk.

    Bounds are enforced here, not by the caller: monotone sequence, per-frame
    and cumulative size ceilings, an optional ``last`` flag, and the declared
    total. A chunk that would exceed the declared payload is refused before it
    is written anywhere.
    """
    if (
        isinstance(total, bool)
        or not isinstance(total, int)
        or total <= 0
        or total > MAX_PAYLOAD_BYTES
    ):
        raise IPCViolation("payload_size_invalid")
    doc = decode_json_frame(payload)
    if doc.get("kind") != "chunk":
        raise IPCViolation("not_a_chunk")
    if doc.get("run_id") != run_id:
        raise IPCViolation("run_id_mismatch")
    seq = doc.get("seq")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq <= last_seq:
        raise IPCViolation("chunk_replay")
    if seq > _CHUNK_SEQ_MAX:
        raise IPCViolation("chunk_seq_invalid")
    encoded = doc.get("data")
    if not isinstance(encoded, str):
        raise IPCViolation("chunk_data_invalid")
    try:
        data = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise IPCViolation("chunk_not_base64") from exc
    if not data:
        raise IPCViolation("chunk_empty")
    if len(data) > PAYLOAD_CHUNK_BYTES:
        raise IPCViolation("chunk_too_large")
    if seq > (total + PAYLOAD_CHUNK_BYTES - 1) // PAYLOAD_CHUNK_BYTES:
        raise IPCViolation("chunk_seq_invalid")
    last = doc.get("last")
    if not isinstance(last, bool):
        raise IPCViolation("chunk_last_invalid")
    if received + len(data) > total:
        raise IPCViolation("payload_overflow")
    return seq, data, last


def encode_report(
    *,
    run_id: str,
    seq: int,
    report: Mapping[str, Any],
    subject: str,
    policy_digest: str,
    module_digest: str,
) -> bytes:
    """Guest→host worker report. The report is a claim, never a grant."""
    return _claims_frame(
        "report",
        run_id=run_id,
        seq=seq,
        subject=subject,
        policy_digest=policy_digest,
        module_digest=module_digest,
        report=dict(report),
    )


def decode_report(
    payload: bytes,
    *,
    context: HostExecutionContext,
    last_seq: int,
    now: float | None = None,
) -> tuple[int, dict[str, Any]]:
    """Validate a report frame against the host's own context and sequence."""
    if (now if now is not None else time.monotonic()) > context.expires_at:
        raise IPCViolation("expired")
    doc = decode_json_frame(payload)
    if doc.get("kind") != "report":
        raise IPCViolation("not_a_report")
    if doc.get("run_id") != context.run_id:
        raise IPCViolation("run_id_mismatch")
    seq = doc.get("seq")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq <= 0:
        raise IPCViolation("seq_invalid")
    if seq <= last_seq:
        raise IPCViolation("replay")
    claims = doc.get("claims")
    if not isinstance(claims, dict) or set(claims) != _CLAIM_KEYS:
        raise IPCViolation("claims_invalid")
    expected = {
        "subject": context.subject,
        "policy_digest": context.policy_digest,
        "module_digest": context.module_digest,
    }
    for key, value in claims.items():
        if not isinstance(value, str):
            raise IPCViolation("claims_invalid")
        if value != expected[key]:
            raise IPCViolation(f"{key}_mismatch")
    report = doc.get("report")
    if not isinstance(report, dict):
        raise IPCViolation("report_invalid")
    return seq, report


def decode_json_frame(payload: bytes) -> dict[str, Any]:
    if len(payload) > MAX_FRAME_BYTES:
        raise IPCViolation("frame_too_large")
    try:
        doc = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise IPCViolation("frame_not_json") from exc
    if not isinstance(doc, dict):
        raise IPCViolation("frame_not_object")
    if doc.get("ipc_version") != IPC_VERSION:
        raise IPCViolation("ipc_version_unsupported")
    return doc


def decode_request(
    payload: bytes,
    *,
    context: HostExecutionContext,
    last_seq: int,
) -> IPCRequest:
    doc = decode_json_frame(payload)
    if doc.get("kind") != "request":
        raise IPCViolation("not_a_request")
    if doc.get("run_id") != context.run_id:
        raise IPCViolation("run_id_mismatch")
    seq = doc.get("seq")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq <= 0:
        raise IPCViolation("seq_invalid")
    if seq <= last_seq:
        raise IPCViolation("replay")
    action = doc.get("action")
    if not isinstance(action, str) or action not in context.allowed_actions:
        raise IPCViolation("action_not_allowed")
    arguments = doc.get("arguments")
    if not isinstance(arguments, dict):
        raise IPCViolation("arguments_invalid")
    _check_value(arguments)
    claims = doc.get("claims", {})
    if not isinstance(claims, dict):
        raise IPCViolation("claims_invalid")
    if not set(claims) <= _CLAIM_KEYS:
        raise IPCViolation("claims_unknown")
    for key, value in claims.items():
        if not isinstance(value, str):
            raise IPCViolation("claims_invalid")
        expected = {
            "subject": context.subject,
            "policy_digest": context.policy_digest,
            "module_digest": context.module_digest,
        }[key]
        if value != expected:
            raise IPCViolation(f"{key}_mismatch")
    return IPCRequest(seq=seq, action=action, arguments=arguments, claims=claims)


ActionHandler = Callable[[HostExecutionContext, dict[str, Any]], Any]


@dataclass
class HostMediator:
    """Applies the host context to guest frames; never grants from a claim."""

    context: HostExecutionContext
    handles: HostHandleRegistry
    actions: Mapping[str, ActionHandler]
    last_seq: int = 0
    in_flight: int = 0
    executed: list[str] = field(default_factory=list)

    def handle_frame(self, payload: bytes, *, now: float | None = None) -> bytes:
        if (now if now is not None else time.monotonic()) > self.context.expires_at:
            return encode_result(
                run_id=self.context.run_id, seq=0, status="refused", reason="expired"
            )
        try:
            request = decode_request(
                payload, context=self.context, last_seq=self.last_seq
            )
        except IPCViolation as exc:
            return encode_result(
                run_id=self.context.run_id,
                seq=0,
                status="refused",
                reason=exc.reason,
            )
        if self.in_flight >= self.context.max_in_flight:
            return encode_result(
                run_id=self.context.run_id,
                seq=request.seq,
                status="refused",
                reason="busy",
            )
        self.last_seq = request.seq
        self.in_flight += 1
        try:
            resolved = self._resolve_handles(request.arguments)
            value = self.actions[request.action](self.context, resolved)
        except IPCViolation as exc:
            return encode_result(
                run_id=self.context.run_id,
                seq=request.seq,
                status="refused",
                reason=exc.reason,
            )
        except Exception:
            return encode_result(
                run_id=self.context.run_id,
                seq=request.seq,
                status="error",
                reason="action_failed",
            )
        finally:
            self.in_flight -= 1
        self.executed.append(request.action)
        return encode_result(
            run_id=self.context.run_id, seq=request.seq, status="ok", value=value
        )

    def _resolve_handles(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        resolved = dict(arguments)
        handle = resolved.get("handle")
        if handle is not None:
            if not isinstance(handle, str):
                raise IPCViolation("handle_invalid")
            resolved["_value"] = self.handles.resolve(handle)
        return resolved


class FrameStream(Protocol):
    """What frame transport needs from its peer: two ordered byte methods.

    Both a :class:`socket.socket` and the serial-line transport the VM channel
    uses satisfy this structurally, so framing stays one implementation instead
    of two — and the length-prefix rules cannot drift apart per transport.
    """

    def sendall(self, data: bytes) -> None: ...

    def recv(self, __count: int) -> bytes: ...


def send_frame(sock: FrameStream, payload: bytes) -> None:
    if len(payload) > MAX_FRAME_BYTES:
        raise IPCViolation("frame_too_large")
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def recv_frame(sock: FrameStream) -> bytes:
    header = _recv_exact(sock, 4)
    (length,) = struct.unpack(">I", header)
    if length == 0 or length > MAX_FRAME_BYTES:
        raise IPCViolation("frame_too_large")
    return _recv_exact(sock, length)


def _recv_exact(sock: FrameStream, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise IPCDisconnected()
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class GuestClient:
    """Guest-side frame builder. All values here are claims, not grants."""

    def __init__(
        self,
        sock: FrameStream,
        *,
        run_id: str,
        subject: str,
        policy_digest: str,
        module_digest: str,
    ) -> None:
        self._sock: FrameStream | socket.socket = sock
        self._run_id = run_id
        self._subject = subject
        self._policy_digest = policy_digest
        self._module_digest = module_digest
        self._seq = 0

    def request(self, action: str, arguments: Mapping[str, Any] | None = None) -> dict:
        self._seq += 1
        payload = encode_request(
            run_id=self._run_id,
            seq=self._seq,
            action=action,
            arguments=arguments or {},
            subject=self._subject,
            policy_digest=self._policy_digest,
            module_digest=self._module_digest,
        )
        send_frame(self._sock, payload)
        result = decode_json_frame(recv_frame(self._sock))
        if result.get("kind") != "result" or result.get("seq") != self._seq:
            raise IPCViolation("result_seq_mismatch")
        return result

    def close(self) -> None:
        # The client does not own the stream it was handed. A socket is closed;
        # a serial transport belongs to the channel that opened it.
        if isinstance(self._sock, socket.socket):
            self._sock.close()
