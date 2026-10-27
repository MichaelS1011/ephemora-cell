"""v1.2 — host-authoritative IPC contract and negative controls."""

from __future__ import annotations

import json
import socket
import struct
import time

import pytest

from ephemora_cell.ipc_protocol import (
    MAX_FRAME_BYTES,
    GuestClient,
    HostExecutionContext,
    HostHandleRegistry,
    HostMediator,
    IPCDisconnected,
    IPCViolation,
    decode_json_frame,
    decode_request,
    encode_request,
    recv_frame,
    send_frame,
)


def context(**overrides):
    values = dict(
        run_id="run-1",
        subject="tenant:a",
        policy_digest="p" * 64,
        module_digest="m" * 64,
        allowed_actions=frozenset({"echo", "read"}),
        expires_at=time.monotonic() + 60,
    )
    values.update(overrides)
    return HostExecutionContext(**values)


def mediator(context_value=None, handles=None, actions=None):
    return HostMediator(
        context=context_value or context(),
        handles=handles or HostHandleRegistry(),
        actions=actions
        or {
            "echo": lambda _ctx, args: {"value": args.get("value")},
            "read": lambda _ctx, args: {"length": len(args["_value"])},
        },
    )


def request_frame(**overrides):
    values = dict(
        run_id="run-1",
        seq=1,
        action="echo",
        arguments={"value": "hi"},
        subject="tenant:a",
        policy_digest="p" * 64,
        module_digest="m" * 64,
    )
    values.update(overrides)
    return encode_request(**values)


def result_of(frame: bytes) -> dict:
    return decode_json_frame(frame)


def test_frame_roundtrip_and_host_context_binding():
    payload = request_frame()
    request = decode_request(payload, context=context(), last_seq=0)
    assert request.seq == 1
    assert request.action == "echo"
    assert request.claims["subject"] == "tenant:a"

    result = result_of(mediator().handle_frame(payload))
    assert result["status"] == "ok"
    assert result["value"] == {"value": "hi"}
    assert result["run_id"] == "run-1"


def test_oversized_frame_is_refused_before_json():
    with pytest.raises(IPCViolation, match="frame_too_large"):
        decode_json_frame(b"x" * (MAX_FRAME_BYTES + 1))

    host, guest = socket.socketpair()
    try:
        guest.sendall(struct.pack(">I", MAX_FRAME_BYTES + 1))
        with pytest.raises(IPCViolation, match="frame_too_large"):
            recv_frame(host)
    finally:
        host.close()
        guest.close()


def test_forged_subject_is_refused_and_action_not_executed():
    m = mediator()
    frame = request_frame(subject="tenant:b")
    result = result_of(m.handle_frame(frame))
    assert result["status"] == "refused"
    assert result["reason"] == "subject_mismatch"
    assert m.executed == []


def test_forged_policy_and_module_digest_are_refused():
    m = mediator()
    for field in ("policy_digest", "module_digest"):
        result = result_of(m.handle_frame(request_frame(**{field: "f" * 64})))
        assert result["status"] == "refused"
        assert result["reason"] == f"{field}_mismatch"
    assert m.executed == []


def test_replay_and_out_of_order_are_refused():
    m = mediator()
    first = request_frame(seq=1)
    assert result_of(m.handle_frame(first))["status"] == "ok"
    replay = result_of(m.handle_frame(first))
    assert replay["status"] == "refused"
    assert replay["reason"] == "replay"

    m2 = mediator()
    assert result_of(m2.handle_frame(request_frame(seq=2)))["status"] == "ok"
    out_of_order = result_of(m2.handle_frame(request_frame(seq=1)))
    assert out_of_order["status"] == "refused"
    assert out_of_order["reason"] == "replay"


def test_path_arguments_are_refused_even_nested():
    m = mediator()
    for arguments in (
        {"path": "/etc/passwd"},
        {"nested": {"file": "secret"}},
        {"items": [{"socket": "/tmp/x"}]},
    ):
        result = result_of(m.handle_frame(request_frame(arguments=arguments)))
        assert result["status"] == "refused"
        assert result["reason"] == "argument_key_forbidden"
    assert m.executed == []


def test_unknown_action_is_refused():
    result = result_of(mediator().handle_frame(request_frame(action="host.read_file")))
    assert result["status"] == "refused"
    assert result["reason"] == "action_not_allowed"


def test_expired_context_refuses_without_executing():
    m = mediator(context_value=context(expires_at=time.monotonic() - 1))
    result = result_of(m.handle_frame(request_frame()))
    assert result["status"] == "refused"
    assert result["reason"] == "expired"
    assert m.executed == []


def test_handle_is_opaque_and_guest_never_sees_host_value():
    handles = HostHandleRegistry()
    handle = handles.issue("sensitive-host-object")
    m = mediator(handles=handles)
    frame = request_frame(action="read", arguments={"handle": handle})
    raw = m.handle_frame(frame)
    result = result_of(raw)
    assert result["status"] == "ok"
    assert result["value"] == {"length": len("sensitive-host-object")}
    assert b"sensitive-host-object" not in raw
    assert m.executed == ["read"]


def test_unknown_handle_is_refused():
    result = result_of(
        mediator().handle_frame(
            request_frame(action="read", arguments={"handle": "0" * 32})
        )
    )
    assert result["status"] == "refused"
    assert result["reason"] == "unknown_handle"


def test_result_too_large_is_refused_without_sending_a_partial_frame():
    m = mediator(actions={"echo": lambda _ctx, _args: "A" * (MAX_FRAME_BYTES + 1)})
    result = result_of(m.handle_frame(request_frame()))
    assert result["status"] == "refused"
    assert result["reason"] == "result_too_large"


def test_host_context_is_authoritative_when_claims_are_absent():
    # A compromised guest may omit claims; the host still applies its context.
    raw = encode_request(
        run_id="run-1",
        seq=1,
        action="echo",
        arguments={"value": "ok"},
        subject="tenant:a",
        policy_digest="p" * 64,
        module_digest="m" * 64,
    )
    doc = json.loads(raw)
    del doc["claims"]
    payload = json.dumps(doc, separators=(",", ":"), sort_keys=True).encode()
    result = result_of(mediator().handle_frame(payload))
    assert result["status"] == "ok"


def test_socketpair_roundtrip_and_fail_closed_disconnect():
    import threading

    host, guest = socket.socketpair()
    try:
        client = GuestClient(
            guest,
            run_id="run-1",
            subject="tenant:a",
            policy_digest="p" * 64,
            module_digest="m" * 64,
        )
        m = mediator()

        def host_loop():
            payload = recv_frame(host)
            send_frame(host, m.handle_frame(payload))

        thread = threading.Thread(target=host_loop)
        thread.start()
        result = client.request("echo", {"value": "over-socket"})
        thread.join(timeout=5)
        assert result["status"] == "ok"
        assert result["value"] == {"value": "over-socket"}
        assert m.executed == ["echo"]
    finally:
        host.close()
        guest.close()

    host, guest = socket.socketpair()
    guest.close()
    with pytest.raises(IPCDisconnected):
        recv_frame(host)
    host.close()
