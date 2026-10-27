# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""Pin the actual WASI Preview1 socket surface of the qualified runtime.

The public claim is deliberately narrower than "no socket surface": the
qualified 49.0.4 linker defines the handle-only calls (accept/recv/send/
shutdown) but defines no way to create or connect a socket. This test fails if
a later engine starts exposing creation or connect, and the present-handle case
is the positive control proving the probe can detect a defined import at all.
"""

from __future__ import annotations

import importlib.metadata

import pytest

wasmtime = pytest.importorskip("wasmtime")

_QUALIFIED_RELEASE = "49.0.4.post1"
pytestmark = pytest.mark.skipif(
    importlib.metadata.version("wasmtime").split("+")[0] != _QUALIFIED_RELEASE,
    reason="socket import surface is pinned to the qualified 49.0.4 build",
)

_SIGNATURES = {
    "sock_open": "(param i32 i32 i32 i32) (result i32)",
    "sock_bind": "(param i32 i32 i32) (result i32)",
    "sock_connect": "(param i32 i32 i32) (result i32)",
    "sock_listen": "(param i32 i32) (result i32)",
    "sock_accept": "(param i32 i32 i32) (result i32)",
    "sock_recv": "(param i32 i32 i32 i32 i32 i32) (result i32)",
    "sock_send": "(param i32 i32 i32 i32 i32) (result i32)",
    "sock_shutdown": "(param i32 i32) (result i32)",
    "proc_spawn": "(param i32) (result i32)",
    "proc_exec": "(param i32) (result i32)",
    "proc_fork": "(result i32)",
}


def _links(name: str) -> bool:
    engine = wasmtime.Engine()
    wat = (
        '(module (import "wasi_snapshot_preview1" "'
        + name
        + '" (func '
        + _SIGNATURES[name]
        + ")))"
    )
    module = wasmtime.Module(engine, wasmtime.wat2wasm(wat))
    store = wasmtime.Store(engine)
    store.set_wasi(wasmtime.WasiConfig())
    linker = wasmtime.Linker(engine)
    linker.define_wasi()
    try:
        linker.instantiate(store, module)
    except Exception as exc:
        if "unknown import" in str(exc):
            return False
        raise
    return True


@pytest.mark.parametrize(
    "name", ["sock_open", "sock_bind", "sock_connect", "sock_listen"]
)
def test_socket_creation_and_connect_are_not_defined(name):
    assert _links(name) is False, f"{name} became reachable on this runtime"


@pytest.mark.parametrize(
    "name", ["sock_accept", "sock_recv", "sock_send", "sock_shutdown"]
)
def test_handle_operations_are_defined_positive_probe_control(name):
    assert _links(name) is True, (
        "the probe can no longer detect a defined import; the absent cases "
        "above would be unfalsifiable"
    )


@pytest.mark.parametrize("name", ["proc_spawn", "proc_exec", "proc_fork"])
def test_process_spawning_is_not_defined(name):
    assert _links(name) is False, f"{name} became reachable on this runtime"
