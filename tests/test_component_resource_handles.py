# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Real component-model resource-handle lifetime test (WASI 0.2 era).

The component now imports a host-defined resource type and one host function
that takes an *owned* handle. Its exported ``f`` forwards the handle back to
the host, so the test exercises the ownership transit host -> guest -> host,
the resource destructor, and double-drop behaviour on the same engine
configuration the product ships (``build_engine_config``).

The component bytes below were compiled with wasm-tools 1.255.0 from
``COMPONENT_WAT`` and are embedded (not generated at test time) so the test
needs no external toolchain. The digest is pinned: if the bytes change, the
test says the fixture is no longer the measured artifact.

Coverage added where the existing suite had none:
* resource type + destructor acceptance by the loader guard,
* a real owned handle being dropped exactly once (destructor runs once),
* a second drop of the same handle failing without re-running the destructor,
* two handles keeping independent lifetimes,
* a valid nested sync component being accepted (positive control for the
  nested-component recursion, which previously had only refusal tests).
"""

from __future__ import annotations

import base64
import hashlib
import os
import sys

import pytest
import wasmtime
import wasmtime.component as component

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell._engine_config import build_engine_config
from ephemora_cell.component_guard import ComponentGuardError, guard_component_bytes

# Source of the embedded component. Rebuild with:
#   wasm-tools parse resource_component.wat -o resource_component.wasm
COMPONENT_WAT = """(component
  (import "r" (type $r (sub resource)))
  (import "take" (func $take (param "x" (own $r)) (result u32)))
  (core module $m
    (import "" "take" (func $take (param i32) (result i32)))
    (func (export "f") (param i32) (result i32) local.get 0 call $take)
  )
  (core func $take_lowered (canon lower (func $take)))
  (core instance $i (instantiate $m (with "" (instance (export "take" (func $take_lowered))))))
  (type $ft (func (param "x" (own $r)) (result u32)))
  (func (export "f") (type $ft) (canon lift (core func $i "f")))
)
"""

COMPONENT_B64 = """
AGFzbQ0AAQAKBgEAAXIDAQcKAmkAQAEBeAEAeQoJAQAEdGFrZQECAUQAYXNtAQAAAAEGAWABfwF/
AgkBAAR0YWtlAAADAgEABwUBAWYAAQoIAQYAIAAQAAsAEgRuYW1lAAIBbQEHAQAEdGFrZQgFAQEA
AAACEAIBAQR0YWtlAAAAAAEAEgAHCgJpAEABAXgDAHkGBwEAAAEBAWYIBgEAAAEABAsHAQABZgEB
AABHDmNvbXBvbmVudC1uYW1lAREAAAEADHRha2VfbG93ZXJlZAEGABEBAAFtAQYAEgEBAWkBCAEB
AAR0YWtlAQkDAgABcgQCZnQ=
"""

COMPONENT_BYTES = base64.b64decode("".join(COMPONENT_B64.split()))
COMPONENT_SHA256 = "0936484039727cb4ec28acc3dafebaf8df0fa5195af792560937a90ed474b45f"
_HOST_RESOURCE_ID = 1
_HEADER = bytes([0x00, 0x61, 0x73, 0x6D, 0x0D, 0x00, 0x01, 0x00])


def _section(section_id: int, payload: bytes) -> bytes:
    # Test vectors stay below 128 bytes, so a single-byte LEB length is exact.
    assert len(payload) < 128
    return bytes([section_id, len(payload)]) + payload


def _instantiate(dtor, take):
    engine = wasmtime.Engine(build_engine_config(max_fuel=None, memory64=False))
    store = wasmtime.Store(engine)
    # build_engine_config enables epoch interruption; an unset deadline traps.
    store.set_epoch_deadline(1 << 60)
    linker = component.Linker(engine)
    with linker.root() as root:
        root.add_resource("r", component.ResourceType.host(_HOST_RESOURCE_ID), dtor)
        root.add_func("take", take)
    instance = linker.instantiate(store, component.Component(engine, COMPONENT_BYTES))
    func = instance.get_func(store, "f")
    assert func is not None
    return store, func


def test_embedded_component_is_the_pinned_artifact():
    assert hashlib.sha256(COMPONENT_BYTES).hexdigest() == COMPONENT_SHA256


def test_guard_accepts_real_resource_component():
    assert guard_component_bytes(COMPONENT_BYTES) is None


def test_guard_accepts_valid_nested_sync_component():
    inner = _HEADER + _section(0x07, bytes([0x01, 0x40, 0x00, 0x01, 0x00]))
    nested = _HEADER + _section(0x04, inner)
    assert guard_component_bytes(nested) is None


def test_guard_refuses_malformed_resource_destructor():
    # resourcetype (0x3F), rep i32 (0x7F), invalid has-dtor byte 0x02.
    malformed = _HEADER + _section(0x07, bytes([0x01, 0x3F, 0x7F, 0x02]))
    with pytest.raises(ComponentGuardError, match="malformed resource dtor"):
        guard_component_bytes(malformed)


def test_owned_handle_runs_destructor_once_and_rejects_double_drop():
    seen: list[tuple[str, object]] = []

    def dtor(_ctx, rep):
        seen.append(("drop", rep))

    def take(ctx, handle):
        seen.append(("take", handle.owned))
        handle.drop(ctx)
        try:
            handle.drop(ctx)
        except wasmtime.WasmtimeError as exc:
            seen.append(("second_drop_error", str(exc).splitlines()[-1]))
        else:  # pragma: no cover - a silent second drop is the bug
            seen.append(("second_drop_error", "none"))
        return 5

    store, func = _instantiate(dtor, take)
    handle = component.ResourceHost.own(7, _HOST_RESOURCE_ID).to_any(store)
    assert handle.owned is True
    assert func(store, handle) == 5
    assert seen[0] == ("take", True)
    assert seen[1] == ("drop", 7)
    assert seen[2][0] == "second_drop_error"
    assert "unknown handle" in seen[2][1]
    assert [x for x in seen if x[0] == "drop"] == [("drop", 7)]


def test_two_handles_keep_independent_lifetimes():
    dropped: list[int] = []

    def dtor(_ctx, rep):
        dropped.append(rep)

    def take(ctx, handle):
        handle.drop(ctx)
        return 5

    store, func = _instantiate(dtor, take)
    for rep in (11, 13):
        handle = component.ResourceHost.own(rep, _HOST_RESOURCE_ID).to_any(store)
        assert func(store, handle) == 5
    assert dropped == [11, 13]
