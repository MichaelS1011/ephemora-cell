# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Tests for the GHSA-32h6 component-model async detector (wired into the loader).

These are pure-Python: they never invoke the native ``wasmtime`` parser (that is
the code under attack) and never spawn a worker, so they run even under host load
and cannot abort the interpreter. They pin two properties of
``ephemora_cell.component_guard``:

* **detection soundness** — a component-model async construct (async functype
  0x43, future 0x65, stream 0x66) is positively refused wherever it appears,
  including inside a nested component; and
* **non-triviality + fail-closed** — a fully-decodable sync component is
  accepted, while any byte stream the reader cannot confidently walk is refused
  (so a bug in the accept path can only ever cause a refusal, never a bypass).

The detector is wired at the single ``wasmtime.component.Component()`` site in
``wasi_02.ComponentSandbox.run``: ``TestAcceptSideRealGuests`` shows the real
WASI p2 guests the product runs walk cleanly (no over-rejection), and
``TestLoaderIntegration`` proves an async-lifted component is refused with a
``GHSA-32h6-97mm-8q3c`` error *before* the native parser while a real guest is
not blocked. Fail-closed still applies to any byte the reader cannot confidently
walk (e.g. an embedded core WasmGC ``type`` declarator) — over-reject only,
never a bypass. See the module docstring.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import component_guard as _cg
from ephemora_cell.component_guard import (
    ComponentGuardError,
    guard_component_bytes,
)

# Component layer header: magic \0asm + version 0x0d 0x00 + layer 0x01 0x00.
_HEADER = bytes([0x00, 0x61, 0x73, 0x6D, 0x0D, 0x00, 0x01, 0x00])
_SECTION_TYPE = 0x07
_SECTION_COMPONENT = 0x04


def _section(section_id: int, payload: bytes) -> bytes:
    assert len(payload) < 128, "test vectors keep sizes single-byte LEB"
    return bytes([section_id, len(payload)]) + payload


def _sync_functype_only() -> bytes:
    # vec(type) count 1; functype 0x40; paramlist vec count 0; resultlist 0x01 0x00.
    return _HEADER + _section(_SECTION_TYPE, bytes([0x01, 0x40, 0x00, 0x01, 0x00]))


def _async_functype() -> bytes:
    return _HEADER + _section(_SECTION_TYPE, bytes([0x01, 0x43, 0x00, 0x01, 0x00]))


def _future() -> bytes:
    # future 0x65 with no element type (0x00).
    return _HEADER + _section(_SECTION_TYPE, bytes([0x01, 0x65, 0x00]))


def _stream() -> bytes:
    # stream 0x66 with no element type (0x00).
    return _HEADER + _section(_SECTION_TYPE, bytes([0x01, 0x66, 0x00]))


def _nested_async() -> bytes:
    inner = _async_functype()
    return _HEADER + _section(_SECTION_COMPONENT, inner)


class TestAsyncDetection:
    def test_sync_component_is_accepted(self):
        # Proves the detector is not a blanket reject: a fully-parseable sync
        # component walks cleanly.
        assert guard_component_bytes(_sync_functype_only()) is None

    @pytest.mark.parametrize(
        "vector,label",
        [
            (_async_functype(), "async functype"),
            (_future(), "future"),
            (_stream(), "stream"),
        ],
    )
    def test_async_construct_refused(self, vector, label):
        with pytest.raises(ComponentGuardError) as excinfo:
            guard_component_bytes(vector)
        message = str(excinfo.value)
        assert label in message
        assert "GHSA-32h6-97mm-8q3c" in message

    def test_async_in_nested_component_refused(self):
        with pytest.raises(ComponentGuardError, match="async functype"):
            guard_component_bytes(_nested_async())


class TestFailClosed:
    def test_truncated_type_section_refused(self):
        # A type section that starts an async functype but is cut off mid-entry:
        # the reader must refuse, never silently accept a truncated walk.
        truncated = _HEADER + _section(_SECTION_TYPE, bytes([0x01, 0x43, 0x00]))
        with pytest.raises(ComponentGuardError):
            guard_component_bytes(truncated)

    def test_non_component_bytes_refused(self):
        core_module = bytes([0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00])
        with pytest.raises(ComponentGuardError):
            guard_component_bytes(core_module)

    def test_missing_magic_refused(self):
        with pytest.raises(ComponentGuardError):
            guard_component_bytes(b"not a wasm file at all")

    def test_truncated_nested_component_refused(self):
        # A nested section carrying only the four magic bytes has no version and
        # no layer to check. Slicing it to "header, then nothing" used to walk as
        # an empty inner component and pass; the nested header is now held to the
        # same eight-byte invariant as the outer one.
        nested = _HEADER + _section(_SECTION_COMPONENT, bytes(_HEADER[:4]))
        with pytest.raises(ComponentGuardError, match="truncated nested component"):
            guard_component_bytes(nested)

    def test_non_component_layer_nested_refused(self):
        # component version byte inside the nested section, but layer 0x0002.
        inner = bytes([0x00, 0x61, 0x73, 0x6D, 0x0D, 0x00, 0x02, 0x00])
        nested = _HEADER + _section(_SECTION_COMPONENT, inner)
        with pytest.raises(
            ComponentGuardError, match="nested component is not a component-layer"
        ):
            guard_component_bytes(nested)


class TestAcceptSideRealGuests:
    """Positive controls: the real production guests walk cleanly.

    These are the guests the product actually runs (WASI p2 components). If any
    of these is refused, the guard is a product regression and must not ship
    wired — so this is the acceptance gate for wiring.
    """

    @pytest.mark.parametrize(
        "fixture",
        [
            "hello02.wasm",
            "fs02.wasm",
            "wat_run.wasm",
            "wat_loop.wasm",
            "wat_no_run.wasm",
        ],
    )
    def test_real_component_accepted(self, fixture):
        path = os.path.join(os.path.dirname(__file__), "fixtures", fixture)
        data = open(path, "rb").read()
        assert guard_component_bytes(data) is None

    def test_async_inside_instance_type_declarator_flagged(self):
        # A component type that nests an instancetype containing an async
        # functype — proves the recursion reaches async types declared inside
        # component/instance type bodies, not only the top-level type vector.
        # instancetype 0x42 -> vec 1 -> instancedecl 0x01 <type> -> async 0x43.
        inner = bytes([0x01, 0x42, 0x01, 0x01, 0x43, 0x00, 0x01, 0x00])
        component = _HEADER + _section(_SECTION_TYPE, inner)
        with pytest.raises(ComponentGuardError, match="async functype"):
            guard_component_bytes(component)


class TestLoaderIntegration:
    """The guard is wired at the single Component() construction site."""

    def test_async_component_refused_before_native_parser(self, tmp_path):
        from ephemora_cell.wasi_02 import ComponentSandbox
        from ephemora_cell.wasi_runtime import WASIConfig

        # An async-lifted component the loader must refuse. It is a valid
        # component-layer binary (passes is_component_binary) but carries an
        # async functype; the guard fires before wasmtime.Component().
        bad = tmp_path / "async.wasm"
        bad.write_bytes(_async_functype())
        sandbox = ComponentSandbox(WASIConfig(max_fuel=5_000_000))
        try:
            result = sandbox.run(str(bad))
            assert result.status.value.lower() == "error"
            joined = (result.stderr or "").lower()
            assert "component guard" in joined
            assert "ghsa-32h6" in joined
            assert "async" in joined
        finally:
            sandbox.cleanup()

    def test_real_guest_not_blocked_by_guard(self, tmp_path):
        from ephemora_cell.wasi_02 import ComponentSandbox
        from ephemora_cell.wasi_runtime import WASIConfig

        src = os.path.join(os.path.dirname(__file__), "fixtures", "hello02.wasm")
        guest = tmp_path / "hello02.wasm"
        guest.write_bytes(open(src, "rb").read())
        sandbox = ComponentSandbox(WASIConfig(max_fuel=5_000_000))
        try:
            result = sandbox.run(str(guest))
            # The guard must NOT reject a legitimate guest: any failure here is
            # an execution/engine issue, never a "component guard" refusal.
            joined = (result.stderr or "").lower()
            assert "component guard" not in joined
        finally:
            sandbox.cleanup()


class TestFailClosedBranches:
    """Pin the guard's fail-closed guarantee: every construct the reader cannot
    confidently walk is *refused*, never guessed. These are the branches a
    happy-path corpus never reaches, so they are covered here explicitly rather
    than left as untested defense-in-depth — the guarantee that detection can
    only over-reject, never bypass, must be executable, not asserted in a comment.
    """

    @staticmethod
    def _r(data: bytes):
        return _cg._Reader(data)

    def test_truncated_header_refused(self):
        with pytest.raises(ComponentGuardError, match="truncated header"):
            guard_component_bytes(bytes([0x00, 0x61, 0x73, 0x6D, 0x0D, 0x00]))

    def test_non_component_layer_refused(self):
        # component version byte but a layer other than 0x0001.
        data = bytes([0x00, 0x61, 0x73, 0x6D, 0x0D, 0x00, 0x02, 0x00])
        with pytest.raises(ComponentGuardError, match="not a component-layer"):
            guard_component_bytes(data)

    def test_unknown_nameattributes_tag_refused(self):
        with pytest.raises(ComponentGuardError, match="nameattributes tag"):
            _cg._read_nameattributes(self._r(bytes([0x09])))

    def test_unknown_attribute_tag_refused(self):
        # 0x02 nameattributes carrying one attribute with a bad tag byte.
        data = bytes([0x02, 0x01, 0x41, 0x01, 0x09])
        with pytest.raises(ComponentGuardError, match="attribute tag"):
            _cg._read_nameattributes(self._r(data))

    def test_unknown_sort_refused(self):
        with pytest.raises(ComponentGuardError, match="unknown sort"):
            _cg._read_sort(self._r(bytes([0x09])))

    def test_truncated_valtype_refused(self):
        with pytest.raises(ComponentGuardError, match="truncated valtype"):
            _cg._read_valtype(self._r(b""))

    def test_malformed_optional_valtype_refused(self):
        with pytest.raises(ComponentGuardError, match="optional valtype"):
            _cg._read_opt_valtype(self._r(bytes([0x05])))

    def test_unknown_instance_decl_refused(self):
        finder = _cg._Finder()
        with pytest.raises(ComponentGuardError, match="unknown instance decl"):
            finder._scan_instancedecl_body(self._r(b""), 0x09)

    def test_malformed_core_extern_refused(self):
        finder = _cg._Finder()
        with pytest.raises(ComponentGuardError, match="malformed core extern"):
            finder._scan_externtype(self._r(bytes([0x00, 0x09])))

    def test_malformed_valuebound_refused(self):
        finder = _cg._Finder()
        with pytest.raises(ComponentGuardError, match="malformed valuebound"):
            finder._scan_externtype(self._r(bytes([0x02, 0x09])))

    def test_malformed_typebound_refused(self):
        finder = _cg._Finder()
        with pytest.raises(ComponentGuardError, match="malformed typebound"):
            finder._scan_externtype(self._r(bytes([0x03, 0x09])))

    def test_unsupported_extern_type_refused(self):
        finder = _cg._Finder()
        with pytest.raises(ComponentGuardError, match="unsupported extern type"):
            finder._scan_externtype(self._r(bytes([0x09])))

    def test_unknown_alias_kind_refused(self):
        finder = _cg._Finder()
        # sort byte (0x01 = func) then an alias kind outside 0x00/0x01/0x02.
        with pytest.raises(ComponentGuardError, match="unknown alias kind"):
            finder._read_alias(self._r(bytes([0x01, 0x09])))

    def test_embedded_core_type_declarator_refused(self):
        # The documented non-goal: a core WasmGC type declarator is refused
        # (over-reject) rather than mis-walked — the exact fail-closed guarantee
        # that keeps an async construct from hiding behind a misparsed span.
        finder = _cg._Finder()
        with pytest.raises(ComponentGuardError, match="core type declarator"):
            finder._skip_core_type(self._r(b""))

    def test_value_and_type_bound_accept_paths(self):
        # Positive walk of the externtype sub-forms so the accept side is not
        # left unexercised: valuebound(0x00 valueidx), valuebound(0x01 valtype),
        # typebound(0x01 sub). None of these should raise.
        finder = _cg._Finder()
        finder._scan_externtype(self._r(bytes([0x02, 0x00, 0x00])))
        finder._scan_externtype(self._r(bytes([0x02, 0x01, 0x7F])))
        finder._scan_externtype(self._r(bytes([0x03, 0x01])))
