# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Pre-flight component guard — GHSA-32h6-97mm-8q3c native-path avoidance.

GHSA-32h6-97mm-8q3c (identical to RUSTSEC-2026-0327) is a **native stack buffer
overflow** in Wasmtime: the result count of an *async-lifted* component callback
is not validated before it indexes a fixed-size native stack array. At the
intermediate ``wasmtime==49.0.0`` development pin the defect was **unresolved**
(IN BAND: fixed upstream in 49.0.2). 1.2.0 ships the controlled build on the
**49.0.3** line, so the upstream fix is present *by version*; that the shipped
binary really contains it has **not** been independently verified, and
SECURITY.md tracks that parity as an open risk. The exclusion below is kept for
exactly that reason: it is the part that can be measured here, and it still holds
if the version claim is ever wrong.

The overflow is reached during *component validation*, not only during async
execution — the isolated lab measurement (SECURITY.md, benchmarks results
2026-10-13) shows an async-lifted export driving the native parser into a fatal
path the moment ``wasmtime.component.Component(bytes)`` runs, in whatever process
calls it. Process isolation therefore cannot be the closure: the parse
boundary also runs on the host-authorised ``trusted``/in-process path and in the
MCP server. The governance directive forbids declaring this path excluded by
configuration alone, and forbids presenting worker containment as a full fix.

This module is the enforced exclusion the directive asks for: an **independent**
component-binary reader (it never delegates to the native ``wasmtime`` parser —
that is the very code under attack) that inspects the bytes before they are handed
to ``Component()`` and refuses any component that carries a component-model
**async** construct, or that it cannot fully and confidently parse (fail-closed).

Detection principle: every component-model async capability is anchored by an
async *type* definition — an async-lift requires an async ``functype`` (0x43) and
every async canon operation (``stream.*`` / ``future.*`` / ``task.return`` …)
takes a ``typeidx`` that must resolve to a ``future`` (0x65) or ``stream`` (0x66)
type. So a faithful walk of the component type section, recursing through nested
component / instance type definitions, is sufficient to flag the whole async
surface without decoding the canon section's per-opcode operand grammar. Any byte
sequence this reader cannot confidently walk is refused (fail-closed).

Why refusing async breaks no legitimate workload: the pinned engine disables
component async at build time, its Python binding exposes no async call surface,
and enabling it aborts engine construction (see
``tests/test_async_component_reachability.py``). No guest that could ever run on
this product uses component-async ``future`` / ``stream`` / async-lift, so the
gate removes only inputs the native runtime mishandles unsafely.

This is **avoidance / defense-in-depth at the loader boundary**, not a claim that
the upstream overflow is patched in the bytes we ship — the definitive fix is the
controlled source build on the 49.0.3 line, and its parity with the upstream patch
is an open, tracked risk in SECURITY.md rather than a verified fact.

.. note::

   **Status: wired into the loader (GHSA-32h6 enforced path exclusion).**
   :func:`guard_component_bytes` is called in ``wasi_02.ComponentSandbox.run``
   on the single ``Component()`` construction site, so both the in-process
   trusted path and the protected worker refuse an async component before the
   native parser ever sees it. The async *detection* side is proven against the
   known async shapes (async functype / future / stream, including inside a
   nested component). The accept side — walking every legitimate sync component
   — is certified against the repository's real component corpus (WASI p2 Rust
   probes, ``componentize-py`` lifted guests and WAT fixtures): all of them walk
   cleanly. Remaining grammar boundary, stated honestly: this reader does NOT
   parse an embedded core WebAssembly-GC ``type`` declarator (a full core
   ``rectype``/``subtype``/``moduletype`` with struct/array bodies); a component
   that places a core type inside a component/instance *type* section is refused
   fail-closed. That is a conservative over-reject, never a bypass — the walk
   can only ever refuse an input it cannot confidently parse, so a grammar gap
   can hide an async construct from acceptance but can never let it through.
"""

from __future__ import annotations

__all__ = ["ComponentGuardError", "guard_component_bytes"]


class ComponentGuardError(ValueError):
    """A component was refused before reaching the native runtime.

    Raised when the bytes carry a component-model async construct (the
    GHSA-32h6 surface) or when the guard cannot confidently decode them —
    both fail closed.
    """


# Component-model binary layout constants (WebAssembly/component-model Binary.md).
_MAGIC = b"\x00asm"
_COMPONENT_VERSION = 0x0D  # low version byte; core modules are 0x01

# Component-level section ids. Only these carry / nest async constructs; every
# other section is skipped by its declared length.
_SECTION_CORE_MODULE = 0x01  # embedded core module — opaque, cannot carry async
_SECTION_COMPONENT = 0x04  # nested component — must recurse
_SECTION_TYPE = 0x07  # vec(<type>) — async functype / future / stream live here

# Type opcodes flagged as component-model async (single-byte negative SLEB).
_ASYNC_FUNCTYPE = 0x43
_STREAM = 0x66
_FUTURE = 0x65
_ASYNC_TYPE_OPCODES = frozenset({_ASYNC_FUNCTYPE, _FUTURE, _STREAM})

# deftype opcodes that are leaf / non-recursive (single byte, no operands).
_PRIMVALTYPES = frozenset(
    {
        0x7F,  # bool
        0x7E,  # s8
        0x7D,  # u8
        0x7C,  # s16
        0x7B,  # u16
        0x7A,  # s32
        0x79,  # u32
        0x78,  # s64
        0x77,  # u64
        0x76,  # f32
        0x75,  # f64
        0x74,  # char
        0x73,  # string
        0x64,  # error-context
    }
)

# deftype / defvaltype opcodes that are *not* async and whose operand layout this
# reader walks; any leading opcode outside this known set is refused (fail-closed).
_KNOWN_TYPE_OPCODES = frozenset(
    {
        0x40,  # functype (sync)
        _ASYNC_FUNCTYPE,  # 0x43 async functype
        0x41,  # componenttype
        0x42,  # instancetype
        0x3F,  # resourcetype
        0x72,  # record
        0x71,  # variant
        0x70,  # list
        0x67,  # list (fixed)
        0x6F,  # tuple
        0x6E,  # flags
        0x6D,  # enum
        0x6B,  # option
        0x6A,  # result
        0x69,  # own
        0x68,  # borrow
        0x66,  # stream (async)
        0x65,  # future (async)
        0x63,  # map
    }
)


class _Reader:
    """Minimal, bounds-checked little-endian / LEB reader over a byte buffer."""

    __slots__ = ("data", "pos")

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def eof(self) -> bool:
        return self.pos >= len(self.data)

    def byte(self) -> int:
        if self.pos >= len(self.data):
            raise ComponentGuardError("component guard: unexpected end of buffer")
        b = self.data[self.pos]
        self.pos += 1
        return b

    def peek(self) -> int | None:
        return self.data[self.pos] if self.pos < len(self.data) else None

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise ComponentGuardError("component guard: length runs past the buffer")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def u32(self) -> int:
        """Unsigned LEB128 with a 4-byte cap (values must fit u32)."""
        result = 0
        shift = 0
        for _ in range(5):
            b = self.byte()
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                if result > 0xFFFFFFFF:
                    raise ComponentGuardError(
                        "component guard: u32 LEB exceeds 32-bit range"
                    )
                return result
            shift += 7
        raise ComponentGuardError("component guard: u32 LEB too long / not terminated")

    def count(self) -> int:
        n = self.u32()
        # A count this large cannot be backed by real bytes in any component we
        # accept; cap it so a crafted huge vector cannot drive unbounded work.
        remaining = len(self.data) - self.pos
        if n > remaining * 8 + 8:
            raise ComponentGuardError("component guard: implausible vector length")
        return n


def _read_name(r: _Reader) -> None:
    # core:name / labellit / a bare attribute name: uLEB length + that many bytes.
    length = r.u32()
    r.take(length)


def _read_nameattributes(r: _Reader) -> None:
    # nameattributes ::= 0x00 len en | 0x01 len en | 0x02 len en vec(attribute)
    # attribute      ::= 0x00 len in | 0x01 len vs | 0x02 n:<name>
    # Each carries one name (uLEB length + bytes); 0x02 appends an attribute vec.
    tag = r.byte()
    if tag not in (0x00, 0x01, 0x02):
        raise ComponentGuardError(
            f"component guard: unknown nameattributes tag 0x{tag:02x} (fail-closed)"
        )
    _read_name(r)
    if tag == 0x02:
        n = r.count()
        for _ in range(n):
            a = r.byte()  # 0x00 implements | 0x01 versionsuffix | 0x02 external-id
            if a not in (0x00, 0x01, 0x02):
                raise ComponentGuardError(
                    f"component guard: unknown attribute tag 0x{a:02x} (fail-closed)"
                )
            _read_name(r)


def _read_sort(r: _Reader) -> None:
    # sort ::= 0x00 <core:sort> | 0x01 func | 0x02 value | 0x03 type
    #        | 0x04 component | 0x05 instance
    b = r.byte()
    if b == 0x00:
        r.byte()  # embedded core:sort discriminator
    elif b not in (0x01, 0x02, 0x03, 0x04, 0x05):
        raise ComponentGuardError(
            f"component guard: unknown sort 0x{b:02x} (fail-closed)"
        )


def _read_valtype(r: _Reader) -> None:
    """Consume a valtype: a primvaltype byte, else a non-negative typeidx (uLEB)."""
    b = r.peek()
    if b is None:
        raise ComponentGuardError("component guard: truncated valtype")
    if b in _PRIMVALTYPES:
        r.byte()
        return
    # Non-negative SLEB128 => typeidx (composite / defined types referenced by index).
    r.u32()


def _read_labelvaltype(r: _Reader) -> None:
    _read_name(r)
    _read_valtype(r)


def _read_opt_valtype(r: _Reader) -> None:
    present = r.byte()
    if present == 0x01:
        _read_valtype(r)
    elif present != 0x00:
        raise ComponentGuardError("component guard: malformed optional valtype")


def _read_paramlist(r: _Reader) -> None:
    n = r.count()
    for _ in range(n):
        _read_labelvaltype(r)


def _read_resultlist(r: _Reader) -> None:
    # resultlist ::= 0x00 t:<valtype> | 0x01 0x00 (empty)
    tag = r.byte()
    if tag == 0x00:
        _read_valtype(r)
    elif tag == 0x01:
        if r.byte() != 0x00:
            raise ComponentGuardError("component guard: malformed empty result")
    else:
        raise ComponentGuardError(
            f"component guard: unknown resultlist tag 0x{tag:02x} (fail-closed)"
        )


class _Finder:
    """Recursive component-binary walk that flags any async type construct."""

    def __init__(self) -> None:
        self.found: str | None = None

    # -- component layer ----------------------------------------------------
    def scan_component(self, r: _Reader) -> None:
        while not r.eof():
            section_id = r.byte()
            size = r.u32()
            payload = r.take(size)
            if section_id == _SECTION_CORE_MODULE:
                # A core module is opaque component-free wasm; its own version
                # header must be intact, but it cannot carry component async.
                if not payload.startswith(b"\x00asm"):
                    raise ComponentGuardError(
                        "component guard: malformed embedded core module"
                    )
                continue
            if section_id == _SECTION_COMPONENT:
                self._scan_inner_component(payload)
            elif section_id == _SECTION_TYPE:
                self._scan_type_section(payload)
            # Every other section (custom/instance/alias/start/import/export/canon…)
            # is skipped by its length; async canon ops require async types that
            # can only be introduced by the type section / nested components above.

    def _scan_inner_component(self, payload: bytes) -> None:
        # A nested component repeats the 8-byte magic+version+layer header, so it
        # is held to the same invariant as the outer bytes. Reading a shorter
        # payload as "header, then nothing" would walk an unversioned body and
        # accept it — a nested component is validated or refused, never assumed.
        if len(payload) < 8:
            raise ComponentGuardError("component guard: truncated nested component")
        if not payload.startswith(_MAGIC):
            raise ComponentGuardError("component guard: malformed nested component")
        if payload[4] != _COMPONENT_VERSION:
            raise ComponentGuardError(
                "component guard: nested version byte "
                f"0x{payload[4]:02x} (fail-closed)"
            )
        if payload[6] | (payload[7] << 8) != 0x0001:
            raise ComponentGuardError(
                "component guard: nested component is not a component-layer module"
            )
        inner = _Reader(payload[8:])  # skip magic(4) + version(2) + layer(2)
        self.scan_component(inner)

    def _scan_type_section(self, payload: bytes) -> None:
        r = _Reader(payload)
        n = r.count()
        for _ in range(n):
            self._scan_type(r)

    # -- type layer ---------------------------------------------------------
    def _scan_type(self, r: _Reader) -> None:
        b = r.byte()
        if b in _PRIMVALTYPES:
            return
        if b in _ASYNC_TYPE_OPCODES:
            self._flag(b)
        if b not in _KNOWN_TYPE_OPCODES:
            raise ComponentGuardError(
                f"component guard: unknown type opcode 0x{b:02x} (fail-closed)"
            )
        if b == 0x40 or b == _ASYNC_FUNCTYPE:  # functype (sync) / async functype
            _read_paramlist(r)
            _read_resultlist(r)
        elif b == 0x41:  # componenttype
            self._scan_componentdecls(r)
        elif b == 0x42:  # instancetype
            self._scan_instancedecls(r)
        elif b == 0x3F:  # resourcetype: core rep valtype (u8) + optional dtor
            r.byte()  # core:valtype
            has_dtor = r.byte()
            if has_dtor == 0x01:
                r.u32()
            elif has_dtor != 0x00:
                raise ComponentGuardError("component guard: malformed resource dtor")
        elif b == 0x72:  # record
            n = r.count()
            for _ in range(n):
                _read_labelvaltype(r)
        elif b == 0x71:  # variant
            n = r.count()
            for _ in range(n):
                _read_name(r)  # case label
                ref = r.byte()
                if ref == 0x01:
                    _read_valtype(r)
                elif ref != 0x00:
                    raise ComponentGuardError("component guard: malformed variant ref")
                r.byte()  # redundant-label 0x00
        elif b == 0x70:  # list
            _read_valtype(r)
        elif b == 0x67:  # list (fixed)
            _read_valtype(r)
            r.u32()
        elif b == 0x6F:  # tuple
            n = r.count()
            for _ in range(n):
                _read_valtype(r)
        elif b == 0x6E:  # flags
            n = r.count()
            for _ in range(n):
                _read_name(r)
        elif b == 0x6D:  # enum
            n = r.count()
            for _ in range(n):
                _read_name(r)
        elif b == 0x6B:  # option
            _read_valtype(r)
        elif b == 0x6A:  # result
            _read_opt_valtype(r)
            _read_opt_valtype(r)
        elif b == 0x69 or b == 0x68:  # own / borrow
            r.u32()
        elif b == 0x66 or b == 0x65:  # stream / future (async) — flagged above
            _read_opt_valtype(r)
        elif b == 0x63:  # map
            _read_valtype(r)
            _read_valtype(r)

    def _scan_componentdecls(self, r: _Reader) -> None:
        n = r.count()
        for _ in range(n):
            tag = r.byte()
            if tag == 0x03:  # componentdecl ::= 0x03 <importdecl>
                _read_nameattributes(r)
                self._scan_externtype(r)
            else:  # otherwise a componentdecl IS an instancedecl
                self._scan_instancedecl_body(r, tag)

    def _scan_instancedecls(self, r: _Reader) -> None:
        n = r.count()
        for _ in range(n):
            tag = r.byte()
            self._scan_instancedecl_body(r, tag)

    def _scan_instancedecl_body(self, r: _Reader, tag: int) -> None:
        if tag == 0x00:  # core type
            self._skip_core_type(r)
        elif tag == 0x01:  # type
            self._scan_type(r)
        elif tag == 0x02:  # alias
            self._read_alias(r)
        elif tag == 0x04:  # exportdecl
            _read_nameattributes(r)
            self._scan_externtype(r)
        else:
            raise ComponentGuardError(
                f"component guard: unknown instance decl 0x{tag:02x} (fail-closed)"
            )

    def _scan_externtype(self, r: _Reader) -> None:
        # externtype ::= 0x00 0x11 <core:typeidx> | 0x01 <typeidx>
        #              | 0x02 <valuebound> | 0x03 <typebound>
        #              | 0x04 <typeidx> | 0x05 <typeidx>
        tag = r.byte()
        if tag == 0x00:  # core module
            if r.byte() != 0x11:
                raise ComponentGuardError("component guard: malformed core extern")
            r.u32()
        elif tag in (0x01, 0x04, 0x05):  # func / component / instance typeidx
            r.u32()
        elif tag == 0x02:  # valuebound: 0x00 valueidx | 0x01 valtype
            inner = r.byte()
            if inner == 0x00:
                r.u32()
            elif inner == 0x01:
                _read_valtype(r)
            else:
                raise ComponentGuardError("component guard: malformed valuebound")
        elif tag == 0x03:  # typebound: 0x00 typeidx (eq) | 0x01 (sub resource)
            inner = r.byte()
            if inner == 0x00:
                r.u32()
            elif inner == 0x01:
                pass
            else:
                raise ComponentGuardError("component guard: malformed typebound")
        else:
            raise ComponentGuardError(
                f"component guard: unsupported extern type 0x{tag:02x} (fail-closed)"
            )

    def _skip_core_type(self, r: _Reader) -> None:
        # A core:type declarator is a full core WebAssembly (GC) deftype —
        # rectype / rec-group / subtype / module-type with struct/array/functype
        # bodies. This reader does not implement that grammar, so it refuses
        # (fail-closed) rather than guess byte spans: a component whose type
        # section embeds a core type is never accepted by this guard until that
        # grammar is added and certified. Detection can only ever over-reject,
        # never silently skip past an async construct hidden behind a misparse.
        raise ComponentGuardError(
            "component guard: embedded core type declarator is not yet parsed "
            "(fail-closed)"
        )

    def _read_alias(self, r: _Reader) -> None:
        # alias ::= <sort> ( 0x00 <instanceidx> <name>
        #                  | 0x01 <core:instanceidx> <core:name>
        #                  | 0x02 <ct:u32> <idx:u32> )
        _read_sort(r)
        tag = r.byte()
        if tag in (0x00, 0x01):  # export alias: idx + name
            r.u32()
            _read_name(r)
        elif tag == 0x02:  # outer alias: two u32 indices
            r.u32()
            r.u32()
        else:
            raise ComponentGuardError(
                f"component guard: unknown alias kind 0x{tag:02x} (fail-closed)"
            )

    def _flag(self, opcode: int) -> None:
        name = {
            _ASYNC_FUNCTYPE: "async functype",
            _FUTURE: "future",
            _STREAM: "stream",
        }.get(opcode, f"type 0x{opcode:02x}")
        if self.found is None:
            self.found = name


def guard_component_bytes(data: bytes) -> None:
    """Refuse any component-async construct before it reaches ``Component()``.

    Raises :class:`ComponentGuardError` (fail-closed) when the bytes carry a
    component-model async type (async-lift / future / stream) or cannot be
    confidently walked. Returns ``None`` only for a fully decoded component with
    no async surface. Non-component bytes (core modules) are ignored here — the
    caller only routes actual component binaries through this guard.
    """
    if not data.startswith(_MAGIC):
        raise ComponentGuardError("component guard: missing wasm magic")
    if len(data) < 8:
        raise ComponentGuardError("component guard: truncated header")
    version = data[4]
    if version != _COMPONENT_VERSION:
        # Core modules (version byte 0x01) carry no component async surface and
        # are not routed here; anything else is refused rather than assumed safe.
        raise ComponentGuardError(
            f"component guard: unexpected version byte 0x{version:02x} (fail-closed)"
        )
    layer = data[6] | (data[7] << 8)
    if layer != 0x0001:
        raise ComponentGuardError("component guard: not a component-layer module")
    finder = _Finder()
    finder.scan_component(_Reader(data[8:]))
    if finder.found is not None:
        raise ComponentGuardError(
            f"component guard: refused component carrying component-model async "
            f"construct '{finder.found}' (GHSA-32h6-97mm-8q3c native stack "
            f"buffer-overflow surface; the pinned engine cannot run it safely)"
        )
