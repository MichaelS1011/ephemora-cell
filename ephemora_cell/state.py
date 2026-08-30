# Ephemora Cell — Named state across isolated runs (ADR-004)
# SPDX-License-Identifier: Apache-2.0
"""Session-scoped named state for consecutive sandbox runs.

Cell runs are fully ephemeral — every ``run()`` gets a fresh sandbox
dir. Cross-call state therefore had to go through a persistent preopen
directory (manual cleanup, no caps, session-leakage risk) or through
the caller's hands (stdout/stdin, capped far below record sizes).

``StateStore`` is the explicit primitive (ADR-004): a host-side,
session-scoped key/value store whose lifetime IS the session. A caller
passes one into ``WASISandbox.run(..., state_store=store)`` — that
argument is the capability grant; the guest then imports
``ephemora_state.get/set/del`` (core module import name
``ephemora_state``). Caps are enforced inside the store: value bytes,
total bytes, entry count — breach returns a WASI-style errno to the
guest instead of raising.

Security properties:
  * explicit capability: no state imports unless a StateStore is passed;
  * session scoping: two StateStores never share keys (no leakage);
  * bounded: per-value, total, and entry-count caps, host-enforced;
  * auditable: the run result carries ``state_bytes`` (store footprint);
  * lifetime: session ends when the caller drops/clears the store —
    nothing persists to disk.
"""

from __future__ import annotations

# errno values returned to the guest
ERRNO_OK = 0
ERRNO_CAP = 1
ERRNO_INVALID = 2
ERRNO_NOT_FOUND = 3
ERRNO_BUF_TOO_SMALL = 4


class StateCapExceeded(Exception):
    """A StateStore cap (value bytes / total bytes / entry count) was hit."""


class StateStore:
    """Bounded, session-scoped key/value state (ADR-004).

    Args:
        max_value_bytes: cap per stored value (default 256 KiB).
        max_total_bytes: cap on the sum of all value bytes (default 1 MiB).
        max_entries: cap on the number of names (default 64).
    """

    def __init__(
        self,
        max_value_bytes: int = 256 * 1024,
        max_total_bytes: int = 1024 * 1024,
        max_entries: int = 64,
    ) -> None:
        if max_value_bytes <= 0 or max_total_bytes <= 0 or max_entries <= 0:
            raise ValueError("state caps must be positive")
        self._max_value = max_value_bytes
        self._max_total = max_total_bytes
        self._max_entries = max_entries
        self._data: dict[str, bytes] = {}
        self._total = 0

    # --- host-side API (tests, callers, MCP layers) ---

    def get(self, name: str) -> bytes | None:
        return self._data.get(name)

    def set(self, name: str, value: bytes) -> None:
        if not name:
            raise StateCapExceeded("state name must be non-empty")
        if len(value) > self._max_value:
            raise StateCapExceeded(
                f"value of {len(value)} bytes exceeds max_value_bytes="
                f"{self._max_value}"
            )
        old = self._data.get(name, b"")
        if len(value) - len(old) + self._total > self._max_total:
            raise StateCapExceeded(
                f"total state {self._total - len(old) + len(value)} bytes "
                f"would exceed max_total_bytes={self._max_total}"
            )
        if name not in self._data and len(self._data) >= self._max_entries:
            raise StateCapExceeded(
                f"entry count {len(self._data)} at max_entries={self._max_entries}"
            )
        self._total += len(value) - len(old)
        self._data[name] = value

    def delete(self, name: str) -> bool:
        old = self._data.pop(name, None)
        if old is None:
            return False
        self._total -= len(old)
        return True

    def names(self) -> list[str]:
        return sorted(self._data)

    def clear(self) -> None:
        self._data.clear()
        self._total = 0

    @property
    def total_bytes(self) -> int:
        return self._total

    def __len__(self) -> int:
        return len(self._data)


# --- guest-facing import bindings (wasmtime Caller-based) ---


def _caller_memory(caller):
    """The caller's exported linear memory (wasmtime-py: caller.get)."""
    return caller.get("memory")


def _read_bytes(caller, ptr: int, length: int) -> bytes:
    return bytes(_caller_memory(caller).read(caller, ptr, ptr + length))


def make_state_imports(state_store: StateStore) -> dict:
    """Build the ``ephemora_state`` host functions bound to ``state_store``.

    Returns a mapping ``func_name -> (param_types, result_types, callback)``
    for :meth:`WASISandbox.run` to define on the linker.
    """
    from wasmtime import ValType

    i32 = ValType.i32()
    imports: dict = {}

    def _set(caller, name_ptr, name_len, val_ptr, val_len) -> int:
        try:
            name = _read_bytes(caller, name_ptr, name_len).decode("utf-8")
            value = _read_bytes(caller, val_ptr, val_len)
            state_store.set(name, value)
        except StateCapExceeded:
            return ERRNO_CAP
        except Exception:
            return ERRNO_INVALID
        return ERRNO_OK

    def _get(caller, name_ptr, name_len, buf_ptr, buf_len_ptr) -> int:
        try:
            name = _read_bytes(caller, name_ptr, name_len).decode("utf-8")
        except Exception:
            return ERRNO_INVALID
        value = state_store.get(name)
        if value is None:
            return ERRNO_NOT_FOUND
        try:
            provided = int.from_bytes(
                _caller_memory(caller).read(caller, buf_len_ptr, buf_len_ptr + 4),
                "little",
            )
        except Exception:
            return ERRNO_INVALID
        if provided < len(value):
            _caller_memory(caller).write(
                caller, len(value).to_bytes(4, "little"), buf_len_ptr
            )
            return ERRNO_BUF_TOO_SMALL
        _caller_memory(caller).write(caller, value, buf_ptr)
        _caller_memory(caller).write(
            caller, len(value).to_bytes(4, "little"), buf_len_ptr
        )
        return ERRNO_OK

    def _delete(caller, name_ptr, name_len) -> int:
        try:
            name = _read_bytes(caller, name_ptr, name_len).decode("utf-8")
        except Exception:
            return ERRNO_INVALID
        return ERRNO_OK if state_store.delete(name) else ERRNO_NOT_FOUND

    imports["set"] = (
        [i32, i32, i32, i32],
        [i32],
        _set,
    )
    imports["get"] = (
        [i32, i32, i32, i32],
        [i32],
        _get,
    )
    imports["del"] = ([i32, i32], [i32], _delete)
    return imports
