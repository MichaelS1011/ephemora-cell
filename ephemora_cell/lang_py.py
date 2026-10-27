# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Experimental Python adapter — opt-in, CPython-WASI guests only.

Part of the language-integration program. This module is **optional and
experimental**: nothing in the core sandbox imports it, and it does not widen
any security boundary.

What it does: runs a Python script with a CPython-WASI interpreter guest
(e.g. singlestore-labs/python-wasi 3.10) through the existing protected
execution path — subprocess worker, fuel, epoch wall, memory cap,
byte-budgeted output. There is no host CPython involvement and no
in-process fallback under any condition.

What it deliberately does NOT do:
  * claim full Python compatibility. The guest is a specific CPython WASI
    build: no threads, no subprocess spawning, no sockets — the WASI
    boundary refuses these (measured; see the language-program docs).
  * ship an interpreter. Guests are bring-your-own binaries, pinned by
    digest, exactly like every other untrusted module.
  * leave bytecodes writable. CPython would write ``__pycache__`` .pyc files
    back into its (read/write) stdlib preopen; the adapter therefore always
    passes ``-B`` so a run cannot mutate the pinned guest tree on the host.
    ``-B`` suppresses writing, it does not remove the mount's write
    capability — hardening the grant itself to read-only is a
    security-qualification item, not an adapter decision.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import replace
from typing import Any

from ._lang_common import shape_result as _shape_result
from .profiles import get as get_profile
from .wasi_runtime import WASIConfig, WASISandbox
from .wasm_inspector import inspect_module

EXPERIMENTAL = True
ADAPTER_NAME = "cpython-wasi"

#: The only host import namespace a CPython-WASI *core-module* interpreter
#: guest may require. Component guests (WASI 0.2) go through the component
#: runner's own admission and are not constrained by this Preview1 check.
_ALLOWED_IMPORT_MODULES = frozenset({"wasi_snapshot_preview1"})

#: Guest-visible mount point for the user's script in both execution models.
_WORK_GUEST_PATH = "/work"
#: Legacy core-module interpreter mounts its stdlib at this fixed guest path.
_STDLIB_GUEST_PATH = "/opt/wasi-python/lib/python3.10"

#: Component-model binary preamble (``\0asm`` + layer 0x0d + version). Used to
#: tell a modern WASI-0.2 component guest apart from a Preview1 core module.
_COMPONENT_PREAMBLE = b"\x00asm\x0d\x00\x01\x00"

#: Marker the modern component guest writes to stderr to signal that the
#: *user's* script raised, reported cleanly instead of aborting the worker.
_COMPONENT_USER_ERROR = "EPHEMORA_USER_ERROR"

#: Runner installed as ``/work/main.py`` for the component guest. The WASI 0.2
#: stdout/stderr stream accepts a bounded write and reports a short count; the
#: CPython file object does not retry it, so a single large ``print`` used to
#: lose everything past the stream buffer without a marker. This runner writes
#: in sub-boundary chunks and, when the host sink refuses the write at the
#: documented output budget, stops forwarding and lets the script finish. The
#: host capture carries the truncation marker and the measured byte count.
_COMPONENT_RUNNER = """\
import sys as _sys

_CHUNK = 4096


class _ChunkedBuffer:
    def __init__(self, buffer, state):
        self._buffer = buffer
        self._state = state

    def write(self, data):
        if self._state["blocked"]:
            return len(data)
        total = 0
        for i in range(0, len(data), _CHUNK):
            try:
                total += self._buffer.write(data[i:i + _CHUNK])
                self._buffer.flush()
            except OSError:
                self._state["blocked"] = True
                return len(data)
        return total

    def flush(self):
        if self._state["blocked"]:
            return None
        try:
            self._buffer.flush()
        except OSError:
            self._state["blocked"] = True
        return None

    def __getattr__(self, name):
        return getattr(self._buffer, name)


class _ChunkedText:
    def __init__(self, stream, state):
        self._stream = stream
        self._state = state
        self._buffer_proxy = _ChunkedBuffer(stream.buffer, state)

    @property
    def buffer(self):
        return self._buffer_proxy

    def write(self, data):
        if self._state["blocked"]:
            return len(data)
        if not isinstance(data, str):
            return self._stream.write(data)
        total = 0
        for i in range(0, len(data), _CHUNK):
            try:
                total += self._stream.write(data[i:i + _CHUNK])
                self._stream.flush()
            except OSError:
                self._state["blocked"] = True
                return len(data)
        return total

    def writelines(self, lines):
        for line in lines:
            self.write(line)

    def flush(self):
        if self._state["blocked"]:
            return None
        try:
            self._stream.flush()
        except OSError:
            self._state["blocked"] = True
        return None

    def __getattr__(self, name):
        return getattr(self._stream, name)


_state = {"blocked": False}
_sys.stdout = _ChunkedText(_sys.stdout, _state)
_sys.stderr = _ChunkedText(_sys.stderr, _state)
_sys.path.insert(0, "/work")
# The guest is a stripped CPython (no runpy/importlib._abc). compile/exec are
# builtins and keep the script's __name__/__file__ contract intact.
with open("/work/user_main.py", "rb") as _handle:
    _source = _handle.read()
exec(
    compile(_source, "/work/user_main.py", "exec"),
    {"__name__": "__main__", "__file__": "/work/user_main.py",
     "__builtins__": __builtins__},
)
"""


def _is_component_guest(path: str) -> bool:
    """True when ``path`` is a WASI-0.2 component (not a Preview1 core module).

    Only the 8-byte header is read; callers must still digest-verify the bytes
    before running.
    """
    try:
        with open(path, "rb") as handle:
            return handle.read(8) == _COMPONENT_PREAMBLE
    except OSError:
        return False


class AdapterPolicyError(ValueError):
    """The guest or the request violates the adapter's admission policy;
    nothing ran."""


def validate_guest(wasm_path: str) -> None:
    """Admission check: parseable core module, Preview1-only imports.

    Any failure — unparsable file, component, foreign imports — converges on
    ``AdapterPolicyError`` so callers have exactly one refusal type.
    """
    try:
        info = inspect_module(wasm_path)
        modules = {i["module"] for i in info.imports}
    except Exception as exc:
        raise AdapterPolicyError(f"guest is not a valid core module: {exc}") from exc
    if not modules <= _ALLOWED_IMPORT_MODULES:
        raise AdapterPolicyError(
            f"guest imports non-allowlisted namespaces: {sorted(modules)}"
        )


# The result-shape helper lives in ``_lang_common``: one
# construction site for the four adapter paths; the import above binds it
# under the historical local name. The per-path marker wiring stays exactly as
# it was — pinned by ``tests/test_adapter_result_shape.py``.


def _run_component_script(
    guest_path: str,
    *,
    script_path: str,
    input_json: Any,
    args: tuple[str, ...],
    expected_sha256: str | None,
    config: WASIConfig | None,
) -> dict[str, Any]:
    """Run a user's own Python script on a modern WASI-0.2 component guest.

    The script is staged as ``/work/main.py`` in a throwaway directory and the
    caller's ``input_json`` is delivered on the guest's real stdin (the guest
    execs the staged file, so a ``sys.stdin`` read by the user gets the data).
    ``args`` are forwarded to the component runner's argv; the runner supplies
    its own ``argv[0]``, so the caller's arguments occupy the guest's
    ``sys.argv[1:]`` (measured against the shipped CPython-WASI component
    guest — dropping them here would silently break ``run --language python
    s.py -- a b``). Runs only through the subprocess worker under the
    interpreter profile with mandatory digest verification — never in-process,
    never a host fallback. A user-level fault that the guest reports via the
    ``EPHEMORA_USER_ERROR`` marker is recorded as ``guest_reported_error`` — a
    *guest-supplied* diagnostic kept strictly separate from the host-observed
    ``status`` and ``exit_code`` (see the execution-record integrity rule).
    """
    work = tempfile.mkdtemp(prefix="ephemora-pycomp-")
    try:
        # The user's script is executed by the runner, which owns the stdout
        # chunking contract. Staging it as a separate file keeps the runner's
        # code out of the user's module (and preserves __file__ / __name__).
        shutil.copyfile(script_path, os.path.join(work, "user_main.py"))
        with open(os.path.join(work, "main.py"), "w", encoding="utf-8") as handle:
            handle.write(_COMPONENT_RUNNER)
        cfg = replace(
            config or get_profile("interpreter"),
            allow_dirs=(f"{work}::{_WORK_GUEST_PATH}",),
        )
        sandbox = WASISandbox(config=cfg)
        try:
            result = sandbox.run(
                guest_path,
                abi="component",
                args=list(args),
                stdin_data=(json.dumps(input_json) if input_json is not None else None),
                use_subprocess=True,
                expected_sha256=expected_sha256,
            )
        finally:
            sandbox.cleanup()
    finally:
        shutil.rmtree(work, ignore_errors=True)
    # Execution-record integrity: the marker in stderr is a message the
    # *user's own code* can produce, so it is untrusted as a status signal —
    # ``shape_result`` records it as the separate ``guest_reported_error``
    # diagnostic and NEVER lets it fabricate ``exit_code`` or override the
    # host-observed ``status`` (one shared rule: the
    # execution record reflects exactly what the worker saw, not what the
    # guest claims).
    return _shape_result(
        result,
        user_error_marker=_COMPONENT_USER_ERROR,
        # Named deliberately, because the derivation would answer a different
        # question. The guest here can leave through its exit interface, so
        # `guest_exit_observed` may well be true — but the PROGRAM the caller
        # handed over is the SCRIPT, and this guest's loader returns on SystemExit,
        # so the script's own status never arrives. The channel this field
        # describes is closed either way (measured in
        # tests/test_guest_exit_code_fidelity.py; docs/languages.md).
        exit_status_fidelity="none",
        config=cfg,
    )


def run_python_script(
    guest_path: str,
    *,
    stdlib_dir: str | None = None,
    script_path: str,
    input_json: Any = None,
    args: tuple[str, ...] = (),
    expected_sha256: str | None = None,
    config: WASIConfig | None = None,
) -> dict[str, Any]:
    """Run one Python script with a CPython-WASI guest under the interpreter
    profile.

    Two guest models are supported and chosen automatically from the guest
    bytes: a **modern WASI-0.2 component guest** (the product path — an
    embedded current CPython that execs the user's own script; no ``stdlib_dir``
    required) and the historical **Preview1 core-module interpreter** (needs a
    ``stdlib_dir`` tree and is pinned by digest). In both cases both paths are
    mounted read/write by the sandbox and nothing executes in this process; a
    missing path or policy violation raises, it never falls back.
    """
    if not os.path.exists(guest_path):
        raise AdapterPolicyError(f"guest does not exist: {guest_path}")
    if not os.path.exists(script_path):
        raise AdapterPolicyError(f"script_path does not exist: {script_path}")
    if _is_component_guest(guest_path):
        return _run_component_script(
            guest_path,
            script_path=script_path,
            input_json=input_json,
            args=args,
            expected_sha256=expected_sha256,
            config=config,
        )
    # Legacy interpreter (core module): stdlib is mandatory, guest is Preview1.
    if not stdlib_dir:
        raise AdapterPolicyError(
            "interpreter guest requires stdlib_dir (a component guest does not)"
        )
    if not os.path.isdir(stdlib_dir):
        raise AdapterPolicyError(f"stdlib_dir is not a directory: {stdlib_dir}")
    validate_guest(guest_path)

    script_dir, script_name = os.path.split(os.path.abspath(script_path))
    cfg = replace(
        config or get_profile("interpreter"),
        allow_dirs=(
            f"{os.path.abspath(stdlib_dir)}::{_STDLIB_GUEST_PATH}",
            f"{script_dir}::{_WORK_GUEST_PATH}",
        ),
    )
    sandbox = WASISandbox(config=cfg)
    try:
        result = sandbox.run(
            guest_path,
            # -B first and unconditional: bytecode write-back into the RW
            # stdlib grant is the guest's one measured host side effect.
            args=["-B", f"{_WORK_GUEST_PATH}/{script_name}", *args],
            stdin_data=(json.dumps(input_json) if input_json is not None else None),
            use_subprocess=True,
            expected_sha256=expected_sha256,
        )
    finally:
        sandbox.cleanup()
    # Marker-less by contract for this legacy path — pinned by
    # ``tests/test_adapter_result_shape.py`` (this consolidation keeps the
    # observable shape per path identical).
    return _shape_result(
        result,
        # Derived, not named: the Preview1 interpreter exits with the script's own
        # status and the ABI delivers it (measured: sys.exit(3) reports exit_code 3),
        # so the run's ``guest_exit_observed`` yields ``exact`` — while a fuel or
        # timeout stop on this same route yields ``none``, because there the host
        # stopped the run and no guest exit arrived.
        config=cfg,
    )
