# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Experimental JavaScript adapter — opt-in, Javy-built guests only.

Part of the language-integration program. This module is **optional and
experimental**: nothing in the core sandbox imports it, and it does not widen
any security boundary.

What it does: runs a JavaScript program that was ALREADY compiled to a WebAssembly
core module by the Javy toolchain (bytecodealliance/javy 9.x) through the
existing protected execution path — subprocess worker, fuel, epoch wall,
memory cap, byte-budgeted output, no host-side JS execution and no in-process
fallback under any condition.

What it deliberately does NOT do:
  * compile JavaScript here. Translating untrusted source to WASM needs the
    separate, resource-bounded, secret-free build environment from the
    directive; the CLI therefore lives outside the repository's runtime path.
  * claim JavaScript, Node.js or npm compatibility. Guests are plain Javy
    static modules: stdin JSON in, stdout JSON out, ES features limited to
    what QuickJS-in-WASM provides.
  * run anything the inspector does not accept: the guest must be a core
    module whose only import namespace is ``wasi_snapshot_preview1`` — the
    same admission the Preview1 path already requires, checked up front so a
    refusal is an ``AdapterPolicyError``, not an engine surprise.
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
ADAPTER_NAME = "quickjs-preview1"

#: The only host import namespace a Javy/QuickJS guest may require.
_ALLOWED_IMPORT_MODULES = frozenset({"wasi_snapshot_preview1"})

#: Guest-visible mount for the staged JavaScript source (interpreter path).
_WORK_GUEST_PATH = "/work"
#: Marker a source-interpreter guest writes to stderr on a user-level fault.
_JS_USER_ERROR = "EPHEMORA_USER_ERROR"


class AdapterPolicyError(ValueError):
    """The guest violates the adapter's admission policy; nothing ran."""


def validate_guest(wasm_path: str) -> None:
    """Admission check: parseable core module, Preview1-only imports.

    Any failure — unparsable file, component, foreign imports — converges on
    ``AdapterPolicyError`` so callers have exactly one refusal type and
    nothing downstream ever sees a half-validated guest.
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


def run_javascript_module(
    wasm_path: str,
    *,
    input_json: Any = None,
    expected_sha256: str | None = None,
    config: WASIConfig | None = None,
) -> dict[str, Any]:
    """Run a Javy-built guest under the interpreter profile.

    Returns a dict with the raw ``ExecutionResult`` plus a parsed ``output``
    when the guest's stdout is valid JSON. Never executes anything in this
    process; a missing guest or policy violation raises, it does not fall
    back.
    """
    validate_guest(wasm_path)
    cfg = replace(config or get_profile("interpreter"))
    sandbox = WASISandbox(config=cfg)
    try:
        result = sandbox.run(
            wasm_path,
            stdin_data=(json.dumps(input_json) if input_json is not None else None),
            use_subprocess=True,
            expected_sha256=expected_sha256,
        )
    finally:
        sandbox.cleanup()
    # Shared construction site; the module path stays
    # marker-less by contract (pinned in tests/test_adapter_result_shape.py).
    return _shape_result(
        result,
        # Derived from the run, never named here. A caller-built guest that
        # leaves through the Preview1 ``proc_exit`` DOES deliver its own status
        # (measured in tests/test_guest_exit_code_fidelity.py) and reads ``exact``;
        # the same route stopped by the host's fuel or timeout budget produced no
        # guest exit at all and must read ``none``. This call site used to assert
        # ``exact`` unconditionally, which attested an exit code the host had
        # never observed.
        config=cfg,
    )


def run_javascript_source(
    wasm_path: str,
    *,
    source: str | None = None,
    script_path: str | None = None,
    input_json: Any = None,
    expected_sha256: str | None = None,
    config: WASIConfig | None = None,
) -> dict[str, Any]:
    """Run a user's OWN JavaScript on a QuickJS interpreter guest.

    Exactly one of ``source`` (JS text) or ``script_path`` (a JS file) must be
    given. The program is staged at ``/work/main.js`` inside a throwaway
    directory mounted as the run's only caller-visible preopen — a preview1 run
    additionally gets its own ephemeral ``/sandbox`` scratch, measured in
    benchmarks/results/2026-10-19/language_grant_views_measured.json — with
    optional ``input_json`` written to ``/work/input.json``; the guest evaluates
    the source under the isolated subprocess worker (fuel, epoch wall, memory
    cap, byte-budgeted output). No host Node.js/V8 is ever involved and there is
    no in-process fallback. A clean user-level fault (the guest's
    ``EPHEMORA_USER_ERROR`` marker) is recorded as ``guest_reported_error`` — a
    *guest-supplied* diagnostic kept separate from the host-observed
    ``status``/``exit_code`` (execution-record integrity).
    """
    if (source is None) == (script_path is None):
        raise AdapterPolicyError(
            "run_javascript_source needs exactly one of source or script_path"
        )
    if script_path is not None and not os.path.exists(script_path):
        raise AdapterPolicyError(f"script_path does not exist: {script_path}")
    validate_guest(wasm_path)

    work = tempfile.mkdtemp(prefix="ephemora-jssrc-")
    try:
        if source is not None:
            with open(os.path.join(work, "main.js"), "w") as handle:
                handle.write(source)
        else:
            # Unreachable: the exactly-one check above already ruled this out,
            # but stating it keeps the copy argument a real path for readers and
            # for the type gate.
            if script_path is None:
                raise AdapterPolicyError(
                    "script_path is required when source is absent"
                )
            shutil.copyfile(script_path, os.path.join(work, "main.js"))
        if input_json is not None:
            with open(os.path.join(work, "input.json"), "w") as handle:
                json.dump(input_json, handle)
        cfg = replace(
            config or get_profile("interpreter"),
            allow_dirs=(f"{work}::{_WORK_GUEST_PATH}",),
        )
        sandbox = WASISandbox(config=cfg)
        try:
            result = sandbox.run(
                wasm_path,
                use_subprocess=True,
                expected_sha256=expected_sha256,
            )
        finally:
            sandbox.cleanup()
    finally:
        shutil.rmtree(work, ignore_errors=True)

    # Execution-record integrity: the marker is user-controllable stderr
    # content — ``shape_result`` records it as an untrusted *diagnostic*, never
    # a status signal (one shared rule).
    return _shape_result(
        result,
        user_error_marker=_JS_USER_ERROR,
        # Named deliberately: the QuickJS harness decides, so a thrown error and a
        # process.exit() both come back success/0 (measured on the qualified
        # guest). The guest's own exit interface is not the program's — the SCRIPT's
        # status is what this field would have to describe, and it never arrives.
        exit_status_fidelity="none",
        config=cfg,
    )
