# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Unified language entry point — experimental, opt-in dispatcher.

One call shape for every supported language adapter. This module owns no
execution logic: it routes to the per-language adapters, which each enforce
the same invariants (inspection before sandbox, subprocess worker only, no
in-process fallback, interpreter-profile budgets, digest pinning supported).

Adding a language means adding an adapter module and registering it here —
never touching the core sandbox. Adapters are imported lazily so importing
this dispatcher does not pull any language runtime into the process.
"""

from __future__ import annotations

from typing import Any

EXPERIMENTAL = True

#: language id -> adapter module name (lazy-imported on first use)
_ADAPTERS = {
    "javascript": "ephemora_cell.lang_js",
    "python": "ephemora_cell.lang_py",
}


class LanguagePolicyError(ValueError):
    """The request violates the unified-language admission policy; nothing
    ran. Adapter-level refusals (``AdapterPolicyError``) pass through
    unchanged so callers can tell routing failures from guest refusals."""


def available_languages() -> tuple[str, ...]:
    """Registered language identifiers, sorted."""
    return tuple(sorted(_ADAPTERS))


def run_language(language: str, **kwargs: Any) -> dict[str, Any]:
    """Dispatch one isolated run to the adapter for ``language``.

    Keyword arguments are adapter-specific (see ``lang_js`` / ``lang_py``);
    every adapter returns the same result keys: ``status``, ``stdout``,
    ``stderr``, ``exit_code``, ``fuel_consumed``, ``elapsed_ms``, ``output``.
    ``status`` and ``exit_code`` are always the *host-observed* worker result;
    a user-level fault the guest self-reports is exposed only as the separate,
    untrusted ``guest_reported_error`` diagnostic and never changes them.
    An unknown language raises ``LanguagePolicyError`` before any adapter —
    and therefore any sandbox — comes into existence.
    """
    try:
        module_name = _ADAPTERS[language]
    except KeyError:
        raise LanguagePolicyError(
            f"unsupported language {language!r}; available: {available_languages()}"
        ) from None
    import importlib

    adapter = importlib.import_module(module_name)
    try:
        entry = kwargs.pop("entrypoint", None)
        if language == "javascript":
            # a user's own JavaScript source goes through the QuickJS
            # interpreter guest; a pre-compiled module keeps the Javy path.
            run = (
                adapter.run_javascript_source
                if ("source" in kwargs or "script_path" in kwargs)
                else adapter.run_javascript_module
            )
        elif language == "python":
            run = adapter.run_python_script
        else:  # defensive: registry and dispatch must stay in sync
            raise LanguagePolicyError(f"no entry function for {language!r}")
        wasm_path = entry if entry is not None else kwargs.pop("wasm_path", None)
        if wasm_path is None:
            # 1.2.0 language decision: no manual guest hunting after install.
            # Resolve the installed optional-package guest (explicit BYO pins are
            # honoured inside the resolver too); fail closed with the install
            # command -- never a hidden runtime download.
            from .lang_guest import resolve_guest

            guest = resolve_guest(language)
            wasm_path = guest.wasm_path
            if language == "python" and "stdlib_dir" not in kwargs:
                kwargs["stdlib_dir"] = guest.stdlib_dir
            if guest.expected_sha256 and "expected_sha256" not in kwargs:
                kwargs["expected_sha256"] = guest.expected_sha256
        return run(str(wasm_path), **kwargs)
    except TypeError as exc:
        # a missing/unknown keyword on the adapter call is a caller error
        raise LanguagePolicyError(f"invalid request for {language!r}: {exc}") from exc


def run_python(**kwargs: Any) -> dict[str, Any]:
    """Run one Python workload in an isolated sandbox (language-level entry).

    The understandable convenience over the raw :func:`WASISandbox.run`
    primitive: a developer asks for *Python*, not a guest file. Precedence and
    guarantees mirror :func:`run_language` — an explicit ``entrypoint``/guest
    path wins; otherwise the installed optional language package is resolved
    (or an explicit ``EPHEMORA_BYO_*`` pin), and if neither exists the call
    fails closed with the single ``pip install`` command. Nothing is ever
    downloaded or executed in this process, and the run is isolated.

    Recognised keywords (see :mod:`ephemora_cell.lang_py`): ``script_path``
    (required), ``stdlib_dir``, ``entrypoint`` (an explicit guest path),
    ``input_json``, ``args``, ``expected_sha256``, ``config``. Returns the
    shared adapter result shape.
    """
    return run_language("python", **kwargs)


def run_javascript(**kwargs: Any) -> dict[str, Any]:
    """Run one JavaScript module in an isolated sandbox (language-level entry).

    Same contract as :func:`run_python` for the JavaScript adapter
    (:mod:`ephemora_cell.lang_js`): explicit ``entrypoint`` first, otherwise the
    installed/resolved guest, fail-closed with the install command when none is
    present, never a hidden download, always isolated. Recognised keywords
    include ``entrypoint``, ``input_json``, ``args``, ``expected_sha256``,
    ``config``. Returns the shared adapter result shape.
    """
    return run_language("javascript", **kwargs)
