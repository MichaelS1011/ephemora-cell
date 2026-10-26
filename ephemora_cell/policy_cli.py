# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Pre-run policy view — what a run WOULD be allowed to do before it starts.

Backs ``ephemora policy check``: it answers "which permissions and which
isolation would this configuration actually carry?" *before* anything executes.
The view is computed EXCLUSIVELY from the authoritative policy primitives the
runtime itself reads, for the configuration the flags select: ``--language
python|javascript`` starts from the same ``interpreter`` profile the language
run resolves, and ``--isolated`` raises isolation exactly the way the run gate
does — it can never lower a mandate that already holds. Flags that do not shape
policy (``--stdin``, the ``--tenant`` quota flags) are deliberately absent:
accepting a flag this view could not honour would describe a run that never
happens. The primitives read are:

* ``execution_report.isolation_required_for`` — the ADR-015 isolation mandate,
* ``execution_report.sync_blockade_holds`` — the sync-enforcement equation,
* ``execution_report.policy_fingerprint`` / ``security_baseline_for`` — the
  digest and posture the signed record carries,
* ``_sandbox_common.validate_allow_dirs`` / ``filter_dangerous_dirs`` /
  ``split_dir_mapping`` / ``canonicalize_dir`` — the ONE preopen guard both ABI
  paths delegate to (``WASISandbox`` and ``ComponentSandbox`` call exactly these
  with exactly these defaults).

Deliberately NOT here: a second policy engine, an engine instantiation, or a
guest execution. Nothing is started and no wasmtime object is built — the
preopen section therefore reports what a run WOULD grant (canonicalised host
path plus guest name) and lists with the run's own wording everything it would
refuse or skip (config-time validation, run-time dir guard, grant-time
existence check).

Env VALUES are secrets and never appear in any output — only names, the same
rule ``policy_fingerprint`` applies to its digest input.

Two limits are stated rather than papered over. A language run's ABI is the
adapter's fact, never the caller's: an ``--abi`` that contradicts it is refused
by the CLI instead of being quietly rewritten, because the sync-blockade verdict
and the ``/sandbox`` note both hang off it (a Python run leaves the choice to
the guest bytes, a JavaScript run is always preview1). And the ``fingerprint``
of such a view is the digest of the configuration passed to the call — the
adapter rebuilds the grants, so the run's own signed record carries a
different digest, which the snapshot labels as its scope instead of implying an
attestation it cannot make. A caller directory the adapter would drop does NOT
fail the gate: the run is still safe to start and the approval is merely void,
so exit 1 stays reserved for what a run would actually refuse.

``security_baseline`` is exactly what ``security_baseline_for(config)`` returns —
the CONFIG posture. The keys ``apply_config`` adds only once a run has resolved
them (``execution_mode``, ``abi``, ``sync_blockade_enforced``) are run-time facts
and are reported in the ``isolation`` / ``sync_blockade`` sections instead of
being fabricated into the baseline here.
"""

from __future__ import annotations

import dataclasses
import os
from typing import Any

from ephemora_cell._sandbox_common import (
    canonicalize_dir,
    filter_dangerous_dirs,
    split_dir_mapping,
    validate_allow_dirs,
)
from ephemora_cell.execution_report import (
    ABI_COMPONENT,
    ABI_PREVIEW1,
    EXECUTION_MODE_IN_PROCESS,
    EXECUTION_MODE_SUBPROCESS,
    VALID_TRUST,
    isolation_required_for,
    policy_fingerprint,
    security_baseline_for,
    sync_blockade_holds,
)
from ephemora_cell.wasi_runtime import WASIConfig

__all__ = [
    "ABI_AUTO",
    "LANGUAGE_ABI",
    "LANGUAGE_WASM",
    "SCHEMA",
    "format_report",
    "snapshot",
    "to_json",
]

#: Schema tag of the machine-readable policy snapshot.
SCHEMA = "ephemora-cell/policy-check/1"

#: ``abi="auto"``: the module bytes decide the ABI at run time.
ABI_AUTO = "auto"

#: The concrete ABIs, in the order the snapshot reports them.
_ABIS = (ABI_PREVIEW1, ABI_COMPONENT)
#: The guests a view can describe. ``wasm`` is the compiled-module default;
#: the language guests resolve from the interpreter profile (same as the run).
LANGUAGE_WASM = "wasm"
_LANGUAGES = (LANGUAGE_WASM, "python", "javascript")
_LANG_ALWAYS_ISOLATED = (
    "the {language} adapter always runs the guest in the disposable subprocess "
    "worker (it passes use_subprocess=True), so an explicit host 'trusted' "
    "posture does not open an in-process path for a source run"
)

#: The ABI a language run ACTUALLY executes under. Neither adapter takes an ABI
#: from the caller: ``lang_js`` never passes ``abi`` (so both JavaScript entries
#: are preview1), while ``lang_py`` selects the component ABI for a component
#: guest and preview1 for the legacy interpreter — from the guest bytes. Echoing
#: the caller's ``--abi`` here would promise a run that cannot happen, so the CLI
#: refuses the flag for a language guest and the view names its own source.
LANGUAGE_ABI: dict[str, str] = {"javascript": ABI_PREVIEW1, "python": ABI_AUTO}
_LANG_ABI_SOURCE = {
    "javascript": (
        "the javascript adapter — neither entry passes an abi, so a .js run is "
        "always the preview1 ABI; an --abi that contradicts it is refused"
    ),
    "python": (
        "the guest's own bytes — a component guest runs the component ABI, a "
        "legacy Preview1 interpreter guest the preview1 ABI; both are reported"
    ),
}

#: Why a language view's digest is not the run's attestation.
_FINGERPRINT_LANG_NOTE = (
    "digest of the configuration passed to the call. A {language} run executes "
    "under the grants the adapter builds, so the signed record of that actual "
    "run carries a DIFFERENT digest — this is the pre-run view's fingerprint, "
    "not the run's attestation"
)

#: The ONE WASIConfig field carrying secrets (name AND value pairs). Its names
#: are reported like the fingerprint does; its values never.
_SECRET_FIELD = "allow_env"

_MANDATE = "ADR-015"

_ISOLATION_DETAIL = {
    True: (
        "process isolation is MANDATORY for this posture: the run is routed "
        "through the disposable subprocess worker, and no in-process fallback "
        f"is attempted ({_MANDATE}, 1.2.0 decision 2)"
    ),
    False: (
        "explicit host 'trusted' authorisation: the documented-trusted "
        f"in-process fast path is kept ({_MANDATE}); no guest, manifest or tool "
        "parameter can raise a posture into it"
    ),
}

_AUTO_SUFFIX = " — both ABIs are reported separately; module bytes decide at run time"

_SYNC_DETAIL = (
    "effective only on the preview1 path with allow_fsync closed; the component "
    "path links wasi:filesystem and has no sync trap at all"
)

_SANDBOX_MOUNT_NOTE = (
    "additionally, a preview1 run preopens its own per-run ephemeral sandbox "
    "directory as /sandbox (its host path exists only at run time); a component "
    "run grants no such mount"
)

#: Which half of this view a signed record actually compares against. Stated here
#: because the same key name means two things in the two documents, and a reader
#: who does not know that can mistake a normalised path for a policy drift.
_BASELINE_SCOPE_NOTE = (
    "security_baseline.preopens in this view lists the entries AS REQUESTED (the "
    "config a run would be built from); a run's signed baseline records the "
    "canonical host paths it actually granted. Compare effective[].host here with "
    "the record's security_baseline.preopens — those are the same decision, read "
    "off at the same place"
)

_REFUSED_AT_CONSTRUCTION = "a run would be refused at construction: {exc}"
_REFUSED_BY_FILTER = (
    "filtered out at run time by the canonical allowlist / dir guard — the "
    "guest would not see this path"
)
_REFUSED_AT_GRANT = (
    "directory does not exist ({canon!r}): a run would skip it with a warning "
    "and the guest path {guest!r} would not be available"
)


def _jsonable(value: Any) -> Any:
    """Tuples become lists so ``json.dumps`` round-trips the snapshot exactly."""
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _budgets(config: WASIConfig) -> dict[str, Any]:
    """Every WASIConfig field, with the secret-bearing ``allow_env`` pairs
    replaced by their names (values are secrets, not policy)."""
    out: dict[str, Any] = {
        field.name: _jsonable(getattr(config, field.name))
        for field in dataclasses.fields(WASIConfig)
        if field.name != _SECRET_FIELD
    }
    out["allow_env_names"] = [name for name, _ in (config.allow_env or ())]
    # The engine's effective bytes, not just the MB knob: max_memory_mb == 0
    # also means 0 bytes, which the bare number cannot explain.
    out["memory_capacity_bytes"] = config.memory_capacity_bytes
    return out


def _execution_mode(required: bool) -> str:
    """The ADR-014 execution-mode tag a run with this verdict would attest."""
    return EXECUTION_MODE_SUBPROCESS if required else EXECUTION_MODE_IN_PROCESS


def _isolation_view(trust: str, abi: str, isolated: bool = False) -> dict[str, Any]:
    """The ADR-015 mandate as the run's gate would read it (no widening).

    ``isolated`` mirrors the run's ``--isolated``: it raises the requirement into
    the worker, and never lowers a mandate that already holds.
    """
    mandated = isolation_required_for(trust, abi)
    required = mandated or isolated
    view: dict[str, Any] = {
        "trust": trust,
        "abi": abi,
        "required": required,
        "execution_mode": _execution_mode(required),
        "mandate": _MANDATE,
        "detail": _ISOLATION_DETAIL[required],
    }
    if isolated and not mandated:
        view["raised_by"] = "--isolated"
        view["detail"] = (
            "isolation RAISED by --isolated: the run goes through the disposable "
            f"subprocess worker even though the {trust} posture alone would allow "
            "the in-process path (the flag can raise, never lower)"
        )
    if abi == ABI_AUTO:
        view["detail"] = view["detail"] + _AUTO_SUFFIX
        view["per_abi"] = {
            candidate: {
                "required": isolation_required_for(trust, candidate) or isolated,
                "execution_mode": _execution_mode(
                    isolation_required_for(trust, candidate) or isolated
                ),
            }
            for candidate in _ABIS
        }
    return view


def _language_isolation_view(view: dict[str, Any], language: str) -> dict[str, Any]:
    """Raise the ABI mandate to what a source run actually does.

    The adapters pass ``use_subprocess=True`` unconditionally, so a host-declared
    ``trusted`` posture cannot open an in-process path for a ``.py``/``.js`` run.
    This is the adapter's fact, not a second policy engine; the pinned test
    ``test_the_adapter_facts_the_view_asserts_are_pinned_in_the_adapters`` breaks
    if the adapters ever stop forcing the worker.
    """
    raised = {
        **view,
        "required": True,
        "execution_mode": EXECUTION_MODE_SUBPROCESS,
        "mandate_source": f"the {language} adapter (use_subprocess=True)",
        "detail": _LANG_ALWAYS_ISOLATED.format(language=language)
        + " | "
        + view["detail"],
    }
    if "per_abi" in view:
        raised["per_abi"] = {
            abi: {
                **entry,
                "required": True,
                "execution_mode": EXECUTION_MODE_SUBPROCESS,
            }
            for abi, entry in view["per_abi"].items()
        }
    return raised


def _guest_run(
    adapter_entry: str,
    *,
    replaces: bool,
    dropped: list[str],
    mounts: list[dict[str, str]],
    run_abi: str,
    sandbox_scratch: bool,
    extra_grants: str,
    reachability: str,
) -> dict[str, Any]:
    """One concrete grant set a language run can end up with.

    ``run_abi`` and ``sandbox_scratch`` are kept per branch because they are NOT
    the same across branches: a preview1 run additionally preopens its own
    ephemeral ``/sandbox`` scratch, a component run does not — measured, not
    inferred (measured in
    benchmarks/results/2026-10-19/language_grant_views_measured.json). The
    boolean is a field, not
    something to be guessed out of the sentence, so a consumer cannot read "no
    /sandbox scratch" as a grant.
    """
    return {
        "adapter_entry": adapter_entry,
        "abi": run_abi,
        "sandbox_scratch": sandbox_scratch,
        "extra_grants": extra_grants,
        "reachability": reachability,
        "replaces_allow_dirs": replaces,
        "dropped_allow_dirs": dropped,
        "mounts": mounts,
    }


#: The sub-run keys the report renders, in the order it renders them.
_RUN_KEYS = ("component_run", "legacy_interpreter_run", "source_run", "module_run")

_PREVIEW1_SANDBOX = (
    "plus the run's own ephemeral /sandbox scratch (preview1 always preopens it)"
)
_COMPONENT_NO_SANDBOX = "no /sandbox scratch — the component path grants none"

_PY_FROM_CLI = (
    "reachable from run --language python when the resolved guest is a "
    "WASI-0.2 component (the installed product guest)"
)
_PY_FROM_LEGACY_GUEST = (
    "reachable from run --language python only when the guest is a legacy "
    "Preview1 core-module interpreter (it then requires stdlib_dir)"
)
_JS_FROM_CLI = (
    "the only entry run --language javascript can reach — the CLI always passes "
    "script_path"
)
_JS_LIBRARY_ONLY = (
    "library-only: reached through lang_js.run_javascript_module (or "
    "run_language('javascript') without script_path); the CLI never selects it"
)

_PY_DECIDED_BY = (
    "the guest's own bytes — lang_py.run_python_script branches on "
    "lang_py._is_component_guest (an 8-byte header test), not on any flag"
)
_JS_DECIDED_BY = (
    "the artifact handed to run — lang.run_language routes source/script_path to "
    "run_javascript_source and anything else to run_javascript_module"
)


def _language_preopens_view(view: dict[str, Any], language: str) -> dict[str, Any]:
    """State the grants the language adapter actually builds.

    Neither language run takes the caller's ``allow_dirs`` at face value, and
    which grant set ends up in effect is decided by the ARTIFACT, not by a
    flag: ``lang_py.run_python_script`` branches on the guest's header bytes (a
    WASI-0.2 component guest gets one throwaway per-run directory, a legacy
    Preview1 interpreter guest additionally mounts its own stdlib plus the
    script's OWN directory at ``/work``), and JavaScript source goes to
    ``lang_js.run_javascript_source`` (which replaces the grants) while a
    pre-compiled module goes to ``lang_js.run_javascript_module`` (which keeps
    them). A view that listed one fixed set would pre-approve permissions the
    run never gets, or hide ones it really gets — the exact drift this command
    exists to stop. The mount paths are read from the adapter constants so the
    view cannot drift away from the code it describes.
    """
    from ephemora_cell import lang_js, lang_py

    dropped = list(view["requested"])
    if language == "python":
        return {
            **view,
            "language_effect": {
                "guest": "python",
                "path_dependent": True,
                "decided_by": _PY_DECIDED_BY,
                # both branches replace, so this one answer is honest
                "replaces_allow_dirs": True,
                "dropped_allow_dirs": dropped,
                "component_run": _guest_run(
                    "lang_py.run_python_script",
                    replaces=True,
                    dropped=dropped,
                    mounts=[
                        {
                            "guest_path": lang_py._WORK_GUEST_PATH,
                            "owner": "a throwaway per-run directory holding a copy "
                            "of the script — the run's only preopen",
                        }
                    ],
                    run_abi=ABI_COMPONENT,
                    sandbox_scratch=False,
                    extra_grants=_COMPONENT_NO_SANDBOX,
                    reachability=_PY_FROM_CLI,
                ),
                "legacy_interpreter_run": _guest_run(
                    "lang_py.run_python_script",
                    replaces=True,
                    dropped=dropped,
                    mounts=[
                        {
                            "guest_path": lang_py._STDLIB_GUEST_PATH,
                            "owner": "the installed interpreter guest's own stdlib "
                            "(host-owned)",
                        },
                        {
                            "guest_path": lang_py._WORK_GUEST_PATH,
                            "owner": "the directory holding the script being run — "
                            "the caller's own files, NOT a private per-run directory",
                        },
                    ],
                    run_abi=ABI_PREVIEW1,
                    sandbox_scratch=True,
                    extra_grants=_PREVIEW1_SANDBOX,
                    reachability=_PY_FROM_LEGACY_GUEST,
                ),
                "detail": (
                    "both Python branches REPLACE the allow_dirs passed to the call: "
                    "the installed WASI-0.2 component guest gets one throwaway "
                    f"per-run {lang_py._WORK_GUEST_PATH} mount; a legacy Preview1 "
                    "interpreter guest additionally mounts its own stdlib at "
                    f"{lang_py._STDLIB_GUEST_PATH} and the script's OWN directory at "
                    f"{lang_py._WORK_GUEST_PATH} — that last grant is the caller's "
                    "files, not a private directory"
                ),
            },
        }
    return {
        **view,
        "language_effect": {
            "guest": "javascript",
            "path_dependent": True,
            "decided_by": _JS_DECIDED_BY,
            # here even WHETHER the grants are replaced differs, so no single verdict
            "replaces_allow_dirs": None,
            # Symmetric with the Python view on purpose: the key is always
            # present, so a consumer cannot read a missing field as "nothing is
            # dropped". These are the entries the CLI-reachable branch discards.
            "dropped_allow_dirs": dropped,
            "source_run": _guest_run(
                "lang_js.run_javascript_source",
                replaces=True,
                dropped=dropped,
                mounts=[
                    {
                        "guest_path": lang_js._WORK_GUEST_PATH,
                        "owner": "a throwaway per-run directory holding the staged "
                        "program — the only grant taken from the caller's set; the "
                        "run still gets its own ephemeral /sandbox scratch",
                    }
                ],
                run_abi=ABI_PREVIEW1,
                sandbox_scratch=True,
                extra_grants=_PREVIEW1_SANDBOX,
                reachability=_JS_FROM_CLI,
            ),
            "module_run": _guest_run(
                "lang_js.run_javascript_module",
                replaces=False,
                dropped=[],
                mounts=[],
                run_abi=ABI_PREVIEW1,
                sandbox_scratch=True,
                extra_grants=_PREVIEW1_SANDBOX,
                reachability=_JS_LIBRARY_ONLY,
            ),
            "detail": (
                "a JavaScript SOURCE run replaces the caller's allow_dirs with one "
                f"private {lang_js._WORK_GUEST_PATH} mount; a pre-compiled JavaScript "
                "MODULE run keeps them — which grant set is being approved depends on "
                "the artifact handed to run. Both entries run the preview1 ABI, so "
                "both additionally get the run's own ephemeral /sandbox scratch named "
                "in the note below"
            ),
        },
    }


def _sync_view(config: WASIConfig, abi: str) -> dict[str, Any]:
    """The enforcement equation for the ABI this run would resolve to."""
    allow_fsync = bool(config.allow_fsync)
    view: dict[str, Any] = {
        "allow_fsync": allow_fsync,
        "abi": abi,
        "detail": _SYNC_DETAIL,
    }
    if abi == ABI_AUTO:
        # Nothing has run, so no ABI is resolved yet: state no verdict at the
        # top level instead of guessing one, and report both per-ABI verdicts.
        view["holds"] = None
        view["per_abi"] = {
            candidate: sync_blockade_holds(candidate, allow_fsync)
            for candidate in _ABIS
        }
    else:
        view["holds"] = sync_blockade_holds(abi, allow_fsync)
    return view


def _refusal_reason(entry: str) -> str | None:
    """Why a run would NOT preopen ``entry`` — or None when it would.

    The two layers that fire in the run's own order are consulted: the
    constructor's canonical validation (a run fails before it starts) and,
    behind it, the run-time dir guard plus the grant-time existence check (an
    entry is dropped with a warning). Only the existing implementations are
    consulted; this module relays their result. Honest scope note: with the
    shipped ``_DANGEROUS_DIRS_POLICY``, anything the run-time guard would strip
    is already refused by ``validate_allow_dirs`` first, so the guard's own
    refusal string is defence-in-depth for a policy that changes — it has never
    been observed to fire, and a run that reaches it is still refused.
    """
    try:
        validate_allow_dirs((entry,))
    except ValueError as exc:  # the run's own construction-time refusal
        return _REFUSED_AT_CONSTRUCTION.format(exc=exc)
    if not filter_dangerous_dirs((entry,)):
        return _REFUSED_BY_FILTER
    host, guest = split_dir_mapping(entry)
    canon = canonicalize_dir(host)
    if not os.path.isdir(canon):
        return _REFUSED_AT_GRANT.format(canon=canon, guest=guest)
    return None


def _preopens_view(config: WASIConfig) -> dict[str, Any]:
    effective: list[dict[str, str]] = []
    refused: list[dict[str, str]] = []
    for entry in config.allow_dirs:
        reason = _refusal_reason(entry)
        if reason is not None:
            refused.append({"entry": entry, "reason": reason})
            continue
        host, guest = split_dir_mapping(entry)
        effective.append({"host": canonicalize_dir(host), "guest": guest})
    return {
        "requested": list(config.allow_dirs),
        "effective": effective,
        "refused": refused,
        "note": _SANDBOX_MOUNT_NOTE,
        "baseline_scope": _BASELINE_SCOPE_NOTE,
    }


def _env_view(config: WASIConfig) -> dict[str, Any]:
    """Env NAMES and count only — a value here would be a secret leak."""
    names = [name for name, _ in (config.allow_env or ())]
    return {"names": names, "count": len(names)}


def snapshot(
    config: WASIConfig,
    *,
    trust: str,
    abi: str,
    profile_name: str | None,
    isolated: bool = False,
    language: str = LANGUAGE_WASM,
) -> dict[str, Any]:
    """Compute the policy a run with this config/trust/abi WOULD carry.

    Pure and deterministic: it reads the config and the existing policy
    functions, starts nothing and builds no engine. Fails closed on a posture,
    ABI or guest the runtime would refuse (a mis-set value must never widen a
    guarantee — same check as the run gate).
    """
    if trust not in VALID_TRUST:
        raise ValueError(
            f"unknown trust {trust!r}; expected one of {sorted(VALID_TRUST)} "
            "(a mis-set posture must never widen the isolation guarantee)"
        )
    if abi != ABI_AUTO and abi not in _ABIS:
        raise ValueError(
            f"unknown abi {abi!r}; expected 'auto' or one of {list(_ABIS)}"
        )
    if language not in _LANGUAGES:
        raise ValueError(
            f"unknown language {language!r}; expected one of {list(_LANGUAGES)}"
        )
    # A language run's ABI is the adapter's fact, not the caller's choice:
    # viewing it under any other ABI would report a sync blockade and a sandbox
    # note for a run that cannot happen. The CLI refuses a contradicting --abi
    # (see _abi_contradicts_guest), so no caller is quietly re-labelled here.
    effective_abi = abi if language == LANGUAGE_WASM else LANGUAGE_ABI[language]
    isolation = _isolation_view(trust, effective_abi, isolated)
    if language != LANGUAGE_WASM:
        isolation = _language_isolation_view(isolation, language)
    preopens = _preopens_view(config)
    if language != LANGUAGE_WASM:
        preopens = _language_preopens_view(preopens, language)
    sync = _sync_view(config, effective_abi)
    abi_source = (
        {} if language == LANGUAGE_WASM else {"abi_source": _LANG_ABI_SOURCE[language]}
    )
    fingerprint_note = (
        {}
        if language == LANGUAGE_WASM
        else {"fingerprint_note": _FINGERPRINT_LANG_NOTE.format(language=language)}
    )
    return {
        "schema": SCHEMA,
        "profile": profile_name,
        "language": language,
        "trust": trust,
        "abi": effective_abi,
        **abi_source,
        "budgets": _budgets(config),
        "isolation": isolation,
        "sync_blockade": sync,
        "preopens": preopens,
        "env": _env_view(config),
        # Exactly the record's digest: same function, same bytes.
        # For a language guest this is the digest of the CALLER's config — the
        # adapter rebuilds the grants, so the run's own record digers differ;
        # the snapshot says so instead of implying an attestation it cannot make.
        "fingerprint": policy_fingerprint(config),
        **fingerprint_note,
        "security_baseline": security_baseline_for(config),
    }


def to_json(snap: dict[str, Any]) -> dict[str, Any]:
    """The snapshot as the JSON payload the CLI writes (schema-tagged)."""
    if snap.get("schema") != SCHEMA:
        raise ValueError(f"not a policy-check snapshot: schema {snap.get('schema')!r}")
    return snap


def _fmt_value(value: Any) -> str:
    if isinstance(value, list):
        return "[" + ", ".join(str(item) for item in value) + "]"
    return str(value)


def _format_isolation(view: dict[str, Any]) -> list[str]:
    def label(required: bool) -> str:
        return (
            "worker subprocess MANDATORY"
            if required
            else "explicit-trusted in-process fast path"
        )

    if "per_abi" in view:
        lines = [
            f"isolation [{abi}]: {label(entry['required'])} — {_MANDATE} "
            "(per ABI; module bytes decide at run time)"
            for abi, entry in view["per_abi"].items()
        ]
    else:
        lines = [
            f"isolation: {label(view['required'])} "
            f"(trust={view['trust']}, abi={view['abi']}) — {_MANDATE}"
        ]
    if view.get("raised_by"):
        lines.append(
            f"isolation raised by: {view['raised_by']} "
            "(the flag can raise isolation, never lower it)"
        )
    if view.get("mandate_source"):
        lines.append(f"isolation forced by: {view['mandate_source']}")
    return lines


def _sync_verdict(abi: str, holds: bool, allow_fsync: bool) -> str:
    if holds:
        return "enforced (preview1 path, allow_fsync closed)"
    if abi == ABI_PREVIEW1:
        return f"not enforced (allow_fsync={allow_fsync} lifts the blockade)"
    return "not applicable (this path has no sync trap)"


def _format_sync(view: dict[str, Any]) -> list[str]:
    allow_fsync = view["allow_fsync"]
    if "per_abi" in view:
        return [
            f"sync blockade [{abi}]: {_sync_verdict(abi, holds, allow_fsync)}"
            for abi, holds in view["per_abi"].items()
        ]
    return [f"sync blockade: {_sync_verdict(view['abi'], view['holds'], allow_fsync)}"]


def _format_preopens(view: dict[str, Any]) -> list[str]:
    effect = view.get("language_effect")
    # A language adapter rebuilds the grants, so an entry this view calls
    # 'allowed' may never reach the guest. Saying 'allowed' unqualified would
    # read as an approval the run does not carry, so the line is labelled for
    # exactly what it is: a config-time verdict, before the adapter's set wins.
    will_drop = bool(effect and _effect_dropped(effect)) if effect else False
    allowed_label = "allowed (pre-adapter)" if will_drop else "allowed"
    lines = [f"preopens (requested {len(view['requested'])}):"]
    for entry in view["effective"]:
        lines.append(f"  {allowed_label}: {entry['host']} -> {entry['guest']}")
    if not view["refused"]:
        lines.append("  refused: (none)")
    for entry in view["refused"]:
        lines.append(f"  refused: {entry['entry']} — {entry['reason']}")
    if effect is not None:
        lines.append(f"  guest [{effect['guest']}]: {effect['detail']}")
        if effect.get("decided_by"):
            lines.append(f"    decided by: {effect['decided_by']}")
        for run_key in _RUN_KEYS:
            sub = effect.get(run_key)
            if not isinstance(sub, dict):
                continue
            lines.append(f"    {run_key} ({sub['adapter_entry']}, abi={sub['abi']}):")
            if sub["mounts"]:
                for mount in sub["mounts"]:
                    lines.append(
                        f"      grants: {mount['guest_path']} — {mount['owner']}"
                    )
            else:
                lines.append("      grants: (the caller's own allow_dirs stand)")
            lines.append(f"      also: {sub['extra_grants']}")
            lines.append(f"      reach: {sub['reachability']}")
            if sub["dropped_allow_dirs"]:
                lines.append(f"    drops: {', '.join(sub['dropped_allow_dirs'])}")
    lines.append(f"  note: {view['note']}")
    return lines


def _effect_dropped(effect: dict[str, Any]) -> list[str]:
    """Caller directories any branch of this language view would discard."""
    dropped = list(effect.get("dropped_allow_dirs") or ())
    for run_key in _RUN_KEYS:
        sub = effect.get(run_key)
        if isinstance(sub, dict):
            dropped.extend(sub.get("dropped_allow_dirs") or ())
    return sorted(set(dropped))


def format_report(snap: dict[str, Any]) -> str:
    """Human-readable plain-text rendering of :func:`snapshot` (allowed/denied)."""
    profile = snap["profile"] if snap["profile"] is not None else "(none)"
    lines = [
        f"policy check — {snap['schema']}",
        f"profile: {profile}",
        f"guest: {snap.get('language', 'wasm')}   "
        f"trust: {snap['trust']}   abi: {snap['abi']}",
    ]
    if snap.get("abi_source"):
        lines.append(f"abi decided by: {snap['abi_source']}")
    lines.extend(_format_isolation(snap["isolation"]))
    lines.extend(_format_sync(snap["sync_blockade"]))
    lines.append("budgets:")
    for key, value in snap["budgets"].items():
        rendered = _fmt_value(value)
        if key == "max_wasm_bytes" and value == 0:
            rendered += " (no cap)"
        lines.append(f"  {key}: {rendered}")
    lines.extend(_format_preopens(snap["preopens"]))
    env = snap["env"]
    lines.append(f"env: {env['count']} name(s): {', '.join(env['names']) or '(none)'}")
    lines.append(
        f"fingerprint: {snap['fingerprint'][:16]}… (sha256 prefix of the policy)"
    )
    if snap.get("fingerprint_note"):
        lines.append(f"fingerprint scope: {snap['fingerprint_note']}")
    return "\n".join(lines)
