#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""Measure what the language adapters really preopen, against what
``ephemora policy check --language`` promises before the run.

WHY THIS EXISTS: ``policy check`` states permissions for a run that has not
happened yet. Every claim it makes about a Python or JavaScript guest is an
claim about code in ``lang_py``/``lang_js`` — and source-text pinning alone
passed one false exclusivity claim (a Preview1 run's ``/sandbox`` scratch). This
harness runs the four adapter entries with real guests and compares:

* the ``allow_dirs`` the adapter builds, by GUEST and by HOST path,
* the ``abi`` the adapter hands the sandbox (``None`` = the runner default),
* whether ``use_subprocess=True`` was actually passed,
* the run-side ``effective_preopens`` the worker reported, including /sandbox,
* and, for Python, what the guest itself can see inside ``/work``.

Guests are bring-your-own (ADR-009 D2 — no interpreter binaries ship in the
core). A missing guest is recorded as ``NOT-MEASURED``, never guessed, and a
guest whose digest matches neither the supplied ``*_SHA256`` env nor the canonical
table below is a hard ``MISMATCH`` rather than a silent substitute.

Env (same names the opt-in suite tests use):
  EPHEMORA_BYO_PYTHON_GUEST / _STDLIB / EPHEMORA_BYO_PYTHON_GUEST_SHA256
      legacy Preview1 CPython-WASI core-module interpreter
  EPHEMORA_PY_COMPONENT_GUEST / _SHA256   WASI-0.2 component CPython guest
  EPHEMORA_JS_INTERPRETER_GUEST / _SHA256  QuickJS source-interpreter guest
  EPHEMORA_BYO_JAVY_GUEST / _SHA256        pre-compiled Javy module guest

The published report is redacted at serialisation time: a path under the
maintainer's ignored build tree collapses to ``<build-tree>``, the repo root
becomes ``<repo>``, the system temp dir ``<tmpdir>`` and the home directory
``<home>``. The measurement itself compares real paths; the artefact's authority
is the guest digest, not the directory a particular machine keeps guests in.

Usage (all four guests must be named, or those cases report NOT-MEASURED):
  EPHEMORA_BYO_PYTHON_GUEST=<python3.10.wasm> \
  EPHEMORA_BYO_PYTHON_STDLIB=<…/lib/python3.10> \
  EPHEMORA_PY_COMPONENT_GUEST=<componentize-py guest.wasm> \
  EPHEMORA_JS_INTERPRETER_GUEST=<quickjs guest.wasm> \
  EPHEMORA_BYO_JAVY_GUEST=<javy module.wasm> \
  python benchmarks/language_grant_evidence.py \
      > benchmarks/results/<date>/language_grant_views_measured.json
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from tempfile import gettempdir, mkdtemp

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

#: Machine-specific prefixes replaced in the serialised report (longest first, so
#: a build tree inside the repo cannot be half-rewritten by the repo rule, and a
#: repo inside the home directory cannot be half-rewritten by the home rule).
#: Local scratch trees are whatever ``.tmp*`` directories sit beside the checkout;
#: the report names none of them.
_SCRATCH_TREES = tuple(
    (str(path), "<build-tree>") for path in sorted(REPO.glob(".tmp*")) if path.is_dir()
)
_PREFIXES = tuple(
    sorted(
        (
            *_SCRATCH_TREES,
            (str(REPO), "<repo>"),
            (str(Path(gettempdir()).resolve()), "<tmpdir>"),
            (str(Path(gettempdir())), "<tmpdir>"),
            (str(Path.home()), "<home>"),
        ),
        key=lambda pair: -len(pair[0]),
    )
)

_BUILD_TREE_LABEL = "<build-tree>"


def _redact(text: str) -> str:
    for real, label in _PREFIXES:
        if real in text:
            text = text.replace(real, label)
    # A build-tree path is collapsed to the marker alone: which guest ran is
    # identified by its digest and role in this report, and the directory layout
    # of one maintainer's working copy is not part of the claim being published.
    if text.startswith(_BUILD_TREE_LABEL):
        return _BUILD_TREE_LABEL
    return text


def _redact_tree(value):
    """Redact every string in a report structure, keys included."""
    if isinstance(value, str):
        return _redact(value)
    if isinstance(value, list):
        return [_redact_tree(item) for item in value]
    if isinstance(value, dict):
        return {_redact(key): _redact_tree(item) for key, item in value.items()}
    return value


from ephemora_cell import lang_js, lang_py  # noqa: E402
from ephemora_cell.policy_cli import snapshot  # noqa: E402
from ephemora_cell.profiles import get as get_profile  # noqa: E402

#: Canonical digests of the guests the published measurement was taken with.
#: ``EPHEMORA_*_SHA`` wins when supplied; these are the fallback claim.
#: The ``js_interpreter`` value is the 1.2.0 release-candidate guest — the clean
#: rebuild that removed local build paths (``docs/language-guest-build.md`` §3).
#: The superseded bytes it replaces (``53037972…fe5646``, 737 959 B) must not be
#: able to stand in for a release measurement.
CANONICAL_GUEST_SHA256 = {
    "python_legacy": "8e40bfb538b390c1e8b652f4b4369d83d3fd6d1af6b3111631ad80bf0c5a0a02",
    "python_component": "42984274746ee96e9855049f5d0370b9515fa13e4ce9610c29083c9a8a558935",
    "js_interpreter": "a192e2308cd3ea6749cc15ff36ef9db9edbe2456bf9520922234c9efc46efed5",
    "js_javy_module": "124757d481928a5b232551177e78a8fafab0b03418e7fd89c53424a843acc64b",
}

PROBE = """\
import json, os, sys
print(json.dumps({
    "argv": sys.argv,
    "work_listing": sorted(os.listdir("/work"))[:8],
    "sibling_of_script_visible_at_work": os.path.exists("/work/caller_marker.txt"),
    "separate_caller_dir_visible_at_work": os.path.exists("/work/caller_dir_marker.txt"),
}))
"""

_rows: list[dict] = []


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _guest(role: str, env: str) -> dict:
    """Resolve one BYO guest and verify it against a pinned digest."""
    raw = os.environ.get(env)
    if not raw:
        return {"role": role, "present": False, "why": f"{env} not set"}
    # Absolute before anything downstream sees it: the adapters preopen these
    # paths, and a relative BYO value would describe a different directory.
    path = Path(raw).expanduser().resolve()
    if not path.exists():
        return {"role": role, "present": False, "why": f"{env} points at {path}"}
    digest = _sha256(path)
    expected = os.environ.get(f"{env}_SHA256") or CANONICAL_GUEST_SHA256[role]
    return {
        "role": role,
        "present": True,
        "path": str(path),
        "sha256": digest,
        "digest_verified": digest == expected,
        "expected_sha256": expected,
    }


def _instrument(module) -> None:
    """Record the adapter's own sandbox calls without changing its behaviour."""
    real = module.WASISandbox

    class _Recording(real):
        def __init__(self, *args, **kwargs):
            cfg = kwargs.get("config")
            _rows.append(
                {"constructed_allow_dirs": list(cfg.allow_dirs) if cfg else []}
            )
            super().__init__(*args, **kwargs)

        def run(self, *args, **kwargs):
            result = super().run(*args, **kwargs)
            _rows.append(
                {
                    "effective_preopens": list(result.effective_preopens),
                    "abi": kwargs.get("abi"),
                    "use_subprocess": kwargs.get("use_subprocess"),
                }
            )
            return result

    module.WASISandbox = _Recording


def _guest_names(entries) -> list[str]:
    return sorted(
        str(e).split("::", 1)[1] if "::" in str(e) else str(e) for e in entries or ()
    )


def _measure(label: str, fn) -> dict:
    _rows.clear()
    error = status = exit_code = None
    stdout = ""
    try:
        res = fn()
        stdout = (res.get("stdout") or "").strip()
        # a guest fault is a RETURNED result, not an exception: capture it, or a
        # failed probe would read as a successful measurement
        status, exit_code = res.get("status"), res.get("exit_code")
    except Exception as exc:  # fail closed in the evidence, not in a claim
        error = f"{type(exc).__name__}: {exc}"
    constructed = next((r["constructed_allow_dirs"] for r in _rows), None)
    run_row = next((r for r in _rows if "effective_preopens" in r), {})
    probe = None
    if stdout:
        try:
            probe = json.loads(stdout.splitlines()[-1])
        except json.JSONDecodeError:
            probe = {"raw_stdout": stdout.splitlines()[-1][:200]}
    return {
        "case": label,
        "error": error,
        "status": status,
        "exit_code": exit_code,
        "constructed_allow_dirs": constructed,
        "guest_paths": _guest_names(constructed),
        "host_paths": sorted(str(e).split("::", 1)[0] for e in (constructed or ())),
        "effective_preopens": run_row.get("effective_preopens"),
        "abi_passed": run_row.get("abi", "absent"),
        "use_subprocess": run_row.get("use_subprocess", "absent"),
        "guest_probe": probe,
    }


def _promise(language: str, key: str) -> dict:
    view = snapshot(
        replace(get_profile("interpreter")),
        trust="unknown",
        abi="auto",
        profile_name=None,
        language=language,
    )
    return view["preopens"]["language_effect"][key]


def _judge(case: dict, promise: dict, *, expect: dict, caller: list[str]) -> dict:
    """Compare one measurement against the sub-view that makes the claim.

    ``expect`` states what the HOST side can be checked against: either an exact
    set of directories (the caller's grants and the legacy interpreter's two
    mounts are known before the run) or a temp-directory prefix (the throwaway
    branch's path exists only at run time, so its SHAPE is the claim).
    """
    measured = case["effective_preopens"] or []
    measured_sandbox = "/sandbox" in measured
    # A replacing branch promises its own mounts; a keeping branch promises the
    # caller's entries unchanged — those are different lists, not an empty one.
    if promise["replaces_allow_dirs"]:
        promised_names = [m["guest_path"] for m in promise["mounts"]]
    else:
        promised_names = list(caller)
    checks = {
        "guest_paths": case["guest_paths"] == sorted(promised_names),
        "host_paths": _host_matches(case["host_paths"], expect),
        "sandbox_scratch": measured_sandbox == bool(promise["sandbox_scratch"]),
        "abi": (
            case["abi_passed"] == promise["abi"]
            if promise["abi"] == "component"
            else promise["abi"] == "preview1" and case["abi_passed"] is None
        ),
        "worker": case["use_subprocess"] is True,
        # a guest-level fault is a returned status, not an exception: a MATCH on
        # grants would otherwise be read off a run that never completed
        "run_succeeded": case["error"] is None
        and str(case["status"] or "").upper().endswith("SUCCESS"),
    }
    if "argv" in expect:
        # the argv contract differs between the two Python routes (the runner's
        # neutral argv[0] vs the interpreter's script path) and is stated here
        # rather than assumed
        checks["argv"] = (case["guest_probe"] or {}).get("argv") == expect["argv"]
    return {
        "case": case["case"],
        "verdict": "MATCH" if all(checks.values()) else "MISMATCH",
        "checks": checks,
        "promised": {
            "guest_paths": [m["guest_path"] for m in promise["mounts"]],
            "replaces_allow_dirs": promise["replaces_allow_dirs"],
            "abi": promise["abi"],
            "sandbox_scratch": promise["sandbox_scratch"],
            "reachability": promise["reachability"],
        },
        "host_expectation": expect,
        "measured": {
            "guest_paths": case["guest_paths"],
            "host_paths": case["host_paths"],
            "sandbox_scratch": measured_sandbox,
            "abi_passed": case["abi_passed"],
            "use_subprocess": case["use_subprocess"],
            "effective_preopens": measured,
        },
        "guest_probe": case["guest_probe"],
        "run_status": case["status"],
        "run_error": case["error"],
    }


def _host_matches(host_paths: list[str], expect: dict) -> bool:
    """Resolve before comparing: macOS reports temp roots both with and without
    the ``/private`` prefix, and that is not a difference in grants."""
    resolved = sorted(str(Path(p).resolve()) for p in host_paths)
    if expect["kind"] == "set":
        return resolved == sorted(str(Path(p).resolve()) for p in expect["paths"])
    if expect["kind"] == "temp_prefix":
        want_root = str(Path(expect["tempdir"]).resolve())
        return (
            len(resolved) == 1
            and os.path.basename(resolved[0]).startswith(expect["prefix"])
            and str(Path(resolved[0]).parent) == want_root
        )
    return False


def main() -> int:
    guests = {
        "python_legacy": _guest("python_legacy", "EPHEMORA_BYO_PYTHON_GUEST"),
        "python_component": _guest("python_component", "EPHEMORA_PY_COMPONENT_GUEST"),
        "js_interpreter": _guest("js_interpreter", "EPHEMORA_JS_INTERPRETER_GUEST"),
        "js_javy_module": _guest("js_javy_module", "EPHEMORA_BYO_JAVY_GUEST"),
    }
    stdlib = os.environ.get("EPHEMORA_BYO_PYTHON_STDLIB")
    if stdlib:
        stdlib = str(Path(stdlib).expanduser().resolve())
    for module in (lang_py, lang_js):
        _instrument(module)

    results: list[dict] = []

    def run_case(name: str, fn, language: str, key: str, expect: dict) -> None:
        guest = guests[language_role(name)]
        if not guest["present"]:
            results.append(
                {"case": name, "verdict": "NOT-MEASURED", "why": guest["why"]}
            )
            return
        if not guest["digest_verified"]:
            # a substituted guest is not the measured claim — refuse the verdict
            results.append(
                {
                    "case": name,
                    "verdict": "MISMATCH",
                    "why": "guest digest differs from the pinned value",
                    "guest": guest,
                }
            )
            return
        case = _measure(name, fn)
        results.append(
            _judge(case, _promise(language, key), expect=expect, caller=[caller])
        )

    work = Path(mkdtemp(prefix="ephemora-grantev-"))
    (work / "caller_dir").mkdir()
    (work / "caller_dir" / "caller_dir_marker.txt").write_text("x\n")
    (work / "script_dir").mkdir()
    (work / "script_dir" / "caller_marker.txt").write_text("x\n")
    (work / "script_dir" / "probe.py").write_text(PROBE)
    caller = str(work / "caller_dir")
    script_dir = work / "script_dir"
    config = replace(get_profile("interpreter"), allow_dirs=(caller,))

    run_case(
        "python_legacy_interpreter",
        lambda: lang_py.run_python_script(
            guests["python_legacy"]["path"],
            stdlib_dir=stdlib,
            script_path=str(script_dir / "probe.py"),
            expected_sha256=guests["python_legacy"]["sha256"],
            config=config,
        ),
        "python",
        "legacy_interpreter_run",
        {
            "kind": "set",
            "paths": [str(Path(stdlib or ".").resolve()), str(script_dir.resolve())],
            "argv": ["/work/probe.py"],
        },
    )
    run_case(
        "python_component_guest",
        lambda: lang_py.run_python_script(
            guests["python_component"]["path"],
            script_path=str(script_dir / "probe.py"),
            expected_sha256=guests["python_component"]["sha256"],
            config=config,
        ),
        "python",
        "component_run",
        {
            "kind": "temp_prefix",
            "prefix": "ephemora-pycomp-",
            "tempdir": gettempdir(),
            "argv": ["wasm-module"],
        },
    )
    run_case(
        "python_component_args_forwarded",
        lambda: lang_py.run_python_script(
            guests["python_component"]["path"],
            script_path=str(script_dir / "probe.py"),
            args=("a", "b"),
            expected_sha256=guests["python_component"]["sha256"],
            config=config,
        ),
        "python",
        "component_run",
        {
            "kind": "temp_prefix",
            "prefix": "ephemora-pycomp-",
            "tempdir": gettempdir(),
            # the caller's arguments occupy sys.argv[1:]; argv[0] stays the
            # runner's neutral tag (no host path is leaked to the guest)
            "argv": ["wasm-module", "a", "b"],
        },
    )
    run_case(
        "javascript_source_run",
        lambda: lang_js.run_javascript_source(
            guests["js_interpreter"]["path"],
            source="console.log('grantev');",
            expected_sha256=guests["js_interpreter"]["sha256"],
            config=config,
        ),
        "javascript",
        "source_run",
        {"kind": "temp_prefix", "prefix": "ephemora-jssrc-", "tempdir": gettempdir()},
    )
    run_case(
        "javascript_module_run",
        lambda: lang_js.run_javascript_module(
            guests["js_javy_module"]["path"],
            expected_sha256=guests["js_javy_module"]["sha256"],
            config=config,
        ),
        "javascript",
        "module_run",
        {"kind": "set", "paths": [str(Path(caller).resolve())]},
    )

    report = {
        "schema": "ephemora-cell/language-grant-evidence/1",
        "measured_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "environment": {
            "python": sys.version.split()[0],
            "platform": f"{platform.system()} {platform.release()} {platform.machine()}",
            "wasmtime": _wasmtime_version(),
            "doctor_runtime_floor": _doctor_floor(),
        },
        "guests": guests,
        "results": results,
    }
    print(json.dumps(_redact_tree(report), indent=2, sort_keys=False))
    return 0


def language_role(name: str) -> str:
    return {
        "python_legacy_interpreter": "python_legacy",
        "python_component_guest": "python_component",
        "python_component_args_forwarded": "python_component",
        "javascript_source_run": "js_interpreter",
        "javascript_module_run": "js_javy_module",
    }[name]


def _wasmtime_version() -> str:
    import importlib.metadata as md

    try:
        return md.version("wasmtime")
    except Exception:
        return "not installed"


def _doctor_floor() -> str:
    """The runtime line this measurement was taken on, in doctor's own words."""
    from ephemora_cell import doctor

    for check in doctor.run_checks():
        if check.name in ("runtime-floor", "runtime-identity"):
            return f"{check.status} — {check.detail}"
    return "no runtime-floor check"


if __name__ == "__main__":
    sys.exit(main())
