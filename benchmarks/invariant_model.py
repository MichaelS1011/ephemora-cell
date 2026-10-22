#!/usr/bin/env python3
"""Small security-decision model + exhaustive invariant check.

Formal-methods FEASIBILITY probe, not a verification of Wasmtime. It models the
ONE decision that carries the security weight in Ephemora-cell — the ADR-015
isolation choke point in ``WASISandbox.run`` — plus the capability-confinement
filter and the execution-record attestation rule, and checks three invariants
over the full (small) state space:

  I1 Fail-Closed            — if isolation is required and cannot be honoured,
                              the job is refused / safely ended; the guest NEVER
                              silently runs on the weaker (in-process) boundary.
  I2 Capability Confinement — the granted capabilities stay inside the allowed
                              set; a request can only shrink, never widen.
  I3 Isolation Monotonicity — the effective isolation is >= the required one;
                              an unknown state is never read as safe.

The model is checked by brute-force enumeration (state space is a few dozen
tuples), mirroring the real decision functions:
  isolation_required_for, _isolation_gate, _filter_dangerous_dirs/_grant_preopens,
  apply_config(execution_mode/abi/sync_blockade_enforced).

It is a MODEL, and the rule is stated up front: a clean model does NOT prove a clean
implementation. The real path is corroborated by tests/test_isolation_gate.py,
referenced per transition in the report.

Run (any interpreter; no wasmtime needed — pure model):
    python benchmarks/invariant_model.py
"""

from __future__ import annotations

import itertools
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

# Import the ACTUAL predicates so the model cannot drift from the code it models.
from ephemora_cell.execution_report import (  # noqa: E402
    ABI_COMPONENT,
    ABI_PREVIEW1,
    VALID_TRUST,
    isolation_required_for,
)

TRUST_TRUSTED = "trusted"
EXECUTION_MODES = ("in_process", "subprocess")

# Isolation strength ordering used by monotonicity: a subprocess run isolates
# strictly more than an in-process run; "refused" carries the guest nowhere.
STRENGTH = {"in_process": 0, "subprocess": 1}


def gate_decision(
    trust: str, abi: str, requested_subprocess: bool, isolation_available: bool
) -> tuple[str, bool]:
    """Mirror ``WASISandbox._isolation_gate``. Returns (mode, ran_in_process).

    mode is one of: 'raise' (bad trust), 'in_process', 'subprocess', 'refused'.
    ran_in_process is True only if a guest would actually execute in-process.
    """
    if trust not in VALID_TRUST:
        return ("raise", False)
    if trust == TRUST_TRUSTED:
        # host authorised the in-process fast path; passed through unchanged.
        return (
            ("subprocess" if requested_subprocess else "in_process"),
            not requested_subprocess,
        )
    if not isolation_required_for(trust, abi):
        # Only reachable for a trusted posture now (1.2.0 mandate spans both
        # ABIs); the pass-through keeps the mirror faithful to the gate.
        return (
            ("subprocess" if requested_subprocess else "in_process"),
            not requested_subprocess,
        )
    # isolation mandated (untrusted/unknown, preview1 OR component)
    if isolation_available:
        return ("subprocess", False)  # force worker; NEVER lowered -> not in-process
    return ("refused", False)  # refuse BEFORE the guest runs; never downgraded


def worker_outcome(mode: str, outcome: str) -> tuple[str, bool]:
    """Given a chosen mode and a worker event, the effective (mode, ran_in_process).

    The mandate can only be raised to subprocess; a worker crash/timeout under a
    forced run yields a fail-closed ERROR, never an in-process re-run.
    """
    if mode in ("in_process", "refused", "raise"):
        return (mode, mode == "in_process")
    # forced/selected subprocess path
    if outcome in ("crash", "timeout"):
        return ("error", False)  # fail-closed, NOT re-run in-process
    return ("subprocess", False)


def filter_grant(allow_dirs: tuple[str, ...], abi: str) -> tuple[set[str], set[str]]:
    """Mirror capability confinement: requested -> effective.

    Dangerous dirs (/dev,/proc,/sys family) are dropped; a component run is
    granted none of the preview1 /sandbox scratch. Effective is always a subset
    of requested; nothing here can ADD a directory the host did not request.
    """
    DANGEROUS_PREFIXES = ("/dev", "/proc", "/sys")
    safe = {
        d
        for d in allow_dirs
        if not any(d == p or d.startswith(p + "/") for p in DANGEROUS_PREFIXES)
    }
    if abi == ABI_COMPONENT:
        safe = {d for d in safe if d != "/sandbox"}
    return (set(allow_dirs), safe)


def record_attests(
    mode: str, ran_in_process: bool, abi: str | None
) -> dict[str, object]:
    """Mirror apply_config evidence rules (ADR-014): effective, not requested."""
    rec: dict[str, object] = {}
    # A refusal of a protected component sets abi=None -> no component attested.
    rec["execution_mode"] = mode if mode in EXECUTION_MODES else None
    rec["abi"] = abi if mode in EXECUTION_MODES else None
    # sync_blockade is DERIVED from (abi, allow_fsync), never trusted from caller;
    # the worker applies the same preview1 fd_sync trap, so an EXECUTED preview1
    # run holds the blockade in EITHER mode (in_process or subprocess) -- not
    # in_process only. Mode outside the execution set (refused/error) attests
    # nothing. This mirrors the real sync_blockade_holds(abi, allow_fsync=False).
    rec["sync_blockade_enforced"] = mode in EXECUTION_MODES and abi == ABI_PREVIEW1
    return rec


def run() -> dict:
    violations: list[dict] = []
    checked = 0
    trusts = ["trusted", "untrusted", "unknown", "bogus"]
    abis = [ABI_PREVIEW1, ABI_COMPONENT]
    for trust, abi, req_sub, avail, outcome in itertools.product(
        trusts, abis, (True, False), (True, False), ("ok", "crash", "timeout")
    ):
        checked += 1
        base_mode, _ = gate_decision(trust, abi, req_sub, avail)
        eff_mode, eff_ran_ip = worker_outcome(base_mode, outcome)

        # I1 Fail-Closed: mandated isolation must never end with the guest run in-process.
        mandate = isolation_required_for(trust, abi) if trust in VALID_TRUST else False
        if mandate and eff_ran_ip:
            violations.append(
                {
                    "inv": "I1_fail_closed",
                    "state": (trust, abi, req_sub, avail, outcome),
                    "why": "mandated isolation but guest ran in-process",
                }
            )
        # I1b: mandated + unavailable must be refused/error, not a plain in-process run.
        if mandate and not avail and eff_mode not in ("refused", "error", "subprocess"):
            violations.append(
                {
                    "inv": "I1b_no_downgrade",
                    "state": (trust, abi, req_sub, avail, outcome),
                    "why": f"mandated+unavailable resolved to {eff_mode}",
                }
            )
        # I3 Monotonicity: unknown trust behaves exactly like untrusted (never
        # safer). The 1.2.0 mandate spans both ABIs, so the check covers each.
        if trust in ("unknown", "untrusted"):
            m_unk = isolation_required_for("unknown", abi)
            m_un = isolation_required_for("untrusted", abi)
            if m_unk != m_un:
                violations.append(
                    {
                        "inv": "I3_unknown_not_equal_untrusted",
                        "state": (trust, abi, req_sub, avail, outcome),
                        "why": "unknown diverged",
                    }
                )
        # I3b: a run that resolved to component under a mandate must reach subprocess
        # (strength 1) or be ended — never strength 0 while a guest executes.
        if mandate and eff_mode == "in_process":
            violations.append(
                {
                    "inv": "I3b_isolation_weaker_than_required",
                    "state": (trust, abi, req_sub, avail, outcome),
                    "why": "in_process under mandate",
                }
            )
        # I2 Capability confinement: effective grant subset of requested, never widened.
        for abi_probe in abis:
            req_set, eff_set = filter_grant(("/data", "/dev", "/sandbox"), abi_probe)
            if not eff_set.issubset(req_set):
                violations.append(
                    {
                        "inv": "I2_capability_widened",
                        "state": (trust, abi_probe, req_sub, avail, outcome),
                        "why": f"{sorted(eff_set - req_set)} added beyond request",
                    }
                )
            if "/dev" in eff_set or "/proc" in eff_set or "/sys" in eff_set:
                violations.append(
                    {
                        "inv": "I2_dangerous_granted",
                        "state": (trust, abi_probe, req_sub, avail, outcome),
                        "why": "dangerous dir granted",
                    }
                )

    # Evidence-consistency (release-mandated): a component that never ran attests no
    # component execution. Simulate the protect-component refusal.
    ev = record_attests("refused", False, ABI_COMPONENT)
    evidence_consistent = ev["abi"] is None and ev["execution_mode"] is None

    return {
        "title": "Security-decision model — exhaustive invariant check",
        "measured": True,
        "model_scope": "ADR-015 isolation gate + capability filter + record "
        "attestation. Wasmtime runtime NOT modeled.",
        "states_enumerated": checked,
        "trust_levels": sorted(VALID_TRUST),
        "abis": [ABI_PREVIEW1, ABI_COMPONENT],
        "execution_modes": list(EXECUTION_MODES),
        "invariants": {
            "I1_fail_closed": "mandated isolation never runs guest in-process",
            "I2_capability_confinement": "effective grant subset of requested; dangerous never granted",
            "I3_isolation_monotonicity": "effective isolation >= required; unknown == untrusted, never safe",
        },
        "violations_found": len(violations),
        "violations": violations,
        "evidence_consistency": {
            "protected_refusal_attests_no_component": evidence_consistent,
            "note": "sync_blockade_enforced is derived from (abi,allow_fsync), never trusted from caller",
        },
        "verdict": "PASS" if (not violations and evidence_consistent) else "FAIL",
        "model_limitation": "A clean model does NOT prove a clean implementation. "
        "Corroboration: tests/test_isolation_gate.py.",
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
