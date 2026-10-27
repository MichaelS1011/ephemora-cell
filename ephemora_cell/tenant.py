# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""Cumulative per-tenant accounting and admission (ADR-012).

A tenant is a **billing and aggregation identity, not an isolation boundary**.
Nothing a guest can observe changes when a tenant is attached — the walls stay
the ones in :class:`~ephemora_cell.wasi_runtime.WASIConfig`. What changes is
host-side: whether the host accepts the run at all, and whose total the consumed
units land in. ``SECURITY.md`` and ``docs/threat-model.md`` describe Cell as
single-tenant; this module adds attribution, it does not silently overturn that.

The model, chosen so every claim stays checkable:

* **Reserve on admission, charge the actual.** ``admit`` writes a line reserving
  what the run *could* consume under its own per-run walls (fuel, output bytes,
  wall clock). ``settle`` writes what it *did* consume and drops the
  reservation. A reservation is never billed: a guest that dies immediately
  after admission would otherwise empty its own account without doing work —
  a caller-controlled lockout.
* **Refusal happens before the run, never during it.** The comparison is the cap
  against ``settled + open reservations + THIS run's reservation`` — a cap of N
  admits N runs, not N+1. A run already executing is bounded only by its own
  per-run walls, and the overshoot is therefore bounded by
  (concurrent runs x per-run walls) — stated, not hidden.
* **The file is the evidence, the numbers are derived.** Totals are replayed
  from the lines and each line records the totals as they must be AFTER it took
  effect, so `apply` proves the book is internally consistent — it catches
  truncation, reordering and an edit that leaves the recorded totals stale.
  This is a SELF-CONSISTENCY check, not a keyed or hash-chained tamper-proof:
  the format is public, so a writer who can edit a line can also recompute the
  `totals` to match it, and an open reservation's size is deliberately outside
  the chained block (it depends on the read time). A writer who strips
  ``booking_version=2`` **and every v2-only total from every line** makes the
  book indistinguishable from a v1.1 book: it is then read as legacy and
  refuses new bookings, but its historical totals are whatever the writer
  left. The boundary is file ownership and mode, not the totals chain. What actually bars an
  unauthorized edit is ownership and mode — the book is host-exclusive and
  `AppendLog` refuses a symlinked or group-/world-writable file (v1.2). A
  caller with write access to this file is already the host: it can just delete
  the book, so the totals chain is a tamper-EVIDENCE aid, not the boundary.
* **Integers only.** Sums across runs must not depend on float
  shortest-round-trip forms. The JCS safe-integer ceiling is a real limit here,
  so crossing it is refused instead of writing a line no verifier reads back
  identically.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ._appendlog import AppendLog
from .execution_report import JCS_MAX_SAFE_INTEGER

#: Line schema tag; a future version can coexist in one file.
TENANT_ENTRY_VERSION = "v1"

#: Totals fields that only a ``booking_version=2`` writer records. A book that
#: carries any of them is a v2 book; a settle line without the version in such
#: a book is a stripped line, not a v1.1 line.
_AUDIT_TOTAL_KEYS = frozenset(
    {
        "unknown_charged_runs",
        "unknown_fuel_charged",
        "unknown_output_charged",
        "unknown_output_runs",
        "unknown_wall_charged_ms",
        "unknown_wall_runs",
    }
)

#: Configuration record that binds the host-wide cap to the BOOK, so a second
#: process using the same file cannot run uncapped just by omitting the flags.
_HOST_POLICY_KIND = "host_policy"

CHARGE_FIELDS = ("fuel", "output_bytes", "wall_ms")
_TENANT_ID_CHARS = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-"
)


class TenantId(str):
    """Operator-chosen billing identity, validated on construction.

    A ``str`` subclass on purpose: the value is only ever a label the host
    picked. It must never be read out of guest-visible channels (argv, stdin,
    state, MCP ``params``) and never passed as an env *value* — env values are
    excluded from the policy fingerprint, so an account key living there would
    be invisible to attestation.
    """

    def __new__(cls, value: object) -> TenantId:
        if not isinstance(value, str):
            raise ValueError(f"tenant id must be a string, got {type(value).__name__}")
        if not 1 <= len(value) <= 128:
            raise ValueError("tenant id must be 1..128 characters")
        if value != value.strip() or value[0] == ".":
            raise ValueError(f"tenant id {value!r} has padding or a leading dot")
        bad = sorted({c for c in value if c not in _TENANT_ID_CHARS})
        if bad:
            raise ValueError(
                f"tenant id {value!r} uses characters outside "
                f"[A-Za-z0-9._:-]: {bad}"
            )
        return super().__new__(cls, value)


def _check_charge_values(values: dict[str, int]) -> None:
    for name, value in values.items():
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{name} must be an integer, got {value!r}")
        if value < 0:
            raise ValueError(f"{name} must not be negative: {value}")
        if value > JCS_MAX_SAFE_INTEGER:
            raise ValueError(f"{name} exceeds the JCS safe integer range")


@dataclass(frozen=True)
class Charge:
    """What one run took: guest instructions, host bytes, host wall time."""

    fuel: int = 0
    output_bytes: int = 0
    wall_ms: int = 0

    def __post_init__(self) -> None:
        _check_charge_values(
            {
                "fuel": self.fuel,
                "output_bytes": self.output_bytes,
                "wall_ms": self.wall_ms,
            }
        )

    @classmethod
    def from_line(cls, record: dict[str, Any] | None) -> Charge:
        record = record or {}
        return cls(**{name: int(record.get(name, 0)) for name in CHARGE_FIELDS})

    def plus(self, other: Charge) -> Charge:
        return Charge(
            fuel=self.fuel + other.fuel,
            output_bytes=self.output_bytes + other.output_bytes,
            wall_ms=self.wall_ms + other.wall_ms,
        )

    def to_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in CHARGE_FIELDS}


@dataclass(frozen=True)
class CumulativeBudget:
    """Cross-run caps. ``None`` means the dimension is not capped."""

    max_total_fuel: int | None = None
    max_total_output_bytes: int | None = None
    max_total_wall_ms: int | None = None
    max_runs: int | None = None
    window: str = "all_time"

    def __post_init__(self) -> None:
        if self.window != "all_time":
            raise ValueError(
                f"window {self.window!r} is not implemented — only 'all_time' exists"
            )
        for name, value in (
            ("max_total_fuel", self.max_total_fuel),
            ("max_total_output_bytes", self.max_total_output_bytes),
            ("max_total_wall_ms", self.max_total_wall_ms),
            ("max_runs", self.max_runs),
        ):
            if value is None:
                continue
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer or None")
            if value > JCS_MAX_SAFE_INTEGER:
                raise ValueError(f"{name} exceeds the JCS safe integer range")

    def violation(self, runs: int, used: Charge) -> str | None:
        """First dimension over cap, given runs and used/reserved units."""
        limits = (
            ("fuel", self.max_total_fuel, used.fuel),
            ("output_bytes", self.max_total_output_bytes, used.output_bytes),
            ("wall_ms", self.max_total_wall_ms, used.wall_ms),
            ("runs", self.max_runs, runs),
        )
        for name, cap, value in limits:
            if cap is not None and value > cap:
                return name
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_total_fuel": self.max_total_fuel,
            "max_total_output_bytes": self.max_total_output_bytes,
            "max_total_wall_ms": self.max_total_wall_ms,
            "max_runs": self.max_runs,
            "window": self.window,
        }

    def ref(self) -> str:
        """Short stable reference for attestation (not the whole object)."""
        payload = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class TenantUsage:
    """One tenant's state at one moment, derived by replaying the file."""

    tenant: str
    runs: int = 0
    charged: Charge = Charge()
    reserved: Charge = Charge()
    inflight: int = 0
    violations: int = 0
    refused: int = 0
    unknown_charged_runs: int = 0
    #: Fuel booked conservatively for an attempt whose fuel the host could not
    #: measure. It is part of ``charged.fuel``; the separate counter exists so
    #: an auditor can tell a measured charge from an upper-bound charge.
    unknown_fuel_charged: int = 0
    #: Output bytes booked as an upper bound for attempts whose raw output the
    #: host could not measure. Part of ``charged.output_bytes``.
    unknown_output_charged: int = 0
    unknown_output_runs: int = 0
    #: Wall milliseconds booked as an upper bound for a lease that lapsed
    #: without a settlement. Part of ``charged.wall_ms``.
    unknown_wall_charged_ms: int = 0
    unknown_wall_runs: int = 0
    #: Fuel/output/wall from admissions whose lease lapsed without a settle.
    #: The reservation is converted into a conservative charge instead of
    #: silently disappearing.
    recovered: Charge = Charge()
    recovered_expired_runs: int = 0
    #: A v1.1 book carries settle lines without ``booking_version=2``. Such a
    #: book is readable (so regular stock does not become unreadable), but it
    #: is not writable: new runs require an explicit migration.
    legacy_book: bool = False
    legacy_settles: int = 0
    #: Expired reservations carried over by ``migrate_to`` as conservative
    #: charges. They are already part of ``charged``; the counter stays
    #: separate so an auditor can see where the charge came from.
    legacy_recovered_runs: int = 0

    def projected(self) -> TenantUsage:
        """Settled totals plus recovered leases and open reservations."""
        projected_charge = self.charged.plus(self.recovered).plus(self.reserved)
        return TenantUsage(
            tenant=self.tenant,
            runs=self.runs + self.inflight,
            charged=projected_charge,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant": self.tenant,
            "runs": self.runs,
            "charged": self.charged.to_dict(),
            "reserved": self.reserved.to_dict(),
            "inflight": self.inflight,
            "violations": self.violations,
            "refused": self.refused,
            "unknown_charged_runs": self.unknown_charged_runs,
            "unknown_fuel_charged": self.unknown_fuel_charged,
            "unknown_output_charged": self.unknown_output_charged,
            "unknown_output_runs": self.unknown_output_runs,
            "unknown_wall_charged_ms": self.unknown_wall_charged_ms,
            "unknown_wall_runs": self.unknown_wall_runs,
            "recovered": self.recovered.to_dict(),
            "recovered_expired_runs": self.recovered_expired_runs,
            "legacy_book": self.legacy_book,
            "legacy_settles": self.legacy_settles,
            "legacy_recovered_runs": self.legacy_recovered_runs,
        }


@dataclass(frozen=True)
class Admission:
    """The answer to "may this run start".

    ``projected`` is the account as it would stand if the answer were yes
    (settled + open reservations + this reservation). For a refusal it is the
    account as it stands now — the reservation was never taken, so it is not
    shown as if it had been.
    """

    allowed: bool
    reason: str
    tenant: str
    admit_id: str | None = None
    reserve: Charge = Charge()
    projected: TenantUsage | None = None
    #: Which cap the refusal hit (``fuel`` / ``output_bytes`` / ``wall_ms`` /
    #: ``runs``), so a transport layer can report it without parsing prose.
    limit: str | None = None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _stamp(moment: datetime) -> str:
    return moment.isoformat(timespec="milliseconds")


class TenantStore:
    """Append-only tenant book: admit, settle, refuse, expire.

    Same single-writer discipline as the execution ledger (both use
    :class:`~ephemora_cell._appendlog.AppendLog`): the read-that-decides and the
    write happen inside one exclusive lock, because two threads that each read
    "there is room" would otherwise spend the same budget twice.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._log = AppendLog(path)

    # ---- host-wide policy binding ----

    def host_policy(self) -> tuple[int | None, int | None] | None:
        """The host-wide cap recorded in the book, or ``None`` if none was."""
        replay = _Replay(_now())
        for record in self.entries(None):
            if record.get("kind") == _HOST_POLICY_KIND:
                replay.fold(record, self.path)
        return replay.host_policy

    def bind_host_budget(
        self, budget: CumulativeBudget | None
    ) -> CumulativeBudget | None:
        """Record the host-wide cap in the book; first writer wins.

        Returns the cap this process must use: the recorded one when no cap was
        passed, the stricter of both when one was. A cap that would exceed the
        recorded one is refused — once a cap is declared, the BOOK is the
        authority, not the flags a later process happens to carry.
        """
        if budget is None:
            return self._effective_host_budget(None)
        if budget.max_runs is None and budget.max_total_fuel is None:
            return budget

        def decide(last: bytes | None) -> tuple[CumulativeBudget | None, bytes]:
            recorded = self.host_policy()
            if recorded is not None:
                return self._effective_host_budget(budget), b""
            if self._legacy_settles_present():
                raise ValueError(
                    f"legacy_book: {self.path} carries pre-1.2 settle lines; "
                    "migrate it with 'ephemora tenant migrate' before binding "
                    "a host budget"
                )
            record = _line(
                kind=_HOST_POLICY_KIND,
                at=_now(),
                max_runs=budget.max_runs,
                max_total_fuel=budget.max_total_fuel,
            )
            return budget, _encode(record)

        effective, _ = self._log.decide_and_append(decide)
        return effective

    def _effective_host_budget(
        self, budget: CumulativeBudget | None
    ) -> CumulativeBudget | None:
        recorded = self.host_policy()
        if recorded is None:
            return budget
        recorded_runs, recorded_fuel = recorded
        if budget is None:
            return CumulativeBudget(
                max_runs=recorded_runs, max_total_fuel=recorded_fuel
            )
        for name, given, cap in (
            ("runs", budget.max_runs, recorded_runs),
            ("fuel", budget.max_total_fuel, recorded_fuel),
        ):
            if cap is not None and given is not None and given > cap:
                raise ValueError(
                    f"host cap {name}={given} exceeds the cap {cap} recorded in "
                    f"{self.path}; lower the flag or use a new book"
                )
        return CumulativeBudget(
            max_runs=_stricter(budget.max_runs, recorded_runs),
            max_total_fuel=_stricter(budget.max_total_fuel, recorded_fuel),
            max_total_output_bytes=budget.max_total_output_bytes,
            max_total_wall_ms=budget.max_total_wall_ms,
        )

    # ---- writing ----

    def admit(
        self,
        tenant: TenantId | str,
        *,
        reserve: Charge,
        budget: CumulativeBudget | None = None,
        host_budget: CumulativeBudget | None = None,
        ttl_seconds: float = 900.0,
    ) -> Admission:
        """Reserve a run's worst-case footprint, or refuse it.

        ``reserve`` should be the per-run ceiling the caller is about to enforce
        anyway (``config.max_fuel``, the output cap, the wall clock), so the
        reservation cannot be padded: it is the same number the sandbox stops at.
        ``budget=None`` means pure accounting — record the reservation, never
        refuse. ``host_budget`` caps the WHOLE book across every tenant, so a
        caller choosing a fresh ``--tenant`` cannot spend a fresh budget; it is
        checked before, and independently of, the per-tenant ``budget``. The cap
        RECORDED in the book (``bind_host_budget``) binds every process using
        it: ``host_budget`` may tighten it, never lift it. Recording happens
        through ``bind_host_budget`` — the CLI, the MCP server and
        ``WASISandbox.run`` call it; a direct ``admit`` caller that wants the
        cap shared across processes must call it too.
        """
        name = TenantId(str(tenant))
        if not isinstance(reserve, Charge):
            raise TypeError(f"reserve must be a Charge, got {type(reserve).__name__}")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        budget_ref = budget.ref() if budget else None

        def decide(last: bytes | None) -> tuple[Admission, bytes]:
            clock = _now()
            if self._legacy_settles_present():
                return (
                    Admission(
                        allowed=False,
                        reason=(
                            f"legacy_book: {self.path} carries pre-1.2 settle "
                            "lines; migrate it with 'ephemora tenant migrate' "
                            "before admitting new runs"
                        ),
                        tenant=name,
                        projected=self._replay(
                            name, now=clock, allow_legacy=True
                        ).usage(name),
                    ),
                    b"",
                )
            state = self._replay(name, now=clock)
            balance = state.usage(name).projected()
            # The cap recorded IN THE BOOK binds every process using it, even
            # one started without --host-max-* (v1.2/F1). A process may pass
            # a stricter cap, never a looser one.
            effective_host = self._effective_host_budget(host_budget)
            host_budget_ref = effective_host.ref() if effective_host else None
            # The cap is compared against the account INCLUDING this run, so a
            # cap of N admits N runs and not N+1.
            prospective = TenantUsage(
                tenant=name,
                runs=balance.runs + 1,
                charged=balance.charged.plus(reserve),
            )
            # Host-wide cap first: the WHOLE book, not this tenant. A caller
            # choosing a fresh --tenant must not get a fresh budget.
            if effective_host is not None:
                host_runs, host_charged = self._host_projected(now=clock)
                host_limit = effective_host.violation(
                    host_runs + 1, host_charged.plus(reserve)
                )
                if host_limit is not None:
                    refusal = Admission(
                        allowed=False,
                        reason=f"host budget exhausted: {host_limit}",
                        tenant=name,
                        projected=balance,
                        limit=host_limit,
                    )
                    return refusal, _encode(
                        state.sealed(
                            _line(
                                kind="refuse",
                                tenant=name,
                                at=clock,
                                reason=refusal.reason,
                                budget_ref=host_budget_ref,
                            ),
                            self.path,
                        )
                    )
            limit = (
                budget.violation(prospective.runs, prospective.charged)
                if budget
                else None
            )
            if limit is not None:
                refusal = Admission(
                    allowed=False,
                    reason=f"budget exhausted: {limit}",
                    tenant=name,
                    projected=balance,
                    limit=limit,
                )
                return refusal, _encode(
                    state.sealed(
                        _line(
                            kind="refuse",
                            tenant=name,
                            at=clock,
                            reason=refusal.reason,
                            budget_ref=budget_ref,
                        ),
                        self.path,
                    )
                )
            admit_id = uuid.uuid4().hex
            approval = Admission(
                allowed=True,
                reason="ok",
                tenant=name,
                admit_id=admit_id,
                reserve=reserve,
                projected=prospective,
            )
            return approval, _encode(
                state.sealed(
                    _line(
                        kind="admit",
                        tenant=name,
                        at=clock,
                        admit_id=admit_id,
                        expires_at=clock + timedelta(seconds=ttl_seconds),
                        charge=reserve.to_dict(),
                        budget_ref=budget_ref,
                    ),
                    self.path,
                )
            )

        admission, _ = self._log.decide_and_append(decide)
        return admission

    def settle(
        self,
        tenant: TenantId | str,
        admit_id: str,
        *,
        charge: Charge,
        violation: bool = False,
        unknown: bool = False,
        unknown_fuel_charged: int = 0,
        unknown_output: bool = False,
        unknown_output_charged: int = 0,
        unknown_wall: bool = False,
        unknown_wall_charged_ms: int = 0,
    ) -> dict[str, Any]:
        """Book the measured consumption of one admitted run.

        ``unknown=True`` is the crashed-worker case: the host has wall time but
        no fuel figure. Such an attempt must not become a proven zero.
        ``unknown_fuel_charged`` is the upper-bound fuel booked into
        ``charge.fuel`` for that unknown attempt; the measured and conservative
        parts remain distinguishable in the settle line. The value may never
        exceed the admission's fuel reservation.

        ``unknown_output_charged`` and ``unknown_wall_charged_ms`` are the same
        idea for the other two dimensions. They are part of the authoritative
        ``charge`` (not a side note) and are bounded by both the admission's
        reservation and the booked charge. The cumulative audit counters are
        carried in the recorded ``totals`` block, so editing one without
        rewriting the chain is detected.
        """
        name = TenantId(str(tenant))
        if not isinstance(charge, Charge):
            raise TypeError(f"charge must be a Charge, got {type(charge).__name__}")
        for label, value in (
            ("unknown_fuel_charged", unknown_fuel_charged),
            ("unknown_output_charged", unknown_output_charged),
            ("unknown_wall_charged_ms", unknown_wall_charged_ms),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{label} must be a non-negative integer")
        if unknown_fuel_charged and not unknown:
            raise ValueError(
                "unknown_fuel_charged requires unknown=True: an upper-bound "
                "charge is only valid for an unmeasured attempt"
            )
        if unknown_output_charged and not unknown_output:
            raise ValueError(
                "unknown_output_charged requires unknown_output=True: the "
                "audit flag and the conservative amount must name the same fact"
            )
        if unknown_wall_charged_ms and not unknown_wall:
            raise ValueError(
                "unknown_wall_charged_ms requires unknown_wall=True: the audit "
                "flag and the conservative amount must name the same fact"
            )

        def decide(last: bytes | None) -> tuple[dict[str, Any], bytes]:
            if self._legacy_settles_present():
                raise ValueError(
                    f"legacy_book: {self.path} carries pre-1.2 settle lines; "
                    "migrate it with 'ephemora tenant migrate' before booking"
                )
            state = self._replay(name)
            if admit_id not in state.open:
                raise ValueError(
                    f"settle references unknown admission {admit_id!r} for tenant "
                    f"{name!r} — refusing to book an unreserved run"
                )
            reserved = state.open[admit_id][0]
            for field_name, dimension, booked, ceiling in (
                (
                    "unknown_fuel_charged",
                    "fuel",
                    unknown_fuel_charged,
                    reserved.fuel,
                ),
                (
                    "unknown_output_charged",
                    "output_bytes",
                    unknown_output_charged,
                    reserved.output_bytes,
                ),
                (
                    "unknown_wall_charged_ms",
                    "wall_ms",
                    unknown_wall_charged_ms,
                    reserved.wall_ms,
                ),
            ):
                if booked > ceiling:
                    raise ValueError(
                        f"{field_name}={booked} exceeds the admission's "
                        f"{dimension} reservation {ceiling}"
                    )
                if booked > getattr(charge, dimension):
                    raise ValueError(
                        f"{field_name}={booked} exceeds the booked "
                        f"{dimension} charge {getattr(charge, dimension)} — the "
                        "conservative part must be inside the authoritative charge"
                    )
            record = state.sealed(
                _line(
                    kind="settle",
                    tenant=name,
                    at=_now(),
                    admit_id=admit_id,
                    booking_version=2,
                    charge=charge.to_dict(),
                    violation=True if violation else None,
                    unknown=True if unknown else None,
                    unknown_fuel_charged=unknown_fuel_charged or None,
                    unknown_output=True if unknown_output else None,
                    unknown_output_charged=unknown_output_charged or None,
                    unknown_wall=True if unknown_wall else None,
                    unknown_wall_charged_ms=unknown_wall_charged_ms or None,
                ),
                self.path,
            )
            return record, _encode(record)

        record, _ = self._log.decide_and_append(decide)
        return record

    def expire(self, tenant: TenantId | str, admit_id: str) -> dict[str, Any]:
        """Release a reservation whose run never settled (crash, abandoned call)."""
        name = TenantId(str(tenant))

        def decide(last: bytes | None) -> tuple[dict[str, Any], bytes]:
            if self._legacy_settles_present():
                raise ValueError(
                    f"legacy_book: {self.path} carries pre-1.2 settle lines; "
                    "migrate it with 'ephemora tenant migrate' before expiring"
                )
            state = self._replay(name)
            if admit_id not in state.open:
                raise ValueError(
                    f"expire references unknown admission {admit_id!r} for tenant {name!r}"
                )
            record = state.sealed(
                _line(kind="expire", tenant=name, at=_now(), admit_id=admit_id),
                self.path,
            )
            return record, _encode(record)

        record, _ = self._log.decide_and_append(decide)
        return record

    # ---- reading ----

    def usage(
        self, tenant: TenantId | str, *, now: datetime | None = None
    ) -> TenantUsage:
        """Replayed state; expired open admissions no longer reserve.

        A v1.1 book is readable and reports ``legacy_book=True``; it is not
        writable until an explicit ``migrate_to``.
        """
        name = TenantId(str(tenant))
        return self._replay(name, now=now, allow_legacy=True).usage(str(name))

    def entries(self, tenant: TenantId | str | None = None) -> list[dict[str, Any]]:
        """All lines, optionally one tenant. A malformed line raises, never skipped."""
        wanted = str(tenant) if tenant is not None else None
        out: list[dict[str, Any]] = []
        for number, raw in enumerate(self._log.read_lines(), start=1):
            try:
                record = json.loads(raw)
            except ValueError as exc:
                raise ValueError(
                    f"tenant line {number} is not JSON: {self.path}"
                ) from exc
            if wanted is None or record.get("tenant") == wanted:
                out.append(record)
        return out

    def migrate_to(self, new_path: str | Path) -> dict[str, Any]:
        """Write a v2 book that carries a v1.1 book's settled totals forward.

        The old file is never rewritten. The new book starts with one
        ``carryover`` line per tenant, each bound to the old file's SHA-256 and
        to the totals the old book actually held; expired reservations become
        conservative charges, an active reservation refuses the migration (it
        may still be running). After the carryovers, the recorded host policy
        is copied. New admissions and settlements then use ``booking_version=2``
        and the usual audit counters.
        """
        target = Path(new_path)
        if target.exists():
            raise ValueError(f"migration target already exists: {target}")
        if target.resolve() == self.path.resolve():
            raise ValueError("migration target must differ from the legacy book")
        source_digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        now = _now()
        carry: list[tuple[TenantId, dict[str, Any]]] = []
        legacy_found = False
        for tenant in self._distinct_tenants():
            state = self._replay(tenant, now=now, allow_legacy=True)
            recovered = state.recovered()
            recovered_runs = state.recovered_expired_runs()
            has_usage = bool(
                state.runs
                or state.charged != Charge()
                or recovered != Charge()
                or state.violations
                or state.refused
                or state.legacy_settles
            )
            if state.legacy_settles:
                legacy_found = True
            if not has_usage:
                continue
            if state.inflight():
                raise ValueError(
                    f"tenant {tenant} still has {state.inflight()} active "
                    "reservation(s); settle or expire them before migrating"
                )
            carry.append(
                (
                    tenant,
                    {
                        "runs": state.runs + recovered_runs,
                        "charge": state.charged.plus(recovered),
                        "recovered_runs": recovered_runs,
                        "violations": state.violations,
                        "refused": state.refused,
                        "unknown_charged_runs": state.unknown_charged_runs,
                        "unknown_fuel_charged": state.unknown_fuel_charged,
                        "unknown_output_charged": state.unknown_output_charged,
                        "unknown_output_runs": state.unknown_output_runs,
                        "unknown_wall_charged_ms": state.unknown_wall_charged_ms,
                        "unknown_wall_runs": state.unknown_wall_runs,
                        "legacy_settles": state.legacy_settles,
                    },
                )
            )
        if not legacy_found or not carry:
            raise ValueError(
                f"{self.path} has no pre-1.2 settle lines; nothing to migrate"
            )
        policy = self.host_policy()
        tmp = target.with_name(f".{target.name}.migrate-{uuid.uuid4().hex}")
        log = AppendLog(tmp)

        def decide(last: bytes | None) -> tuple[dict[str, Any], bytes]:
            if last is not None:
                raise ValueError(f"migration target was written concurrently: {target}")
            payloads = []
            for tenant, values in carry:
                record = _line(
                    kind="carryover",
                    tenant=str(tenant),
                    at=now,
                    booking_version=2,
                    legacy_sha256=source_digest,
                    runs=values["runs"],
                    charge=values["charge"].to_dict(),
                    recovered_runs=values["recovered_runs"],
                    violations=values["violations"],
                    refused=values["refused"],
                    unknown_charged_runs=values["unknown_charged_runs"],
                    unknown_fuel_charged=values["unknown_fuel_charged"],
                    unknown_output_charged=values["unknown_output_charged"],
                    unknown_output_runs=values["unknown_output_runs"],
                    unknown_wall_charged_ms=values["unknown_wall_charged_ms"],
                    unknown_wall_runs=values["unknown_wall_runs"],
                    legacy_settles=values["legacy_settles"],
                )
                payloads.append(_encode(_Replay(now).sealed(record, target)))
            if policy is not None:
                payloads.append(
                    _encode(
                        _line(
                            kind=_HOST_POLICY_KIND,
                            at=now,
                            max_runs=policy[0],
                            max_total_fuel=policy[1],
                        )
                    )
                )
            return {}, b"".join(payloads)

        try:
            log.decide_and_append(decide)
            migrated = TenantStore(tmp)
            for tenant, values in carry:
                usage = migrated.usage(tenant)
                if usage.legacy_book or usage.runs != values["runs"]:
                    raise ValueError(
                        f"migration verification failed for tenant {tenant}: "
                        f"runs {usage.runs} != {values['runs']}"
                    )
                if usage.charged != values["charge"]:
                    raise ValueError(
                        f"migration verification failed for tenant {tenant}: "
                        f"charge {usage.charged} != {values['charge']}"
                    )
            # Publish without ever replacing a file that appeared in the
            # meantime: link(2) fails with EEXIST instead of overwriting.
            os.link(tmp, target)
        except FileExistsError as exc:
            raise ValueError(f"migration target already exists: {target}") from exc
        finally:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
        return {
            "source": str(self.path),
            "target": str(target),
            "source_sha256": source_digest,
            "tenants": [
                {
                    "tenant": str(tenant),
                    "runs": values["runs"],
                    "charge": values["charge"].to_dict(),
                    "recovered_runs": values["recovered_runs"],
                    "legacy_settles": values["legacy_settles"],
                }
                for tenant, values in carry
            ],
            "host_policy": (
                {"max_runs": policy[0], "max_total_fuel": policy[1]}
                if policy is not None
                else None
            ),
        }

    def _legacy_settles_present(self) -> bool:
        """True if any tenant's lines predate ``booking_version=2``.

        Read-only use is fine; a book carrying one is refused for every new
        admission/settlement until an explicit migration.
        """
        return any(
            self._replay(tenant, allow_legacy=True).legacy_settles
            for tenant in self._distinct_tenants()
        )

    def _replay(
        self,
        tenant: TenantId,
        *,
        now: datetime | None = None,
        allow_legacy: bool = False,
    ) -> _Replay:
        replay = _Replay(now or _now())
        for line in self.entries(tenant):
            replay.apply(line, self.path, allow_legacy=allow_legacy)
        return replay

    def _replay_host(
        self, *, now: datetime | None = None, allow_legacy: bool = False
    ) -> _Replay:
        """Fold every tenant's lines into one aggregate (the host-wide account).

        ``admit_id`` is a uuid, so the open-reservation map does not collide
        across tenants; the aggregate is simply the sum of everything booked
        in this file.
        """
        replay = _Replay(now or _now())
        for line in self.entries(None):
            replay.apply(line, self.path, allow_legacy=allow_legacy)
        return replay

    def _host_projected(self, *, now: datetime | None = None) -> tuple[int, Charge]:
        """Host-wide (settled + reserved) totals, per-tenant-chain verified.

        Each tenant's lines carry their own ``totals`` chain, so folding them
        into one aggregate replay would trip the tamper-evidence check. Instead
        replay each distinct tenant separately (verifying its chain) and sum the
        projected usage — a corrupted line in ANY tenant still raises.
        """
        clock = now or _now()
        runs = 0
        charged = Charge()
        for tenant in self._distinct_tenants():
            projected = (
                self._replay(tenant, now=clock, allow_legacy=True)
                .usage(str(tenant))
                .projected()
            )
            runs += projected.runs
            charged = charged.plus(projected.charged)
        return runs, charged

    def _distinct_tenants(self) -> list[TenantId]:
        seen: list[TenantId] = []
        for record in self.entries(None):
            if record.get("kind") == _HOST_POLICY_KIND:
                continue
            value = record.get("tenant")
            if value is None:
                raise ValueError(
                    f"tenant line kind {record.get('kind')!r} has no tenant label "
                    f"in {self.path} — refusing to aggregate a book that cannot be "
                    "attributed"
                )
            # A malformed label used to be skipped here, which let an edited
            # tenant field drop a settled run out of the host-wide aggregate
            # and silently reset the cap. It raises now.
            tenant = TenantId(value)
            if tenant not in seen:
                seen.append(tenant)
        return seen


def _line(**fields: Any) -> dict[str, Any]:
    """One record's fields, before the derived ``totals`` block is attached.

    A ``datetime`` is stamped here rather than at the call sites, so no caller
    can hand JSON a timestamp object mid-lock.
    """
    record: dict[str, Any] = {"tenant_entry_version": TENANT_ENTRY_VERSION}
    for key, value in fields.items():
        if value is None:
            continue
        record[key] = _stamp(value) if isinstance(value, datetime) else value
    return record


def _encode(record: dict[str, Any]) -> bytes:
    """UTF-8 JSON with sorted keys, so a re-read is byte-stable."""
    return (
        json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )


def _parse_stamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _stricter(first: int | None, second: int | None) -> int | None:
    """The tighter of two caps; ``None`` means that dimension is unbounded."""
    if first is None:
        return second
    if second is None:
        return first
    return min(first, second)


class _Replay:
    """Folds a tenant's lines into state and proves every recorded total.

    Each line carries the state as it must be AFTER that line took effect — the
    same forward-chaining idea the ledger uses for ``prev_hash``. A reader
    replays from the empty book, so editing a booked charge, dropping a line or
    reordering them all shows up as a mismatch rather than as a plausible
    number. What is deliberately NOT in the block is anything time-dependent
    (open reservations, their sizes): those depend on the moment of reading, so
    binding them to a written value would reject honest files.
    """

    def __init__(self, now: datetime) -> None:
        self.now = now
        self.runs = 0
        self.charged = Charge()
        self.violations = 0
        self.refused = 0
        self.unknown_charged_runs = 0
        self.unknown_fuel_charged = 0
        self.unknown_output_charged = 0
        self.unknown_output_runs = 0
        self.unknown_wall_charged_ms = 0
        self.unknown_wall_runs = 0
        self.legacy_settles = 0
        self.legacy_recovered_runs = 0
        #: Set by the one carryover line a migrated book starts with.
        self.carryover = False
        #: True once a line proves this book was written by a v2 writer. A
        #: settle line without ``booking_version=2`` after that is stripped,
        #: not legacy, and must be refused even for reading.
        self.v2_evidence = False
        # (max_runs, max_total_fuel) recorded ONCE in the book; None = no cap.
        self.host_policy: tuple[int | None, int | None] | None = None
        # admit_id -> (reserved charge, expires_at)
        self.open: dict[str, tuple[Charge, datetime | None]] = {}

    def copied(self) -> _Replay:
        clone = _Replay(self.now)
        clone.runs = self.runs
        clone.charged = self.charged
        clone.violations = self.violations
        clone.refused = self.refused
        clone.unknown_charged_runs = self.unknown_charged_runs
        clone.unknown_fuel_charged = self.unknown_fuel_charged
        clone.unknown_output_charged = self.unknown_output_charged
        clone.unknown_output_runs = self.unknown_output_runs
        clone.unknown_wall_charged_ms = self.unknown_wall_charged_ms
        clone.unknown_wall_runs = self.unknown_wall_runs
        clone.legacy_settles = self.legacy_settles
        clone.legacy_recovered_runs = self.legacy_recovered_runs
        clone.carryover = self.carryover
        clone.v2_evidence = self.v2_evidence
        clone.host_policy = self.host_policy
        clone.open = dict(self.open)
        return clone

    # ---- derived views ----

    def active_open(self) -> list[tuple[str, Charge]]:
        return [
            (admit_id, charge)
            for admit_id, (charge, expires) in self.open.items()
            if expires is None or expires > self.now
        ]

    def reserved(self) -> Charge:
        total = Charge()
        for _, charge in self.active_open():
            total = total.plus(charge)
        return total

    def inflight(self) -> int:
        return len(self.active_open())

    def recovered(self) -> Charge:
        """A lapsed lease's whole reservation, kept as a conservative charge.

        An expired admission frees its run slot (a crashed holder must not
        block the host forever) but none of its resource ceilings — fuel,
        output bytes, wall time — is proven unused. The reservation becomes an
        upper-bound charge instead of quietly disappearing. An explicit
        ``expire`` remains the caller's assertion that nothing ran.
        """
        total = Charge()
        for _, (charge, expires) in self.open.items():
            if expires is not None and expires <= self.now:
                total = total.plus(charge)
        return total

    def recovered_expired_runs(self) -> int:
        return sum(
            1
            for _, (_, expires) in self.open.items()
            if expires is not None and expires <= self.now
        )

    def usage(self, tenant: str = "") -> TenantUsage:
        return TenantUsage(
            tenant=tenant,
            runs=self.runs,
            charged=self.charged,
            reserved=self.reserved(),
            inflight=self.inflight(),
            violations=self.violations,
            refused=self.refused,
            unknown_charged_runs=self.unknown_charged_runs,
            unknown_fuel_charged=self.unknown_fuel_charged,
            unknown_output_charged=self.unknown_output_charged,
            unknown_output_runs=self.unknown_output_runs,
            unknown_wall_charged_ms=self.unknown_wall_charged_ms,
            unknown_wall_runs=self.unknown_wall_runs,
            recovered=self.recovered(),
            recovered_expired_runs=self.recovered_expired_runs(),
            legacy_book=self.legacy_settles > 0,
            legacy_settles=self.legacy_settles,
            legacy_recovered_runs=self.legacy_recovered_runs,
        )

    def totals(self) -> dict[str, int]:
        """The settled state as it stands after everything folded so far."""
        return {
            "runs": self.runs,
            "fuel": self.charged.fuel,
            "output_bytes": self.charged.output_bytes,
            "wall_ms": self.charged.wall_ms,
            "violations": self.violations,
            "refused": self.refused,
            "unknown_charged_runs": self.unknown_charged_runs,
            "unknown_fuel_charged": self.unknown_fuel_charged,
            "unknown_output_charged": self.unknown_output_charged,
            "unknown_output_runs": self.unknown_output_runs,
            "unknown_wall_charged_ms": self.unknown_wall_charged_ms,
            "unknown_wall_runs": self.unknown_wall_runs,
        }

    # ---- folding ----

    def sealed(self, line: dict[str, Any], path: Path) -> dict[str, Any]:
        """Return ``line`` with its post-state block attached.

        The writer folds its own draft through the SAME code the reader uses, so
        a line can only be written if the replay accepts it, and the numbers it
        asserts are by construction the numbers a replay derives.
        """
        probe = self.copied()
        probe.fold(line, path)
        return {**line, "totals": probe.totals()}

    def fold(self, line: dict[str, Any], path: Path) -> None:
        """Apply one line, rejecting anything that cannot be interpreted."""
        if line.get("tenant_entry_version") != TENANT_ENTRY_VERSION:
            raise ValueError(f"unknown tenant_entry_version in {path}")
        kind = line.get("kind")
        if kind == "admit":
            self.open[str(line["admit_id"])] = (
                Charge.from_line(line.get("charge")),
                _parse_stamp(line.get("expires_at")),
            )
        elif kind == "settle":
            admit_id = str(line["admit_id"])
            if admit_id not in self.open:
                raise ValueError(
                    f"settle line for unknown admission {admit_id!r} in {path}"
                )
            reserved = self.open[admit_id][0]
            booked = Charge.from_line(line.get("charge"))
            conservative: dict[str, int] = {}
            for field_name, flag_name, dimension in (
                ("unknown_fuel_charged", "unknown", "fuel"),
                ("unknown_output_charged", "unknown_output", "output_bytes"),
                ("unknown_wall_charged_ms", "unknown_wall", "wall_ms"),
            ):
                value = line.get(field_name, 0) or 0
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise ValueError(f"settle line has invalid {field_name} in {path}")
                if value and not line.get(flag_name):
                    raise ValueError(
                        f"settle line carries {field_name} without {flag_name} "
                        f"in {path}"
                    )
                if value > getattr(reserved, dimension):
                    raise ValueError(
                        f"settle line's {field_name}={value} exceeds the "
                        f"admission's {dimension} reservation in {path}"
                    )
                if value > getattr(booked, dimension):
                    raise ValueError(
                        f"settle line's {field_name}={value} exceeds the "
                        f"booked {dimension} charge in {path}"
                    )
                conservative[field_name] = value
            self.charged = self.charged.plus(booked)
            del self.open[admit_id]
            self.runs += 1
            if line.get("violation"):
                self.violations += 1
            if line.get("unknown"):
                self.unknown_charged_runs += 1
            self.unknown_fuel_charged += conservative["unknown_fuel_charged"]
            if line.get("unknown_output"):
                self.unknown_output_runs += 1
            self.unknown_output_charged += conservative["unknown_output_charged"]
            if line.get("unknown_wall"):
                self.unknown_wall_runs += 1
            self.unknown_wall_charged_ms += conservative["unknown_wall_charged_ms"]
        elif kind == "expire":
            self.open.pop(str(line["admit_id"]), None)
        elif kind == "carryover":
            if self.carryover or self.runs or self.charged != Charge() or self.open:
                raise ValueError(
                    f"carryover line is only valid as the first line of an empty "
                    f"tenant account in {path}"
                )
            charge = Charge.from_line(line.get("charge"))
            values = {
                "runs": line.get("runs"),
                "recovered_runs": line.get("recovered_runs", 0),
                "violations": line.get("violations", 0),
                "refused": line.get("refused", 0),
                "unknown_charged_runs": line.get("unknown_charged_runs", 0),
                "unknown_fuel_charged": line.get("unknown_fuel_charged", 0),
                "unknown_output_charged": line.get("unknown_output_charged", 0),
                "unknown_output_runs": line.get("unknown_output_runs", 0),
                "unknown_wall_charged_ms": line.get("unknown_wall_charged_ms", 0),
                "unknown_wall_runs": line.get("unknown_wall_runs", 0),
            }
            for name, value in values.items():
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise ValueError(
                        f"carryover {name} must be a non-negative integer in {path}"
                    )
            self.charged = charge
            self.runs = values["runs"]
            self.legacy_recovered_runs = values["recovered_runs"]
            self.violations = values["violations"]
            self.refused = values["refused"]
            self.unknown_charged_runs = values["unknown_charged_runs"]
            self.unknown_fuel_charged = values["unknown_fuel_charged"]
            self.unknown_output_charged = values["unknown_output_charged"]
            self.unknown_output_runs = values["unknown_output_runs"]
            self.unknown_wall_charged_ms = values["unknown_wall_charged_ms"]
            self.unknown_wall_runs = values["unknown_wall_runs"]
            self.carryover = True
        elif kind == "refuse":
            self.refused += 1
        elif kind == _HOST_POLICY_KIND:
            runs = line.get("max_runs")
            fuel = line.get("max_total_fuel")
            for name, value in (("max_runs", runs), ("max_total_fuel", fuel)):
                if value is None:
                    continue
                if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                    raise ValueError(
                        f"host_policy {name} must be a positive integer or absent "
                        f"in {path}"
                    )
            policy = (runs, fuel)
            if self.host_policy is not None and self.host_policy != policy:
                raise ValueError(
                    f"conflicting host_policy lines in {path}: the book already "
                    f"records {self.host_policy}, refusing {policy}"
                )
            self.host_policy = policy
        else:
            raise ValueError(f"unknown tenant line kind {kind!r} in {path}")

    def apply(
        self, line: dict[str, Any], path: Path, *, allow_legacy: bool = False
    ) -> None:
        """Fold one line of a file under inspection and prove its totals.

        ``allow_legacy`` is for READING a v1.1 book (``usage``, inspection,
        migration): it accepts a settle line without ``booking_version=2``
        and counts it as legacy. Every write decision uses the default and
        refuses such a line, so a legacy book cannot silently accept new
        bookings; an operator must migrate it explicitly.
        """
        kind = line.get("kind")
        version = line.get("booking_version")
        if version not in (None, 1, 2):
            raise ValueError(
                f"unknown booking_version {version!r} in {path} — refusing a "
                "line whose audit fields this reader cannot prove"
            )
        totals_block = line.get("totals")
        carries_v2_totals = isinstance(totals_block, dict) and any(
            key in totals_block for key in _AUDIT_TOTAL_KEYS
        )
        if version == 2 or kind == "carryover" or carries_v2_totals:
            self.v2_evidence = True
        if kind == "settle" and version != 2:
            if not allow_legacy:
                raise ValueError(
                    f"settle line without booking_version=2 in {path} — refusing "
                    "a booking whose audit counters cannot be bound to the "
                    "authoritative entry"
                )
            if self.v2_evidence:
                raise ValueError(
                    f"settle line without booking_version=2 in a book that "
                    f"already carries v2 totals in {path} — the version was "
                    "stripped; refusing to read a tampered booking"
                )
        if kind == "carryover" and version != 2:
            raise ValueError(f"carryover line without booking_version=2 in {path}")
        self.fold(line, path)
        if kind == "settle" and version != 2:
            self.legacy_settles += 1
        if kind == _HOST_POLICY_KIND:
            # A policy line records configuration, not usage: it has no
            # per-tenant totals chain to prove.
            return
        expected = self.totals()
        recorded = line.get("totals") or {}
        if version == 2:
            missing = sorted(key for key in _AUDIT_TOTAL_KEYS if key not in recorded)
            if missing:
                raise ValueError(
                    f"booking_version 2 line lacks audit totals {missing} in "
                    f"{path} — the audit counters are bound to the booking entry"
                )
        for key, value in expected.items():
            if key in _AUDIT_TOTAL_KEYS and version != 2 and key not in recorded:
                # Only non-settle legacy lines may predate the counters; a
                # settle line without version=2 is rejected above.
                continue
            if int(recorded.get(key, -1)) != value:
                raise ValueError(
                    f"tenant line totals do not match the replayed state "
                    f"({line.get('kind')}) in {path} — the file was edited or "
                    "reordered"
                )
