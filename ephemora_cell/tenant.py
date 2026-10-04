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
  from the lines; each line also records the totals as they must be AFTER it
  took effect, so a reader can show that a booked charge was edited or that
  lines were reordered — not only that the file was truncated.
* **Integers only.** Sums across runs must not depend on float
  shortest-round-trip forms. The JCS safe-integer ceiling is a real limit here,
  so crossing it is refused instead of writing a line no verifier reads back
  identically.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ._appendlog import AppendLog
from .execution_report import JCS_MAX_SAFE_INTEGER

#: Line schema tag; a future version can coexist in one file.
TENANT_ENTRY_VERSION = "v1"

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

    def projected(self) -> TenantUsage:
        """Settled totals plus everything still reserved by an open admission."""
        return TenantUsage(
            tenant=self.tenant,
            runs=self.runs + self.inflight,
            charged=self.charged.plus(self.reserved),
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

    # ---- writing ----

    def admit(
        self,
        tenant: TenantId | str,
        *,
        reserve: Charge,
        budget: CumulativeBudget | None = None,
        ttl_seconds: float = 900.0,
    ) -> Admission:
        """Reserve a run's worst-case footprint, or refuse it.

        ``reserve`` should be the per-run ceiling the caller is about to enforce
        anyway (``config.max_fuel``, the output cap, the wall clock), so the
        reservation cannot be padded: it is the same number the sandbox stops at.
        ``budget=None`` means pure accounting — record the reservation, never
        refuse.
        """
        name = TenantId(str(tenant))
        if not isinstance(reserve, Charge):
            raise TypeError(f"reserve must be a Charge, got {type(reserve).__name__}")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        budget_ref = budget.ref() if budget else None

        def decide(last: bytes | None) -> tuple[Admission, bytes]:
            clock = _now()
            state = self._replay(name, now=clock)
            balance = state.usage(name).projected()
            # The cap is compared against the account INCLUDING this run, so a
            # cap of N admits N runs and not N+1.
            prospective = TenantUsage(
                tenant=name,
                runs=balance.runs + 1,
                charged=balance.charged.plus(reserve),
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
    ) -> dict[str, Any]:
        """Book the measured consumption of one admitted run.

        ``unknown=True`` is the crashed-worker case: the host has wall time but
        no fuel figure, and that run is counted in ``unknown_charged_runs``
        instead of quietly charging zero fuel.
        """
        name = TenantId(str(tenant))
        if not isinstance(charge, Charge):
            raise TypeError(f"charge must be a Charge, got {type(charge).__name__}")

        def decide(last: bytes | None) -> tuple[dict[str, Any], bytes]:
            state = self._replay(name)
            if admit_id not in state.open:
                raise ValueError(
                    f"settle references unknown admission {admit_id!r} for tenant "
                    f"{name!r} — refusing to book an unreserved run"
                )
            record = state.sealed(
                _line(
                    kind="settle",
                    tenant=name,
                    at=_now(),
                    admit_id=admit_id,
                    charge=charge.to_dict(),
                    violation=True if violation else None,
                    unknown=True if unknown else None,
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
        """Replayed state; expired open admissions no longer reserve."""
        name = TenantId(str(tenant))
        return self._replay(name, now=now).usage(str(name))

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

    def _replay(self, tenant: TenantId, *, now: datetime | None = None) -> _Replay:
        replay = _Replay(now or _now())
        for line in self.entries(tenant):
            replay.apply(line, self.path)
        return replay


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
        # admit_id -> (reserved charge, expires_at)
        self.open: dict[str, tuple[Charge, datetime | None]] = {}

    def copied(self) -> _Replay:
        clone = _Replay(self.now)
        clone.runs = self.runs
        clone.charged = self.charged
        clone.violations = self.violations
        clone.refused = self.refused
        clone.unknown_charged_runs = self.unknown_charged_runs
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
            self.charged = self.charged.plus(Charge.from_line(line.get("charge")))
            del self.open[admit_id]
            self.runs += 1
            if line.get("violation"):
                self.violations += 1
            if line.get("unknown"):
                self.unknown_charged_runs += 1
        elif kind == "expire":
            self.open.pop(str(line["admit_id"]), None)
        elif kind == "refuse":
            self.refused += 1
        else:
            raise ValueError(f"unknown tenant line kind {kind!r} in {path}")

    def apply(self, line: dict[str, Any], path: Path) -> None:
        """Fold one line of a file under inspection and prove its totals."""
        self.fold(line, path)
        expected = self.totals()
        recorded = line.get("totals") or {}
        if any(int(recorded.get(key, -1)) != value for key, value in expected.items()):
            raise ValueError(
                f"tenant line totals do not match the replayed state ({line.get('kind')}) "
                f"in {path} — the file was edited or reordered"
            )
