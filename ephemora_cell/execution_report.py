# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Structured ExecutionReport — serializable, machine-readable.

Also provides RFC 8785 (JCS) canonicalization — the deterministic JSON
serialization used by MCP SEP-2787 as the signing input for
attestations and signed execution records — plus SEP-2787-style
sign/verify helpers that stay signer-agnostic (bytes in, bytes out).
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

#: Type tag of the pre-execution attestation payload (ADR-008).
PRE_EXEC_RECORD_TYPE = "ephemora.pre_exec.v1"

#: Default DSSE type URIs for Cell records (ADR-008). Defined before the
#: record classes because they appear as ``to_dsse`` default arguments.
DSSE_TYPE_EXECUTION_REPORT = "https://ephemora.dev/execution-report.v1"
DSSE_TYPE_PRE_EXEC_RECORD = "https://ephemora.dev/pre-execution-record.v1"

#: Schema tag of the replay-binding block inside a signed receipt. The tag is
#: signed *with* the receipt, so a verifier that requires freshness can tell
#: "this receipt predates the evidence field" apart from "this one is forged".
EVIDENCE_SCHEMA = "ephemora-execution-evidence.v1"

#: Clock skew a freshness check tolerates before it calls a receipt from the
#: future a forgery. One minute: enough for an NTP hop, small enough that a
#: deliberately long-lived replay cannot hide behind the skew.
_ISSUED_AT_FUTURE_SKEW_SECONDS = 60.0


def _default_security_baseline() -> dict[str, Any]:
    """Fingerprint of the runtime's security-relevant settings."""
    version: str | None = None
    try:
        from importlib.metadata import version as _pkg_version

        version = _pkg_version("wasmtime")
    except Exception:
        version = None
    if version is None:
        try:
            import wasmtime as _wasmtime

            version = getattr(_wasmtime, "__version__", None)
        except Exception:
            version = None
    return {
        "wasmtime_version": version,
        "memory_limit_bytes": 128 * 1024 * 1024,
        "fuel": 1_000_000,
        "threads_enabled": False,
        "memory64": False,
        "multi_memory": False,
        # GHSA-m63x-6p34-q65x: enforced-off proposals — the engine rejects
        # call_ref/try_table modules, so fuel accounting stays deterministic.
        "function_references_enabled": False,
        "exceptions_enabled": False,
        "gc_enabled": False,
        "tail_calls_enabled": False,
        # WASI 0.3 gate-off: native async rides on stack-switching.
        "stack_switching_enabled": False,
        # Loader posture (see apply_config): module size cap and whether
        # WASI sync calls are permitted.
        "max_wasm_bytes": 32 * 1024 * 1024,
        "allow_fsync": False,
        "preopens": [],
    }


def security_baseline_for(
    config: Any,
    *,
    tenant: str | None = None,
    tenant_budget_ref: str | None = None,
) -> dict[str, Any]:
    """The posture a run carries, read off ITS OWN config.

    Single source for both attestations — the execution receipt
    (``ExecutionReport.apply_config``) and the pre-execution record
    (``PreExecutionRecord.build``). Before this existed the pre-exec record
    took the hardcoded default baseline, so a signed record could certify
    ``allow_fsync: false`` for a run whose config had it on: the two
    attestations of one run could disagree, and the one a verifier sees
    first was the wrong one.

    ``max_wasm_bytes: 0`` means NO cap, which reads like the tightest
    possible limit in a bare number, so the posture carries the flag too.

    ``tenant``/``tenant_budget_ref`` (ADR-012) add their keys ONLY when set:
    an unaccounted run's baseline stays byte-identical to every earlier
    release. With them, a receipt says which account it drained and under
    which cumulative cap — a number no single run's config can show.
    """
    baseline = _default_security_baseline()
    baseline.update(
        {
            "memory_limit_bytes": config.memory_capacity_bytes,
            "fuel": config.max_fuel,
            "memory64": bool(config.memory64),
            "gc_heap_mb": config.max_gc_heap_mb,
            "disk_quota_bytes": config.disk_quota_bytes,
            "io_budget_bytes": config.io_budget_bytes,
            "io_cpu_seconds": config.io_cpu_seconds,
            "max_wasm_bytes": config.max_wasm_bytes,
            "max_wasm_bytes_unlimited": config.max_wasm_bytes == 0,
            "allow_fsync": bool(config.allow_fsync),
            "preopens": list(config.allow_dirs),
        }
    )
    if tenant is not None:
        baseline["tenant"] = str(tenant)
    if tenant_budget_ref is not None:
        baseline["tenant_budget_ref"] = str(tenant_budget_ref)
    return baseline


@dataclass
class ExecutionReport:
    """Structured report from a WASM execution.

    Contains all execution metadata, fuel breakdown, timing,
    and warnings for debugging and monitoring.
    """

    status: str
    exit_code: int
    elapsed_ms: float
    fuel_consumed: int | None = None
    fuel_budget: int | None = None
    memory_mb: float = 0.0
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    warnings: list[str] = field(default_factory=list)
    sandbox_dir: str = ""
    module_path: str = ""
    security_baseline: dict[str, Any] = field(
        default_factory=_default_security_baseline
    )
    # ADR-008 record split: link to the signed pre-execution attestation.
    # None (default) for every plain report — `to_dict()` output is
    # byte-identical to pre-ADR-008 reports unless the caller opts in.
    back_link: dict[str, Any] | None = None
    # ADR-008 replay binding: a per-receipt nonce, its issue time and the tool it
    # answers for. None (default) keeps `to_dict()` byte-identical to an
    # evidence-free report — only the signing path populates it.
    evidence: dict[str, Any] | None = None

    @property
    def fuel_utilization(self) -> float | None:
        """Fraction of fuel budget consumed (0.0-1.0).

        None when either value is unknown. 0.0 is a valid reading
        (no fuel consumed) and stays 0.0 — it must not collapse to None.
        A zero budget with zero consumption is reported as 0.0; a zero
        budget with consumption is reported as 1.0 (fully exhausted).
        """
        if self.fuel_consumed is None or self.fuel_budget is None:
            return None
        if self.fuel_budget <= 0:
            return 1.0 if self.fuel_consumed > 0 else 0.0
        return min(self.fuel_consumed / self.fuel_budget, 1.0)

    @property
    def is_safe(self) -> bool:
        """True if no warnings and execution completed cleanly."""
        return self.status == "success" and len(self.warnings) == 0

    def add_warning(self, warning: str):
        self.warnings.append(warning)

    def apply_config(
        self,
        config: Any,
        *,
        effective_preopens: tuple[str, ...] | None = None,
        tenant: str | None = None,
        tenant_budget_ref: str | None = None,
    ) -> ExecutionReport:
        """Overlay the effective sandbox configuration into the baseline.

        S2: ``preopens`` attests the directories that were ACTUALLY
        preopened for the run (per-ABI: preview1 grants additionally grant
        ``/sandbox``, component runs grant none of that) — not the
        configured ``allow_dirs``, which may contain entries that were
        filtered out or never existed. Pass ``effective_preopens`` from the
        execution result; when no run result is available, the configured
        ``allow_dirs`` are reported as configured, without claiming grants
        only a live run can attest.

        ``tenant``/``tenant_budget_ref`` are read from the result for the same
        reason (ADR-012): the run, not the caller, decides whether it was
        billed. Passing neither leaves both keys absent, so records of
        unaccounted runs keep the exact bytes they had before this existed.
        """
        baseline = self.security_baseline
        baseline.update(
            security_baseline_for(
                config, tenant=tenant, tenant_budget_ref=tenant_budget_ref
            )
        )
        # Engine posture keys are enforced by the runtime, not chosen by the
        # config, so they stay as the default sets them (threads, multi-memory
        # and the enforced-off proposals).
        baseline["threads_enabled"] = False
        baseline["multi_memory"] = False
        baseline["function_references_enabled"] = False
        baseline["exceptions_enabled"] = False
        baseline["gc_enabled"] = False
        baseline["tail_calls_enabled"] = False
        baseline["stack_switching_enabled"] = False
        if effective_preopens is not None:
            baseline["preopens"] = list(effective_preopens)
        return self

    def to_dict(self) -> dict[str, Any]:
        out = {
            "status": self.status,
            "exit_code": self.exit_code,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "fuel_consumed": self.fuel_consumed,
            "fuel_budget": self.fuel_budget,
            "fuel_utilization": (
                round(self.fuel_utilization, 4)
                if self.fuel_utilization is not None
                else None
            ),
            "memory_mb": round(self.memory_mb, 2),
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
            "warnings": self.warnings,
            "security_baseline": dict(self.security_baseline),
        }
        if self.back_link is not None:
            out["back_link"] = dict(self.back_link)
        if self.evidence is not None:
            out["evidence"] = dict(self.evidence)
        return out

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_jcs(self) -> str:
        """Canonical JSON (RFC 8785 JCS) of the execution record payload.

        Deterministic single-line representation: object keys sorted by
        UTF-16 code units, minimal string escaping, and ES6 number
        formatting. Two reports that are semantically equal serialize to
        identical bytes regardless of key insertion order, which makes
        this the stable signing input for signed execution records.
        """
        return jcs_canonicalize(self.to_dict())

    def sign(self, signer: Callable[[bytes], bytes], *, alg: str = "ES256") -> dict:
        """Return a SEP-2787-style signed execution record.

        The signer is an opaque bytes-in/bytes-out callable (e.g. an
        Ed25519 private-key signer from ``cryptography``) that returns
        the raw signature over the JCS canonical bytes of the record.

        Following SEP-2787 "Tool Call Attestation" conventions:

        * the signing input is the RFC 8785 canonicalization of every
          field EXCEPT ``signature`` (SEP-2787 "Canonical JSON for
          Signing"), including the ``alg`` header so it is covered by
          the signature;
        * the payload stays native JSON — no base64url wrapper (SEP-2787
          "Relationship to JWT" point 1);
        * ``alg`` is a JWS registry identifier (RFC 7518), e.g.
          ``"ES256"``, ``"HS256"``, ``"RS256"`` or ``"EdDSA"``, and MUST
          match the caller-provided signer;
        * ``signature`` is the lowercase hex encoding of the raw
          signature bytes (SEP-2787 Attestation Envelope).

        Returns a JSON-serializable dict: the report payload plus
        ``alg`` and ``signature``.
        """
        if not callable(signer):
            raise TypeError(
                f"signer must be callable bytes->bytes, got {type(signer).__name__}"
            )
        record = dict(self.to_dict())
        record["alg"] = alg
        raw = signer(canonical_bytes(record))
        if not isinstance(raw, (bytes, bytearray)):
            raise TypeError(f"signer must return bytes, got {type(raw).__name__}")
        record["signature"] = bytes(raw).hex()
        return record

    @staticmethod
    def verify(
        signed_record: dict,
        verifier: Callable[[bytes, bytes], bool],
        *,
        expected_alg: str | None = None,
    ) -> bool:
        """Verify a signed record produced by :meth:`sign`.

        The verifier is an opaque bytes-in/bytes-out callable
        ``verifier(canonical_bytes, signature_bytes) -> bool`` (e.g. an
        Ed25519 public-key verify from ``cryptography``).

        Args:
            signed_record: The signed record (payload plus ``alg`` and
                ``signature``).
            verifier: Opaque verification callable.
            expected_alg: When given, the record MUST carry an ``alg``
                field equal to it — a mismatching OR MISSING ``alg``
                returns ``False`` (fail-closed). This pins the verifier to
                the algorithm the signer declared and closes the
                alg-confusion audit finding ("alg-Verwechslung möglich"):
                without the pin, a record signed under a different
                algorithm than the verifier's key verifies whenever the
                raw signature happens to fit. ``None`` (default) keeps the
                legacy behavior (``alg`` is covered by the signature but
                not checked here).

        Fails closed: any malformed input (missing signature field,
        non-hex signature, non-JSON payload, integer beyond the JCS safe
        range, verifier exception) returns ``False``.
        """
        if not isinstance(signed_record, dict) or not callable(verifier):
            return False
        if expected_alg is not None and signed_record.get("alg") != expected_alg:
            return False
        try:
            signature_hex = signed_record["signature"]
        except (KeyError, TypeError):
            return False
        payload = {k: v for k, v in signed_record.items() if k != "signature"}
        try:
            signature = bytes.fromhex(signature_hex)
            canonical = canonical_bytes(payload)
        except (TypeError, ValueError):
            return False
        try:
            return bool(verifier(canonical, signature))
        except Exception:
            return False

    def to_dsse(
        self,
        signer: Callable[[bytes], bytes],
        *,
        type_uri: str = DSSE_TYPE_EXECUTION_REPORT,
        alg: str = "ES256",
        key_id: str | None = None,
    ) -> dict[str, Any]:
        """DSSE v1 envelope over this record's JCS payload (ADR-008).

        Interoperable with the in-toto/TUF ecosystem: the signature is
        over the DSSE PAE, verification goes through :func:`dsse_verify`.
        """
        return dsse_sign(
            canonical_bytes(self.to_dict()),
            payload_type=type_uri,
            signer=signer,
            alg=alg,
            key_id=key_id,
        )

    def summary(self) -> str:
        lines = [
            f"Status: {self.status}",
            f"Time: {self.elapsed_ms:.2f}ms",
            (
                f"Fuel: {self.fuel_consumed:,}/{self.fuel_budget:,}"
                if self.fuel_consumed is not None
                else "Fuel: unlimited"
            ),
            f"Memory: {self.memory_mb:.1f} MB",
        ]
        if self.warnings:
            lines.append(f"Warnings ({len(self.warnings)}):")
            for w in self.warnings:
                lines.append(f"  ⚠️  {w}")
        return "\n".join(lines)


def policy_fingerprint(
    config: Any,
    *,
    tenant: str | None = None,
    tenant_budget_ref: str | None = None,
) -> str:
    """SHA-256 over the JCS of the security-relevant policy (ADR-008).

    Deliberately broader than the engine-pool cache fingerprint: this is
    the PRE-EXECUTION attestation of the policy a run carries, covering
    every wall the guest experiences. ``allow_env`` contributes its NAMES
    only — values are secrets, not policy.

    ``tenant``/``tenant_budget_ref`` (ADR-012) join the digest only when
    given. Without them two runs that drained different accounts from the
    same cumulative cap fingerprinted identically, and an agreement made
    against one account would have been usable for the other.
    """

    def _names(pairs: Any) -> list:
        return [[pair[0], None] for pair in (pairs or ())]

    policy = {
        "max_memory_mb": getattr(config, "max_memory_mb", None),
        "max_fuel": getattr(config, "max_fuel", None),
        "timeout_seconds": getattr(config, "timeout_seconds", None),
        "memory_capacity_bytes": getattr(config, "memory_capacity_bytes", 0),
        "max_threads": getattr(config, "max_threads", None),
        "memory64": getattr(config, "memory64", False),
        "max_gc_heap_mb": getattr(config, "max_gc_heap_mb", None),
        "disk_quota_bytes": getattr(config, "disk_quota_bytes", None),
        "io_cpu_seconds": getattr(config, "io_cpu_seconds", None),
        # The two posture knobs an operator can move: how big a module a run
        # may load, and whether WASI sync calls are permitted. Without them
        # here, a config with allow_fsync on fingerprinted IDENTICALLY to the
        # closed default — the attestation could not tell the two runs apart.
        "max_wasm_bytes": getattr(config, "max_wasm_bytes", None),
        "allow_fsync": bool(getattr(config, "allow_fsync", False)),
        "io_budget_bytes": getattr(config, "io_budget_bytes", None),
        "allow_env_names": _names(getattr(config, "allow_env", None)),
        "allow_dirs": list(getattr(config, "allow_dirs", ()) or ()),
    }
    if tenant is not None:
        policy["tenant"] = str(tenant)
    if tenant_budget_ref is not None:
        policy["tenant_budget_ref"] = str(tenant_budget_ref)
    return hashlib.sha256(jcs_canonicalize(policy).encode("utf-8")).hexdigest()


def input_digest(args: list[str] | None, stdin_data: str | None) -> str:
    """SHA-256 over the JCS of the guest input (argv + stdin)."""
    payload = jcs_canonicalize({"args": list(args or []), "stdin": stdin_data})
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def module_digest(
    module_path: str | None = None, module_bytes: bytes | None = None
) -> str:
    """Lowercase hex SHA-256 of a module (bytes or streamed file)."""
    if module_bytes is not None:
        return hashlib.sha256(module_bytes).hexdigest()
    if module_path is None:
        raise ValueError("provide module_path or module_bytes")
    digest = hashlib.sha256()
    with open(module_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass
class PreExecutionRecord:
    """Signed pre-execution attestation (ADR-008 record split).

    Signed BEFORE the guest runs and bound to the post-execution receipt
    via the receipt's optional ``back_link`` field: what is about to
    execute (module digest), under which policy (policy fingerprint) and
    with which input (input digest). Same signer-agnostic, JCS-canonical
    signing conventions as :meth:`ExecutionReport.sign` (SEP-2787
    style), so the same keys sign both halves of the chain. The split
    answers the verification-order problem: a verifier can check the
    pre-exec record BEFORE trusting anything the run claims.
    """

    id: str
    timestamp: str
    module_sha256: str
    config_fingerprint: str
    input_hash: str
    security_baseline: dict[str, Any] = field(
        default_factory=_default_security_baseline
    )

    @classmethod
    def build(
        cls,
        *,
        module_path: str | None = None,
        module_bytes: bytes | None = None,
        config: Any = None,
        args: list[str] | None = None,
        stdin_data: str | None = None,
        security_baseline: dict[str, Any] | None = None,
        record_id: str | None = None,
        timestamp: str | None = None,
        tenant: str | None = None,
        tenant_budget_ref: str | None = None,
    ) -> PreExecutionRecord:
        """Assemble a pre-exec record from the run's inputs.

        ``record_id``/``timestamp`` are injectable for deterministic
        tests; production callers let them default (uuid4 hex / UTC ISO).
        ``tenant``/``tenant_budget_ref`` (ADR-012) are attested in BOTH
        halves of the record — the fingerprint and the baseline — and are
        omitted entirely when unset.
        """
        if config is None:
            raise ValueError("config is required")
        return cls(
            id=record_id or uuid.uuid4().hex,
            timestamp=timestamp
            or datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            module_sha256=module_digest(module_path, module_bytes),
            config_fingerprint=policy_fingerprint(
                config, tenant=tenant, tenant_budget_ref=tenant_budget_ref
            ),
            input_hash=input_digest(args, stdin_data),
            security_baseline=dict(
                security_baseline
                or security_baseline_for(
                    config, tenant=tenant, tenant_budget_ref=tenant_budget_ref
                )
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": PRE_EXEC_RECORD_TYPE,
            "id": self.id,
            "timestamp": self.timestamp,
            "module_sha256": self.module_sha256,
            "config_fingerprint": self.config_fingerprint,
            "input_hash": self.input_hash,
            "security_baseline": dict(self.security_baseline),
        }

    def sign(self, signer: Callable[[bytes], bytes], *, alg: str = "ES256") -> dict:
        """SEP-2787-style signed copy (same conventions as
        :meth:`ExecutionReport.sign` — signer-agnostic, JCS input, hex
        signature, ``alg`` covered by the signature)."""
        if not callable(signer):
            raise TypeError(
                f"signer must be callable bytes->bytes, got {type(signer).__name__}"
            )
        record = dict(self.to_dict())
        record["alg"] = alg
        raw = signer(canonical_bytes(record))
        if not isinstance(raw, (bytes, bytearray)):
            raise TypeError(f"signer must return bytes, got {type(raw).__name__}")
        record["signature"] = bytes(raw).hex()
        return record

    @staticmethod
    def verify(
        signed_record: Any,
        verifier: Callable[[bytes, bytes], bool],
        *,
        expected_alg: str | None = None,
    ) -> bool:
        """Fail-closed verification (same contract as
        :meth:`ExecutionReport.verify`).

        With ``expected_alg``, the record must carry an ``alg`` field equal
        to it — mismatching or missing ``alg`` returns ``False``
        (fail-closed alg pinning; closes the alg-confusion audit finding).
        ``None`` (default) keeps the legacy behavior.
        """
        if not isinstance(signed_record, dict) or not callable(verifier):
            return False
        if expected_alg is not None and signed_record.get("alg") != expected_alg:
            return False
        try:
            signature_hex = signed_record["signature"]
        except (KeyError, TypeError):
            return False
        payload = {k: v for k, v in signed_record.items() if k != "signature"}
        try:
            signature = bytes.fromhex(signature_hex)
            canonical = canonical_bytes(payload)
        except (TypeError, ValueError):
            return False
        try:
            return bool(verifier(canonical, signature))
        except Exception:
            return False

    def to_dsse(
        self,
        signer: Callable[[bytes], bytes],
        *,
        type_uri: str = DSSE_TYPE_PRE_EXEC_RECORD,
        alg: str = "ES256",
        key_id: str | None = None,
    ) -> dict[str, Any]:
        """DSSE v1 envelope over this record's JCS payload (ADR-008)."""
        return dsse_sign(
            canonical_bytes(self.to_dict()),
            payload_type=type_uri,
            signer=signer,
            alg=alg,
            key_id=key_id,
        )


def verify_chain(
    signed_pre_exec: Any,
    signed_receipt: Any,
    verifier: Callable[[bytes, bytes], bool],
) -> bool:
    """Verify the pre-exec → receipt chain (ADR-008).

    Both halves must verify with the SAME verifier, and the receipt's
    ``back_link`` must reference the pre-exec record id AND the digest of
    its canonical payload — the receipt is bound to exactly this
    pre-exec attestation, not merely to *a* pre-exec attestation. Fails
    closed on every malformed input.
    """
    if not PreExecutionRecord.verify(signed_pre_exec, verifier):
        return False
    if not ExecutionReport.verify(signed_receipt, verifier):
        return False
    back_link = signed_receipt.get("back_link")
    if not isinstance(back_link, dict):
        return False
    pre_payload = {k: v for k, v in signed_pre_exec.items() if k != "signature"}
    try:
        digest = hashlib.sha256(canonical_bytes(pre_payload)).hexdigest()
    except (TypeError, ValueError):
        return False
    return (
        back_link.get("pre_exec_id") == signed_pre_exec.get("id")
        and back_link.get("pre_exec_digest") == digest
    )


_SURROGATE_MIN = 0xD800
_SURROGATE_MAX = 0xDFFF

#: Largest JSON integer every JCS consumer must read identically. JSON has
#: no integer type: a Rust/JS verifier parses numbers as IEEE-754 doubles,
#: so any int beyond ±(2^53 - 1) round-trips to a DIFFERENT value there and
#: the canonical bytes (hence signatures) disagree (CELL-TODO P2).
JCS_MAX_SAFE_INTEGER = 2**53 - 1


def _jcs_number(v: int | float) -> str:
    """Serialize a JSON number per RFC 8785 §3.2.2.3 / ES6 Number::toString.

    Integers print as plain decimal digits — but only within the JCS safe
    range: ints strictly beyond ±(2**53 - 1) raise ``ValueError``
    (fail-closed). Third-party verifiers (Rust/JS) parse JSON numbers as
    IEEE-754 doubles and would read those ints back differently, so signed
    records must not contain them (the ``sign()``/``verify()`` callers
    turn this into sign-time rejection / verify-time ``False``).
    Floats use the shortest round-trip decimal digits, laid out per
    ECMA-262 7.1.12.1: decimal notation when -6 < n <= 21 (n =
    integer-part digit count), otherwise exponent notation with a
    one-digit mantissa head and a sign-bearing exponent. IEEE-754
    NaN/Infinity are not valid JSON and raise TypeError. -0.0 serializes
    as "0". ``bool`` (an int subclass) is handled before this branch and
    serializes as ``true``/``false``.
    """
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        if v > JCS_MAX_SAFE_INTEGER or v < -JCS_MAX_SAFE_INTEGER:
            raise ValueError(
                f"integer value {v} exceeds the JCS safe integer range "
                "(2^53-1); signed records must not contain them "
                "(third-party verifiers would disagree)"
            )
        return str(v)
    if not isinstance(v, float):
        raise TypeError(f"value of type {type(v).__name__} is not a JSON number")
    if math.isnan(v) or math.isinf(v):
        raise TypeError(f"IEEE-754 special value {v!r} has no JSON representation")
    if v == 0.0:
        return "0"
    sign = ""
    if v < 0:
        sign = "-"
        v = -v
    mantissa, sep, exp = repr(v).partition("e")
    e = int(exp) if sep else 0
    if "." in mantissa:
        int_part, frac_part = mantissa.split(".")
    else:
        int_part, frac_part = mantissa, ""
    digits = (int_part + frac_part).lstrip("0")
    stripped = digits.rstrip("0")
    trailing_zeros = len(digits) - len(stripped)
    digits = stripped
    e10 = e - len(frac_part) + trailing_zeros
    n = e10 + len(digits)
    if -6 < n <= 21:
        if n > 0:
            if n >= len(digits):
                out = digits + "0" * (n - len(digits))
            else:
                out = digits[:n] + "." + digits[n:]
        else:
            out = "0." + "0" * (-n) + digits
    else:
        if len(digits) == 1:
            out = digits
        else:
            out = digits[0] + "." + digits[1:]
        exponent = n - 1
        out += "e" + ("+" if exponent >= 0 else "-") + str(abs(exponent))
    return sign + out


def _jcs_string(s: str) -> str:
    """Serialize a JSON string per RFC 8785 §3.2.2.2 (minimal escaping).

    Only ``"``, ``\\`` and U+0000..U+001F are escaped (control characters
    as \\b \\t \\n \\f \\r or lowercase \\uXXXX); all other code points,
    including non-ASCII, are emitted as-is. Lone surrogates are invalid
    and raise ValueError.
    """
    out = ['"']
    for ch in s:
        o = ord(ch)
        if _SURROGATE_MIN <= o <= _SURROGATE_MAX:
            raise ValueError(f"lone surrogate U+{o:04X} is not valid JSON string data")
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\r":
            out.append("\\r")
        elif o < 0x20:
            out.append(f"\\u{o:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _jcs_object(obj: dict) -> str:
    """Serialize a JSON object per RFC 8785 §3.2.3: keys sorted by
    UTF-16 code units, recursively, values minimal-escaped."""
    for k in obj:
        if not isinstance(k, str):
            raise TypeError(f"JSON object keys must be strings, got {type(k).__name__}")
    items = sorted(
        obj.items(),
        key=lambda kv: kv[0].encode("utf-16-be", "surrogatepass"),
    )
    return "{" + ",".join(_jcs_string(k) + ":" + _jcs_value(v) for k, v in items) + "}"


def _jcs_value(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return _jcs_number(v)
    if isinstance(v, str):
        return _jcs_string(v)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_jcs_value(x) for x in v) + "]"
    if isinstance(v, dict):
        return _jcs_object(v)
    raise TypeError(f"value of type {type(v).__name__} is not JSON-serializable")


def jcs_canonicalize(value: Any) -> str:
    """RFC 8785 (JCS) canonicalization of any JSON-serializable value.

    Raises TypeError for values outside the JSON data model (NaN,
    Infinity, bytes, sets, objects, ...), ValueError for lone surrogates
    inside strings, and ValueError for integers strictly beyond the JCS
    safe range ±(2**53 - 1) — those would serialize differently in
    third-party verifiers (Rust/JS read IEEE-754), so they are rejected
    fail-closed instead of producing disagreeing bytes.
    """
    return _jcs_value(value)


def canonical_bytes(record: Any) -> bytes:
    """JCS-canonical UTF-8 bytes of a record.

    Accepts either a plain JSON-serializable value (dict, list, ...) or
    an :class:`ExecutionReport`, whose :meth:`ExecutionReport.to_dict`
    payload is used. This is the exact byte string that
    :meth:`ExecutionReport.sign` feeds to the signer and that
    :meth:`ExecutionReport.verify` recomputes.

    Raises ValueError (fail-closed) for integers strictly beyond the JCS
    safe range ±(2**53 - 1): :meth:`ExecutionReport.sign` propagates the
    error (a record that cannot be canonicalized is never signed) and
    :meth:`ExecutionReport.verify` returns ``False`` for crafted records
    containing such ints.
    """
    if isinstance(record, ExecutionReport):
        record = record.to_dict()
    return jcs_canonicalize(record).encode("utf-8")


# ---------------------------------------------------------------------------
# Open-standard envelopes (ADR-008): DSSE v1 and detached JWS (RFC 7797).
#
# These are PARALLEL output formats to the SEP-2787-native sign()/verify()
# primitives above (which keep the payload native JSON, no base64url).
# The payload bytes are always the RFC 8785 JCS canonicalization, so a
# payload's digest is the same across all three formats.
# ---------------------------------------------------------------------------


def _b64url(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def _b64url_decode(data: str | bytes) -> bytes:
    if isinstance(data, str):
        data = data.encode("ascii")
    return base64.urlsafe_b64decode(data + b"=" * (-len(data) % 4))


def dsse_pae(payload: bytes, payload_type: str) -> bytes:
    """DSSE v1 Pre-Authentication Encoding.

    ``"DSSEv1" || LE32(len(type)) || type || LE32(len(payload)) || payload``
    — the exact byte string every DSSE consumer (in-toto, TUF ecosystem)
    feeds to its verifier.
    """
    t = payload_type.encode("utf-8")
    return (
        b"DSSEv1"
        + len(t).to_bytes(4, "little")
        + t
        + len(payload).to_bytes(4, "little")
        + payload
    )


def dsse_sign(
    payload: bytes,
    *,
    payload_type: str,
    signer: Callable[[bytes], bytes],
    alg: str = "ES256",
    key_id: str | None = None,
) -> dict[str, Any]:
    """Wrap canonical payload bytes in a DSSE v1 envelope.

    The signer receives the PAE — per DSSE, signatures are over the
    encoded envelope, not the raw payload.
    """
    if not callable(signer):
        raise TypeError(f"signer must be callable, got {type(signer).__name__}")
    raw = signer(dsse_pae(payload, payload_type))
    if not isinstance(raw, (bytes, bytearray)):
        raise TypeError(f"signer must return bytes, got {type(raw).__name__}")
    signature: dict[str, Any] = {
        "alg": alg,
        "sig": base64.b64encode(bytes(raw)).decode("ascii"),
    }
    if key_id is not None:
        signature["keyid"] = key_id
    return {
        "payloadType": payload_type,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [signature],
    }


def dsse_verify(envelope: Any, verifier: Callable[[bytes, bytes], bool]) -> bool:
    """Verify a DSSE v1 envelope. **Fails closed.**

    Per the DSSE spec, ALL listed signatures must verify (an envelope
    with zero signatures is malformed, not valid).
    """
    if not isinstance(envelope, dict) or not callable(verifier):
        return False
    payload_type = envelope.get("payloadType")
    payload_b64 = envelope.get("payload")
    signatures = envelope.get("signatures")
    if (
        not isinstance(payload_type, str)
        or not isinstance(payload_b64, str)
        or not isinstance(signatures, list)
        or not signatures
    ):
        return False
    try:
        payload = base64.b64decode(payload_b64, validate=True)
        pae = dsse_pae(payload, payload_type)
        for sig_entry in signatures:
            if not isinstance(sig_entry, dict) or "sig" not in sig_entry:
                return False
            signature = base64.b64decode(sig_entry["sig"], validate=True)
            if not bool(verifier(pae, signature)):
                return False
    except (KeyError, TypeError, ValueError):
        return False
    return True


def new_execution_evidence(
    *, tool: str | None = None, now: datetime | None = None
) -> dict[str, Any]:
    """Build the replay-binding block for one signed receipt.

    A receipt without a nonce is a statement about a *shape* ("a call of this
    tool ended like this"), not about one *execution* — the same bytes prove any
    call that looked the same. ``report_id`` makes each receipt one-of-one and
    ``issued_at`` makes it ageable, so a caller can refuse a receipt that is
    stale or that it has already seen. The signature covers this block because
    it is part of the payload (see :meth:`ExecutionReport.to_dsse`).

    ``issued_at`` is always an aware UTC timestamp (``+00:00``): a naive stamp
    would be re-readable as local time, which is how a replay gains hours.
    """
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        raise ValueError("issued_at must be an aware datetime (UTC), not naive")
    evidence: dict[str, Any] = {
        "schema": EVIDENCE_SCHEMA,
        "report_id": uuid.uuid4().hex,
        "issued_at": moment.astimezone(timezone.utc).isoformat(),
    }
    if tool is not None:
        # Binding to the tool is what stops a receipt for `echo` being presented
        # as evidence for a call of a different tool.
        evidence["tool"] = tool
    return evidence


def verify_execution_attestation(
    envelope: Any,
    verifier: Callable[[bytes, bytes], bool],
    execution: Any,
    *,
    payload_type: str = DSSE_TYPE_EXECUTION_REPORT,
    max_age_seconds: float | None = None,
    now: datetime | None = None,
) -> bool:
    """Verify a signed receipt against the ``_meta.execution`` it accompanies.

    Not just :func:`dsse_verify`: the signature alone proves nothing about the
    receipt a caller is reading, because a signer could sign one dict and present
    another. This binds the two — the envelope must carry this ``payload_type``,
    its base64 payload must be EXACTLY ``canonical_bytes(execution)``, and the
    DSSE signature over the PAE must verify. All three hold or it returns False
    (fails closed on any malformed input). This is the check a caller runs with
    the host's public key to turn a self-reported ``_meta`` into a verified
    receipt.

    ``max_age_seconds`` adds a freshness requirement on top of the cryptographic
    one: the receipt must carry an :data:`EVIDENCE_SCHEMA` block whose
    ``issued_at`` is within the window (and not more than
    :data:`_ISSUED_AT_FUTURE_SKEW_SECONDS` in the future). A receipt that is
    genuinely signed but months old passes without this argument — which is
    exactly why the nonce exists: it is the caller's job to also refuse a
    ``report_id`` it has already accepted.
    """
    if not isinstance(envelope, dict):
        return False
    if envelope.get("payloadType") != payload_type:
        return False
    payload_b64 = envelope.get("payload")
    if not isinstance(payload_b64, str):
        return False
    try:
        expected = canonical_bytes(execution)
        if base64.b64decode(payload_b64, validate=True) != expected:
            return False
    except (ValueError, TypeError):
        return False
    if not dsse_verify(envelope, verifier):
        return False
    if max_age_seconds is not None:
        if not _issued_at_is_fresh(execution, max_age_seconds, now):
            return False
    return True


def _issued_at_is_fresh(execution: Any, max_age_seconds: float, now: Any) -> bool:
    """Fail-closed freshness check on the signed evidence block."""
    if not isinstance(execution, dict):
        return False
    evidence = execution.get("evidence")
    if not isinstance(evidence, dict):
        return False
    if evidence.get("schema") != EVIDENCE_SCHEMA:
        return False
    if not isinstance(evidence.get("report_id"), str) or not evidence["report_id"]:
        return False
    stamp = evidence.get("issued_at")
    if not isinstance(stamp, str):
        return False
    try:
        issued = datetime.fromisoformat(stamp)
    except ValueError:
        return False
    if issued.tzinfo is None:
        # A naive stamp is not a timestamp, it is a guess about which zone was
        # meant — refuse rather than pick one.
        return False
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        return False
    age = (moment - issued).total_seconds()
    return -_ISSUED_AT_FUTURE_SKEW_SECONDS <= age <= max_age_seconds


def detached_jws_sign(
    payload: dict[str, Any],
    signer: Callable[[bytes], bytes],
    *,
    alg: str = "ES256",
    headers: dict[str, Any] | None = None,
) -> str:
    """Compact detached JWS over the JCS payload (RFC 7797, unencoded).

    The payload is NOT carried in the token: the JWS is
    ``header..signature`` and the verifier must supply the payload
    itself (here: the dict to JCS-canonicalize). Signing input is
    ``ASCII(header) || '.' || payload_bytes`` per RFC 7797 §3.
    """
    if not callable(signer):
        raise TypeError(f"signer must be callable, got {type(signer).__name__}")
    header: dict[str, Any] = {"alg": alg, "b64": False, "crit": ["b64"]}
    if headers:
        header.update(headers)
    header_b64 = _b64url(
        json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    payload_bytes = canonical_bytes(payload)
    raw = signer(header_b64 + b"." + payload_bytes)
    if not isinstance(raw, (bytes, bytearray)):
        raise TypeError(f"signer must return bytes, got {type(raw).__name__}")
    return (header_b64 + b"." + b"." + _b64url(bytes(raw))).decode("ascii")


def detached_jws_verify(
    jws: str,
    payload: dict[str, Any],
    verifier: Callable[[bytes, bytes], bool],
) -> bool:
    """Verify a detached JWS against the SUPPLIED payload. **Fails closed.**"""
    if (
        not isinstance(jws, str)
        or not isinstance(payload, dict)
        or not callable(verifier)
    ):
        return False
    try:
        header_b64, payload_b64, signature_b64 = jws.split(".")
        if payload_b64:
            return False  # detached form carries no payload segment
        header = json.loads(_b64url_decode(header_b64))
        if not isinstance(header, dict):
            return False
        if header.get("b64") is not False or "b64" not in header.get("crit", []):
            return False
        signing_input = header_b64.encode("ascii") + b"." + canonical_bytes(payload)
        signature = _b64url_decode(signature_b64)
    except (ValueError, TypeError):
        return False
    try:
        return bool(verifier(signing_input, signature))
    except Exception:
        return False
