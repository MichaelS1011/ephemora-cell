"""Structured ExecutionReport — serializable, machine-readable.

Also provides RFC 8785 (JCS) canonicalization — the deterministic JSON
serialization used by MCP SEP-2787 as the signing input for
attestations and signed execution records — plus SEP-2787-style
sign/verify helpers that stay signer-agnostic (bytes in, bytes out).
"""

from __future__ import annotations

import json
import math
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


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
        "preopens": [],
    }


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
        self, config: Any, *, effective_preopens: tuple[str, ...] | None = None
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
        """
        baseline = self.security_baseline
        baseline["memory_limit_bytes"] = config.memory_capacity_bytes
        baseline["fuel"] = config.max_fuel
        baseline["threads_enabled"] = False
        baseline["memory64"] = bool(config.memory64)
        baseline["multi_memory"] = False
        baseline["gc_heap_mb"] = config.max_gc_heap_mb
        if effective_preopens is not None:
            baseline["preopens"] = list(effective_preopens)
        else:
            baseline["preopens"] = list(config.allow_dirs)
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
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
    def verify(signed_record: dict, verifier: Callable[[bytes, bytes], bool]) -> bool:
        """Verify a signed record produced by :meth:`sign`.

        The verifier is an opaque bytes-in/bytes-out callable
        ``verifier(canonical_bytes, signature_bytes) -> bool`` (e.g. an
        Ed25519 public-key verify from ``cryptography``).

        Fails closed: any malformed input (missing signature field,
        non-hex signature, non-JSON payload, verifier exception) returns
        ``False``.
        """
        if not isinstance(signed_record, dict) or not callable(verifier):
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


_SURROGATE_MIN = 0xD800
_SURROGATE_MAX = 0xDFFF


def _jcs_number(v: int | float) -> str:
    """Serialize a JSON number per RFC 8785 §3.2.2.3 / ES6 Number::toString.

    Integers print as plain decimal digits. Floats use the shortest
    round-trip decimal digits, laid out per ECMA-262 7.1.12.1:
    decimal notation when -6 < n <= 21 (n = integer-part digit count),
    otherwise exponent notation with a one-digit mantissa head and a
    sign-bearing exponent. IEEE-754 NaN/Infinity are not valid JSON and
    raise TypeError. -0.0 serializes as "0".
    """
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
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
    Infinity, bytes, sets, objects, ...) and ValueError for lone
    surrogates inside strings.
    """
    return _jcs_value(value)


def canonical_bytes(record: Any) -> bytes:
    """JCS-canonical UTF-8 bytes of a record.

    Accepts either a plain JSON-serializable value (dict, list, ...) or
    an :class:`ExecutionReport`, whose :meth:`ExecutionReport.to_dict`
    payload is used. This is the exact byte string that
    :meth:`ExecutionReport.sign` feeds to the signer and that
    :meth:`ExecutionReport.verify` recomputes.
    """
    if isinstance(record, ExecutionReport):
        record = record.to_dict()
    return jcs_canonicalize(record).encode("utf-8")
