"""
MCP SEP-2787 signed execution records: JCS (RFC 8785)
canonicalization + sign/verify tests.

Covers:
* RFC 8785 official vectors: the §3.2.2/§3.2.3 canonicalization example,
  the §3.2.4 UTF-8 byte dump, the §3.2.3 UTF-16 code-unit key-sort
  sample, and the Appendix B IEEE-754 number serialization samples.
* JCS determinism and minimal string escaping rules.
* SEP-2787-style sign/verify roundtrip, tamper detection, and a real
  Ed25519 roundtrip when the optional `cryptography` package is present.
"""

from __future__ import annotations

import hashlib
import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import ExecutionReport
from ephemora_cell.execution_report import canonical_bytes, jcs_canonicalize


def _sample_report() -> ExecutionReport:
    return ExecutionReport(
        status="success",
        exit_code=0,
        elapsed_ms=12.345,
        fuel_consumed=1200,
        fuel_budget=1_000_000,
        memory_mb=8.5,
        stdout_bytes=1024,
        stderr_bytes=0,
        warnings=["note"],
        sandbox_dir="/sandbox",
        module_path="guest.wasm",
        security_baseline={
            "wasmtime_version": "47.0.1",
            "memory_limit_bytes": 128 * 1024 * 1024,
            "fuel": 1_000_000,
            "threads_enabled": False,
            "memory64": False,
            "multi_memory": False,
            "preopens": ["/sandbox"],
        },
    )


def _sha256_signer(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _sha256_verifier(canonical: bytes, signature: bytes) -> bool:
    return hashlib.sha256(canonical).digest() == signature


# === RFC 8785 official vectors ===


def test_rfc8785_322_combined_example():
    """RFC 8785 §3.2.2/§3.2.3: the official combined example.

    Input numbers must be re-serialized per ES6 Number::toString
    (shortest round-trip digits, decimal/exponent layout), the string
    minimally escaped, and the object keys sorted.
    """
    document = {
        "numbers": [
            333333333.33333329,
            1e30,
            4.50,
            2e-3,
            0.000000000000000000000000001,
        ],
        "string": "\u20ac$\u000f\u000aA'\u0042\u0022\u005c\\\"/",
        "literals": [None, True, False],
    }
    # The RFC input decodes to:  € $ \x0f \n A ' B " \ \ " /  and the
    # canonical form escapes each of those as \u000f \n \" \\ \\ \".
    serialized_string = "\"\u20ac$\\u000f\\nA'B" + "\\" + '"' + "\\" * 5 + '"' + '/"'
    expected = (
        '{"literals":[null,true,false],'
        '"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
        '"string":' + serialized_string + "}"
    )
    assert jcs_canonicalize(document) == expected


def test_rfc8785_324_utf8_bytes():
    """RFC 8785 §3.2.4: the canonical form as exact UTF-8 bytes."""
    document = {
        "numbers": [
            333333333.33333329,
            1e30,
            4.50,
            2e-3,
            0.000000000000000000000000001,
        ],
        "string": "\u20ac$\u000f\u000aA'\u0042\u0022\u005c\\\"/",
        "literals": [None, True, False],
    }
    expected = bytes.fromhex(
        "7b226c69746572616c73223a5b6e756c6c2c747275652c66616c73655d2c"
        "226e756d62657273223a5b3333333333333333332e333333333333332c31"
        "652b33302c342e352c302e3030322c31652d32375d2c22737472696e6722"
        "3a22e282ac245c75303030665c6e4127425c225c5c5c5c5c222f227d"
    )
    assert canonical_bytes(document) == expected


def test_rfc8785_323_utf16_code_unit_key_sorting():
    """RFC 8785 §3.2.3: object keys sort by UTF-16 code units.

    The emoji (surrogate pair 0xD83D 0xDE00) must sort BEFORE U+FB33
    even though its code point is larger — UTF-8/code-point sorting
    would get this wrong.
    """
    document = {
        "\u20ac": "Euro Sign",
        "\r": "Carriage Return",
        "\ufb33": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "\U0001f600": "Emoji: Grinning Face",
        "\u0080": "Control",
        "\u00f6": "Latin Small Letter O With Diaeresis",
    }
    expected = (
        '{"\\r":"Carriage Return","1":"One",'
        '"\u0080":"Control",'
        '"\u00f6":"Latin Small Letter O With Diaeresis",'
        '"\u20ac":"Euro Sign",'
        '"\U0001f600":"Emoji: Grinning Face",'
        '"\ufb33":"Hebrew Letter Dalet With Dagesh"}'
    )
    assert jcs_canonicalize(document) == expected


_RFC8785_APPENDIX_B = [
    ("0000000000000000", "0"),
    ("8000000000000000", "0"),
    ("0000000000000001", "5e-324"),
    ("8000000000000001", "-5e-324"),
    ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("ffefffffffffffff", "-1.7976931348623157e+308"),
    ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"),
    ("4430000000000000", "295147905179352830000"),
    ("44b52d02c7e14af5", "9.999999999999997e+22"),
    ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"),
    ("444b1ae4d6e2ef4e", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000"),
    ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
    ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"),
    ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"),
    ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"),
    ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
]


@pytest.mark.parametrize("ieee754,expected", _RFC8785_APPENDIX_B)
def test_rfc8785_appendix_b_number_samples(ieee754, expected):
    """RFC 8785 Appendix B: ES6 number serialization for IEEE-754 doubles."""
    value = struct.unpack(">d", bytes.fromhex(ieee754))[0]
    assert jcs_canonicalize(value) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        (1e16, "10000000000000000"),
        (1e-7, "1e-7"),
        (1.2345678901234568e20, "123456789012345680000"),
        (1e21, "1e+21"),
        (0.5, "0.5"),
        (-1.5, "-1.5"),
        (123.0, "123"),
        (-0.0, "0"),
        (9007199254740993.0, "9007199254740992"),
    ],
)
def test_jcs_es6_number_layout_diverges_from_python_repr(value, expected):
    """Python's repr differs from ES6 in layout; JCS must follow ES6."""
    assert jcs_canonicalize(value) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("a\nb", '"a\\nb"'),
        ('"', '"\\""'),
        ("\\", '"\\\\"'),
        ("\x00", '"\\u0000"'),
        ("\x1f", '"\\u001f"'),
        ("\b\t\f\r", '"\\b\\t\\f\\r"'),
        ("\x7f", '"\x7f"'),
        ("\u2028\u2029", '"\u2028\u2029"'),
        ("héllo 中文 🎉", '"héllo 中文 🎉"'),
    ],
)
def test_jcs_minimal_string_escaping(value, expected):
    """RFC 8785 §3.2.2.2: only quote, backslash, and U+0000..U+001F."""
    assert jcs_canonicalize(value) == expected


# === JCS determinism / integration ===


def test_jcs_deterministic_regardless_of_key_insertion_order():
    d1 = {
        "b": 1,
        "a": {"y": [1, 2, {"z": 3}], "x": None},
        "nested": {"deep": {"k": True}},
    }
    d2 = {
        "nested": {"deep": {"k": True}},
        "a": {"x": None, "y": [1, 2, {"z": 3}]},
        "b": 1,
    }
    assert canonical_bytes(d1) == canonical_bytes(d2)


def test_jcs_nested_arrays_and_objects_recursive():
    document = {"outer": [{"b": 2, "a": [3, {"d": 4, "c": 5}]}]}
    assert jcs_canonicalize(document) == '{"outer":[{"a":[3,{"c":5,"d":4}],"b":2}]}'


def test_execution_report_to_jcs_matches_payload_canonicalization():
    report = _sample_report()
    assert report.to_jcs() == jcs_canonicalize(report.to_dict())
    assert canonical_bytes(report) == canonical_bytes(report.to_dict())
    assert canonical_bytes(report).decode("utf-8") == report.to_jcs()


def test_execution_report_to_jcs_is_single_line_and_stable():
    report = _sample_report()
    serialized = report.to_jcs()
    assert "\n" not in serialized
    assert serialized == _sample_report().to_jcs()


@pytest.mark.parametrize(
    "value",
    [float("nan"), float("inf"), float("-inf")],
)
def test_jcs_rejects_ieee_special_values(value):
    with pytest.raises(TypeError):
        jcs_canonicalize({"bad": value})


@pytest.mark.parametrize(
    "value",
    [b"bytes", {1, 2, 3}, object(), {"bad": b"bytes"}, {1: "int-key"}, [object()]],
)
def test_jcs_rejects_non_json_values(value):
    with pytest.raises(TypeError):
        canonical_bytes(value)


def test_jcs_rejects_lone_surrogate():
    with pytest.raises(ValueError):
        jcs_canonicalize({"a": "\ud800"})
    with pytest.raises(ValueError):
        jcs_canonicalize("\udead")


# === SEP-2787 sign / verify ===


def test_sign_returns_sep2787_style_record():
    report = _sample_report()
    signed = report.sign(_sha256_signer, alg="HS256")
    assert isinstance(signed, dict)
    assert signed["alg"] == "HS256"
    assert signed["signature"]
    assert bytes.fromhex(signed["signature"]) == _sha256_signer(
        canonical_bytes(report.to_dict() | {"alg": "HS256"})
    )
    assert set(report.to_dict()) <= set(signed)


def test_sign_deterministic_for_deterministic_signer():
    first = _sample_report().sign(_sha256_signer, alg="HS256")
    second = _sample_report().sign(_sha256_signer, alg="HS256")
    assert first == second


def test_sign_covers_alg_header():
    report = _sample_report()
    signed = report.sign(_sha256_signer, alg="EdDSA")
    tampered_alg = dict(signed)
    tampered_alg["alg"] = "ES256"
    assert not ExecutionReport.verify(tampered_alg, _sha256_verifier)


def test_verify_roundtrip():
    signed = _sample_report().sign(_sha256_signer, alg="HS256")
    assert ExecutionReport.verify(signed, _sha256_verifier)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda s: {**s, "exit_code": 42},
        lambda s: {**s, "status": "errored"},
        lambda s: {**s, "elapsed_ms": 9999.0},
        lambda s: {**s, "warnings": []},
        lambda s: {**s, "security_baseline": {**s["security_baseline"], "fuel": 0}},
    ],
)
def test_tamper_payload_field_fails_verification(mutate):
    signed = _sample_report().sign(_sha256_signer, alg="HS256")
    assert not ExecutionReport.verify(mutate(signed), _sha256_verifier)


def test_tamper_signature_flip_fails_verification():
    signed = _sample_report().sign(_sha256_signer, alg="HS256")
    flipped = "0" if signed["signature"][0] != "0" else "1"
    tampered = {**signed, "signature": flipped + signed["signature"][1:]}
    assert not ExecutionReport.verify(tampered, _sha256_verifier)


def test_resign_different_signer_fails_verification():
    signed = _sample_report().sign(
        lambda data: hashlib.sha256(b"salt" + data).digest(), alg="HS256"
    )
    assert not ExecutionReport.verify(signed, _sha256_verifier)


@pytest.mark.parametrize(
    "signed_record,verifier",
    [
        (None, _sha256_verifier),
        ("not-a-dict", _sha256_verifier),
        ({}, _sha256_verifier),
        ({"signature": "abcd"}, _sha256_verifier),
        ({"signature": "zz"}, _sha256_verifier),
        ({"signature": "00"}, _sha256_verifier),
        ({"signature": "00", "bad_key": object()}, _sha256_verifier),
        ({"signature": "00"}, None),
        ({"signature": "00"}, "not-callable"),
    ],
)
def test_verify_fails_closed_on_malformed_input(signed_record, verifier):
    assert not ExecutionReport.verify(signed_record, verifier)


def test_verify_fails_closed_when_verifier_raises():
    signed = _sample_report().sign(_sha256_signer, alg="HS256")

    def boom(canonical, signature):
        raise RuntimeError("crypto backend failure")

    assert not ExecutionReport.verify(signed, boom)


def test_sign_rejects_non_callable_signer():
    with pytest.raises(TypeError):
        _sample_report().sign("not-a-callable")


def test_sign_rejects_non_bytes_signer_result():
    with pytest.raises(TypeError):
        _sample_report().sign(lambda data: "not-bytes")


def test_ed25519_roundtrip():
    """Real Ed25519 sign/verify via the optional cryptography package."""
    pytest.importorskip("cryptography")
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    def ed25519_verifier(canonical, signature):
        try:
            public_key.verify(signature, canonical)
            return True
        except InvalidSignature:
            return False

    signed = _sample_report().sign(private_key.sign, alg="EdDSA")
    assert signed["alg"] == "EdDSA"
    assert len(bytes.fromhex(signed["signature"])) == 64
    assert ExecutionReport.verify(signed, ed25519_verifier)

    tampered = dict(signed)
    tampered["fuel_consumed"] = 999999
    assert not ExecutionReport.verify(tampered, ed25519_verifier)

    wrong_key = Ed25519PrivateKey.generate().public_key()

    def wrong_key_verifier(canonical, signature):
        try:
            wrong_key.verify(signature, canonical)
            return True
        except InvalidSignature:
            return False

    assert not ExecutionReport.verify(signed, wrong_key_verifier)


class TestFuelUtilizationSemantics:
    """Zero-budget safety and the 0.0 vs None distinction."""

    def test_zero_budget_zero_consumed_is_zero(self):
        report = ExecutionReport(
            status="success",
            exit_code=0,
            elapsed_ms=0.0,
            fuel_consumed=0,
            fuel_budget=0,
        )
        assert report.fuel_utilization == 0.0
        assert report.to_dict()["fuel_utilization"] == 0.0

    def test_zero_budget_with_consumption_is_full(self):
        report = ExecutionReport(
            status="success",
            exit_code=0,
            elapsed_ms=0.0,
            fuel_consumed=10,
            fuel_budget=0,
        )
        assert report.fuel_utilization == 1.0

    def test_clamped_to_one(self):
        report = ExecutionReport(
            status="success",
            exit_code=0,
            elapsed_ms=0.0,
            fuel_consumed=2_000_000,
            fuel_budget=1_000_000,
        )
        assert report.fuel_utilization == 1.0

    def test_zero_consumption_is_not_none(self):
        report = ExecutionReport(
            status="success",
            exit_code=0,
            elapsed_ms=0.0,
            fuel_consumed=0,
            fuel_budget=1_000_000,
        )
        assert report.fuel_utilization == 0.0
        assert report.to_dict()["fuel_utilization"] == 0.0
