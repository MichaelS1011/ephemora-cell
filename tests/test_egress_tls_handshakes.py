"""Real TLS handshakes through the shipped host-side egress mediator.

Unlike the policy/unit tests in ``test_egress_sidecar.py``, every HTTPS leg in
this module drives ``mediate()`` / ``execute_request()`` against a loopback
``HTTPServer`` wrapped in ``ssl.SSLContext(PROTOCOL_TLS_SERVER)``. Nothing is
mocked at the transport layer: the certificate chain is generated with
``cryptography`` into a temp dir, the server presents it, and OpenSSL on the
client side performs verification using the product's real ``_https_context()``
(only ``certifi.where`` is redirected to the test CA bundle).

The synthetic root named ``emSign ECC Root CA - G3`` is clearly a TEST fixture:
it is not the publicly compromised root and its fingerprint does not match the
published one. It exists to prove that the local chain would otherwise verify,
so a failure in the no-injection leg is a trust-anchor refusal, not a malformed
certificate.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import socket
import ssl
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ephemora_cell import egress_sidecar
from ephemora_cell.egress_sidecar import EgressPolicy, mediate

#: Published SHA-256 fingerprint of the REAL compromised root that certifi
#: removed. The synthetic fixture root below deliberately does not match it.
PUBLISHED_G3_SHA256 = "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b"

_NOW = datetime.now(timezone.utc)
_VALID_FROM = _NOW - timedelta(days=1)
_VALID_UNTIL = _NOW + timedelta(days=30)


# ---------------------------------------------------------------------------
# PKI generated locally, once per module, in a temp directory
# ---------------------------------------------------------------------------


def _rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _write_pem(path: Path, *certs: x509.Certificate) -> Path:
    path.write_bytes(
        b"".join(cert.public_bytes(serialization.Encoding.PEM) for cert in certs)
    )
    return path


def _write_key(path: Path, key) -> Path:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return path


def _ca_certificate(
    *,
    subject_cn: str,
    subject_key,
    issuer_name: x509.Name,
    issuer_key,
    path_length: int | None,
    not_before: datetime = _VALID_FROM,
    not_after: datetime = _VALID_UNTIL,
) -> x509.Certificate:
    subject = _name(subject_cn)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()),
            critical=False,
        )
    )
    if issuer_name != subject:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
    return builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())


def _leaf_certificate(
    *,
    subject_cn: str,
    subject_key,
    issuer_cert: x509.Certificate,
    issuer_key,
    sans: list[x509.GeneralName],
    not_before: datetime = _VALID_FROM,
    not_after: datetime = _VALID_UNTIL,
) -> x509.Certificate:
    return (
        x509.CertificateBuilder()
        .subject_name(_name(subject_cn))
        .issuer_name(issuer_cert.subject)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
        .sign(private_key=issuer_key, algorithm=hashes.SHA256())
    )


@dataclass(frozen=True)
class _Pki:
    root_pem: Path
    intermediate_pem: Path
    # leaf + intermediate, as a real server would send
    valid_chain: Path
    valid_key: Path
    # leaf only (the server omits the intermediate)
    leaf_only_chain: Path
    mismatch_chain: Path
    mismatch_key: Path
    expired_chain: Path
    expired_key: Path
    # synthetic, clearly test-only root with the published CN
    synthetic_g3_root_pem: Path
    synthetic_g3_chain: Path
    synthetic_g3_key: Path
    synthetic_g3_fingerprint: str


@pytest.fixture(scope="module")
def pki(tmp_path_factory: pytest.TempPathFactory) -> _Pki:
    """A local root -> intermediate -> leaf PKI, written as PEM files."""
    directory = tmp_path_factory.mktemp("s3-tls-pki")

    root_key = _rsa_key()
    root_cert = _ca_certificate(
        subject_cn="S3 Test Root CA",
        subject_key=root_key,
        issuer_name=_name("S3 Test Root CA"),
        issuer_key=root_key,
        path_length=1,
    )

    intermediate_key = _rsa_key()
    intermediate_cert = _ca_certificate(
        subject_cn="S3 Test Intermediate CA",
        subject_key=intermediate_key,
        issuer_name=root_cert.subject,
        issuer_key=root_key,
        path_length=0,
    )

    leaf_key = _rsa_key()
    valid_leaf = _leaf_certificate(
        subject_cn="127.0.0.1",
        subject_key=leaf_key,
        issuer_cert=intermediate_cert,
        issuer_key=intermediate_key,
        sans=[
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            x509.IPAddress(ipaddress.ip_address("::1")),
        ],
    )

    mismatch_key = _rsa_key()
    mismatch_leaf = _leaf_certificate(
        subject_cn="other.test",
        subject_key=mismatch_key,
        issuer_cert=intermediate_cert,
        issuer_key=intermediate_key,
        sans=[x509.DNSName("other.test")],
    )

    expired_key = _rsa_key()
    expired_leaf = _leaf_certificate(
        subject_cn="127.0.0.1",
        subject_key=expired_key,
        issuer_cert=intermediate_cert,
        issuer_key=intermediate_key,
        sans=[x509.IPAddress(ipaddress.ip_address("127.0.0.1"))],
        not_before=_NOW - timedelta(days=400),
        not_after=_NOW - timedelta(days=30),
    )

    # Synthetic, TEST-ONLY root. Not the real compromised eMudhra root: only
    # the subject CN is borrowed so the trust-anchor path can be driven with a
    # chain that is otherwise valid. The fingerprint is checked to differ.
    synthetic_g3_key = ec.generate_private_key(ec.SECP256R1())
    synthetic_g3_root = _ca_certificate(
        subject_cn="emSign ECC Root CA - G3",
        subject_key=synthetic_g3_key,
        issuer_name=_name("emSign ECC Root CA - G3"),
        issuer_key=synthetic_g3_key,
        path_length=0,
    )
    synthetic_g3_leaf_key = _rsa_key()
    synthetic_g3_leaf = _leaf_certificate(
        subject_cn="127.0.0.1",
        subject_key=synthetic_g3_leaf_key,
        issuer_cert=synthetic_g3_root,
        issuer_key=synthetic_g3_key,
        sans=[x509.IPAddress(ipaddress.ip_address("127.0.0.1"))],
    )

    return _Pki(
        root_pem=_write_pem(directory / "root.pem", root_cert),
        intermediate_pem=_write_pem(directory / "intermediate.pem", intermediate_cert),
        valid_chain=_write_pem(
            directory / "valid-chain.pem", valid_leaf, intermediate_cert
        ),
        valid_key=_write_key(directory / "valid-key.pem", leaf_key),
        leaf_only_chain=_write_pem(directory / "leaf-only.pem", valid_leaf),
        mismatch_chain=_write_pem(
            directory / "mismatch-chain.pem", mismatch_leaf, intermediate_cert
        ),
        mismatch_key=_write_key(directory / "mismatch-key.pem", mismatch_key),
        expired_chain=_write_pem(
            directory / "expired-chain.pem", expired_leaf, intermediate_cert
        ),
        expired_key=_write_key(directory / "expired-key.pem", expired_key),
        synthetic_g3_root_pem=_write_pem(
            directory / "synthetic-g3-root.pem", synthetic_g3_root
        ),
        synthetic_g3_chain=_write_pem(
            directory / "synthetic-g3-chain.pem", synthetic_g3_leaf
        ),
        synthetic_g3_key=_write_key(
            directory / "synthetic-g3-key.pem", synthetic_g3_leaf_key
        ),
        synthetic_g3_fingerprint=synthetic_g3_root.fingerprint(hashes.SHA256()).hex(),
    )


@pytest.fixture(scope="module", autouse=True)
def _require_product_certifi_floor() -> None:
    """The product floor is real; a below-floor environment cannot exercise TLS.

    Without this guard every negative leg would "pass" for the wrong reason:
    ``_https_context()`` refuses before any handshake, so a certificate failure
    would never be observed. Fail loudly instead of accepting that trade.
    """
    installed = egress_sidecar._installed_certifi_version()
    if installed < egress_sidecar._CERTIFI_MIN_VERSION:
        pytest.fail(
            "certifi "
            + ".".join(map(str, installed))
            + " is below the product floor "
            + ".".join(map(str, egress_sidecar._CERTIFI_MIN_VERSION))
            + "; run this module with the locked certifi release"
        )


# ---------------------------------------------------------------------------
# Loopback servers
# ---------------------------------------------------------------------------


class _QuietTlsHTTPServer(HTTPServer):
    """HTTPServer that records failed handshakes instead of printing them."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.handshake_errors: list[str] = []

    def handle_error(self, request, client_address) -> None:
        self.handshake_errors.append(f"{client_address}: handshake/request error")


class _V6HTTPServer(_QuietTlsHTTPServer):
    address_family = socket.AF_INET6


@contextlib.contextmanager
def _serve_tls(chain: Path, key: Path, handler_cls, *, host: str = "127.0.0.1"):
    server_cls = _V6HTTPServer if ":" in host else _QuietTlsHTTPServer
    server = server_cls((host, 0), handler_cls)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(chain), keyfile=str(key))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@contextlib.contextmanager
def _serve_http(handler_cls):
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _json_handler(hits: list[str], payload: dict | None = None):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            body = json.dumps(payload or {"answer": 42}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    return Handler


def _redirect_handler(hits: list[str], location: str):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    return Handler


# ---------------------------------------------------------------------------
# Helpers for driving the shipped product path
# ---------------------------------------------------------------------------


def _endpoint(port: int, host: str = "127.0.0.1") -> str:
    bracket = f"[{host}]" if ":" in host else host
    return f"https://{bracket}:{port}/v1/"


def _mediate_https(policy: EgressPolicy, port: int, *, host: str = "127.0.0.1"):
    bracket = f"[{host}]" if ":" in host else host
    return mediate(
        policy,
        json.dumps({"url": f"https://{bracket}:{port}/v1/data", "method": "GET"}),
    )


def _inject_ca(monkeypatch: pytest.MonkeyPatch, bundle: Path) -> None:
    """Point the product's certifi bundle at our CA, leaving the rest real."""
    monkeypatch.setattr(egress_sidecar.certifi, "where", lambda: str(bundle))


def _assert_transport_refused(result, hits: list[str]) -> None:
    """A failed handshake is audited, delivers nothing, and opens no request."""
    assert result.audit.decision == "allowed", result.audit.reason
    assert (
        result.audit.transport_ok is False
    ), "audit claims delivery although the TLS handshake failed"
    assert result.audit.status is None
    assert result.response_doc["ok"] is False
    assert "content" not in result.response_doc
    assert hits == [], "an HTTP request reached the handler despite a failed handshake"


# ---------------------------------------------------------------------------
# 1. Trusted local CA: a real handshake, a real 200
# ---------------------------------------------------------------------------


def test_trusted_local_ca_handshake_delivers_http_200(pki: _Pki, monkeypatch):
    hits: list[str] = []
    with _serve_tls(pki.valid_chain, pki.valid_key, _json_handler(hits)) as server:
        port = server.server_address[1]
        _inject_ca(monkeypatch, pki.root_pem)
        result = _mediate_https(
            EgressPolicy(allowed_endpoints=(_endpoint(port),)), port
        )

    assert result.audit.decision == "allowed", result.audit.reason
    assert result.audit.transport_ok is True
    assert result.audit.status == 200
    assert result.response_doc["ok"] is True
    assert result.response_doc["status"] == 200
    assert result.response_doc["content"] == {"answer": 42}
    assert hits == ["/v1/data"]


# ---------------------------------------------------------------------------
# 2. Untrusted CA: verification must fail, mediate must not raise
# ---------------------------------------------------------------------------


def test_untrusted_ca_is_refused_by_real_certifi(pki: _Pki):
    hits: list[str] = []
    with _serve_tls(pki.valid_chain, pki.valid_key, _json_handler(hits)) as server:
        port = server.server_address[1]
        # No injection: this is the shipped certifi bundle.
        result = _mediate_https(
            EgressPolicy(allowed_endpoints=(_endpoint(port),)), port
        )

    _assert_transport_refused(result, hits)
    assert "fetch failed" in result.response_doc["error"]
    assert any(
        marker in result.response_doc["error"].lower()
        for marker in ("certificate", "verify", "issuer")
    ), result.response_doc["error"]


# ---------------------------------------------------------------------------
# 3. Hostname mismatch: SAN other.test, URL 127.0.0.1
# ---------------------------------------------------------------------------


def test_hostname_mismatch_is_refused_even_with_trusted_ca(pki: _Pki, monkeypatch):
    hits: list[str] = []
    with _serve_tls(
        pki.mismatch_chain, pki.mismatch_key, _json_handler(hits)
    ) as server:
        port = server.server_address[1]
        _inject_ca(monkeypatch, pki.root_pem)
        result = _mediate_https(
            EgressPolicy(allowed_endpoints=(_endpoint(port),)), port
        )

    _assert_transport_refused(result, hits)
    error = result.response_doc["error"].lower()
    assert any(
        marker in error for marker in ("hostname", "certificate", "verify")
    ), error


# ---------------------------------------------------------------------------
# 4. Expired certificate
# ---------------------------------------------------------------------------


def test_expired_certificate_is_refused(pki: _Pki, monkeypatch):
    hits: list[str] = []
    with _serve_tls(pki.expired_chain, pki.expired_key, _json_handler(hits)) as server:
        port = server.server_address[1]
        _inject_ca(monkeypatch, pki.root_pem)
        result = _mediate_https(
            EgressPolicy(allowed_endpoints=(_endpoint(port),)), port
        )

    _assert_transport_refused(result, hits)
    error = result.response_doc["error"].lower()
    assert any(
        marker in error for marker in ("expired", "certificate", "verify")
    ), error


# ---------------------------------------------------------------------------
# 5. Missing intermediate: server sends leaf only, client trusts root only
# ---------------------------------------------------------------------------


def test_missing_intermediate_is_refused(pki: _Pki, monkeypatch):
    hits: list[str] = []
    with _serve_tls(pki.leaf_only_chain, pki.valid_key, _json_handler(hits)) as server:
        port = server.server_address[1]
        _inject_ca(monkeypatch, pki.root_pem)
        result = _mediate_https(
            EgressPolicy(allowed_endpoints=(_endpoint(port),)), port
        )

    _assert_transport_refused(result, hits)
    error = result.response_doc["error"].lower()
    assert any(
        marker in error
        for marker in ("issuer", "unable to get", "certificate", "verify")
    ), error


# ---------------------------------------------------------------------------
# 6. G3 mutation/control: synthetic root, positive then negative
# ---------------------------------------------------------------------------


def test_synthetic_g3_named_root_verifies_with_injection_only(pki: _Pki, monkeypatch):
    """A chain under a root NAMED like G3 is otherwise valid.

    The synthetic root shares only the subject CN with the compromised public
    root; its key/fingerprint are freshly generated. With it injected the
    handshake must succeed (chain validity control). Without injection the real
    certifi bundle must refuse it. If the first half failed, the second would
    prove nothing about trust anchoring.
    """
    synthetic_root = x509.load_pem_x509_certificate(
        pki.synthetic_g3_root_pem.read_bytes()
    )
    common_names = synthetic_root.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert [attr.value for attr in common_names] == ["emSign ECC Root CA - G3"]
    assert pki.synthetic_g3_fingerprint != PUBLISHED_G3_SHA256
    assert (
        pki.synthetic_g3_fingerprint not in _certifi_bundle_fingerprints()
    ), "the synthetic fixture root unexpectedly appears in the real certifi bundle"

    hits: list[str] = []
    with _serve_tls(
        pki.synthetic_g3_chain, pki.synthetic_g3_key, _json_handler(hits)
    ) as server:
        port = server.server_address[1]
        policy = EgressPolicy(allowed_endpoints=(_endpoint(port),))
        with monkeypatch.context() as patch:
            _inject_ca(patch, pki.synthetic_g3_root_pem)
            trusted = _mediate_https(policy, port)
        untrusted = _mediate_https(policy, port)

    assert trusted.audit.decision == "allowed", trusted.audit.reason
    assert trusted.audit.transport_ok is True
    assert trusted.audit.status == 200
    assert trusted.response_doc["ok"] is True
    assert trusted.response_doc["content"] == {"answer": 42}

    _assert_transport_refused(untrusted, hits[1:])
    error = untrusted.response_doc["error"].lower()
    assert any(marker in error for marker in ("certificate", "verify", "issuer")), error
    assert hits == ["/v1/data"]


def _certifi_bundle_fingerprints() -> set[str]:
    certs = x509.load_pem_x509_certificates(
        Path(egress_sidecar.certifi.where()).read_bytes()
    )
    return {cert.fingerprint(hashes.SHA256()).hex() for cert in certs}


def test_real_certifi_bundle_does_not_contain_published_g3_root(pki: _Pki):
    fingerprints = _certifi_bundle_fingerprints()
    assert PUBLISHED_G3_SHA256 not in fingerprints, (
        "the active certifi bundle still trusts the compromised emSign ECC "
        "Root CA - G3"
    )
    assert pki.synthetic_g3_fingerprint not in fingerprints


# ---------------------------------------------------------------------------
# 7. HTTPS -> HTTP downgrade redirect (opposite direction of the existing test)
# ---------------------------------------------------------------------------


def test_https_to_http_downgrade_redirect_is_refused(pki: _Pki, monkeypatch):
    http_hits: list[str] = []
    tls_hits: list[str] = []
    with _serve_http(_json_handler(http_hits)) as http_server:
        http_port = http_server.server_address[1]
        location = f"http://127.0.0.1:{http_port}/v1/"
        with _serve_tls(
            pki.valid_chain,
            pki.valid_key,
            _redirect_handler(tls_hits, location),
        ) as tls_server:
            tls_port = tls_server.server_address[1]
            policy = EgressPolicy(
                allowed_endpoints=(
                    _endpoint(tls_port),
                    f"http://127.0.0.1:{http_port}/v1/",
                )
            )
            _inject_ca(monkeypatch, pki.root_pem)
            result = _mediate_https(policy, tls_port)

    assert tls_hits == ["/v1/data"], "the HTTPS origin was not contacted"
    assert http_hits == [], "the downgraded HTTP target received a request"
    assert result.audit.decision == "denied", result.audit.reason
    assert result.audit.transport_ok is False
    assert "scheme" in result.audit.reason.lower(), result.audit.reason
    assert result.response_doc["ok"] is False
    assert "content" not in result.response_doc


# ---------------------------------------------------------------------------
# 8. IPv6 end-to-end, if this host has an IPv6 loopback
# ---------------------------------------------------------------------------


def test_ipv6_loopback_handshake_and_request(pki: _Pki, monkeypatch):
    hits: list[str] = []
    try:
        manager = _serve_tls(
            pki.valid_chain, pki.valid_key, _json_handler(hits), host="::1"
        )
        server = manager.__enter__()
    except OSError as exc:  # no IPv6 loopback on this host
        pytest.skip(f"IPv6 loopback unavailable: {exc}")

    try:
        port = server.server_address[1]
        policy = EgressPolicy(allowed_endpoints=(f"https://[::1]:{port}/v1/",))
        _inject_ca(monkeypatch, pki.root_pem)
        result = _mediate_https(policy, port, host="::1")
    finally:
        manager.__exit__(None, None, None)

    assert result.audit.decision == "allowed", result.audit.reason
    assert result.audit.transport_ok is True, result.response_doc.get("error")
    assert result.audit.status == 200
    assert result.response_doc["content"] == {"answer": 42}
    assert hits == ["/v1/data"]
