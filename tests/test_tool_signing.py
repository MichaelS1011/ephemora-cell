"""ADR-006 signed-tools mode: manifest signing, verify-at-load, fail-closed.

The sign/verify primitives are signer-agnostic (bytes in, bytes out —
Cell ships no crypto dependency). These tests exercise the real chain
end to end with Ed25519 from the optional cryptography package:
sign_manifest -> verify_manifest -> ToolRegistry enforcement ->
ed25519_verifier_from_pem -> the sign_tool CLI.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell_mcp.sign_tool import main as sign_tool_main
from ephemora_cell_mcp.tool_registry import (
    ToolRegistry,
    ed25519_verifier_from_pem,
    sign_manifest,
    verify_manifest,
)

MANIFEST = {
    "name": "widget",
    "description": "Does widget things",
    "input_schema": {"type": "object", "properties": {}},
    "profile": "llm",
    "allow_dirs": [],
}

# Registry scans content-agnostically; a magic-prefixed stub is enough here.
WASM_STUB = b"\x00asm\x01\x00\x00\x01"


@pytest.fixture()
def keypair(tmp_path):
    key = Ed25519PrivateKey.generate()
    priv = tmp_path / "ed25519_private.pem"
    pub = tmp_path / "ed25519_public.pem"
    priv.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    pub.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return key, priv, pub


def _tools_dir(tmp_path, sidecar: dict | None) -> Path:
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "widget.wasm").write_bytes(WASM_STUB)
    if sidecar is not None:
        (tools / "widget.json").write_text(
            json.dumps(sidecar, ensure_ascii=False), encoding="utf-8"
        )
    return tools


class TestManifestSignVerify:
    def test_sign_and_verify_roundtrip(self, keypair, tmp_path):
        key, _, pub = keypair
        signed = sign_manifest(dict(MANIFEST), lambda data: key.sign(data))
        assert signed["alg"] == "EdDSA"
        assert isinstance(signed["signature"], str)
        assert verify_manifest(signed, ed25519_verifier_from_pem(str(pub)))

    def test_tampered_manifest_rejected(self, keypair, tmp_path):
        key, _, pub = keypair
        signed = sign_manifest(dict(MANIFEST), lambda data: key.sign(data))
        signed["description"] = "TAMPERED — now with allow_dirs=['/']"
        assert not verify_manifest(signed, ed25519_verifier_from_pem(str(pub)))

    def test_unsigned_manifest_rejected(self, keypair, tmp_path):
        _, _, pub = keypair
        assert not verify_manifest(dict(MANIFEST), ed25519_verifier_from_pem(str(pub)))

    def test_fail_closed_on_malformed_input(self, keypair):
        # keypair is only needed for fixture symmetry; the verifier here
        # is deliberately permissive to prove fail-closed input handling.
        _, _, _ = keypair
        verifier = lambda c, s: True  # noqa: E731 — must never be trusted

        assert not verify_manifest(None, verifier)
        assert not verify_manifest(["not", "a", "dict"], verifier)
        assert not verify_manifest({}, verifier)
        assert not verify_manifest({"alg": "EdDSA", "signature": "not-hex!"}, verifier)
        # A non-callable verifier is malformed input, not a bypass.
        assert not verify_manifest({"alg": "EdDSA", "signature": "00"}, "nope")

    def test_signer_contract_enforced(self):
        with pytest.raises(TypeError):
            sign_manifest(dict(MANIFEST), "not-callable")
        with pytest.raises(TypeError):
            sign_manifest(dict(MANIFEST), lambda data: "not-bytes")


class TestRegistrySignedMode:
    def test_signed_sidecar_loads(self, keypair, tmp_path):
        key, _, pub = keypair
        signed = sign_manifest(dict(MANIFEST), lambda data: key.sign(data))
        tools = _tools_dir(tmp_path, signed)
        registry = ToolRegistry(
            tools, manifest_verifier=ed25519_verifier_from_pem(str(pub))
        )
        assert [t.name for t in registry.list_tools()] == ["widget"]
        # The manifest grants survive verification unchanged.
        assert registry.get("widget").description == "Does widget things"

    def test_tampered_sidecar_rejected(self, keypair, tmp_path):
        key, _, pub = keypair
        signed = sign_manifest(dict(MANIFEST), lambda data: key.sign(data))
        signed["allow_dirs"] = ["/etc"]
        tools = _tools_dir(tmp_path, signed)
        with pytest.warns(RuntimeWarning, match="verification"):
            registry = ToolRegistry(
                tools, manifest_verifier=ed25519_verifier_from_pem(str(pub))
            )
        assert registry.list_tools() == []

    def test_unsigned_sidecar_rejected(self, keypair, tmp_path):
        _, _, pub = keypair
        tools = _tools_dir(tmp_path, dict(MANIFEST))
        with pytest.warns(RuntimeWarning, match="verification"):
            registry = ToolRegistry(
                tools, manifest_verifier=ed25519_verifier_from_pem(str(pub))
            )
        assert registry.list_tools() == []

    def test_bare_wasm_without_sidecar_rejected(self, keypair, tmp_path):
        """Fail closed: no manifest, no signature, no registration."""
        _, _, pub = keypair
        tools = _tools_dir(tmp_path, None)
        with pytest.warns(RuntimeWarning, match="no sidecar manifest"):
            registry = ToolRegistry(
                tools, manifest_verifier=ed25519_verifier_from_pem(str(pub))
            )
        assert registry.list_tools() == []

    def test_enforcement_off_keeps_legacy_convention(self, keypair, tmp_path):
        """Without a verifier (default) sidecars stay metadata only."""
        tools = _tools_dir(tmp_path, dict(MANIFEST))
        registry = ToolRegistry(tools)
        assert [t.name for t in registry.list_tools()] == ["widget"]


class TestSignToolCLI:
    def test_cli_signs_sidecar_and_registry_accepts(self, keypair, tmp_path):
        _, priv, pub = keypair
        tools = _tools_dir(tmp_path, dict(MANIFEST))
        sidecar = tools / "widget.json"
        assert sign_tool_main([str(sidecar), "--key", str(priv)]) == 0
        signed = json.loads(sidecar.read_text(encoding="utf-8"))
        assert signed["alg"] == "EdDSA"
        registry = ToolRegistry(
            tools, manifest_verifier=ed25519_verifier_from_pem(str(pub))
        )
        assert [t.name for t in registry.list_tools()] == ["widget"]

    def test_cli_missing_key_is_clean_error(self, tmp_path):
        tools = _tools_dir(tmp_path, dict(MANIFEST))
        rc = sign_tool_main([str(tools / "widget.json"), "--key", "/absent.pem"])
        assert rc == 2
