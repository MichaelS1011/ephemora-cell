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
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell_mcp import Server
from ephemora_cell_mcp.sign_tool import main as sign_tool_main
from ephemora_cell_mcp.tool_registry import (
    TOOL_REQUEST_SUFFIX,
    ToolRegistry,
    ed25519_verifier_from_pem,
    sign_manifest,
    tool_wasm_sha256,
    verify_manifest,
)
from ephemora_cell_mcp.transport import MemoryTransport

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


class TestGovernedLoad:
    """ADR-006 request-file loading: the agent proposes, the host disposes.

    Server.process_tool_requests() enforces verify-before-register: path
    allowlist, manifest signature (covering the module digest), module
    hash re-check, registry policy — then rescan + list_changed.
    """

    @staticmethod
    def _drop_request(
        key,
        requests_dir,
        *,
        stem="widget",
        tamper=False,
        unsigned=False,
        manifest_extra=None,
    ):
        """Vendor side: drop a module + its (signed) request into DIR."""
        wasm = requests_dir / f"{stem}.wasm"
        wasm.write_bytes(WASM_STUB)
        manifest = dict(MANIFEST)
        manifest["wasm_sha256"] = tool_wasm_sha256(wasm)
        if manifest_extra:
            manifest.update(manifest_extra)
        if not unsigned:
            manifest = sign_manifest(manifest, lambda data: key.sign(data))
        if tamper:
            wasm.write_bytes(WASM_STUB + b"\x00tampered-after-signing")
        request_file = requests_dir / f"{stem}{TOOL_REQUEST_SUFFIX}"
        request_file.write_text(
            json.dumps({"wasm_path": str(wasm), "manifest": manifest}),
            encoding="utf-8",
        )
        return request_file

    @staticmethod
    def _server(tmp_path, pub, *, with_verifier=True, with_requests=True):
        tools = tmp_path / "srv_tools"
        tools.mkdir(exist_ok=True)
        requests = tmp_path / "requests"
        requests.mkdir(exist_ok=True)
        transport = MemoryTransport()
        server = Server(
            tools_dir=tools,
            transport=transport,
            manifest_verifier=(
                ed25519_verifier_from_pem(str(pub)) if with_verifier else None
            ),
            tool_requests_dir=requests if with_requests else None,
        )
        return server, transport, tools, requests

    def test_request_installs_tool_and_notifies(self, keypair, tmp_path):
        key, _, pub = keypair
        server, transport, tools, requests = self._server(tmp_path, pub)
        request_file = self._drop_request(key, requests)
        report = server.process_tool_requests()
        assert report["accepted"] == ["widget"]
        assert report["rejected"] == []
        assert [t.name for t in server.registry.list_tools()] == ["widget"]
        # the request is consumed; module + signed sidecar are installed
        assert not request_file.exists()
        assert (tools / "widget.wasm").read_bytes() == WASM_STUB
        assert json.loads((tools / "widget.json").read_text())["signature"]
        # the registry change is announced
        assert any(
            m.get("method") == "notifications/tools/list_changed"
            for m in transport.outbox
        )

    def test_tampered_module_rejected(self, keypair, tmp_path):
        key, _, pub = keypair
        server, transport, _tools, requests = self._server(tmp_path, pub)
        request_file = self._drop_request(key, requests, tamper=True)
        report = server.process_tool_requests()
        assert report["accepted"] == []
        assert "hash mismatch" in report["rejected"][0]["reason"]
        assert [t.name for t in server.registry.list_tools()] == []
        # rejected requests stay on disk for operator inspection
        assert request_file.exists()
        assert transport.outbox == []

    def test_unsigned_manifest_rejected(self, keypair, tmp_path):
        key, _, pub = keypair
        server, _, _, requests = self._server(tmp_path, pub)
        self._drop_request(key, requests, unsigned=True)
        report = server.process_tool_requests()
        assert "signature invalid" in report["rejected"][0]["reason"]

    def test_path_escape_rejected(self, keypair, tmp_path):
        key, _, pub = keypair
        server, _, _, requests = self._server(tmp_path, pub)
        # a module OUTSIDE the allowlisted dir is unreachable by request
        outside = tmp_path / "evil.wasm"
        outside.write_bytes(WASM_STUB)
        manifest = dict(MANIFEST)
        manifest["wasm_sha256"] = tool_wasm_sha256(outside)
        signed = sign_manifest(manifest, lambda data: key.sign(data))
        (requests / "evil.tool.request.json").write_text(
            json.dumps({"wasm_path": str(outside), "manifest": signed}),
            encoding="utf-8",
        )
        report = server.process_tool_requests()
        assert "outside the allowlisted" in report["rejected"][0]["reason"]

    def test_unknown_profile_rejected(self, keypair, tmp_path):
        key, _, pub = keypair
        server, _, _, requests = self._server(tmp_path, pub)
        self._drop_request(key, requests, manifest_extra={"profile": "nope"})
        report = server.process_tool_requests()
        assert "Unknown profile" in report["rejected"][0]["reason"]

    def test_name_collision_never_overwrites(self, keypair, tmp_path):
        key, _, pub = keypair
        server, _, tools, requests = self._server(tmp_path, pub)
        self._drop_request(key, requests, stem="widget")
        assert server.process_tool_requests()["accepted"] == ["widget"]
        original = (tools / "widget.wasm").read_bytes()
        # second request for the same stem — different bytes with a VALID
        # signature over exactly those bytes (v2), so only the collision
        # rule can reject it
        wasm_v2 = requests / "widget.wasm"
        wasm_v2.write_bytes(WASM_STUB + b"\x00version-2")
        manifest = dict(MANIFEST)
        manifest["wasm_sha256"] = tool_wasm_sha256(wasm_v2)
        signed_v2 = sign_manifest(manifest, lambda data: key.sign(data))
        (requests / "widget.tool.request.json").write_text(
            json.dumps({"wasm_path": str(wasm_v2), "manifest": signed_v2}),
            encoding="utf-8",
        )
        report = server.process_tool_requests()
        assert report["accepted"] == []
        assert "collision" in report["rejected"][0]["reason"]
        # the registered module was not replaced
        assert (tools / "widget.wasm").read_bytes() == original

    def test_requires_signed_mode(self, keypair, tmp_path):
        key, _, pub = keypair
        server, _, _, requests = self._server(tmp_path, pub, with_verifier=False)
        self._drop_request(key, requests)
        report = server.process_tool_requests()
        assert "signed-tools mode" in report["rejected"][0]["reason"]

    def test_no_requests_dir_is_a_noop(self, keypair, tmp_path):
        _, _, pub = keypair
        server, transport, _, _ = self._server(tmp_path, pub, with_requests=False)
        assert server.process_tool_requests() == {"accepted": [], "rejected": []}
        assert transport.outbox == []

    def test_initialize_advertises_list_changed(self, keypair, tmp_path):
        _, _, pub = keypair
        server, _, _, _ = self._server(tmp_path, pub)
        assert (
            server._handle_initialize({})["capabilities"]["tools"]["listChanged"]
            is True
        )
        plain, _, _, _ = self._server(tmp_path, pub, with_requests=False)
        assert (
            plain._handle_initialize({})["capabilities"]["tools"]["listChanged"]
            is False
        )

    def test_sign_tool_wasm_binding_end_to_end(self, keypair, tmp_path):
        """sign_tool --wasm injects the digest; the request chain accepts."""
        _, priv, pub = keypair
        server, transport, _tools, requests = self._server(tmp_path, pub)
        wasm = requests / "widget.wasm"
        wasm.write_bytes(WASM_STUB)
        sidecar = requests / "widget.json"
        sidecar.write_text(json.dumps(dict(MANIFEST)), encoding="utf-8")
        assert (
            sign_tool_main([str(sidecar), "--key", str(priv), "--wasm", str(wasm)]) == 0
        )
        signed = json.loads(sidecar.read_text(encoding="utf-8"))
        assert signed["wasm_sha256"] == tool_wasm_sha256(wasm)
        (requests / "widget.tool.request.json").write_text(
            json.dumps({"wasm_path": str(wasm), "manifest": signed}),
            encoding="utf-8",
        )
        report = server.process_tool_requests()
        assert report["accepted"] == ["widget"]
        assert any(
            m.get("method") == "notifications/tools/list_changed"
            for m in transport.outbox
        )


def test_signed_record_demo_detects_tampering():
    """The runnable demo (examples/signed_record_demo.py) must print
    verify=True for the intact record and verify=False after tampering —
    the recipes-doc claim stays backed by a live run."""
    repo_root = os.path.join(os.path.dirname(__file__), "..")
    proc = subprocess.run(
        [sys.executable, "examples/signed_record_demo.py"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=repo_root,
    )
    assert proc.returncode == 0, proc.stderr[-300:]
    assert "verify(intact): True" in proc.stdout
    assert "verify(tampered): False" in proc.stdout
