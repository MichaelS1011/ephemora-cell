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
    # The signing chain needs the optional tools-signing extra; consumers
    # running bare pytest skip instead of erroring. CI installs the extra,
    # so these tests run for real there (not green-by-skip).
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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
        tools = tmp_path / "tools"
        tools.mkdir()
        (tools / "widget.wasm").write_bytes(WASM_STUB)
        manifest = dict(MANIFEST)
        manifest["wasm_sha256"] = tool_wasm_sha256(tools / "widget.wasm")
        signed = sign_manifest(manifest, lambda data: key.sign(data))
        (tools / "widget.json").write_text(
            json.dumps(signed, ensure_ascii=False), encoding="utf-8"
        )
        registry = ToolRegistry(
            tools, manifest_verifier=ed25519_verifier_from_pem(str(pub))
        )
        assert [t.name for t in registry.list_tools()] == ["widget"]
        # The manifest grants survive verification unchanged.
        assert registry.get("widget").description == "Does widget things"

    def test_missing_module_binding_rejected(self, keypair, tmp_path):
        """Signed but unbound: a signature over a manifest that does not
        name its module cannot keep the module honest - fail closed."""
        key, _, pub = keypair
        signed = sign_manifest(dict(MANIFEST), lambda data: key.sign(data))
        tools = _tools_dir(tmp_path, signed)
        with pytest.warns(RuntimeWarning, match="no module binding"):
            registry = ToolRegistry(
                tools, manifest_verifier=ed25519_verifier_from_pem(str(pub))
            )
        assert registry.list_tools() == []

    def test_module_hash_mismatch_rejected(self, keypair, tmp_path):
        """One tampered wasm byte after signing must reject the tool at
        load (register-time re-hash, ADR-006)."""
        key, _, pub = keypair
        tools = tmp_path / "tools"
        tools.mkdir()
        wasm = tools / "widget.wasm"
        wasm.write_bytes(WASM_STUB)
        manifest = dict(MANIFEST)
        manifest["wasm_sha256"] = tool_wasm_sha256(wasm)
        signed = sign_manifest(manifest, lambda data: key.sign(data))
        (tools / "widget.json").write_text(json.dumps(signed), encoding="utf-8")
        data = bytearray(wasm.read_bytes())
        data[-1] = (data[-1] + 1) % 256
        wasm.write_bytes(bytes(data))
        with pytest.warns(RuntimeWarning, match="hash mismatch"):
            registry = ToolRegistry(
                tools, manifest_verifier=ed25519_verifier_from_pem(str(pub))
            )
        assert registry.list_tools() == []

    def test_module_swap_after_signing_rejected(self, keypair, tmp_path):
        """MCPoison class (payload swap after trust): a VALID different
        module under a signed manifest never registers - the load path
        re-hashes against the binding, same as the governed-load path."""
        key, _, pub = keypair
        tools = tmp_path / "tools"
        tools.mkdir()
        wasm = tools / "widget.wasm"
        wasm.write_bytes(WASM_STUB)
        manifest = dict(MANIFEST)
        manifest["wasm_sha256"] = tool_wasm_sha256(wasm)
        signed = sign_manifest(manifest, lambda data: key.sign(data))
        (tools / "widget.json").write_text(json.dumps(signed), encoding="utf-8")
        wasm.write_bytes(WASM_STUB + b"\x00a-different-valid-module")
        with pytest.warns(RuntimeWarning, match="hash mismatch"):
            registry = ToolRegistry(
                tools, manifest_verifier=ed25519_verifier_from_pem(str(pub))
            )
        assert registry.list_tools() == []

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
        assert (
            sign_tool_main(
                [
                    str(sidecar),
                    "--key",
                    str(priv),
                    "--wasm",
                    str(tools / "widget.wasm"),
                ]
            )
            == 0
        )
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

    def test_stdio_loop_evaluates_requests_between_messages(self, keypair, tmp_path):
        """--tool-requests-dir works without a custom embedding host: the
        serve loop evaluates dropped requests before each incoming message,
        so the notification precedes the response and the tool is listed."""
        key, _, pub = keypair
        server, transport, _tools, requests = self._server(tmp_path, pub)
        request_file = self._drop_request(key, requests)
        transport._inbox = [
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        ]
        server.serve()
        methods = [m.get("method") for m in transport.outbox]
        assert "notifications/tools/list_changed" in methods
        assert methods.index("notifications/tools/list_changed") == 0
        response = transport.outbox[-1]
        assert response["id"] == 1
        assert "widget" in {t["name"] for t in response["result"]["tools"]}
        # the request was consumed, not left on disk
        assert not request_file.exists()

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
        server, _, _, requests = TestGovernedLoad._server(tmp_path, pub)
        self._drop_request(key, requests, unsigned=True)
        report = server.process_tool_requests()
        assert "signature invalid" in report["rejected"][0]["reason"]

    def test_path_escape_rejected(self, keypair, tmp_path):
        key, _, pub = keypair
        server, _, _, requests = TestGovernedLoad._server(tmp_path, pub)
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
        server, _, _, requests = TestGovernedLoad._server(tmp_path, pub)
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
        server, _, _, requests = TestGovernedLoad._server(
            tmp_path, pub, with_verifier=False
        )
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
    pytest.importorskip("cryptography")
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


class TestTrustHandoff:
    """Multi-hop trust-handoff probes (2026 probe class).

    Motivation: Pillar's "Week of Sandbox Escapes" (W5/W6, cited at
    docs/egress_patterns.md:27) and arXiv 2603.22489 ("Securing the MCP:
    A Dual-Axis Survey" — handoff erosion, tool poisoning). The invariant
    under test: verification NEVER inherits across delegation hops — a
    trusted tool cannot vouch for a follower, and every hop verifies
    independently on its own merit.
    """

    def test_trusted_hop_does_not_relax_next_hop_signature(self, keypair, tmp_path):
        """Hop 1 installs a validly signed tool. Hop 2 submits identical
        metadata but WITHOUT a signature — the earlier trust buys it
        nothing (fail closed)."""
        key, _, pub = keypair
        server, _, _, requests = TestGovernedLoad._server(tmp_path, pub)
        first = TestGovernedLoad._drop_request(key, requests, stem="alpha")
        report = server.process_tool_requests()
        assert report["accepted"] == ["alpha"]
        assert first.exists() is False
        # Hop 2: same manifest shape, unsigned.
        wasm = requests / "beta.wasm"
        wasm.write_bytes(WASM_STUB)
        request_file = requests / f"beta{TOOL_REQUEST_SUFFIX}"
        request_file.write_text(
            json.dumps({"wasm_path": str(wasm), "manifest": dict(MANIFEST)}),
            encoding="utf-8",
        )
        report = server.process_tool_requests()
        assert report["accepted"] == []
        assert "signature invalid" in report["rejected"][0]["reason"]
        assert [t.name for t in server.registry.list_tools()] == ["alpha"]

    def test_hop1_manifest_cannot_describe_hop2_module(self, keypair, tmp_path):
        """The signature of a trusted hop is bound to ITS module: reusing
        hop 1's signed manifest for a DIFFERENT module fails the hash
        binding even though the signature itself is valid."""
        import hashlib as _h

        key, _, pub = keypair
        server, _, _, requests = TestGovernedLoad._server(tmp_path, pub)
        # Hop 1: a validly signed "alpha" is accepted and consumed.
        alpha_file = TestGovernedLoad._drop_request(key, requests, stem="alpha")
        assert server.process_tool_requests()["accepted"] == ["alpha"]
        assert not alpha_file.exists()
        # Hop 2: "beta" (different bytes) arrives with alpha's SIGNED
        # manifest — valid signature over alpha's digest, wrong module.
        manifest = dict(MANIFEST)
        manifest["wasm_sha256"] = _h.sha256(WASM_STUB).hexdigest()
        signed = sign_manifest(manifest, lambda data: key.sign(data))
        beta = requests / "beta.wasm"
        beta.write_bytes(WASM_STUB + b"\x00different-bytes")
        request_file = requests / f"beta{TOOL_REQUEST_SUFFIX}"
        request_file.write_text(
            json.dumps({"wasm_path": str(beta), "manifest": signed}),
            encoding="utf-8",
        )
        report = server.process_tool_requests()
        assert report["accepted"] == []
        assert "hash mismatch" in report["rejected"][0]["reason"]
        assert [t.name for t in server.registry.list_tools()] == ["alpha"]

    def test_second_hop_collision_never_overwrites_first(self, keypair, tmp_path):
        """A later hop cannot displace an already-trusted tool by re-using
        its name with different (even validly signed) bytes."""
        key, _, pub = keypair
        server, _, tools, requests = TestGovernedLoad._server(tmp_path, pub)
        TestGovernedLoad._drop_request(key, requests, stem="gamma")
        assert server.process_tool_requests()["accepted"] == ["gamma"]
        installed_before = (tools / "gamma.wasm").read_bytes()
        # Hop 2: validly signed request for the SAME name, different bytes.
        request_file = TestGovernedLoad._drop_request(
            key,
            requests,
            stem="gamma",
            manifest_extra={"description": "IMPOSTOR"},
        )
        # _drop_request writes fresh stub bytes at the same path; make
        # the second hop genuinely different so the hash differs.
        (requests / "gamma.wasm").write_bytes(WASM_STUB + b"\x00v2")
        report = server.process_tool_requests()
        assert report["accepted"] == []
        assert (
            any("collision" in r["reason"] for r in report["rejected"])
            or "hash mismatch" in report["rejected"][0]["reason"]
        )
        assert (tools / "gamma.wasm").read_bytes() == installed_before
        assert request_file.exists()  # rejected requests stay on disk

    def test_guest_runtime_writes_cannot_reach_requests_dir(self, keypair, tmp_path):
        """A running guest can write files — but only into its own
        scratch. A request-lookalike dropped by the GUEST never reaches
        the operator-allowlisted requests dir, so process_tool_requests
        cannot be fed from inside the sandbox."""
        import wasmtime as _w

        pub = None
        server, _, _, requests = TestGovernedLoad._server(
            tmp_path, pub, with_verifier=False
        )
        evil_writer = """(module
          (import "wasi_snapshot_preview1" "path_open" (func $po
            (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
          (import "wasi_snapshot_preview1" "fd_write" (func $fw
            (param i32 i32 i32 i32) (result i32)))
          (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "evil.tool.request.json")
          (data (i32.const 32) "{}")
          (func (export "_start")
            (local $err i32)
            i32.const 3 i32.const 0 i32.const 0 i32.const 22 i32.const 1
            i64.const 64 i64.const 0 i32.const 0 i32.const 100
            call $po local.set $err
            local.get $err if local.get $err call $exit end
            i32.const 64 i32.const 32 i32.store
            i32.const 68 i32.const 2 i32.store
            i32.const 100 i32.load i32.const 64 i32.const 1 i32.const 72
            call $fw local.set $err
            local.get $err call $exit
          )
        )"""
        from ephemora_cell import WASIConfig, WASISandbox

        wasm = tmp_path / "evil_writer.wasm"
        wasm.write_bytes(_w.wat2wasm(evil_writer))
        sandbox = WASISandbox(config=WASIConfig(max_fuel=1_000_000))
        try:
            result = sandbox.run(str(wasm))
            assert result.exit_code == 0, result.stderr
        finally:
            sandbox.cleanup()
        # The guest wrote SOMETHING (its scratch), but the requests dir
        # never saw a request file.
        report = server.process_tool_requests()
        assert report["accepted"] == []
        assert list(requests.glob(f"*{TOOL_REQUEST_SUFFIX}")) == []
