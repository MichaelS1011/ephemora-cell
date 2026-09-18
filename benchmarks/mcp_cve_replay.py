"""MCP CVE replay harness (plan item T0-3).

Replays three documented MCP attack classes — as their ORIGINAL exploit
paths, not synthetic probes — against two boundaries on the same machine,
same files:

  1. CVE-2025-53109 (symlink escape, CWE-59) and CVE-2025-53110 (prefix
     path-traversal, CWE-22) in the official MCP filesystem reference
     server ("EscapeRoute", Cymulate 2025). The vulnerable version
     v2025.3.28 is pinned and run locally via npx; a minimal MCP stdio
     client performs the real tools/call round-trips.
  2. CVE-2025-54136 ("MCPoison", Check Point 2025) — trust granted to an
     MCP entry, then the payload is swapped. The class-level equivalent
     against Cell is governed tool loading (ADR-006): a signed tool is
     accepted once, then a single tampered wasm byte must make the next
     request fail closed (verify-before-register, wasm_sha256 binding).

Every class runs a positive control (a granted-capability read that MUST
succeed on both sides) — blocking everything is not a pass. Evidence is
written to benchmarks/results/<date>/mcp_cve_replay.json with
measured:true; the fixture uses a random marker token so a "leak" can
only come from actually reading the protected file.

Usage:
    python benchmarks/mcp_cve_replay.py            # all classes
    python benchmarks/mcp_cve_replay.py --cell-only
    python benchmarks/mcp_cve_replay.py --component-only

Exit 0 when: the reference leaks both fs-CVE intents, Cell blocks all
fs-CVE intents, all positive controls pass, and the tampered tool request
is rejected. Exit 1 otherwise (that includes the reference NOT leaking —
a patched reference version is a harness change, not a pass).

Component branch (WASI 0.2): the same attack intents are replayed against
the ComponentSandbox boundary with prebuilt component probes
(benchmarks/component_probes/, rebuilt via its rebuild.sh). The WASI 0.2
world LINKS wasi:sockets — unlike Preview1, denial must happen at call
time, so a dedicated network intent (TCP connect to an IP literal, with a
granted-read positive control in the same run) verifies fail-closed
behavior as a measured fact. Evidence:
benchmarks/results/<date>/mcp_cve_replay_component.json with abi:"component".

Requires: node/npx on PATH (reference side), the 'cryptography' package
(class 3). Nothing is downloaded at test time except the pinned npm
package; fixtures live under $HOME, never /tmp (macOS canonical-path
allowlist). The component branch needs neither node nor the npm package.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import secrets
import shutil
import subprocess
import sys
import time
from datetime import date
from importlib.metadata import version as _pkg_version
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from ephemora_cell_mcp.server import Server  # noqa: E402
from ephemora_cell_mcp.sign_tool import main as sign_tool_main  # noqa: E402

VULNERABLE_SERVER = "@modelcontextprotocol/server-filesystem@2025.3.28"
COMPONENT_PROBES = REPO / "benchmarks" / "component_probes"
FS_PROBE_COMPONENT = COMPONENT_PROBES / "fs_probe.wasm"
NET_PROBE_COMPONENT = COMPONENT_PROBES / "net_probe.wasm"

FS_PROBE_WAT = r"""
(module
  (import "wasi_snapshot_preview1" "fd_read" (func $fd_read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "path_open" (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 2)
  (data (i32.const 8300) "\"path\":")
  (data (i32.const 8800) "PATH_NOT_FOUND")
  (func $dump (param $ptr i32) (param $len i32)
    (i32.store (i32.const 8700) (local.get $ptr))
    (i32.store (i32.const 8704) (local.get $len))
    (drop (call $fd_write (i32.const 1) (i32.const 8700) (i32.const 1) (i32.const 8708))))
  (func $put3 (param $ptr i32) (param $v i32)
    (i32.store8 (local.get $ptr) (i32.add (i32.const 48)
      (i32.rem_u (i32.div_u (local.get $v) (i32.const 100)) (i32.const 10))))
    (i32.store8 (i32.add (local.get $ptr) (i32.const 1)) (i32.add (i32.const 48)
      (i32.rem_u (i32.div_u (local.get $v) (i32.const 10)) (i32.const 10))))
    (i32.store8 (i32.add (local.get $ptr) (i32.const 2)) (i32.add (i32.const 48)
      (i32.rem_u (local.get $v) (i32.const 10)))))
  (func $find (param $n i32) (result i32)
    (local $i i32) (local $m i32) (local $ok i32) (local $j i32)
    (block $out
      (loop $scan
        (br_if $out (i32.gt_u (i32.add (local.get $i) (i32.const 7)) (local.get $n)))
        (local.set $ok (i32.const 1))
        (local.set $m (i32.const 0))
        (block $done
          (loop $cmp
            (br_if $done (i32.ge_u (local.get $m) (i32.const 7)))
            (if (i32.ne (i32.load8_u (i32.add (i32.const 8300) (local.get $m)))
                        (i32.load8_u (i32.add (local.get $i) (local.get $m))))
              (then (local.set $ok (i32.const 0)) (br $done)))
            (local.set $m (i32.add (local.get $m) (i32.const 1)))
            (br $cmp)))
        (if (i32.eq (local.get $ok) (i32.const 1))
          (then
            (local.set $j (i32.add (local.get $i) (i32.const 7)))
            (block $spdone
              (loop $sp
                (br_if $spdone (i32.ne (i32.load8_u (local.get $j)) (i32.const 32)))
                (local.set $j (i32.add (local.get $j) (i32.const 1)))
                (br $sp)))
            (if (i32.eq (i32.load8_u (local.get $j)) (i32.const 34))
              (then (return (i32.add (local.get $j) (i32.const 1)))))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $scan)))
    (i32.const -1))
  (func (export "_start")
    (local $n i32) (local $start i32) (local $plen i32)
    (local $fd i32) (local $e3 i32) (local $e4 i32) (local $rd i32)
    (i32.store (i32.const 8192) (i32.const 0))
    (i32.store (i32.const 8196) (i32.const 8000))
    (drop (call $fd_read (i32.const 0) (i32.const 8192) (i32.const 1) (i32.const 8216)))
    (local.set $n (i32.load (i32.const 8216)))
    (local.set $start (call $find (local.get $n)))
    (if (i32.eq (local.get $start) (i32.const -1))
      (then (call $dump (i32.const 8800) (i32.const 14)) (call $exit (i32.const 0))))
    (local.set $plen (i32.const 0))
    (block $done
      (loop $copy
        (br_if $done (i32.ge_u (i32.add (local.get $start) (local.get $plen)) (local.get $n)))
        (br_if $done (i32.eq
          (i32.load8_u (i32.add (local.get $start) (local.get $plen))) (i32.const 34)))
        (i32.store8 (i32.add (i32.const 8400) (local.get $plen))
          (i32.load8_u (i32.add (local.get $start) (local.get $plen))))
        (local.set $plen (i32.add (local.get $plen) (i32.const 1)))
        (br $copy)))
    (local.set $e3 (call $path_open (i32.const 3) (i32.const 0) (i32.const 8400)
      (local.get $plen) (i32.const 0) (i64.const 0) (i64.const 0) (i32.const 0) (i32.const 8600)))
    (if (i32.eq (local.get $e3) (i32.const 0))
      (then (local.set $fd (i32.load (i32.const 8600))))
      (else
        (local.set $e4 (call $path_open (i32.const 4) (i32.const 0) (i32.const 8400)
          (local.get $plen) (i32.const 0) (i64.const 0) (i64.const 0) (i32.const 0) (i32.const 8600)))
        (if (i32.eq (local.get $e4) (i32.const 0))
          (then (local.set $fd (i32.load (i32.const 8600))))
          (else
            (i32.store8 (i32.const 8500) (i32.const 69)) (i32.store8 (i32.const 8501) (i32.const 82))
            (i32.store8 (i32.const 8502) (i32.const 82)) (i32.store8 (i32.const 8503) (i32.const 78))
            (i32.store8 (i32.const 8504) (i32.const 79)) (i32.store8 (i32.const 8505) (i32.const 58))
            (call $put3 (i32.const 8506) (local.get $e3))
            (i32.store8 (i32.const 8509) (i32.const 47))
            (call $put3 (i32.const 8510) (local.get $e4))
            (call $dump (i32.const 8500) (i32.const 13)) (call $exit (i32.const 0))))))
    (block $done2
      (loop $read
        (i32.store (i32.const 8700) (i32.const 10300))
        (i32.store (i32.const 8704) (i32.const 20000))
        (drop (call $fd_read (local.get $fd) (i32.const 8700) (i32.const 1) (i32.const 8720)))
        (local.set $rd (i32.load (i32.const 8720)))
        (br_if $done2 (i32.eqz (local.get $rd)))
        (call $dump (i32.const 10300) (local.get $rd))
        (br $read)))
    (call $exit (i32.const 0)))
)
"""


def build_probe_wasm(work: Path) -> Path:
    import wasmtime

    wat = FS_PROBE_WAT
    wasm = work / "fs_probe.wasm"
    wasm.write_bytes(wasmtime.wat2wasm(wat))
    return wasm


class McpStdioClient:
    """Minimal newline-delimited JSON-RPC MCP client (initialize + tools/call)."""

    def __init__(self, cmd: list[str], cwd: str | None = None):
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            cwd=cwd,
        )
        self._next_id = 1
        self._rpc(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "mcp-cve-replay", "version": "1.0"},
            },
            want_id=self._next_id,
        )
        self._next_id += 1
        self._notify("notifications/initialized")

    def _rpc(
        self, method: str, params: dict, want_id: int, timeout: float = 90.0
    ) -> dict:
        self.proc.stdin.write(
            json.dumps(
                {"jsonrpc": "2.0", "id": want_id, "method": method, "params": params}
            )
            + "\n"
        )
        self.proc.stdin.flush()
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError(f"{method}: server closed")
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("id") == want_id:
                return msg
        raise RuntimeError(f"{method}: timeout")

    def _notify(self, method: str) -> None:
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method}) + "\n")
        self.proc.stdin.flush()

    def call_tool(self, name: str, arguments: dict) -> str:
        self._next_id += 1
        resp = self._rpc(
            "tools/call", {"name": name, "arguments": arguments}, want_id=self._next_id
        )
        if "error" in resp:
            return f"MCP-ERROR: {resp['error'].get('message', '')}"
        content = resp.get("result", {}).get("content", [])
        return "\n".join(c.get("text", "") for c in content if c.get("type") == "text")

    def close(self) -> None:
        try:
            self.proc.kill()
        except OSError:
            pass


def build_fixtures(work: Path) -> dict:
    token = secrets.token_hex(8)
    base = Path(os.path.expanduser(f"~/.mcp_cve_replay_{secrets.token_hex(4)}"))
    allowed = base / "allowed"
    secret = base / "allowed-secret"
    allowed.mkdir(parents=True)
    secret.mkdir(parents=True)
    (allowed / "ok.txt").write_text(f"SAFE-{token}")
    (secret / "leak.txt").write_text(f"LEAKMARKER-{token}")
    os.symlink(secret / "leak.txt", allowed / "link_to_secret")
    return {"base": base, "allowed": allowed, "secret": secret, "token": token}


def run_reference(fx: dict) -> list[dict]:
    intents = [
        (
            "positive-control (granted read)",
            "read_file",
            {"path": str(fx["allowed"] / "ok.txt")},
        ),
        (
            "CVE-2025-53109 symlink escape",
            "read_file",
            {"path": str(fx["allowed"] / "link_to_secret")},
        ),
        (
            "CVE-2025-53110 prefix traversal",
            "read_file",
            {"path": str(fx["secret"] / "leak.txt")},
        ),
    ]
    out = []
    client = McpStdioClient(["npx", "-y", VULNERABLE_SERVER, str(fx["allowed"])])
    try:
        for name, tool, args in intents:
            text = client.call_tool(tool, args)
            out.append(
                {
                    "intent": name,
                    "leaked": f"LEAKMARKER-{fx['token']}" in text,
                    "response": text[:200],
                }
            )
    finally:
        client.close()
    return out


def run_cell(fx: dict, work: Path) -> list[dict]:
    """Counter-probes on the Cell engine boundary.

    ephemora-cell-mcp executes every tool through WASISandbox — this runs
    the probe on exactly that boundary with an explicit preopen grant
    (positive control) instead of a sidecar grant. FINDING F1: sidecar
    allow_dirs grants are currently inert because every shipped profile
    has allow_dirs=() and _config_for() intersects with them — the MCP
    server therefore cannot hand a tool real filesystem grants; the
    blocked surface is even larger than the docstring implies.
    """
    probe_wasm = build_probe_wasm(work)
    from ephemora_cell import WASIConfig, WASISandbox

    sandbox = WASISandbox(
        config=WASIConfig(allow_dirs=(str(fx["allowed"]),), max_fuel=1_000_000)
    )
    intents = [
        ("positive-control (granted read)", {"path": "ok.txt"}),
        ("CVE-2025-53109 symlink escape", {"path": "link_to_secret"}),
        (
            "CVE-2025-53110 prefix traversal (absolute)",
            {"path": str(fx["secret"] / "leak.txt")},
        ),
        ("CVE-2025-53110 traversal (../)", {"path": "../allowed-secret/leak.txt"}),
    ]
    out = []
    try:
        for name, args in intents:
            r = sandbox.run(
                str(probe_wasm),
                stdin_data=json.dumps({"params": args}),
                use_subprocess=False,
                abi="auto",
            )
            text = r.stdout.strip()
            if "positive-control" in name:
                out.append(
                    {
                        "intent": name,
                        "granted": text.startswith("SAFE"),
                        "response": text[:200],
                    }
                )
            else:
                out.append(
                    {
                        "intent": name,
                        "blocked": "LEAKMARKER-" not in text,
                        "response": text[:200],
                    }
                )
    finally:
        sandbox.cleanup()
    return out


def run_class3(work: Path, probe_wasm: Path | None = None) -> dict:
    """CVE-2025-54136 class equivalent: signed tool accepted once, then a
    tampered wasm must fail closed on the next governed request. The probe
    is parameterized so the same flow runs against a WASI 0.2 component
    (governed loading hashes raw bytes — ABI-agnostic)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if probe_wasm is None:
        probe_wasm = build_probe_wasm(work)
    tools = work / "srv_tools"  # server registry: starts EMPTY
    tools.mkdir(exist_ok=True)
    requests = work / "requests"  # vendor drop zone
    requests.mkdir(exist_ok=True)
    shutil.copy(probe_wasm, requests / "widget.wasm")
    manifest = {
        "name": "widget",
        "description": "governed-load replay tool",
        "input_schema": {"type": "object", "properties": {}},
        "profile": "llm",
        "allow_dirs": [],
    }
    (requests / "widget.json").write_text(json.dumps(manifest))

    key = Ed25519PrivateKey.generate()
    priv = work / "ed25519_private.pem"
    pub = work / "ed25519_public.pem"
    priv.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    pub.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

    rc = sign_tool_main(
        [
            str(requests / "widget.json"),
            "--key",
            str(priv),
            "--wasm",
            str(requests / "widget.wasm"),
        ]
    )
    if rc != 0:
        return {"error": f"signing failed rc={rc}"}

    # governed loading: the vendor drops module + signed manifest into the
    # requests dir as {"wasm_path": ..., "manifest": ...}; the HOST evaluates.
    wasm_src = requests / "widget.wasm"
    signed_manifest = json.loads((requests / "widget.json").read_text())
    from ephemora_cell_mcp.tool_registry import ed25519_verifier_from_pem
    from ephemora_cell_mcp.transport import MemoryTransport

    server = Server(
        tools_dir=tools,
        tool_requests_dir=work,
        manifest_verifier=ed25519_verifier_from_pem(str(pub)),
        transport=MemoryTransport(),
    )

    def drop_request():
        (work / "widget.tool.request.json").write_text(
            json.dumps(
                {
                    "wasm_path": str(wasm_src),
                    "manifest": signed_manifest,
                }
            )
        )

    drop_request()
    report1 = server.process_tool_requests()
    accepted_first = (
        report1.get("accepted", []) == ["widget"] and (tools / "widget.wasm").exists()
    )

    # MCPoison step: swap the payload AFTER trust was granted (one byte),
    # re-presenting the SAME trusted manifest identity
    data = bytearray(wasm_src.read_bytes())
    data[100] = (data[100] + 1) % 256
    wasm_src.write_bytes(bytes(data))
    drop_request()
    report2 = server.process_tool_requests()
    rejected = "widget" not in report2.get("accepted", [])
    reason = str(report2.get("rejected", report2.get("errors", report2)))[:200]

    return {
        "accepted_first": accepted_first,
        "tampered_rejected": rejected,
        "fail_closed": bool(accepted_first and rejected),
        "tamper_report": reason,
    }


def _redact(s: str) -> str:
    """Scrub the local home prefix from guest/stderr text before it lands in
    committed evidence (the 1.0.1 audit fixed exactly this leak pattern)."""
    home = os.path.expanduser("~")
    return s.replace(home, "~") if home and home != "/" else s


def run_cell_component(fx: dict) -> list[dict]:
    """The same four intents as run_cell, replayed on the ComponentSandbox
    (WASI 0.2) boundary. Preopen semantics on the component path: the guest
    sees the HOST path (no /sandbox mount), so intents pass host-absolute
    paths; the traversal intent keeps its relative form to show there is no
    preopen base to traverse from. Verdict logic is identical to run_cell:
    marker-based, positive control must succeed."""
    from ephemora_cell import WASIConfig
    from ephemora_cell.wasi_02 import ComponentSandbox

    sandbox = ComponentSandbox(
        config=WASIConfig(allow_dirs=(str(fx["allowed"]),), max_fuel=1_000_000)
    )
    intents = [
        ("positive-control (granted read)", str(fx["allowed"] / "ok.txt")),
        ("CVE-2025-53109 symlink escape", str(fx["allowed"] / "link_to_secret")),
        (
            "CVE-2025-53110 prefix traversal (absolute)",
            str(fx["secret"] / "leak.txt"),
        ),
        ("CVE-2025-53110 traversal (../)", "../allowed-secret/leak.txt"),
    ]
    out = []
    try:
        for name, path in intents:
            r = sandbox.run(
                str(FS_PROBE_COMPONENT),
                stdin_data=json.dumps({"params": {"path": path}}),
            )
            text = _redact((r.stdout or "").strip())
            if "positive-control" in name:
                out.append(
                    {
                        "intent": name,
                        "granted": text.startswith("SAFE"),
                        "response": text[:200],
                    }
                )
            else:
                out.append(
                    {
                        "intent": name,
                        "blocked": "LEAKMARKER-" not in text,
                        "response": text[:200],
                    }
                )
    finally:
        sandbox.cleanup()
    return out


def run_network_intent(fx: dict) -> dict:
    """U4 network intent on the component path (audit requirement): the
    WASI 0.2 world LINKS wasi:sockets — unlike Preview1 there is no
    "API does not exist" argument, so denial MUST happen at call time. One
    run carries its own FS positive control (granted preopen read via
    argv). A NET:CONNECTED marker would mean the network vector is OPEN."""
    from ephemora_cell import WASIConfig
    from ephemora_cell.wasi_02 import ComponentSandbox

    sandbox = ComponentSandbox(
        config=WASIConfig(allow_dirs=(str(fx["allowed"]),), max_fuel=1_000_000)
    )
    try:
        r = sandbox.run(
            str(NET_PROBE_COMPONENT),
            args=[str(fx["allowed"] / "ok.txt")],
            stdin_data="x",
        )
    finally:
        sandbox.cleanup()
    text = _redact((r.stdout or "").strip())
    fs_control = "FS:OK" in text.splitlines()
    network_open = "NET:CONNECTED" in text
    return {
        "fs_positive_control": fs_control,
        "network_open": network_open,
        "fail_closed": bool(fs_control and not network_open),
        "response": text[:200],
    }


def main() -> int:
    results = {
        "measured": True,
        "source": "measurement",
        "date": str(date.today()),
        "python": platform.python_version(),
        "wasmtime": _pkg_version("wasmtime"),
        "package": _pkg_version("ephemora-cell"),
        "node": subprocess.run(
            ["node", "--version"], capture_output=True, text=True
        ).stdout.strip(),
        "vulnerable_reference": VULNERABLE_SERVER,
        "classes": {},
    }
    work = Path(os.path.expanduser(f"~/.mcp_cve_replay_work_{secrets.token_hex(4)}"))
    work.mkdir(parents=True)
    fx = build_fixtures(work)
    results["marker_token"] = fx["token"]

    comp_only = "--component-only" in sys.argv
    ok = True
    if not comp_only and "--cell-only" not in sys.argv:
        ref = run_reference(fx)
        results["classes"]["reference (server-filesystem v2025.3.28)"] = ref
        leaked = [r for r in ref if r["leaked"]]
        print("REFERENCE (vulnerable):")
        for r in ref:
            print(f"  {r['intent']:38} -> {'LEAKED' if r['leaked'] else 'no-leak'}")
        if not (len(leaked) == 2 and not ref[0]["leaked"]):
            print(
                "  !! reference did not behave as the advisory describes — "
                "check the pinned version"
            )
            ok = False

    if not comp_only:
        cell = run_cell(fx, work)
        results["classes"]["ephemora-cell-mcp"] = cell
        print("CELL:")
        for r in cell:
            if "granted" in r:
                verdict = "GRANTED" if r["granted"] else "NOT-GRANTED"
            else:
                verdict = "BLOCKED" if r["blocked"] else "ALLOWED"
            print(f"  {r['intent']:38} -> {verdict}  [{r['response'][:60]}]")
        cell_attacks = [r for r in cell if "blocked" in r]
        control = next((r for r in cell if "granted" in r), None)
        if not (
            all(r["blocked"] for r in cell_attacks)
            and control is not None
            and control["granted"]
        ):
            ok = False

        c3 = run_class3(work)
        results["classes"]["CVE-2025-54136 class (governed loading)"] = c3
        print(
            f"CLASS 3 (manifest swap): accepted_first={c3.get('accepted_first')} "
            f"tampered_rejected={c3.get('tampered_rejected')} "
            f"fail_closed={c3.get('fail_closed')}"
        )
        if not c3.get("fail_closed"):
            ok = False

    # ---- WASI 0.2 component branch (no node/npm dependency) ------------
    comp = {
        "measured": True,
        "source": "measurement",
        "date": str(date.today()),
        "python": platform.python_version(),
        "wasmtime": _pkg_version("wasmtime"),
        "package": _pkg_version("ephemora-cell"),
        "abi": "component",
        "probes_sha256": {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in (FS_PROBE_COMPONENT, NET_PROBE_COMPONENT)
        },
        "classes": {},
    }
    comp_ok = True

    cellc = run_cell_component(fx)
    comp["classes"]["ephemora-cell-mcp (WASI 0.2 component)"] = cellc
    print("CELL (component):")
    for r in cellc:
        if "granted" in r:
            verdict = "GRANTED" if r["granted"] else "NOT-GRANTED"
        else:
            verdict = "BLOCKED" if r["blocked"] else "ALLOWED"
        print(f"  {r['intent']:38} -> {verdict}  [{r['response'][:60]}]")
    comp_attacks = [r for r in cellc if "blocked" in r]
    comp_control = next((r for r in cellc if "granted" in r), None)
    if not (
        all(r["blocked"] for r in comp_attacks)
        and comp_control is not None
        and comp_control["granted"]
    ):
        comp_ok = False

    neti = run_network_intent(fx)
    comp["classes"]["network intent (wasi:sockets/tcp)"] = neti
    print(
        f"NETWORK INTENT: fs_positive_control={neti['fs_positive_control']} "
        f"network_open={neti['network_open']} fail_closed={neti['fail_closed']}"
    )
    if not neti["fail_closed"]:
        print("  !! NETWORK VECTOR OPEN on the component path — security finding")
        comp_ok = False

    c3c = run_class3(work, FS_PROBE_COMPONENT)
    comp["classes"]["CVE-2025-54136 class (governed loading, component)"] = c3c
    print(
        f"CLASS 3 (manifest swap, component): accepted_first={c3c.get('accepted_first')} "
        f"tampered_rejected={c3c.get('tampered_rejected')} "
        f"fail_closed={c3c.get('fail_closed')}"
    )
    if not c3c.get("fail_closed"):
        comp_ok = False

    comp["pass"] = comp_ok
    ok = ok and comp_ok
    results["component_evidence"] = "mcp_cve_replay_component.json"

    results["pass"] = ok
    results_dir = REPO / "benchmarks" / "results" / str(date.today())
    results_dir.mkdir(parents=True, exist_ok=True)
    comp_dest = results_dir / "mcp_cve_replay_component.json"
    comp_dest.write_text(json.dumps(comp, indent=2))
    if not comp_only:
        # In component-only mode the Preview1 evidence file must stay
        # untouched (it carries the npm-dependent classes of its own run).
        dest = results_dir / "mcp_cve_replay.json"
        dest.write_text(json.dumps(results, indent=2))
        print(f"\nEvidence: {dest}  |  PASS={ok}")
    else:
        print("\n(Preview1 evidence untouched in --component-only mode)")
    print(f"Component evidence: {comp_dest}  |  PASS={comp_ok}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
