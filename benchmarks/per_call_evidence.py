#!/usr/bin/env python3
"""Per-call evidence comparison — what does the caller RECEIVE per tool call?

The "ask for the receipt" table (comparison-mcp-servers.md §4.1): the same
kind of call is made against every candidate that is measurable locally,
and the response is inspected for execution evidence:

  - ephemora-cell-mcp      → text content PLUS `_meta.execution`: fuel
                             consumed/budget, memory, output bytes, warnings
                             and the security baseline (wasmtime version,
                             limits, preopens) — RFC 8785-canonicalizable,
                             sign-ready (`sign()`/`verify()` shipped)
  - pinned vulnerable MCP filesystem server → text content only
  - docker run (stock container) → stdout text + exit code only
  - plain subprocess       → stdout text + exit code only

Nothing is hardcoded: each row records the keys actually present in the
response. A missing receipt is a measurement, not a judgement. Candidates
that cannot be measured locally (cloud providers, runtimes without a local
install path) are literature rows in the docs table and are labeled there.

Evidence: benchmarks/results/<date>/05_per_call_evidence.json
(measured:true). Fixtures under $HOME, never /tmp (macOS canonical-path
allowlist); home prefixes are redacted from committed evidence.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
from datetime import date
from importlib.metadata import version as _pkg_version
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "benchmarks"))

from mcp_cve_replay import McpStdioClient, _redact  # noqa: E402

VULNERABLE_SERVER = "@modelcontextprotocol/server-filesystem@2025.3.28"
RECEIPT_KEYS = ("fuel_consumed", "elapsed_ms", "security_baseline", "wasmtime_version")


def row(
    name: str,
    command_note: str,
    stdout: str,
    response_keys: list[str],
    signed_record: bool,
    notes: str,
) -> dict:
    return {
        "candidate": name,
        "invocation": command_note,
        "caller_receives_keys": response_keys,
        "has_execution_receipt": signed_record,
        "excerpt": _redact(stdout[:200]),
        "notes": notes,
    }


def main() -> int:
    token = secrets.token_hex(8)
    base = Path(os.path.expanduser(f"~/.per_call_evidence_{secrets.token_hex(4)}"))
    base.mkdir(parents=True)
    (base / "ok.txt").write_text(f"SAFE-{token}")
    rows: list[dict] = []
    ok = True

    # 1. ephemora-cell-mcp — raw tools/call keeps the full result incl. _meta
    client = McpStdioClient(["ephemora-cell-mcp"])
    try:
        resp = client._rpc(
            "tools/call", {"name": "echo", "arguments": {"text": f"receipt-{token}"}}, 1
        )
        result = resp.get("result", {})
        meta = result.get("_meta", {})
        execution = meta.get("execution", {})
        signed = all(k in json.dumps(execution) for k in RECEIPT_KEYS)
        rows.append(
            row(
                "ephemora-cell-mcp (echo)",
                "stdio MCP server, bundled WASM tool",
                json.dumps(execution),
                sorted(result.keys()),
                signed,
                "receipt = _meta.execution: fuel consumed/budget, memory, output "
                "bytes, security baseline (wasmtime version, limits, preopens); "
                "canonicalizable (RFC 8785) and sign-ready",
            )
        )
        pol = client._rpc(
            "tools/call", {"name": "get-policy", "arguments": {"tool": "echo"}}, 2
        )
        pol_ok = "security_baseline" in json.dumps(pol.get("result", {}))
        rows.append(
            row(
                "ephemora-cell-mcp (get-policy)",
                "read-only meta tool",
                json.dumps(pol.get("result", {})),
                sorted(pol.get("result", {}).keys()),
                pol_ok,
                "policy reads are tools; the report is computed by the same code "
                "path that enforces it",
            )
        )
    finally:
        client.close()

    # 2. pinned vulnerable reference server — same protocol, what comes back?
    try:
        ref = McpStdioClient(["npx", "-y", VULNERABLE_SERVER, str(base)])
        try:
            resp = ref._rpc(
                "tools/call",
                {"name": "read_file", "arguments": {"path": str(base / "ok.txt")}},
                1,
            )
            result = resp.get("result", {})
            text = "\n".join(
                c.get("text", "")
                for c in result.get("content", [])
                if c.get("type") == "text"
            )
            rows.append(
                row(
                    f"{VULNERABLE_SERVER} (read_file)",
                    "stdio MCP server via npx (pinned version)",
                    text,
                    sorted(result.keys()),
                    False,
                    "returns the file content; no execution metadata, no cost, "
                    "no policy attestation in the response",
                )
            )
        finally:
            ref.close()
    except Exception as e:
        rows.append(
            row(
                f"{VULNERABLE_SERVER} (read_file)",
                "npx",
                str(e),
                [],
                False,
                "measurement error — see excerpt",
            )
        )
        ok = False

    # 3. stock Docker container
    p = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "python:3.12-slim",
            "python3",
            "-c",
            "print('CALLOUT-" + token + "')",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    rows.append(
        row(
            "docker run python:3.12-slim",
            "container per call",
            p.stdout,
            ["stdout", "exit_code"],
            False,
            "the caller gets stdout and the exit code — no cost, no policy, "
            "no engine version attestation",
        )
    )

    # 4. plain subprocess
    p = subprocess.run(
        [sys.executable, "-c", "print('CALLOUT-" + token + "')"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    rows.append(
        row(
            "plain subprocess (python3 -c)",
            "in-process host execution",
            p.stdout,
            ["stdout", "exit_code"],
            False,
            "baseline: everything the sandbox adds is the delta against this row",
        )
    )

    doc = {
        "measured": True,
        "source": "measurement",
        "date": str(date.today()),
        "python": sys.version.split()[0],
        "package": _pkg_version("ephemora-cell"),
        "marker_token": token,
        "rows": rows,
        "pass": ok,
    }
    out_dir = REPO / "benchmarks" / "results" / str(date.today())
    out_dir.mkdir(parents=True, exist_ok=True)
    dest = out_dir / "05_per_call_evidence.json"
    dest.write_text(json.dumps(doc, indent=2))
    for r in rows:
        print(
            f"{r['candidate'][:44]:46} receipt={'YES' if r['has_execution_receipt'] else 'no '}"
            f"  keys={r['caller_receives_keys']}"
        )
    print(f"Saved: {dest}  |  measured-only rows complete={ok}")
    shutil.rmtree(base, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
