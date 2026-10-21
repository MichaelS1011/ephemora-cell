# n8n integration (MCP over an authenticated loopback bridge)

Ephemora-cell's MCP server speaks the protocol over **stdio**
(`python -m ephemora_cell_mcp`). n8n cannot use that transport, so this page
documents what was measured, what the bridge is for, and where the integration
is still blocked.

## Why a bridge exists (measured, not assumed)

Checked against the installed packages rather than release notes:

| n8n build | node package | `mcpClientTool` versions | transports offered | stdio? |
|---|---|---|---|---|
| 1.123.85 (local test instance) | `@n8n/n8n-nodes-langchain` 1.122.60 | 1, 1.1, 1.2 | `httpStreamable`, `sse` | **no** |
| 2.43.6 (published package) | `@n8n/n8n-nodes-langchain` 2.43.4 | 1 … 1.4 | `httpStreamable`, `sse` | **no** |

n8n's MCP client node dials an **endpoint URL**; it never launches a child
process. So the earlier idea of a workflow that runs `python -m
ephemora_cell_mcp` over stdio is not implementable in n8n — a workflow JSON
claiming so would import as decoration and never execute.

`ephemora_cell_mcp.http_bridge` closes exactly that gap: it starts the same
stdio server as a child process and exposes it over
`http://127.0.0.1:<port>/mcp` with a mandatory bearer token. It forwards
`tools/list` and `tools/call` and returns the upstream result **untouched**, so
the `_meta.execution` record a caller sees over HTTP is the host-observed record
from the worker, not a bridge-authored summary.

## Running it

```sh
# 1. operator-side secret: env only — a command-line token would be readable
#    through ps//proc by every local user
export EPHEMORA_MCP_BRIDGE_TOKEN="$(python -c 'import secrets;print(secrets.token_hex(32))')"

# 2. bridge in front of the stdio server (same interpreter, same tools dir)
python -m ephemora_cell_mcp.http_bridge --port 8765 -- --tools-dir /srv/ephemora/tools

# 3. in n8n: HTTP Bearer credential with that token, then the MCP Client node
#    endpoint http://127.0.0.1:8765/mcp · transport "HTTP Streamable" · auth Bearer
```

An importable workflow is
[`examples/n8n_ephemora_mcp_workflow.json`](../examples/n8n_ephemora_mcp_workflow.json)
(chat trigger → AI Agent → OpenAI Chat Model → MCP Client, node types pinned to
the versions n8n 1.123 actually ships). Credential ids are placeholders by
design; the file embeds no secret.

Posture, enforced in code and covered by `tests/test_mcp_http_bridge.py`:

- **no token, no start** — the bridge exits with code 2 rather than binding an
  anonymous execution endpoint; tokens shorter than 32 characters are refused.
- **loopback by default** — a non-loopback bind needs `--allow-non-loopback`
  explicitly and still needs a token.
- **every request authenticated** before any MCP message is parsed, compared in
  constant time; a missing, wrong-scheme, or forged credential gets `401` and
  never reaches the tool layer.
- **Host/Origin allowlist** (DNS-rebinding protection), so a page in a local
  browser cannot POST into the bridge through a rebinding DNS name.
- one upstream child per bridge, calls serialised: opening more HTTP sessions
  does not multiply sandbox processes.
- **no half-open endpoint.** A wrong `--tools-dir` once produced a live,
  authenticated server advertising only `get-policy` — nothing executable behind
  it. `python -m ephemora_cell_mcp` now exits 2 when `--tools-dir` is not a
  directory, and the bridge refuses to start when the upstream lists no WASM tool
  (`--allow-no-tools` overrides, if an empty tool set is really intended).

## What was measured (local, 2026-10-15)

Against n8n **1.123.85** installed from npm on this machine, with the bridge in
front of `python -m ephemora_cell_mcp`:

> **Which engine these rows describe.** They were measured with the interpreter and
> Wasmtime build installed on that machine on 2026-10-15 — before 1.2.0 fixed its
> qualified runtime line. Nothing here is evidence about that later line: the
> bridge inherits the execution gate of the interpreter behind it, so on an engine
> outside the qualified range every `tools/call` comes back refused with the
> environment reason while the socket stays up and `get-policy` keeps answering.
> Check the interpreter a workflow dials before wiring it:
> `python -m ephemora_cell.cli doctor` on that same interpreter, and re-run the
> rows below against the release's own artefacts when the line moves.

| Check | Result |
|---|---|
| `n8n import:workflow` of the shipped JSON | imported; `export:workflow` round-trips all 4 nodes at `chatTrigger@1.4`, `agent@1.9`, `lmChatOpenAi@1.3`, `mcpClientTool@1.2` |
| n8n's own client factory (`connectMcpClient`, the function the node calls) | connected in 65 ms; `listTools` → `clock, echo, get-policy` |
| real tool call through that path | `clock` → `{"utc": … , "unix_ms": …}`, `_meta.execution = {"status":"success","exit_code":0,"elapsed_ms":77.65,"fuel_consumed":22531,"fuel_budget":2000000,…}` |
| anonymous connect | refused: `{"type":"auth","error":{"code":401}}` |
| forged token | refused: same 401 |
| unknown tool name | `McpError -32602: unknown tool` — an error, never a fabricated success |
| oversized call (200 KB) | `isError: true` (bounded), the connection survives |
| foreign `Host` header with a valid token | `421 Invalid Host header` |
| call past `--call-timeout` | `isError: true`, `"upstream call timed out after 0.001s"`; three consecutive calls all return, `tools/list` still works — a timeout is an error, not a hung connection |
| upstream given a missing `--tools-dir` | server exits 2 ("is not a directory"); bridge startup fails (exit 3), **no socket bound** |
| upstream with an empty tool directory | bridge refuses: `upstream server exposes no WASM tools (only 'get-policy')`, exit 3, no listener |
| the same with `--allow-no-tools` | serves as explicitly configured: `initialize` → `200` |
| plain MCP SDK client 1.32.1 (the library n8n builds on) | connects, lists, executes |

Two findings shaped the bridge itself:

1. **SSE answers stall n8n's fetch path.** n8n wraps fetch in its own
   redirect-following helper, which waits for the body to finish; against an
   SSE-streaming response `connectMcpClient` never resolved (while a client
   using the platform fetch did). The bridge therefore answers
   `application/json` — a legal streamable-HTTP response and all this transport
   needs, since the bridge sends no server-initiated notifications. `--event-stream`
   restores SSE for clients that demand it.
2. **The `execute` CLI needs an Execute Workflow Trigger**, and this n8n line
   ships no mock language-model node, so a CLI-driven run of the agent workflow
   cannot get past the model slot without credentials.

## Not yet proven: the agent-driven end-to-end run (BLOCKED)

The remaining step is a chat message driving the AI Agent, which then calls the
MCP tool. That requires an **authorized model endpoint** (an OpenAI-compatible
credential). Without one, the workflow is verified as *importable and
node-valid*, and the MCP/Cell path is verified as *executable through n8n's own
client code*, but the full agent loop is **not** claimed as tested. No mock model
stand-in was substituted, because a stand-in would prove the wiring at the cost
of the claim.

No public MCP endpoint was created at any point: the bridge bound to
`127.0.0.1` only, and the temporary n8n instance was shut down after the tests
(n8n binds all interfaces by default — run it with `N8N_LISTEN_ADDRESS=127.0.0.1`).

## No trust escalation from workflow or agent input

A workflow node and a model's tool call supply **arguments**, never security
configuration:

- which tools count as trusted is a host-declared allowlist
  (`CellToolEngine.trusted_tools`), never read from a tool's own bytes;
- the profile, posture and capability grants are host decisions; `get-policy`
  is read-only and cannot be driven by chat text;
- the bridge adds no authority of its own — it forwards the upstream result, so
  a guest printing `{"status":"ok"}` still cannot overwrite the host facts
  written into `_meta.execution`;
- a framework that routes through `EphemoraCellExecutor` additionally confines
  execution to the operator's `allowed_roots`, and — when the operator pins
  `allowed_sha256` — to the exact module bytes, refusing anything else before a
  sandbox exists.

Pinned by `tests/test_execution_record_integrity.py`,
`tests/test_agent_executor_confinement.py`, `tests/test_isolation_gate.py` and
`tests/test_mcp_http_bridge.py`.

## Behaviour reference

| Scenario | What n8n observes | Where enforced |
|---|---|---|
| Success | tool text + host `_meta.execution` (status, exit code, fuel, memory) | worker report, passed through |
| Tool-level error | `isError: true` with the tool's `{"error": …}` message; host status stays authoritative in `_meta` | `parse_tool_stdout` / `_build_call_result` |
| Runaway tool | `isError: true`, status `fuel_exhausted` / `timeout` — returns, never hangs | fuel + epoch wall |
| Unknown tool | JSON-RPC error `-32602` | tool registry |
| Missing/forged credential | `401`, no message parsing | bridge bearer gate |
| Rebinding-looking Host | `421` | SDK transport security |
| Policy read (`get-policy`) | read-only description of the host posture | host decision, never chat input |
