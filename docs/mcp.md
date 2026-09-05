# ephemora-cell-mcp — MCP adapter on top of Ephemora Cell

`ephemora-cell-mcp` is an MCP (Model Context Protocol) **stdio server** whose
tools are **WASM modules executed inside the Ephemora Cell**. It occupies the
same spot as mcp.run or Wassette, but with Cell properties: determinism, fuel
metering, 10 KB output cap, no network.

```
MCP client (Claude Desktop, generic MCP host)
    │  JSON-RPC 2.0, NDJSON lines over stdin/stdout (MCP stdio transport)
    ▼
ephemora-cell-mcp (Python host process)
    │  executes <toolname>.wasm in the Ephemora Cell
    │  stdin:  {"params": <tool arguments>}
    │  stdout: <one JSON value>            (exit 0 = success)
    ▼
Ephemora Cell (wasmtime, fuel-metered, no network, 10 KB output cap)
```

The adapter itself is **dependency-free**: it implements the small JSON-RPC
surface it needs (no `mcp` SDK, no other runtime deps beyond `ephemora_cell`
and its `wasmtime`). This mirrors the Cell's own zero-dependency philosophy
and keeps the attack surface minimal — the host process only parses lines of
JSON.

## Quick start

```bash
pip install ephemora-cell        # provides the Cell engine
python -m ephemora_cell_mcp --tools-dir /path/to/tools
```

The bundled tools ship with the package:

```bash
python -m ephemora_cell_mcp           # serves the bundled "clock" and "echo" tools
```

Run it and feed a hand-written client cycle:

```json
{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
{"jsonrpc": "2.0", "method": "notifications/initialized"}
{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "echo", "arguments": {"message": "hi"}}}
```

The last one returns:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [{"type": "text", "text": "{\"echo\": {\"message\": \"hi\"}}"}],
    "_meta": {
      "execution": {
        "status": "success",
        "exit_code": 0,
        "elapsed_ms": 0.48,
        "fuel_consumed": 20591,
        "fuel_budget": 2000000,
        "memory_mb": 0.0,
        "stdout_bytes": 23,
        "stderr_bytes": 0,
        "warnings": [],
        "security_baseline": {
          "wasmtime_version": "47.0.1",
          "memory_limit_bytes": 134217728,
          "fuel": 2000000,
          "threads_enabled": false,
          "memory64": false,
          "multi_memory": false,
          "gc_heap_mb": null,
          "preopens": ["/sandbox"]
        }
      }
    }
  }
}
```

## Protocol surface

| Message | Behaviour |
|---|---|
| `initialize` | Returns `protocolVersion: "2025-06-18"`, `capabilities: {"tools": {"listChanged": false}}`, `serverInfo: {name: "ephemora-cell-mcp", version: <package version>}` (single-sourced in `ephemora_cell_mcp/_version.py`; 1.0.1 as of this writing) |
| `notifications/initialized` | Accepted silently (no response, per JSON-RPC notifications) |
| `tools/list` | Tools discovered in the registry, as MCP `{name, description, inputSchema}` |
| `tools/call` | Runs the tool's WASM module; result `content[0].text` is the guest's stdout JSON; `_meta.execution` carries the `ExecutionReport` |
| anything else | JSON-RPC error `-32601` (method not found) |

Errors, cleanly separated:

- **Unknown tool** → JSON-RPC error `-32602` (invalid params), message `unknown tool: <name>`.
- **Cell failure** (fuel exhausted, timeout, memory exceeded, error status,
  non-zero exit) → a *valid* JSON-RPC response with `isError: true`; the text
  payload is `{"status": ..., "message": ..., "exit_code": ...}` and the full
  `_meta.execution` report is included.
- **Malformed JSON line** → `-32700`; malformed request → `-32600`.

### `_meta` — "Verified. Not claimed."

Every `tools/call` result embeds the Cell's `ExecutionReport` under
`_meta.execution`: `status`, `exit_code`, `elapsed_ms`, `fuel_consumed`,
`fuel_budget`, `fuel_utilization`, `memory_mb`, `stdout_bytes`,
`stderr_bytes`, `warnings`, and `security_baseline` (incl. the exact
`wasmtime_version` the tool ran on). The client can record this as an
auditable execution witness — signing it into a SEP-2787-style signed
record (via `ExecutionReport.sign()`) is a drop-in next step.

### `get-policy` — the agent can read its sandbox policy, not rewrite it

A native (host-implemented) meta tool, listed in `tools/list` alongside the
WASM tools and dispatched without running a module. Policy reads are tools;
policy writes are host decisions (ADR-006) — there is deliberately no
agent-callable permission grant. The payload is derived from the same
`_config_for()` code path `tools/call` uses, so the reported policy and the
enforced policy cannot drift:

```json
{"jsonrpc": "2.0", "id": 4, "method": "tools/call",
 "params": {"name": "get-policy", "arguments": {"tool": "clock"}}}
```

```json
{
  "name": "clock",
  "profile": "llm",
  "allow_dirs_configured": [],
  "network": "disabled - the WASI surface exposes no socket APIs; egress only via a host-side mediator (ADR-002)",
  "security_baseline": {
    "wasmtime_version": "47.0.1",
    "memory_limit_bytes": 134217728,
    "fuel": 2000000,
    "threads_enabled": false,
    "memory64": false,
    "multi_memory": false,
    "preopens": [],
    "gc_heap_mb": null
  },
  "tool": "clock"
}
```

(Capture from a live call on 2026-09-05; only whitespace is prettified.)

`preopens` here reports CONFIGURED grants — no live run has attested more
than that. The per-call attested grants come from
`_meta.execution.security_baseline.preopens`: a preview1 execution
additionally attests `/sandbox` (the guest scratch directory) even when no
other directory is configured. The executed baseline is the authoritative
record. Without arguments, `get-policy` returns this entry for every
registry tool plus the server identity and the native tool list.

## The stdin/stdout contract for tool authors

A WASM MCP tool is a plain WASI module (wasm32-wasip1 or WASI 0.2
component) with one contract:

1. **stdin:** exactly one JSON document `{"params": <tool arguments>}`.
   Arguments can be any JSON value (object, array, string, ...). Host-side
   stdin is capped at 9 216 bytes (`ephemora_cell.STDIN_MAX_BYTES`); larger
   payloads must come via a preopened file.
2. **stdout:** on success exactly one JSON value (any shape), exit code 0.
   Output is byte-capped at 10 KB by the Cell (ENOSPC budget) — keep results
   small.
3. **Failure convention:** a tool that parses but rejects its input writes a
   JSON object with a string `"error"` key to stdout (exit 0 or non-zero);
   the server answers `isError: true`. A non-zero exit or Cell failure
   (fuel/timeout/memory) also produces `isError: true` with status + message.

The bundled `echo` tool is a complete reference implementation in
`ephemora_cell_mcp/tools_src/echo/` (dependency-free Rust, no crates.io fetch):

```bash
cd ephemora_cell_mcp/tools_src/echo
cargo build --release --target wasm32-wasip1
cp target/wasm32-wasip1/release/echo.wasm ../../tools/echo.wasm
```

## Tool registry convention

`Server(tools_dir="tools")` scans a directory:

- `tools/<toolname>.wasm` → a tool named `<toolname>`.
- `tools/<toolname>.json` (optional) → MCP metadata:
  `name`, `description`, `input_schema`, `profile`, `allow_dirs`.

```json
{
  "name": "echo",
  "description": "Echoes its arguments back",
  "input_schema": {"type": "object", "properties": {}},
  "profile": "llm",
  "allow_dirs": []
}
```

Defaults without a sidecar: description `Executes <toolname>`, generic
`{"type": "object"}` input schema, profile `"llm"`, **no** preopened
directories.

- **Profiles** map to the Cell's `SandboxProfile` (`plugin`, `llm`, `edge`,
  `default`): memory, fuel and timeout budgets per tool. `"llm"` is the
  default (128 MB / 2 000 000 fuel / 30 s).
- **`allow_dirs` is granted only through the sidecar** — the server never
  invents file access. Granting a directory means the tool gets full
  read/write access to it; forbidden host locations (`/etc`, `/usr`, ...)
  are rejected by the Cell regardless.

## Integrating with MCP clients

MCP is the industry-standard tool surface: any client that speaks the stdio
transport can mount `ephemora-cell-mcp` and get sandboxed, verifiable tools. The
config snippets below cover the mainstream clients. `EPHEMORA_BIN` =
the absolute path to the `ephemora-cell-mcp` entry point (or
`<python> -m ephemora_cell_mcp`).

### Claude Desktop

`claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ephemora": {
      "command": "/absolute/path/to/.venv/bin/python",
      "args": ["-m", "ephemora_cell_mcp", "--tools-dir", "/absolute/path/to/tools"],
      "env": {}
    }
  }
}
```

Use the absolute path to the Python interpreter that has `ephemora-cell`
installed (the command's `cwd` is not the server's — point `--tools-dir` at
an absolute path).

### Generic MCP clients / SDKs

Any MCP client that supports the stdio transport with the
`2025-06-18` protocol version works: `command` = your Python, `args` =
`["-m", "ephemora_cell_mcp", "--tools-dir", "<abs>"]`. Alternatively use the
installed entry point directly (same process, no interpreter prefix):

```bash
ephemora-cell-mcp --tools-dir /absolute/path/to/tools
```

Programmatic use (embedding, tests):

```python
from ephemora_cell_mcp import Server

server = Server(tools_dir="tools")
server.serve()  # stdio loop; in-process: server.handle_line(line)
```

### Hermes Desktop (Nous Research)

Hermes Agent ships with full MCP client support (stdio + HTTP). Register the
server once, tools are discovered at startup (`/reload-mcp` reloads):

```bash
hermes mcp add ephemora --command <EPHEMORA_BIN>
hermes mcp test ephemora          # verify connection + discovery
```

Or declaratively in `~/.hermes/config.yaml`:

```yaml
mcp_servers:
  ephemora:
    command: <EPHEMORA_BIN>
    enabled: true
    # optional: tools:
    #   include: [echo, compute]   # per-server filtering
```

**One-click install link:** Hermes supports an "Add to Hermes" deeplink
(`hermes://mcp/install?name=NAME&config=<base64url-json>`) that opens the
desktop app with a pre-filled server config for explicit user confirmation.
A landing page or README badge can host this link for `ephemora`:

```
hermes://mcp/install?name=ephemora&config=<base64url of {"command":"<EPHEMORA_BIN>"}>
```

### OpenAI Codex CLI / Desktop

Codex reads MCP servers from `~/.codex/config.toml`:

```toml
[mcp_servers.ephemora]
command = "<EPHEMORA_BIN>"
```

### Visual Studio Code (Copilot)

Fastest path (Copilot in VS Code picks the server up immediately; use the
reload button in the chat's tool panel if it does not):

```bash
code --add-mcp '{"name":"Ephemora Cell","command":"ephemora-cell-mcp"}'
```

VS Code also mounts MCP servers via `.vscode/mcp.json` (workspace) or the
Copilot settings (user scope):

```json
{
  "servers": {
    "ephemora": { "command": "<EPHEMORA_BIN>" }
  }
}
```

### OpenCode

`opencode.json` `mcp` block (local project) or `~/.config/opencode/opencode.json` (user):

```json
{
  "mcp": {
    "ephemora": { "type": "local", "command": ["<EPHEMORA_BIN>"], "enabled": true }
  }
}
```

### mcp CLI (reference client)

```bash
npx @modelcontextprotocol/inspector -- <EPHEMORA_BIN>   # interactive UI
mcp dev <EPHEMORA_BIN>                                   # MCP developer CLI
```

### Compatibility map

| Client | Config location | Transport | Verified |
|---|---|---|---|
| Hermes Desktop / Agent | `~/.hermes/config.yaml` `mcp_servers` | stdio | ✅ (this repo, 2026-08-20) |
| Official MCP Python SDK | any | stdio | ✅ (this repo, 2026-08-20) |
| Claude Desktop | `claude_desktop_config.json` | stdio | config documented (not installed locally) |
| OpenAI Codex | `~/.codex/config.toml` | stdio | config documented |
| VS Code (Copilot) | `.vscode/mcp.json` | stdio | config documented |
| OpenCode | `opencode.json` `mcp` | local stdio | config documented |
| mcp inspector / dev CLI | n/a | stdio | config documented |

### Local verification results (2026-08-20)

- **Official MCP Python SDK** client (`mcp.ClientSession` via `stdio_client`)
  against `ephemora-cell-mcp`: `initialize` → `ephemora-cell-mcp 0.1.0`,
  protocol `2025-06-18`; `tools/list` → `['echo']`; `tools/call` → echoed
  payload; `_meta.execution` carried status `success`, fuel
  `21646 / 2000000`, `34.68 ms`, `wasmtime 47.0.1`.
- **Hermes Desktop** (`hermes mcp add` + `hermes mcp test`): `Connected
  (332ms)`, `Tools discovered: 1` (`echo`), saved to `~/.hermes/config.yaml`
  with 1/1 tools enabled.
- **Bundled `clock` tool** (2026-09-05): `tools/list` → `['clock', 'echo']`;
  `tools/call clock` returned `{"utc": "...", "unix_ms": ...}` matching the
  host UTC clock to the second; `_meta.execution`: status `success`, exit 0,
  fuel 22,841 / 2,000,000, wasmtime 47.0.1.

## Comparison: naive MCP tool vs. Ephemora Cell tool

MCP servers commonly run tools **in-process with full host privileges**. The
same tool shape executed as a WASM module inside the Cell has no such
access. Measured on this machine (2026-08-20):

| Capability | Naive MCP tool (host process) | `ephemora-cell-mcp` tool (Cell) |
|---|---|---|
| Read `/etc/passwd` | ✅ read (host file) | ❌ blocked (no preopen, default deny) |
| Env access | ✅ full `environ` (PATH, Homebrew, …) | ❌ none (`allow_env` off by default) |
| `os.system` / shell | ✅ would run | ❌ no exec in WASI Preview1 |
| Network | ✅ would connect | ❌ no socket imports |
| Resource limits | none (host rules) | ✅ fuel + memory + timeout per profile |
| Output | unbounded | ✅ 10 KB byte budget (ENOSPC) |
| Per-call witness | none | ✅ `_meta.execution` (fuel, ms, baseline) |

The naive server above read `/etc/passwd` and dumped the host environment —
a single compromised or hallucinated tool call leaks the machine. The Cell
version cannot: the guest never sees those capabilities. That is the
security gap MCP-SandboxScan (arXiv 2601.01241) formalizes for the agent
tool supply chain.

## Security notes — what the Cell guarantees (and what it does not)

**Guaranteed by the Cell for every tool execution:**

- **No network** — WASI Preview1 has no socket imports; the sandbox engine
  enables no sockets, no shell, no process spawning.
- **Determinism** — fuel metering (`fuel_consumed` per call, per profile),
  no threads (`wasm_threads = False`), no environment variables unless
  explicitly forwarded, no host filesystem unless explicitly preopened.
- **Bounded output** — 10 KB stdout/stderr byte budget (ENOSPC), host-owned
  capture files the guest cannot tamper with.
- **Attack-vector closure** — the 8 documented vectors (shell, fork,
  network, fsync, host FS, symlink escape, threading, env) are verified
  blocked (reproducible via `benchmarks/verify_8_vectors.py`).

**What the Cell does NOT guarantee:**

- The *host process* (`ephemora-cell-mcp`) is ordinary Python — it is not
  sandboxed. It validates tool names and JSON-RPC framing, but a malicious
  WASM tool cannot escape the Cell to attack the host; a compromised host
  process can do anything it wants.
- Tools are trusted per-metadata: an `allow_dirs` grant is a real
  read/write capability. Do not ship tools with directory grants you have
  not audited.
- The MCP protocol layer is deliberately minimal (initialize / tools/list /
  tools/call). It does not implement sampling, resources, prompts or
  `tools/notifications` — unsupported methods are rejected with `-32601`.