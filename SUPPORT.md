# Support

## How to get help

- **Bug reports & feature requests:**
  [GitHub Issues](https://github.com/MichaelS1011/ephemora-cell/issues) —
  please include your OS, Python version, `wasmtime` version, and a minimal
  reproducing module (WAT is fine).
- **Security vulnerabilities:** do **not** open a public issue — follow
  [SECURITY.md](SECURITY.md) (responsible disclosure, 48 h acknowledgment).
- **Questions & usage:** open a GitHub Discussion or issue tagged `question`.

## What to include

1. What you ran (CLI invocation or code snippet)
2. What you expected vs. what happened
3. The `ExecutionResult` / JSON report (status, exit_code, stderr) — if the
   report is large, attach only `status`, `exit_code`, and `stderr`
4. Environment: `python -c "import ephemora_cell; print(ephemora_cell.__version__)"`

## Scope of support

- Supported: the Python package (`ephemora_cell`), the MCP stdio server
  (`ephemora-cell-mcp`), the CLI (`ephemora-cell`), Python 3.10–3.12 on
  Linux and macOS.
- Best effort: Windows (wasmtime works, but the RLIMIT-based hardening paths
  in the subprocess worker are POSIX-only; Windows falls back gracefully).
- Out of scope: adversarial training data, model integration examples under
  `integration/` (they require external services), and Ephemora (the
  enterprise product) — see its own channels.

## Release cadence

Patch releases ship security fixes promptly (see the upgrade windows in
[SECURITY.md](SECURITY.md)). The changelog is the source of truth for what
changed and why: [CHANGELOG.md](CHANGELOG.md).
