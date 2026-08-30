# Contributing to Ephemora Cell

## Development Setup

```bash
# Clone the repository
git clone https://github.com/MichaelS1011/ephemora-cell.git
cd ephemora-cell

# Create virtual environment
python3.12 -m venv .venv
source .venv/bin/activate  # Linux/macOS

# Install dependencies
pip install -e ".[dev]"
```

## Running Tests

```bash
# Run all tests
python3.12 -m pytest tests/ -v

# Run with coverage
python3.12 -m pytest tests/ -v --cov=ephemora_cell --cov-report=term-missing

# Run a specific test
python3.12 -m pytest tests/test_disk_quota.py -v
```

## Code Style

- Type hints required for all public functions
- Docstrings in Google style
- Black/Ruff are enforced by CI (`black --check ephemora_cell/ tests/`,
  `ruff check ephemora_cell/ tests/`). Install everything with
  `pip install -e ".[dev]"` (pytest, pytest-cov, black, ruff)

## Commit Conventions

Use conventional commits:
- `feat: add memory limit enforcement`
- `fix: correct fuel metering calculation`
- `docs: update README with arXiv results`
- `test: add path traversal test`
- `refactor: extract WASI config validation`

## Benchmarks & Result Files

Running the benchmark scripts (e.g. `python benchmarks/pool_vs_budget.py`)
writes raw JSON under `benchmarks/results/<date>/` — your working tree will
show these as untracked files. That is intentional:

- **New evidence** (a measurement backing a README/CHANGELOG claim) is
  welcome: commit the dated directory with a `measured:true` JSON and a
  note in your PR describing hardware, dates and command.
- **Throwaway runs** can simply be deleted (`rm -r benchmarks/results/<date>`).
- Per-run result *indexes* (`00_INDEX.md`) and `*.log` files are gitignored
  and stay local.

## Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Commit changes with conventional commit messages
4. Push to your fork (`git push origin feat/my-feature`)
5. Open a Pull Request against `main`
6. All tests must pass before merge

## Reporting Issues

- **Bug reports:** Open a GitHub Issue with reproduction steps
- **Security vulnerabilities:** See [SECURITY.md](SECURITY.md) for the reporting channels — do NOT open public issues
- **Feature requests:** Open a GitHub Issue with the `enhancement` label