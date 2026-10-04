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

Requires Python >= 3.10 (3.12 recommended). Homebrew's system Python is
PEP 668 externally-managed — always install into the venv, never with a
bare `pip3 install`.

Alternative with [uv](https://docs.astral.sh/uv/) (no pip in the venv
needed — this is how the maintainer's local `.venv` is managed):

```bash
uv venv --python 3.12
uv pip install -e ".[dev]"
```

## Toolchain Versions

CI verifies the `build` recipes with **Zig 0.13.0**, Go 1.22 and WASI SDK
25. Newer Zig releases change `std` APIs regularly — if a guest build fails
locally, compare `zig version` against the CI pin first (the builder prints
the same hint).

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

## Licensing of Contributions

Ephemora Cell is licensed under the Business Source License 1.1
([LICENSE](LICENSE), BUSL-1.1 — source-available, converting to Apache-2.0
four years after each version's first public release).

By submitting a pull request or patch, you agree that your contribution is
accepted under the project license (BUSL-1.1), and you confirm that:

- you have the right to submit the work under those terms (you wrote it or
  hold the necessary rights), and
- you grant the Licensor a perpetual, irrevocable, worldwide right to
  relicense the contribution (including under future versions of the project
  license and any commercial or open-source license) and to enforce the
  project license.

Contributions of code keep the project's SPDX header
(`# SPDX-License-Identifier: BUSL-1.1`) — do not change it or add conflicting
license notices. If your contribution pulls in third-party code, make sure
its license is compatible and note it in the PR.

## Release Checklist

1. Bump the version in ALL FOUR sources together (they must never drift):
   `pyproject.toml`, `ephemora_cell/__init__.py`,
   `ephemora_cell_mcp/_version.py`, `server.json` (both version fields)
2. Update the CHANGELOG and the README freshness block (latest release,
   security audit, latest evidence dates, tests-passing badge)
3. Tag the release with an ANNOTATED tag (`git tag -a v<version> -m "v<version>"`) — the tag IS a version source (all release tags are annotated)
3a. Running the suite from an installed artifact is supported for the
   behavioural tests: `pip install dist/ephemora_cell-*.tar.gz[dev,tools-signing]`,
   unpack the sdist and run `pytest tests/`. Modules that inspect repository files
   (metadata, `scripts/`, module source text) skip with a stated reason — the full
   suite needs a checkout, and CI runs it from one.
4. `python scripts/check_version_sync.py` must exit 0 (CI enforces this
   in the `security` job — a push with drifted sources fails there). The guard
   treats a bump commit whose sources all agree but whose tag does not exist yet
   as a release in progress (WARNING, exit 0); once the tag is pushed the same
   run is a hard equality check, and a version LOWER than the newest tag fails.
5. Build, upload to PyPI, publish the GitHub release
6. Smoke-test: fresh venv, `pip install ephemora-cell==<version>`,
   `ephemora-cell --version` reports `<version>` (console script — the package has no `__main__`)

Tone rule for docs: numbers speak, adjectives sparingly — measured
claims with evidence links, no marketing adjectives around them.

## Reporting Issues

- **Bug reports:** Open a GitHub Issue with reproduction steps
- **Security vulnerabilities:** See [SECURITY.md](SECURITY.md) for the reporting channels — do NOT open public issues
- **Feature requests:** Open a GitHub Issue with the `enhancement` label