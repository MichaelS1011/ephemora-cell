"""Daily traction snapshot: PyPI downloads + GitHub stars/forks/traffic.

Appends one JSONL line per UTC date to metrics/history.jsonl (idempotent:
re-running the same date replaces that line). Sources are public
endpoints; the GitHub traffic API needs push access and may 403 — a
missing value is recorded as null and the snapshot still succeeds, so the
scheduled job never fails on data-source hiccups. Runs from
.github/workflows/metrics.yml (etiquette: one pypistats call per day).

No in-package telemetry: this measures the PUBLIC distribution channels
only. Cell itself never phones home.
"""

from __future__ import annotations

import json
import os
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

PYPI_PACKAGE = "ephemora-cell"
GITHUB_REPO = "MichaelS1011/ephemora-cell"
OUT = Path("metrics/history.jsonl")


def _get(url: str, token: str | None = None, timeout: int = 30) -> dict:
    # Fixed allowlisted https endpoints only (pypistats.org, api.github.com);
    # no user-controlled URL ever reaches this function.
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-https URL: {url}")
    headers = {"User-Agent": "ephemora-cell-metrics/1.0"}
    # api.github.com rejects the generic vnd.api+json accept type (415).
    headers["Accept"] = (
        "application/vnd.github+json"
        if url.startswith("https://api.github.com")
        else "application/json"
    )
    request = urllib.request.Request(url, headers=headers)
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
        return json.loads(response.read().decode("utf-8"))


def _pypi_snapshot(snap: dict) -> None:
    try:
        recent = _get(f"https://pypistats.org/api/packages/{PYPI_PACKAGE}/recent")[
            "data"
        ]
        per_day = _get(
            f"https://pypistats.org/api/packages/{PYPI_PACKAGE}/overall?mirrors=false"
        ).get("data", [])
        snap["pypi"] = {
            "last_day": recent.get("last_day"),
            "last_week": recent.get("last_week"),
            "last_month": recent.get("last_month"),
            "downloads_without_mirrors_by_day": {
                row["date"]: row["downloads"] for row in per_day
            },
        }
    except Exception as e:
        snap["pypi_error"] = f"{type(e).__name__}: {e}"[:200]


def _github_snapshot(snap: dict, token: str | None) -> None:
    try:
        repo = _get(f"https://api.github.com/repos/{GITHUB_REPO}", token)
        snap["github"] = {
            "stars": repo.get("stargazers_count"),
            "forks": repo.get("forks_count"),
            "open_issues": repo.get("open_issues_count"),
        }
    except Exception as e:
        snap["github_error"] = f"{type(e).__name__}: {e}"[:200]
        return
    for key, path in (("views", "traffic/views"), ("clones", "traffic/clones")):
        try:
            traffic = _get(f"https://api.github.com/repos/{GITHUB_REPO}/{path}", token)
            snap["github"][f"{key}_14d"] = {
                "count": traffic.get("count"),
                "uniques": traffic.get("uniques"),
            }
        except Exception as e:
            snap["github"][f"{key}_14d"] = None
            snap["github"][f"{key}_error"] = f"{type(e).__name__}: {e}"[:120]


def main() -> int:
    now = datetime.now(timezone.utc)
    snap = {
        "date": now.strftime("%Y-%m-%d"),
        "recorded_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "pypi": None,
        "github": None,
    }
    token = os.environ.get("GITHUB_TOKEN")
    _pypi_snapshot(snap)
    _github_snapshot(snap, token)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []
    if OUT.exists():
        for line in OUT.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                if row.get("date") != snap["date"]:
                    rows.append(row)
    rows.append(snap)
    OUT.write_text(
        "\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(snap, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
