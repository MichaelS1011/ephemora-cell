"""Daily traction snapshot: PyPI downloads + GitHub stars/forks/traffic.

Appends one JSONL line per UTC date to metrics/history.jsonl (idempotent:
re-running the same date replaces that line). Sources are public
endpoints. The GitHub traffic endpoints reject the Actions GITHUB_TOKEN
regardless of the workflow's permissions block (they require repository
write/administration access, which GITHUB_TOKEN cannot be granted), so a
dedicated TRAFFIC_TOKEN secret (fine-grained PAT with Administration:
read-only on this repo, or a classic PAT with repo scope) is used for
them when present; without it the traffic values are recorded as null
and the snapshot still succeeds, so the scheduled job never fails on
data-source hiccups. Runs from .github/workflows/metrics.yml
(etiquette: one pypistats call per day).

No in-package telemetry: this measures the PUBLIC distribution channels
only. Cell itself never phones home.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

PYPI_PACKAGE = "ephemora-cell"
GITHUB_REPO = "MichaelS1011/ephemora-cell"
OUT = Path("metrics/history.jsonl")
BADGE_OUT = Path("metrics/clones.json")
DOWNLOADS_BADGE_OUT = Path("metrics/downloads.json")

# pypistats etiquette: a single daily run should never hammer the endpoint.
# On a transient 429/5xx we back off and retry a few times; if it still fails
# the caller keeps the last-known-good badge (see _update_*_badge null guards),
# so a rate-limit degrades to "badge shows yesterday's number", never a crash
# and never a blanked/public-reset metric. GET is idempotent, so retry is safe.
_PYPI_RETRIES = 4
_PYPI_BASE_BACKOFF_S = (
    3.0  # ponytail: fixed backoff, no jitter; add jitter if multiple publishers
)
#                                             # share this endpoint. Only ONE publisher exists today.


def _get_pypi_with_backoff(url: str) -> dict:
    """GET a PyPI stats URL, retrying 429/5xx with exponential backoff.

    Returns the parsed body on success; raises the last error if all attempts
    fail (caller degrades to last-known-good). 404 is treated as a hard miss
    (package truly unknown) and is NOT retried.
    """
    last: Exception | None = None
    for attempt in range(_PYPI_RETRIES):
        try:
            return _get(url)
        except urllib.error.HTTPError as e:  # nosec B310 - fixed https host, see _get
            last = e
            if e.code == 404:  # hard miss: package not found; don't retry
                raise
            if e.code not in (429, 403, 500, 502, 503):
                raise  # non-transient (e.g. 4xx auth) — don't burn retries
        except Exception as e:  # urlopen network blip — retry
            last = e
        if attempt < _PYPI_RETRIES - 1:
            time.sleep(_PYPI_BASE_BACKOFF_S * (2**attempt))  # 3,6,12s
    assert last is not None  # loop ran >=1 attempt; _PYPI_RETRIES>=1
    raise last


def _update_clones_badge(snap: dict) -> None:
    """Refresh metrics/clones.json (shields.io endpoint schema) from live
    clone data. On null-tolerant runs (no TRAFFIC_TOKEN) any previous badge
    file is left untouched, so the README keeps its last known value."""
    clones = (snap.get("github") or {}).get("clones_14d") or {}
    count = clones.get("count")
    if count is None:
        return
    BADGE_OUT.parent.mkdir(parents=True, exist_ok=True)
    BADGE_OUT.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "label": "clones (14d)",
                "message": str(count),
                "color": "blue",
            }
        )
        + "\n",
        encoding="utf-8",
    )


def _update_downloads_badge(snap: dict) -> None:
    """Refresh metrics/downloads.json (shields.io endpoint schema) from live
    PyPI data — the README badge reads this instead of shields' pypistats
    source, so a pypistats rate limit can never render an error string on
    the README. On a failed pypistats fetch the previous badge file is left
    untouched, so the README keeps its last known value."""
    last_month = (snap.get("pypi") or {}).get("last_month")
    if last_month is None:
        return
    DOWNLOADS_BADGE_OUT.parent.mkdir(parents=True, exist_ok=True)
    DOWNLOADS_BADGE_OUT.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "label": "downloads (30d)",
                "message": f"{last_month:,}".replace(",", " "),
                "color": "blue",
            }
        )
        + "\n",
        encoding="utf-8",
    )


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
        recent = _get_pypi_with_backoff(
            f"https://pypistats.org/api/packages/{PYPI_PACKAGE}/recent"
        )["data"]
        per_day = _get_pypi_with_backoff(
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
        # Traffic-only token: GITHUB_TOKEN is structurally rejected here.
        traffic_token = os.environ.get("TRAFFIC_TOKEN") or token
        try:
            traffic = _get(
                f"https://api.github.com/repos/{GITHUB_REPO}/{path}", traffic_token
            )
            snap["github"][f"{key}_14d"] = {
                "count": traffic.get("count"),
                "uniques": traffic.get("uniques"),
            }
        except Exception as e:
            snap["github"][f"{key}_14d"] = None
            snap["github"][f"{key}_error"] = f"{type(e).__name__}: {e}"[:120]


def _conversion_context(snap: dict, token: str | None) -> None:
    """Correlation fields for demand attribution: which commit and which
    release was live when this snapshot was taken. Lets the JSONL history
    answer "what changed the day before a spike" without archaeology.
    Null-tolerant like every other source."""
    ctx: dict = {}
    try:
        head = _get(f"https://api.github.com/repos/{GITHUB_REPO}/commits/main", token)
        ctx["git_head_sha"] = (head.get("sha") or "")[:12]
        ctx["git_head_message"] = (
            (head.get("commit", {}).get("message") or "").splitlines() or [""]
        )[0][:120]
    except Exception as e:
        ctx["git_head_error"] = f"{type(e).__name__}: {e}"[:120]
    try:
        release = _get(
            f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest", token
        )
        ctx["latest_release_tag"] = release.get("tag_name")
    except Exception as e:
        ctx["latest_release_error"] = f"{type(e).__name__}: {e}"[:120]
    try:
        with urllib.request.urlopen(  # nosec B310 - https pinned below
            f"https://pypi.org/pypi/{PYPI_PACKAGE}/json", timeout=30
        ) as r:
            ctx["pypi_latest_version"] = json.load(r).get("info", {}).get("version")
    except Exception as e:
        ctx["pypi_latest_version_error"] = f"{type(e).__name__}: {e}"[:120]
    snap["context"] = ctx


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
    _conversion_context(snap, token)
    _update_clones_badge(snap)
    _update_downloads_badge(snap)

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


def _self_check() -> None:
    """Assert-based guard for the 429 backoff logic (no pytest)."""
    import urllib.error

    calls = {"n": 0}

    def flaky_429(url, token=None, timeout=30):
        calls["n"] += 1
        if calls["n"] < 3:  # fail twice with 429, then succeed
            raise urllib.error.HTTPError(
                url=url, code=429, msg="Too Many Requests", hdrs=None, fp=None
            )
        return {"ok": True}

    orig = _get
    try:
        globals()["_get"] = flaky_429
        globals()["_PYPI_BASE_BACKOFF_S"] = 0.0  # fast test path
        assert _get_pypi_with_backoff("https://pypistats.org/x") == {"ok": True}
        assert calls["n"] == 3, calls  # proves it retried through two 429s

        # 404 = hard miss, must NOT retry
        calls["n"] = 0

        def hard_404(url, token=None, timeout=30):
            calls["n"] += 1
            raise urllib.error.HTTPError(
                url=url, code=404, msg="Not Found", hdrs=None, fp=None
            )  # type: ignore

        globals()["_get"] = hard_404
        try:
            _get_pypi_with_backoff("https://pypistats.org/y")
            raise AssertionError("404 should have raised")
        except urllib.error.HTTPError as e:
            assert e.code == 404
        assert calls["n"] == 1, calls  # proves no retry on 404
    finally:
        globals()["_get"] = orig
    print("self-check: 429-retry + 404-hard-miss OK")


if __name__ == "__main__":
    _self_check()
    raise SystemExit(main())
