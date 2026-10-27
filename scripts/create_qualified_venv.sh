#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# Create a venv with the audited pip and CA bundle, without trusting the
# runner's preinstalled Python packages. The two wheels are downloaded with
# --require-hashes, so a TLS interception cannot substitute them.
set -euo pipefail

venv="${1:?usage: create_qualified_venv.sh <venv-dir> [python]}"
python_bin="${2:-python}"
work="${venv}.bootstrap"

rm -rf "$work"
mkdir -p "$work/wheels"
cat > "$work/tools.txt" <<'EOF'
pip==26.2.2 --hash=sha256:fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70
certifi==2026.10.19 --hash=sha256:42d35340cc5b9ba78e818ddbff0c5b1c2b779de448a340fd1b989f5fa8670e1b
EOF

"$python_bin" -m pip download \
    --disable-pip-version-check \
    --no-deps \
    --only-binary=:all: \
    --require-hashes \
    -r "$work/tools.txt" \
    -d "$work/wheels" >/dev/null

"$python_bin" -m venv "$venv"
"$venv/bin/python" -m pip install \
    --disable-pip-version-check \
    --no-index \
    --no-deps \
    --force-reinstall \
    "$work/wheels"/*.whl >/dev/null

"$venv/bin/python" - <<'PY'
import importlib.metadata as md
import sys

import certifi

MIN_PIP = (26, 2, 2)
MIN_CERTIFI = (2026, 10, 19)


def version_tuple(text: str) -> tuple[int, ...]:
    parts = []
    for part in text.split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts)


pip_version = md.version("pip")
certifi_version = certifi.__version__
if version_tuple(pip_version) < MIN_PIP:
    sys.exit(f"FAIL: pip {pip_version} < 26.2.2")
if version_tuple(certifi_version) < MIN_CERTIFI:
    sys.exit(f"FAIL: certifi {certifi_version} < 2026.10.19")
print(f"qualified venv: pip {pip_version}, certifi {certifi_version}")
PY

rm -rf "$work"
