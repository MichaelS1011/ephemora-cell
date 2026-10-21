# Ephemora Cell — Protected Linux Reference Environment (worker outer wall)
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
#
# Purpose: a concrete, reproducible OUTER security boundary for the
# `ephemora_cell.process_worker` process that runs a protected-component guest.
# The WASI sandbox + worker RLIMITs are the INNER wall (guest resource bounds,
# capability FS, fuel/epoch/IO budgets). THIS container is the OUTER wall the
# worker process itself lives behind, so a native engine fault or a worker-level
# escape lands in a kernel-enforced boundary, not on the host.
#
# Fresh install from the built wheel (reproduces the release artifact path;
# `requirements.lock` carries the sha256-pinned wasmtime==49.0.0 floor).
#
# Base pinned by digest — the same python:3.12-slim digest the repo Dockerfile
# resolves (multi-arch index; re-resolve per docs). The digest is what the build
# pulls; the tag is the human-readable half.
FROM python:3.12-slim@sha256:02108f5d322dd89f1c9e552442c25acb0543dfdbc455693a5599624f20d9155d

# Reproducible, non-interactive, no cache metadata leaking into layers.
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

# Minimal runtime OS deps: the worker needs no build toolchain, no shell utils
# beyond coreutils, and nothing that opens an egress path. `slim` already
# carries the C library the wasmtime native wheel links against.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Dedicated unprivileged user. No login shell, no home write access needed.
# The worker runs as this UID; --cap-drop=ALL + no-new-privileges mean it can
# never regain root inside the container.
RUN groupadd --system --gid 10001 cell \
    && useradd --system --uid 10001 --gid 10001 --shell /usr/sbin/nologin \
         --no-create-home cell

WORKDIR /opt/cell

# Fresh install from the built wheel ONLY (no source tree, no VCS). The wheel is
# copied in by the harness; its sha256 is checked before install.
COPY dist/ /opt/cell/dist/
RUN set -eux; \
    wheel="$(ls /opt/cell/dist/*.whl | head -n1)"; \
    pip install "$wheel"; \
    python -c "import wasmtime, importlib.metadata as m; \
assert m.version('wasmtime').startswith('49.'), m.version('wasmtime'); \
print('engine', m.version('wasmtime'))"

# The worker reads run payload from stdin; drop any world-writable scratch. The
# container runs --read-only with a tmpfs at /tmp; nothing here is writable.
USER cell
ENV HOME=/tmp

# Default command: one protected-worker run driven by stdin payload. The harness
# overrides args per probe. The worker prints a single JSON report to stdout.
ENTRYPOINT ["python", "-m", "ephemora_cell.process_worker"]
