# Glama safety/quality check: build + smoke-test the stdio MCP server.
# ponytail: minimal install-from-repo image; if Glama wants a PyPI-pinned
# base later, swap `pip install .` for `pip install ephemora-cell==<ver>`.
# Base pinned by digest (resolved 2026-10-05 from the registry's
# Docker-Content-Digest for the multi-arch index of this tag; re-resolve with
#   curl -sI -H "Authorization: Bearer $TOKEN" -H "Accept: application/vnd.oci.image.index.v1+json," \
#     https://index.docker.io/v2/library/python/manifests/3.12-slim | grep -i docker-content-digest
# `3.12-slim` is the tag this digest was taken for — the comment is the
# human-readable half, the digest is what the build actually pulls.
FROM python:3.12-slim@sha256:02108f5d322dd89f1c9e552442c25acb0543dfdbc455693a5599624f20d9155d

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir . \
    && useradd --create-home --shell /usr/sbin/nologin cell

# stdio JSON-RPC 2.0 server; the console script bundles echo.wasm + clock.
# No network, no host fs — runs the bundled WASI sandbox. Never root.
USER cell
ENTRYPOINT ["ephemora-cell-mcp"]
