# Glama safety/quality check: build + smoke-test the stdio MCP server.
# ponytail: minimal install-from-repo image; if Glama wants a PyPI-pinned
# base later, swap `pip install .` for `pip install ephemora-cell==<ver>`.
FROM python:3.12-slim

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir . \
    && useradd --create-home --shell /usr/sbin/nologin cell

# stdio JSON-RPC 2.0 server; the console script bundles echo.wasm + clock.
# No network, no host fs — runs the bundled WASI sandbox. Never root.
USER cell
ENTRYPOINT ["ephemora-cell-mcp"]
