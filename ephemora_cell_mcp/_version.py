"""Single source of truth for the ephemora-cell-mcp package version.

Kept in its own module so ``protocol.SERVER_VERSION`` can import it
without a circular import through ``__init__`` (which imports the server).
"""

__version__ = "1.0.1"
