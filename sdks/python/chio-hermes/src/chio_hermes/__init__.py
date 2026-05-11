"""Hermes Agent plugin for the Chio protocol.

This package wires :class:`chio_code_agent.CodeAgent` into the Hermes
Agent tool registry. Every Hermes tool call is routed through the Chio
sidecar so policy enforcement and signed receipts apply uniformly across
file, shell, and git operations.

Public surface:

* :func:`register` -- the Hermes plugin entry-point. Hermes discovers
  the plugin via the ``hermes_agent.plugins`` entry-point group and
  calls ``register(ctx)`` once per process. The function builds the
  runtime handle and registers tools, hooks, the ``hermes chio`` CLI
  subcommand, and the ``/chio`` slash command.
* :class:`ChioHermesPlugin` -- a small dataclass returned by
  :func:`register` for tests; lets a :class:`FakePluginContext` assert
  the registered surface without depending on Hermes internals.
* :data:`__version__` -- the installed package version, resolved via
  :func:`importlib.metadata.version` with a hard-coded fallback for
  source-tree imports.

This module performs no network or filesystem I/O at import time; the
:class:`ChioClient` is connected lazily on first tool dispatch.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

from chio_hermes.plugin import ChioHermesPlugin, register

try:
    __version__ = _pkg_version("chio-hermes")
except PackageNotFoundError:
    # Source-tree import (no installed dist-info); fall back to the
    # version pinned in pyproject.toml.
    __version__ = "0.1.0"

__all__ = [
    "ChioHermesPlugin",
    "__version__",
    "register",
]
