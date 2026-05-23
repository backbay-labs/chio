"""Hermes Agent plugin for the Chio protocol.

Routes Hermes file/shell/git tool calls through the Chio sidecar so
policy enforcement and signed receipts apply uniformly. Hermes
discovers the plugin via the ``hermes_agent.plugins`` entry point and
calls :func:`register` once per process. No I/O happens at import time;
the :class:`ChioClient` is connected lazily on first tool dispatch.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

from chio_hermes.plugin import ChioHermesPlugin, register

try:
    __version__ = _pkg_version("chio-hermes")
except PackageNotFoundError:
    # Source-tree import has no installed dist-info; mirror pyproject.
    __version__ = "0.1.1"

__all__ = [
    "ChioHermesPlugin",
    "__version__",
    "register",
]
