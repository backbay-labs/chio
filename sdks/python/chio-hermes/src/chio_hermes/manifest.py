"""Tool manifest table and `ToolEntry` dataclass.

`TOOL_TABLE` is the single source of truth consumed by
`plugin.register`. Each entry binds a Hermes tool name to its JSON
Schema, a one-line description, and a factory that produces the async
handler for that tool when given a :class:`RuntimeHandle`.

Handlers themselves live in :mod:`chio_hermes.handlers`; keeping the
factory functions out of this module keeps the manifest cheap to
import for tests that only need the table shape.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from chio_hermes.handlers import (
    _factory_file_edit,
    _factory_file_list,
    _factory_file_read,
    _factory_file_search,
    _factory_file_write,
    _factory_git_add,
    _factory_git_commit,
    _factory_git_diff,
    _factory_git_log,
    _factory_git_run,
    _factory_git_status,
    _factory_shell_run,
)
from chio_hermes.schemas import SCHEMAS

if TYPE_CHECKING:
    from chio_hermes.runtime import RuntimeHandle

ToolHandler = Callable[..., Awaitable[str]]
"""Async handler signature accepted by `ctx.register_tool(..., is_async=True)`."""


@dataclass(frozen=True)
class ToolEntry:
    """Single row in :data:`TOOL_TABLE`.

    Attribute access (rather than tuple unpacking) lets `plugin.register`
    iterate without positional indexing and lets tests assert on
    individual fields.
    """

    name: str
    schema: dict[str, Any]
    description: str
    factory: Callable[[RuntimeHandle], ToolHandler]


TOOL_TABLE: list[ToolEntry] = [
    ToolEntry(
        name="chio_file_read",
        schema=SCHEMAS["chio_file_read"],
        description="Read a file inside the workspace root via Chio policy.",
        factory=_factory_file_read,
    ),
    ToolEntry(
        name="chio_file_write",
        schema=SCHEMAS["chio_file_write"],
        description="Write text content to a file via Chio policy.",
        factory=_factory_file_write,
    ),
    ToolEntry(
        name="chio_file_edit",
        schema=SCHEMAS["chio_file_edit"],
        description="Apply a unified diff to a file via Chio policy.",
        factory=_factory_file_edit,
    ),
    ToolEntry(
        name="chio_file_list",
        schema=SCHEMAS["chio_file_list"],
        description="List entries in a directory via Chio policy.",
        factory=_factory_file_list,
    ),
    ToolEntry(
        name="chio_file_search",
        schema=SCHEMAS["chio_file_search"],
        description="Search files by glob via Chio policy.",
        factory=_factory_file_search,
    ),
    ToolEntry(
        name="chio_shell_run",
        schema=SCHEMAS["chio_shell_run"],
        description="Run a shell command (argv-tokenised) via Chio policy.",
        factory=_factory_shell_run,
    ),
    ToolEntry(
        name="chio_git_status",
        schema=SCHEMAS["chio_git_status"],
        description="Run `git status --porcelain` via Chio policy.",
        factory=_factory_git_status,
    ),
    ToolEntry(
        name="chio_git_diff",
        schema=SCHEMAS["chio_git_diff"],
        description="Run `git diff` (optionally constrained to paths).",
        factory=_factory_git_diff,
    ),
    ToolEntry(
        name="chio_git_log",
        schema=SCHEMAS["chio_git_log"],
        description="Run `git log` with a configurable entry limit.",
        factory=_factory_git_log,
    ),
    ToolEntry(
        name="chio_git_add",
        schema=SCHEMAS["chio_git_add"],
        description="Stage paths with `git add`.",
        factory=_factory_git_add,
    ),
    ToolEntry(
        name="chio_git_commit",
        schema=SCHEMAS["chio_git_commit"],
        description="Create a git commit with the provided message.",
        factory=_factory_git_commit,
    ),
    ToolEntry(
        name="chio_git_run",
        schema=SCHEMAS["chio_git_run"],
        description="Run an arbitrary `git ...` command via Chio policy.",
        factory=_factory_git_run,
    ),
]


__all__ = ["TOOL_TABLE", "ToolEntry", "ToolHandler"]
