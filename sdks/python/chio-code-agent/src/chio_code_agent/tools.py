"""Pre-built :class:`FileTool`, :class:`ShellTool`, and :class:`GitTool`.

These wrappers sit between an MCP-style coding agent (Claude Code,
Cursor, a custom CLI) and the Chio sidecar. Each operation:

1. Runs a local pre-flight check against :class:`CodeAgentPolicy` so
   locally-denied calls fail without a sidecar round-trip (and so the
   package works for unit tests without a live kernel).
2. Calls ``ChioClient.evaluate_tool_call`` to get a signed receipt.
3. Executes the wrapped I/O only after an allow verdict comes back.

The tools do not execute the underlying I/O themselves by default --
that is delegated to an ``executor`` callable the host passes in. This
keeps the SDK framework-agnostic and usable from async or sync code.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from chio_sdk.errors import ChioDeniedError
from chio_sdk.models import ChioReceipt

from chio_code_agent.errors import (
    ChioCodeAgentDeniedError,
    ChioCodeAgentError,
)
from chio_code_agent.policy import CodeAgentPolicy, DEFAULT_POLICY


class _ChioClientLike(Protocol):
    """Structural type for :class:`chio_sdk.ChioClient` and its mock."""

    async def evaluate_tool_call(
        self,
        *,
        capability_id: str,
        tool_server: str,
        tool_name: str,
        parameters: dict[str, Any],
    ) -> ChioReceipt: ...


# ---------------------------------------------------------------------------
# Executors
# ---------------------------------------------------------------------------


Executor = Callable[..., Any]
"""Callable shape ``(**kwargs) -> Any | Awaitable[Any]`` that performs
the underlying I/O after the Chio verdict is allow."""


# ---------------------------------------------------------------------------
# Result containers
# ---------------------------------------------------------------------------


@dataclass
class ToolInvocation:
    """Result of a successful tool invocation.

    Attributes
    ----------
    result:
        Whatever the ``executor`` returned.
    receipt:
        The signed Chio receipt returned by the sidecar.
    """

    result: Any
    receipt: ChioReceipt


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------


class _BaseChioTool:
    """Shared plumbing for all code-agent tool wrappers."""

    SERVER_ID: str = ""

    def __init__(
        self,
        *,
        chio_client: _ChioClientLike,
        capability_id: str,
        policy: CodeAgentPolicy | None = None,
        cwd: Path | None = None,
    ) -> None:
        self._chio_client = chio_client
        self._capability_id = capability_id
        self._policy = policy or DEFAULT_POLICY
        self._cwd = (cwd or Path.cwd()).resolve()

    @property
    def policy(self) -> CodeAgentPolicy:
        return self._policy

    @property
    def cwd(self) -> Path:
        return self._cwd

    async def _evaluate(
        self,
        *,
        tool_name: str,
        parameters: dict[str, Any],
    ) -> ChioReceipt:
        if not self._policy.is_tool_allowed(self.SERVER_ID, tool_name):
            raise ChioCodeAgentDeniedError(
                f"tool {self.SERVER_ID}/{tool_name!r} is not permitted by the default policy",
                tool_name=tool_name,
                reason="not_in_allow_list",
                guard="tool_access",
            )
        try:
            receipt = await self._chio_client.evaluate_tool_call(
                capability_id=self._capability_id,
                tool_server=self.SERVER_ID,
                tool_name=tool_name,
                parameters=parameters,
            )
        except ChioDeniedError:
            raise
        if not receipt.is_allowed:
            decision = receipt.decision
            raise ChioDeniedError(
                decision.reason
                if decision is not None and decision.reason is not None
                else "non-authorizing Chio receipt",
                guard=decision.guard if decision is not None else None,
                reason=decision.reason if decision is not None else None,
                tool_name=tool_name,
                tool_server=self.SERVER_ID,
                receipt_id=receipt.id,
            )
        return receipt

    @staticmethod
    async def _run_executor(
        executor: Executor | None, **kwargs: Any
    ) -> Any:
        if executor is None:
            return None
        result: Any = executor(**kwargs)
        if asyncio.iscoroutine(result) or isinstance(result, Awaitable):
            return await result
        return result


# ---------------------------------------------------------------------------
# FileTool
# ---------------------------------------------------------------------------


class FileTool(_BaseChioTool):
    """File I/O wrapper: read, write, list, search, edit.

    Each public method first runs the local pre-flight (``check_read``
    / ``check_write``) and then asks the sidecar for a receipt. Only
    after an allow verdict is the ``executor`` invoked.
    """

    SERVER_ID = "fs"

    async def read_file(
        self,
        path: str,
        *,
        executor: Executor | None = None,
    ) -> ToolInvocation:
        """Read a file from disk after the sidecar approves the call."""
        self._policy.check_read(path, cwd=self._cwd)
        receipt = await self._evaluate(
            tool_name="read_file",
            parameters={"path": path},
        )
        result = await self._run_executor(
            executor or _default_read_file,
            path=path,
            cwd=self._cwd,
        )
        return ToolInvocation(result=result, receipt=receipt)

    async def write_file(
        self,
        path: str,
        content: str,
        *,
        executor: Executor | None = None,
    ) -> ToolInvocation:
        """Write ``content`` to ``path`` after pre-flight + sidecar allow."""
        self._policy.check_write(path, cwd=self._cwd)
        receipt = await self._evaluate(
            tool_name="write_file",
            parameters={"path": path, "bytes": len(content)},
        )
        result = await self._run_executor(
            executor or _default_write_file,
            path=path,
            content=content,
            cwd=self._cwd,
        )
        return ToolInvocation(result=result, receipt=receipt)

    async def edit_file(
        self,
        path: str,
        patch: str,
        *,
        executor: Executor | None = None,
    ) -> ToolInvocation:
        """Apply a patch to an existing file."""
        self._policy.check_write(path, cwd=self._cwd)
        receipt = await self._evaluate(
            tool_name="edit_file",
            parameters={"path": path, "bytes": len(patch)},
        )
        result = await self._run_executor(
            executor, path=path, patch=patch, cwd=self._cwd
        )
        return ToolInvocation(result=result, receipt=receipt)

    async def list_directory(
        self,
        path: str,
        *,
        executor: Executor | None = None,
    ) -> ToolInvocation:
        """List entries in a directory."""
        self._policy.check_read(path, cwd=self._cwd)
        receipt = await self._evaluate(
            tool_name="list_directory",
            parameters={"path": path},
        )
        result = await self._run_executor(
            executor, path=path, cwd=self._cwd
        )
        return ToolInvocation(result=result, receipt=receipt)

    async def search_files(
        self,
        query: str,
        *,
        path: str = ".",
        executor: Executor | None = None,
    ) -> ToolInvocation:
        """Search for files by name."""
        self._policy.check_read(path, cwd=self._cwd)
        receipt = await self._evaluate(
            tool_name="search_files",
            parameters={"path": path, "query": query},
        )
        result = await self._run_executor(
            executor, path=path, query=query, cwd=self._cwd
        )
        return ToolInvocation(result=result, receipt=receipt)


def _default_read_file(path: str, cwd: Path) -> str:
    target = Path(path)
    if not target.is_absolute():
        target = cwd / target
    return target.read_text(encoding="utf-8")


def _default_write_file(path: str, content: str, cwd: Path) -> int:
    target = Path(path)
    if not target.is_absolute():
        target = cwd / target
    target.parent.mkdir(parents=True, exist_ok=True)
    return target.write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# ShellTool
# ---------------------------------------------------------------------------


@dataclass
class ShellResult:
    """Result of a shell execution via :class:`ShellTool`."""

    command: str
    approval_required: bool
    output: Any


class ShellTool(_BaseChioTool):
    """Shell command wrapper with approval and deny-list enforcement.

    The pre-flight raises :class:`ChioCodeAgentDeniedError` for
    commands matching the deny list. Commands that match the
    approval-required list return a result whose ``approval_required``
    flag is ``True``; it is up to the host to prompt the user before
    running them. Anything that is neither denied nor flagged is
    treated as safe.
    """

    SERVER_ID = "shell"

    async def run_command(
        self,
        command: str,
        *,
        executor: Executor | None = None,
        approved: bool | None = None,
    ) -> ToolInvocation:
        """Run ``command`` via the supplied ``executor``.

        Parameters
        ----------
        command:
            Shell command as a single string.
        executor:
            Callable invoked with ``command=...`` after the verdict is
            allow.
        approved:
            When a command matches the approval-required list, pass
            ``True`` to confirm the user has approved. If the list is
            matched and ``approved`` is not ``True``, the call is
            denied locally.
        """
        approval_required = self._policy.check_shell(command)
        if approval_required and approved is not True:
            raise ChioCodeAgentDeniedError(
                f"shell command {command!r} requires explicit approval",
                tool_name="run_command",
                reason="approval_required",
                guard="shell_command",
            )
        receipt = await self._evaluate(
            tool_name="run_command",
            parameters={
                "command": command,
                "approved": bool(approved) if approved is not None else False,
            },
        )
        output = await self._run_executor(executor, command=command)
        return ToolInvocation(
            result=ShellResult(
                command=command,
                approval_required=approval_required,
                output=output,
            ),
            receipt=receipt,
        )


# ---------------------------------------------------------------------------
# GitTool
# ---------------------------------------------------------------------------


class GitTool(_BaseChioTool):
    """Git wrapper that blocks ``git push --force`` and friends.

    Read-only commands (``status``, ``diff``, ``log``) are allowed
    straight through. Mutating commands (``add``, ``commit``) run
    through the sidecar. ``push --force`` / ``reset --hard origin``
    are denied outright by :meth:`CodeAgentPolicy.check_git`.
    """

    SERVER_ID = "git"

    async def status(
        self,
        *,
        executor: Executor | None = None,
    ) -> ToolInvocation:
        return await self._simple("status", {}, executor)

    async def diff(
        self,
        *,
        paths: list[str] | None = None,
        executor: Executor | None = None,
    ) -> ToolInvocation:
        return await self._simple(
            "diff", {"paths": paths or []}, executor, paths=paths
        )

    async def log(
        self,
        *,
        limit: int = 20,
        executor: Executor | None = None,
    ) -> ToolInvocation:
        return await self._simple(
            "log", {"limit": limit}, executor, limit=limit
        )

    async def add(
        self,
        paths: list[str],
        *,
        executor: Executor | None = None,
    ) -> ToolInvocation:
        for p in paths:
            self._policy.check_write(p, cwd=self._cwd)
        return await self._simple(
            "add", {"paths": list(paths)}, executor, paths=paths
        )

    async def commit(
        self,
        message: str,
        *,
        executor: Executor | None = None,
    ) -> ToolInvocation:
        return await self._simple(
            "commit", {"message": message}, executor, message=message
        )

    async def run(
        self,
        command: str,
        *,
        executor: Executor | None = None,
    ) -> ToolInvocation:
        """Run an arbitrary git command string (use for push/fetch/etc).

        The command is passed through :meth:`CodeAgentPolicy.check_git`
        and also through the shell deny list before being evaluated by
        the sidecar.
        """
        self._policy.check_git(command)
        self._policy.check_shell(command)
        return await self._simple(
            "run", {"command": command}, executor, command=command
        )

    async def _simple(
        self,
        tool_name: str,
        parameters: dict[str, Any],
        executor: Executor | None,
        **executor_kwargs: Any,
    ) -> ToolInvocation:
        receipt = await self._evaluate(
            tool_name=tool_name, parameters=parameters
        )
        result = await self._run_executor(executor, **executor_kwargs)
        return ToolInvocation(result=result, receipt=receipt)


__all__ = [
    "Executor",
    "FileTool",
    "GitTool",
    "ShellResult",
    "ShellTool",
    "ToolInvocation",
    "ChioCodeAgentError",
]
