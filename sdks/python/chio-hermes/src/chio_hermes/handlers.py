"""Async tool handlers for the chio-hermes plugin.

Each handler is `async def handler(args, **kwargs) -> str` and ALWAYS
returns canonical JSON (sorted keys, no whitespace, ASCII-safe).
Envelope shapes:

* allow:   `{"status":"allowed","result":...,"receipt_id":"...","tool_name":"...","tool_server":"..."}`
* deny:    `{"error":"denied","guard":"...","reason":"...","receipt_id":...}`
* typed:   `{"error":"chio_<slug>","message":"...", ...}`

Slugs: `denied`, `chio_sidecar_unreachable`, `chio_capability_expired`,
`chio_not_configured`, `chio_error`, `chio_executor_error`. Receipts are
recorded by the post_tool_call hook, not here.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from functools import partial
from typing import TYPE_CHECKING, Any

from chio_hermes import executors as _exec

if TYPE_CHECKING:
    from chio_hermes.manifest import ToolEntry, ToolHandler
    from chio_hermes.runtime import RuntimeHandle


def _dumps(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _coerce_jsonable(value: Any) -> Any:
    """Best-effort conversion of CodeAgent results to JSON-friendly shapes."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dict):
        return {str(k): _coerce_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_coerce_jsonable(item) for item in value]
    payload = getattr(value, "__dict__", None)
    if isinstance(payload, dict):
        return {str(k): _coerce_jsonable(v) for k, v in payload.items()}
    return repr(value)


def _receipt_id(invocation: Any) -> str | None:
    receipt = getattr(invocation, "receipt", None)
    return getattr(receipt, "id", None) if receipt is not None else None


def _tool_server_for(tool_name: str) -> str:
    """Map a `chio_<domain>_<verb>` tool name to its sidecar server id."""
    if tool_name.startswith("chio_file_"):
        return "fs"
    if tool_name.startswith("chio_shell_"):
        return "shell"
    if tool_name.startswith("chio_git_"):
        return "git"
    return "unknown"


def _allowed(
    result: Any,
    *,
    receipt_id: str | None,
    tool_name: str,
    tool_server: str,
) -> str:
    payload: dict[str, Any] = {
        "status": "allowed",
        "result": _coerce_jsonable(result),
        "tool_name": tool_name,
        "tool_server": tool_server,
    }
    if receipt_id is not None:
        payload["receipt_id"] = receipt_id
    return _dumps(payload)


def _denied(
    *,
    guard: str | None,
    reason: str | None,
    receipt_id: str | None = None,
    message: str | None = None,
) -> str:
    payload: dict[str, Any] = {
        "error": "denied",
        "guard": guard,
        "reason": reason,
        "receipt_id": receipt_id,
    }
    if message is not None:
        payload["message"] = message
    return _dumps(payload)


def _typed_error(error: str, message: str, **extra: Any) -> str:
    payload: dict[str, Any] = {"error": error, "message": message}
    payload.update(extra)
    return _dumps(payload)


def _wrap_envelope(
    handle: RuntimeHandle,
    tool_name: str,
    inner: Callable[[dict[str, Any]], Awaitable[Any]],
) -> ToolHandler:
    """Standard envelope around a per-tool inner coroutine.

    Catches the chio-code-agent + chio-sdk error hierarchy and a bare
    `Exception`, converting each to the canonical JSON shape. Never
    raises.
    """

    async def handler(args: dict[str, Any] | None = None, **_kwargs: Any) -> str:
        params: dict[str, Any] = dict(args or {})

        if not handle.is_configured():
            message = handle.init_error or (
                "set CHIO_CAPABILITY_ID before invoking Chio tools"
            )
            return _typed_error("chio_not_configured", message)

        # Lazy import keeps chio_code_agent off the import path in
        # degraded mode.
        try:
            from chio_code_agent.errors import (
                ChioCodeAgentDeniedError,
                ChioCodeAgentError,
                ChioCodeAgentPolicyError,
            )
            from chio_sdk.errors import (
                ChioConnectionError,
                ChioDeniedError,
            )
        except Exception as exc:  # noqa: BLE001
            return _typed_error(
                "chio_not_configured", f"chio runtime imports failed: {exc}"
            )

        try:
            invocation = await inner(params)
        except ChioCodeAgentDeniedError as exc:
            return _denied(
                guard=getattr(exc, "guard", None),
                reason=getattr(exc, "reason", None),
                receipt_id=None,
                message=str(exc),
            )
        except ChioDeniedError as exc:
            guard = getattr(exc, "guard", None)
            receipt_id = getattr(exc, "receipt_id", None)
            if guard == "ExpiredCapabilityGuard":
                masked = handle.masked_capability_id()
                return _typed_error(
                    "chio_capability_expired",
                    (
                        f"capability {masked} has expired; "
                        "run `hermes chio issue` to mint a new one"
                    ),
                    guard="ExpiredCapabilityGuard",
                    receipt_id=receipt_id,
                )
            return _denied(
                guard=guard,
                reason=getattr(exc, "reason", None),
                receipt_id=receipt_id,
                message=str(exc),
            )
        except ChioCodeAgentPolicyError as exc:
            return _typed_error("chio_error", str(exc))
        except ChioConnectionError as exc:
            return _typed_error(
                "chio_sidecar_unreachable",
                f"Failed to connect to Chio sidecar at {handle.sidecar_url}: {exc}",
            )
        except ChioCodeAgentError as exc:
            return _typed_error("chio_error", str(exc))
        except Exception as exc:  # noqa: BLE001 - last resort
            receipt_id = getattr(exc, "receipt_id", None)
            if receipt_id is not None:
                return _typed_error(
                    "chio_executor_error",
                    f"{type(exc).__name__}: {exc}",
                    receipt_id=receipt_id,
                )
            return _typed_error("chio_error", f"{type(exc).__name__}: {exc}")

        return _allowed(
            getattr(invocation, "result", invocation),
            receipt_id=_receipt_id(invocation),
            tool_name=tool_name,
            tool_server=_tool_server_for(tool_name),
        )

    return handler


def make_handler(runtime: RuntimeHandle, entry: ToolEntry) -> ToolHandler:
    """Public factory delegating to the per-tool factory on `entry`."""
    return entry.factory(runtime)


def _require(args: dict[str, Any], key: str) -> Any:
    if key not in args:
        raise KeyError(f"missing required argument {key!r}")
    return args[key]


def _agent(handle: RuntimeHandle) -> Any:
    """Narrow `handle.code_agent` from `Any | None` to `Any`.

    The wrapper short-circuits with `chio_not_configured` before the
    inner closure runs, so by this point `code_agent` is non-None.
    Mypy cannot follow the closure capture; centralise the assert here.
    """
    agent = handle.code_agent
    assert agent is not None, "handle.code_agent must be set in configured mode"
    return agent


def _factory_file_read(handle: RuntimeHandle) -> ToolHandler:
    async def inner(args: dict[str, Any]) -> Any:
        path = _require(args, "path")
        return await _agent(handle).files.read_file(path)

    return _wrap_envelope(handle, "chio_file_read", inner)


def _factory_file_write(handle: RuntimeHandle) -> ToolHandler:
    async def inner(args: dict[str, Any]) -> Any:
        path = _require(args, "path")
        content = _require(args, "content")
        return await _agent(handle).files.write_file(path, content)

    return _wrap_envelope(handle, "chio_file_write", inner)


def _factory_file_edit(handle: RuntimeHandle) -> ToolHandler:
    async def inner(args: dict[str, Any]) -> Any:
        path = _require(args, "path")
        patch = _require(args, "patch")
        return await _agent(handle).files.edit_file(
            path, patch, executor=_exec.edit_file_executor
        )

    return _wrap_envelope(handle, "chio_file_edit", inner)


def _factory_file_list(handle: RuntimeHandle) -> ToolHandler:
    async def inner(args: dict[str, Any]) -> Any:
        path = _require(args, "path")
        return await _agent(handle).files.list_directory(
            path, executor=_exec.list_directory_executor
        )

    return _wrap_envelope(handle, "chio_file_list", inner)


def _factory_file_search(handle: RuntimeHandle) -> ToolHandler:
    async def inner(args: dict[str, Any]) -> Any:
        query = _require(args, "query")
        path = args.get("path", ".")
        return await _agent(handle).files.search_files(
            query, path=path, executor=_exec.search_files_executor
        )

    return _wrap_envelope(handle, "chio_file_search", inner)


def _factory_shell_run(handle: RuntimeHandle) -> ToolHandler:
    async def inner(args: dict[str, Any]) -> Any:
        command = _require(args, "command")
        approved = args.get("approved")
        return await _agent(handle).shell.run_command(
            command,
            approved=approved,
            executor=partial(_exec.shell_run_executor, cwd=handle.cwd),
        )

    return _wrap_envelope(handle, "chio_shell_run", inner)


def _factory_git_status(handle: RuntimeHandle) -> ToolHandler:
    async def inner(_args: dict[str, Any]) -> Any:
        return await _agent(handle).git.status(
            executor=partial(_exec.git_status_executor, cwd=handle.cwd)
        )

    return _wrap_envelope(handle, "chio_git_status", inner)


def _factory_git_diff(handle: RuntimeHandle) -> ToolHandler:
    async def inner(args: dict[str, Any]) -> Any:
        paths = args.get("paths")
        return await _agent(handle).git.diff(
            paths=paths, executor=partial(_exec.git_diff_executor, cwd=handle.cwd)
        )

    return _wrap_envelope(handle, "chio_git_diff", inner)


def _factory_git_log(handle: RuntimeHandle) -> ToolHandler:
    async def inner(args: dict[str, Any]) -> Any:
        limit = int(args.get("limit", 20))
        return await _agent(handle).git.log(
            limit=limit, executor=partial(_exec.git_log_executor, cwd=handle.cwd)
        )

    return _wrap_envelope(handle, "chio_git_log", inner)


def _factory_git_add(handle: RuntimeHandle) -> ToolHandler:
    async def inner(args: dict[str, Any]) -> Any:
        paths = list(_require(args, "paths"))
        return await _agent(handle).git.add(
            paths, executor=partial(_exec.git_add_executor, cwd=handle.cwd)
        )

    return _wrap_envelope(handle, "chio_git_add", inner)


def _factory_git_commit(handle: RuntimeHandle) -> ToolHandler:
    async def inner(args: dict[str, Any]) -> Any:
        message = _require(args, "message")
        return await _agent(handle).git.commit(
            message, executor=partial(_exec.git_commit_executor, cwd=handle.cwd)
        )

    return _wrap_envelope(handle, "chio_git_commit", inner)


def _factory_git_run(handle: RuntimeHandle) -> ToolHandler:
    async def inner(args: dict[str, Any]) -> Any:
        command = _require(args, "command")
        return await _agent(handle).git.run(
            command, executor=partial(_exec.git_run_executor, cwd=handle.cwd)
        )

    return _wrap_envelope(handle, "chio_git_run", inner)


__all__ = ["make_handler"]
