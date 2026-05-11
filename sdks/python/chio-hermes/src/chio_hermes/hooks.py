"""Hermes hook factories.

Hermes's `PluginManager.invoke_hook` (`hermes_cli/plugins.py:1222`)
runs callbacks as `ret = cb(**kwargs)` with NO await, so every hook
here is a plain `def`. Returning a coroutine would silently drop the
body and trigger a `RuntimeWarning` at GC time.
"""

from __future__ import annotations

import json
import sys
import time
from collections.abc import Callable
from typing import Any

from chio_hermes.runtime import RuntimeHandle

PreHook = Callable[..., Any]
PostHook = Callable[..., None]
SessionHook = Callable[..., None]


def _is_chio_tool(tool_name: str | None) -> bool:
    return isinstance(tool_name, str) and tool_name.startswith("chio_")


def make_pre_tool_call(handle: RuntimeHandle) -> PreHook:
    def pre_tool_call(
        tool_name: str | None = None,
        args: dict[str, Any] | None = None,
        task_id: str | None = None,
        **_kwargs: Any,
    ) -> dict[str, Any] | None:
        if not _is_chio_tool(tool_name):
            return None
        if not handle.is_configured() or handle.policy is None:
            # Degraded mode: handler emits chio_not_configured.
            return None
        params = dict(args or {})

        try:
            from chio_code_agent.errors import ChioCodeAgentDeniedError
        except Exception:
            return None

        try:
            if tool_name in {"chio_file_read", "chio_file_list", "chio_file_search"}:
                target = params.get("path", ".")
                handle.policy.check_read(target, cwd=handle.cwd)
            elif tool_name in {"chio_file_write", "chio_file_edit"}:
                target = params.get("path", "")
                handle.policy.check_write(target, cwd=handle.cwd)
            elif tool_name == "chio_shell_run":
                command = params.get("command", "")
                handle.policy.check_shell(command)
            elif tool_name == "chio_git_run":
                command = params.get("command", "")
                handle.policy.check_git(command)
                handle.policy.check_shell(command)
            elif tool_name == "chio_git_add":
                for path in params.get("paths", []) or []:
                    handle.policy.check_write(path, cwd=handle.cwd)
        except ChioCodeAgentDeniedError as exc:
            _ = task_id  # reserved for future telemetry
            return {
                "action": "block",
                "message": str(exc),
                "guard": getattr(exc, "guard", None),
                "reason": getattr(exc, "reason", None),
            }
        except Exception:  # noqa: BLE001 - never crash Hermes from a hook
            return None
        return None

    return pre_tool_call


def _envelope_status_fields(result: Any) -> tuple[str | None, str | None]:
    """Hoist `status` / `error` from the handler's JSON envelope so
    `ReceiptBuffer.denial_count` (which reads top-level keys) sees the
    deny verdict. Returns ``(None, None)`` for non-JSON-object results.
    """
    if not isinstance(result, str):
        return None, None
    try:
        decoded = json.loads(result)
    except (TypeError, ValueError):
        return None, None
    if not isinstance(decoded, dict):
        return None, None
    status = decoded.get("status")
    error = decoded.get("error")
    return (
        status if isinstance(status, str) else None,
        error if isinstance(error, str) else None,
    )


def make_post_tool_call(handle: RuntimeHandle) -> PostHook:
    def post_tool_call(
        tool_name: str | None = None,
        args: dict[str, Any] | None = None,
        result: Any = None,
        task_id: str | None = None,
        duration_ms: float | int | None = None,
        **_kwargs: Any,
    ) -> None:
        if not _is_chio_tool(tool_name) or handle.receipts is None:
            return
        status, error = _envelope_status_fields(result)
        record: dict[str, Any] = {
            "tool_name": tool_name,
            "args": dict(args or {}),
            "task_id": task_id,
            "duration_ms": float(duration_ms) if duration_ms is not None else None,
            "recorded_at": time.time(),
            "result": result,
        }
        if status is not None:
            record["status"] = status
        if error is not None:
            record["error"] = error
        try:
            handle.receipts.record(record)
        except Exception as exc:  # noqa: BLE001
            print(
                f"[chio-hermes] post_tool_call record failed: {exc}",
                file=sys.stderr,
            )

    return post_tool_call


def make_on_session_start(handle: RuntimeHandle) -> SessionHook:
    def on_session_start(
        session_id: str | None = None, **_kwargs: Any
    ) -> None:
        _ = session_id
        if handle.receipts is None:
            return
        handle.receipts.clear_pending()

    return on_session_start


def make_on_session_end(handle: RuntimeHandle) -> SessionHook:
    def on_session_end(
        session_id: str | None = None, **_kwargs: Any
    ) -> None:
        _ = session_id
        if handle.receipts is None:
            return
        for entry in list(handle.receipts.drain_pending()):
            entry["recorded_at"] = time.time()
            entry["session_end_flush"] = True
            try:
                handle.receipts.record(entry)
            except Exception:  # noqa: BLE001
                pass

    return on_session_end


__all__ = [
    "PostHook",
    "PreHook",
    "SessionHook",
    "make_on_session_end",
    "make_on_session_start",
    "make_post_tool_call",
    "make_pre_tool_call",
]
