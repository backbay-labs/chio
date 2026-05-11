"""Hermes hook factories for the chio-hermes plugin.

Hermes's `PluginManager.invoke_hook` (`hermes_cli/plugins.py:1222`)
runs callbacks as `ret = cb(**kwargs)` with NO await, so every hook
here is a plain `def`. Returning a coroutine would silently drop the
body and trigger a `RuntimeWarning` at GC time.

* `make_pre_tool_call`   - policy precheck for `chio_*` tools; returns
  `{"action": "block", "message": ...}` for a deny verdict, `None`
  otherwise.
* `make_post_tool_call`  - finalises the receipt record from the
  kwargs Hermes hands the hook and appends it to JSONL.
* `make_on_session_start` - drops any leftover pending entries from a
  crashed prior session.
* `make_on_session_end`   - drains pending entries through the JSONL
  writer so they are not lost.

Every factory tolerates `**kwargs` because the upstream hook signature
is expected to evolve.
"""

from __future__ import annotations

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
    """Return a sync pre-hook that pre-checks Chio tools against policy."""

    def pre_tool_call(
        tool_name: str | None = None,
        args: dict[str, Any] | None = None,
        task_id: str | None = None,
        **_kwargs: Any,
    ) -> dict[str, Any] | None:
        if not _is_chio_tool(tool_name):
            return None
        if not handle.is_configured() or handle.policy is None:
            # Degraded mode: handler emits chio_not_configured; pre-hook
            # stays silent so the canonical envelope wins.
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


def make_post_tool_call(handle: RuntimeHandle) -> PostHook:
    """Return a sync post-hook that records the canonical receipt.

    JSONL write failures are swallowed so a hook exception never kills
    the Hermes session.
    """

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
        record: dict[str, Any] = {
            "tool_name": tool_name,
            "args": dict(args or {}),
            "task_id": task_id,
            "duration_ms": float(duration_ms) if duration_ms is not None else None,
            "recorded_at": time.time(),
            "result": result,
        }
        try:
            handle.receipts.record(record)
        except Exception as exc:  # noqa: BLE001 - tolerate any IO failure
            print(
                f"[chio-hermes] post_tool_call record failed: {exc}",
                file=sys.stderr,
            )

    return post_tool_call


def make_on_session_start(handle: RuntimeHandle) -> SessionHook:
    """Return a sync session-start hook that clears stale pending entries."""

    def on_session_start(
        session_id: str | None = None, **_kwargs: Any
    ) -> None:
        _ = session_id
        if handle.receipts is None:
            return
        handle.receipts.clear_pending()

    return on_session_start


def make_on_session_end(handle: RuntimeHandle) -> SessionHook:
    """Return a sync session-end hook that flushes pending entries."""

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
