"""Hermes hook factories.

`PluginManager.invoke_hook` (`hermes_cli/plugins.py:1222`) runs
callbacks as `ret = cb(**kwargs)` with NO await, so every hook is a
plain `def`; returning a coroutine would silently drop the body.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from typing import Any

from chio_adapter_base.redact import RedactionPolicy
from chio_adapter_base.redact import redact_args as _adapter_base_redact_args

from chio_hermes.runtime import RuntimeHandle

_logger = logging.getLogger(__name__)

PreHook = Callable[..., Any]
PostHook = Callable[..., None]
SessionHook = Callable[..., None]


def _is_chio_tool(tool_name: str | None) -> bool:
    return isinstance(tool_name, str) and tool_name.startswith("chio_")


def _block_pre_tool_call(
    message: str,
    *,
    guard: str | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    return {
        "action": "block",
        "message": message,
        "guard": guard,
        "reason": reason,
    }


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
        except Exception as exc:
            return _block_pre_tool_call(
                f"Chio local policy unavailable: {exc}",
                guard="chio_policy_error",
                reason="policy_unavailable",
            )

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
                # `command` is a git subcommand argv ("push --force"), not a
                # shell line ("git push --force"). Policy patterns in
                # `git_deny_patterns` and `shell_forbidden_patterns` anchor on
                # `git\s+...` because they are written to match what a human
                # types at a shell. Prefix `git ` here so the model cannot
                # bypass `push --force`, `reset --hard origin`, etc by leaving
                # the `git` token off (which `git_run_executor` strips anyway
                # before exec). Defense in depth: the executor would also have
                # rejected via `tool_access` because `git/run` is not in the
                # default allow list, but make the hook block at the policy
                # patterns the docs advertise.
                command = params.get("command", "")
                shell_form = command if command.startswith("git ") else f"git {command}"
                handle.policy.check_git(shell_form)
                handle.policy.check_shell(shell_form)
            elif tool_name == "chio_git_add":
                paths = params.get("paths", []) or []
                if isinstance(paths, str):
                    paths = [paths]
                if not isinstance(paths, list) or not all(
                    isinstance(path, str) for path in paths
                ):
                    return _block_pre_tool_call(
                        "chio_git_add requires paths to be an array of strings",
                        guard="chio_policy_error",
                        reason="invalid_paths",
                    )
                for path in paths:
                    handle.policy.check_write(path, cwd=handle.cwd)
        except ChioCodeAgentDeniedError as exc:
            _ = task_id  # reserved for future telemetry
            return _block_pre_tool_call(
                str(exc),
                guard=getattr(exc, "guard", None),
                reason=getattr(exc, "reason", None),
            )
        except Exception as exc:  # noqa: BLE001 - never crash Hermes from a hook
            return _block_pre_tool_call(
                f"Chio local policy check failed: {exc}",
                guard="chio_policy_error",
                reason="policy_error",
            )
        return None

    return pre_tool_call


def _envelope_status_fields(result: Any) -> tuple[str | None, str | None]:
    # Hoist status/error from the handler's JSON envelope so
    # ReceiptBuffer.denial_count (top-level key reader) sees denies.
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


RECEIPT_RESULT_MAX_BYTES = 256

# Tools whose result is mostly raw content; truncate so secrets and
# large blobs do not get baked into the audit trail.
_CONTENT_HEAVY_TOOLS = frozenset(
    {
        "chio_file_read",
        "chio_file_search",
        "chio_shell_run",
        "chio_git_diff",
        "chio_git_log",
        "chio_git_status",
        "chio_git_run",
    }
)


def _truncate_receipt_result(
    tool_name: str | None, result: Any
) -> tuple[Any, bool]:
    if tool_name not in _CONTENT_HEAVY_TOOLS:
        return result, False
    if not isinstance(result, str):
        return result, False
    encoded = result.encode("utf-8", errors="replace")
    if len(encoded) <= RECEIPT_RESULT_MAX_BYTES:
        return result, False
    head = encoded[:RECEIPT_RESULT_MAX_BYTES].decode("utf-8", errors="replace")
    return head, True


_DEFAULT_REDACTION_POLICY: RedactionPolicy = RedactionPolicy.chio_default()
"""Module-private policy used by the post-tool-call hook."""

_BODY_REDACT_FIELDS: dict[str, tuple[str, ...]] = dict(
    _DEFAULT_REDACTION_POLICY.body_fields
)


def _redact_args(
    tool_name: str | None, args: dict[str, Any]
) -> dict[str, Any]:
    """Delegates to ``chio_adapter_base.redact.redact_args``."""
    return _adapter_base_redact_args(
        tool_name, args, policy=_DEFAULT_REDACTION_POLICY
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
        truncated_result, was_truncated = _truncate_receipt_result(
            tool_name, result
        )
        record: dict[str, Any] = {
            "tool_name": tool_name,
            "args": _adapter_base_redact_args(
                tool_name,
                dict(args or {}),
                policy=_DEFAULT_REDACTION_POLICY,
            ),
            "task_id": task_id,
            "duration_ms": float(duration_ms) if duration_ms is not None else None,
            "recorded_at": time.time(),
            "result": truncated_result,
        }
        if was_truncated:
            record["result_truncated"] = True
        if status is not None:
            record["status"] = status
        if error is not None:
            record["error"] = error
        try:
            handle.receipts.record(record)
        except Exception as exc:  # noqa: BLE001
            _logger.warning("post_tool_call record failed: %s", exc)

    return post_tool_call


def make_on_session_start(handle: RuntimeHandle) -> SessionHook:
    def on_session_start(
        session_id: str | None = None, **_kwargs: Any
    ) -> None:
        _ = session_id
        if handle.receipts is None:
            return
        # F14: if Hermes fires on_session_start per turn (dispatch
        # contract is undocumented), `clear_pending` would drop any
        # queued receipts. Flush into the recorded buffer instead.
        for entry in list(handle.receipts.drain_pending()):
            entry["recorded_at"] = time.time()
            entry["session_start_flush"] = True
            try:
                handle.receipts.record(entry)
            except Exception:  # noqa: BLE001
                pass

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
    "RECEIPT_RESULT_MAX_BYTES",
    "PostHook",
    "PreHook",
    "SessionHook",
    "_redact_args",
    "make_on_session_end",
    "make_on_session_start",
    "make_post_tool_call",
    "make_pre_tool_call",
]
