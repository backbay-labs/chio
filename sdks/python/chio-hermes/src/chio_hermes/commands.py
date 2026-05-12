"""`/chio` slash command factory.

`make_slash_handler(handle)` returns the async closure Hermes registers
via `ctx.register_command(...)`. Subcommands: `status`, `receipts [N]`,
`policy`, `approvals`, `approve <id>`, `deny <id>`.
"""

from __future__ import annotations

import json
import shlex
from collections.abc import Awaitable, Callable
from typing import Any

from chio_hermes.runtime import RuntimeHandle

SlashHandler = Callable[[str], Awaitable[str | None]]


def _format_status(handle: RuntimeHandle) -> str:
    lines = [
        "chio plugin status:",
        f"  sidecar URL:   {handle.sidecar_url}",
        f"  capability id: ...{handle.masked_capability_id()}",
        f"  configured:    {handle.is_configured()}",
        f"  workspace:     {handle.cwd}",
    ]
    if handle.receipts is not None:
        lines.append(f"  recent denials: {handle.receipts.denial_count()}")
        lines.append(f"  pending records: {handle.receipts.pending_total()}")
    if handle.init_error:
        lines.append(f"  init_error:    {handle.init_error}")
    return "\n".join(lines)


def _format_receipts(handle: RuntimeHandle, raw_args: list[str]) -> str:
    if handle.receipts is None:
        return "chio receipts unavailable (runtime not configured)"
    requested = 5
    if raw_args:
        try:
            requested = int(raw_args[0])
        except ValueError:
            return f"invalid receipt count: {raw_args[0]!r}"
    requested = max(1, min(50, requested))
    records = handle.receipts.recent(requested)
    if not records:
        return "no chio receipts buffered yet"
    lines = [f"last {len(records)} chio receipts:"]
    for record in records:
        tool = record.get("tool_name", "?")
        task = record.get("task_id", "?")
        duration = record.get("duration_ms")
        recorded = record.get("recorded_at")
        lines.append(
            f"  - tool={tool} task={task} duration_ms={duration} ts={recorded}"
        )
    return "\n".join(lines)


def _format_policy(handle: RuntimeHandle) -> str:
    policy = handle.policy
    if policy is None:
        return "chio policy unavailable (runtime not configured)"
    summary: dict[str, Any] = {
        "allowed_tools": sorted(
            f"{t.server}/{t.tool}" for t in getattr(policy, "allowed_tools", set())
        ),
        "writable_roots": list(getattr(policy, "writable_roots", []) or []),
        "forbidden_path_patterns": list(
            getattr(policy, "forbidden_path_patterns", []) or []
        ),
        "shell_forbidden_patterns": [
            getattr(p, "pattern", str(p))
            for p in getattr(policy, "shell_forbidden_patterns", []) or []
        ],
        "git_deny_patterns": [
            getattr(p, "pattern", str(p))
            for p in getattr(policy, "git_deny_patterns", []) or []
        ],
        "readable_from_cwd": bool(getattr(policy, "readable_from_cwd", True)),
    }
    return "chio policy summary:\n" + json.dumps(summary, sort_keys=True, indent=2)


async def _format_approvals_list(handle: RuntimeHandle) -> str:
    """`/chio approvals` -- list pending HITL approvals from the sidecar."""
    client = handle.chio_client
    if client is None:
        return "chio approvals unavailable (chio client not initialised)"
    try:
        rows = await client.list_pending_approvals()
    except Exception as exc:  # noqa: BLE001 - surface to user
        return f"failed to list approvals: {exc}"
    if not rows:
        return "no pending chio approvals"
    lines = [f"pending chio approvals ({len(rows)}):"]
    for row in rows:
        approval_id = getattr(row, "approval_id", "?")
        tool_server = getattr(row, "tool_server", "?")
        tool_name = getattr(row, "tool_name", "?")
        summary = getattr(row, "summary", "")
        expires_at = getattr(row, "expires_at", "?")
        lines.append(
            f"  - {approval_id} {tool_server}/{tool_name} "
            f"expires={expires_at} summary={summary!r}"
        )
    lines.append("respond with `/chio approve <id> [reason]` or `/chio deny <id> [reason]`.")
    return "\n".join(lines)


async def _respond_approval(
    handle: RuntimeHandle,
    *,
    verdict: str,
    args: list[str],
) -> str:
    if not args:
        return f"usage: /chio {verdict} <approval_id> [reason]"
    approval_id = args[0]
    reason = " ".join(args[1:]).strip() or None
    client = handle.chio_client
    if client is None:
        return "chio approvals unavailable (chio client not initialised)"
    try:
        result = await client.respond_approval(approval_id, verdict, reason)
    except Exception as exc:  # noqa: BLE001
        return f"failed to {verdict} {approval_id}: {exc}"
    outcome = getattr(result, "outcome", verdict)
    outcome_str = getattr(outcome, "value", str(outcome))
    if reason:
        return (
            f"chio approval {approval_id} -> {outcome_str} (reason: {reason}). "
            "Retry the original tool call to proceed (auto-resume is v0.3 work)."
        )
    return (
        f"chio approval {approval_id} -> {outcome_str}. "
        "Retry the original tool call to proceed (auto-resume is v0.3 work)."
    )


def make_slash_handler(handle: RuntimeHandle) -> SlashHandler:
    """Return an async `/chio` handler bound to `handle`."""

    async def handle_slash(raw_args: str) -> str | None:
        try:
            tokens = shlex.split(raw_args or "")
        except ValueError as exc:
            return f"could not parse /chio arguments: {exc}"
        sub = tokens[0] if tokens else "status"
        rest = tokens[1:]
        if sub in {"", "status"}:
            return _format_status(handle)
        if sub == "receipts":
            return _format_receipts(handle, rest)
        if sub == "policy":
            return _format_policy(handle)
        if sub == "approvals":
            return await _format_approvals_list(handle)
        if sub == "approve":
            return await _respond_approval(handle, verdict="approve", args=rest)
        if sub == "deny":
            return await _respond_approval(handle, verdict="deny", args=rest)
        return (
            f"unknown /chio subcommand: {sub!r} "
            "(try: status, receipts, policy, approvals, approve, deny)"
        )

    return handle_slash


__all__ = ["SlashHandler", "make_slash_handler"]
