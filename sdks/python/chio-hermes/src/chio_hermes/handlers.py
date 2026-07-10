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
from contextvars import ContextVar
from functools import partial
from typing import TYPE_CHECKING, Any

from chio_adapter_base.filters import (
    filter_diff_output as _adapter_base_filter_diff_output,
)
from chio_adapter_base.filters import (
    filter_directory_entries as _adapter_base_filter_directory_entries,
)
from chio_adapter_base.filters import (
    filter_status_output as _adapter_base_filter_status_output,
)
from chio_adapter_base.filters import forbidden_path_filter
from chio_adapter_base.security import ChioPathEscapeError
from chio_adapter_base.security import (
    reject_shell_argv_escape as _adapter_base_reject_shell_argv_escape,
)

from chio_hermes import executors as _exec

if TYPE_CHECKING:
    from chio_hermes.manifest import ToolEntry, ToolHandler
    from chio_hermes.runtime import RuntimeHandle


def _dumps(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _coerce_jsonable(value: Any) -> Any:
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


_LAST_RECEIPT_ID: ContextVar[str | None] = ContextVar(
    "chio_hermes_last_receipt_id", default=None
)


class _RequiresApprovalSignal(Exception):
    """Internal signal raised when a tool call needs HITL sign-off.

    The `_wrap_envelope` wrapper catches this and emits the
    `chio_requires_approval` envelope. Carries the metadata needed to
    write the canonical envelope without re-querying the sidecar.
    """

    def __init__(
        self,
        *,
        approval_id: str,
        tool_name: str,
        tool_server: str,
        command: str,
        expires_at: int | None = None,
    ) -> None:
        super().__init__(f"approval required: {approval_id}")
        self.approval_id = approval_id
        self.tool_name = tool_name
        self.tool_server = tool_server
        self.command = command
        self.expires_at = expires_at


def _shell_requires_approval(handle: RuntimeHandle, command: str) -> bool:
    policy = handle.policy
    if policy is None:
        return False
    try:
        return bool(policy.check_shell(command))
    except Exception as exc:  # noqa: BLE001
        try:
            from chio_code_agent.errors import (
                ChioCodeAgentDeniedError as denied_error_type,
            )
        except Exception:
            denied_error_type = None
        if denied_error_type is not None and isinstance(exc, denied_error_type):
            raise
        # Fail closed for HITL: a broken approval policy must not let the
        # command bypass the approval queue.
        return True


async def _maybe_submit_for_approval(
    handle: RuntimeHandle,
    *,
    tool_name: str,
    tool_server: str,
    command: str,
    tool_args: dict[str, Any],
    policy_check: str = "shell",
) -> None:
    """Submit `command` to the sidecar's HITL channel if the policy
    flags it as approval-required, then raise `_RequiresApprovalSignal`.

    `policy_check` selects between `policy.check_shell` (shell tools)
    and the same callable for git tools, since both use
    `check_shell` to evaluate the raw command string.
    """
    del policy_check  # both shell and git_run currently route through check_shell.
    if not _shell_requires_approval(handle, command):
        return

    client = handle.chio_client
    cap_id = handle.capability_id
    if client is None or not cap_id:
        # No client / capability means we cannot hold the call; fall
        # through to the typed deny so the model still gets a typed
        # rejection.
        return

    summary = command if len(command) <= 200 else command[:200] + "..."
    triggered_by = [
        "shell.requires_approval"
        if tool_server == "shell"
        else "git.requires_approval"
    ]
    try:
        approval_id = await client.submit_for_approval(
            capability_id=cap_id,
            tool_name=tool_name,
            tool_args=tool_args,
            tool_server=tool_server,
            ttl_seconds=3600,
            summary=summary,
            triggered_by=triggered_by,
        )
    except Exception:
        # Any sidecar error (unreachable, validation, store): bubble up
        # so the envelope wrapper turns it into chio_sidecar_unreachable
        # / chio_error rather than masking it as a deny.
        raise

    raise _RequiresApprovalSignal(
        approval_id=approval_id,
        tool_name=tool_name,
        tool_server=tool_server,
        command=command,
    )


def _requires_approval_envelope(signal: _RequiresApprovalSignal) -> str:
    payload: dict[str, Any] = {
        "status": "requires_approval",
        "error": "chio_requires_approval",
        "approval_id": signal.approval_id,
        "command": signal.command,
        "tool_name": signal.tool_name,
        "tool_server": signal.tool_server,
        "hint": (
            f"Use `/chio approve {signal.approval_id}` in this session "
            "or `hermes chio approvals respond "
            f"{signal.approval_id} --approve` from another shell. "
            "After approval, retry the original tool call (auto-resume "
            "is v0.3 work)."
        ),
    }
    if signal.expires_at is not None:
        payload["expires_at"] = signal.expires_at
    return _dumps(payload)


def _wrap_envelope(
    handle: RuntimeHandle,
    tool_name: str,
    inner: Callable[[dict[str, Any]], Awaitable[Any]],
) -> ToolHandler:
    """Catch the chio error hierarchy and convert to canonical JSON. Never raises."""

    async def handler(args: dict[str, Any] | None = None, **_kwargs: Any) -> str:
        params: dict[str, Any] = dict(args or {})

        if not handle.is_configured():
            message = handle.init_error or (
                "set CHIO_CAPABILITY_ID before invoking Chio tools"
            )
            return _typed_error("chio_not_configured", message)

        # Lazy import keeps chio_code_agent off the path in degraded mode.
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

        # Reset per-call so executor errors surface THIS call's receipt id.
        token = _LAST_RECEIPT_ID.set(None)
        try:
            invocation = await inner(params)
        except _RequiresApprovalSignal as signal:
            _LAST_RECEIPT_ID.reset(token)
            return _requires_approval_envelope(signal)
        except ChioCodeAgentDeniedError as exc:
            _LAST_RECEIPT_ID.reset(token)
            return _denied(
                guard=getattr(exc, "guard", None),
                reason=getattr(exc, "reason", None),
                receipt_id=None,
                message=str(exc),
            )
        except ChioDeniedError as exc:
            _LAST_RECEIPT_ID.reset(token)
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
            _LAST_RECEIPT_ID.reset(token)
            return _typed_error("chio_error", str(exc))
        except ChioConnectionError as exc:
            _LAST_RECEIPT_ID.reset(token)
            return _typed_error(
                "chio_sidecar_unreachable",
                f"Failed to connect to Chio sidecar at {handle.sidecar_url}: {exc}",
            )
        except ChioCodeAgentError as exc:
            _LAST_RECEIPT_ID.reset(token)
            return _typed_error("chio_error", str(exc))
        except Exception as exc:  # noqa: BLE001 - last resort
            # Receipt id precedence: explicit exception attribute wins,
            # else the captured most-recent allow verdict.
            receipt_id = getattr(exc, "receipt_id", None)
            if receipt_id is None:
                receipt_id = _LAST_RECEIPT_ID.get()
            _LAST_RECEIPT_ID.reset(token)
            if receipt_id is not None:
                return _typed_error(
                    "chio_executor_error",
                    f"{type(exc).__name__}: {exc}",
                    receipt_id=receipt_id,
                )
            return _typed_error("chio_error", f"{type(exc).__name__}: {exc}")
        else:
            _LAST_RECEIPT_ID.reset(token)

        return _allowed(
            getattr(invocation, "result", invocation),
            receipt_id=_receipt_id(invocation),
            tool_name=tool_name,
            tool_server=_tool_server_for(tool_name),
        )

    return handler


def make_handler(runtime: RuntimeHandle, entry: ToolEntry) -> ToolHandler:
    return entry.factory(runtime)


def _require(args: dict[str, Any], key: str) -> Any:
    if key not in args:
        raise KeyError(f"missing required argument {key!r}")
    return args[key]


def _agent(handle: RuntimeHandle) -> Any:
    # Wrapper short-circuits with chio_not_configured before this runs,
    # so code_agent is non-None; centralise the mypy-narrowing assert.
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


def _is_read_forbidden(handle: RuntimeHandle, path: str) -> bool:
    policy = handle.policy
    if policy is None:
        return False
    try:
        from chio_code_agent.errors import ChioCodeAgentDeniedError
    except Exception:
        return False
    try:
        policy.check_read(path, cwd=handle.cwd)
    except ChioCodeAgentDeniedError:
        return True
    except Exception:
        # Conservative: treat unexpected errors as forbidden.
        return True
    return False


def _factory_file_list(handle: RuntimeHandle) -> ToolHandler:
    async def inner(args: dict[str, Any]) -> Any:
        path = _require(args, "path")
        result = await _agent(handle).files.list_directory(
            path, executor=_exec.list_directory_executor
        )
        # Post-filter so listings cannot leak the existence of files
        # the policy bans from chio_file_read.
        return _filter_directory_entries(handle, path, result)

    return _wrap_envelope(handle, "chio_file_list", inner)


def _filter_directory_entries(
    handle: RuntimeHandle, listing_root: str, result: Any
) -> Any:
    """Drop forbidden directory entries; delegates to chio-adapter-base.

    Hermes-aware adapter over
    :func:`chio_adapter_base.filters.filter_directory_entries`. Builds
    an ``is_forbidden`` callable that runs ``handle.policy.check_read``
    so the chio-adapter-base helper does not need a chio-code-agent
    dependency.
    """
    if not isinstance(result, dict):
        return result
    return _adapter_base_filter_directory_entries(
        result,
        is_forbidden=lambda child: _is_read_forbidden(handle, child),
        listing_root=listing_root,
    )


def _factory_file_search(handle: RuntimeHandle) -> ToolHandler:
    async def inner(args: dict[str, Any]) -> Any:
        query = _require(args, "query")
        path = args.get("path", ".")
        # `Path.rglob` walks `..` out of the workspace; reject the
        # obvious escape before dispatch.
        _reject_path_escape(query, label="query")
        invocation = await _agent(handle).files.search_files(
            query, path=path, executor=_exec.search_files_executor
        )
        # rglob enumerates secret files (`*.pem`) even though
        # chio_file_read would deny them; re-check against check_read.
        return _filter_search_matches(handle, invocation)

    return _wrap_envelope(handle, "chio_file_search", inner)


def _filter_search_matches(handle: RuntimeHandle, invocation: Any) -> Any:
    inner_result = getattr(invocation, "result", None)
    target = inner_result if inner_result is not None else invocation
    filtered = _filter_matches(handle, target)
    if inner_result is not None and filtered is not target:
        try:
            invocation.result = filtered
            return invocation
        except Exception:  # noqa: BLE001 - frozen dataclass etc.
            return filtered
    return filtered if filtered is not target else invocation


def _filter_matches(handle: RuntimeHandle, result: Any) -> Any:
    """Drop forbidden search matches via chio-adapter-base.

    Uses :func:`chio_adapter_base.filters.forbidden_path_filter` for
    the policy-check loop and re-assembles the chio-hermes search
    result envelope. Non-string match entries pass through untouched
    (the chio-hermes 0.1.0 contract).
    """
    if not isinstance(result, dict):
        return result
    matches = result.get("matches")
    if not isinstance(matches, list):
        return result
    str_matches = [m for m in matches if isinstance(m, str)]
    non_str = [m for m in matches if not isinstance(m, str)]
    kept_strs, dropped = forbidden_path_filter(
        str_matches,
        is_forbidden=lambda path: _is_read_forbidden(handle, path),
    )
    if not dropped:
        return result
    filtered = dict(result)
    filtered["matches"] = [*kept_strs, *non_str]
    filtered["forbidden_paths_filtered"] = sorted(set(dropped))
    return filtered


def _reject_path_escape(value: str, *, label: str) -> None:
    # Best-effort: rejects literal `..` segments. Cannot catch shell
    # expansion, env var indirection, or symlink races.
    from chio_code_agent.errors import ChioCodeAgentDeniedError

    text = str(value or "")
    parts = text.replace("\\", "/").split("/")
    if any(part == ".." for part in parts):
        raise ChioCodeAgentDeniedError(
            f"{label} {text!r} contains a `..` segment that escapes the workspace",
            tool_name="file_search",
            reason="path_escape",
            guard="chio_path_escape",
        )


def _factory_shell_run(handle: RuntimeHandle) -> ToolHandler:
    async def inner(args: dict[str, Any]) -> Any:
        command = _require(args, "command")
        # Syntactic guardrail (not a sandbox): rejects `..` and
        # out-of-workspace absolute paths.
        _reject_shell_argv_escape(command, root=handle.cwd)
        # Approval-required commands route through the sidecar's HITL channel. The wrapper raises
        # `_RequiresApprovalSignal` which the envelope wrapper turns
        # into a `chio_requires_approval` JSON envelope.
        await _maybe_submit_for_approval(
            handle,
            tool_name="chio_shell_run",
            tool_server="shell",
            command=command,
            tool_args={"command": command},
        )
        # `approved=False` hard-coded: the sidecar holds approval, and an
        # `approved=True` would be rejected anyway because `approved` is not
        # in the public JSON schema.
        return await _agent(handle).shell.run_command(
            command,
            approved=False,
            executor=partial(_exec.shell_run_executor, cwd=handle.cwd),
        )

    return _wrap_envelope(handle, "chio_shell_run", inner)


def _reject_shell_argv_escape(command: str, *, root: Any) -> None:
    """Reject argv tokens that escape the workspace root.

    Delegates to :func:`chio_adapter_base.security.reject_shell_argv_escape`
    and translates its :class:`ChioPathEscapeError` into the
    chio-hermes :class:`ChioCodeAgentDeniedError` so the surrounding
    handler envelope renders the deny verdict with the
    ``tool_name`` / ``reason`` / ``guard`` fields.
    """
    from chio_code_agent.errors import ChioCodeAgentDeniedError

    try:
        _adapter_base_reject_shell_argv_escape(command, root=root)
    except ChioPathEscapeError as exc:
        if exc.reason == "dotdot_segment":
            message = (
                f"shell argv token {exc.token!r} contains `..` "
                "(workspace escape)"
            )
        else:
            message = (
                f"shell argv token {exc.token!r} points outside the "
                "workspace root"
            )
        raise ChioCodeAgentDeniedError(
            message,
            tool_name="run_command",
            reason="path_escape",
            guard="chio_path_escape",
        ) from None


def _factory_git_status(handle: RuntimeHandle) -> ToolHandler:
    async def inner(_args: dict[str, Any]) -> Any:
        invocation = await _agent(handle).git.status(
            executor=partial(_exec.git_status_executor, cwd=handle.cwd)
        )
        # Drop porcelain rows for forbidden paths so secret-file
        # existence cannot be confirmed via git status.
        return _filter_invocation_status(handle, invocation)

    return _wrap_envelope(handle, "chio_git_status", inner)


def _filter_invocation_status(handle: RuntimeHandle, invocation: Any) -> Any:
    inner_result = getattr(invocation, "result", None)
    target = inner_result if inner_result is not None else invocation
    filtered = _filter_status_output(handle, target)
    if inner_result is not None and filtered is not target:
        try:
            invocation.result = filtered
            return invocation
        except Exception:  # noqa: BLE001
            return filtered
    return filtered if filtered is not target else invocation


def _filter_status_output(handle: RuntimeHandle, result: Any) -> Any:
    """Drop porcelain rows for forbidden paths; delegates to chio-adapter-base."""
    if not isinstance(result, dict):
        return result
    return _adapter_base_filter_status_output(
        result,
        is_forbidden=lambda path: _is_read_forbidden(handle, path),
    )


def _factory_git_diff(handle: RuntimeHandle) -> ToolHandler:
    async def inner(args: dict[str, Any]) -> Any:
        paths = args.get("paths")
        invocation = await _agent(handle).git.diff(
            paths=paths, executor=partial(_exec.git_diff_executor, cwd=handle.cwd)
        )
        # Strip diff hunks for files the policy bans from reads so
        # secrets do not echo into the model context or receipt log.
        return _filter_invocation_diff(handle, invocation)

    return _wrap_envelope(handle, "chio_git_diff", inner)


def _filter_invocation_diff(handle: RuntimeHandle, invocation: Any) -> Any:
    inner = getattr(invocation, "result", None)
    target = inner if inner is not None else invocation
    filtered = _filter_diff_output(handle, target)
    if inner is not None and filtered is not target:
        try:
            invocation.result = filtered
            return invocation
        except Exception:  # noqa: BLE001 - frozen dataclass etc.
            return filtered
    return filtered if filtered is not target else invocation


def _filter_diff_output(handle: RuntimeHandle, result: Any) -> Any:
    """Drop diff hunks for forbidden paths; delegates to chio-adapter-base."""
    if not isinstance(result, dict):
        return result
    return _adapter_base_filter_diff_output(
        result,
        is_forbidden=lambda path: _is_read_forbidden(handle, path),
    )


def _factory_git_log(handle: RuntimeHandle) -> ToolHandler:
    async def inner(args: dict[str, Any]) -> Any:
        limit = int(args.get("limit", 20))
        return await _agent(handle).git.log(
            limit=limit, executor=partial(_exec.git_log_executor, cwd=handle.cwd)
        )

    return _wrap_envelope(handle, "chio_git_log", inner)


def _coerce_git_add_paths(raw_paths: Any) -> list[str]:
    if isinstance(raw_paths, str):
        return [raw_paths]
    if not isinstance(raw_paths, list) or not all(isinstance(path, str) for path in raw_paths):
        from chio_code_agent.errors import ChioCodeAgentDeniedError

        raise ChioCodeAgentDeniedError(
            "chio_git_add requires paths to be an array of strings",
            tool_name="git_add",
            reason="invalid_paths",
            guard="invalid_args",
        )
    return list(raw_paths)


def _factory_git_add(handle: RuntimeHandle) -> ToolHandler:
    async def inner(args: dict[str, Any]) -> Any:
        paths = _coerce_git_add_paths(_require(args, "paths"))
        # `git add src/**` can expand to forbidden paths (`.env`,
        # `.git/**`); resolve via `git ls-files` and policy-check.
        await _reject_git_add_forbidden_expansion(handle, paths)
        return await _agent(handle).git.add(
            paths, executor=partial(_exec.git_add_executor, cwd=handle.cwd)
        )

    return _wrap_envelope(handle, "chio_git_add", inner)


async def _reject_git_add_forbidden_expansion(
    handle: RuntimeHandle, pathspecs: list[str]
) -> None:
    # Best-effort: if ls-files fails, fall back to literal pathspecs;
    # the pre-hook's policy.check_write covers exact-path checks.
    from chio_code_agent.errors import ChioCodeAgentDeniedError

    expansion = await _expand_git_pathspecs(handle, pathspecs)
    if expansion is None:
        return
    policy = handle.policy
    if policy is None:
        return
    forbidden: list[str] = []
    for path in expansion:
        try:
            policy.check_write(path, cwd=handle.cwd)
        except ChioCodeAgentDeniedError:
            forbidden.append(path)
        except Exception:  # noqa: BLE001 - treat as denial to be safe
            forbidden.append(path)
    if forbidden:
        raise ChioCodeAgentDeniedError(
            (
                f"git add pathspec(s) {pathspecs!r} would stage forbidden "
                f"path(s): {sorted(set(forbidden))!r}"
            ),
            tool_name="git_add",
            reason="forbidden_path",
            guard="forbidden_path",
        )


async def _expand_git_pathspecs(
    handle: RuntimeHandle, pathspecs: list[str]
) -> list[str] | None:
    # Returns expanded paths, or None when git is missing/fails (caller
    # falls back to the literal pathspecs).
    if not pathspecs:
        return []
    import asyncio
    import subprocess
    from pathlib import Path

    cwd_str = str(Path(str(handle.cwd)))

    def _run() -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - argv list, no shell
            [
                "git",
                "ls-files",
                "--others",
                "--modified",
                "--cached",
                "--exclude-standard",
                "--",
                *pathspecs,
            ],
            cwd=cwd_str,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )

    try:
        completed = await asyncio.to_thread(_run)
    except Exception:  # noqa: BLE001 - timeouts, OSError, etc.
        return None
    if completed.returncode != 0:
        return None
    paths = [line for line in completed.stdout.splitlines() if line]
    return paths


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
        # Approval-required git commands route through the sidecar's
        # HITL channel (raises `_RequiresApprovalSignal`).
        await _maybe_submit_for_approval(
            handle,
            tool_name="chio_git_run",
            tool_server="git",
            command=command,
            tool_args={"command": command},
            policy_check="git",
        )
        # Reject flags that retarget git at a different worktree.
        _reject_git_run_flag_escape(command)
        return await _agent(handle).git.run(
            command, executor=partial(_exec.git_run_executor, cwd=handle.cwd)
        )

    return _wrap_envelope(handle, "chio_git_run", inner)


def _reject_git_run_flag_escape(command: str) -> None:
    # `-C`, `--git-dir`, etc. retarget git at a different worktree,
    # defeating the executor's workspace anchoring.
    import shlex

    from chio_code_agent.errors import ChioCodeAgentDeniedError

    try:
        argv = shlex.split(command or "")
    except ValueError:
        return
    if argv and argv[0] == "git":
        argv = argv[1:]
    blacklist = {"-C", "--git-dir", "--work-tree", "--namespace", "--exec-path"}
    for idx, token in enumerate(argv):
        bare = token.split("=", 1)[0]
        if bare in blacklist:
            raise ChioCodeAgentDeniedError(
                f"git flag {bare!r} is forbidden (workspace escape)",
                tool_name="git_run",
                reason="path_escape",
                guard="chio_path_escape",
            )
        # Catch joined `-C/path` form.
        if token.startswith("-C") and idx == 0 and len(token) > 2:
            raise ChioCodeAgentDeniedError(
                "git flag '-C<path>' is forbidden (workspace escape)",
                tool_name="git_run",
                reason="path_escape",
                guard="chio_path_escape",
            )


__all__ = ["make_handler"]
