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
            # Receipt id precedence: explicit attribute (legacy) wins,
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
    if not isinstance(result, dict):
        return result
    entries = result.get("entries")
    if not isinstance(entries, list):
        return result
    base = result.get("path") or listing_root
    from pathlib import Path

    base_path = Path(str(base))
    kept: list[str] = []
    dropped: list[str] = []
    for entry in entries:
        if not isinstance(entry, str):
            kept.append(entry)
            continue
        child = str(base_path / entry)
        if _is_read_forbidden(handle, child):
            dropped.append(entry)
            continue
        kept.append(entry)
    if not dropped:
        return result
    filtered = dict(result)
    filtered["entries"] = kept
    filtered["forbidden_paths_filtered"] = sorted(set(dropped))
    return filtered


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
    if not isinstance(result, dict):
        return result
    matches = result.get("matches")
    if not isinstance(matches, list):
        return result
    kept: list[Any] = []
    dropped: list[str] = []
    for match in matches:
        if isinstance(match, str) and _is_read_forbidden(handle, match):
            dropped.append(match)
            continue
        kept.append(match)
    if not dropped:
        return result
    filtered = dict(result)
    filtered["matches"] = kept
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
        # `approved=False` hard-coded: there is no trusted human-in-the-
        # loop channel and `approved` is not in the public JSON schema.
        # Approval-required commands fall through to chio_code_agent's
        # deny path.
        return await _agent(handle).shell.run_command(
            command,
            approved=False,
            executor=partial(_exec.shell_run_executor, cwd=handle.cwd),
        )

    return _wrap_envelope(handle, "chio_shell_run", inner)


def _reject_shell_argv_escape(command: str, *, root: Any) -> None:
    import shlex
    from pathlib import Path

    from chio_code_agent.errors import ChioCodeAgentDeniedError

    try:
        argv = shlex.split(command or "")
    except ValueError:
        # Malformed quoting: let the executor surface the syntax error
        # rather than masking it as a path escape.
        return
    root_path = Path(str(root)).resolve() if root is not None else None
    for token in argv:
        normalised = token.replace("\\", "/")
        segments = normalised.split("/")
        if any(seg == ".." for seg in segments):
            raise ChioCodeAgentDeniedError(
                f"shell argv token {token!r} contains `..` (workspace escape)",
                tool_name="run_command",
                reason="path_escape",
                guard="chio_path_escape",
            )
        if root_path is not None and normalised.startswith("/"):
            try:
                resolved = Path(token).resolve()
            except OSError:
                continue
            try:
                resolved.relative_to(root_path)
            except ValueError:
                raise ChioCodeAgentDeniedError(
                    f"shell argv token {token!r} points outside the workspace root",
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
    # Porcelain v1: `XY <path>` or rename `XY <old> -> <new>`. Drop the
    # row when either side fails check_read.
    if not isinstance(result, dict):
        return result
    stdout = result.get("stdout")
    if not isinstance(stdout, str) or not stdout:
        return result
    kept_lines: list[str] = []
    dropped: list[str] = []
    for raw_line in stdout.splitlines():
        if len(raw_line) < 4:
            kept_lines.append(raw_line)
            continue
        body = raw_line[3:]
        if " -> " in body:
            old, new = body.split(" -> ", 1)
            paths = [_strip_quotes(old), _strip_quotes(new)]
        else:
            paths = [_strip_quotes(body)]
        forbidden = [p for p in paths if _is_read_forbidden(handle, p)]
        if forbidden:
            dropped.extend(forbidden)
            continue
        kept_lines.append(raw_line)
    if not dropped:
        return result
    filtered = dict(result)
    filtered["stdout"] = "\n".join(kept_lines) + ("\n" if kept_lines else "")
    filtered["forbidden_paths_filtered"] = sorted(set(dropped))
    return filtered


def _strip_quotes(path: str) -> str:
    # Porcelain quotes paths with unusual chars; strip them.
    text = path.strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        return text[1:-1]
    return text


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
    if not isinstance(result, dict):
        return result
    stdout = result.get("stdout")
    if not isinstance(stdout, str) or not stdout:
        return result
    hunks = _split_git_diff_hunks(stdout)
    if not hunks:
        return result
    kept: list[str] = []
    dropped: list[str] = []
    for path, body in hunks:
        if path is not None and _is_read_forbidden(handle, path):
            dropped.append(path)
            continue
        kept.append(body)
    if not dropped:
        return result
    filtered = dict(result)
    filtered["stdout"] = "".join(kept)
    filtered["forbidden_paths_filtered"] = sorted(set(dropped))
    return filtered


def _split_git_diff_hunks(stdout: str) -> list[tuple[str | None, str]]:
    # Returns (path, hunk_text); path is None on malformed header.
    if "diff --git" not in stdout:
        return []
    hunks: list[tuple[str | None, str]] = []
    current_path: str | None = None
    current_lines: list[str] = []
    for line in stdout.splitlines(keepends=True):
        if line.startswith("diff --git "):
            if current_lines:
                hunks.append((current_path, "".join(current_lines)))
            current_lines = [line]
            current_path = _parse_diff_git_header(line)
        else:
            current_lines.append(line)
    if current_lines:
        hunks.append((current_path, "".join(current_lines)))
    return hunks


def _parse_diff_git_header(line: str) -> str | None:
    # `diff --git a/<p> b/<p>` -> b path.
    parts = line.strip().split()
    if len(parts) < 4:
        return None
    a_path = parts[2]
    b_path = parts[3]
    if a_path.startswith("a/"):
        a_path = a_path[2:]
    if b_path.startswith("b/"):
        b_path = b_path[2:]
    return b_path or a_path or None


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
        # Custom policy enabling git/run must not accept a model-
        # supplied approval channel; treat requires_approval as deny.
        _require_git_run_approval_or_deny(handle, command)
        # Reject flags that retarget git at a different worktree.
        _reject_git_run_flag_escape(command)
        return await _agent(handle).git.run(
            command, executor=partial(_exec.git_run_executor, cwd=handle.cwd)
        )

    return _wrap_envelope(handle, "chio_git_run", inner)


def _require_git_run_approval_or_deny(handle: RuntimeHandle, command: str) -> None:
    # `policy.check_shell` returns True when approval is required; with
    # no trusted approval channel, deny.
    policy = handle.policy
    if policy is None:
        return
    from chio_code_agent.errors import ChioCodeAgentDeniedError

    if bool(policy.check_shell(command)):
        raise ChioCodeAgentDeniedError(
            f"git command {command!r} requires approval; no approval channel is configured",
            tool_name="git_run",
            reason="requires_approval",
            guard="shell_command",
        )


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
