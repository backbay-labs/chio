"""Hook-layer tests.

Hermes dispatches hooks synchronously (no await); all hooks are plain
`def` and asserted to never return a coroutine. Sync-dispatch
regression coverage lives in `tests/test_hook_sync_dispatch.py`.
"""

from __future__ import annotations

import inspect
from pathlib import Path
from typing import Any

import pytest
from chio_code_agent.errors import ChioCodeAgentDeniedError
from chio_sdk.testing import MockChioClient

from chio_hermes import receipts as receipts_mod
from chio_hermes.hooks import (
    make_on_session_end,
    make_on_session_start,
    make_post_tool_call,
    make_pre_tool_call,
)
from chio_hermes.receipts import ReceiptBuffer
from chio_hermes.runtime import RuntimeHandle
from tests.conftest import make_configured_runtime


def _runtime_with_buf(buf: ReceiptBuffer) -> RuntimeHandle:
    return RuntimeHandle(
        chio_client=MockChioClient(),
        capability_id="cap-test-12345678",
        cwd=Path.cwd(),
        receipts=buf,
    )


def test_pre_tool_call_returns_block_dict_for_denied_path(
    monkeypatch: pytest.MonkeyPatch, tmp_workspace: Path
) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)

    def _raise(*_args: Any, **_kwargs: Any) -> None:
        raise ChioCodeAgentDeniedError(
            "writing to .env is forbidden",
            tool_name="write_file",
            guard="ForbiddenPathGuard",
            reason=".env matches forbidden_path_patterns",
        )

    monkeypatch.setattr(runtime.policy, "check_write", _raise)

    hook = make_pre_tool_call(runtime)
    result = hook(
        tool_name="chio_file_write",
        args={"path": ".env", "content": "x"},
        task_id="task-1",
    )
    assert not inspect.iscoroutine(result), "pre hook must be sync (Hermes does not await)"

    assert isinstance(result, dict)
    assert result["action"] == "block"
    assert result["guard"] == "ForbiddenPathGuard"
    assert result["reason"] == ".env matches forbidden_path_patterns"
    assert "writing to .env is forbidden" in result["message"]


def test_pre_tool_call_blocks_unexpected_policy_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_workspace: Path
) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)

    def _raise(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("policy backend unavailable")

    monkeypatch.setattr(runtime.policy, "check_write", _raise)

    hook = make_pre_tool_call(runtime)
    result = hook(
        tool_name="chio_file_write",
        args={"path": "src/main.py", "content": "x"},
        task_id="task-policy-error",
    )

    assert isinstance(result, dict)
    assert result["action"] == "block"
    assert result["guard"] == "chio_policy_error"
    assert result["reason"] == "policy_error"


def test_pre_tool_call_treats_git_add_string_as_single_path(
    monkeypatch: pytest.MonkeyPatch, tmp_workspace: Path
) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)
    seen: list[str] = []

    def _record(path: str, **_kwargs: Any) -> None:
        seen.append(path)

    monkeypatch.setattr(runtime.policy, "check_write", _record)

    hook = make_pre_tool_call(runtime)
    result = hook(
        tool_name="chio_git_add",
        args={"paths": ".env"},
        task_id="task-git-add-string",
    )

    assert result is None
    assert seen == [".env"]


def test_pre_tool_call_returns_none_for_allowed_call(
    tmp_workspace: Path,
) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)
    hook = make_pre_tool_call(runtime)
    result = hook(
        tool_name="chio_file_read",
        args={"path": "README.md"},
        task_id="task-1",
    )
    assert not inspect.iscoroutine(result)
    assert result is None


def test_pre_tool_call_blocks_on_unexpected_policy_error(
    monkeypatch: pytest.MonkeyPatch, tmp_workspace: Path
) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)

    def _raise(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("policy backend unavailable")

    monkeypatch.setattr(runtime.policy, "check_read", _raise)

    hook = make_pre_tool_call(runtime)
    result = hook(
        tool_name="chio_file_read",
        args={"path": "README.md"},
        task_id="task-1",
    )
    assert not inspect.iscoroutine(result)
    assert isinstance(result, dict)
    assert result["action"] == "block"
    assert result["guard"] == "chio_policy_error"
    assert result["reason"] == "policy_error"
    assert "policy backend unavailable" in result["message"]


def test_pre_tool_call_ignores_non_chio_tool(
    tmp_workspace: Path,
) -> None:
    """Non-chio_ tools pass through untouched (other plugins own them)."""
    runtime = make_configured_runtime(cwd=tmp_workspace)
    hook = make_pre_tool_call(runtime)
    result = hook(
        tool_name="read_file",  # built-in Hermes tool, not ours
        args={"path": ".env"},
        task_id="task-1",
    )
    assert not inspect.iscoroutine(result)
    assert result is None


@pytest.mark.parametrize(
    "command",
    [
        "push --force origin main",
        "push -f",
        "push --force-with-lease origin main",
        "reset --hard origin/main",
        # Already-prefixed forms should still trip (no double prefix).
        "git push --force origin main",
        "git reset --hard origin/main",
    ],
)
def test_pre_tool_call_blocks_chio_git_run_force_push(
    tmp_workspace: Path, command: str
) -> None:
    """Regression: chio_git_run must block git_deny patterns even though the
    model passes a subcommand argv ('push --force') without the leading
    `git ` token. The hook prefixes `git ` before pattern-matching so the
    default policy's `git\\s+push\\s+.*--force` regex matches.
    """
    runtime = make_configured_runtime(cwd=tmp_workspace)
    hook = make_pre_tool_call(runtime)
    result = hook(
        tool_name="chio_git_run",
        args={"command": command},
        task_id="task-git-deny",
    )
    assert isinstance(result, dict), (
        f"chio_git_run('{command}') was NOT blocked by pre_tool_call hook; "
        f"got {result!r}. The default policy's git_deny / shell_forbidden "
        f"patterns are anchored on `git\\s+...` and need a `git ` prefix."
    )
    assert result.get("action") == "block"


def test_pre_tool_call_allows_chio_git_run_safe_subcommand(
    tmp_workspace: Path,
) -> None:
    """Sanity: a benign git subcommand still passes the pre-hook (the
    deny-only check). Allow-listing happens at the executor / SDK layer.
    """
    runtime = make_configured_runtime(cwd=tmp_workspace)
    hook = make_pre_tool_call(runtime)
    result = hook(
        tool_name="chio_git_run",
        args={"command": "status"},
        task_id="task-git-safe",
    )
    assert result is None


def test_post_tool_call_writes_receipt_with_result_and_duration(
    tmp_workspace: Path,
    tmp_hermes_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)

    written: list[dict[str, Any]] = []

    def _capture_jsonl(_path: Path, payload: dict[str, Any]) -> None:
        written.append(dict(payload))

    monkeypatch.setattr(receipts_mod, "append_jsonl", _capture_jsonl)

    hook = make_post_tool_call(runtime)
    result = hook(
        tool_name="chio_file_read",
        args={"path": "README.md"},
        result='{"status": "allowed", "result": "hello"}',
        task_id="task-post-1",
        duration_ms=42,
    )
    assert not inspect.iscoroutine(result)
    assert result is None
    assert written, "post_tool_call must have appended a JSONL line"
    payload = written[-1]
    assert payload["task_id"] == "task-post-1"
    assert payload["tool_name"] == "chio_file_read"
    assert payload["duration_ms"] == 42.0
    assert "result" in payload


def test_post_tool_call_tolerates_writer_failure(
    tmp_workspace: Path,
    tmp_hermes_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """JSONL writer failure must not propagate.

    Hermes treats any hook exception as a fatal session error; that
    would convert a debug-only side effect into a session killer.
    """
    runtime = make_configured_runtime(cwd=tmp_workspace)

    def _boom(_path: Path, _payload: dict[str, Any]) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(receipts_mod, "append_jsonl", _boom)

    hook = make_post_tool_call(runtime)
    result = hook(
        tool_name="chio_file_read",
        args={"path": "README.md"},
        result='{"status": "allowed"}',
        task_id="task-fail-1",
        duration_ms=7,
    )
    assert not inspect.iscoroutine(result)
    assert result is None


def test_buffer_push_pop_next_isolates_per_task() -> None:
    buf = ReceiptBuffer()
    buf.push("task-A", {"i": 0})
    buf.push("task-B", {"i": 1})
    buf.push("task-A", {"i": 2})
    assert buf.pop_next("task-A") == {"i": 0}
    assert buf.pop_next("task-A") == {"i": 2}
    assert buf.pop_next("task-A") is None
    assert buf.pop_next("task-B") == {"i": 1}


def test_on_session_start_clears_pending() -> None:
    buf = ReceiptBuffer()
    buf.push("task-A", {"k": "v"})
    assert buf.pending_total() == 1
    hook = make_on_session_start(_runtime_with_buf(buf))
    result = hook(session_id="s-1")
    assert not inspect.iscoroutine(result)
    assert buf.pending_total() == 0


def test_on_session_end_flushes_pending(
    tmp_hermes_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    buf = ReceiptBuffer()
    buf.push("task-A", {"tool_name": "chio_file_read", "args": {}})
    buf.push("task-B", {"tool_name": "chio_file_write", "args": {}})
    assert buf.pending_total() == 2

    written: list[dict[str, Any]] = []

    def _capture(_path: Path, payload: dict[str, Any]) -> None:
        written.append(dict(payload))

    monkeypatch.setattr(receipts_mod, "append_jsonl", _capture)

    hook = make_on_session_end(_runtime_with_buf(buf))
    result = hook(session_id="s-end")
    assert not inspect.iscoroutine(result)

    assert buf.pending_total() == 0
    assert len(written) == 2
    for entry in written:
        assert entry["session_end_flush"] is True
        assert "recorded_at" in entry
