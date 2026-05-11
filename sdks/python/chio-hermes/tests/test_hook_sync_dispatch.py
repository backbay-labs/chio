"""Sync-dispatch regression for hooks.

Hermes's `PluginManager.invoke_hook` (`hermes_cli/plugins.py:1218-1232`)
calls every registered callback as `ret = cb(**kwargs)` with NO await,
so hooks must be plain `def`. These exercise that path via
`SyncFakePluginContext.invoke_hook_sync`.
"""

from __future__ import annotations

import inspect
import warnings
from pathlib import Path
from typing import Any

import pytest
from chio_code_agent.errors import ChioCodeAgentDeniedError

from chio_hermes import receipts as receipts_mod
from chio_hermes.hooks import (
    make_on_session_end,
    make_on_session_start,
    make_post_tool_call,
    make_pre_tool_call,
)
from chio_hermes.receipts import ReceiptBuffer
from chio_hermes.runtime import RuntimeHandle
from tests.conftest import SyncFakePluginContext, make_configured_runtime


def _runtime_with_buf(buf: ReceiptBuffer) -> RuntimeHandle:
    from chio_sdk.testing import MockChioClient

    return RuntimeHandle(
        chio_client=MockChioClient(),
        capability_id="cap-test-12345678",
        cwd=Path.cwd(),
        receipts=buf,
    )


def test_pre_tool_call_sync_dispatch_returns_dict_not_coroutine(
    sync_fake_plugin_context: SyncFakePluginContext,
    monkeypatch: pytest.MonkeyPatch,
    tmp_workspace: Path,
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

    sync_fake_plugin_context.register_hook(
        "pre_tool_call", make_pre_tool_call(runtime)
    )

    with warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)
        results = sync_fake_plugin_context.invoke_hook_sync(
            "pre_tool_call",
            tool_name="chio_file_write",
            args={"path": ".env", "content": "x"},
            task_id="task-sync-1",
        )

    assert len(results) == 1
    verdict = results[0]
    assert not inspect.iscoroutine(verdict), (
        "Hermes does NOT await hook returns; pre_tool_call must be sync"
    )
    assert isinstance(verdict, dict)
    assert verdict["action"] == "block"
    assert verdict["guard"] == "ForbiddenPathGuard"


def test_pre_tool_call_sync_dispatch_returns_none_for_allowed_call(
    sync_fake_plugin_context: SyncFakePluginContext,
    tmp_workspace: Path,
) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)
    sync_fake_plugin_context.register_hook(
        "pre_tool_call", make_pre_tool_call(runtime)
    )

    with warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)
        results = sync_fake_plugin_context.invoke_hook_sync(
            "pre_tool_call",
            tool_name="chio_file_read",
            args={"path": "README.md"},
            task_id="task-sync-2",
        )

    assert results == []


def test_pre_tool_call_sync_dispatch_skips_non_chio_tool(
    sync_fake_plugin_context: SyncFakePluginContext,
    tmp_workspace: Path,
) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)
    sync_fake_plugin_context.register_hook(
        "pre_tool_call", make_pre_tool_call(runtime)
    )

    with warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)
        results = sync_fake_plugin_context.invoke_hook_sync(
            "pre_tool_call",
            tool_name="read_file",
            args={"path": ".env"},
            task_id="task-sync-3",
        )

    assert results == []


def test_post_tool_call_sync_dispatch_writes_receipt_to_jsonl(
    sync_fake_plugin_context: SyncFakePluginContext,
    tmp_workspace: Path,
    tmp_hermes_home: Path,
) -> None:
    """The body must run synchronously; an async hook would leave the file empty."""
    runtime = make_configured_runtime(cwd=tmp_workspace)
    sync_fake_plugin_context.register_hook(
        "post_tool_call", make_post_tool_call(runtime)
    )

    log_path = tmp_hermes_home / "logs" / "chio-receipts.jsonl"
    assert not log_path.exists()

    with warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)
        results = sync_fake_plugin_context.invoke_hook_sync(
            "post_tool_call",
            tool_name="chio_file_read",
            args={"path": "README.md"},
            result='{"status": "allowed", "result": "hello"}',
            task_id="task-sync-post",
            duration_ms=11,
        )

    assert results == []
    assert log_path.exists()
    contents = log_path.read_bytes()
    assert b"chio_file_read" in contents
    assert b"task-sync-post" in contents


def test_post_tool_call_sync_dispatch_no_runtime_warning(
    sync_fake_plugin_context: SyncFakePluginContext,
    tmp_workspace: Path,
    tmp_hermes_home: Path,
) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)
    sync_fake_plugin_context.register_hook(
        "post_tool_call", make_post_tool_call(runtime)
    )

    with warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)
        sync_fake_plugin_context.invoke_hook_sync(
            "post_tool_call",
            tool_name="chio_file_read",
            args={"path": "README.md"},
            result="ok",
            task_id="task-no-warn",
            duration_ms=1,
        )


def test_on_session_start_sync_dispatch_clears_pending_immediately(
    sync_fake_plugin_context: SyncFakePluginContext,
) -> None:
    buf = ReceiptBuffer()
    buf.push("task-A", {"k": "v"})
    assert buf.pending_total() == 1

    sync_fake_plugin_context.register_hook(
        "on_session_start", make_on_session_start(_runtime_with_buf(buf))
    )

    with warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)
        results = sync_fake_plugin_context.invoke_hook_sync(
            "on_session_start", session_id="s-sync"
        )

    assert results == []
    assert buf.pending_total() == 0


def test_on_session_end_sync_dispatch_flushes_pending_immediately(
    sync_fake_plugin_context: SyncFakePluginContext,
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

    sync_fake_plugin_context.register_hook(
        "on_session_end", make_on_session_end(_runtime_with_buf(buf))
    )

    with warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)
        results = sync_fake_plugin_context.invoke_hook_sync(
            "on_session_end", session_id="s-end-sync"
        )

    assert results == []
    assert buf.pending_total() == 0
    assert len(written) == 2
    for entry in written:
        assert entry["session_end_flush"] is True


def test_register_hooks_survive_sync_dispatch(
    sync_fake_plugin_context: SyncFakePluginContext,
    monkeypatch: pytest.MonkeyPatch,
    tmp_workspace: Path,
    tmp_hermes_home: Path,
) -> None:
    monkeypatch.setenv("CHIO_SIDECAR_URL", "http://127.0.0.1:9090")
    monkeypatch.setenv("CHIO_CAPABILITY_ID", "cap-sync-dispatch-test")
    monkeypatch.chdir(tmp_workspace)

    from chio_hermes import register

    plugin = register(sync_fake_plugin_context)
    assert set(plugin.hook_names) == {
        "pre_tool_call",
        "post_tool_call",
        "on_session_start",
        "on_session_end",
    }

    with warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)

        pre_results = sync_fake_plugin_context.invoke_hook_sync(
            "pre_tool_call",
            tool_name="chio_file_read",
            args={"path": "README.md"},
            task_id="task-e2e",
        )
        assert pre_results == []

        sync_fake_plugin_context.invoke_hook_sync(
            "post_tool_call",
            tool_name="chio_file_read",
            args={"path": "README.md"},
            result="ok",
            task_id="task-e2e",
            duration_ms=3,
        )
        sync_fake_plugin_context.invoke_hook_sync(
            "on_session_start", session_id="sess-e2e"
        )
        sync_fake_plugin_context.invoke_hook_sync(
            "on_session_end", session_id="sess-e2e"
        )

    log_path = tmp_hermes_home / "logs" / "chio-receipts.jsonl"
    assert log_path.exists()
    assert b"task-e2e" in log_path.read_bytes()
