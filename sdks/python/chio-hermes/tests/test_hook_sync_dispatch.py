"""Regression tests for Hermes-faithful sync hook dispatch.

Hermes's `PluginManager.invoke_hook` (`hermes_cli/plugins.py:1218-1232`)
calls every registered hook callback as `ret = cb(**kwargs)` with NO
await. If our hook factories return coroutines, the coroutine object
ends up in the results list and gets garbage-collected (raising a
`RuntimeWarning: coroutine ... was never awaited`), and the hook's
side effects (policy verdict, receipt JSONL append, pending flush)
NEVER run.

These tests exercise the registered hooks the same way Hermes does -
through `SyncFakePluginContext.invoke_hook_sync` - and assert that:

* `pre_tool_call` returns `dict | None`, NEVER a coroutine
* `post_tool_call` writes the receipt synchronously (verifiable on
  the JSONL file BEFORE returning)
* `on_session_start` / `on_session_end` mutate the buffer state
  synchronously

The unit tests in `test_hooks.py` verify each factory's body in
isolation; this file is the integration-style guard against the
specific bug F1 in DOGFOOD.md (silently dropped coroutines).
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


# ---------------------------------------------------------------------------
# pre_tool_call sync dispatch
# ---------------------------------------------------------------------------


def test_pre_tool_call_sync_dispatch_returns_dict_not_coroutine(
    sync_fake_plugin_context: SyncFakePluginContext,
    monkeypatch: pytest.MonkeyPatch,
    tmp_workspace: Path,
) -> None:
    """The deny path must return a dict directly, not a coroutine."""
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
    """Allowed calls return None directly; results list stays empty."""
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

    assert results == [], (
        "an allowed call returns None; invoke_hook_sync skips None results"
    )


def test_pre_tool_call_sync_dispatch_skips_non_chio_tool(
    sync_fake_plugin_context: SyncFakePluginContext,
    tmp_workspace: Path,
) -> None:
    """Non-chio_ tools pass through (None), no coroutine, no warning."""
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


# ---------------------------------------------------------------------------
# post_tool_call sync dispatch
# ---------------------------------------------------------------------------


def test_post_tool_call_sync_dispatch_writes_receipt_to_jsonl(
    sync_fake_plugin_context: SyncFakePluginContext,
    tmp_workspace: Path,
    tmp_hermes_home: Path,
) -> None:
    """The post hook must write the JSONL line synchronously.

    This is the bug F1 verification: prior to the fix, the post hook
    returned a coroutine that Hermes never awaited, so the JSONL file
    stayed empty. The file's contents AFTER `invoke_hook_sync` returns
    are the load-bearing assertion here - if the body never ran, the
    file is empty.
    """
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

    assert results == []  # post hook always returns None
    assert log_path.exists(), (
        "post_tool_call must have written the JSONL line synchronously"
    )
    contents = log_path.read_bytes()
    assert b"chio_file_read" in contents
    assert b"task-sync-post" in contents


def test_post_tool_call_sync_dispatch_no_runtime_warning(
    sync_fake_plugin_context: SyncFakePluginContext,
    tmp_workspace: Path,
    tmp_hermes_home: Path,
) -> None:
    """The exact reproduction from DOGFOOD F1.

    `python -W error::RuntimeWarning` would raise
    `RuntimeWarning: coroutine ... was never awaited` if the hook
    returned a coroutine. We turn RuntimeWarning into an error and
    invoke through the sync dispatcher; if the hook is sync, no warning
    is raised.
    """
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


# ---------------------------------------------------------------------------
# Session lifecycle sync dispatch
# ---------------------------------------------------------------------------


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
    assert buf.pending_total() == 0, (
        "on_session_start must have run synchronously"
    )


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
    assert len(written) == 2, "drain must have happened synchronously"
    for entry in written:
        assert entry["session_end_flush"] is True


# ---------------------------------------------------------------------------
# End-to-end through register(): hooks registered into a sync ctx must
# survive Hermes-style dispatch.
# ---------------------------------------------------------------------------


def test_register_hooks_survive_sync_dispatch(
    sync_fake_plugin_context: SyncFakePluginContext,
    monkeypatch: pytest.MonkeyPatch,
    tmp_workspace: Path,
    tmp_hermes_home: Path,
) -> None:
    """register() into a sync ctx, then invoke each hook the way Hermes does.

    Mirrors the dogfood reproduction from DOGFOOD section 7 F1, scoped
    down to one process.
    """
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
        assert pre_results == []  # allowed, returns None

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
