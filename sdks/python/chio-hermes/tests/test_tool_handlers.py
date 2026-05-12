"""Per-handler unit tests against `MockChioClient`.

Every entry in `manifest.TOOL_TABLE` must:

* return a JSON string (never raise),
* on allow, return `"status": "allowed"` per the canonical envelope,
* on deny (e.g. `.env`), return `"error": "denied"`.

No live sidecar is touched.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from chio_sdk.testing import MockChioClient, MockVerdict

from chio_hermes.handlers import make_handler
from chio_hermes.manifest import TOOL_TABLE, ToolEntry
from chio_hermes.receipts import ReceiptBuffer
from tests.conftest import make_configured_runtime


def _allow_all_policy(_tool: str, _scope: dict, _ctx: dict) -> MockVerdict:
    return MockVerdict.allow_verdict()


def _deny_env_policy(tool: str, _scope: dict, ctx: dict) -> MockVerdict:
    """Deny any call whose `parameters.path` looks like `.env`."""
    params = ctx.get("parameters", {}) if isinstance(ctx, dict) else {}
    path = (params.get("path") or "")
    if path.endswith(".env") or ".env" in path:
        return MockVerdict.deny_verdict(
            "path .env is forbidden", guard="ForbiddenPathGuard"
        )
    return MockVerdict.allow_verdict()


@pytest.fixture
def tool_table() -> list[ToolEntry]:
    assert TOOL_TABLE, "TOOL_TABLE is empty"
    return list(TOOL_TABLE)


def _entry_args_for(entry_name: str, _workspace: Path) -> dict[str, Any]:
    """Build a minimal valid `args` dict per tool name.

    Paths target locations under `src/` so they fall inside
    DEFAULT_POLICY's `writable_roots` (`{docs, src, tests}`).
    """
    if entry_name == "chio_file_read":
        return {"path": "README.md"}
    if entry_name == "chio_file_write":
        return {"path": "src/new.py", "content": "x = 1\n"}
    if entry_name == "chio_file_edit":
        return {"path": "src/main.py", "patch": "--- a\n+++ b\n"}
    if entry_name == "chio_file_list":
        return {"path": "."}
    if entry_name == "chio_file_search":
        return {"query": "*.py"}
    if entry_name == "chio_shell_run":
        return {"command": "echo hello"}
    if entry_name == "chio_git_status":
        return {}
    if entry_name == "chio_git_diff":
        return {}
    if entry_name == "chio_git_log":
        return {"limit": 5}
    if entry_name == "chio_git_add":
        return {"paths": ["src/main.py"]}
    if entry_name == "chio_git_commit":
        return {"message": "test commit"}
    if entry_name == "chio_git_run":
        return {"command": "status"}
    raise AssertionError(f"unknown tool {entry_name!r}")


@pytest.mark.asyncio
async def test_every_handler_returns_json_string_on_allow(
    tool_table: list[ToolEntry],
    tmp_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Patch every shell-out executor so the test stays hermetic; the
    # contract under test is the envelope shape, not the I/O.
    from chio_hermes import executors as _exec

    async def _ok(**_kw: Any) -> dict[str, Any]:
        return {"ok": True}

    for name in (
        "edit_file_executor",
        "list_directory_executor",
        "search_files_executor",
        "shell_run_executor",
        "git_status_executor",
        "git_diff_executor",
        "git_log_executor",
        "git_add_executor",
        "git_commit_executor",
        "git_run_executor",
    ):
        monkeypatch.setattr(_exec, name, _ok)

    client = MockChioClient(policy=_allow_all_policy)
    runtime = make_configured_runtime(chio_client=client, cwd=tmp_workspace)

    for entry in tool_table:
        # chio_git_run routes through git/run, which is not in
        # DEFAULT_POLICY.allowed_tools; the local pre-flight denies
        # before the sidecar verdict is consulted. Correct fail-closed
        # behaviour, exercised separately.
        if entry.name == "chio_git_run":
            continue
        handler = make_handler(runtime, entry)
        args = _entry_args_for(entry.name, tmp_workspace)

        result = await handler(args, task_id="task-1")

        assert isinstance(result, str), (
            f"{entry.name} handler must return a JSON string, got {type(result).__name__}"
        )
        payload = json.loads(result)
        assert isinstance(payload, dict)
        assert payload.get("status") == "allowed", (
            f"{entry.name} allow envelope must be status=allowed, got {payload!r}"
        )
        assert payload.get("tool_name") == entry.name
        assert "tool_server" in payload
        assert "result" in payload


@pytest.mark.asyncio
async def test_handlers_deny_forbidden_path(
    tool_table: list[ToolEntry], tmp_workspace: Path
) -> None:
    """Every chio_file_* handler surfaces the canonical denied envelope
    when the local pre-flight rejects `.env`."""
    client = MockChioClient(policy=_deny_env_policy)
    runtime = make_configured_runtime(chio_client=client, cwd=tmp_workspace)

    by_name = {entry.name: entry for entry in tool_table}
    candidates = [
        "chio_file_read",
        "chio_file_write",
        "chio_file_edit",
        "chio_file_list",
    ]

    for name in candidates:
        handler = make_handler(runtime, by_name[name])
        args = dict(_entry_args_for(name, tmp_workspace))
        args["path"] = ".env"
        if name == "chio_file_write":
            args.setdefault("content", "BAD=value")
        if name == "chio_file_edit":
            args.setdefault("patch", "--- a\n+++ b\n")

        result = await handler(args, task_id="task-deny")
        payload = json.loads(result)
        assert payload["error"] == "denied", (
            f"{name} must surface the canonical denied envelope, got {payload!r}"
        )
        # The local pre-flight raises before the sidecar is consulted,
        # so the guard is "forbidden_path" (NOT the sidecar's
        # "ForbiddenPathGuard"); _deny_env_policy is never reached.
        assert payload["guard"] == "forbidden_path"
        assert payload["reason"] is not None


@pytest.mark.asyncio
async def test_handler_never_raises_on_internal_error(
    tool_table: list[ToolEntry],
    tmp_workspace: Path,
) -> None:
    """A bare exception from the sidecar surfaces as `chio_error` and
    never propagates past the handler.

    `chio_git_run` is excluded because it routes through `git/run`,
    which is not in `DEFAULT_POLICY.allowed_tools`; the local
    pre-flight raises `ChioCodeAgentDeniedError` BEFORE the sidecar is
    consulted (correct fail-closed behaviour for an unmapped subcommand).
    """

    class _Boom(MockChioClient):
        async def evaluate_tool_call(self, **_: Any) -> Any:
            raise RuntimeError("synthetic kaboom")

    client = _Boom()
    runtime = make_configured_runtime(chio_client=client, cwd=tmp_workspace)

    for entry in tool_table:
        if entry.name == "chio_git_run":
            continue
        handler = make_handler(runtime, entry)
        args = _entry_args_for(entry.name, tmp_workspace)
        result = await handler(args, task_id="task-err")
        assert isinstance(result, str)
        payload = json.loads(result)
        assert isinstance(payload, dict)
        assert payload["error"] == "chio_error", (
            f"{entry.name} must surface chio_error envelope, got {payload!r}"
        )


@pytest.mark.asyncio
async def test_chio_git_run_fails_closed_when_not_in_allow_list(
    tmp_workspace: Path,
) -> None:
    """`chio_git_run` routes through `git/run`, not in
    DEFAULT_POLICY.allowed_tools; every dispatch fail-closes at the
    local pre-flight."""
    by_name = {entry.name: entry for entry in TOOL_TABLE}
    client = MockChioClient(policy=_allow_all_policy)
    runtime = make_configured_runtime(chio_client=client, cwd=tmp_workspace)
    handler = make_handler(runtime, by_name["chio_git_run"])

    payload = json.loads(await handler({"command": "status"}, task_id="t-run"))
    assert payload["error"] == "denied"
    assert payload["guard"] == "tool_access"
    assert payload["reason"] == "not_in_allow_list"


def test_tool_server_inference_covers_three_servers() -> None:
    from chio_hermes.handlers import _tool_server_for

    assert _tool_server_for("chio_file_read") == "fs"
    assert _tool_server_for("chio_file_write") == "fs"
    assert _tool_server_for("chio_shell_run") == "shell"
    assert _tool_server_for("chio_git_status") == "git"


def test_receipt_buffer_push_pop_next_direct() -> None:
    """`push` / `pop_next` API stays exposed for deferred-record use
    cases even though handlers no longer use it (post-hook owns the
    record)."""
    buf = ReceiptBuffer()
    record = {"tool_name": "chio_file_read", "args": {"path": "README.md"}}
    buf.push("task-1", record)
    popped = buf.pop_next("task-1")
    assert popped == record
    assert buf.pop_next("task-1") is None


def test_chio_shell_run_schema_does_not_expose_approved() -> None:
    """A model-supplied `approved=true` would bypass CodeAgentPolicy's
    approval list (rm -rf <subdir>, mv, git reset --hard). Drop the
    property so `additionalProperties: false` rejects it."""
    from chio_hermes.schemas import CHIO_SHELL_RUN

    parameters = CHIO_SHELL_RUN["parameters"]
    assert "approved" not in parameters["properties"]
    assert parameters.get("additionalProperties") is False


@pytest.mark.asyncio
async def test_chio_shell_run_handler_ignores_caller_supplied_approved(
    tmp_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Handler MUST pass `approved=False` regardless of caller args."""
    from chio_hermes import executors as _exec

    runtime = make_configured_runtime(
        chio_client=MockChioClient(policy=_allow_all_policy),
        cwd=tmp_workspace,
    )

    captured: dict[str, Any] = {}

    real_run_command = runtime.code_agent.shell.run_command

    async def _spy_run_command(command: str, **kwargs: Any) -> Any:
        captured["command"] = command
        captured["kwargs"] = dict(kwargs)
        return await real_run_command(command, **kwargs)

    runtime.code_agent.shell.run_command = _spy_run_command  # type: ignore[method-assign]

    async def _ok(**_kw: Any) -> dict[str, Any]:
        return {"ok": True}

    monkeypatch.setattr(_exec, "shell_run_executor", _ok)

    by_name = {entry.name: entry for entry in TOOL_TABLE}
    handler = make_handler(runtime, by_name["chio_shell_run"])

    result = await handler(
        {"command": "echo hi", "approved": True}, task_id="task-approval"
    )

    assert isinstance(result, str)
    payload = json.loads(result)
    assert "kwargs" in captured, (
        f"handler did not invoke run_command (envelope: {payload!r})"
    )
    assert captured["kwargs"].get("approved") is False
