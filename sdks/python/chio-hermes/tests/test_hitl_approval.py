"""Tests for the HITL approval channel wiring in chio-hermes."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from chio_code_agent.policy import DEFAULT_POLICY, AllowedTool

from chio_hermes.handlers import make_handler
from chio_hermes.manifest import TOOL_TABLE
from tests.conftest import make_configured_runtime


def _by_name(name: str) -> Any:
    by_name = {entry.name: entry for entry in TOOL_TABLE}
    return by_name[name]


@pytest.mark.asyncio
async def test_chio_shell_run_returns_requires_approval_envelope(
    tmp_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)
    monkeypatch.setattr(runtime.policy, "check_shell", lambda _cmd: True)

    handler = make_handler(runtime, _by_name("chio_shell_run"))
    payload = json.loads(
        await handler({"command": "rm -rf old_build/"}, task_id="t-shell-1")
    )

    assert payload["status"] == "requires_approval"
    assert payload["error"] == "chio_requires_approval"
    assert payload["approval_id"].startswith("mock-ap-")
    assert payload["tool_server"] == "shell"
    assert payload["tool_name"] == "chio_shell_run"
    assert payload["command"] == "rm -rf old_build/"
    assert "approve" in payload["hint"]


@pytest.mark.asyncio
async def test_chio_shell_run_records_submit_call_with_command_args(
    tmp_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)
    monkeypatch.setattr(runtime.policy, "check_shell", lambda _cmd: True)

    handler = make_handler(runtime, _by_name("chio_shell_run"))
    await handler({"command": "rm -rf old_build/"}, task_id="t-shell-2")

    submits = [
        call
        for call in runtime.chio_client.calls
        if call.method == "submit_for_approval"
    ]
    assert len(submits) == 1
    ctx = submits[0].context
    assert ctx["tool_name"] == "chio_shell_run"
    assert ctx["tool_server"] == "shell"
    assert ctx["capability_id"] == runtime.capability_id
    assert "rm -rf" in (ctx.get("summary") or "")


@pytest.mark.asyncio
async def test_chio_shell_run_allows_when_policy_does_not_require_approval(
    tmp_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)
    monkeypatch.setattr(runtime.policy, "check_shell", lambda _cmd: False)

    handler = make_handler(runtime, _by_name("chio_shell_run"))
    payload = json.loads(
        await handler({"command": "ls -la"}, task_id="t-shell-3")
    )

    # Allowed path: no approval submission, no requires_approval envelope.
    assert payload.get("error") != "chio_requires_approval"
    submits = [
        call
        for call in runtime.chio_client.calls
        if call.method == "submit_for_approval"
    ]
    assert submits == []


@pytest.mark.asyncio
async def test_chio_shell_run_requires_approval_when_policy_check_raises(
    tmp_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)

    def raise_policy_error(_cmd: str) -> bool:
        raise RuntimeError("policy failed")

    monkeypatch.setattr(runtime.policy, "check_shell", raise_policy_error)

    handler = make_handler(runtime, _by_name("chio_shell_run"))
    payload = json.loads(
        await handler({"command": "rm -rf old_build/"}, task_id="t-shell-policy-error")
    )

    assert payload["status"] == "requires_approval"
    assert payload["error"] == "chio_requires_approval"


@pytest.mark.asyncio
async def test_chio_git_run_returns_requires_approval_envelope(
    tmp_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    custom_policy = copy.copy(DEFAULT_POLICY)
    custom_policy.allowed_tools = set(DEFAULT_POLICY.allowed_tools) | {
        AllowedTool(server="git", tool="run")
    }
    runtime = make_configured_runtime(cwd=tmp_workspace, policy=custom_policy)
    monkeypatch.setattr(runtime.policy, "check_shell", lambda _cmd: True)
    monkeypatch.setattr(runtime.policy, "check_git", lambda _cmd: None)

    handler = make_handler(runtime, _by_name("chio_git_run"))
    payload = json.loads(
        await handler({"command": "reset --hard"}, task_id="t-git-1")
    )

    assert payload["status"] == "requires_approval"
    assert payload["error"] == "chio_requires_approval"
    assert payload["tool_server"] == "git"
    assert payload["tool_name"] == "chio_git_run"
    assert payload["command"] == "reset --hard"


@pytest.mark.asyncio
async def test_chio_shell_run_falls_back_to_legacy_deny_when_client_missing(
    tmp_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)
    monkeypatch.setattr(runtime.policy, "check_shell", lambda _cmd: True)
    runtime.chio_client = None  # simulate degraded mode

    handler = make_handler(runtime, _by_name("chio_shell_run"))
    payload = json.loads(
        await handler({"command": "rm -rf old/"}, task_id="t-shell-4")
    )

    # Without a client we still want a typed error, just not the
    # requires_approval envelope (which would lie about the queue).
    # The plugin short-circuits on chio_not_configured because
    # is_configured() now returns False.
    assert payload["error"] == "chio_not_configured"
