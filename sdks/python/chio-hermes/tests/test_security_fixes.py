"""Regression tests for the bot-reviewer security findings on PR #650.

Each test pins one of the fixes documented in the PR commit body so a
later refactor cannot silently re-open the hole.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from chio_sdk.testing import MockChioClient, MockVerdict

from chio_hermes import handlers as _handlers
from chio_hermes import hooks as _hooks
from chio_hermes import runtime as _runtime
from chio_hermes.commands import make_slash_handler
from chio_hermes.handlers import make_handler
from chio_hermes.manifest import TOOL_TABLE
from chio_hermes.receipts import ReceiptBuffer
from tests.conftest import make_configured_runtime


def _allow_all_policy(_t: str, _s: dict, _c: dict) -> MockVerdict:
    return MockVerdict.allow_verdict()


# ---------------------------------------------------------------------------
# P1-2: fail closed when CHIO_POLICY_FILE is set but unreadable
# ---------------------------------------------------------------------------


def test_runtime_fails_closed_when_policy_file_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`CHIO_POLICY_FILE` opt-in must NOT fall back to DEFAULT_POLICY."""
    missing = tmp_path / "does-not-exist.yaml"
    monkeypatch.setenv("CHIO_POLICY_FILE", str(missing))
    monkeypatch.setenv("CHIO_SIDECAR_URL", "http://127.0.0.1:9090")
    monkeypatch.setenv("CHIO_CAPABILITY_ID", "cap-test-12345678")
    monkeypatch.chdir(tmp_path)

    handle = _runtime.build_runtime_handle()
    assert handle.is_configured() is False
    assert handle.init_error is not None
    assert "policy_load_failed" in handle.init_error


def test_runtime_uses_default_policy_when_env_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No env var: fall back to the bundled default (existing behaviour)."""
    monkeypatch.delenv("CHIO_POLICY_FILE", raising=False)
    monkeypatch.setenv("CHIO_SIDECAR_URL", "http://127.0.0.1:9090")
    monkeypatch.setenv("CHIO_CAPABILITY_ID", "cap-test-12345678")
    monkeypatch.chdir(tmp_path)

    handle = _runtime.build_runtime_handle()
    assert handle.policy is not None
    assert handle.init_error is None


# ---------------------------------------------------------------------------
# P1-3: filter forbidden paths from `chio_git_diff`
# ---------------------------------------------------------------------------


def test_filter_diff_output_drops_forbidden_hunks(tmp_workspace: Path) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)
    diff_text = (
        "diff --git a/.env b/.env\n"
        "--- a/.env\n"
        "+++ b/.env\n"
        "+SECRET=topsecret\n"
        "diff --git a/src/main.py b/src/main.py\n"
        "--- a/src/main.py\n"
        "+++ b/src/main.py\n"
        "+x = 2\n"
    )
    raw = {"stdout": diff_text, "returncode": 0}
    filtered = _handlers._filter_diff_output(runtime, raw)
    assert "SECRET=topsecret" not in filtered["stdout"]
    assert "x = 2" in filtered["stdout"]
    assert ".env" in filtered["forbidden_paths_filtered"]


def test_filter_diff_output_no_op_on_clean_diff(tmp_workspace: Path) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)
    raw = {
        "stdout": (
            "diff --git a/src/main.py b/src/main.py\n"
            "--- a/src/main.py\n"
            "+++ b/src/main.py\n"
            "+x = 1\n"
        ),
        "returncode": 0,
    }
    out = _handlers._filter_diff_output(runtime, raw)
    assert "forbidden_paths_filtered" not in out
    assert out is raw


# ---------------------------------------------------------------------------
# P1-4: reject shell argv tokens that escape the workspace
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_chio_shell_run_rejects_dotdot_token(
    tmp_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from chio_hermes import executors as _exec

    async def _ok(**_kw: Any) -> dict[str, Any]:
        return {"ok": True}

    monkeypatch.setattr(_exec, "shell_run_executor", _ok)

    runtime = make_configured_runtime(
        chio_client=MockChioClient(policy=_allow_all_policy), cwd=tmp_workspace
    )
    by_name = {entry.name: entry for entry in TOOL_TABLE}
    handler = make_handler(runtime, by_name["chio_shell_run"])

    payload = json.loads(
        await handler({"command": "cat ../etc/passwd"}, task_id="t-escape")
    )
    assert payload["error"] == "denied"
    assert payload["guard"] == "chio_path_escape"


# ---------------------------------------------------------------------------
# P1-5: expand `chio_git_add` pathspecs and policy-check each result
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_chio_git_add_rejects_forbidden_expansion(
    tmp_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pathspec that expands to `.env` is denied, even if `policy.check_write`
    on the literal pathspec wouldn't fail."""
    runtime = make_configured_runtime(cwd=tmp_workspace)

    async def _fake_expand(_handle: Any, _paths: list[str]) -> list[str]:
        # Pretend `git ls-files` matched `.env` from the pathspec.
        return [".env"]

    monkeypatch.setattr(_handlers, "_expand_git_pathspecs", _fake_expand)

    by_name = {entry.name: entry for entry in TOOL_TABLE}
    handler = make_handler(runtime, by_name["chio_git_add"])

    payload = json.loads(
        await handler({"paths": ["src/**"]}, task_id="t-add-forbid")
    )
    assert payload["error"] == "denied"
    assert payload["guard"] == "forbidden_path"


# ---------------------------------------------------------------------------
# P2-8: filter forbidden entries from directory listings
# ---------------------------------------------------------------------------


def test_filter_directory_entries_drops_dotenv(tmp_workspace: Path) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)
    raw = {
        "path": str(tmp_workspace),
        "entries": [".env", "README.md", "src"],
    }
    filtered = _handlers._filter_directory_entries(runtime, ".", raw)
    assert ".env" not in filtered["entries"]
    assert "README.md" in filtered["entries"]
    assert filtered["entries_filtered"] is True


# ---------------------------------------------------------------------------
# P2-9: reject `git_run` flags that escape (-C, --git-dir, ...)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "-C /tmp status",
        "--git-dir=/tmp/.git status",
        "--work-tree=/tmp status",
    ],
)
def test_reject_git_run_flag_escape(command: str) -> None:
    from chio_code_agent.errors import ChioCodeAgentDeniedError

    with pytest.raises(ChioCodeAgentDeniedError) as excinfo:
        _handlers._reject_git_run_flag_escape(command)
    assert excinfo.value.guard == "chio_path_escape"


def test_reject_git_run_flag_escape_allows_safe_git() -> None:
    # No exception for a normal subcommand.
    _handlers._reject_git_run_flag_escape("status --porcelain")


# ---------------------------------------------------------------------------
# P2-10: receipt result truncation for content-heavy tools
# ---------------------------------------------------------------------------


def test_truncate_receipt_result_truncates_file_read() -> None:
    big = '{"status":"allowed","result":"' + ("A" * 1024) + '"}'
    payload, truncated = _hooks._truncate_receipt_result("chio_file_read", big)
    assert truncated is True
    assert isinstance(payload, str)
    assert len(payload.encode("utf-8")) <= _hooks.RECEIPT_RESULT_MAX_BYTES


def test_truncate_receipt_result_passthrough_for_small_payload() -> None:
    payload, truncated = _hooks._truncate_receipt_result(
        "chio_file_read", '{"status":"allowed"}'
    )
    assert truncated is False
    assert payload == '{"status":"allowed"}'


def test_truncate_receipt_result_passthrough_for_chio_file_write() -> None:
    """chio_file_write is NOT content-heavy; the result is small status JSON."""
    big = '{"status":"allowed","result":"' + ("A" * 1024) + '"}'
    payload, truncated = _hooks._truncate_receipt_result("chio_file_write", big)
    assert truncated is False
    assert payload == big


# ---------------------------------------------------------------------------
# P2-12: search query containing `..` is rejected
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_chio_file_search_rejects_dotdot_query(
    tmp_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from chio_hermes import executors as _exec

    async def _ok(**_kw: Any) -> dict[str, Any]:
        return {"ok": True}

    monkeypatch.setattr(_exec, "search_files_executor", _ok)

    runtime = make_configured_runtime(
        chio_client=MockChioClient(policy=_allow_all_policy), cwd=tmp_workspace
    )
    by_name = {entry.name: entry for entry in TOOL_TABLE}
    handler = make_handler(runtime, by_name["chio_file_search"])

    payload = json.loads(
        await handler({"query": "../*"}, task_id="t-query-escape")
    )
    assert payload["error"] == "denied"
    assert payload["guard"] == "chio_path_escape"


# ---------------------------------------------------------------------------
# P2-14: chio_git_run never accepts model-supplied approval
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_chio_git_run_denies_when_check_shell_requires_approval(
    tmp_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A custom policy that returns `True` from `check_shell` (= requires
    approval) must be denied, not silently allowed.
    """
    # Use a freshly-cloned policy so we never mutate DEFAULT_POLICY's
    # `allowed_tools` set (other tests rely on git/run being absent).
    import copy

    from chio_code_agent.policy import DEFAULT_POLICY, AllowedTool

    custom_policy = copy.copy(DEFAULT_POLICY)
    custom_policy.allowed_tools = set(DEFAULT_POLICY.allowed_tools) | {
        AllowedTool(server="git", tool="run")
    }

    runtime = make_configured_runtime(cwd=tmp_workspace, policy=custom_policy)

    # Force check_shell to declare approval required for any git argv;
    # patch on the cloned policy only.
    monkeypatch.setattr(runtime.policy, "check_shell", lambda _cmd: True)
    monkeypatch.setattr(runtime.policy, "check_git", lambda _cmd: None)

    by_name = {entry.name: entry for entry in TOOL_TABLE}
    handler = make_handler(runtime, by_name["chio_git_run"])

    payload = json.loads(
        await handler({"command": "status"}, task_id="t-git-run-approve")
    )
    assert payload["error"] == "denied"
    assert payload["reason"] == "requires_approval"


# ---------------------------------------------------------------------------
# Cursor M: shlex.split ValueError in /chio dispatch
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_slash_chio_handles_unclosed_quote(tmp_workspace: Path) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)
    handle_slash = make_slash_handler(runtime)
    out = await handle_slash('"unclosed')
    assert out is not None
    assert "could not parse" in out


# ---------------------------------------------------------------------------
# Cursor L: ReceiptBuffer.recent(0) returns []
# ---------------------------------------------------------------------------


def test_receipt_buffer_recent_zero_returns_empty() -> None:
    buf = ReceiptBuffer()
    for i in range(5):
        buf._buffer.append({"i": i})  # type: ignore[attr-defined]
    assert buf.recent(0) == []
    assert buf.recent(-1) == []
    # Sanity: positive request still works.
    assert len(buf.recent(2)) == 2


# ---------------------------------------------------------------------------
# P2-13: receipt id from prior allow surfaces in chio_executor_error
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_executor_error_recovers_receipt_id_from_context(
    tmp_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the executor raises a generic exception (no `receipt_id`
    attribute), the wrapper still surfaces the receipt id captured from
    the most recent allow verdict by the chio_client wrapper."""

    captured: dict[str, Any] = {}

    class _ClientCapture(MockChioClient):
        async def evaluate_tool_call(self, **kw: Any) -> Any:
            receipt = await super().evaluate_tool_call(**kw)
            captured["receipt_id"] = receipt.id
            return receipt

    client = _ClientCapture(policy=_allow_all_policy)
    # Install the receipt-id capture wrapper that runtime.build_runtime_handle
    # would normally install.
    _runtime._install_receipt_id_capture(client)

    runtime = make_configured_runtime(chio_client=client, cwd=tmp_workspace)

    async def _boom(**_kw: Any) -> Any:
        raise RuntimeError("disk full")

    from chio_hermes import executors as _exec

    monkeypatch.setattr(_exec, "edit_file_executor", _boom)
    by_name = {entry.name: entry for entry in TOOL_TABLE}
    handler = make_handler(runtime, by_name["chio_file_edit"])

    payload = json.loads(
        await handler(
            {"path": "src/new.py", "patch": "--- a\n+++ b\n"},
            task_id="t-recover-rid",
        )
    )
    assert payload["error"] == "chio_executor_error"
    assert payload["receipt_id"] == captured["receipt_id"]
