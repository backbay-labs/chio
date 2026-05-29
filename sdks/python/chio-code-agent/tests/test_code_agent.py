"""Acceptance test for the 10-line chio-code-agent quickstart.

Verifies that a 10-line Python script demonstrates safe file reads
allowed and `.env` writes denied.

Also covers a few round-trip cases that exercise the real
``CodeAgent`` / ``FileTool`` surface against a ``MockChioClient``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from chio_sdk.errors import ChioDeniedError
from chio_sdk.testing import MockChioClient, MockVerdict

from chio_code_agent import (
    ChioCodeAgentDeniedError,
    CodeAgent,
    DEFAULT_POLICY,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _allow_all_policy(_tool: str, _scope: dict[str, Any], _ctx: dict[str, Any]) -> MockVerdict:
    return MockVerdict.allow_verdict()


def _project_tree(tmp_path: Path) -> Path:
    """Lay down a realistic project layout the tests can read/write in."""
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "docs").mkdir()
    (tmp_path / "README.md").write_text("hello\n", encoding="utf-8")
    (tmp_path / ".env").write_text("SECRET=shh\n", encoding="utf-8")
    (tmp_path / "src" / "main.py").write_text("print('hi')\n", encoding="utf-8")
    return tmp_path


# ---------------------------------------------------------------------------
# The 10-line quickstart
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_quickstart_safe_reads_allowed_env_writes_denied(
    tmp_path: Path,
) -> None:
    """The 10-line demo: safe reads allowed, .env writes denied."""
    project = _project_tree(tmp_path)
    # --- 10-line quickstart (what the README shows verbatim) ---
    client = MockChioClient(policy=_allow_all_policy)
    agent = CodeAgent(chio_client=client, capability_id="cap-1", cwd=project)

    read = await agent.files.read_file("README.md")
    assert read.receipt.is_allowed and "hello" in read.result

    with pytest.raises(ChioCodeAgentDeniedError) as excinfo:
        await agent.files.write_file(".env", "BAD=value")
    assert "forbidden_path" in (excinfo.value.reason or "")
    # --- end 10-line quickstart ---

    # The sidecar was asked about the read, never the write.
    methods = [c.method for c in client.calls]
    assert methods.count("evaluate_tool_call") == 1


# ---------------------------------------------------------------------------
# FileTool surface
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_write_inside_src_is_allowed(tmp_path: Path) -> None:
    project = _project_tree(tmp_path)
    client = MockChioClient(policy=_allow_all_policy)
    agent = CodeAgent(chio_client=client, capability_id="cap-2", cwd=project)

    result = await agent.files.write_file("src/new.py", "x = 1\n")

    assert result.receipt.is_allowed
    assert (project / "src" / "new.py").read_text() == "x = 1\n"


@pytest.mark.asyncio
async def test_write_outside_writable_roots_is_denied(tmp_path: Path) -> None:
    project = _project_tree(tmp_path)
    client = MockChioClient(policy=_allow_all_policy)
    agent = CodeAgent(chio_client=client, capability_id="cap-3", cwd=project)

    with pytest.raises(ChioCodeAgentDeniedError) as excinfo:
        await agent.files.write_file("top-level.txt", "nope")

    assert excinfo.value.reason == "not_in_writable_root"


@pytest.mark.asyncio
async def test_read_outside_cwd_is_denied(tmp_path: Path) -> None:
    project = _project_tree(tmp_path)
    client = MockChioClient(policy=_allow_all_policy)
    agent = CodeAgent(chio_client=client, capability_id="cap-4", cwd=project)

    with pytest.raises(ChioCodeAgentDeniedError) as excinfo:
        await agent.files.read_file("/etc/passwd")

    # Either forbidden_path matched or the cwd check; both are acceptable.
    assert excinfo.value.reason in {"outside_cwd", "forbidden_path"}


@pytest.mark.asyncio
async def test_read_of_git_internals_denied(tmp_path: Path) -> None:
    project = _project_tree(tmp_path)
    (project / ".git").mkdir()
    (project / ".git" / "config").write_text("[core]\n", encoding="utf-8")

    client = MockChioClient(policy=_allow_all_policy)
    agent = CodeAgent(chio_client=client, capability_id="cap-5", cwd=project)

    with pytest.raises(ChioCodeAgentDeniedError) as excinfo:
        await agent.files.read_file(".git/config")

    assert excinfo.value.reason == "forbidden_path"


# ---------------------------------------------------------------------------
# ShellTool surface
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_shell_rm_rf_root_denied(tmp_path: Path) -> None:
    project = _project_tree(tmp_path)
    client = MockChioClient(policy=_allow_all_policy)
    agent = CodeAgent(chio_client=client, capability_id="cap-6", cwd=project)

    with pytest.raises(ChioCodeAgentDeniedError) as excinfo:
        await agent.shell.run_command("rm -rf /")

    assert excinfo.value.guard == "shell_command"


@pytest.mark.asyncio
async def test_shell_approval_required(tmp_path: Path) -> None:
    project = _project_tree(tmp_path)
    client = MockChioClient(policy=_allow_all_policy)
    agent = CodeAgent(chio_client=client, capability_id="cap-7", cwd=project)

    with pytest.raises(ChioCodeAgentDeniedError):
        await agent.shell.run_command("rm -rf build/")

    # Approved: the call goes through.
    result = await agent.shell.run_command(
        "rm -rf build/",
        approved=True,
        executor=lambda command: f"deleted {command}",
    )
    assert result.receipt.is_allowed
    assert result.result.approval_required is True


# ---------------------------------------------------------------------------
# GitTool surface
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_git_force_push_denied(tmp_path: Path) -> None:
    project = _project_tree(tmp_path)
    client = MockChioClient(policy=_allow_all_policy)
    agent = CodeAgent(chio_client=client, capability_id="cap-8", cwd=project)

    with pytest.raises(ChioCodeAgentDeniedError):
        await agent.git.run("git push --force origin main")


@pytest.mark.asyncio
async def test_git_status_allowed(tmp_path: Path) -> None:
    project = _project_tree(tmp_path)
    client = MockChioClient(policy=_allow_all_policy)
    agent = CodeAgent(chio_client=client, capability_id="cap-9", cwd=project)

    result = await agent.git.status(executor=lambda: "clean")

    assert result.receipt.is_allowed
    assert result.result == "clean"


# ---------------------------------------------------------------------------
# Sidecar denial still propagates
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sidecar_deny_propagates(tmp_path: Path) -> None:
    project = _project_tree(tmp_path)

    def deny_reads(
        tool: str,
        _scope: dict[str, Any],
        _ctx: dict[str, Any],
    ) -> MockVerdict:
        if tool == "read_file":
            return MockVerdict.deny_verdict("kernel says no", guard="TestGuard")
        return MockVerdict.allow_verdict()

    client = MockChioClient(policy=deny_reads)
    agent = CodeAgent(chio_client=client, capability_id="cap-10", cwd=project)

    with pytest.raises(ChioDeniedError) as excinfo:
        await agent.files.read_file("README.md")

    assert excinfo.value.guard == "TestGuard"


# ---------------------------------------------------------------------------
# Dispatch helper
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dispatch_routes_by_server_tool_string(tmp_path: Path) -> None:
    project = _project_tree(tmp_path)
    client = MockChioClient(policy=_allow_all_policy)
    agent = CodeAgent(chio_client=client, capability_id="cap-11", cwd=project)

    result = await agent.dispatch("fs/read_file", path="README.md")

    assert result.receipt.is_allowed
    assert "hello" in result.result


def test_default_policy_is_loaded() -> None:
    """Import-time invariant: the bundled policy loaded cleanly."""
    assert DEFAULT_POLICY.allowed_tools
    assert any(t.tool == "read_file" for t in DEFAULT_POLICY.allowed_tools)
