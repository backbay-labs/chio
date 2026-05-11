"""`/chio` slash command coverage."""

from __future__ import annotations

from pathlib import Path

import pytest

from chio_hermes.commands import make_slash_handler
from tests.conftest import make_configured_runtime


@pytest.mark.asyncio
async def test_chio_status_includes_sidecar_url(tmp_workspace: Path) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)
    runtime.sidecar_url = "http://127.0.0.1:9999"
    handle_slash = make_slash_handler(runtime)
    out = await handle_slash("status")
    assert isinstance(out, str)
    assert "http://127.0.0.1:9999" in out


@pytest.mark.asyncio
async def test_chio_status_masks_capability_id(tmp_workspace: Path) -> None:
    runtime = make_configured_runtime(
        cwd=tmp_workspace,
        capability_id="cap-12345678901234567890",
    )
    handle_slash = make_slash_handler(runtime)
    out = await handle_slash("status")
    assert "34567890" in out
    assert "cap-12345678901234567890" not in out


@pytest.mark.asyncio
async def test_chio_status_default_when_empty_args(tmp_workspace: Path) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)
    handle_slash = make_slash_handler(runtime)
    out = await handle_slash("")
    assert out is not None
    assert "chio plugin status" in out


@pytest.mark.asyncio
async def test_chio_receipts_returns_up_to_n(tmp_workspace: Path) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)
    for i in range(10):
        runtime.receipts._buffer.append(
            {"tool_name": f"tool-{i}", "task_id": f"t-{i}"}
        )
    handle_slash = make_slash_handler(runtime)
    out = await handle_slash("receipts 3")
    assert out is not None
    record_lines = [line for line in out.splitlines() if line.startswith("  - ")]
    assert len(record_lines) == 3


@pytest.mark.asyncio
async def test_chio_receipts_caps_at_50(tmp_workspace: Path) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)
    for i in range(100):
        runtime.receipts._buffer.append(
            {"tool_name": f"tool-{i}", "task_id": f"t-{i}"}
        )
    handle_slash = make_slash_handler(runtime)
    out = await handle_slash("receipts 9999")
    assert out is not None
    record_lines = [line for line in out.splitlines() if line.startswith("  - ")]
    assert len(record_lines) <= 50


@pytest.mark.asyncio
async def test_chio_policy_lists_forbidden_patterns(tmp_workspace: Path) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)
    handle_slash = make_slash_handler(runtime)
    out = await handle_slash("policy")
    assert out is not None
    assert "forbidden_path_patterns" in out


@pytest.mark.asyncio
async def test_chio_unknown_subcommand_lists_options(tmp_workspace: Path) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)
    handle_slash = make_slash_handler(runtime)
    out = await handle_slash("nope")
    assert out is not None
    assert "status" in out
    assert "receipts" in out
    assert "policy" in out


@pytest.mark.asyncio
async def test_chio_status_reports_actual_denial_count(
    tmp_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End-to-end: post-hook envelope decode -> deny counter -> /chio status."""
    import chio_hermes.receipts as _receipts
    from chio_hermes.hooks import make_post_tool_call

    runtime = make_configured_runtime(cwd=tmp_workspace)

    log = tmp_workspace / "chio-receipts.jsonl"
    monkeypatch.setattr(_receipts, "_resolve_log_path", lambda: log)

    post = make_post_tool_call(runtime)

    post(
        tool_name="chio_file_read",
        args={"path": "README.md"},
        result='{"status":"allowed","result":"hi"}',
        task_id="t-allow-1",
        duration_ms=1,
    )
    post(
        tool_name="chio_file_read",
        args={"path": "README.md"},
        result='{"status":"allowed","result":"hi"}',
        task_id="t-allow-2",
        duration_ms=1,
    )
    post(
        tool_name="chio_file_write",
        args={"path": ".env"},
        result=(
            '{"error":"denied","guard":"ForbiddenPathGuard",'
            '"reason":".env","receipt_id":null}'
        ),
        task_id="t-deny-1",
        duration_ms=1,
    )

    handle_slash = make_slash_handler(runtime)
    out = await handle_slash("status")
    assert out is not None
    assert "recent denials: 1" in out
