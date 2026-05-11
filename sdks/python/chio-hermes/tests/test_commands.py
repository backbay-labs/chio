"""`/chio` slash command coverage.

The slash command handler returned by `make_slash_handler(handle)`
exposes three subcommands:

* `status`   -- summarises sidecar URL, masked capability id, fail-open,
                configured-yes/no, and recent denial / pending counts.
* `receipts` -- last N receipts (default 5, capped at 50).
* `policy`   -- pretty-prints the active CodeAgentPolicy summary.

An unknown subcommand falls back to a usage hint that lists the three
options.
"""

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
    # 3 records means 3 lines starting with "  - tool=", plus the header.
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
