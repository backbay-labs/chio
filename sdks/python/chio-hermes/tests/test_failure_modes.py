"""Failure-mode coverage for every error envelope shape.

| Case                              | Slug                          |
|-----------------------------------|-------------------------------|
| Sidecar unreachable               | chio_sidecar_unreachable      |
| Capability expired                | chio_capability_expired       |
| Configuration missing             | chio_not_configured           |
| Generic exception                 | chio_error                    |
| Executor I/O error after allow    | chio_executor_error           |
| Sidecar deny with receipt id      | denied (carries receipt_id)   |
| Plugin reload tolerance           | register(ctx) called twice    |
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from chio_sdk.errors import ChioConnectionError
from chio_sdk.testing import MockChioClient, MockVerdict

from chio_hermes import handlers, manifest
from chio_hermes import register as plugin_register
from chio_hermes.runtime import RuntimeHandle
from tests.conftest import FakePluginContext, make_configured_runtime


def _read_file_handler(runtime: RuntimeHandle) -> Any:
    by_name = {entry.name: entry for entry in manifest.TOOL_TABLE}
    return handlers.make_handler(runtime, by_name["chio_file_read"])


def _envelope(result: str) -> dict[str, Any]:
    payload = json.loads(result)
    assert isinstance(payload, dict)
    return payload


@pytest.mark.asyncio
async def test_sidecar_unreachable_returns_runtime_unavailable_envelope(
    tmp_workspace: Path,
) -> None:
    class _Down(MockChioClient):
        async def evaluate_tool_call(self, **_: Any) -> Any:
            raise ChioConnectionError(
                "Failed to connect to Chio sidecar at http://127.0.0.1:9090"
            )

    runtime = make_configured_runtime(chio_client=_Down(), cwd=tmp_workspace)
    handler = _read_file_handler(runtime)

    result = await handler({"path": "README.md"}, task_id="task-down")
    payload = _envelope(result)
    assert payload["error"] == "chio_sidecar_unreachable"


@pytest.mark.asyncio
async def test_capability_expired_returns_denied_envelope(
    tmp_workspace: Path,
) -> None:
    def _expired_policy(_t: str, _s: dict, _c: dict) -> MockVerdict:
        return MockVerdict.deny_verdict(
            "capability cap-aaaa has expired",
            guard="ExpiredCapabilityGuard",
        )

    runtime = make_configured_runtime(
        chio_client=MockChioClient(policy=_expired_policy), cwd=tmp_workspace
    )
    handler = _read_file_handler(runtime)

    result = await handler({"path": "README.md"}, task_id="task-exp")
    payload = _envelope(result)

    assert payload["error"] == "chio_capability_expired"
    assert payload["guard"] == "ExpiredCapabilityGuard"


@pytest.mark.asyncio
async def test_configuration_missing_returns_not_configured_envelope(
    tmp_workspace: Path, unconfigured_env: None
) -> None:
    # Degraded handle (no code_agent) so is_configured() is False.
    runtime = RuntimeHandle(
        chio_client=MockChioClient(),
        capability_id=None,
        cwd=tmp_workspace,
    )
    handler = _read_file_handler(runtime)

    result = await handler({"path": "README.md"}, task_id="task-noconf")
    payload = _envelope(result)

    assert payload["error"] == "chio_not_configured"
    assert "CHIO_CAPABILITY_ID" in payload["message"]


@pytest.mark.asyncio
async def test_generic_exception_returns_chio_error_envelope(
    tmp_workspace: Path,
) -> None:
    class _Boom(MockChioClient):
        async def evaluate_tool_call(self, **_: Any) -> Any:
            raise ValueError("something went sideways")

    runtime = make_configured_runtime(chio_client=_Boom(), cwd=tmp_workspace)
    handler = _read_file_handler(runtime)

    result = await handler({"path": "README.md"}, task_id="task-boom")
    payload = _envelope(result)
    assert payload["error"] == "chio_error"


@pytest.mark.asyncio
async def test_executor_error_after_allow(
    tmp_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _ExecutorError(Exception):
        def __init__(self, msg: str, *, receipt_id: str) -> None:
            super().__init__(msg)
            self.receipt_id = receipt_id

    runtime = make_configured_runtime(cwd=tmp_workspace)

    async def _boom(**_kw: Any) -> Any:
        raise _ExecutorError("disk full", receipt_id="rcpt-after-allow")

    from chio_hermes import executors as _exec

    monkeypatch.setattr(_exec, "edit_file_executor", _boom)
    by_name = {entry.name: entry for entry in manifest.TOOL_TABLE}
    handler = handlers.make_handler(runtime, by_name["chio_file_edit"])

    result = await handler(
        {"path": "src/new.py", "patch": "--- a\n+++ b\n"},
        task_id="task-exec-err",
    )
    payload = _envelope(result)
    assert payload["error"] == "chio_executor_error"
    assert payload["receipt_id"] == "rcpt-after-allow"


@pytest.mark.asyncio
async def test_sidecar_deny_includes_receipt_id(
    tmp_workspace: Path,
) -> None:
    """A sidecar deny receipt's receipt_id propagates so the user can
    correlate the deny with the audit log."""
    from chio_sdk.errors import ChioDeniedError

    class _DenyWithReceipt(MockChioClient):
        async def evaluate_tool_call(self, **_kw: Any) -> Any:
            raise ChioDeniedError(
                "policy says no",
                guard="ForbiddenPathGuard",
                reason="forbidden",
                receipt_id="rcpt-deny-1",
            )

    runtime = make_configured_runtime(
        chio_client=_DenyWithReceipt(), cwd=tmp_workspace
    )
    handler = _read_file_handler(runtime)
    result = await handler({"path": "README.md"}, task_id="task-deny")
    payload = _envelope(result)
    assert payload["error"] == "denied"
    assert payload["receipt_id"] == "rcpt-deny-1"
    assert payload["guard"] == "ForbiddenPathGuard"


def test_register_is_idempotent_under_reload(
    tmp_workspace: Path,
    fake_plugin_context: FakePluginContext,
    configured_env: None,
) -> None:
    plugin_register(fake_plugin_context)
    first_count = len(fake_plugin_context.tools)

    second_ctx = FakePluginContext()
    plugin_register(second_ctx)
    assert len(second_ctx.tools) == first_count


def test_register_then_register_same_ctx_does_not_double_register(
    fake_plugin_context: FakePluginContext, configured_env: None
) -> None:
    """Pin the no-crash contract on second registration.

    `FakePluginContext.register_tool` overwrites by name; real Hermes
    may raise on duplicate names.
    """
    plugin_register(fake_plugin_context)
    plugin_register(fake_plugin_context)
    assert len(fake_plugin_context.tools) == 12
