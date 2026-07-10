"""Tests for ChioActivityInterceptor argument redaction."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

from chio_adapter_base.redact import RedactionPolicy
from chio_sdk.models import (
    CapabilityToken,
    ChioScope,
    Operation,
    ToolGrant,
)
from chio_sdk.testing import MockChioClient, allow_all
from temporalio import activity

from chio_temporal import ChioActivityInterceptor, WorkflowGrant
from chio_temporal.interceptor import _ChioInboundInterceptor

INVOKE_OPERATION = getattr(Operation, "INVOKE", Operation.invoke)


def _scope_for_tools(*tool_names: str, server_id: str = "srv") -> ChioScope:
    grants = [
        ToolGrant(
            server_id=server_id,
            tool_name=name,
            operations=[INVOKE_OPERATION],
        )
        for name in tool_names
    ]
    return ChioScope(grants=grants)


def _default_info(
    *,
    activity_type: str,
    activity_id: str = "act-1",
    workflow_id: str = "wf-1",
    workflow_run_id: str = "run-1",
    attempt: int = 1,
) -> activity.Info:
    utc_zero = datetime.fromtimestamp(0, tz=UTC)
    import temporalio.common as temporal_common

    return activity.Info(
        activity_id=activity_id,
        activity_type=activity_type,
        attempt=attempt,
        current_attempt_scheduled_time=utc_zero,
        heartbeat_details=[],
        heartbeat_timeout=None,
        is_local=False,
        namespace="default",
        schedule_to_close_timeout=timedelta(seconds=10),
        scheduled_time=utc_zero,
        start_to_close_timeout=timedelta(seconds=10),
        started_time=utc_zero,
        task_queue="tq",
        task_token=b"tt",
        workflow_id=workflow_id,
        workflow_namespace="default",
        workflow_run_id=workflow_run_id,
        workflow_type="TestWorkflow",
        priority=temporal_common.Priority.default,
        retry_policy=None,
        activity_run_id=None,
    )


class _NextInterceptor:
    """Stand-in for the downstream :class:`ActivityInboundInterceptor`."""

    def __init__(self, result: Any = "ok") -> None:
        self.result = result
        self.called = False
        self.received_args: list[Any] | None = None

    def init(self, outbound: Any) -> None:  # pragma: no cover -- unused
        pass

    async def execute_activity(self, input: Any) -> Any:
        self.called = True
        self.received_args = list(input.args)
        return self.result


@contextmanager
def _patched_activity_info(info: activity.Info):
    original = activity.info
    activity.info = lambda: info  # type: ignore[assignment]
    try:
        yield
    finally:
        activity.info = original  # type: ignore[assignment]


def _make_input(*args: Any, fn: Callable[..., Any] | None = None) -> Any:
    from temporalio.worker import ExecuteActivityInput

    if fn is None:
        async def _fn() -> None:  # pragma: no cover -- not invoked
            pass

        fn = _fn

    return ExecuteActivityInput(
        fn=fn,
        args=list(args),
        executor=None,
        headers={},
    )


async def _mint_token(
    chio: MockChioClient,
    *,
    subject: str,
    scope: ChioScope,
) -> CapabilityToken:
    token = await chio.create_capability(subject=subject, scope=scope)
    store: dict[str, Any] = getattr(chio, "_tokens", {})
    store[token.id] = token
    chio._tokens = store  # type: ignore[attr-defined]
    return token


# ---------------------------------------------------------------------------
# Default policy: chio_file_write.content / chio_file_edit.patch
# ---------------------------------------------------------------------------


class TestDefaultPolicyRedacts:
    async def test_chio_file_write_content_is_redacted(self) -> None:
        async with allow_all() as chio:
            token = await _mint_token(
                chio,
                subject="agent:alice",
                scope=_scope_for_tools("chio_file_write"),
            )
            grant = WorkflowGrant(
                workflow_id="wf-1",
                token=token,
                tool_server="srv",
            )
            interceptor = ChioActivityInterceptor(chio_client=chio)
            interceptor.register_workflow_grant(grant)

            next_i = _NextInterceptor()
            inbound = _ChioInboundInterceptor(next_i, interceptor)

            payload = {"path": "/tmp/x", "content": "PROD_SECRET=abc123"}
            info = _default_info(activity_type="chio_file_write")
            with _patched_activity_info(info):
                await inbound.execute_activity(_make_input(payload))

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(evaluate_calls) == 1
        forwarded_args = evaluate_calls[0].parameters["args"]
        assert len(forwarded_args) == 1
        forwarded = forwarded_args[0]
        assert forwarded["path"] == "/tmp/x"
        assert forwarded["content"] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }

        assert next_i.received_args == [payload]
        assert payload["content"] == "PROD_SECRET=abc123"

        receipt = interceptor.workflow_receipt("wf-1", "run-1")
        assert receipt is not None
        step = receipt.steps[0]
        recorded = step.receipt.action.parameters["args"][0]
        assert recorded["path"] == "/tmp/x"
        assert recorded["content"] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }

    async def test_chio_file_edit_patch_is_redacted(self) -> None:
        async with allow_all() as chio:
            token = await _mint_token(
                chio,
                subject="agent:alice",
                scope=_scope_for_tools("chio_file_edit"),
            )
            grant = WorkflowGrant(
                workflow_id="wf-1",
                token=token,
                tool_server="srv",
            )
            interceptor = ChioActivityInterceptor(chio_client=chio)
            interceptor.register_workflow_grant(grant)

            next_i = _NextInterceptor()
            inbound = _ChioInboundInterceptor(next_i, interceptor)

            payload = {"path": "/tmp/x", "patch": "--- a\n+++ b\n@@ secret @@"}
            info = _default_info(activity_type="chio_file_edit")
            with _patched_activity_info(info):
                await inbound.execute_activity(_make_input(payload))

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        forwarded = evaluate_calls[0].parameters["args"][0]
        assert forwarded["path"] == "/tmp/x"
        assert forwarded["patch"] == {
            "omitted": True,
            "byte_count": len(b"--- a\n+++ b\n@@ secret @@"),
        }
        assert "content" not in forwarded

    async def test_chio_file_write_dict_body_alias_is_redacted(self) -> None:
        def write_file(path: str, body: str) -> None:
            del path, body

        async with allow_all() as chio:
            token = await _mint_token(
                chio,
                subject="agent:alice",
                scope=_scope_for_tools("chio_file_write"),
            )
            grant = WorkflowGrant(
                workflow_id="wf-1",
                token=token,
                tool_server="srv",
            )
            interceptor = ChioActivityInterceptor(chio_client=chio)
            interceptor.register_workflow_grant(grant)

            next_i = _NextInterceptor()
            inbound = _ChioInboundInterceptor(next_i, interceptor)

            payload = {"path": "/tmp/x", "body": "PROD_SECRET=abc123"}
            info = _default_info(activity_type="chio_file_write")
            with _patched_activity_info(info):
                await inbound.execute_activity(_make_input(payload, fn=write_file))

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        forwarded = evaluate_calls[0].parameters["args"][0]
        assert forwarded["path"] == "/tmp/x"
        assert forwarded["body"] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }
        assert next_i.received_args == [payload]

    async def test_unrelated_activity_passes_args_through(self) -> None:
        async with allow_all() as chio:
            token = await _mint_token(
                chio,
                subject="agent:alice",
                scope=_scope_for_tools("send_email"),
            )
            grant = WorkflowGrant(
                workflow_id="wf-1",
                token=token,
                tool_server="srv",
            )
            interceptor = ChioActivityInterceptor(chio_client=chio)
            interceptor.register_workflow_grant(grant)

            inbound = _ChioInboundInterceptor(_NextInterceptor(), interceptor)
            payload = {"to": "alice@example.com", "content": "not redacted"}
            info = _default_info(activity_type="send_email")
            with _patched_activity_info(info):
                await inbound.execute_activity(_make_input(payload))

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        forwarded = evaluate_calls[0].parameters["args"][0]
        assert forwarded == {
            "to": "alice@example.com",
            "content": "not redacted",
        }

    async def test_chio_file_write_positional_args_are_redacted(self) -> None:
        """Regression: positional ``chio_file_write(path, content)`` must not
        leak the body field into the receipt."""
        async with allow_all() as chio:
            token = await _mint_token(
                chio,
                subject="agent:alice",
                scope=_scope_for_tools("chio_file_write"),
            )
            grant = WorkflowGrant(
                workflow_id="wf-1",
                token=token,
                tool_server="srv",
            )
            interceptor = ChioActivityInterceptor(chio_client=chio)
            interceptor.register_workflow_grant(grant)

            inbound = _ChioInboundInterceptor(_NextInterceptor(), interceptor)
            info = _default_info(activity_type="chio_file_write")
            with _patched_activity_info(info):
                await inbound.execute_activity(
                    _make_input("/tmp/x", "PROD_SECRET=abc123")
                )

        import json

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        forwarded = evaluate_calls[0].parameters
        assert "PROD_SECRET" not in json.dumps(forwarded)
        # Bound shape: positional args lifted into a single dict under
        # the declared parameter names.
        assert forwarded["args"] == [
            {
                "path": "/tmp/x",
                "content": {
                    "omitted": True,
                    "byte_count": len(b"PROD_SECRET=abc123"),
                },
            }
        ]

    async def test_chio_file_write_positional_args_with_extras_redact_known_prefix(
        self,
    ) -> None:
        """``chio_file_write(path, content, overwrite)``: redact the known prefix.

        The exact-length check must not fall through to raw pass-through
        when extras are appended after the documented (path, content)
        shape. The table-named prefix is bound + redacted and any
        trailing positional extras are preserved alongside.
        """
        async with allow_all() as chio:
            token = await _mint_token(
                chio,
                subject="agent:alice",
                scope=_scope_for_tools("chio_file_write"),
            )
            grant = WorkflowGrant(
                workflow_id="wf-1",
                token=token,
                tool_server="srv",
            )
            interceptor = ChioActivityInterceptor(chio_client=chio)
            interceptor.register_workflow_grant(grant)

            inbound = _ChioInboundInterceptor(_NextInterceptor(), interceptor)
            info = _default_info(activity_type="chio_file_write")
            with _patched_activity_info(info):
                await inbound.execute_activity(
                    _make_input("/tmp/x", "PROD_SECRET=abc123", True)
                )

        import json

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        forwarded = evaluate_calls[0].parameters
        assert "PROD_SECRET" not in json.dumps(forwarded)
        assert forwarded["args"] == [
            {
                "path": "/tmp/x",
                "content": {
                    "omitted": True,
                    "byte_count": len(b"PROD_SECRET=abc123"),
                },
            },
            True,
        ]

    async def test_chio_file_write_swapped_positional_args_are_redacted(self) -> None:
        def chio_file_write(content: str, path: str) -> None:
            del content, path

        async with allow_all() as chio:
            token = await _mint_token(
                chio,
                subject="agent:alice",
                scope=_scope_for_tools("chio_file_write"),
            )
            grant = WorkflowGrant(
                workflow_id="wf-1",
                token=token,
                tool_server="srv",
            )
            interceptor = ChioActivityInterceptor(chio_client=chio)
            interceptor.register_workflow_grant(grant)

            inbound = _ChioInboundInterceptor(_NextInterceptor(), interceptor)
            info = _default_info(activity_type="chio_file_write")
            with _patched_activity_info(info):
                await inbound.execute_activity(
                    _make_input(
                        "PROD_SECRET=abc123",
                        "/tmp/x",
                        fn=chio_file_write,
                    )
                )

        import json

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        forwarded = evaluate_calls[0].parameters
        assert "PROD_SECRET" not in json.dumps(forwarded)
        assert forwarded["args"] == [
            {
                "path": "/tmp/x",
                "content": {
                    "omitted": True,
                    "byte_count": len(b"PROD_SECRET=abc123"),
                },
            }
        ]

    async def test_chio_file_edit_positional_args_are_redacted(self) -> None:
        async with allow_all() as chio:
            token = await _mint_token(
                chio,
                subject="agent:alice",
                scope=_scope_for_tools("chio_file_edit"),
            )
            grant = WorkflowGrant(
                workflow_id="wf-1",
                token=token,
                tool_server="srv",
            )
            interceptor = ChioActivityInterceptor(chio_client=chio)
            interceptor.register_workflow_grant(grant)

            inbound = _ChioInboundInterceptor(_NextInterceptor(), interceptor)
            info = _default_info(activity_type="chio_file_edit")
            diff = "@@ -1,1 +1,1 @@\n-old\n+API_TOKEN=ghp_abc\n"
            with _patched_activity_info(info):
                await inbound.execute_activity(_make_input("/etc/cfg", diff))

        import json

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        forwarded = evaluate_calls[0].parameters
        assert "API_TOKEN" not in json.dumps(forwarded)
        assert forwarded["args"] == [
            {
                "path": "/etc/cfg",
                "patch": {
                    "omitted": True,
                    "byte_count": len(diff.encode("utf-8")),
                },
            }
        ]

    async def test_unknown_tool_positional_args_pass_through(self) -> None:
        """Non-chio-default tools' positional args forward verbatim."""
        async with allow_all() as chio:
            token = await _mint_token(
                chio,
                subject="agent:alice",
                scope=_scope_for_tools("custom_tool"),
            )
            grant = WorkflowGrant(
                workflow_id="wf-1",
                token=token,
                tool_server="srv",
            )
            interceptor = ChioActivityInterceptor(chio_client=chio)
            interceptor.register_workflow_grant(grant)

            inbound = _ChioInboundInterceptor(_NextInterceptor(), interceptor)
            info = _default_info(activity_type="custom_tool")
            with _patched_activity_info(info):
                await inbound.execute_activity(_make_input("a", "b"))

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        forwarded = evaluate_calls[0].parameters["args"]
        assert forwarded == ["a", "b"]


class TestCustomPolicy:
    async def test_custom_policy_redacts_only_named_fields(self) -> None:
        async with allow_all() as chio:
            token = await _mint_token(
                chio,
                subject="agent:alice",
                scope=_scope_for_tools("my_activity"),
            )
            grant = WorkflowGrant(
                workflow_id="wf-1",
                token=token,
                tool_server="srv",
            )
            custom = RedactionPolicy(body_fields={"my_activity": ("body",)})
            interceptor = ChioActivityInterceptor(
                chio_client=chio,
                redaction_policy=custom,
            )
            interceptor.register_workflow_grant(grant)

            inbound = _ChioInboundInterceptor(_NextInterceptor(), interceptor)
            payload = {"label": "hello", "body": "SECRET_TOKEN=xyz"}
            info = _default_info(activity_type="my_activity")
            with _patched_activity_info(info):
                await inbound.execute_activity(_make_input(payload))

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        forwarded = evaluate_calls[0].parameters["args"][0]
        assert forwarded["label"] == "hello"
        assert forwarded["body"] == {
            "omitted": True,
            "byte_count": len(b"SECRET_TOKEN=xyz"),
        }

    async def test_custom_policy_does_not_redact_default_fields(self) -> None:
        async with allow_all() as chio:
            token = await _mint_token(
                chio,
                subject="agent:alice",
                scope=_scope_for_tools("chio_file_write"),
            )
            grant = WorkflowGrant(
                workflow_id="wf-1",
                token=token,
                tool_server="srv",
            )
            custom = RedactionPolicy(body_fields={"my_activity": ("body",)})
            interceptor = ChioActivityInterceptor(
                chio_client=chio,
                redaction_policy=custom,
            )
            interceptor.register_workflow_grant(grant)

            inbound = _ChioInboundInterceptor(_NextInterceptor(), interceptor)
            payload = {"path": "/tmp/x", "content": "not-redacted-now"}
            info = _default_info(activity_type="chio_file_write")
            with _patched_activity_info(info):
                await inbound.execute_activity(_make_input(payload))

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        forwarded = evaluate_calls[0].parameters["args"][0]
        assert forwarded["content"] == "not-redacted-now"


class TestInterceptorDefaultPolicy:
    def test_default_policy_is_chio_default(self) -> None:
        interceptor = ChioActivityInterceptor()
        assert "chio_file_write" in interceptor._redaction_policy.body_fields
        assert "chio_file_edit" in interceptor._redaction_policy.body_fields
