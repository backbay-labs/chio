"""Tests for chio-prefect argument redaction (chio-adapter-base wiring).

These tests assert that ``@chio_task`` redacts secret-bearing fields
from its tool kwargs BEFORE forwarding them to the sidecar's
``evaluate_tool_call`` endpoint, so the receipt log never carries the
raw secret bytes. The wrapped function body still receives the
original, unredacted arguments.

Source of truth: ``chio_adapter_base.redact.redact_args``.
"""

from __future__ import annotations

from chio_adapter_base.redact import RedactionPolicy
from chio_sdk.models import ChioScope, Operation, ToolGrant
from chio_sdk.testing import allow_all

from chio_prefect import chio_flow, chio_task


def _scope_for_tools(*tool_names: str, server_id: str = "srv") -> ChioScope:
    grants = [
        ToolGrant(
            server_id=server_id,
            tool_name=name,
            operations=[Operation.INVOKE],
        )
        for name in tool_names
    ]
    return ChioScope(grants=grants)


# ---------------------------------------------------------------------------
# Default policy: chio_file_write.content / chio_file_edit.patch
# ---------------------------------------------------------------------------


class TestDefaultPolicyRedacts:
    def test_chio_file_write_content_is_redacted_in_sidecar_payload(self) -> None:
        chio = allow_all()
        body_seen: dict[str, object] = {}

        @chio_task(
            scope=_scope_for_tools("chio_file_write"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
            tool_name="chio_file_write",
        )
        def write_file(*, path: str, content: str) -> str:
            # Function body must still see the *original* unredacted args.
            body_seen["path"] = path
            body_seen["content"] = content
            return "ok"

        @chio_flow(
            scope=_scope_for_tools("chio_file_write"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        def myflow() -> str:
            return write_file(path="/tmp/x", content="PROD_SECRET=abc123")

        result = myflow()
        assert result == "ok"

        # Sidecar must have received the REDACTED kwargs.
        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(evaluate_calls) == 1
        forwarded = evaluate_calls[0].parameters
        assert forwarded["args"] == []
        assert forwarded["kwargs"]["path"] == "/tmp/x"
        assert forwarded["kwargs"]["content"] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }

        # And the function body must have seen the raw bytes.
        assert body_seen["content"] == "PROD_SECRET=abc123"
        assert body_seen["path"] == "/tmp/x"

    def test_chio_file_edit_patch_is_redacted(self) -> None:
        chio = allow_all()

        @chio_task(
            scope=_scope_for_tools("chio_file_edit"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
            tool_name="chio_file_edit",
        )
        def edit_file(*, path: str, patch: str) -> str:
            return "ok"

        @chio_flow(
            scope=_scope_for_tools("chio_file_edit"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        def myflow() -> str:
            return edit_file(path="/tmp/x", patch="--- a\n+++ b\n@@ secret @@")

        myflow()

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        forwarded = evaluate_calls[0].parameters
        assert forwarded["kwargs"]["path"] == "/tmp/x"
        assert forwarded["kwargs"]["patch"] == {
            "omitted": True,
            "byte_count": len(b"--- a\n+++ b\n@@ secret @@"),
        }

    def test_unrelated_tool_passes_kwargs_through(self) -> None:
        chio = allow_all()

        @chio_task(
            scope=_scope_for_tools("search"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
            tool_name="search",
        )
        def search(*, query: str, content: str) -> str:
            return "ok"

        @chio_flow(
            scope=_scope_for_tools("search"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        def myflow() -> str:
            return search(query="quantum", content="not redacted here")

        myflow()

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        forwarded = evaluate_calls[0].parameters
        # The default policy only matches chio_file_write / chio_file_edit;
        # unrelated tools see their kwargs unmodified.
        assert forwarded["kwargs"] == {
            "query": "quantum",
            "content": "not redacted here",
        }

    def test_positional_args_are_not_touched(self) -> None:
        """Positional args are forwarded verbatim because the wrapper does
        not know the callable's parameter names. Tools with secret bodies
        should accept them as keyword-only arguments to opt in to
        redaction (this is documented in :func:`_task_parameters`).
        """
        chio = allow_all()

        @chio_task(
            scope=_scope_for_tools("chio_file_write"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
            tool_name="chio_file_write",
        )
        def write_file(path: str, content: str) -> str:
            return "ok"

        @chio_flow(
            scope=_scope_for_tools("chio_file_write"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        def myflow() -> str:
            # Note: positional, not kwarg.
            return write_file("/tmp/x", "RAW_SECRET=xyz")

        myflow()

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        forwarded = evaluate_calls[0].parameters
        # Args land in the args list verbatim; kwargs is empty so there is
        # nothing for redact_args to touch. This is documented behaviour.
        assert forwarded["args"] == ["/tmp/x", "RAW_SECRET=xyz"]
        assert forwarded["kwargs"] == {}


# ---------------------------------------------------------------------------
# Custom policy: only my_tool.body is redacted
# ---------------------------------------------------------------------------


class TestCustomPolicy:
    def test_custom_policy_on_task_redacts_only_named_fields(self) -> None:
        chio = allow_all()
        custom = RedactionPolicy(body_fields={"my_tool": ("body",)})

        @chio_task(
            scope=_scope_for_tools("my_tool"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
            tool_name="my_tool",
            redaction_policy=custom,
        )
        def my_tool(*, label: str, body: str) -> str:
            return "ok"

        @chio_flow(
            scope=_scope_for_tools("my_tool"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        def myflow() -> str:
            return my_tool(label="hello", body="SECRET_TOKEN=xyz")

        myflow()

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        forwarded = evaluate_calls[0].parameters
        assert forwarded["kwargs"]["label"] == "hello"
        assert forwarded["kwargs"]["body"] == {
            "omitted": True,
            "byte_count": len(b"SECRET_TOKEN=xyz"),
        }

    def test_custom_task_policy_does_not_redact_default_fields(self) -> None:
        """A custom policy fully replaces the default; chio_file_write is
        no longer redacted under it.
        """
        chio = allow_all()
        custom = RedactionPolicy(body_fields={"my_tool": ("body",)})

        @chio_task(
            scope=_scope_for_tools("chio_file_write"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
            tool_name="chio_file_write",
            redaction_policy=custom,
        )
        def write(*, path: str, content: str) -> str:
            return "ok"

        @chio_flow(
            scope=_scope_for_tools("chio_file_write"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        def myflow() -> str:
            return write(path="/tmp/x", content="not-redacted-now")

        myflow()

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        forwarded = evaluate_calls[0].parameters
        assert forwarded["kwargs"]["content"] == "not-redacted-now"


# ---------------------------------------------------------------------------
# Flow-level policy is inherited by enclosed tasks
# ---------------------------------------------------------------------------


class TestFlowPolicyInheritance:
    def test_flow_redaction_policy_propagates_to_enclosed_tasks(self) -> None:
        chio = allow_all()
        custom = RedactionPolicy(body_fields={"my_tool": ("body",)})

        @chio_task(
            scope=_scope_for_tools("my_tool"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
            tool_name="my_tool",
        )
        def my_tool(*, body: str) -> str:
            return "ok"

        @chio_flow(
            scope=_scope_for_tools("my_tool"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
            redaction_policy=custom,
        )
        def myflow() -> str:
            return my_tool(body="SECRET=abc")

        myflow()

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        forwarded = evaluate_calls[0].parameters
        assert forwarded["kwargs"]["body"] == {
            "omitted": True,
            "byte_count": len(b"SECRET=abc"),
        }

    def test_task_policy_overrides_flow_policy(self) -> None:
        chio = allow_all()
        flow_policy = RedactionPolicy(body_fields={"flow_tool": ("flowbody",)})
        task_policy = RedactionPolicy(body_fields={"task_tool": ("taskbody",)})

        @chio_task(
            scope=_scope_for_tools("task_tool"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
            tool_name="task_tool",
            redaction_policy=task_policy,
        )
        def task_tool(*, taskbody: str, flowbody: str) -> str:
            return "ok"

        @chio_flow(
            scope=_scope_for_tools("task_tool"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
            redaction_policy=flow_policy,
        )
        def myflow() -> str:
            return task_tool(taskbody="SECRET", flowbody="NOT-A-SECRET-HERE")

        myflow()

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        forwarded = evaluate_calls[0].parameters
        # Task policy wins: ``taskbody`` is stubbed, ``flowbody`` is not.
        assert forwarded["kwargs"]["taskbody"] == {
            "omitted": True,
            "byte_count": len(b"SECRET"),
        }
        assert forwarded["kwargs"]["flowbody"] == "NOT-A-SECRET-HERE"
