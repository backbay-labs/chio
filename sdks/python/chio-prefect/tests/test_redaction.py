"""Argument-redaction tests for chio-prefect."""

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
            # Body must see the original unredacted args.
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

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(evaluate_calls) == 1
        forwarded = evaluate_calls[0].parameters
        assert forwarded["args"] == []
        assert forwarded["kwargs"]["path"] == "/tmp/x"
        assert forwarded["kwargs"]["content"] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }
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
        assert forwarded["kwargs"] == {
            "query": "quantum",
            "content": "not redacted here",
        }

    def test_positional_args_are_bound_and_redacted(self) -> None:
        """Positional invocations must NOT bypass the redactor.

        Regression for the previous "positional args bypass redaction"
        leak. Positional args are bound to declared parameter names via
        ``inspect.signature.bind_partial`` so the same body fields are
        scrubbed regardless of how the caller passes them. The wire
        shape is preserved: positional values stay in
        ``parameters["args"]`` after redaction.
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
            return write_file("/tmp/x", "RAW_SECRET=xyz")

        myflow()

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        forwarded = evaluate_calls[0].parameters
        import json

        assert "RAW_SECRET" not in json.dumps(forwarded)
        # Wire shape preserved: positional values stay positional after
        # redaction.
        assert forwarded["args"][0] == "/tmp/x"
        assert forwarded["args"][1] == {
            "omitted": True,
            "byte_count": len(b"RAW_SECRET=xyz"),
        }
        assert forwarded["kwargs"] == {}


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
        """Custom policy fully replaces the default."""
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
        # Task policy wins.
        assert forwarded["kwargs"]["taskbody"] == {
            "omitted": True,
            "byte_count": len(b"SECRET"),
        }
        assert forwarded["kwargs"]["flowbody"] == "NOT-A-SECRET-HERE"


class TestVarKeywordSignatureRedacts:
    """Regression: bind_partial does NOT raise for `**kwargs` callables.

    A pure-``**kwargs`` task bound with ``bind_partial(content="SECRET")``
    returns ``{"kw": {"content": "SECRET"}}``. ``redact_args`` keys on
    ``content`` and would miss the nested value. Detect VAR_KEYWORD
    first and redact directly on the kwargs dict.
    """

    def test_var_keyword_only_task_redacts_content(self) -> None:
        from typing import Any

        chio = allow_all()

        @chio_task(
            scope=_scope_for_tools("chio_file_write"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
            tool_name="chio_file_write",
        )
        def write_file(**kwargs: Any) -> str:
            return "ok"

        @chio_flow(
            scope=_scope_for_tools("chio_file_write"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        def myflow() -> str:
            return write_file(path="/tmp/x", content="PROD_SECRET=abc123")

        assert myflow() == "ok"

        import json

        forwarded = [c for c in chio.calls if c.method == "evaluate_tool_call"][
            0
        ].parameters
        assert "PROD_SECRET" not in json.dumps(forwarded)
        assert forwarded["kwargs"]["content"] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }

    def test_named_plus_var_keyword_task_redacts_spillover(self) -> None:
        from typing import Any

        chio = allow_all()

        @chio_task(
            scope=_scope_for_tools("chio_file_write"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
            tool_name="chio_file_write",
        )
        def write_file(path: str, **extras: Any) -> str:
            return "ok"

        @chio_flow(
            scope=_scope_for_tools("chio_file_write"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        def myflow() -> str:
            return write_file(path="/tmp/x", content="PROD_SECRET=abc123")

        assert myflow() == "ok"

        import json

        forwarded = [c for c in chio.calls if c.method == "evaluate_tool_call"][
            0
        ].parameters
        assert "PROD_SECRET" not in json.dumps(forwarded)
        # Wire shape preserved: prefect normalises ``path=`` into the
        # positional bucket because it matches a declared positional
        # parameter; the VAR_KEYWORD spillover (``content``) stays in
        # kwargs and gets scrubbed by the redactor.
        path_in_args = (
            forwarded["args"] and forwarded["args"][0] == "/tmp/x"
        )
        path_in_kwargs = forwarded.get("kwargs", {}).get("path") == "/tmp/x"
        assert path_in_args or path_in_kwargs
        assert forwarded["kwargs"]["content"] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }

    def test_existing_positional_path_still_redacts(self) -> None:
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
            return write_file("/tmp/x", "PROD_SECRET=abc123")

        assert myflow() == "ok"

        import json

        forwarded = [c for c in chio.calls if c.method == "evaluate_tool_call"][
            0
        ].parameters
        assert "PROD_SECRET" not in json.dumps(forwarded)

    def test_pure_forwarding_wrapper_redacts_positional_via_tool_table(
        self,
    ) -> None:
        # Forwarding wrappers ``def fn(*args, **kwargs)`` have no fixed
        # parameter names to bind positional values against. The
        # tool-arity table covers chio-default tools so their bodies
        # still get scrubbed when supplied positionally, while the wire
        # shape (positional values in args) is preserved.
        from typing import Any

        chio = allow_all()

        @chio_task(
            scope=_scope_for_tools("chio_file_write"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
            tool_name="chio_file_write",
        )
        def write_file(*args: Any, **kwargs: Any) -> str:
            return "ok"

        @chio_flow(
            scope=_scope_for_tools("chio_file_write"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        def myflow() -> str:
            return write_file("/tmp/x", "PROD_SECRET=abc123")

        assert myflow() == "ok"

        import json

        forwarded = [
            c for c in chio.calls if c.method == "evaluate_tool_call"
        ][0].parameters
        assert "PROD_SECRET" not in json.dumps(forwarded)
        assert forwarded["args"][0] == "/tmp/x"
        assert forwarded["args"][1] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }
        assert forwarded["kwargs"] == {}

    def test_var_positional_extras_remain_in_args(self) -> None:
        # ``*extras`` past the fixed positional slots have no parameter
        # name to bind to, so they remain in args (not migrated to
        # kwargs and not dropped).
        from typing import Any

        chio = allow_all()

        @chio_task(
            scope=_scope_for_tools("chio_file_write"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
            tool_name="chio_file_write",
        )
        def write_file(path: str, content: str, *extras: Any) -> str:
            return "ok"

        @chio_flow(
            scope=_scope_for_tools("chio_file_write"),
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
        )
        def myflow() -> str:
            return write_file(
                "/tmp/x",
                "PROD_SECRET=abc123",
                "trailing-1",
                "trailing-2",
            )

        assert myflow() == "ok"

        import json

        forwarded = [
            c for c in chio.calls if c.method == "evaluate_tool_call"
        ][0].parameters
        assert "PROD_SECRET" not in json.dumps(forwarded)
        assert forwarded["args"][0] == "/tmp/x"
        assert forwarded["args"][1] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }
        assert forwarded["args"][2] == "trailing-1"
        assert forwarded["args"][3] == "trailing-2"
        assert forwarded["kwargs"] == {}

    def test_bind_partial_failure_does_not_leak_positional_args(self) -> None:
        # Duplicate keyword: bind_partial raises TypeError before fn() is
        # called. The redactor must not forward the raw positional value
        # into the receipt.
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
        def myflow() -> object:
            try:
                return write_file(
                    "/tmp/x", "PROD_SECRET=abc123", path="/tmp/dup"
                )
            except TypeError as exc:
                return exc

        myflow()

        import json

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        if evaluate_calls:
            assert "PROD_SECRET" not in json.dumps(evaluate_calls[0].parameters)
