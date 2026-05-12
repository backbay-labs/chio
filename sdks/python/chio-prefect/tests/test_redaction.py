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


class TestForwardingTablePassthroughHelper:
    """Direct unit coverage for ``_forwarding_table_or_passthrough``.

    Targets the C-extension fallback path and the merge-conflict edge
    case in pure-forwarding wrappers; both are awkward to express via a
    full ``@chio_task`` decorator round-trip because Prefect requires a
    pure-Python callable.
    """

    def test_c_extension_fallback_redacts_via_tool_arity_table(self) -> None:
        # ``inspect.signature(dict.update)`` raises ValueError because
        # the C-implemented method has no introspectable parameter list
        # (verified against Python 3.13). The fallback must not forward
        # positional bodies raw; it should consult the tool arity table
        # for chio-default tools.
        import inspect

        from chio_prefect.decorators import _task_parameters

        # Sanity guard: if a future Python release exposes a signature
        # for ``dict.update`` we want this test to fail loudly so we can
        # pick a different non-introspectable stand-in.
        try:
            inspect.signature(dict.update)
        except (TypeError, ValueError):
            pass
        else:  # pragma: no cover - guard against silent test rot
            raise AssertionError(
                "dict.update is no longer non-introspectable; pick a "
                "different C-extension stand-in for this test."
            )

        policy = RedactionPolicy.chio_default()
        params = _task_parameters(
            ("/tmp/x", "PROD_SECRET=abc123"),
            {},
            "chio_file_write",
            policy,
            fn=dict.update,  # builtin: inspect.signature raises
        )

        import json

        assert "PROD_SECRET" not in json.dumps(params)
        assert params["args"][0] == "/tmp/x"
        assert params["args"][1] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }
        assert params["kwargs"] == {}

    def test_c_extension_fallback_kwargs_only_for_unknown_tool(self) -> None:
        # Tools absent from the arity table fall back to kwargs-only
        # redaction; positional values pass through unredacted because
        # we have no name to bind them against. Documented limitation.
        from chio_prefect.decorators import _task_parameters

        policy = RedactionPolicy.chio_default()
        params = _task_parameters(
            ("payload",),
            {"unrelated": "value"},
            "search",  # not in the arity table
            policy,
            fn=dict.update,
        )
        assert params["args"] == ["payload"]
        assert params["kwargs"] == {"unrelated": "value"}

    def test_pure_var_positional_signature_redacts_via_tool_table(
        self,
    ) -> None:
        # ``def write(*args)`` has no fixed-named params and no
        # **kwargs; previously it routed through a path that filtered
        # VAR_POSITIONAL out of the bound dict before redaction, leaving
        # the body field unredacted. The forwarding-table helper must
        # bind positional values by name and scrub them.
        from typing import Any

        from chio_prefect.decorators import _task_parameters

        def write(*args: Any) -> str:
            return ""

        policy = RedactionPolicy.chio_default()
        params = _task_parameters(
            ("/tmp/x", "PROD_SECRET=abc123"),
            {},
            "chio_file_write",
            policy,
            fn=write,
        )

        import json

        assert "PROD_SECRET" not in json.dumps(params)
        assert params["args"][0] == "/tmp/x"
        assert params["args"][1] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }

    def test_pure_var_positional_with_extras_keeps_extras_unredacted(
        self,
    ) -> None:
        # Extras past the tool-arity table cardinality have no name to
        # bind to and stay positional / unredacted (documented
        # limitation of forwarding-table redaction).
        from typing import Any

        from chio_prefect.decorators import _task_parameters

        def write(*args: Any, **kwargs: Any) -> str:
            return ""

        policy = RedactionPolicy.chio_default()
        params = _task_parameters(
            ("/tmp/x", "PROD_SECRET=abc123", "trailing-1", "trailing-2"),
            {},
            "chio_file_write",
            policy,
            fn=write,
        )

        import json

        assert "PROD_SECRET" not in json.dumps(params)
        assert params["args"][0] == "/tmp/x"
        assert params["args"][1] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }
        assert params["args"][2] == "trailing-1"
        assert params["args"][3] == "trailing-2"
        assert params["kwargs"] == {}

    def test_forwarding_wrapper_kwarg_does_not_overwrite_positional(
        self,
    ) -> None:
        # Pathological caller passes both a positional AND a keyword
        # for the same field. Both must be redacted independently so
        # the kwarg-side payload cannot leak by overwriting the
        # positional value before the redactor sees it.
        from typing import Any

        from chio_prefect.decorators import _task_parameters

        def write(*args: Any, **kwargs: Any) -> str:
            return ""

        policy = RedactionPolicy.chio_default()
        params = _task_parameters(
            ("/tmp/x", "POSITIONAL_BODY"),
            {"path": "/etc/passwd", "content": "KW_BODY"},
            "chio_file_write",
            policy,
            fn=write,
        )

        import json

        forwarded = json.dumps(params)
        assert "POSITIONAL_BODY" not in forwarded
        assert "KW_BODY" not in forwarded
        # ``path`` is not a redacted body field; the kwarg value is preserved.
        assert params["kwargs"]["path"] == "/etc/passwd"
        assert params["kwargs"]["content"] == {
            "omitted": True,
            "byte_count": len(b"KW_BODY"),
        }
        assert params["args"][0] == "/tmp/x"
        assert params["args"][1] == {
            "omitted": True,
            "byte_count": len(b"POSITIONAL_BODY"),
        }


class TestFixedPositionalWithVarPositional:
    """Coverage for ``def fn(path, *args)`` shape (closes 3228423995)."""

    def test_var_positional_secret_is_redacted_via_tool_arity_table(
        self,
    ) -> None:
        # ``def write_file(path, *args)`` called as
        # ``write_file("/tmp/x", "PROD_SECRET")`` puts the secret in the
        # VAR_POSITIONAL bucket; the chio default tool-arity table
        # (chio_file_write -> ("path", "content")) must still bind it to
        # `content` so it gets redacted, otherwise the secret would
        # re-emit unredacted in `args`.
        from typing import Any

        from chio_prefect.decorators import _task_parameters

        def write_file(path: str, *args: Any) -> str:
            return ""

        policy = RedactionPolicy.chio_default()
        params = _task_parameters(
            ("/tmp/x", "PROD_SECRET=abc123"),
            {},
            "chio_file_write",
            policy,
            fn=write_file,
        )

        import json

        forwarded = json.dumps(params)
        assert "PROD_SECRET" not in forwarded
        assert params["args"][0] == "/tmp/x"
        assert params["args"][1] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }
        assert params["kwargs"] == {}

    def test_var_positional_extras_past_table_pass_through_unredacted(
        self,
    ) -> None:
        # ``def write_file(path, *args)`` called with two trailing extras
        # past the chio_file_write table cardinality (path, content).
        # Extras beyond index 1 have no declared name to bind to and
        # remain in args unchanged.
        from typing import Any

        from chio_prefect.decorators import _task_parameters

        def write_file(path: str, *args: Any) -> str:
            return ""

        policy = RedactionPolicy.chio_default()
        params = _task_parameters(
            ("/tmp/x", "PROD_SECRET=abc123", "trailing-1", "trailing-2"),
            {},
            "chio_file_write",
            policy,
            fn=write_file,
        )

        import json

        forwarded = json.dumps(params)
        assert "PROD_SECRET" not in forwarded
        assert params["args"][0] == "/tmp/x"
        assert params["args"][1] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }
        assert params["args"][2] == "trailing-1"
        assert params["args"][3] == "trailing-2"
        assert params["kwargs"] == {}


class TestPositionalOnlyVarKeywordSpillover:
    """Coverage for ``def fn(path, /, **kw)`` spillover (closes 3228423999)."""

    def test_positional_only_with_same_named_var_keyword_spillover(
        self,
    ) -> None:
        # Python permits a positional-only param and a same-named entry
        # inside **kwargs to coexist: ``def write(path, /, **kw)`` called
        # as ``write("/etc", path="/tmp")`` binds to
        # ``{"path": "/etc", "kw": {"path": "/tmp"}}``. Both values are
        # real and must be redacted independently rather than collapsed:
        # the positional value's redacted form must NOT be overwritten
        # by the spillover entry.
        from typing import Any

        from chio_prefect.decorators import _task_parameters

        def write(path: str, /, **kw: Any) -> str:
            return ""

        policy = RedactionPolicy.chio_default()
        params = _task_parameters(
            ("/etc/POSITIONAL",),
            {"path": "/tmp/SPILLOVER"},
            "chio_file_write",
            policy,
            fn=write,
        )

        # Both raw values must be absent from the wire payload because
        # neither is a redacted body field, but the assertion below is
        # the strong one: both values survive in different buckets so
        # neither is silently dropped.
        assert params["args"][0] == "/etc/POSITIONAL"
        # Spillover entry surfaces under the synthetic key so it cannot
        # silently collapse with the fixed name; the wrapped fn already
        # accepted the call shape, so the underlying invocation runs.
        spillover_key = "path__var_kw_spillover__"
        assert spillover_key in params["kwargs"]
        assert params["kwargs"][spillover_key] == "/tmp/SPILLOVER"

    def test_positional_only_spillover_redacted_when_name_is_body_field(
        self,
    ) -> None:
        # Same shape but the spilled-over name IS a redacted body field
        # (chio_file_write -> ("content",)). Both the positional and the
        # spillover values must be redacted independently.
        from typing import Any

        from chio_prefect.decorators import _task_parameters

        def write(content: str, /, **kw: Any) -> str:
            return ""

        policy = RedactionPolicy.chio_default()
        params = _task_parameters(
            ("POSITIONAL_BODY",),
            {"content": "SPILLOVER_BODY"},
            "chio_file_write",
            policy,
            fn=write,
        )

        import json

        forwarded = json.dumps(params)
        assert "POSITIONAL_BODY" not in forwarded
        assert "SPILLOVER_BODY" not in forwarded
        # Positional content's redacted envelope is preserved in args[0].
        assert params["args"][0] == {
            "omitted": True,
            "byte_count": len(b"POSITIONAL_BODY"),
        }
        # Spillover redacted envelope is routed to the synthetic kwargs
        # key so it does not overwrite the positional redacted value.
        spillover_key = "content__var_kw_spillover__"
        assert spillover_key in params["kwargs"]
        assert params["kwargs"][spillover_key] == {
            "omitted": True,
            "byte_count": len(b"SPILLOVER_BODY"),
        }


class TestVarPositionalNamedAfterBodyField:
    """Regression for #672 comment 3228939863.

    ``def write_file(*content, path)`` puts the positional secret in the
    VAR_POSITIONAL bucket whose declared name is ``content`` (one of the
    chio_file_write body fields). The chio default tool-arity table
    (``("path", "content")``) maps ``args[0]`` to ``path`` instead, which
    silently leaks the positional secret because ``path`` is not in the
    redaction policy. The fix prefers the variadic parameter's own name
    when it matches a redacted body field for this tool.
    """

    def test_positional_secret_redacted_when_var_positional_named_content(
        self,
    ) -> None:
        from typing import Any

        from chio_prefect.decorators import _task_parameters

        def write_file(*content: Any, path: str) -> str:
            return ""

        policy = RedactionPolicy.chio_default()
        params = _task_parameters(
            ("PROD_SECRET",),
            {"path": "/tmp/x"},
            "chio_file_write",
            policy,
            fn=write_file,
        )

        import json

        serialised = json.dumps(params)
        assert "PROD_SECRET" not in serialised
        # Positional content stub re-emits in args[0]; the kwarg path
        # stays unredacted because ``path`` is not a body field.
        assert params["args"][0] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET"),
        }
        assert params["kwargs"]["path"] == "/tmp/x"

    def test_multiple_var_positional_secrets_all_redacted(self) -> None:
        from typing import Any

        from chio_prefect.decorators import _task_parameters

        def write_file(*content: Any, path: str) -> str:
            return ""

        policy = RedactionPolicy.chio_default()
        params = _task_parameters(
            ("SECRET_1", "SECRET_2"),
            {"path": "/tmp/x"},
            "chio_file_write",
            policy,
            fn=write_file,
        )

        import json

        serialised = json.dumps(params)
        assert "SECRET_1" not in serialised
        assert "SECRET_2" not in serialised
        assert params["args"][0] == {
            "omitted": True,
            "byte_count": len(b"SECRET_1"),
        }
        assert params["args"][1] == {
            "omitted": True,
            "byte_count": len(b"SECRET_2"),
        }
