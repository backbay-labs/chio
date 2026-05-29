"""Tests for chio-ray argument redaction."""

from __future__ import annotations

import time
from typing import Any

import ray
from chio_adapter_base.redact import RedactionPolicy
from chio_sdk.models import CapabilityToken, ChioScope, Operation, ToolGrant
from chio_sdk.testing import allow_all

from chio_ray import ChioActor, StandingGrant, chio_remote


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


def _local_token(scope: ChioScope, *, token_id: str = "tok-1") -> CapabilityToken:
    now = int(time.time())
    return CapabilityToken(
        id=token_id,
        issuer="test-issuer",
        subject="agent:tester",
        scope=scope,
        issued_at=now,
        expires_at=now + 3600,
        signature="test-signature",
    )


def _eval_calls(chio: Any) -> list[Any]:
    return [c for c in chio.calls if c.method == "evaluate_tool_call"]


class TestChioRemoteRedaction:
    def test_default_policy_redacts_chio_file_write_content(self) -> None:
        chio = allow_all()

        @chio_remote(
            scope="tools:chio_file_write",
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
            tool_name="chio_file_write",
        )
        def write(*, path: str, content: str) -> str:
            return path

        ref = write.remote(path="/tmp/x", content="PROD_SECRET=abc123")
        assert ray.get(ref) == "/tmp/x"

        calls = _eval_calls(chio)
        assert len(calls) == 1
        forwarded = calls[0].parameters["kwargs"]
        assert forwarded["path"] == "/tmp/x"
        assert forwarded["content"] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }

    def test_default_policy_redacts_chio_file_edit_patch(self) -> None:
        chio = allow_all()

        @chio_remote(
            scope="tools:chio_file_edit",
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
            tool_name="chio_file_edit",
        )
        def edit(*, path: str, patch: str) -> str:
            return path

        ref = edit.remote(path="/tmp/x", patch="--- a\n+++ b\n@@ secret @@")
        assert ray.get(ref) == "/tmp/x"

        forwarded = _eval_calls(chio)[0].parameters["kwargs"]
        assert forwarded["path"] == "/tmp/x"
        assert forwarded["patch"] == {
            "omitted": True,
            "byte_count": len(b"--- a\n+++ b\n@@ secret @@"),
        }

    def test_unrelated_tool_passes_kwargs_through(self) -> None:
        chio = allow_all()

        @chio_remote(
            scope="tools:search",
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
            tool_name="search",
        )
        def search(*, query: str, content: str) -> str:
            return query

        ref = search.remote(query="quantum", content="not redacted here")
        assert ray.get(ref) == "quantum"

        forwarded = _eval_calls(chio)[0].parameters["kwargs"]
        assert forwarded == {"query": "quantum", "content": "not redacted here"}

    def test_custom_policy_redacts_only_named_fields(self) -> None:
        chio = allow_all()
        custom = RedactionPolicy(body_fields={"my_tool": ("body",)})

        @chio_remote(
            scope="tools:my_tool",
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
            tool_name="my_tool",
            redaction_policy=custom,
        )
        def run(*, label: str, body: str) -> str:
            return label

        ref = run.remote(label="hello", body="SECRET_TOKEN=xyz")
        assert ray.get(ref) == "hello"

        forwarded = _eval_calls(chio)[0].parameters["kwargs"]
        assert forwarded["label"] == "hello"
        assert forwarded["body"] == {
            "omitted": True,
            "byte_count": len(b"SECRET_TOKEN=xyz"),
        }

    def test_custom_policy_does_not_redact_default_fields(self) -> None:
        chio = allow_all()
        custom = RedactionPolicy(body_fields={"my_tool": ("body",)})

        @chio_remote(
            scope="tools:chio_file_write",
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
            tool_name="chio_file_write",
            redaction_policy=custom,
        )
        def write(*, path: str, content: str) -> str:
            return path

        ref = write.remote(path="/tmp/x", content="not-redacted-now")
        assert ray.get(ref) == "/tmp/x"

        forwarded = _eval_calls(chio)[0].parameters["kwargs"]
        assert forwarded["content"] == "not-redacted-now"

    def test_positional_args_for_known_tool_are_redacted(self) -> None:
        chio = allow_all()

        @chio_remote(
            scope="tools:chio_file_write",
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
            tool_name="chio_file_write",
        )
        def write(path: str, content: str) -> str:
            return path

        ref = write.remote("/tmp/x", "POSITIONAL_SECRET")
        assert ray.get(ref) == "/tmp/x"

        import json

        params = _eval_calls(chio)[0].parameters
        assert params["args"][0] == "/tmp/x"
        assert params["args"][1] == {
            "omitted": True,
            "byte_count": len(b"POSITIONAL_SECRET"),
        }
        assert params["kwargs"] == {}
        assert "POSITIONAL_SECRET" not in json.dumps(params)

    def test_pure_forwarding_wrapper_redacts_positional_via_tool_table(
        self,
    ) -> None:
        chio = allow_all()

        @chio_remote(
            scope="tools:chio_file_write",
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
            tool_name="chio_file_write",
        )
        def write(*args: Any, **kwargs: Any) -> str:
            return str(args[0]) if args else ""

        ref = write.remote("/tmp/x", "PROD_SECRET=abc123")
        assert ray.get(ref) == "/tmp/x"

        import json

        params = _eval_calls(chio)[0].parameters
        assert "PROD_SECRET" not in json.dumps(params)
        assert params["args"][0] == "/tmp/x"
        assert params["args"][1] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }
        assert params["kwargs"] == {}

    def test_pure_forwarding_wrapper_preserves_kwarg_conflict(self) -> None:
        # Caller supplies both positional and kwarg for the same field;
        # both sides must be redacted independently. The wrapped fn raises
        # TypeError for the duplicate; we only assert sidecar saw both redacted.
        chio = allow_all()

        @chio_remote(
            scope="tools:chio_file_write",
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
            tool_name="chio_file_write",
        )
        def write(*args: Any, **kwargs: Any) -> str:
            return str(args[0]) if args else ""

        try:
            ref = write.remote(
                "/tmp/x",
                "POSITIONAL_BODY",
                path="/etc/passwd",
                content="KW_BODY",
            )
            ray.get(ref)
        except Exception:
            # TypeError from the duplicate ``path`` kwarg; expected.
            pass

        import json

        params = _eval_calls(chio)[0].parameters
        forwarded_blob = json.dumps(params)
        # Neither side leaks: the positional body and the keyword body
        # are both replaced by the omission stub.
        assert "POSITIONAL_BODY" not in forwarded_blob
        assert "KW_BODY" not in forwarded_blob
        assert "/etc/passwd" in forwarded_blob  # path is not a body field
        assert params["args"][0] == "/tmp/x"
        assert params["args"][1] == {
            "omitted": True,
            "byte_count": len(b"POSITIONAL_BODY"),
        }
        assert params["kwargs"]["path"] == "/etc/passwd"
        assert params["kwargs"]["content"] == {
            "omitted": True,
            "byte_count": len(b"KW_BODY"),
        }

    def test_var_positional_extras_remain_in_args(self) -> None:
        chio = allow_all()

        @chio_remote(
            scope="tools:chio_file_write",
            capability_id="cap-1",
            tool_server="srv",
            chio_client=chio,
            tool_name="chio_file_write",
        )
        def write(path: str, content: str, *extras: Any) -> str:
            return path

        ref = write.remote(
            "/tmp/x", "PROD_SECRET=abc123", "trailing-1", "trailing-2"
        )
        assert ray.get(ref) == "/tmp/x"

        import json

        params = _eval_calls(chio)[0].parameters
        assert "PROD_SECRET" not in json.dumps(params)
        assert params["args"][0] == "/tmp/x"
        assert params["args"][1] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }
        assert params["args"][2] == "trailing-1"
        assert params["args"][3] == "trailing-2"
        assert params["kwargs"] == {}


class TestChioActorRedaction:
    def test_default_policy_redacts_chio_file_write_method_kwargs(self) -> None:
        chio = allow_all()
        scope = _scope_for_tools("chio_file_write", server_id="srv")
        token = _local_token(scope)
        grant = StandingGrant(
            token=token, tool_server="srv", actor_class="tests.Writer"
        )

        @ray.remote
        class Writer(ChioActor):
            def __init__(self) -> None:
                super().__init__(standing_grant=grant, chio_client=chio)

            @ChioActor.requires(
                "tools:chio_file_write", tool_name="chio_file_write"
            )
            def chio_file_write(self, *, path: str, content: str) -> str:
                return path

        handle = Writer.remote()
        result = ray.get(
            handle.chio_file_write.remote(
                path="/tmp/x", content="PROD_SECRET=abc123"
            )
        )
        assert result == "/tmp/x"

        forwarded = _eval_calls(chio)[0].parameters["kwargs"]
        assert forwarded["path"] == "/tmp/x"
        assert forwarded["content"] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }

    def test_unrelated_method_passes_kwargs_through(self) -> None:
        chio = allow_all()
        scope = _scope_for_tools("search", server_id="srv")
        token = _local_token(scope)
        grant = StandingGrant(
            token=token, tool_server="srv", actor_class="tests.Searcher"
        )

        @ray.remote
        class Searcher(ChioActor):
            def __init__(self) -> None:
                super().__init__(standing_grant=grant, chio_client=chio)

            @ChioActor.requires("tools:search", tool_name="search")
            def search(self, *, query: str, content: str) -> str:
                return query

        handle = Searcher.remote()
        result = ray.get(
            handle.search.remote(query="quantum", content="not redacted here")
        )
        assert result == "quantum"

        forwarded = _eval_calls(chio)[0].parameters["kwargs"]
        assert forwarded == {
            "query": "quantum",
            "content": "not redacted here",
        }

    def test_var_keyword_method_redacts_content(self) -> None:
        # bind_partial does NOT raise for **kwargs; `content="SECRET"`
        # absorbed into `{"kw": {...}}` must still pass through the
        # redactor rather than bypass it.
        chio = allow_all()
        scope = _scope_for_tools("chio_file_write", server_id="srv")
        token = _local_token(scope)
        grant = StandingGrant(
            token=token, tool_server="srv", actor_class="tests.WriterKW"
        )

        @ray.remote
        class WriterKW(ChioActor):
            def __init__(self) -> None:
                super().__init__(standing_grant=grant, chio_client=chio)

            @ChioActor.requires(
                "tools:chio_file_write", tool_name="chio_file_write"
            )
            def chio_file_write(self, **kwargs: Any) -> str:
                return str(kwargs.get("path", ""))

        handle = WriterKW.remote()
        result = ray.get(
            handle.chio_file_write.remote(
                path="/tmp/x", content="PROD_SECRET=abc123"
            )
        )
        assert result == "/tmp/x"

        import json

        params = _eval_calls(chio)[0].parameters
        assert "PROD_SECRET" not in json.dumps(params)
        assert params["kwargs"]["content"] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }

    def test_named_plus_var_keyword_method_redacts_spillover(self) -> None:
        chio = allow_all()
        scope = _scope_for_tools("chio_file_write", server_id="srv")
        token = _local_token(scope)
        grant = StandingGrant(
            token=token, tool_server="srv", actor_class="tests.WriterMixed"
        )

        @ray.remote
        class WriterMixed(ChioActor):
            def __init__(self) -> None:
                super().__init__(standing_grant=grant, chio_client=chio)

            @ChioActor.requires(
                "tools:chio_file_write", tool_name="chio_file_write"
            )
            def chio_file_write(self, path: str, **extras: Any) -> str:
                return path

        handle = WriterMixed.remote()
        result = ray.get(
            handle.chio_file_write.remote(
                path="/tmp/x", content="PROD_SECRET=abc123"
            )
        )
        assert result == "/tmp/x"

        import json

        params = _eval_calls(chio)[0].parameters
        assert "PROD_SECRET" not in json.dumps(params)
        assert params["kwargs"]["path"] == "/tmp/x"
        assert params["kwargs"]["content"] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }

    def test_positional_method_args_still_redacted(self) -> None:
        chio = allow_all()
        scope = _scope_for_tools("chio_file_write", server_id="srv")
        token = _local_token(scope)
        grant = StandingGrant(
            token=token, tool_server="srv", actor_class="tests.WriterPos"
        )

        @ray.remote
        class WriterPos(ChioActor):
            def __init__(self) -> None:
                super().__init__(standing_grant=grant, chio_client=chio)

            @ChioActor.requires(
                "tools:chio_file_write", tool_name="chio_file_write"
            )
            def chio_file_write(self, path: str, content: str) -> str:
                return path

        handle = WriterPos.remote()
        result = ray.get(
            handle.chio_file_write.remote("/tmp/x", "PROD_SECRET=abc123")
        )
        assert result == "/tmp/x"

        import json

        params = _eval_calls(chio)[0].parameters
        assert "PROD_SECRET" not in json.dumps(params)
        assert params["args"][0] == "/tmp/x"
        assert params["args"][1] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }
        assert params["kwargs"] == {}

    def test_method_receiver_not_named_self_still_drops_implicit_arg(
        self,
    ) -> None:
        # Receiver named "this" rather than "self"; the redaction helper
        # must still drop the implicit receiver or the body field binds
        # to "path" and "content" leaks unredacted.
        chio = allow_all()
        scope = _scope_for_tools("chio_file_write", server_id="srv")
        token = _local_token(scope)
        grant = StandingGrant(
            token=token,
            tool_server="srv",
            actor_class="tests.WriterAlt",
        )

        @ray.remote
        class WriterAlt(ChioActor):
            def __init__(self) -> None:
                super().__init__(standing_grant=grant, chio_client=chio)

            @ChioActor.requires(
                "tools:chio_file_write", tool_name="chio_file_write"
            )
            def chio_file_write(this, path: str, content: str) -> str:  # noqa: N805
                return path

        handle = WriterAlt.remote()
        result = ray.get(
            handle.chio_file_write.remote("/tmp/x", "PROD_SECRET=abc123")
        )
        assert result == "/tmp/x"

        import json

        params = _eval_calls(chio)[0].parameters
        forwarded_blob = json.dumps(params)
        assert "PROD_SECRET" not in forwarded_blob
        assert params["args"][0] == "/tmp/x"
        assert params["args"][1] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }
        assert params["kwargs"] == {}

    def test_custom_policy_via_actor_ctor(self) -> None:
        chio = allow_all()
        scope = _scope_for_tools("my_tool", server_id="srv")
        token = _local_token(scope)
        grant = StandingGrant(
            token=token, tool_server="srv", actor_class="tests.Custom"
        )
        custom = RedactionPolicy(body_fields={"my_tool": ("body",)})

        @ray.remote
        class Custom(ChioActor):
            def __init__(self) -> None:
                super().__init__(
                    standing_grant=grant,
                    chio_client=chio,
                    redaction_policy=custom,
                )

            @ChioActor.requires("tools:my_tool", tool_name="my_tool")
            def my_tool(self, *, label: str, body: str) -> str:
                return label

        handle = Custom.remote()
        result = ray.get(
            handle.my_tool.remote(label="hello", body="SECRET_TOKEN=xyz")
        )
        assert result == "hello"

        forwarded = _eval_calls(chio)[0].parameters["kwargs"]
        assert forwarded["label"] == "hello"
        assert forwarded["body"] == {
            "omitted": True,
            "byte_count": len(b"SECRET_TOKEN=xyz"),
        }
