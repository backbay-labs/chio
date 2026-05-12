"""Tests for ChioFunctionRegistry argument redaction."""

from __future__ import annotations

from typing import Any

from autogen import ConversableAgent
from chio_adapter_base.redact import RedactionPolicy
from chio_sdk.testing import allow_all

from chio_autogen import ChioFunctionRegistry


def _make_agent(name: str) -> ConversableAgent:
    return ConversableAgent(
        name=name,
        llm_config=False,
        human_input_mode="NEVER",
        code_execution_config=False,
    )


class TestDefaultPolicyRedacts:
    async def test_chio_file_write_content_is_redacted_in_recorded_params(
        self,
    ) -> None:
        captured_kwargs: list[dict[str, Any]] = []

        def write_file(**kwargs: Any) -> str:
            captured_kwargs.append(dict(kwargs))
            return f"wrote {len(kwargs.get('content', ''))} bytes"

        async with allow_all() as chio:
            agent = _make_agent("writer")
            registry = ChioFunctionRegistry(
                agent=agent,
                chio_client=chio,
                server_id="fs",
                capability_id="cap-1",
            )
            registry.register("chio_file_write", write_file)

            wrapped = agent.function_map["chio_file_write"]
            wrapped(path="/tmp/x", content="PROD_SECRET=abc123")

        eval_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(eval_calls) == 1
        recorded = eval_calls[0]
        assert recorded.parameters["path"] == "/tmp/x"
        assert recorded.parameters["content"] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }
        assert captured_kwargs == [
            {"path": "/tmp/x", "content": "PROD_SECRET=abc123"}
        ]

    async def test_chio_file_edit_patch_is_redacted(self) -> None:
        async with allow_all() as chio:
            agent = _make_agent("editor")
            registry = ChioFunctionRegistry(
                agent=agent,
                chio_client=chio,
                server_id="fs",
                capability_id="cap-1",
            )
            registry.register("chio_file_edit", lambda **kw: "ok")

            wrapped = agent.function_map["chio_file_edit"]
            wrapped(path="/tmp/x", patch="--- a\n+++ b\n@@ secret @@")

        eval_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        recorded = eval_calls[0]
        assert recorded.parameters["path"] == "/tmp/x"
        assert recorded.parameters["patch"] == {
            "omitted": True,
            "byte_count": len(b"--- a\n+++ b\n@@ secret @@"),
        }

    async def test_unrelated_tool_passes_args_through(self) -> None:
        async with allow_all() as chio:
            agent = _make_agent("searcher")
            registry = ChioFunctionRegistry(
                agent=agent,
                chio_client=chio,
                server_id="fs",
                capability_id="cap-1",
            )
            registry.register(
                "search", lambda **kw: f"hit:{kw.get('q')}"
            )

            wrapped = agent.function_map["search"]
            wrapped(q="quantum", content="not redacted here")

        eval_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        recorded = eval_calls[0]
        assert recorded.parameters == {
            "q": "quantum",
            "content": "not redacted here",
        }

    async def test_async_function_redacts_recorded_params(self) -> None:
        captured_kwargs: list[dict[str, Any]] = []

        async def write_file(**kwargs: Any) -> str:
            captured_kwargs.append(dict(kwargs))
            return "ok"

        async with allow_all() as chio:
            agent = _make_agent("async-writer")
            registry = ChioFunctionRegistry(
                agent=agent,
                chio_client=chio,
                server_id="fs",
                capability_id="cap-1",
            )
            registry.register("chio_file_write", write_file)

            wrapped = agent.function_map["chio_file_write"]
            await wrapped(path="/tmp/y", content="ASYNC_SECRET=zzz")

        eval_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        recorded = eval_calls[0]
        assert recorded.parameters["path"] == "/tmp/y"
        assert recorded.parameters["content"] == {
            "omitted": True,
            "byte_count": len(b"ASYNC_SECRET=zzz"),
        }
        assert captured_kwargs == [
            {"path": "/tmp/y", "content": "ASYNC_SECRET=zzz"}
        ]


class TestCustomPolicy:
    async def test_custom_policy_redacts_only_named_fields(self) -> None:
        custom = RedactionPolicy(body_fields={"my_tool": ("body",)})

        async with allow_all() as chio:
            agent = _make_agent("custom")
            registry = ChioFunctionRegistry(
                agent=agent,
                chio_client=chio,
                server_id="fs",
                capability_id="cap-1",
                redaction_policy=custom,
            )
            registry.register("my_tool", lambda **kw: "ok")

            wrapped = agent.function_map["my_tool"]
            wrapped(label="hello", body="SECRET_TOKEN=xyz")

        eval_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        recorded = eval_calls[0]
        assert recorded.parameters["label"] == "hello"
        assert recorded.parameters["body"] == {
            "omitted": True,
            "byte_count": len(b"SECRET_TOKEN=xyz"),
        }

    async def test_custom_policy_does_not_redact_default_fields(self) -> None:
        custom = RedactionPolicy(body_fields={"my_tool": ("body",)})

        async with allow_all() as chio:
            agent = _make_agent("custom-write")
            registry = ChioFunctionRegistry(
                agent=agent,
                chio_client=chio,
                server_id="fs",
                capability_id="cap-1",
                redaction_policy=custom,
            )
            registry.register("chio_file_write", lambda **kw: "ok")

            wrapped = agent.function_map["chio_file_write"]
            wrapped(path="/tmp/x", content="not-redacted-now")

        eval_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        recorded = eval_calls[0]
        assert recorded.parameters["content"] == "not-redacted-now"
