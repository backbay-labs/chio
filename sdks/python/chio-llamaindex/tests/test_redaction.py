"""Tests for ChioFunctionTool argument redaction (chio-adapter-base wiring).

These tests assert that ``ChioFunctionTool`` redacts secret-bearing
fields from its tool arguments BEFORE forwarding them to the sidecar's
``evaluate_tool_call`` endpoint, so the receipt log never carries the
raw secret bytes. The underlying function still sees the original
arguments.

Source of truth: ``chio_adapter_base.redact.redact_args``.
"""

from __future__ import annotations

from typing import Any

from chio_adapter_base.redact import RedactionPolicy
from chio_sdk.testing import allow_all

from chio_llamaindex import ChioFunctionTool

# ---------------------------------------------------------------------------
# Default policy: chio_file_write.content / chio_file_edit.patch
# ---------------------------------------------------------------------------


class TestDefaultPolicyRedacts:
    async def test_chio_file_write_content_is_redacted_in_recorded_params(
        self,
    ) -> None:
        captured_args: list[dict[str, Any]] = []

        def write_file(path: str, content: str) -> str:
            captured_args.append({"path": path, "content": content})
            return f"wrote {len(content)} bytes to {path}"

        async with allow_all() as chio:
            tool = ChioFunctionTool(
                fn=write_file,
                name="chio_file_write",
                description="write a file",
                server_id="fs",
                capability_id="cap-1",
                chio_client=chio,
            )
            await tool.acall(path="/tmp/x", content="PROD_SECRET=abc123")

        # Sidecar received redacted parameters.
        eval_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(eval_calls) == 1
        recorded = eval_calls[0]
        assert recorded.parameters["path"] == "/tmp/x"
        assert recorded.parameters["content"] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }
        # The underlying function still saw the real content.
        assert captured_args == [
            {"path": "/tmp/x", "content": "PROD_SECRET=abc123"}
        ]

    async def test_chio_file_edit_patch_is_redacted(self) -> None:
        async with allow_all() as chio:
            tool = ChioFunctionTool(
                fn=lambda path, patch: f"applied {len(patch)} bytes to {path}",
                name="chio_file_edit",
                description="edit a file",
                server_id="fs",
                capability_id="cap-1",
                chio_client=chio,
            )
            await tool.acall(path="/tmp/x", patch="--- a\n+++ b\n@@ secret @@")

        eval_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        recorded = eval_calls[0]
        assert recorded.parameters["path"] == "/tmp/x"
        assert recorded.parameters["patch"] == {
            "omitted": True,
            "byte_count": len(b"--- a\n+++ b\n@@ secret @@"),
        }

    async def test_chio_file_write_positional_args_are_redacted(self) -> None:
        def write_file(path: str, content: str) -> str:
            return f"wrote {len(content)} bytes to {path}"

        async with allow_all() as chio:
            tool = ChioFunctionTool(
                fn=write_file,
                name="chio_file_write",
                description="write a file",
                server_id="fs",
                capability_id="cap-1",
                chio_client=chio,
            )
            await tool.acall("/tmp/x", "PROD_SECRET=abc123")

        eval_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        recorded = eval_calls[0]
        assert recorded.parameters == {
            "_args": [
                "/tmp/x",
                {
                    "omitted": True,
                    "byte_count": len(b"PROD_SECRET=abc123"),
                },
            ]
        }

    async def test_chio_file_write_body_alias_is_redacted(self) -> None:
        def write_file(path: str, body: str) -> str:
            return f"wrote {len(body)} bytes to {path}"

        async with allow_all() as chio:
            tool = ChioFunctionTool(
                fn=write_file,
                name="chio_file_write",
                description="write a file",
                server_id="fs",
                capability_id="cap-1",
                chio_client=chio,
            )
            await tool.acall(path="/tmp/x", body="PROD_SECRET=abc123")

        eval_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        recorded = eval_calls[0]
        assert recorded.parameters["path"] == "/tmp/x"
        assert recorded.parameters["body"] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }

    async def test_unrelated_tool_passes_args_through(self) -> None:
        async with allow_all() as chio:
            tool = ChioFunctionTool(
                fn=lambda q, content: f"hit:{q}",
                name="search",
                description="search",
                server_id="fs",
                capability_id="cap-1",
                chio_client=chio,
            )
            await tool.acall(q="quantum", content="not redacted here")

        eval_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        recorded = eval_calls[0]
        # Default policy only matches chio_file_write / chio_file_edit;
        # unrelated tools see their args unmodified.
        assert recorded.parameters == {
            "q": "quantum",
            "content": "not redacted here",
        }


# ---------------------------------------------------------------------------
# Custom policy: only my_tool.body is redacted
# ---------------------------------------------------------------------------


class TestCustomPolicy:
    async def test_custom_policy_redacts_only_named_fields(self) -> None:
        custom = RedactionPolicy(body_fields={"my_tool": ("body",)})

        async with allow_all() as chio:
            tool = ChioFunctionTool(
                fn=lambda label, body: f"saw {label}",
                name="my_tool",
                description="my tool",
                server_id="fs",
                capability_id="cap-1",
                chio_client=chio,
                redaction_policy=custom,
            )
            await tool.acall(label="hello", body="SECRET_TOKEN=xyz")

        eval_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        recorded = eval_calls[0]
        assert recorded.parameters["label"] == "hello"
        assert recorded.parameters["body"] == {
            "omitted": True,
            "byte_count": len(b"SECRET_TOKEN=xyz"),
        }

    async def test_custom_policy_does_not_redact_default_fields(self) -> None:
        """A custom policy fully replaces the default; chio_file_write
        is no longer redacted under it.
        """
        custom = RedactionPolicy(body_fields={"my_tool": ("body",)})

        async with allow_all() as chio:
            tool = ChioFunctionTool(
                fn=lambda path, content: "ok",
                name="chio_file_write",
                description="write",
                server_id="fs",
                capability_id="cap-1",
                chio_client=chio,
                redaction_policy=custom,
            )
            await tool.acall(path="/tmp/x", content="not-redacted-now")

        eval_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        recorded = eval_calls[0]
        assert recorded.parameters["content"] == "not-redacted-now"
