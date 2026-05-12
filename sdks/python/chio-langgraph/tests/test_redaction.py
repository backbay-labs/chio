"""Tests for chio-langgraph argument redaction."""

from __future__ import annotations

from typing import Any, TypedDict

from chio_adapter_base.redact import RedactionPolicy
from chio_sdk.models import ChioScope, Operation, ToolGrant
from chio_sdk.testing import MockChioClient, allow_all

from chio_langgraph import (
    ApprovalResolution,
    ChioGraphConfig,
    chio_approval_node,
    chio_node,
)

SERVER_ID = "demo-srv"


class State(TypedDict, total=False):
    path: str
    content: str
    patch: str
    query: str


def _scope(*tools: str) -> ChioScope:
    return ChioScope(
        grants=[
            ToolGrant(
                server_id=SERVER_ID,
                tool_name=name,
                operations=[Operation.INVOKE],
            )
            for name in tools
        ]
    )


async def _build_config(
    chio: MockChioClient, *, node_name: str, scope: ChioScope
) -> ChioGraphConfig:
    cfg = ChioGraphConfig(
        chio_client=chio,
        node_scopes={node_name: scope},
    )
    await cfg.provision()
    return cfg


def _last_eval(chio: MockChioClient) -> Any:
    eval_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
    assert eval_calls, "expected at least one evaluate_tool_call"
    return eval_calls[-1]


class _FakeInterrupt:
    """Drop-in replacement for ``langgraph.types.interrupt``."""

    def __init__(self, resume_value: Any) -> None:
        self.resume_value = resume_value
        self.payloads: list[dict[str, Any]] = []

    def __call__(self, payload: Any) -> Any:
        self.payloads.append(dict(payload))
        return self.resume_value


class TestChioNodeDefaultPolicy:
    async def test_chio_file_write_content_is_redacted(self) -> None:
        def write_body(state: State) -> dict[str, Any]:
            assert state.get("content") == "PROD_SECRET=abc123"
            return {"path": state.get("path", "")}

        chio = allow_all()
        cfg = await _build_config(
            chio, node_name="chio_file_write", scope=_scope("chio_file_write")
        )
        wrapped = chio_node(
            write_body,
            scope=_scope("chio_file_write"),
            config=cfg,
            name="chio_file_write",
        )

        await wrapped({"path": "/tmp/x", "content": "PROD_SECRET=abc123"})

        forwarded = _last_eval(chio).parameters
        assert forwarded["path"] == "/tmp/x"
        assert forwarded["content"] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }

    async def test_chio_file_edit_patch_is_redacted(self) -> None:
        def edit_body(state: State) -> dict[str, Any]:
            return {"path": state.get("path", "")}

        chio = allow_all()
        cfg = await _build_config(
            chio, node_name="chio_file_edit", scope=_scope("chio_file_edit")
        )
        wrapped = chio_node(
            edit_body,
            scope=_scope("chio_file_edit"),
            config=cfg,
            name="chio_file_edit",
        )

        await wrapped({"path": "/tmp/x", "patch": "--- a\n+++ b\n@@ secret @@"})

        forwarded = _last_eval(chio).parameters
        assert forwarded["path"] == "/tmp/x"
        assert forwarded["patch"] == {
            "omitted": True,
            "byte_count": len(b"--- a\n+++ b\n@@ secret @@"),
        }

    async def test_unrelated_tool_passes_state_through(self) -> None:
        def search_body(_state: State) -> dict[str, Any]:
            return {"query": "ok"}

        chio = allow_all()
        cfg = await _build_config(
            chio, node_name="search", scope=_scope("search")
        )
        wrapped = chio_node(
            search_body,
            scope=_scope("search"),
            config=cfg,
            name="search",
        )

        await wrapped({"query": "quantum", "content": "not redacted here"})

        forwarded = _last_eval(chio).parameters
        assert forwarded == {"query": "quantum", "content": "not redacted here"}

    async def test_body_receives_original_state(self) -> None:
        seen: list[dict[str, Any]] = []

        def write_body(state: State) -> dict[str, Any]:
            seen.append(dict(state))
            return {}

        chio = allow_all()
        cfg = await _build_config(
            chio, node_name="chio_file_write", scope=_scope("chio_file_write")
        )
        wrapped = chio_node(
            write_body,
            scope=_scope("chio_file_write"),
            config=cfg,
            name="chio_file_write",
        )

        await wrapped({"path": "/tmp/x", "content": "PLAINTEXT_SECRET"})

        assert seen == [{"path": "/tmp/x", "content": "PLAINTEXT_SECRET"}]


class TestChioNodeCustomPolicy:
    async def test_custom_policy_redacts_only_named_fields(self) -> None:
        custom = RedactionPolicy(body_fields={"my_tool": ("body",)})

        def my_body(_state: dict[str, Any]) -> dict[str, Any]:
            return {}

        chio = allow_all()
        cfg = await _build_config(
            chio, node_name="my_tool", scope=_scope("my_tool")
        )
        wrapped = chio_node(
            my_body,
            scope=_scope("my_tool"),
            config=cfg,
            name="my_tool",
            redaction_policy=custom,
        )

        await wrapped({"label": "hello", "body": "SECRET_TOKEN=xyz"})

        forwarded = _last_eval(chio).parameters
        assert forwarded["label"] == "hello"
        assert forwarded["body"] == {
            "omitted": True,
            "byte_count": len(b"SECRET_TOKEN=xyz"),
        }

    async def test_custom_policy_does_not_redact_default_fields(self) -> None:
        custom = RedactionPolicy(body_fields={"my_tool": ("body",)})

        def write_body(_state: State) -> dict[str, Any]:
            return {}

        chio = allow_all()
        cfg = await _build_config(
            chio, node_name="chio_file_write", scope=_scope("chio_file_write")
        )
        wrapped = chio_node(
            write_body,
            scope=_scope("chio_file_write"),
            config=cfg,
            name="chio_file_write",
            redaction_policy=custom,
        )

        await wrapped({"path": "/tmp/x", "content": "not-redacted-now"})

        forwarded = _last_eval(chio).parameters
        assert forwarded["content"] == "not-redacted-now"


class TestChioApprovalNodeRedacts:
    async def test_approval_payload_carries_redacted_parameter_hash(
        self,
    ) -> None:
        ran: list[dict[str, Any]] = []

        def write_body(state: State) -> dict[str, Any]:
            ran.append(dict(state))
            return {"path": state.get("path", "")}

        async def policy(
            _state: Any, _runtime_config: Any
        ) -> bool:
            return True

        fake_interrupt = _FakeInterrupt(
            ApprovalResolution(outcome="approved", approval_id="ap-1")
        )

        chio = allow_all()
        cfg = await _build_config(
            chio, node_name="chio_file_write", scope=_scope("chio_file_write")
        )
        wrapped = chio_approval_node(
            write_body,
            scope=_scope("chio_file_write"),
            config=cfg,
            name="chio_file_write",
            approval_policy=policy,
            interrupt_fn=fake_interrupt,
        )

        await wrapped(
            {"path": "/tmp/x", "content": "PROD_SECRET=abc123"}
        )

        forwarded = _last_eval(chio).parameters
        assert forwarded["content"] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }
        assert ran == [
            {"path": "/tmp/x", "content": "PROD_SECRET=abc123"}
        ]
        assert len(fake_interrupt.payloads) == 1
        payload = fake_interrupt.payloads[0]
        # Raw secret must never appear in the HITL approval prompt.
        assert "PROD_SECRET=abc123" not in repr(payload)

    async def test_approval_node_custom_policy_replaces_default(self) -> None:
        custom = RedactionPolicy(body_fields={"my_tool": ("body",)})

        def my_body(_state: dict[str, Any]) -> dict[str, Any]:
            return {}

        async def policy(_state: Any, _rc: Any) -> bool:
            return True

        fake_interrupt = _FakeInterrupt(
            ApprovalResolution(outcome="approved", approval_id="ap-1")
        )

        chio = allow_all()
        cfg = await _build_config(
            chio, node_name="my_tool", scope=_scope("my_tool")
        )
        wrapped = chio_approval_node(
            my_body,
            scope=_scope("my_tool"),
            config=cfg,
            name="my_tool",
            approval_policy=policy,
            interrupt_fn=fake_interrupt,
            redaction_policy=custom,
        )

        await wrapped({"label": "hello", "body": "SECRET_TOKEN=xyz"})

        forwarded = _last_eval(chio).parameters
        assert forwarded["body"] == {
            "omitted": True,
            "byte_count": len(b"SECRET_TOKEN=xyz"),
        }
