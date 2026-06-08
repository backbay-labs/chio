"""Tests for ChioTool argument redaction (chio-adapter-base wiring).

These tests assert that ``ChioTool`` redacts secret-bearing fields from
its tool arguments BEFORE forwarding them to the sidecar's
advisory evaluation endpoint, so the receipt log never carries the raw
secret bytes.

Source of truth: ``chio_adapter_base.redact.redact_args``.
"""

from __future__ import annotations

import json

import httpx
import respx
from chio_adapter_base.redact import RedactionPolicy
from chio_langchain.tool import ChioTool, ChioToolkit

BASE = "http://127.0.0.1:9090"


def _make_receipt_dict() -> dict:
    return {
        "id": "1" * 64,
        "timestamp": 1700000000,
        "capability_id": "cap-1",
        "tool_server": "fs",
        "tool_name": "chio_file_write",
        "action": {"parameters": {"path": "/tmp/x"}, "parameter_hash": "2" * 64},
        "decision": None,
        "receipt_kind": "advisory_evaluation",
        "boundary_class": "advisory_only",
        "observation_outcome": "evaluated",
        "tool_origin": "caller_executed",
        "redaction_mode": "none",
        "content_hash": "3" * 64,
        "policy_hash": "cafe",
        "trust_level": "advisory",
        "kernel_key": "5" * 64,
        "signature": "6" * 128,
    }


def _advisory_wrapper(receipt: dict) -> dict:
    return {
        "schema": "chio.sidecar.advisory-evaluation.v1",
        "authorization": False,
        "authorizationBasis": "advisory_only",
        "receipt": receipt,
    }


def _advisory_verify_report() -> dict:
    return {
        "signature_valid": True,
        "signer_trusted": True,
        "receipt_id_valid": True,
        "parameter_hash_valid": True,
        "receipt_kind": "advisory_evaluation",
        "boundary_class": "advisory_only",
        "trust_level": "advisory",
        "result": "allow",
        "authorized": False,
        "signer_key_hex": "5" * 64,
        "ok": False,
    }


# ---------------------------------------------------------------------------
# Default policy: chio_file_write.content / chio_file_edit.patch
# ---------------------------------------------------------------------------


class TestDefaultPolicyRedacts:
    @respx.mock
    async def test_chio_file_write_content_is_redacted(self) -> None:
        route = respx.post(f"{BASE}/v1/evaluate/advisory").mock(
            return_value=httpx.Response(
                200,
                json=_advisory_wrapper(_make_receipt_dict()),
            )
        )
        respx.post(f"{BASE}/v1/receipts/verify").mock(
            return_value=httpx.Response(200, json=_advisory_verify_report())
        )

        tool = ChioTool(
            name="chio_file_write",
            description="Write a file",
            server_id="fs",
            capability_id="cap-1",
            sidecar_url=BASE,
        )
        await tool._arun(path="/tmp/x", content="PROD_SECRET=abc123")

        # The sidecar should have received the REDACTED parameters, never
        # the raw content bytes.
        assert route.called
        body = json.loads(route.calls.last.request.content.decode("utf-8"))
        forwarded = body.get("parameters", {})
        assert forwarded["path"] == "/tmp/x"
        assert forwarded["content"] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }

    @respx.mock
    async def test_chio_file_edit_patch_is_redacted(self) -> None:
        receipt = _make_receipt_dict()
        receipt["tool_name"] = "chio_file_edit"
        route = respx.post(f"{BASE}/v1/evaluate/advisory").mock(
            return_value=httpx.Response(200, json=_advisory_wrapper(receipt))
        )
        respx.post(f"{BASE}/v1/receipts/verify").mock(
            return_value=httpx.Response(200, json=_advisory_verify_report())
        )

        tool = ChioTool(
            name="chio_file_edit",
            description="Edit a file",
            server_id="fs",
            capability_id="cap-1",
            sidecar_url=BASE,
        )
        await tool._arun(path="/tmp/x", patch="--- a\n+++ b\n@@ secret @@")

        body = json.loads(route.calls.last.request.content.decode("utf-8"))
        forwarded = body.get("parameters", {})
        assert forwarded["path"] == "/tmp/x"
        assert forwarded["patch"] == {
            "omitted": True,
            "byte_count": len(b"--- a\n+++ b\n@@ secret @@"),
        }

    @respx.mock
    async def test_unrelated_tool_passes_args_through(self) -> None:
        receipt = _make_receipt_dict()
        receipt["tool_name"] = "search"
        route = respx.post(f"{BASE}/v1/evaluate/advisory").mock(
            return_value=httpx.Response(200, json=_advisory_wrapper(receipt))
        )
        respx.post(f"{BASE}/v1/receipts/verify").mock(
            return_value=httpx.Response(200, json=_advisory_verify_report())
        )

        tool = ChioTool(
            name="search",
            description="Search",
            server_id="fs",
            capability_id="cap-1",
            sidecar_url=BASE,
        )
        await tool._arun(query="quantum", content="not redacted here")

        body = json.loads(route.calls.last.request.content.decode("utf-8"))
        forwarded = body.get("parameters", {})
        # The default policy only matches chio_file_write / chio_file_edit;
        # unrelated tools see their args unmodified.
        assert forwarded == {"query": "quantum", "content": "not redacted here"}


# ---------------------------------------------------------------------------
# Custom policy: only my_tool.body is redacted
# ---------------------------------------------------------------------------


class TestCustomPolicy:
    @respx.mock
    async def test_custom_policy_redacts_only_named_fields(self) -> None:
        receipt = _make_receipt_dict()
        receipt["tool_name"] = "my_tool"
        route = respx.post(f"{BASE}/v1/evaluate/advisory").mock(
            return_value=httpx.Response(200, json=_advisory_wrapper(receipt))
        )
        respx.post(f"{BASE}/v1/receipts/verify").mock(
            return_value=httpx.Response(200, json=_advisory_verify_report())
        )

        custom = RedactionPolicy(body_fields={"my_tool": ("body",)})
        tool = ChioTool(
            name="my_tool",
            description="My tool",
            server_id="fs",
            capability_id="cap-1",
            sidecar_url=BASE,
            redaction_policy=custom,
        )
        await tool._arun(label="hello", body="SECRET_TOKEN=xyz")

        body = json.loads(route.calls.last.request.content.decode("utf-8"))
        forwarded = body.get("parameters", {})
        assert forwarded["label"] == "hello"
        assert forwarded["body"] == {
            "omitted": True,
            "byte_count": len(b"SECRET_TOKEN=xyz"),
        }

    @respx.mock
    async def test_custom_policy_does_not_redact_default_fields(self) -> None:
        """A custom policy fully replaces the default; chio_file_write
        is no longer redacted under it.
        """
        receipt = _make_receipt_dict()
        route = respx.post(f"{BASE}/v1/evaluate/advisory").mock(
            return_value=httpx.Response(200, json=_advisory_wrapper(receipt))
        )
        respx.post(f"{BASE}/v1/receipts/verify").mock(
            return_value=httpx.Response(200, json=_advisory_verify_report())
        )

        custom = RedactionPolicy(body_fields={"my_tool": ("body",)})
        tool = ChioTool(
            name="chio_file_write",
            description="Write",
            server_id="fs",
            capability_id="cap-1",
            sidecar_url=BASE,
            redaction_policy=custom,
        )
        await tool._arun(path="/tmp/x", content="not-redacted-now")

        body = json.loads(route.calls.last.request.content.decode("utf-8"))
        forwarded = body.get("parameters", {})
        assert forwarded["content"] == "not-redacted-now"


# ---------------------------------------------------------------------------
# Toolkit forwards the policy to constructed tools
# ---------------------------------------------------------------------------


class TestToolkitForwardsPolicy:
    def test_create_tool_uses_default_policy(self) -> None:
        toolkit = ChioToolkit(capability_id="cap-1", sidecar_url=BASE)
        tool = toolkit.create_tool(
            name="chio_file_write",
            description="Write",
            server_id="fs",
        )
        # Default policy is the chio-default mapping.
        assert "chio_file_write" in tool.redaction_policy.body_fields

    def test_create_tool_forwards_custom_policy(self) -> None:
        custom = RedactionPolicy(body_fields={"my_tool": ("body",)})
        toolkit = ChioToolkit(
            capability_id="cap-1",
            sidecar_url=BASE,
            redaction_policy=custom,
        )
        tool = toolkit.create_tool(
            name="my_tool",
            description="d",
            server_id="fs",
        )
        assert tool.redaction_policy is custom
