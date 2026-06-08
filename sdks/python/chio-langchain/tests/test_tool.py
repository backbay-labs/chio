"""Tests for Chio LangChain tool integration."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from chio_langchain.tool import ChioTool, ChioToolkit, _json_type_to_python

BASE = "http://127.0.0.1:9090"


def _make_advisory_receipt_dict(outcome: str = "evaluated") -> dict:
    return {
        "id": "1" * 64,
        "timestamp": 1700000000,
        "capability_id": "cap-1",
        "tool_server": "srv",
        "tool_name": "read_file",
        "action": {"parameters": {"path": "/tmp"}, "parameter_hash": "2" * 64},
        "decision": None,
        "receipt_kind": "advisory_evaluation",
        "boundary_class": "advisory_only",
        "observation_outcome": outcome,
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


def _advisory_verify_report(result: str = "allow") -> dict:
    return {
        "signature_valid": True,
        "signer_trusted": True,
        "receipt_id_valid": True,
        "parameter_hash_valid": True,
        "receipt_kind": "advisory_evaluation",
        "boundary_class": "advisory_only",
        "trust_level": "advisory",
        "result": result,
        "authorized": False,
        "signer_key_hex": "5" * 64,
        "ok": False,
    }


# ---------------------------------------------------------------------------
# ChioTool
# ---------------------------------------------------------------------------


class TestChioTool:
    def test_construction(self) -> None:
        tool = ChioTool(
            name="read_file",
            description="Read a file from disk",
            server_id="fs-server",
            capability_id="cap-1",
            sidecar_url=BASE,
        )
        assert tool.name == "read_file"
        assert tool.server_id == "fs-server"

    def test_sync_raises(self) -> None:
        tool = ChioTool(
            name="t", description="d", server_id="s", capability_id="c"
        )
        with pytest.raises(NotImplementedError):
            tool._run(path="/tmp")

    @respx.mock
    async def test_advisory_invocation_is_non_authorizing(self) -> None:
        respx.post(f"{BASE}/v1/evaluate/advisory").mock(
            return_value=httpx.Response(
                200,
                json=_advisory_wrapper(_make_advisory_receipt_dict()),
            )
        )
        respx.post(f"{BASE}/v1/receipts/verify").mock(
            return_value=httpx.Response(200, json=_advisory_verify_report())
        )

        tool = ChioTool(
            name="read_file",
            description="Read file",
            server_id="srv",
            capability_id="cap-1",
            sidecar_url=BASE,
        )
        result = await tool._arun(path="/tmp/test.txt")
        data = json.loads(result)
        assert data["error"] == "non_authorizing"
        assert data["receipt_id"] == "1" * 64
        assert tool.last_receipt is not None
        assert tool.last_receipt.receipt_kind.value == "advisory_evaluation"
        assert not tool.last_receipt.is_allowed

    @respx.mock
    async def test_dropped_advisory_invocation(self) -> None:
        respx.post(f"{BASE}/v1/evaluate/advisory").mock(
            return_value=httpx.Response(
                200,
                json=_advisory_wrapper(
                    _make_advisory_receipt_dict(outcome="dropped")
                ),
            )
        )
        respx.post(f"{BASE}/v1/receipts/verify").mock(
            return_value=httpx.Response(200, json=_advisory_verify_report("deny"))
        )

        tool = ChioTool(
            name="read_file",
            description="Read file",
            server_id="srv",
            capability_id="cap-1",
            sidecar_url=BASE,
        )
        result = await tool._arun(path="/etc/shadow")
        data = json.loads(result)
        assert data["error"] == "denied"
        assert data["receipt_id"] == "1" * 64

    @respx.mock
    async def test_denied_error_from_sidecar(self) -> None:
        respx.post(f"{BASE}/v1/evaluate/advisory").mock(
            return_value=httpx.Response(
                403,
                json={
                    "message": "expired",
                    "guard": "TimeGuard",
                    "reason": "token expired",
                },
            )
        )

        tool = ChioTool(
            name="t",
            description="d",
            server_id="s",
            capability_id="c",
            sidecar_url=BASE,
        )
        result = await tool._arun(x=1)
        data = json.loads(result)
        assert data["error"] == "denied"
        assert data["guard"] == "TimeGuard"

    def test_args_schema_generation(self) -> None:
        tool = ChioTool(
            name="test_tool",
            description="A test tool",
            server_id="s",
            capability_id="c",
            input_schema_def={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path"},
                    "count": {"type": "integer", "description": "Number of items"},
                    "verbose": {"type": "boolean", "description": "Verbose output"},
                },
                "required": ["path"],
            },
        )
        schema = tool.get_input_schema()
        assert schema is not None
        assert "path" in schema.model_fields
        assert "count" in schema.model_fields

    def test_empty_schema(self) -> None:
        tool = ChioTool(
            name="t", description="d", server_id="s", capability_id="c"
        )
        assert tool.get_input_schema() is None


# ---------------------------------------------------------------------------
# ChioToolkit
# ---------------------------------------------------------------------------


class TestChioToolkit:
    def test_create_tool(self) -> None:
        toolkit = ChioToolkit(capability_id="cap-1", sidecar_url=BASE)
        tool = toolkit.create_tool(
            name="write_file",
            description="Write a file",
            server_id="fs-server",
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
            },
        )
        assert isinstance(tool, ChioTool)
        assert tool.name == "write_file"
        assert tool.capability_id == "cap-1"

    @respx.mock
    async def test_get_tools_from_sidecar(self) -> None:
        health_data = {
            "status": "ok",
            "servers": [
                {
                    "server_id": "fs",
                    "tools": [
                        {
                            "name": "read_file",
                            "description": "Read a file",
                            "input_schema": {
                                "type": "object",
                                "properties": {
                                    "path": {"type": "string"},
                                },
                            },
                        },
                        {
                            "name": "write_file",
                            "description": "Write a file",
                            "input_schema": {},
                        },
                    ],
                },
                {
                    "server_id": "net",
                    "tools": [
                        {
                            "name": "fetch_url",
                            "description": "Fetch a URL",
                            "input_schema": {},
                        },
                    ],
                },
            ],
        }
        respx.get(f"{BASE}/chio/health").mock(
            return_value=httpx.Response(200, json=health_data)
        )

        toolkit = ChioToolkit(capability_id="cap-1", sidecar_url=BASE)
        tools = await toolkit.get_tools()
        assert len(tools) == 3
        assert tools[0].name == "read_file"
        assert tools[0].server_id == "fs"

    @respx.mock
    async def test_get_tools_filtered_by_server(self) -> None:
        health_data = {
            "status": "ok",
            "servers": [
                {
                    "server_id": "fs",
                    "tools": [{"name": "read", "description": "r"}],
                },
                {
                    "server_id": "net",
                    "tools": [{"name": "fetch", "description": "f"}],
                },
            ],
        }
        respx.get(f"{BASE}/chio/health").mock(
            return_value=httpx.Response(200, json=health_data)
        )

        toolkit = ChioToolkit(capability_id="cap-1", sidecar_url=BASE)
        tools = await toolkit.get_tools(server_id="net")
        assert len(tools) == 1
        assert tools[0].name == "fetch"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TestJsonTypeMapping:
    def test_known_types(self) -> None:
        assert _json_type_to_python("string") is str
        assert _json_type_to_python("integer") is int
        assert _json_type_to_python("number") is float
        assert _json_type_to_python("boolean") is bool
        assert _json_type_to_python("array") is list
        assert _json_type_to_python("object") is dict

    def test_unknown_defaults_to_str(self) -> None:
        assert _json_type_to_python("unknown") is str
