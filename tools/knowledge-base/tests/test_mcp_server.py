import httpx
import pytest
from fastapi.testclient import TestClient
from neo4j.exceptions import ServiceUnavailable

from chio_kb.mcp_server import app


def _rpc(client: TestClient, payload: object, headers: dict[str, str] | None = None) -> dict[str, object]:
    response = client.post("/mcp/", json=payload, headers=headers)
    assert response.status_code == 200
    return response.json()


def test_initialized_notification_has_no_json_rpc_response() -> None:
    client = TestClient(app)

    response = client.post(
        "/mcp/",
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
    )

    assert response.status_code == 202
    assert response.content == b""


def test_request_without_id_is_notification() -> None:
    client = TestClient(app)

    response = client.post(
        "/mcp/",
        json={"jsonrpc": "2.0", "method": "ping"},
    )

    assert response.status_code == 202
    assert response.content == b""


def test_explicit_null_id_still_returns_json_rpc_response() -> None:
    client = TestClient(app)

    response = client.post(
        "/mcp/",
        json={"jsonrpc": "2.0", "id": None, "method": "ping"},
    )

    assert response.status_code == 200
    assert response.json() == {"jsonrpc": "2.0", "id": None, "result": {}}


def test_initialize_request_still_returns_json_rpc_result() -> None:
    client = TestClient(app)

    response = client.post(
        "/mcp/",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
    )

    assert response.status_code == 200
    assert response.json()["id"] == 1
    assert response.json()["result"]["serverInfo"]["name"] == "chio-kb-mcp"


def test_ping_returns_empty_json_rpc_result() -> None:
    client = TestClient(app)

    body = _rpc(client, {"jsonrpc": "2.0", "id": "ping-1", "method": "ping"})

    assert body == {"jsonrpc": "2.0", "id": "ping-1", "result": {}}


def test_non_object_json_rpc_payload_is_invalid_request() -> None:
    client = TestClient(app)

    body = _rpc(client, ["not", "a", "request"])

    assert body["id"] is None
    assert body["error"]["code"] == -32600


def test_non_object_params_are_invalid_params() -> None:
    client = TestClient(app)

    body = _rpc(client, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": []})

    assert body["id"] == 2
    assert body["error"]["code"] == -32602


def test_tools_list_returns_kb_tools() -> None:
    client = TestClient(app)

    body = _rpc(client, {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}})
    tools = {tool["name"] for tool in body["result"]["tools"]}

    assert "kb_search_code" in tools
    assert "kb_manifest" in tools
    assert "kb_subgraph" in tools
    assert "kb_add_episode" in tools


def test_unknown_tool_returns_json_rpc_error() -> None:
    client = TestClient(app)

    body = _rpc(
        client,
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "kb_missing", "arguments": {}},
        },
    )

    assert body["id"] == 4
    assert body["error"]["code"] == -32602
    assert body["error"]["message"] == "Unknown tool: kb_missing"


def test_tools_call_success_path(monkeypatch) -> None:
    async def fake_search_code(query: str, limit: int = 8, filters=None) -> list[dict[str, object]]:
        return [{"query": query, "limit": limit, "filters": filters}]

    monkeypatch.setattr("chio_kb.query.search_code", fake_search_code)
    client = TestClient(app)

    body = _rpc(
        client,
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "kb_search_code", "arguments": {"query": "receipt", "limit": 1}},
        },
    )

    assert body["id"] == 5
    assert '"query": "receipt"' in body["result"]["content"][0]["text"]
    assert '"limit": 1' in body["result"]["content"][0]["text"]


def test_manifest_tool_success_path(monkeypatch) -> None:
    async def fake_manifest() -> dict[str, object]:
        return {"schemaVersion": "chio.kb.manifest.v1", "status": "ready"}

    monkeypatch.setattr("chio_kb.query.manifest", fake_manifest)
    client = TestClient(app)

    body = _rpc(
        client,
        {
            "jsonrpc": "2.0",
            "id": "manifest-1",
            "method": "tools/call",
            "params": {"name": "kb_manifest", "arguments": {}},
        },
    )

    assert '"schemaVersion": "chio.kb.manifest.v1"' in body["result"]["content"][0]["text"]


@pytest.mark.parametrize(
    "backend_error",
    [TimeoutError("manifest timed out"), httpx.ReadTimeout("manifest timed out")],
)
def test_backend_timeout_has_stable_error_kind(monkeypatch, backend_error: Exception) -> None:
    async def fake_manifest() -> dict[str, object]:
        raise backend_error

    monkeypatch.setattr("chio_kb.query.manifest", fake_manifest)
    client = TestClient(app)

    body = _rpc(
        client,
        {
            "jsonrpc": "2.0",
            "id": "manifest-timeout",
            "method": "tools/call",
            "params": {"name": "kb_manifest", "arguments": {}},
        },
    )

    assert body["error"]["code"] == -32002
    assert body["error"]["data"] == {"kind": "timeout"}


@pytest.mark.parametrize(
    "backend_error",
    [httpx.ConnectError("Graphiti unavailable"), ServiceUnavailable("Neo4j unavailable")],
)
def test_backend_transport_failure_has_stable_error_kind(monkeypatch, backend_error: Exception) -> None:
    async def fake_manifest() -> dict[str, object]:
        raise backend_error

    monkeypatch.setattr("chio_kb.query.manifest", fake_manifest)
    body = _rpc(
        TestClient(app),
        {
            "jsonrpc": "2.0",
            "id": "manifest-unavailable",
            "method": "tools/call",
            "params": {"name": "kb_manifest", "arguments": {}},
        },
    )

    assert body["error"]["code"] == -32003
    assert body["error"]["data"] == {"kind": "unavailable"}


def test_kb_add_episode_requires_loopback_or_bearer_token() -> None:
    client = TestClient(app)

    body = _rpc(
        client,
        {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "kb_add_episode",
                "arguments": {"name": "repair", "body": "summary"},
            },
        },
    )

    assert body["id"] == 6
    assert body["error"]["code"] == -32001


def test_kb_add_episode_accepts_bearer_token(monkeypatch) -> None:
    async def fake_add_episode(
        name: str,
        body: str,
        source_description: str = "Chio KB user episode",
    ) -> dict[str, object]:
        return {"name": name, "body": body, "source_description": source_description}

    monkeypatch.setenv("CHIO_KB_MCP_BEARER_TOKEN", "test-token")
    monkeypatch.setattr("chio_kb.query.add_episode", fake_add_episode)
    client = TestClient(app)

    body = _rpc(
        client,
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "kb_add_episode",
                "arguments": {"name": "repair", "body": "summary"},
            },
        },
        headers={"authorization": "Bearer test-token"},
    )

    assert body["id"] == 7
    assert '"name": "repair"' in body["result"]["content"][0]["text"]
