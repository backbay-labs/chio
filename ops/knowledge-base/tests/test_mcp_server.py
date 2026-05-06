from fastapi.testclient import TestClient

from chio_kb.mcp_server import app


def test_initialized_notification_has_no_json_rpc_response() -> None:
    client = TestClient(app)

    response = client.post(
        "/mcp/",
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
    )

    assert response.status_code == 202
    assert response.content == b""


def test_initialize_request_still_returns_json_rpc_result() -> None:
    client = TestClient(app)

    response = client.post(
        "/mcp/",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
    )

    assert response.status_code == 200
    assert response.json()["id"] == 1
    assert response.json()["result"]["serverInfo"]["name"] == "chio-kb-mcp"
