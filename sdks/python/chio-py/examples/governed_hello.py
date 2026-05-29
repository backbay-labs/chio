from __future__ import annotations

import json
import os
import sys

import httpx

from chio import ChioClient, ReceiptQueryClient


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"missing required environment variable: {name}")
    return value


def session_capability_id(base_url: str, auth_token: str, session_id: str) -> str:
    response = httpx.get(
        f"{base_url}/admin/sessions/{session_id}/trust",
        headers={"Authorization": f"Bearer {auth_token}"},
        timeout=5.0,
    )
    response.raise_for_status()
    payload = response.json()
    capabilities = payload.get("capabilities") or []
    capability_id = capabilities[0].get("capabilityId") if capabilities else None
    if not isinstance(capability_id, str) or not capability_id:
        raise RuntimeError("session trust endpoint did not return an active capability id")
    return capability_id


def main() -> None:
    base_url = require_env("CHIO_BASE_URL")
    control_url = os.environ.get("CHIO_CONTROL_URL", base_url)
    auth_token = require_env("CHIO_AUTH_TOKEN")
    message = sys.argv[1] if len(sys.argv) > 1 else "hello from the Python SDK"

    client = ChioClient.with_static_bearer(base_url, auth_token)
    session = client.initialize(
        client_info={"name": "chio-sdk/examples/python", "version": "0.1.0"}
    )

    try:
        tools_result = session.list_tools()
        tools = tools_result.get("result", {}).get("tools", [])
        capability_id = session_capability_id(base_url, auth_token, session.session_id)
        tool_result = session.call_tool("echo_text", {"message": message}).get("result", {})
        receipts = ReceiptQueryClient(control_url, auth_token).query(
            {"capabilityId": capability_id, "limit": 10}
        )
        receipt_list = receipts.get("receipts", [])
        if not receipt_list:
            raise RuntimeError("receipt query did not return the governed tool receipt")
        receipt = receipt_list[-1]

        print(
            json.dumps(
                {
                    "sessionId": session.session_id,
                    "capabilityId": capability_id,
                    "toolNames": [tool["name"] for tool in tools],
                    "echo": tool_result.get("structuredContent", {}).get("echo"),
                    "receiptId": receipt.get("id"),
                    "receiptDecision": receipt.get("decision"),
                },
                indent=2,
            )
        )
    finally:
        session.close()


if __name__ == "__main__":
    main()
