from __future__ import annotations

import json
import unittest

import httpx

from chio.session import initialize_session
from chio.transport import parse_rpc_messages, terminal_message


class TransportTests(unittest.TestCase):
    def test_parse_rpc_messages_handles_json_and_sse(self) -> None:
        json_messages = parse_rpc_messages('{"jsonrpc":"2.0","id":1,"result":{"ok":true}}')
        self.assertEqual(json_messages[0]["result"], {"ok": True})

        sse_messages = parse_rpc_messages(
            '\n'.join(
                [
                    'data: {"jsonrpc":"2.0","method":"notifications/ping"}',
                    "",
                    'data: {"jsonrpc":"2.0","id":1,"result":{"ok":true}}',
                    "",
                ]
            )
        )
        self.assertEqual(len(sse_messages), 2)
        self.assertEqual(sse_messages[0]["method"], "notifications/ping")
        self.assertEqual(sse_messages[1]["id"], 1)

    def test_initialize_session_and_low_level_request_execution(self) -> None:
        calls: list[tuple[str, dict[str, str], dict[str, object] | None]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            headers = {key.lower(): value for key, value in request.headers.items()}
            body = None
            if request.content:
                body = json.loads(request.content.decode("utf-8"))
            calls.append((request.method, headers, body))

            if request.method == "POST" and body and body.get("method") == "initialize":
                self.assertNotIn("mcp-session-id", headers)
                return httpx.Response(
                    200,
                    headers={
                        "content-type": "application/json",
                        "mcp-session-id": "sess-123",
                    },
                    text=json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": 0,
                            "result": {
                                "protocolVersion": "2025-11-25",
                                "capabilities": {},
                                "serverInfo": {"name": "chio-test", "version": "0.1.0"},
                            },
                        }
                    ),
                )

            if request.method == "POST" and body and body.get("method") == "notifications/initialized":
                self.assertEqual(headers["mcp-session-id"], "sess-123")
                self.assertEqual(headers["mcp-protocol-version"], "2025-11-25")
                return httpx.Response(202, headers={"content-type": "application/json"}, text="")

            if request.method == "POST" and body and body.get("method") == "tools/list":
                self.assertEqual(headers["mcp-session-id"], "sess-123")
                self.assertEqual(headers["mcp-protocol-version"], "2025-11-25")
                return httpx.Response(
                    200,
                    headers={"content-type": "application/json"},
                    text=json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": body["id"],
                            "result": {"tools": [{"name": "echo_text"}]},
                        }
                    ),
                )

            if request.method == "DELETE":
                self.assertEqual(headers["mcp-session-id"], "sess-123")
                return httpx.Response(204)

            raise AssertionError(f"unexpected request: {request.method} {request.url}")

        client = httpx.Client(transport=httpx.MockTransport(handler))
        session = initialize_session(
            base_url="http://testserver",
            auth_token="token",
            client=client,
            client_info={"name": "chio-sdk-tests", "version": "1.0.0"},
        )

        self.assertEqual(session.session_id, "sess-123")
        self.assertEqual(session.protocol_version, "2025-11-25")
        self.assertIsNotNone(session.handshake)
        self.assertEqual(session.handshake.initialize_response.status, 200)
        self.assertEqual(session.handshake.initialized_response.status, 202)

        tools_response = session.request("tools/list")
        terminal = terminal_message(tools_response.messages, tools_response.request["id"])
        self.assertEqual(terminal["result"]["tools"][0]["name"], "echo_text")
        self.assertEqual(session.close(), 204)
        self.assertEqual([call[0] for call in calls], ["POST", "POST", "POST", "DELETE"])


if __name__ == "__main__":
    unittest.main()
