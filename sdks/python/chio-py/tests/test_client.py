from __future__ import annotations

import json
import unittest

import httpx

from chio.client import ChioClient


class ClientTests(unittest.TestCase):
    def test_chio_client_initialize_returns_session_and_passes_session_to_callbacks(self) -> None:
        callback_sessions = []

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content.decode("utf-8")) if request.content else None
            if request.method == "POST" and body and body.get("method") == "initialize":
                return httpx.Response(
                    200,
                    headers={
                        "content-type": "application/json",
                        "mcp-session-id": "sess-client-123",
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
                return httpx.Response(
                    202,
                    headers={"content-type": "text/event-stream"},
                    text='data: {"jsonrpc":"2.0","method":"notifications/ping"}\n\n',
                )
            raise AssertionError(f"unexpected request: {request.method} {request.url}")

        client = ChioClient.with_static_bearer(
            "http://testserver",
            "token",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )
        session = client.initialize(
            client_info={"name": "chio-sdk-tests", "version": "1.0.0"},
            on_message=lambda _message, session: callback_sessions.append(session.session_id),
        )

        self.assertEqual(session.session_id, "sess-client-123")
        self.assertIsNotNone(session.handshake)
        self.assertEqual(callback_sessions, ["sess-client-123"])


if __name__ == "__main__":
    unittest.main()
