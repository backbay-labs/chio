from __future__ import annotations

import itertools
from typing import Any

from .errors import ChioTransportError
from .models import SessionHandshake, TransportResponse
from .transport import delete_session, post_notification, post_rpc, terminal_message
from .version import default_client_info


class ChioSession:
    def __init__(
        self,
        *,
        auth_token: str,
        base_url: str,
        session_id: str,
        protocol_version: str,
        client: Any | None = None,
        handshake: SessionHandshake | None = None,
    ):
        self.auth_token = auth_token
        self.base_url = base_url.rstrip("/")
        self.session_id = session_id
        self.protocol_version = protocol_version
        self.handshake = handshake
        self._client = client
        self._next_request_id = itertools.count(1)

    def send_envelope(
        self,
        body: dict[str, Any],
        on_message=None,
    ) -> TransportResponse:
        return post_rpc(
            client=self._client,
            base_url=self.base_url,
            auth_token=self.auth_token,
            body=body,
            session_id=self.session_id,
            protocol_version=self.protocol_version,
            on_message=on_message,
        )

    def request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        on_message=None,
    ) -> TransportResponse:
        request_id = next(self._next_request_id)
        body = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {},
        }
        return self.send_envelope(body, on_message)

    def request_result(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        on_message=None,
    ) -> dict[str, Any]:
        response = self.request(method, params, on_message)
        return terminal_message(response.messages, response.request["id"])

    def notification(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        on_message=None,
    ) -> TransportResponse:
        body = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
        }
        return post_notification(
            client=self._client,
            base_url=self.base_url,
            auth_token=self.auth_token,
            body=body,
            session_id=self.session_id,
            protocol_version=self.protocol_version,
            on_message=on_message,
        )

    def list_tools(self) -> dict[str, Any]:
        return self.request_result("tools/list")

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        return self.request_result(
            "tools/call",
            {"name": name, "arguments": arguments or {}},
        )

    def list_resources(self) -> dict[str, Any]:
        return self.request_result("resources/list")

    def read_resource(self, uri: str) -> dict[str, Any]:
        return self.request_result("resources/read", {"uri": uri})

    def subscribe_resource(self, uri: str) -> dict[str, Any]:
        return self.request_result("resources/subscribe", {"uri": uri})

    def unsubscribe_resource(self, uri: str) -> dict[str, Any]:
        return self.request_result("resources/unsubscribe", {"uri": uri})

    def list_resource_templates(self) -> dict[str, Any]:
        return self.request_result("resources/templates/list")

    def list_prompts(self) -> dict[str, Any]:
        return self.request_result("prompts/list")

    def get_prompt(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        return self.request_result("prompts/get", {"name": name, "arguments": arguments or {}})

    def complete(self, params: dict[str, Any]) -> dict[str, Any]:
        return self.request_result("completion/complete", params)

    def set_log_level(self, level: str) -> dict[str, Any]:
        return self.request_result("logging/setLevel", {"level": level})

    def list_tasks(self) -> dict[str, Any]:
        return self.request_result("tasks/list")

    def get_task(self, task_id: str) -> dict[str, Any]:
        return self.request_result("tasks/get", {"taskId": task_id})

    def get_task_result(self, task_id: str) -> dict[str, Any]:
        return self.request_result("tasks/result", {"taskId": task_id})

    def cancel_task(self, task_id: str) -> dict[str, Any]:
        return self.request_result("tasks/cancel", {"taskId": task_id})

    def close(self) -> int:
        return delete_session(
            client=self._client,
            base_url=self.base_url,
            auth_token=self.auth_token,
            session_id=self.session_id,
        )


def initialize_session(
    *,
    base_url: str,
    auth_token: str,
    capabilities: dict[str, Any] | None = None,
    client_info: dict[str, Any] | None = None,
    protocol_version: str = "2025-11-25",
    client: Any | None = None,
    on_message=None,
) -> ChioSession:
    try:
        initialize_response = post_rpc(
            client=client,
            base_url=base_url.rstrip("/"),
            auth_token=auth_token,
            body={
                "jsonrpc": "2.0",
                "id": 0,
                "method": "initialize",
                "params": {
                    "protocolVersion": protocol_version,
                    "capabilities": capabilities or {},
                    "clientInfo": client_info or default_client_info(),
                },
            },
        )
        session_id = initialize_response.headers.get("mcp-session-id")
        if initialize_response.status != 200 or not session_id:
            raise ChioTransportError("initialize did not return a session id")

        initialize_message = terminal_message(initialize_response.messages, 0)
        negotiated_protocol_version = initialize_message.get("result", {}).get("protocolVersion")
        if not isinstance(negotiated_protocol_version, str):
            raise ChioTransportError("initialize did not negotiate a protocol version")

        session = ChioSession(
            auth_token=auth_token,
            base_url=base_url,
            session_id=session_id,
            protocol_version=negotiated_protocol_version,
            client=client,
            handshake=None,
        )
        initialized_response = session.notification("notifications/initialized", on_message=on_message)
        if initialized_response.status not in (200, 202):
            raise ChioTransportError("notifications/initialized did not succeed")
        session.handshake = SessionHandshake(
            initialize_response=initialize_response,
            initialized_response=initialized_response,
        )
        return session
    except Exception:
        raise
