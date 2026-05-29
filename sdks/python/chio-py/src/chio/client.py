from __future__ import annotations

from typing import Any, Callable

from .models import SessionHandshake
from .session import ChioSession
from .transport import post_rpc, terminal_message
from .version import default_client_info

ChioMessageHandler = Callable[[dict[str, Any], ChioSession], None]


class ChioClient:
    def __init__(
        self,
        *,
        base_url: str,
        auth_token: str,
        client: Any | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.auth_token = auth_token
        self._client = client

    @classmethod
    def with_static_bearer(
        cls,
        base_url: str,
        auth_token: str,
        client: Any | None = None,
    ) -> "ChioClient":
        return cls(base_url=base_url, auth_token=auth_token, client=client)

    def initialize(
        self,
        *,
        capabilities: dict[str, Any] | None = None,
        client_info: dict[str, Any] | None = None,
        on_message: ChioMessageHandler | None = None,
        protocol_version: str = "2025-11-25",
    ) -> ChioSession:
        initialize_response = post_rpc(
            client=self._client,
            base_url=self.base_url,
            auth_token=self.auth_token,
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
            raise RuntimeError("initialize did not return a session id")

        initialize_message = terminal_message(initialize_response.messages, 0)
        negotiated_protocol_version = initialize_message.get("result", {}).get("protocolVersion")
        if not isinstance(negotiated_protocol_version, str):
            raise RuntimeError("initialize did not negotiate a protocol version")

        session = ChioSession(
            auth_token=self.auth_token,
            base_url=self.base_url,
            session_id=session_id,
            protocol_version=negotiated_protocol_version,
            client=self._client,
            handshake=None,
        )
        callback = None
        if on_message is not None:
            callback = lambda message: on_message(message, session)
        initialized_response = session.notification(
            "notifications/initialized",
            on_message=callback,
        )
        if initialized_response.status not in (200, 202):
            raise RuntimeError("notifications/initialized did not succeed")

        session.handshake = SessionHandshake(
            initialize_response=initialize_response,
            initialized_response=initialized_response,
        )
        return session
