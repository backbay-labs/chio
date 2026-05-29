from __future__ import annotations

import json
from typing import Any, Callable
import urllib.request

try:
    import httpx
except ModuleNotFoundError:  # pragma: no cover - exercised by the live peer path
    httpx = None

from .errors import ChioRpcError, ChioTransportError, parse_json_text
from .models import TransportResponse

JsonRpcMessageHandler = Callable[[dict[str, Any]], None]


def parse_rpc_messages(raw_body: str) -> list[dict[str, Any]]:
    trimmed = raw_body.strip()
    if not trimmed:
        return []
    if trimmed.startswith("{"):
        return [parse_json_text(trimmed)]

    messages: list[dict[str, Any]] = []
    buffer: list[str] = []
    for line in raw_body.splitlines():
        if not line.strip():
            if buffer:
                messages.append(parse_json_text("\n".join(buffer)))
                buffer.clear()
            continue
        if line.startswith("data:"):
            buffer.append(line[5:].lstrip())
    if buffer:
        messages.append(parse_json_text("\n".join(buffer)))
    return messages


def build_mcp_headers(
    auth_token: str,
    *,
    session_id: str | None = None,
    protocol_version: str | None = None,
) -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    if session_id:
        headers["MCP-Session-Id"] = session_id
    if protocol_version:
        headers["MCP-Protocol-Version"] = protocol_version
    return headers


def read_rpc_messages_until_terminal(
    response: Any,
    expected_id: int | None,
    on_message: JsonRpcMessageHandler | None = None,
) -> list[dict[str, Any]]:
    if on_message is None:
        on_message = lambda _message: None

    content_type = response.headers.get("content-type", "")
    if content_type.startswith("text/event-stream"):
        messages: list[dict[str, Any]] = []
        buffer: list[str] = []
        if hasattr(response, "iter_lines"):
            for line in response.iter_lines():
                if not line.strip():
                    if buffer:
                        message = parse_json_text("\n".join(buffer))
                        messages.append(message)
                        if expected_id is not None and message.get("id") == expected_id and "method" not in message:
                            return messages
                        on_message(message)
                        buffer.clear()
                    continue
                if line.startswith("data:"):
                    buffer.append(line[5:].lstrip())
        else:
            while True:
                line = response.readline()
                if not line:
                    break
                decoded = line.decode("utf-8")
                trimmed = decoded.rstrip("\r\n")
                if not trimmed:
                    if buffer:
                        message = parse_json_text("\n".join(buffer))
                        messages.append(message)
                        if expected_id is not None and message.get("id") == expected_id and "method" not in message:
                            return messages
                        on_message(message)
                        buffer.clear()
                    continue
                if trimmed.startswith("data:"):
                    buffer.append(trimmed[5:].lstrip())
        if buffer:
            message = parse_json_text("\n".join(buffer))
            messages.append(message)
            on_message(message)
        return messages

    raw_body = response.read()
    if isinstance(raw_body, bytes):
        raw_body = raw_body.decode("utf-8")
    messages = parse_rpc_messages(raw_body)
    for message in messages:
        if expected_id is not None and message.get("id") == expected_id and "method" not in message:
            continue
        on_message(message)
    return messages


def terminal_message(messages: list[dict[str, Any]], expected_id: int) -> dict[str, Any]:
    for message in messages:
        if message.get("id") == expected_id and "method" not in message:
            if "error" in message:
                error = message["error"]
                raise ChioRpcError(
                    error.get("message", f"JSON-RPC error for id {expected_id}"),
                    code=error.get("code"),
                    data=error.get("data"),
                )
            return message
    raise ChioTransportError(f"no terminal response for JSON-RPC id {expected_id}")


def post_envelope(
    *,
    client: Any | None,
    base_url: str,
    auth_token: str,
    body: dict[str, Any],
    session_id: str | None = None,
    protocol_version: str | None = None,
    on_message: JsonRpcMessageHandler | None = None,
) -> TransportResponse:
    headers = build_mcp_headers(
        auth_token,
        session_id=session_id,
        protocol_version=protocol_version,
    )
    if client is not None:
        with client.stream(
            "POST",
            f"{base_url}/mcp",
            headers=headers,
            content=json.dumps(body).encode("utf-8"),
            timeout=5.0,
        ) as response:
            response.raise_for_status()
            messages = read_rpc_messages_until_terminal(response, body.get("id"), on_message)
            return TransportResponse(
                request=body,
                status=response.status_code,
                headers={key.lower(): value for key, value in response.headers.items()},
                messages=messages,
            )

    request = urllib.request.Request(
        f"{base_url}/mcp",
        data=json.dumps(body).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return TransportResponse(
            request=body,
            status=response.status,
            headers={key.lower(): value for key, value in response.headers.items()},
            messages=read_rpc_messages_until_terminal(response, body.get("id"), on_message),
        )


def post_rpc(
    *,
    client: Any | None,
    base_url: str,
    auth_token: str,
    body: dict[str, Any],
    session_id: str | None = None,
    protocol_version: str | None = None,
    on_message: JsonRpcMessageHandler | None = None,
) -> TransportResponse:
    return post_envelope(
        client=client,
        base_url=base_url,
        auth_token=auth_token,
        body=body,
        session_id=session_id,
        protocol_version=protocol_version,
        on_message=on_message,
    )


def post_notification(
    *,
    client: Any | None,
    base_url: str,
    auth_token: str,
    body: dict[str, Any],
    session_id: str,
    protocol_version: str,
    on_message: JsonRpcMessageHandler | None = None,
) -> TransportResponse:
    return post_envelope(
        client=client,
        base_url=base_url,
        auth_token=auth_token,
        body=body,
        session_id=session_id,
        protocol_version=protocol_version,
        on_message=on_message,
    )


def delete_session(
    *,
    client: Any | None,
    base_url: str,
    auth_token: str,
    session_id: str,
) -> int:
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "MCP-Session-Id": session_id,
    }
    if client is not None:
        response = client.delete(
            f"{base_url}/mcp",
            headers=headers,
            timeout=5.0,
        )
        response.raise_for_status()
        return response.status_code

    request = urllib.request.Request(f"{base_url}/mcp", headers=headers, method="DELETE")
    with urllib.request.urlopen(request, timeout=5) as response:
        return response.status
