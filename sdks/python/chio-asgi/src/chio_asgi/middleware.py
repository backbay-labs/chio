"""ASGI middleware for Chio protocol evaluation.

Intercepts incoming HTTP requests, extracts caller identity, evaluates the
request against Chio policies via the sidecar, and either forwards or rejects
the request based on the verdict. Works with any ASGI framework (FastAPI,
Starlette, Litestar, etc.).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any, Awaitable, Callable
from urllib.parse import parse_qsl

from chio_sdk.client import ChioClient
from chio_sdk.errors import ChioConnectionError, ChioError, ChioTimeoutError
from chio_sdk.models import HttpReceipt

from chio_asgi.config import ChioASGIConfig
from chio_asgi.extractors import CompositeExtractor, IdentityExtractor


# ASGI type aliases
Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


class ChioASGIMiddleware:
    """ASGI middleware that evaluates requests through the Chio sidecar.

    Usage with Starlette/FastAPI::

        from chio_asgi import ChioASGIMiddleware, ChioASGIConfig

        app.add_middleware(
            ChioASGIMiddleware,
            config=ChioASGIConfig(sidecar_url="http://127.0.0.1:9090"),
        )

    Usage with Litestar::

        from litestar import Litestar
        from chio_asgi import ChioASGIMiddleware

        app = Litestar(middleware=[ChioASGIMiddleware])

    Parameters
    ----------
    app:
        The inner ASGI application.
    config:
        Chio middleware configuration.
    extractor:
        Custom identity extractor. Defaults to CompositeExtractor which
        tries Bearer, API key, and cookie extraction in order.
    on_receipt:
        Optional async callback invoked with each HttpReceipt for logging
        or audit trail integration.
    """

    def __init__(
        self,
        app: ASGIApp,
        config: ChioASGIConfig | None = None,
        extractor: IdentityExtractor | None = None,
        on_receipt: Callable[[HttpReceipt], Awaitable[None]] | None = None,
    ) -> None:
        self._app = app
        self._config = config or ChioASGIConfig()
        self._extractor = extractor or CompositeExtractor()
        self._on_receipt = on_receipt
        self._client: ChioClient | None = None

    def _get_client(self) -> ChioClient:
        if self._client is None:
            self._client = ChioClient(
                self._config.sidecar_url,
                timeout=self._config.timeout,
            )
        return self._client

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        method = scope.get("method", "GET").upper()
        path = scope.get("path", "/")

        # Bypass excluded methods and paths
        if method in self._config.exclude_methods:
            await self._app(scope, receive, send)
            return
        if path in self._config.exclude_paths:
            await self._app(scope, receive, send)
            return

        try:
            headers = _headers_by_name(scope)
            selected_headers = _selected_headers_from(headers)
            query = _query_params(scope)
            capability_token = _extract_capability_token_from(headers, query)
            advertised_body_length = _content_length_from(headers)
        except ValueError as exc:
            await _send_error_response(send, 400, str(exc), "MalformedRequest")
            return
        if advertised_body_length > self._config.max_body_bytes:
            await _send_body_too_large(send, self._config.max_body_bytes)
            return

        # Extract caller identity after rejecting ambiguous policy inputs.
        caller = self._extractor.extract(scope)

        # Extract route pattern if available (Starlette/FastAPI set this)
        route_pattern = scope.get("path", path)
        if "route" in scope and hasattr(scope["route"], "path"):
            route_pattern = scope["route"].path

        # Read the complete request body for hashing before sidecar evaluation.
        body_chunks: list[bytes] = []
        early_replay_message: dict[str, Any] | None = None
        body_complete = False
        body_interrupted = False
        body_too_large = False
        body_size = 0

        async def receive_wrapper() -> dict[str, Any]:
            nonlocal body_complete, body_interrupted, body_size, body_too_large
            nonlocal early_replay_message
            message = await receive()
            if message.get("type") == "http.request":
                body = message.get("body", b"")
                if body:
                    if body_size + len(body) > self._config.max_body_bytes:
                        body_too_large = True
                        body_complete = True
                        return message
                    body_size += len(body)
                    body_chunks.append(body)
                if not message.get("more_body", False):
                    body_complete = True
            else:
                early_replay_message = message
                body_interrupted = True
                body_complete = True
            return message

        while not body_complete:
            message = await receive_wrapper()
            if message.get("type") != "http.request":
                break
        if body_too_large:
            await _send_body_too_large(send, self._config.max_body_bytes)
            return
        if body_interrupted:
            await _send_error_response(
                send,
                400,
                "request body stream ended before the final body frame",
                "ClientDisconnected",
            )
            return

        raw_body = b"".join(body_chunks)
        body_hash: str | None = None
        if raw_body:
            body_hash = hashlib.sha256(raw_body).hexdigest()

        # Replay a single coalesced request-body frame for the inner app. This
        # preserves the body while bounding replay memory by body bytes rather
        # than by untrusted ASGI frame count.
        replay_step = 0

        async def replay_receive() -> dict[str, Any]:
            nonlocal replay_step
            if replay_step == 0:
                replay_step = 1
                return {
                    "type": "http.request",
                    "body": raw_body,
                    "more_body": False,
                }
            if replay_step == 1 and early_replay_message is not None:
                replay_step = 2
                return early_replay_message
            return await receive()

        # Evaluate via sidecar
        request_id = str(uuid.uuid4())
        try:
            client = self._get_client()
            result = await client.evaluate_http_request(
                request_id=request_id,
                method=method,
                route_pattern=route_pattern,
                path=path,
                caller=caller,
                query=query,
                headers=selected_headers,
                body_hash=body_hash,
                body_length=body_size,
                capability_token=capability_token,
            )
        except (ChioConnectionError, ChioTimeoutError):
            await _send_error_response(
                send, 503, "Chio sidecar unavailable", "SidecarUnavailable"
            )
            return
        except ChioError as exc:
            await _send_error_response(
                send, 502, str(exc), "SidecarError"
            )
            return

        receipt = result.receipt

        # Check verdicts. Anything other than explicit allow from both the
        # response and embedded receipt fails closed.
        if not result.verdict.is_allowed or not receipt.is_allowed:
            status = 403
            if receipt.verdict.http_status is not None:
                status = receipt.verdict.http_status
            await _send_error_response(
                send,
                status,
                receipt.verdict.reason or "denied",
                receipt.verdict.guard or "ChioGuard",
                receipt_id=receipt.id,
                receipt_header=self._config.receipt_header,
            )
            return

        try:
            verification = await client.verify_http_receipt(receipt)
        except (ChioConnectionError, ChioTimeoutError, ChioError):
            verification = None
        if verification is None or not verification.authorizes(receipt):
            await _send_error_response(
                send,
                502,
                "Chio sidecar returned an unverified receipt",
                "InvalidReceipt",
                receipt_id=receipt.id,
                receipt_header=self._config.receipt_header,
            )
            return

        # Fire receipt callback only after the authorizing receipt verifies.
        if self._on_receipt is not None:
            await self._on_receipt(receipt)

        # Allowed -- forward with receipt header
        receipt_header_name = self._config.receipt_header.lower().encode("latin-1")
        receipt_id_bytes = receipt.id.encode("latin-1")

        async def send_with_receipt(message: dict[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                headers = list(message.get("headers", []))
                headers.append((receipt_header_name, receipt_id_bytes))
                message = {**message, "headers": headers}
            await send(message)

        await self._app(scope, replay_receive, send_with_receipt)


_POLICY_SINGLETON_HEADERS = frozenset({
    "authorization",
    "content-length",
    "content-type",
    "x-api-key",
    "x-chio-capability",
})


def _headers_by_name(scope: Scope) -> dict[str, str]:
    headers: dict[str, str] = {}
    seen: set[str] = set()
    for raw_name, raw_value in scope.get("headers", []):
        name = raw_name.decode("latin-1").lower()
        value = raw_value.decode("latin-1")
        if name == "cookie" and name in headers:
            headers[name] = f"{headers[name]}; {value}"
            seen.add(name)
            continue
        if name in seen and name in _POLICY_SINGLETON_HEADERS:
            raise ValueError(f"duplicate policy header: {name}")
        seen.add(name)
        headers[name] = value
    return headers


def _extract_capability_token(scope: Scope) -> str | None:
    """Extract the presented Chio capability token from header or query string."""
    headers = _headers_by_name(scope)
    query = _query_params(scope)
    return _extract_capability_token_from(headers, query)


def _extract_capability_token_from(
    headers: dict[str, str],
    query: dict[str, str],
) -> str | None:
    capability_token = headers.get("x-chio-capability")
    if capability_token:
        return capability_token

    return query.get("chio_capability")


def _selected_headers(scope: Scope) -> dict[str, str]:
    return _selected_headers_from(_headers_by_name(scope))


def _selected_headers_from(headers: dict[str, str]) -> dict[str, str]:
    selected: dict[str, str] = {}
    for key in ("content-type", "content-length"):
        value = headers.get(key)
        if value is not None:
            selected[key] = value
    return selected


def _content_length_from(headers: dict[str, str]) -> int:
    value = headers.get("content-length")
    if value is None:
        return 0
    try:
        content_length = int(value)
    except ValueError:
        raise ValueError("invalid content-length header") from None
    if content_length < 0:
        raise ValueError("invalid content-length header")
    return content_length


def _query_params(scope: Scope) -> dict[str, str]:
    params: dict[str, str] = {}
    qs = scope.get("query_string", b"").decode("latin-1")
    if not qs:
        return params

    for key, value in parse_qsl(qs, keep_blank_values=True):
        if key in params:
            raise ValueError(f"duplicate query parameter: {key}")
        params[key] = value
    return params


async def _send_body_too_large(send: Send, max_body_bytes: int) -> None:
    await _send_error_response(
        send,
        413,
        f"request body exceeds {max_body_bytes}-byte limit",
        "PayloadTooLarge",
    )


async def _send_error_response(
    send: Send,
    status: int,
    message: str,
    code: str,
    *,
    receipt_id: str | None = None,
    receipt_header: str = "X-Chio-Receipt",
) -> None:
    """Send a JSON error response."""
    body = json.dumps({
        "error": code,
        "message": message,
        "status": status,
    }).encode("utf-8")

    headers: list[tuple[bytes, bytes]] = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode("latin-1")),
    ]
    if receipt_id is not None:
        headers.append(
            (receipt_header.lower().encode("latin-1"), receipt_id.encode("latin-1"))
        )

    await send({
        "type": "http.response.start",
        "status": status,
        "headers": headers,
    })
    await send({
        "type": "http.response.body",
        "body": body,
    })
