"""ASGI middleware for Chio protocol evaluation.

Intercepts incoming HTTP requests, extracts caller identity, evaluates the
request against Chio policies via the sidecar, and either forwards or rejects
the request based on the verdict. Works with any ASGI framework (FastAPI,
Starlette, Litestar, etc.).
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any, Callable, Awaitable
from urllib.parse import parse_qsl

from chio_sdk.client import ChioClient
from chio_sdk.errors import ChioConnectionError, ChioError, ChioTimeoutError
from chio_sdk.models import CallerIdentity, HttpReceipt

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

        # Extract caller identity
        caller = self._extractor.extract(scope)

        # Extract route pattern if available (Starlette/FastAPI set this)
        route_pattern = scope.get("path", path)
        if "route" in scope and hasattr(scope["route"], "path"):
            route_pattern = scope["route"].path

        # Read the full request body for hashing before evaluating policy.
        body_chunks: list[bytes] = []
        buffered_messages: list[dict[str, Any]] = []

        while True:
            message = await receive()
            buffered_messages.append(message)
            if message.get("type") == "http.request":
                body = message.get("body", b"")
                if body:
                    body_chunks.append(body)
                if not message.get("more_body", False):
                    break
                continue
            break

        body_hash: str | None = None
        if body_chunks:
            raw_body = b"".join(body_chunks)
            body_hash = hashlib.sha256(raw_body).hexdigest()

        # Replay the buffered body for the inner app.
        replay_index = 0

        async def replay_receive() -> dict[str, Any]:
            nonlocal replay_index
            if replay_index < len(buffered_messages):
                message = buffered_messages[replay_index]
                replay_index += 1
                return message
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
                query=_query_params(scope),
                headers=_selected_headers(scope),
                body_hash=body_hash,
                body_length=len(b"".join(body_chunks)) if body_chunks else 0,
                capability_token=_extract_capability_token(scope),
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


def _extract_capability_token(scope: Scope) -> str | None:
    """Extract the presented Chio capability token from header or query string."""
    headers = {
        k.decode("latin-1").lower(): v.decode("latin-1")
        for k, v in scope.get("headers", [])
    }
    capability_token = headers.get("x-chio-capability")
    if capability_token:
        return capability_token

    qs = scope.get("query_string", b"").decode("latin-1")
    for key, value in parse_qsl(qs, keep_blank_values=True):
        if key == "chio_capability":
            return value
    return None


def _selected_headers(scope: Scope) -> dict[str, str]:
    headers = {
        k.decode("latin-1").lower(): v.decode("latin-1")
        for k, v in scope.get("headers", [])
    }
    selected: dict[str, str] = {}
    for key in ("content-type", "content-length"):
        value = headers.get(key)
        if value is not None:
            selected[key] = value
    return selected


def _query_params(scope: Scope) -> dict[str, str]:
    params: dict[str, str] = {}
    qs = scope.get("query_string", b"").decode("latin-1")
    if not qs:
        return params

    for key, value in parse_qsl(qs, keep_blank_values=True):
        params[key] = value
    return params


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
