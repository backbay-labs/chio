"""Tests for Chio ASGI middleware."""

from __future__ import annotations

import json
import hashlib
from typing import Any, Awaitable, Callable
from unittest.mock import AsyncMock, patch

from chio_asgi.config import ChioASGIConfig
from chio_asgi.middleware import (
    ChioASGIMiddleware,
    _extract_capability_token,
    _query_params,
)
from chio_sdk.errors import ChioConnectionError
from chio_sdk.models import (
    EvaluateResponse,
    HttpReceipt,
    Verdict,
    VerifyReceiptResponse,
)


# ---------------------------------------------------------------------------
# ASGI type helpers
# ---------------------------------------------------------------------------

Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]


def _make_scope(
    method: str = "GET",
    path: str = "/test",
    headers: dict[str, str] | None = None,
    query_string: str = "",
) -> Scope:
    raw_headers: list[tuple[bytes, bytes]] = []
    if headers:
        for k, v in headers.items():
            raw_headers.append(
                (k.lower().encode("latin-1"), v.encode("latin-1"))
            )
    return {
        "type": "http",
        "method": method,
        "path": path,
        "headers": raw_headers,
        "query_string": query_string.encode("latin-1"),
    }


def _make_receive(body: bytes = b"") -> Receive:
    """Create a mock ASGI receive callable."""
    sent = False

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    return receive


def _make_chunked_receive(chunks: list[bytes]) -> Receive:
    messages = [
        {
            "type": "http.request",
            "body": chunk,
            "more_body": index < len(chunks) - 1,
        }
        for index, chunk in enumerate(chunks)
    ]
    if not messages:
        messages.append({"type": "http.request", "body": b"", "more_body": False})

    async def receive() -> dict[str, Any]:
        if messages:
            return messages.pop(0)
        return {"type": "http.disconnect"}

    return receive


def _make_interrupted_body_receive(body: bytes = b"partial") -> Receive:
    messages = [
        {"type": "http.request", "body": body, "more_body": True},
        {"type": "http.disconnect"},
    ]

    async def receive() -> dict[str, Any]:
        if messages:
            return messages.pop(0)
        return {"type": "http.disconnect"}

    return receive


def _make_send() -> tuple[Send, list[dict[str, Any]]]:
    """Create a mock ASGI send callable that records messages."""
    messages: list[dict[str, Any]] = []

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    return send, messages


def _make_receipt(
    allowed: bool = True,
    receipt_id: str = "receipt-1",
) -> HttpReceipt:
    verdict = (
        Verdict.allow()
        if allowed
        else Verdict.deny("blocked", "TestGuard", 403)
    )
    return HttpReceipt(
        id=receipt_id,
        request_id="req-1",
        route_pattern="/test",
        method="GET",
        caller_identity_hash="abc",
        verdict=verdict,
        receipt_kind="mediated_decision",
        boundary_class="prevent",
        observation_outcome=None,
        tool_origin="caller_executed",
        redaction_mode="none",
        response_status=200 if allowed else 403,
        timestamp=1700000000,
        content_hash="x",
        policy_hash="y",
        trust_level="mediated",
        kernel_key="k",
        signature="s",
    )


def _make_evaluation(
    allowed: bool = True,
    receipt_id: str = "receipt-1",
) -> EvaluateResponse:
    receipt = _make_receipt(allowed=allowed, receipt_id=receipt_id)
    return EvaluateResponse(
        verdict=receipt.verdict,
        receipt=receipt,
        evidence=[],
    )


def _make_verification(authorized: bool = True) -> VerifyReceiptResponse:
    return VerifyReceiptResponse(
        signature_valid=authorized,
        signer_trusted=authorized,
        receipt_id_valid=authorized,
        parameter_hash_valid=authorized,
        receipt_kind="mediated_decision",
        boundary_class="prevent",
        trust_level="mediated",
        result="allow" if authorized else "deny",
        authorized=authorized,
        signer_key_hex="kernel-key",
        ok=authorized,
    )


async def _echo_app(scope: Scope, receive: Receive, send: Send) -> None:
    """Simple ASGI app that returns 200 OK."""
    await send({
        "type": "http.response.start",
        "status": 200,
        "headers": [(b"content-type", b"text/plain")],
    })
    await send({
        "type": "http.response.body",
        "body": b"ok",
    })


async def _body_echo_app(scope: Scope, receive: Receive, send: Send) -> None:
    chunks: list[bytes] = []
    while True:
        message = await receive()
        if message.get("type") != "http.request":
            break
        chunks.append(message.get("body", b""))
        if not message.get("more_body", False):
            break
    body = b"".join(chunks)
    await send({
        "type": "http.response.start",
        "status": 200,
        "headers": [(b"content-length", str(len(body)).encode("latin-1"))],
    })
    await send({"type": "http.response.body", "body": body})


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestExcludePaths:
    async def test_excluded_path_bypasses_evaluation(self) -> None:
        config = ChioASGIConfig(exclude_paths=frozenset({"/health"}))
        mw = ChioASGIMiddleware(_echo_app, config=config)

        scope = _make_scope(path="/health")
        send, messages = _make_send()
        await mw(scope, _make_receive(), send)

        assert any(m.get("status") == 200 for m in messages)


class TestExcludeMethods:
    async def test_options_excluded_by_default(self) -> None:
        mw = ChioASGIMiddleware(_echo_app)
        scope = _make_scope(method="OPTIONS")
        send, messages = _make_send()
        await mw(scope, _make_receive(), send)

        assert any(m.get("status") == 200 for m in messages)


class TestNonHttpScope:
    async def test_websocket_passthrough(self) -> None:
        called = False

        async def ws_app(scope: Scope, receive: Receive, send: Send) -> None:
            nonlocal called
            called = True

        mw = ChioASGIMiddleware(ws_app)
        scope = {"type": "websocket", "path": "/ws"}
        await mw(scope, _make_receive(), _make_send()[0])
        assert called


class TestAllowedRequest:
    async def test_forwards_on_allow(self) -> None:
        evaluation = _make_evaluation(allowed=True, receipt_id="r-allow")

        with patch(
            "chio_asgi.middleware.ChioClient", autospec=True
        ) as MockClient:
            instance = MockClient.return_value
            instance.evaluate_http_request = AsyncMock(return_value=evaluation)
            instance.verify_http_receipt = AsyncMock(return_value=_make_verification())

            config = ChioASGIConfig(sidecar_url="http://mock:9090")
            mw = ChioASGIMiddleware(_echo_app, config=config)

            scope = _make_scope()
            send, messages = _make_send()
            await mw(scope, _make_receive(), send)

            # Should get 200 from echo app
            start_msg = next(
                m for m in messages if m.get("type") == "http.response.start"
            )
            assert start_msg["status"] == 200

            # Should include receipt header
            header_dict = dict(start_msg.get("headers", []))
            assert b"x-chio-receipt" in header_dict
            assert header_dict[b"x-chio-receipt"] == b"r-allow"

    async def test_accepts_split_cookie_headers_for_cookie_identity(self) -> None:
        evaluation = _make_evaluation(allowed=True, receipt_id="r-cookie")

        with patch(
            "chio_asgi.middleware.ChioClient", autospec=True
        ) as MockClient:
            instance = MockClient.return_value
            instance.evaluate_http_request = AsyncMock(return_value=evaluation)
            instance.verify_http_receipt = AsyncMock(return_value=_make_verification())

            config = ChioASGIConfig(sidecar_url="http://mock:9090")
            mw = ChioASGIMiddleware(_echo_app, config=config)
            scope = _make_scope()
            scope["headers"] = [
                (b"cookie", b"session=abc123"),
                (b"cookie", b"other=xyz"),
            ]
            send, messages = _make_send()

            await mw(scope, _make_receive(), send)

            start_msg = next(
                m for m in messages if m.get("type") == "http.response.start"
            )
            assert start_msg["status"] == 200
            kwargs = instance.evaluate_http_request.await_args.kwargs
            assert kwargs["caller"].auth_method.method == "cookie"

    async def test_hashes_and_replays_full_chunked_body(self) -> None:
        evaluation = _make_evaluation(allowed=True, receipt_id="r-chunked")
        chunks = [b"hello ", b"chunked ", b"world"]
        expected_body = b"".join(chunks)

        with patch(
            "chio_asgi.middleware.ChioClient", autospec=True
        ) as MockClient:
            instance = MockClient.return_value
            instance.evaluate_http_request = AsyncMock(return_value=evaluation)
            instance.verify_http_receipt = AsyncMock(return_value=_make_verification())

            config = ChioASGIConfig(sidecar_url="http://mock:9090")
            mw = ChioASGIMiddleware(_body_echo_app, config=config)

            scope = _make_scope(method="POST")
            send, messages = _make_send()
            await mw(scope, _make_chunked_receive(chunks), send)

            instance.evaluate_http_request.assert_awaited_once()
            kwargs = instance.evaluate_http_request.await_args.kwargs
            assert kwargs["body_length"] == len(expected_body)
            assert kwargs["body_hash"] == hashlib.sha256(expected_body).hexdigest()

            body_msg = next(
                m for m in messages if m.get("type") == "http.response.body"
            )
            assert body_msg["body"] == expected_body

    async def test_coalesces_many_chunked_request_frames_for_replay(self) -> None:
        evaluation = _make_evaluation(allowed=True, receipt_id="r-chunked")
        chunks = [b"x"] * 256
        expected_body = b"".join(chunks)
        replayed_messages: list[dict[str, Any]] = []

        async def frame_count_app(
            _scope: Scope,
            receive: Receive,
            send: Send,
        ) -> None:
            while True:
                message = await receive()
                if message.get("type") != "http.request":
                    break
                replayed_messages.append(message)
                if not message.get("more_body", False):
                    break
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        with patch(
            "chio_asgi.middleware.ChioClient", autospec=True
        ) as MockClient:
            instance = MockClient.return_value
            instance.evaluate_http_request = AsyncMock(return_value=evaluation)
            instance.verify_http_receipt = AsyncMock(return_value=_make_verification())

            config = ChioASGIConfig(sidecar_url="http://mock:9090")
            mw = ChioASGIMiddleware(frame_count_app, config=config)

            scope = _make_scope(method="POST")
            send, _messages = _make_send()
            await mw(scope, _make_chunked_receive(chunks), send)

        assert replayed_messages == [
            {
                "type": "http.request",
                "body": expected_body,
                "more_body": False,
            }
        ]

    async def test_rejects_partial_body_before_disconnect(self) -> None:
        with patch(
            "chio_asgi.middleware.ChioClient", autospec=True
        ) as MockClient:
            config = ChioASGIConfig(sidecar_url="http://mock:9090")
            mw = ChioASGIMiddleware(_body_echo_app, config=config)
            scope = _make_scope(method="POST")
            send, messages = _make_send()

            await mw(scope, _make_interrupted_body_receive(), send)

            MockClient.return_value.evaluate_http_request.assert_not_called()
            start_msg = next(
                m for m in messages if m.get("type") == "http.response.start"
            )
            assert start_msg["status"] == 400
            body_msg = next(
                m for m in messages if m.get("type") == "http.response.body"
            )
            body = json.loads(body_msg["body"])
            assert body["error"] == "ClientDisconnected"

    async def test_rejects_chunked_body_that_exceeds_configured_limit(self) -> None:
        with patch(
            "chio_asgi.middleware.ChioClient", autospec=True
        ) as MockClient:
            config = ChioASGIConfig(
                sidecar_url="http://mock:9090",
                max_body_bytes=4,
            )
            mw = ChioASGIMiddleware(_body_echo_app, config=config)
            scope = _make_scope(method="POST")
            send, messages = _make_send()

            await mw(scope, _make_chunked_receive([b"ab", b"cde"]), send)

            MockClient.return_value.evaluate_http_request.assert_not_called()
            start_msg = next(
                m for m in messages if m.get("type") == "http.response.start"
            )
            assert start_msg["status"] == 413
            body_msg = next(
                m for m in messages if m.get("type") == "http.response.body"
            )
            body = json.loads(body_msg["body"])
            assert body["error"] == "PayloadTooLarge"

    async def test_rejects_duplicate_policy_headers_before_evaluation(self) -> None:
        with patch(
            "chio_asgi.middleware.ChioClient", autospec=True
        ) as MockClient:
            scope = _make_scope()
            scope["headers"] = [
                (b"content-type", b"application/json"),
                (b"Content-Type", b"text/plain"),
            ]
            mw = ChioASGIMiddleware(_echo_app)
            send, messages = _make_send()

            await mw(scope, _make_receive(), send)

            MockClient.return_value.evaluate_http_request.assert_not_called()
            start_msg = next(
                m for m in messages if m.get("type") == "http.response.start"
            )
            assert start_msg["status"] == 400

    async def test_rejects_duplicate_query_parameters_before_evaluation(self) -> None:
        with patch(
            "chio_asgi.middleware.ChioClient", autospec=True
        ) as MockClient:
            scope = _make_scope(query_string="tenant=a&tenant=b")
            mw = ChioASGIMiddleware(_echo_app)
            send, messages = _make_send()

            await mw(scope, _make_receive(), send)

            MockClient.return_value.evaluate_http_request.assert_not_called()
            start_msg = next(
                m for m in messages if m.get("type") == "http.response.start"
            )
            assert start_msg["status"] == 400


class TestDeniedRequest:
    async def test_returns_error_on_deny(self) -> None:
        evaluation = _make_evaluation(allowed=False, receipt_id="r-deny")

        with patch(
            "chio_asgi.middleware.ChioClient", autospec=True
        ) as MockClient:
            instance = MockClient.return_value
            instance.evaluate_http_request = AsyncMock(return_value=evaluation)
            instance.verify_http_receipt = AsyncMock(return_value=_make_verification())

            config = ChioASGIConfig(sidecar_url="http://mock:9090")
            mw = ChioASGIMiddleware(_echo_app, config=config)

            scope = _make_scope()
            send, messages = _make_send()
            await mw(scope, _make_receive(), send)

            start_msg = next(
                m for m in messages if m.get("type") == "http.response.start"
            )
            assert start_msg["status"] == 403

            body_msg = next(
                m for m in messages if m.get("type") == "http.response.body"
            )
            body = json.loads(body_msg["body"])
            assert body["error"] == "TestGuard"


class TestSidecarUnavailable:
    async def test_fail_closed_by_default(self) -> None:
        with patch(
            "chio_asgi.middleware.ChioClient", autospec=True
        ) as MockClient:
            instance = MockClient.return_value
            instance.evaluate_http_request = AsyncMock(
                side_effect=ChioConnectionError("connection refused")
            )

            config = ChioASGIConfig(sidecar_url="http://mock:9090")
            mw = ChioASGIMiddleware(_echo_app, config=config)

            scope = _make_scope()
            send, messages = _make_send()
            await mw(scope, _make_receive(), send)

            start_msg = next(
                m for m in messages if m.get("type") == "http.response.start"
            )
            assert start_msg["status"] == 503


class TestReceiptCallback:
    async def test_on_receipt_called(self) -> None:
        evaluation = _make_evaluation(allowed=True)
        callback = AsyncMock()

        with patch(
            "chio_asgi.middleware.ChioClient", autospec=True
        ) as MockClient:
            instance = MockClient.return_value
            instance.evaluate_http_request = AsyncMock(return_value=evaluation)
            instance.verify_http_receipt = AsyncMock(return_value=_make_verification())

            config = ChioASGIConfig(sidecar_url="http://mock:9090")
            mw = ChioASGIMiddleware(
                _echo_app, config=config, on_receipt=callback
            )

            scope = _make_scope()
            send, _ = _make_send()
            await mw(scope, _make_receive(), send)

            callback.assert_awaited_once_with(evaluation.receipt)


class TestReceiptVerification:
    async def test_unverified_allow_fails_closed(self) -> None:
        evaluation = _make_evaluation(allowed=True, receipt_id="r-unverified")

        with patch(
            "chio_asgi.middleware.ChioClient", autospec=True
        ) as MockClient:
            instance = MockClient.return_value
            instance.evaluate_http_request = AsyncMock(return_value=evaluation)
            instance.verify_http_receipt = AsyncMock(
                return_value=_make_verification(False)
            )

            config = ChioASGIConfig(sidecar_url="http://mock:9090")
            mw = ChioASGIMiddleware(_echo_app, config=config)

            scope = _make_scope()
            send, messages = _make_send()
            await mw(scope, _make_receive(), send)

            start_msg = next(
                m for m in messages if m.get("type") == "http.response.start"
            )
            assert start_msg["status"] == 502
            header_dict = dict(start_msg.get("headers", []))
            assert b"x-chio-receipt" in header_dict


class TestCapabilityIdExtraction:
    def test_from_header(self) -> None:
        scope = _make_scope(headers={"x-chio-capability": "cap-123"})
        assert _extract_capability_token(scope) == "cap-123"

    def test_from_query_string(self) -> None:
        scope = _make_scope(query_string="chio_capability=cap-456&other=val")
        assert _extract_capability_token(scope) == "cap-456"

    def test_from_query_string_decodes_url_encoding(self) -> None:
        scope = _make_scope(query_string="chio_capability=cap%2B456%2Fwith%3Dpadding")
        assert _extract_capability_token(scope) == "cap+456/with=padding"

    def test_query_params_decode_keys_and_values(self) -> None:
        scope = _make_scope(query_string="tag=a+b&scope%2Fname=files%2Fread")
        assert _query_params(scope) == {
            "tag": "a b",
            "scope/name": "files/read",
        }

    def test_none_when_missing(self) -> None:
        scope = _make_scope()
        assert _extract_capability_token(scope) is None

    def test_header_takes_precedence(self) -> None:
        scope = _make_scope(
            headers={"x-chio-capability": "cap-header"},
            query_string="chio_capability=cap-query",
        )
        assert _extract_capability_token(scope) == "cap-header"


class TestConfig:
    def test_defaults(self) -> None:
        config = ChioASGIConfig()
        assert config.sidecar_url == "http://127.0.0.1:9090"
        assert "OPTIONS" in config.exclude_methods
        assert config.receipt_header == "X-Chio-Receipt"
        assert config.fail_open is False
        assert config.max_body_bytes == 8 * 1024 * 1024

    def test_custom(self) -> None:
        config = ChioASGIConfig(
            sidecar_url="http://localhost:9999",
            exclude_paths=frozenset({"/healthz", "/ready"}),
        )
        assert "/healthz" in config.exclude_paths

    def test_positional_fail_open_precedes_max_body_bytes(self) -> None:
        config = ChioASGIConfig(
            "http://mock:9090",
            2.5,
            frozenset({"/health"}),
            frozenset({"OPTIONS"}),
            "X-Test-Receipt",
            True,
            10 * 1024 * 1024,
        )

        assert config.fail_open is True
        assert config.max_body_bytes == 10 * 1024 * 1024
