"""Tests for chio-django middleware."""

from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

from django.http import JsonResponse
from django.test import RequestFactory, TestCase, override_settings

from chio_django.middleware import ChioDjangoMiddleware, _extract_caller


def _allow_http_receipt(receipt_id: str) -> dict:
    return {
        "id": receipt_id,
        "request_id": "req-1",
        "route_pattern": "/protected",
        "method": "GET",
        "caller_identity_hash": "a" * 64,
        "verdict": {"verdict": "allow"},
        "receipt_kind": "mediated_decision",
        "boundary_class": "prevent",
        "tool_origin": "caller_executed",
        "redaction_mode": "none",
        "trust_level": "mediated",
        "evidence": [],
        "response_status": 200,
        "timestamp": 1_700_000_000,
        "content_hash": "b" * 64,
        "policy_hash": "c" * 64,
        "kernel_key": "d" * 64,
        "signature": "e" * 128,
    }


def _verify_report(authorized: bool) -> dict:
    return {
        "signature_valid": authorized,
        "signer_trusted": authorized,
        "receipt_id_valid": authorized,
        "parameter_hash_valid": authorized,
        "receipt_kind": "mediated_decision",
        "boundary_class": "prevent",
        "trust_level": "mediated",
        "result": "allow" if authorized else "deny",
        "authorized": authorized,
        "signer_key_hex": "d" * 64,
        "ok": authorized,
    }


class TestExtractCaller:
    def test_bearer_token(self) -> None:
        factory = RequestFactory()
        request = factory.get("/test", HTTP_AUTHORIZATION="Bearer my-token")
        caller = _extract_caller(request)
        assert caller.auth_method.method == "bearer"
        assert caller.auth_method.token_hash is not None

    def test_api_key(self) -> None:
        factory = RequestFactory()
        request = factory.get("/test", HTTP_X_API_KEY="key-123")
        caller = _extract_caller(request)
        assert caller.auth_method.method == "api_key"

    def test_session_cookie(self) -> None:
        factory = RequestFactory()
        request = factory.get("/test")
        request.COOKIES["session"] = "sess-abc"
        caller = _extract_caller(request)
        assert caller.auth_method.method == "cookie"

    def test_anonymous(self) -> None:
        factory = RequestFactory()
        request = factory.get("/test")
        caller = _extract_caller(request)
        assert caller.auth_method.method == "anonymous"
        assert caller.subject == "anonymous"


class TestMiddlewareExclusions(TestCase):
    def _get_middleware(self) -> ChioDjangoMiddleware:
        def get_response(request):
            return JsonResponse({"status": "ok"})
        return ChioDjangoMiddleware(get_response)

    def test_options_excluded(self) -> None:
        mw = self._get_middleware()
        factory = RequestFactory()
        request = factory.options("/test")
        response = mw(request)
        assert response.status_code == 200

    @override_settings(CHIO_EXCLUDE_PATHS=["/health"])
    def test_excluded_path(self) -> None:
        mw = self._get_middleware()
        factory = RequestFactory()
        request = factory.get("/health")
        response = mw(request)
        assert response.status_code == 200


class TestMiddlewareAllowed(TestCase):
    @patch("chio_django.middleware.httpx.post")
    def test_allowed_request(self, mock_post: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "verdict": {"verdict": "allow"},
            "receipt": _allow_http_receipt("receipt-1"),
        }
        verify_resp = MagicMock()
        verify_resp.status_code = 200
        verify_resp.json.return_value = _verify_report(True)
        mock_post.side_effect = [mock_resp, verify_resp]

        def get_response(request):
            return JsonResponse({"status": "ok"})

        mw = ChioDjangoMiddleware(get_response)
        factory = RequestFactory()
        request = factory.get("/protected")
        response = mw(request)

        assert response.status_code == 200
        assert response["X-Chio-Receipt"] == "receipt-1"
        assert mock_post.call_count == 2


class TestMiddlewareDenied(TestCase):
    @patch("chio_django.middleware.httpx.post")
    def test_denied_request(self, mock_post: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "verdict": {
                "verdict": "deny",
                "reason": "no capability",
                "guard": "CapGuard",
                "http_status": 403,
            },
            "receipt": {
                "id": "receipt-2",
                "verdict": {
                    "verdict": "deny",
                    "reason": "no capability",
                    "guard": "CapGuard",
                    "http_status": 403,
                },
            },
        }
        mock_post.return_value = mock_resp

        def get_response(request):
            return JsonResponse({"status": "ok"})

        mw = ChioDjangoMiddleware(get_response)
        factory = RequestFactory()
        request = factory.get("/protected")
        response = mw(request)

        assert response.status_code == 403
        body = json.loads(response.content)
        assert body["error"]["code"] == "CHIO_GUARD_DENIED"


class TestMiddlewareSidecarDown(TestCase):
    @patch("chio_django.middleware.httpx.post")
    def test_fail_closed(self, mock_post: MagicMock) -> None:
        import httpx
        mock_post.side_effect = httpx.ConnectError("connection refused")

        def get_response(request):
            return JsonResponse({"status": "ok"})

        mw = ChioDjangoMiddleware(get_response)
        factory = RequestFactory()
        request = factory.get("/protected")
        response = mw(request)

        assert response.status_code == 503

    @patch("chio_django.middleware.httpx.post")
    def test_fail_open_setting_still_fails_closed_when_sidecar_unavailable(
        self, mock_post: MagicMock
    ) -> None:
        import httpx
        mock_post.side_effect = httpx.ConnectError("connection refused")

        def get_response(request):
            return JsonResponse({"status": "ok"})

        with override_settings(CHIO_FAIL_OPEN=True):
            mw = ChioDjangoMiddleware(get_response)
            factory = RequestFactory()
            request = factory.get("/protected")
            response = mw(request)

        assert response.status_code == 503
        body = json.loads(response.content)
        assert body["error"]["code"] == "CHIO_SIDECAR_UNAVAILABLE"

class TestMiddlewareReceiptVerification(TestCase):
    @patch("chio_django.middleware.httpx.post")
    def test_legacy_valid_true_fails_closed(self, mock_post: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "verdict": {"verdict": "allow"},
            "receipt": _allow_http_receipt("receipt-legacy-valid"),
        }
        verify_resp = MagicMock()
        verify_resp.status_code = 200
        verify_resp.json.return_value = {"valid": True}
        mock_post.side_effect = [mock_resp, verify_resp]

        def get_response(request):
            return JsonResponse({"status": "ok"})

        mw = ChioDjangoMiddleware(get_response)
        factory = RequestFactory()
        request = factory.get("/protected")
        response = mw(request)

        assert response.status_code == 502
        body = json.loads(response.content)
        assert body["error"]["code"] == "CHIO_INVALID_RECEIPT"

    @patch("chio_django.middleware.httpx.post")
    def test_unverified_allow_fails_closed(self, mock_post: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "verdict": {"verdict": "allow"},
            "receipt": _allow_http_receipt("receipt-3"),
        }
        verify_resp = MagicMock()
        verify_resp.status_code = 200
        verify_resp.json.return_value = _verify_report(False)
        mock_post.side_effect = [mock_resp, verify_resp]

        def get_response(request):
            return JsonResponse({"status": "ok"})

        mw = ChioDjangoMiddleware(get_response)
        factory = RequestFactory()
        request = factory.get("/protected")
        response = mw(request)

        assert response.status_code == 502
        body = json.loads(response.content)
        assert body["error"]["code"] == "CHIO_INVALID_RECEIPT"

    @patch("chio_django.middleware.httpx.post")
    def test_incomplete_fails_closed(self, mock_post: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "verdict": {
                "verdict": "incomplete",
                "reason": "sidecar timeout",
                "http_status": 503,
            },
            "receipt": {
                "id": "receipt-4",
                "verdict": {
                    "verdict": "incomplete",
                    "reason": "sidecar timeout",
                },
            },
        }
        mock_post.return_value = mock_resp

        def get_response(request):
            return JsonResponse({"status": "ok"})

        mw = ChioDjangoMiddleware(get_response)
        factory = RequestFactory()
        request = factory.get("/protected")
        response = mw(request)

        assert response.status_code == 503
        assert mock_post.call_count == 1


class TestMiddlewareBadSidecarResponse(TestCase):
    @patch("chio_django.middleware.httpx.post")
    def test_sidecar_500(self, mock_post: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_post.return_value = mock_resp

        def get_response(request):
            return JsonResponse({"status": "ok"})

        mw = ChioDjangoMiddleware(get_response)
        factory = RequestFactory()
        request = factory.get("/protected")
        response = mw(request)

        assert response.status_code == 502
        body = json.loads(response.content)
        assert body["error"]["code"] == "CHIO_INTERNAL_ERROR"

    @patch("chio_django.middleware.httpx.post")
    def test_malformed_sidecar_json_fails_closed(self, mock_post: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("bad json")
        mock_post.return_value = mock_resp
        reached_view = False

        def get_response(request):
            nonlocal reached_view
            reached_view = True
            return JsonResponse({"status": "ok"})

        mw = ChioDjangoMiddleware(get_response)
        factory = RequestFactory()
        request = factory.get("/protected")
        response = mw(request)

        assert response.status_code == 502
        body = json.loads(response.content)
        assert body["error"]["code"] == "CHIO_INTERNAL_ERROR"
        assert reached_view is False


class TestErrors:
    def test_all_error_codes(self) -> None:
        from chio_django.errors import ChioErrorCode, chio_error_response

        for code in ChioErrorCode:
            resp = chio_error_response(400, code, "test")
            body = json.loads(resp.content)
            assert body["error"]["code"] == code.value
