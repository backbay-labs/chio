"""Django WSGI middleware for Chio protocol evaluation.

Intercepts incoming Django requests, extracts caller identity, and evaluates
the request against Chio policies via the sidecar. Uses synchronous httpx
since Django WSGI middleware runs synchronously.

Usage in settings.py::

    MIDDLEWARE = [
        ...
        "chio_django.ChioDjangoMiddleware",
        ...
    ]

    CHIO_SIDECAR_URL = "http://127.0.0.1:9090"
    CHIO_EXCLUDE_PATHS = ["/health", "/ready"]
    CHIO_EXCLUDE_METHODS = ["OPTIONS"]
    CHIO_RECEIPT_HEADER = "X-Chio-Receipt"
"""

from __future__ import annotations

import hashlib
import time
import uuid
from typing import Any, Callable

import httpx
from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse
from chio_sdk.models import HttpReceipt, VerifyReceiptResponse

from chio_sdk.models import AuthMethod, CallerIdentity, CapabilityToken


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _capability_id_from_token(raw_token: str | None) -> str | None:
    if raw_token is None:
        return None
    try:
        return CapabilityToken.model_validate_json(raw_token).id
    except Exception:
        return None


def _extract_caller(request: HttpRequest) -> CallerIdentity:
    """Extract caller identity from a Django HttpRequest."""
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if token:
            token_hash = _sha256_hex(token)
            return CallerIdentity(
                subject=token_hash,
                auth_method=AuthMethod.bearer(token_hash=token_hash),
                verified=False,
            )

    api_key = request.headers.get("X-API-Key", "")
    if api_key:
        key_hash = _sha256_hex(api_key)
        return CallerIdentity(
            subject=key_hash,
            auth_method=AuthMethod.api_key(key_name="x-api-key", key_hash=key_hash),
            verified=False,
        )

    session_cookie = request.COOKIES.get("session", "")
    if session_cookie:
        cookie_hash = _sha256_hex(session_cookie)
        return CallerIdentity(
            subject=cookie_hash,
            auth_method=AuthMethod.cookie(
                cookie_name="session", cookie_hash=cookie_hash
            ),
            verified=False,
        )

    return CallerIdentity.anonymous()


class ChioDjangoMiddleware:
    """Django middleware that evaluates requests through the Chio sidecar.

    Reads configuration from Django settings:

    - ``CHIO_SIDECAR_URL``: sidecar base URL (default ``http://127.0.0.1:9090``)
    - ``CHIO_FAIL_OPEN``: legacy compatibility setting; outages fail closed
    - ``CHIO_EXCLUDE_PATHS``: list of paths to skip (default ``[]``)
    - ``CHIO_EXCLUDE_METHODS``: list of methods to skip (default ``["OPTIONS"]``)
    - ``CHIO_RECEIPT_HEADER``: response header for receipt ID
      (default ``X-Chio-Receipt``)
    - ``CHIO_TIMEOUT``: request timeout in seconds (default 5)
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response
        self._sidecar_url = getattr(
            settings, "CHIO_SIDECAR_URL", "http://127.0.0.1:9090"
        ).rstrip("/")
        self._exclude_paths: set[str] = set(
            getattr(settings, "CHIO_EXCLUDE_PATHS", [])
        )
        self._exclude_methods: set[str] = set(
            getattr(settings, "CHIO_EXCLUDE_METHODS", ["OPTIONS"])
        )
        self._receipt_header: str = getattr(
            settings, "CHIO_RECEIPT_HEADER", "X-Chio-Receipt"
        )
        self._timeout: float = getattr(settings, "CHIO_TIMEOUT", 5.0)

    def _verify_receipt(self, receipt_data: dict[str, Any]) -> bool:
        try:
            receipt = HttpReceipt.model_validate(receipt_data)
        except Exception:
            return False
        try:
            resp = httpx.post(
                f"{self._sidecar_url}/chio/verify",
                json=receipt.model_dump(exclude_none=True),
                timeout=self._timeout,
            )
        except (httpx.ConnectError, httpx.TimeoutException):
            return False
        if resp.status_code != 200:
            return False
        try:
            result = VerifyReceiptResponse.model_validate(resp.json())
        except Exception:
            return False
        return result.authorizes(receipt)

    def __call__(self, request: HttpRequest) -> HttpResponse:
        method = request.method or "GET"

        # Bypass excluded methods and paths
        if method.upper() in self._exclude_methods:
            return self.get_response(request)
        if request.path in self._exclude_paths:
            return self.get_response(request)

        # Extract caller identity
        caller = _extract_caller(request)

        # Compute body hash
        body_hash: str | None = None
        if request.body:
            body_hash = hashlib.sha256(request.body).hexdigest()

        # Extract presented capability token
        capability_token = (
            request.headers.get("X-Chio-Capability")
            or request.GET.get("chio_capability")
        )
        capability_id = _capability_id_from_token(capability_token)

        # Evaluate via sidecar (synchronous httpx)
        request_id = str(uuid.uuid4())
        payload: dict[str, Any] = {
            "request_id": request_id,
            "method": method,
            "route_pattern": request.path,
            "path": request.path,
            "query": {
                key: request.GET.get(key, "")
                for key in request.GET.keys()
            },
            "headers": {
                key.lower(): value
                for key, value in (
                    ("content-type", request.headers.get("Content-Type")),
                    ("content-length", request.headers.get("Content-Length")),
                )
                if value is not None
            },
            "caller": caller.model_dump(exclude_none=True),
            "body_length": len(request.body),
            "timestamp": int(time.time()),
        }
        if body_hash is not None:
            payload["body_hash"] = body_hash
        if capability_id is not None:
            payload["capability_id"] = capability_id

        request_headers: dict[str, str] | None = None
        if capability_token is not None:
            request_headers = {"X-Chio-Capability": capability_token}

        try:
            resp = httpx.post(
                f"{self._sidecar_url}/chio/evaluate",
                json=payload,
                headers=request_headers,
                timeout=self._timeout,
            )
        except (httpx.ConnectError, httpx.TimeoutException):
            return JsonResponse(
                {
                    "error": {
                        "code": "CHIO_SIDECAR_UNAVAILABLE",
                        "message": "Chio sidecar is unavailable",
                    }
                },
                status=503,
            )

        if resp.status_code >= 400:
            return JsonResponse(
                {
                    "error": {
                        "code": "CHIO_INTERNAL_ERROR",
                        "message": f"Sidecar returned {resp.status_code}",
                    }
                },
                status=502,
            )

        try:
            evaluation = resp.json()
        except ValueError:
            return JsonResponse(
                {
                    "error": {
                        "code": "CHIO_INTERNAL_ERROR",
                        "message": "Sidecar returned malformed JSON",
                    }
                },
                status=502,
            )
        verdict = evaluation.get("verdict", {})
        receipt_data = evaluation.get("receipt", {})

        try:
            receipt = HttpReceipt.model_validate(receipt_data)
        except Exception:
            receipt = None

        if (
            verdict.get("verdict") != "allow"
            or receipt is None
            or not receipt.is_allowed
        ):
            status = verdict.get("http_status", 403)
            return JsonResponse(
                {
                    "error": {
                        "code": "CHIO_GUARD_DENIED",
                        "message": verdict.get("reason", "denied"),
                        "guard": verdict.get("guard", "ChioGuard"),
                    }
                },
                status=status,
            )

        if not receipt_data or not self._verify_receipt(receipt_data):
            return JsonResponse(
                {
                    "error": {
                        "code": "CHIO_INVALID_RECEIPT",
                        "message": "Sidecar returned an unverified receipt",
                    }
                },
                status=502,
            )

        # Store receipt data on request for downstream views
        request.chio_receipt = receipt_data  # type: ignore[attr-defined]
        request.chio_evaluation = evaluation  # type: ignore[attr-defined]

        # Forward to view and attach receipt header
        response = self.get_response(request)
        receipt_id = receipt_data.get("id", "")
        if receipt_id:
            response[self._receipt_header] = receipt_id
        return response
