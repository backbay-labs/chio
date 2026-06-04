from __future__ import annotations

import json
from dataclasses import dataclass

from django.http import HttpRequest, JsonResponse


@dataclass(frozen=True)
class EchoPayload:
    message: str
    count: int


class EchoPayloadError(ValueError):
    pass


def _parse_echo_payload(body: bytes) -> EchoPayload:
    try:
        payload = json.loads(body.decode("utf-8") or "{}")
    except json.JSONDecodeError as exc:
        raise EchoPayloadError(str(exc)) from exc

    if not isinstance(payload, dict):
        raise EchoPayloadError("body must be a JSON object")

    allowed_keys = {"message", "count"}
    extra_keys = sorted(set(payload) - allowed_keys)
    if extra_keys:
        raise EchoPayloadError(f"unexpected fields: {', '.join(extra_keys)}")

    message = payload.get("message")
    if not isinstance(message, str) or not message:
        raise EchoPayloadError("message must be a non-empty string")

    count = payload.get("count", 1)
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise EchoPayloadError("count must be an integer greater than or equal to 1")

    return EchoPayload(message=message, count=count)


def _receipt_id(request: HttpRequest) -> str | None:
    receipt = getattr(request, "chio_receipt", None)
    if isinstance(receipt, dict):
        return receipt.get("id")
    return None


def healthz(_request: HttpRequest) -> JsonResponse:
    return JsonResponse({"status": "ok"})


def hello(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        {
            "message": "hello from django",
            "receipt_id": _receipt_id(request),
        }
    )


def echo(request: HttpRequest) -> JsonResponse:
    try:
        payload = _parse_echo_payload(request.body)
    except EchoPayloadError as exc:
        return JsonResponse({"error": str(exc)}, status=400)

    return JsonResponse(
        {
            "message": payload.message,
            "count": payload.count,
            "receipt_id": _receipt_id(request),
            "body_cached": bool(request.body),
        }
    )
