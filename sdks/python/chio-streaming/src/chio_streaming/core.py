"""Shared helpers for the broker middlewares.

The sidecar Protocol, the deny-receipt synthesiser, scope resolution,
header/body normalisation, and the lazy backpressure semaphore live
here. Broker modules add their own message Protocols on top.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from chio_sdk._generated.receipt.record_schema import (
    BoundaryClass,
    ReceiptKind,
    RedactionMode,
    ToolOrigin,
    TrustLevel,
)
from chio_sdk.errors import ChioDeniedError, ChioError
from chio_sdk.models import ChioReceipt, Decision, ToolCallAction

from chio_streaming.errors import ChioStreamingConfigError, ChioStreamingError

if TYPE_CHECKING:  # pragma: no cover - typing-only import to avoid cycle with dlq.py
    from chio_streaming.dlq import DLQRecord


@runtime_checkable
class ChioClientLike(Protocol):
    """The sidecar surface every middleware calls."""

    async def evaluate_tool_call(
        self,
        *,
        capability_id: str,
        tool_server: str,
        tool_name: str,
        parameters: dict[str, Any],
    ) -> ChioReceipt: ...


MessageHandler = Callable[[Any, ChioReceipt], Awaitable[None] | None]
"""Application callback. Sync or async; return value ignored."""


@dataclass
class BaseProcessingOutcome:
    """Common outcome fields so observability code can be broker-agnostic."""

    allowed: bool
    receipt: ChioReceipt
    request_id: str
    acked: bool = False
    dlq_record: DLQRecord | None = None
    handler_error: Exception | None = None


async def invoke_handler(
    handler: MessageHandler,
    message: Any,
    receipt: ChioReceipt,
) -> None:
    """Call the handler, awaiting it if it returned a coroutine."""
    result = handler(message, receipt)
    if result is None:
        return
    if isinstance(result, Awaitable):
        await result


async def evaluate_with_chio(
    *,
    chio_client: ChioClientLike,
    capability_id: str,
    tool_server: str,
    tool_name: str,
    parameters: dict[str, Any],
    failure_context: Mapping[str, Any] | None = None,
) -> ChioReceipt:
    """Call the sidecar and normalise its outcomes.

    Allow/deny receipts pass through. ``ChioDeniedError`` (the real
    client's 403 shape) becomes a synthesised deny receipt so the deny
    path is uniform. ``ChioError`` (sidecar down/timeout) is wrapped in
    ``ChioStreamingError``, carrying ``failure_context`` for logs.
    """
    try:
        return await chio_client.evaluate_tool_call(
            capability_id=capability_id,
            tool_server=tool_server,
            tool_name=tool_name,
            parameters=parameters,
        )
    except ChioDeniedError as exc:
        return synthesize_deny_receipt(
            capability_id=capability_id,
            tool_server=tool_server,
            tool_name=tool_name,
            parameters=parameters,
            reason=exc.reason or exc.message or "denied",
            guard=exc.guard or "unknown",
        )
    except ChioError as exc:
        ctx = dict(failure_context or {})
        raise ChioStreamingError(
            f"Chio sidecar evaluation failed: {exc}",
            topic=ctx.get("topic"),
            partition=ctx.get("partition"),
            offset=ctx.get("offset"),
            request_id=ctx.get("request_id"),
        ) from exc


#: Marker on synthesised receipt metadata so verifiers can reject
#: them structurally instead of string-matching the signature field.
SYNTHETIC_RECEIPT_MARKER = "chio-streaming/synthetic-deny/v1"


def synthesize_deny_receipt(
    *,
    capability_id: str,
    tool_server: str,
    tool_name: str,
    parameters: dict[str, Any],
    reason: str,
    guard: str,
) -> ChioReceipt:
    """Build a deny receipt when the sidecar raised instead of returning one.

    Signature and kernel_key keep schema-valid placeholders, metadata
    carries the synthetic marker, and the reason is prefixed ``[unsigned]``
    so DLQ analytics surface it without reading metadata. Parameter hash
    stays consistent with what the sidecar would have computed.
    """
    canonical = json.dumps(
        parameters, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    param_hash = hashlib.sha256(canonical).hexdigest()
    annotated_reason = reason if reason.startswith("[unsigned]") else f"[unsigned] {reason}"
    return ChioReceipt(
        id=hashlib.sha256(f"{SYNTHETIC_RECEIPT_MARKER}:{uuid.uuid4().hex}".encode()).hexdigest(),
        timestamp=int(time.time()),
        capability_id=capability_id,
        tool_server=tool_server,
        tool_name=tool_name,
        action=ToolCallAction(
            parameters=dict(parameters),
            parameter_hash=param_hash,
        ),
        decision=Decision.deny(reason=annotated_reason, guard=guard),
        receipt_kind=ReceiptKind.mediated_decision,
        boundary_class=BoundaryClass.prevent,
        tool_origin=ToolOrigin.caller_executed,
        redaction_mode=RedactionMode.none,
        content_hash=param_hash,
        policy_hash="0" * 64,
        evidence=[],
        metadata={
            "chio_streaming_synthetic": True,
            "chio_streaming_synthetic_marker": SYNTHETIC_RECEIPT_MARKER,
        },
        trust_level=TrustLevel.mediated,
        kernel_key="0" * 64,
        signature="0" * 128,
    )


def resolve_scope(
    *,
    scope_map: Mapping[str, str],
    subject: str,
    default_prefix: str = "events:consume",
) -> str:
    """Return the Chio tool_name for ``subject`` (explicit map wins).

    Empty ``subject`` raises; every evaluation needs a non-empty name.
    """
    if not subject:
        raise ChioStreamingConfigError(
            "consumed message has no subject/topic; Chio evaluation requires one"
        )
    mapped = scope_map.get(subject)
    if mapped:
        return mapped
    return f"{default_prefix}:{subject}"


def hash_body(body: bytes | None) -> str | None:
    """Return the hex SHA-256 of ``body`` or ``None`` for empty bodies."""
    if not body:
        return None
    return hashlib.sha256(body).hexdigest()


def stringify_header_value(value: Any) -> Any:
    """UTF-8 decode bytes values (hex fallback). Non-bytes pass through."""
    if isinstance(value, bytes | bytearray):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return bytes(value).hex()
    return value


def _stringify_header_key(key: Any) -> str:
    # str(b"foo") yields "b'foo'", useless for policy matching. Bytes
    # keys (Redis, some Kafka clients) decode as UTF-8 with hex fallback.
    if isinstance(key, bytes | bytearray):
        try:
            return bytes(key).decode("utf-8")
        except UnicodeDecodeError:
            return bytes(key).hex()
    return str(key)


def normalise_headers(
    headers: Any,
) -> dict[str, Any]:
    """Return ``{name: value}`` from a list-of-tuples, mapping, or ``None``."""
    if headers is None:
        return {}
    if isinstance(headers, Mapping):
        return {_stringify_header_key(k): stringify_header_value(v) for k, v in headers.items()}
    out: dict[str, Any] = {}
    for item in headers:
        if not item:
            continue
        name, value = item[0], item[1]
        out[_stringify_header_key(name)] = stringify_header_value(value)
    return out


def new_request_id(prefix: str = "chio-evt") -> str:
    """Synthesise a request id; broker messages do not carry one."""
    return f"{prefix}-{uuid.uuid4().hex}"


class Slots:
    """Bounded semaphore that binds to the running loop lazily.

    Middlewares are built in DI factories (no running loop) but used
    inside one. ``asyncio.Semaphore`` eagerly binds to the current
    loop at construction; deferring to first ``acquire`` keeps that
    binding on the caller's loop.
    """

    __slots__ = ("_limit", "_sem", "_in_flight")

    def __init__(self, limit: int) -> None:
        if limit < 1:
            raise ChioStreamingConfigError("Slots(limit) must be >= 1")
        self._limit = limit
        self._sem: asyncio.Semaphore | None = None
        self._in_flight = 0

    @property
    def in_flight(self) -> int:
        return self._in_flight

    async def acquire(self) -> None:
        if self._sem is None:
            self._sem = asyncio.Semaphore(self._limit)
        await self._sem.acquire()
        self._in_flight += 1

    def release(self) -> None:
        # Extra releases are ignored so drain paths stay simple.
        if self._sem is None:
            return
        if self._in_flight > 0:
            self._in_flight -= 1
            self._sem.release()


__all__ = [
    "SYNTHETIC_RECEIPT_MARKER",
    "BaseProcessingOutcome",
    "ChioClientLike",
    "MessageHandler",
    "Slots",
    "evaluate_with_chio",
    "hash_body",
    "invoke_handler",
    "new_request_id",
    "normalise_headers",
    "resolve_scope",
    "stringify_header_value",
    "synthesize_deny_receipt",
]
