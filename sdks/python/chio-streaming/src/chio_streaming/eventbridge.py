"""AWS EventBridge handler (typically invoked from a Lambda target).

Ack is implicit: returning from Lambda equals ack, raising triggers
EventBridge retry + target DLQ policy. DLQ is out of band - denials
are routed via ``put_events`` to a separate DLQ bus because the
Lambda return value cannot transactionally commit anywhere else.
EventBridge caps a single entry's Detail at 256 KB; the handler
budgets 240 KB to leave room for the framing fields.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, runtime_checkable

from chio_sdk.models import ChioReceipt

from chio_streaming.core import (
    BaseProcessingOutcome,
    ChioClientLike,
    MessageHandler,
    evaluate_with_chio,
    hash_body,
    invoke_handler,
    new_request_id,
    resolve_scope,
)
from chio_streaming.dlq import DLQRecord, DLQRouter
from chio_streaming.errors import ChioStreamingConfigError, ChioStreamingError
from chio_streaming.receipt import ReceiptEnvelope, build_envelope

logger = logging.getLogger(__name__)

SidecarErrorBehaviour = Literal["raise", "deny"]
HandlerErrorStrategy = Literal["raise", "return"]

# EventBridge per-entry cap is 256 KB; budget 240 KB for Detail to
# leave room for Source, DetailType, EventBusName, Resources, framing.
_EVENTBRIDGE_MAX_DETAIL_BYTES = 240_000


@runtime_checkable
class EventBridgeClientLike(Protocol):
    """The ``boto3.client("events")`` surface the handler uses (``put_events``)."""

    def put_events(self, *, Entries: list[Mapping[str, Any]]) -> Mapping[str, Any]: ...


@dataclass
class ChioEventBridgeConfig:
    """Configuration for :class:`ChioEventBridgeHandler`.

    Attributes
    ----------
    capability_id:
        Capability token id passed to the sidecar on every evaluation.
    tool_server:
        Chio tool-server id for the EventBridge bus or AWS account.
    scope_map:
        Map from ``detail-type`` to Chio ``tool_name``. Falls back to
        ``events:consume:{detail-type}``.
    receipt_bus:
        Name or ARN of an event bus for receipt envelopes on allow.
        ``None`` disables receipt publishing.
    receipt_source:
        ``source`` field of the receipt put_events entry. Defaults to
        ``"chio.protocol.receipts"``.
    receipt_detail_type:
        ``detail-type`` of the receipt entry. Defaults to
        ``"ChioReceiptEmitted"``.
    dlq_bus:
        Name or ARN of the DLQ event bus. ``None`` skips DLQ
        publishing; denials surface only via the outcome.
    dlq_source:
        ``source`` of the DLQ entry. Defaults to
        ``"chio.protocol.dlq"``.
    dlq_detail_type:
        ``detail-type`` of the DLQ entry. Defaults to
        ``"ChioCapabilityDenied"``.
    on_sidecar_error:
        ``"raise"`` (default) surfaces sidecar failures as exceptions
        so Lambda retry / DLQ handles them. ``"deny"`` treats sidecar
        failures as terminal denials (fail-closed, useful behind a
        circuit breaker).
    handler_error_strategy:
        ``"raise"`` (default) re-raises handler exceptions from
        ``evaluate()`` so the Lambda invocation fails and EventBridge
        retries / target DLQ fire. ``"return"`` swallows the exception
        and returns an outcome with ``handler_error`` populated
        (Lambda invocation succeeds; no retry).
    """

    capability_id: str
    tool_server: str
    scope_map: Mapping[str, str] = field(default_factory=dict)
    receipt_bus: str | None = None
    receipt_source: str = "chio.protocol.receipts"
    receipt_detail_type: str = "ChioReceiptEmitted"
    dlq_bus: str | None = None
    dlq_source: str = "chio.protocol.dlq"
    dlq_detail_type: str = "ChioCapabilityDenied"
    on_sidecar_error: SidecarErrorBehaviour = "raise"
    handler_error_strategy: HandlerErrorStrategy = "raise"

    def __post_init__(self) -> None:
        if not self.capability_id:
            raise ChioStreamingConfigError("ChioEventBridgeConfig.capability_id must be non-empty")
        if not self.tool_server:
            raise ChioStreamingConfigError("ChioEventBridgeConfig.tool_server must be non-empty")
        if self.on_sidecar_error not in ("raise", "deny"):
            raise ChioStreamingConfigError("on_sidecar_error must be 'raise' or 'deny'")
        if self.handler_error_strategy not in ("raise", "return"):
            raise ChioStreamingConfigError("handler_error_strategy must be 'raise' or 'return'")


@dataclass
class EventBridgeProcessingOutcome(BaseProcessingOutcome):
    """Result of evaluating a single EventBridge event.

    ``lambda_response()`` returns the shape a Lambda handler typically
    returns directly; denials map to ``403``.
    """

    event: Mapping[str, Any] | None = None
    detail_type: str = ""
    dlq_put_response: Any = None

    def lambda_response(self) -> dict[str, Any]:
        """Render a Lambda-compatible response body.

        Allow: ``{"statusCode": 200, "receipt_id": ...}``.
        Deny: ``{"statusCode": 403, "receipt_id": ..., "reason": ...,
        "guard": ...}``.
        Handler error: ``{"statusCode": 500, ...}``.
        """
        if self.allowed and self.handler_error is None:
            return {
                "statusCode": 200,
                "receipt_id": self.receipt.id,
                "request_id": self.request_id,
                "detail_type": self.detail_type,
            }
        if self.handler_error is not None:
            return {
                "statusCode": 500,
                "receipt_id": self.receipt.id,
                "request_id": self.request_id,
                "error": str(self.handler_error),
            }
        decision = self.receipt.decision
        return {
            "statusCode": 403,
            "receipt_id": self.receipt.id,
            "request_id": self.request_id,
            "reason": decision.reason if decision else "non-authorizing Chio receipt",
            "guard": decision.guard if decision else "unknown",
        }


class ChioEventBridgeHandler:
    """Chio-governed adapter for EventBridge-triggered Lambda functions.

    Lambda entrypoint:

    .. code-block:: python

        handler = ChioEventBridgeHandler(
            chio_client=chio_client,
            events_client=boto3.client("events"),
            dlq_router=DLQRouter(default_topic="chio-dlq-bus"),
            config=ChioEventBridgeConfig(
                capability_id="cap-lambda",
                tool_server="aws:events://prod",
                dlq_bus="chio-dlq-bus",
            ),
        )

        def lambda_handler(event, context):
            outcome = asyncio.run(handler.evaluate(event, handler=process))
            return outcome.lambda_response()

    The handler callback receives ``(event, receipt)``.
    """

    def __init__(
        self,
        *,
        chio_client: ChioClientLike,
        events_client: EventBridgeClientLike | None,
        dlq_router: DLQRouter,
        config: ChioEventBridgeConfig,
    ) -> None:
        if chio_client is None:
            raise ChioStreamingConfigError("chio_client is required")
        if dlq_router is None:
            raise ChioStreamingConfigError("dlq_router is required")
        if config.dlq_bus is not None and events_client is None:
            raise ChioStreamingConfigError("events_client is required when config.dlq_bus is set")
        if config.receipt_bus is not None and events_client is None:
            raise ChioStreamingConfigError(
                "events_client is required when config.receipt_bus is set"
            )
        self._chio_client = chio_client
        self._events_client = events_client
        self._dlq_router = dlq_router
        self._config = config

    @property
    def config(self) -> ChioEventBridgeConfig:
        return self._config

    async def evaluate(
        self,
        event: Mapping[str, Any],
        *,
        handler: MessageHandler | None = None,
    ) -> EventBridgeProcessingOutcome:
        """Evaluate an EventBridge ``event`` through Chio.

        Allow + success: handler runs (if provided), receipt published.
        Allow + handler error: outcome carries the exception, no receipt.
        Deny: DLQ entry published (if ``dlq_bus`` set).
        Sidecar failure: re-raises unless ``on_sidecar_error="deny"``.

        ``request_id`` is derived from ``event["id"]`` so target
        retries reuse the same id and receipt / DLQ dedupe collapses
        duplicates. Falls back to a UUID when id is absent.
        """
        event_id = event.get("id")
        request_id = f"chio-eb-{event_id}" if event_id else new_request_id("chio-eb")
        detail_type = str(event.get("detail-type") or event.get("detailType") or "")
        tool_name = resolve_scope(
            scope_map=self._config.scope_map, subject=detail_type or "unknown"
        )
        parameters = self._parameters_for(event, request_id=request_id)

        try:
            receipt = await evaluate_with_chio(
                chio_client=self._chio_client,
                capability_id=self._config.capability_id,
                tool_server=self._config.tool_server,
                tool_name=tool_name,
                parameters=parameters,
                failure_context={
                    "topic": detail_type,
                    "request_id": request_id,
                },
            )
        except ChioStreamingError:
            if self._config.on_sidecar_error == "deny":
                from chio_streaming.core import synthesize_deny_receipt

                receipt = synthesize_deny_receipt(
                    capability_id=self._config.capability_id,
                    tool_server=self._config.tool_server,
                    tool_name=tool_name,
                    parameters=parameters,
                    reason="sidecar unavailable; failing closed",
                    guard="chio-streaming-sidecar",
                )
                return await self._handle_deny(
                    event=event,
                    receipt=receipt,
                    request_id=request_id,
                    detail_type=detail_type,
                )
            raise

        if not receipt.is_allowed:
            return await self._handle_deny(
                event=event,
                receipt=receipt,
                request_id=request_id,
                detail_type=detail_type,
            )
        return await self._handle_allow(
            event=event,
            receipt=receipt,
            request_id=request_id,
            detail_type=detail_type,
            handler=handler,
        )

    async def _handle_allow(
        self,
        *,
        event: Mapping[str, Any],
        receipt: ChioReceipt,
        request_id: str,
        detail_type: str,
        handler: MessageHandler | None,
    ) -> EventBridgeProcessingOutcome:
        envelope = build_envelope(
            request_id=request_id,
            receipt=receipt,
            source_topic=detail_type or None,
        )
        handler_error: Exception | None = None
        if handler is not None:
            try:
                await invoke_handler(handler, event, receipt)
            except Exception as exc:
                handler_error = exc
                logger.warning(
                    "chio-eventbridge: handler raised for detail-type=%s request_id=%s: %s",
                    detail_type,
                    request_id,
                    exc,
                )
                # EventBridge retry + target DLQ only fire when the
                # Lambda invocation itself errors. Default strategy
                # re-raises so the failed business logic is not
                # silently dropped; "return" is opt-in for soft-fail.
                if self._config.handler_error_strategy == "raise":
                    raise
        if handler_error is None and self._config.receipt_bus is not None:
            await self._put_receipt(envelope)
        return EventBridgeProcessingOutcome(
            allowed=True,
            receipt=receipt,
            request_id=request_id,
            acked=True,
            event=event,
            detail_type=detail_type,
            handler_error=handler_error,
        )

    async def _handle_deny(
        self,
        *,
        event: Mapping[str, Any],
        receipt: ChioReceipt,
        request_id: str,
        detail_type: str,
    ) -> EventBridgeProcessingOutcome:
        body = _canonical_event_bytes(event)
        record = self._dlq_router.build_record(
            source_topic=detail_type or "unknown",
            source_partition=None,
            source_offset=None,
            original_key=None,
            original_value=body,
            request_id=request_id,
            receipt=receipt,
            extra_metadata={
                "eventbridge_source": event.get("source"),
                "eventbridge_event_id": event.get("id"),
                "eventbridge_region": event.get("region"),
                "eventbridge_account": event.get("account"),
            },
        )
        put_response: Any = None
        if self._config.dlq_bus is not None:
            put_response = await self._put_dlq(record)
        return EventBridgeProcessingOutcome(
            allowed=False,
            receipt=receipt,
            request_id=request_id,
            acked=True,
            event=event,
            detail_type=detail_type,
            dlq_record=record,
            dlq_put_response=put_response,
        )

    async def _put_receipt(self, envelope: ReceiptEnvelope) -> None:
        assert self._events_client is not None
        detail_bytes = envelope.value
        if len(detail_bytes) > _EVENTBRIDGE_MAX_DETAIL_BYTES:
            raise ChioStreamingError(
                "receipt envelope exceeds EventBridge per-entry limit "
                f"({len(detail_bytes)} > {_EVENTBRIDGE_MAX_DETAIL_BYTES})",
                request_id=envelope.request_id,
                receipt_id=envelope.receipt_id,
            )
        entry = {
            "Source": self._config.receipt_source,
            "DetailType": self._config.receipt_detail_type,
            "Detail": detail_bytes.decode("utf-8"),
            "EventBusName": self._config.receipt_bus,
        }
        # boto3's put_events is sync; the await guard lets async
        # doubles work without wrapping in asyncio.to_thread.
        result = self._events_client.put_events(Entries=[entry])
        response = await result if hasattr(result, "__await__") else result
        _raise_on_failed_entries(response, context="receipt")

    async def _put_dlq(self, record: DLQRecord) -> Any:
        assert self._events_client is not None
        detail_bytes = _truncate_dlq_detail_if_needed(record.value)
        entry = {
            "Source": self._config.dlq_source,
            "DetailType": self._config.dlq_detail_type,
            "Detail": detail_bytes.decode("utf-8"),
            "EventBusName": self._config.dlq_bus,
        }
        result = self._events_client.put_events(Entries=[entry])
        response = await result if hasattr(result, "__await__") else result
        _raise_on_failed_entries(response, context="dlq")
        return response

    def _parameters_for(
        self,
        event: Mapping[str, Any],
        *,
        request_id: str,
    ) -> dict[str, Any]:
        # ``detail`` is hashed, not forwarded; large blobs stay off the
        # Chio RPC path. Guards that need the body pin on body_hash.
        detail = event.get("detail")
        body = _canonical_event_bytes({"detail": detail}) if detail is not None else b""
        return {
            "request_id": request_id,
            "detail_type": event.get("detail-type") or event.get("detailType"),
            "source": event.get("source"),
            "account": event.get("account"),
            "region": event.get("region"),
            "resources": list(event.get("resources") or []),
            "event_id": event.get("id"),
            "time": event.get("time"),
            "body_length": len(body),
            "body_hash": hash_body(body),
        }


def _canonical_event_bytes(event: Mapping[str, Any]) -> bytes:
    """Serialise an EventBridge event (or sub-object) deterministically."""
    return json.dumps(
        event,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    ).encode("utf-8")


def _raise_on_failed_entries(response: Any, *, context: str) -> None:
    """Fail closed when ``put_events`` reports partial failure.

    EventBridge signals per-entry failure via ``FailedEntryCount > 0``
    and ``Entries[i].ErrorCode`` rather than raising. Silently
    swallowing would lose receipts and DLQ envelopes.
    """
    if not isinstance(response, Mapping):
        return
    failed = response.get("FailedEntryCount") or 0
    if not failed:
        return
    entries = response.get("Entries") or []
    error_code = "Unknown"
    error_message = "put_events reported FailedEntryCount > 0"
    for entry in entries:
        if isinstance(entry, Mapping) and entry.get("ErrorCode"):
            error_code = str(entry.get("ErrorCode") or error_code)
            error_message = str(entry.get("ErrorMessage") or error_message)
            break
    raise ChioStreamingError(
        f"EventBridge {context} put_events failed: {error_code}: {error_message}",
        guard="chio-streaming-eventbridge",
    )


def _truncate_dlq_detail_if_needed(detail_bytes: bytes) -> bytes:
    """Rewrite an oversized DLQ Detail payload to fit EventBridge's cap.

    The usual offender is ``original_value`` echoing a large inbound
    record. That field is dropped and a truncation marker added so
    operators can tell the payload was not preserved in full.
    """
    if len(detail_bytes) <= _EVENTBRIDGE_MAX_DETAIL_BYTES:
        return detail_bytes
    try:
        payload = json.loads(detail_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ChioStreamingError(
            "DLQ envelope exceeds EventBridge per-entry limit and is not "
            "JSON-decodable for truncation",
            guard="chio-streaming-eventbridge",
        ) from None
    if isinstance(payload, dict) and "original_value" in payload:
        payload.pop("original_value", None)
        payload["original_value_truncated"] = True
    rewritten = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    if len(rewritten) > _EVENTBRIDGE_MAX_DETAIL_BYTES:
        raise ChioStreamingError(
            "DLQ envelope still exceeds EventBridge per-entry limit after "
            f"truncation ({len(rewritten)} > {_EVENTBRIDGE_MAX_DETAIL_BYTES})",
            guard="chio-streaming-eventbridge",
        )
    return rewritten


def build_eventbridge_handler(
    *,
    chio_client: ChioClientLike,
    events_client: EventBridgeClientLike | None,
    config: ChioEventBridgeConfig,
    dlq_router: DLQRouter | None = None,
    dlq_fallback_topic: str | None = None,
) -> ChioEventBridgeHandler:
    """Construct the handler with an explicit :class:`DLQRouter`.

    One of ``dlq_router`` or ``dlq_fallback_topic`` is required
    (fail-closed: no hard-coded default). ``dlq_fallback_topic`` is
    the routing tag on the denial envelope, distinct from
    ``config.dlq_bus`` which is the EventBridge bus ``put_events``
    targets.
    """
    if dlq_router is None:
        if not dlq_fallback_topic:
            raise ChioStreamingConfigError(
                "build_eventbridge_handler requires dlq_router or dlq_fallback_topic"
            )
        dlq_router = DLQRouter(default_topic=dlq_fallback_topic)
    return ChioEventBridgeHandler(
        chio_client=chio_client,
        events_client=events_client,
        dlq_router=dlq_router,
        config=config,
    )


__all__ = [
    "ChioEventBridgeConfig",
    "ChioEventBridgeHandler",
    "EventBridgeClientLike",
    "EventBridgeProcessingOutcome",
    "SidecarErrorBehaviour",
    "build_eventbridge_handler",
]
