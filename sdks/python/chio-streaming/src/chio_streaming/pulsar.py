"""Apache Pulsar middleware.

No native EOS: publish-then-ack, not atomic. A crash between the two
duplicates the receipt / DLQ entry, so downstream consumers must
dedupe on ``request_id``. Deny uses ``acknowledge`` (not
``negative_acknowledge``) so Pulsar's built-in DLQ policy is not also
triggered. Pulsar properties carry what other brokers call headers.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, runtime_checkable

from chio_sdk.models import ChioReceipt

from chio_streaming.core import (
    BaseProcessingOutcome,
    ChioClientLike,
    MessageHandler,
    Slots,
    evaluate_with_chio,
    hash_body,
    invoke_handler,
    new_request_id,
    normalise_headers,
    resolve_scope,
    stringify_header_value,
    synthesize_deny_receipt,
)
from chio_streaming.dlq import DLQRecord, DLQRouter
from chio_streaming.errors import ChioStreamingConfigError, ChioStreamingError
from chio_streaming.receipt import ReceiptEnvelope, build_envelope

logger = logging.getLogger(__name__)

# Broker strategy vocab is "ack"/"nack".
HandlerErrorStrategy = Literal["nack", "ack"]
SidecarErrorBehaviour = Literal["raise", "deny"]


@runtime_checkable
class PulsarMessageLike(Protocol):
    """The :class:`pulsar.Message` surface the middleware reads."""

    def data(self) -> bytes: ...
    def properties(self) -> Mapping[str, str]: ...
    def topic_name(self) -> str: ...
    def partition_key(self) -> str | None: ...
    def message_id(self) -> Any: ...


@runtime_checkable
class PulsarConsumerLike(Protocol):
    """The :class:`pulsar.Consumer` surface the middleware drives.

    Callers own the ``consumer.receive()`` loop and hand each message
    to :meth:`ChioPulsarMiddleware.dispatch`. Both sync and async
    ``acknowledge`` work; coroutines are awaited.
    """

    def acknowledge(self, message: PulsarMessageLike) -> Any: ...
    def negative_acknowledge(self, message: PulsarMessageLike) -> Any: ...


@runtime_checkable
class PulsarProducerLike(Protocol):
    """The :class:`pulsar.Producer` surface the middleware drives.

    ``send`` may return a coroutine (async producer) or a plain value
    (sync producer); both shapes are handled.
    """

    def send(
        self,
        content: bytes,
        properties: Mapping[str, str] | None = ...,
        partition_key: str | None = ...,
    ) -> Any: ...


@dataclass
class ChioPulsarConsumerConfig:
    """Configuration for :class:`ChioPulsarMiddleware`.

    Attributes
    ----------
    capability_id:
        Capability token id shared across every consumer in the
        subscription.
    tool_server:
        Chio tool-server id for the Pulsar tenant / namespace.
    scope_map:
        Per-topic override of the Chio ``tool_name``. Falls back to
        ``events:consume:{topic}``.
    receipt_topic:
        Fully-qualified Pulsar topic for receipt envelopes. ``None``
        disables receipt publishing.
    max_in_flight:
        Concurrency cap for in-flight evaluations.
    handler_error_strategy:
        ``"nack"`` (default) schedules Pulsar redelivery. ``"ack"``
        treats the failure as terminal (message is lost).
    on_sidecar_error:
        ``"raise"`` (default) propagates ChioStreamingError. ``"deny"``
        synthesises a deny receipt and routes through the DLQ
        (fail-closed).
    """

    capability_id: str
    tool_server: str
    scope_map: Mapping[str, str] = field(default_factory=dict)
    receipt_topic: str | None = None
    max_in_flight: int = 64
    handler_error_strategy: HandlerErrorStrategy = "nack"
    on_sidecar_error: SidecarErrorBehaviour = "raise"

    def __post_init__(self) -> None:
        if not self.capability_id:
            raise ChioStreamingConfigError(
                "ChioPulsarConsumerConfig.capability_id must be non-empty"
            )
        if not self.tool_server:
            raise ChioStreamingConfigError("ChioPulsarConsumerConfig.tool_server must be non-empty")
        if self.max_in_flight < 1:
            raise ChioStreamingConfigError("ChioPulsarConsumerConfig.max_in_flight must be >= 1")
        if self.handler_error_strategy not in ("nack", "ack"):
            raise ChioStreamingConfigError("handler_error_strategy must be 'nack' or 'ack'")
        if self.on_sidecar_error not in ("raise", "deny"):
            raise ChioStreamingConfigError("on_sidecar_error must be 'raise' or 'deny'")


@dataclass
class PulsarProcessingOutcome(BaseProcessingOutcome):
    """Result of processing a single Pulsar message."""

    message: PulsarMessageLike | None = None


class ChioPulsarMiddleware:
    """Chio-governed dispatcher around a Pulsar consumer + producers.

    Needs three handles: the source consumer (to ack), a receipt
    producer (allow path), and a DLQ producer (deny path). Sharing a
    producer across receipt and DLQ is fine if both publish to the
    same topic; the split layout lets subscribers fan out. Producers
    are passed in so batching, compression, and lifecycle stay the
    caller's.
    """

    def __init__(
        self,
        *,
        consumer: PulsarConsumerLike,
        receipt_producer: PulsarProducerLike | None,
        dlq_producer: PulsarProducerLike,
        chio_client: ChioClientLike,
        dlq_router: DLQRouter,
        config: ChioPulsarConsumerConfig,
    ) -> None:
        if consumer is None:
            raise ChioStreamingConfigError("consumer is required")
        if dlq_producer is None:
            raise ChioStreamingConfigError("dlq_producer is required")
        if chio_client is None:
            raise ChioStreamingConfigError("chio_client is required")
        if dlq_router is None:
            raise ChioStreamingConfigError("dlq_router is required")
        if config.receipt_topic is not None and receipt_producer is None:
            raise ChioStreamingConfigError(
                "receipt_producer is required when config.receipt_topic is set"
            )
        self._consumer = consumer
        self._receipt_producer = receipt_producer
        self._dlq_producer = dlq_producer
        self._chio_client = chio_client
        self._dlq_router = dlq_router
        self._config = config
        self._slots = Slots(config.max_in_flight)

    @property
    def config(self) -> ChioPulsarConsumerConfig:
        return self._config

    @property
    def in_flight(self) -> int:
        return self._slots.in_flight

    async def dispatch(
        self,
        msg: PulsarMessageLike,
        handler: MessageHandler,
    ) -> PulsarProcessingOutcome:
        """Evaluate ``msg`` and drive ack / DLQ side effects.

        Allow + success: run handler, publish receipt, acknowledge.
        Allow + handler error: negative_acknowledge (or acknowledge).
        Deny: publish DLQ, acknowledge.
        Sidecar failure: re-raises unless ``on_sidecar_error="deny"``.
        """
        await self._slots.acquire()
        try:
            return await self._process(msg, handler)
        finally:
            self._slots.release()

    async def _process(
        self,
        msg: PulsarMessageLike,
        handler: MessageHandler,
    ) -> PulsarProcessingOutcome:
        # Derive request_id from the Pulsar message id so a redelivery
        # after a failed ack produces byte-identical receipts. A fresh
        # UUID per attempt would bypass downstream dedupe-by-request-id
        # and cause the signed receipt to diverge across retries.
        message_id = msg.message_id()
        request_id = (
            f"chio-pulsar-{message_id}" if message_id else new_request_id("chio-pulsar")
        )
        topic = msg.topic_name() or ""
        tool_name = resolve_scope(scope_map=self._config.scope_map, subject=topic)
        parameters = self._parameters_for(msg, request_id=request_id)

        try:
            receipt = await evaluate_with_chio(
                chio_client=self._chio_client,
                capability_id=self._config.capability_id,
                tool_server=self._config.tool_server,
                tool_name=tool_name,
                parameters=parameters,
                failure_context={
                    "topic": topic,
                    "request_id": request_id,
                },
            )
        except ChioStreamingError:
            if self._config.on_sidecar_error == "deny":
                receipt = synthesize_deny_receipt(
                    capability_id=self._config.capability_id,
                    tool_server=self._config.tool_server,
                    tool_name=tool_name,
                    parameters=parameters,
                    reason="sidecar unavailable; failing closed",
                    guard="chio-streaming-sidecar",
                )
                return await self._handle_deny(msg, receipt, request_id)
            raise
        if not receipt.is_allowed:
            return await self._handle_deny(msg, receipt, request_id)
        return await self._handle_allow(msg, receipt, request_id, handler)

    async def _handle_allow(
        self,
        msg: PulsarMessageLike,
        receipt: ChioReceipt,
        request_id: str,
        handler: MessageHandler,
    ) -> PulsarProcessingOutcome:
        envelope = build_envelope(
            request_id=request_id,
            receipt=receipt,
            source_topic=msg.topic_name(),
        )
        # handler_error_strategy applies to handler failures only. Receipt
        # send and acknowledge errors are infrastructure failures; they
        # propagate so Pulsar redelivers instead of handler_error_strategy
        # silently acking the source without a receipt.
        try:
            await invoke_handler(handler, msg, receipt)
        except Exception as exc:
            await self._negative_ack(msg)
            # handler_error_strategy="ack" means _negative_ack called
            # acknowledge, so the source was acked despite the failure.
            acked = self._config.handler_error_strategy == "ack"
            logger.warning(
                "chio-pulsar: handler raised for topic=%s request_id=%s; redelivery scheduled: %s",
                msg.topic_name(),
                request_id,
                exc,
            )
            return PulsarProcessingOutcome(
                allowed=True,
                receipt=receipt,
                request_id=request_id,
                message=msg,
                acked=acked,
                handler_error=exc,
            )

        if self._config.receipt_topic is not None:
            assert self._receipt_producer is not None  # guaranteed by __init__
            await _maybe_await(
                self._receipt_producer.send(
                    envelope.value,
                    properties=_envelope_properties(envelope),
                    partition_key=envelope.key.decode("utf-8", errors="replace"),
                )
            )
        await _maybe_await(self._consumer.acknowledge(msg))
        return PulsarProcessingOutcome(
            allowed=True,
            receipt=receipt,
            request_id=request_id,
            message=msg,
            acked=True,
        )

    async def _handle_deny(
        self,
        msg: PulsarMessageLike,
        receipt: ChioReceipt,
        request_id: str,
    ) -> PulsarProcessingOutcome:
        body = msg.data() or b""
        key_str = msg.partition_key()
        original_key = key_str.encode("utf-8") if key_str else None
        record = self._dlq_router.build_record(
            source_topic=msg.topic_name() or "",
            source_partition=None,
            source_offset=None,
            original_key=original_key,
            original_value=body if body else None,
            request_id=request_id,
            receipt=receipt,
        )
        await _maybe_await(
            self._dlq_producer.send(
                record.value,
                properties=_record_properties(record),
                partition_key=record.key.decode("utf-8", errors="replace"),
            )
        )
        await _maybe_await(self._consumer.acknowledge(msg))
        return PulsarProcessingOutcome(
            allowed=False,
            receipt=receipt,
            request_id=request_id,
            message=msg,
            dlq_record=record,
            acked=True,
        )

    async def _negative_ack(self, msg: PulsarMessageLike) -> None:
        """Send the redelivery signal dictated by config."""
        if self._config.handler_error_strategy == "ack":
            await _maybe_await(self._consumer.acknowledge(msg))
            return
        await _maybe_await(self._consumer.negative_acknowledge(msg))

    def _parameters_for(
        self,
        msg: PulsarMessageLike,
        *,
        request_id: str,
    ) -> dict[str, Any]:
        properties = normalise_headers(msg.properties())
        body = msg.data() or b""
        params: dict[str, Any] = {
            "request_id": request_id,
            "topic": msg.topic_name(),
            "properties": properties,
            "partition_key": msg.partition_key(),
            "body_length": len(body),
            "body_hash": hash_body(body),
        }
        return params


async def _maybe_await(value: Any) -> Any:
    """Await ``value`` if it is a coroutine, otherwise return as-is.

    Pulsar's sync and async clients differ only in that the async
    variant returns coroutines from ack / send.
    """
    if hasattr(value, "__await__"):
        return await value
    return value


def _envelope_properties(
    envelope: ReceiptEnvelope,
) -> dict[str, str]:
    """Project envelope headers onto Pulsar properties (``Mapping[str, str]``)."""
    out = {name: str(stringify_header_value(value)) for name, value in envelope.headers}
    out.setdefault("X-Chio-Request-Id", envelope.request_id)
    return out


def _record_properties(record: DLQRecord) -> dict[str, str]:
    """Project DLQ record headers onto Pulsar properties."""
    return {name: str(stringify_header_value(value)) for name, value in record.headers}


def build_pulsar_middleware(
    *,
    consumer: PulsarConsumerLike,
    receipt_producer: PulsarProducerLike | None,
    dlq_producer: PulsarProducerLike,
    chio_client: ChioClientLike,
    config: ChioPulsarConsumerConfig,
    dlq_router: DLQRouter | None = None,
    dlq_topic: str | None = None,
) -> ChioPulsarMiddleware:
    """Convenience constructor that wires a default :class:`DLQRouter`."""
    if dlq_router is None:
        if not dlq_topic:
            raise ChioStreamingConfigError(
                "build_pulsar_middleware requires dlq_router or dlq_topic"
            )
        dlq_router = DLQRouter(default_topic=dlq_topic)
    return ChioPulsarMiddleware(
        consumer=consumer,
        receipt_producer=receipt_producer,
        dlq_producer=dlq_producer,
        chio_client=chio_client,
        dlq_router=dlq_router,
        config=config,
    )


__all__ = [
    "ChioPulsarConsumerConfig",
    "ChioPulsarMiddleware",
    "HandlerErrorStrategy",
    "PulsarConsumerLike",
    "PulsarMessageLike",
    "PulsarProcessingOutcome",
    "PulsarProducerLike",
    "SidecarErrorBehaviour",
    "build_pulsar_middleware",
]
