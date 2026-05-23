"""Google Cloud Pub/Sub middleware.

Publish-then-ack, not atomic. A crash between the two redelivers and
duplicates the receipt / DLQ entry, so downstream consumers must
dedupe on ``request_id``. Deny defaults to ``ack`` after publishing
to the Chio DLQ; otherwise Pub/Sub's native dead-letter policy would
fire too and duplicate the entry. The publisher future is drained
before acking so a publish failure blocks the ack and Pub/Sub
redelivers.
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

DenyStrategy = Literal["ack", "nack"]
HandlerErrorStrategy = Literal["nack", "ack"]
SidecarErrorBehaviour = Literal["raise", "deny"]


@runtime_checkable
class PubSubMessageLike(Protocol):
    """The ``pubsub_v1.subscriber.message.Message`` surface the middleware reads."""

    @property
    def data(self) -> bytes: ...
    @property
    def attributes(self) -> Mapping[str, str]: ...
    @property
    def message_id(self) -> str: ...
    @property
    def ordering_key(self) -> str: ...
    def ack(self) -> None: ...
    def nack(self) -> None: ...


@runtime_checkable
class PubSubPublisherLike(Protocol):
    """The ``pubsub_v1.PublisherClient`` surface the middleware drives.

    Official client returns a ``concurrent.futures.Future``; async
    wrappers return coroutines. Both are handled in
    :func:`_await_publish_result`.
    """

    def publish(
        self,
        topic: str,
        data: bytes,
        *,
        ordering_key: str = ...,
        **attributes: str,
    ) -> Any: ...


@dataclass
class ChioPubSubConfig:
    """Configuration for :class:`ChioPubSubMiddleware`.

    Attributes
    ----------
    capability_id:
        Capability token id every evaluation is bound to.
    tool_server:
        Chio tool-server id for the GCP project / bus.
    subscription:
        Fully-qualified subscription name
        (``projects/my-proj/subscriptions/agent-tasks``). Used as the
        fallback scope subject.
    scope_map:
        Map from subject to Chio ``tool_name``. Subject is resolved in
        order: ``X-Chio-Subject`` attribute, ``subject`` attribute,
        configured ``subscription`` name.
    receipt_topic:
        Fully-qualified topic for receipt envelopes on allow. ``None``
        disables receipt publishing.
    dlq_topic:
        Fully-qualified topic for DLQ envelopes on deny. ``None``
        disables DLQ publishing; the outcome still carries the record.
    max_in_flight:
        Concurrency cap. Pub/Sub flow control is typically at the
        subscriber level; this is a second line of defence for sidecar
        traffic.
    deny_strategy:
        ``"ack"`` (default) publishes the Chio DLQ envelope then acks.
        ``"nack"`` skips the Chio DLQ publish and nacks so Pub/Sub's
        native dead-letter policy handles it. Doing both would loop:
        each redelivery re-evaluates, re-publishes, and nacks again.
    handler_error_strategy:
        ``"nack"`` (default) triggers Pub/Sub redelivery. ``"ack"``
        treats the failure as terminal.
    on_sidecar_error:
        ``"raise"`` (default) propagates ChioStreamingError. ``"deny"``
        synthesises a deny receipt and routes through the DLQ
        (fail-closed).
    """

    capability_id: str
    tool_server: str
    subscription: str
    scope_map: Mapping[str, str] = field(default_factory=dict)
    receipt_topic: str | None = None
    dlq_topic: str | None = None
    max_in_flight: int = 64
    deny_strategy: DenyStrategy = "ack"
    handler_error_strategy: HandlerErrorStrategy = "nack"
    on_sidecar_error: SidecarErrorBehaviour = "raise"

    def __post_init__(self) -> None:
        if not self.capability_id:
            raise ChioStreamingConfigError("ChioPubSubConfig.capability_id must be non-empty")
        if not self.tool_server:
            raise ChioStreamingConfigError("ChioPubSubConfig.tool_server must be non-empty")
        if not self.subscription:
            raise ChioStreamingConfigError("ChioPubSubConfig.subscription must be non-empty")
        if self.max_in_flight < 1:
            raise ChioStreamingConfigError("ChioPubSubConfig.max_in_flight must be >= 1")
        if self.deny_strategy not in ("ack", "nack"):
            raise ChioStreamingConfigError("deny_strategy must be 'ack' or 'nack'")
        if self.handler_error_strategy not in ("nack", "ack"):
            raise ChioStreamingConfigError("handler_error_strategy must be 'nack' or 'ack'")
        if self.on_sidecar_error not in ("raise", "deny"):
            raise ChioStreamingConfigError("on_sidecar_error must be 'raise' or 'deny'")


@dataclass
class PubSubProcessingOutcome(BaseProcessingOutcome):
    """Result of processing a single Pub/Sub message."""

    message: PubSubMessageLike | None = None
    subject: str = ""


class ChioPubSubMiddleware:
    """Chio-governed dispatcher for Pub/Sub messages.

    .. code-block:: python

        mw = ChioPubSubMiddleware(
            publisher=pubsub_v1.PublisherClient(),
            chio_client=chio_client,
            dlq_router=DLQRouter(default_topic="projects/p/topics/chio-dlq"),
            config=ChioPubSubConfig(...),
        )

        def callback(message: Message) -> None:
            asyncio.run(mw.dispatch(message, handler=handle_task))

        subscriber.subscribe(subscription, callback=callback).result()

    Async-native callers skip the ``asyncio.run`` hop.
    """

    def __init__(
        self,
        *,
        publisher: PubSubPublisherLike,
        chio_client: ChioClientLike,
        dlq_router: DLQRouter,
        config: ChioPubSubConfig,
    ) -> None:
        if publisher is None:
            raise ChioStreamingConfigError("publisher is required")
        if chio_client is None:
            raise ChioStreamingConfigError("chio_client is required")
        if dlq_router is None:
            raise ChioStreamingConfigError("dlq_router is required")
        self._publisher = publisher
        self._chio_client = chio_client
        self._dlq_router = dlq_router
        self._config = config
        self._slots = Slots(config.max_in_flight)

    @property
    def config(self) -> ChioPubSubConfig:
        return self._config

    @property
    def in_flight(self) -> int:
        return self._slots.in_flight

    async def dispatch(
        self,
        message: PubSubMessageLike,
        handler: MessageHandler,
    ) -> PubSubProcessingOutcome:
        """Evaluate ``message`` and drive publish / ack side effects.

        Allow + success: publish receipt, ack source.
        Allow + handler error: nack (or ack) source, no receipt.
        Deny: publish DLQ + ack, or nack-only (``deny_strategy``).
        Sidecar failure: re-raises unless ``on_sidecar_error="deny"``.
        """
        await self._slots.acquire()
        try:
            return await self._process(message, handler)
        finally:
            self._slots.release()

    async def _process(
        self,
        message: PubSubMessageLike,
        handler: MessageHandler,
    ) -> PubSubProcessingOutcome:
        # Derive request_id from the broker's message identity so a
        # redelivery after a failed ack produces a byte-identical
        # receipt. message_id is only unique per topic, so namespace
        # with the subscription path; otherwise a shared receipt/DLQ
        # stream consuming from multiple subscriptions could collapse
        # genuinely distinct events. Fall back to a UUID only for the
        # defensive case where message_id is empty (should not happen
        # with the official client).
        if message.message_id:
            request_id = (
                f"chio-pubsub-{self._config.subscription}-{message.message_id}"
            )
        else:
            request_id = new_request_id("chio-pubsub")
        subject = self._subject_for(message)
        tool_name = resolve_scope(scope_map=self._config.scope_map, subject=subject)
        parameters = self._parameters_for(
            message=message,
            subject=subject,
            request_id=request_id,
        )

        try:
            receipt = await evaluate_with_chio(
                chio_client=self._chio_client,
                capability_id=self._config.capability_id,
                tool_server=self._config.tool_server,
                tool_name=tool_name,
                parameters=parameters,
                failure_context={
                    "topic": subject,
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
                return await self._handle_deny(
                    message=message,
                    subject=subject,
                    receipt=receipt,
                    request_id=request_id,
                )
            raise
        if not receipt.is_allowed:
            return await self._handle_deny(
                message=message,
                subject=subject,
                receipt=receipt,
                request_id=request_id,
            )
        return await self._handle_allow(
            message=message,
            subject=subject,
            receipt=receipt,
            request_id=request_id,
            handler=handler,
        )

    async def _handle_allow(
        self,
        *,
        message: PubSubMessageLike,
        subject: str,
        receipt: ChioReceipt,
        request_id: str,
        handler: MessageHandler,
    ) -> PubSubProcessingOutcome:
        envelope = build_envelope(
            request_id=request_id,
            receipt=receipt,
            source_topic=subject,
        )
        # handler_error_strategy applies to handler failures only. Receipt
        # publish and ack errors are infrastructure failures; they
        # propagate so Pub/Sub redelivers instead of handler_error_strategy
        # silently acking the source without a receipt.
        try:
            await invoke_handler(handler, message, receipt)
        except Exception as exc:
            if self._config.handler_error_strategy == "ack":
                message.ack()
                acked = True
            else:
                message.nack()
                acked = False
            logger.warning(
                "chio-pubsub: handler raised for subject=%s request_id=%s; redelivery via %s: %s",
                subject,
                request_id,
                self._config.handler_error_strategy,
                exc,
            )
            return PubSubProcessingOutcome(
                allowed=True,
                receipt=receipt,
                request_id=request_id,
                message=message,
                subject=subject,
                acked=acked,
                handler_error=exc,
            )

        if self._config.receipt_topic is not None:
            await self._publish_envelope(self._config.receipt_topic, envelope)
        message.ack()
        return PubSubProcessingOutcome(
            allowed=True,
            receipt=receipt,
            request_id=request_id,
            message=message,
            subject=subject,
            acked=True,
        )

    async def _handle_deny(
        self,
        *,
        message: PubSubMessageLike,
        subject: str,
        receipt: ChioReceipt,
        request_id: str,
    ) -> PubSubProcessingOutcome:
        body = message.data or b""
        record = self._dlq_router.build_record(
            source_topic=subject or "unknown",
            source_partition=None,
            source_offset=None,
            original_key=message.message_id.encode("utf-8") if message.message_id else None,
            original_value=body if body else None,
            request_id=request_id,
            receipt=receipt,
            extra_metadata={
                "pubsub_message_id": message.message_id,
                "pubsub_ordering_key": message.ordering_key,
            },
        )
        if self._config.deny_strategy == "nack":
            # Native Pub/Sub DLQ policy owns redelivery and
            # dead-lettering; publishing our DLQ here would loop.
            message.nack()
            acked = False
        else:
            if self._config.dlq_topic is not None:
                await self._publish_dlq(self._config.dlq_topic, record)
            message.ack()
            acked = True
        return PubSubProcessingOutcome(
            allowed=False,
            receipt=receipt,
            request_id=request_id,
            message=message,
            subject=subject,
            dlq_record=record,
            acked=acked,
        )

    async def _publish_envelope(self, topic: str, envelope: ReceiptEnvelope) -> None:
        attrs = _envelope_attributes(envelope)
        future = self._publisher.publish(topic, envelope.value, **attrs)
        await _await_publish_result(future)

    async def _publish_dlq(self, topic: str, record: DLQRecord) -> None:
        attrs = _record_attributes(record)
        future = self._publisher.publish(topic, record.value, **attrs)
        await _await_publish_result(future)

    def _subject_for(self, message: PubSubMessageLike) -> str:
        """Resolve the Chio scope subject.

        Order: ``X-Chio-Subject`` attribute, ``subject`` attribute,
        configured subscription name.
        """
        attrs = message.attributes or {}
        subject = attrs.get("X-Chio-Subject") or attrs.get("subject")
        if subject:
            return str(subject)
        return self._config.subscription

    def _parameters_for(
        self,
        *,
        message: PubSubMessageLike,
        subject: str,
        request_id: str,
    ) -> dict[str, Any]:
        attrs = normalise_headers(message.attributes)
        body = message.data or b""
        return {
            "request_id": request_id,
            "subject": subject,
            "subscription": self._config.subscription,
            "message_id": message.message_id,
            "ordering_key": message.ordering_key,
            "attributes": attrs,
            "body_length": len(body),
            "body_hash": hash_body(body),
        }


async def _await_publish_result(future: Any) -> Any:
    """Resolve a publish result whether future or awaitable.

    The sync client returns a ``concurrent.futures.Future`` whose
    blocking ``result()`` is offloaded to the default executor so the
    event loop does not stall. Coroutines pass straight through.
    """
    if hasattr(future, "__await__"):
        return await future
    result_attr = getattr(future, "result", None)
    if callable(result_attr):
        import asyncio

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, result_attr)
    return future


def _envelope_attributes(envelope: ReceiptEnvelope) -> dict[str, str]:
    """Project envelope headers onto Pub/Sub attributes."""
    out = {name: str(stringify_header_value(value)) for name, value in envelope.headers}
    out["X-Chio-Request-Id"] = envelope.request_id
    return out


def _record_attributes(record: DLQRecord) -> dict[str, str]:
    """Project DLQ record headers onto Pub/Sub attributes."""
    return {name: str(stringify_header_value(value)) for name, value in record.headers}


def build_pubsub_middleware(
    *,
    publisher: PubSubPublisherLike,
    chio_client: ChioClientLike,
    config: ChioPubSubConfig,
    dlq_router: DLQRouter | None = None,
    dlq_fallback_topic: str | None = None,
) -> ChioPubSubMiddleware:
    """Construct the middleware with an explicit :class:`DLQRouter`.

    One of ``dlq_router`` or ``dlq_fallback_topic`` is required
    (fail-closed: no hard-coded default). ``dlq_fallback_topic`` is
    the router's tag on the denial envelope, distinct from
    ``config.dlq_topic`` which is the Pub/Sub topic
    ``PublisherClient.publish`` targets.
    """
    if dlq_router is None:
        if not dlq_fallback_topic:
            raise ChioStreamingConfigError(
                "build_pubsub_middleware requires dlq_router or dlq_fallback_topic"
            )
        dlq_router = DLQRouter(default_topic=dlq_fallback_topic)
    return ChioPubSubMiddleware(
        publisher=publisher,
        chio_client=chio_client,
        dlq_router=dlq_router,
        config=config,
    )


__all__ = [
    "ChioPubSubConfig",
    "ChioPubSubMiddleware",
    "DenyStrategy",
    "HandlerErrorStrategy",
    "PubSubMessageLike",
    "PubSubProcessingOutcome",
    "PubSubPublisherLike",
    "SidecarErrorBehaviour",
    "build_pubsub_middleware",
]
