"""NATS JetStream middleware.

No atomic transactions: the envelope publishes first, ack follows.
A crash between the two redelivers and duplicates the envelope;
downstream consumers must dedupe on ``request_id``.

Deny defaults to ``ack`` (not ``term``) so the source stream cannot
redeliver and re-DLQ. Set ``deny_strategy="term"`` if you want the
JetStream TERM signal instead.
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

DenyStrategy = Literal["ack", "term"]
# NATS spells the redeliver signal "nak" (not "nack"); kept to match upstream.
HandlerErrorStrategy = Literal["nak", "term"]
SidecarErrorBehaviour = Literal["raise", "deny"]

DenyAckStrategy = DenyStrategy
"""Alias for :data:`DenyStrategy` used by NATS acknowledgement settings."""


@runtime_checkable
class NatsMsgLike(Protocol):
    """``nats.aio.msg.Msg`` surface the middleware reads and acks."""

    @property
    def data(self) -> bytes: ...
    @property
    def subject(self) -> str: ...
    @property
    def reply(self) -> str | None: ...
    @property
    def headers(self) -> Mapping[str, str] | None: ...

    async def ack(self) -> None: ...
    async def nak(self, delay: float | None = ...) -> None: ...
    async def term(self) -> None: ...


@runtime_checkable
class JetStreamPublisherLike(Protocol):
    """``nats.js.JetStreamContext.publish`` surface."""

    async def publish(
        self,
        subject: str,
        payload: bytes,
        headers: Mapping[str, str] | None = ...,
    ) -> Any: ...


@dataclass
class ChioNatsConsumerConfig:
    """Configuration for :class:`ChioNatsMiddleware`.

    Attributes
    ----------
    capability_id:
        Capability token id every evaluation is scoped to. Shared
        across all consumers that share a durable.
    tool_server:
        Chio tool-server id representing the NATS cluster / JetStream
        account. Passed to every ``evaluate_tool_call``.
    scope_map:
        Map from NATS subject -> Chio ``tool_name``. A subject like
        ``tasks.research.claim`` that has no explicit entry falls back
        to ``events:consume:tasks.research.claim``.
    receipt_subject:
        JetStream subject to publish the receipt envelope to on allow.
        ``None`` disables receipt publishing entirely (the application
        still gets the in-memory receipt via the handler).
    max_in_flight:
        Caps concurrent evaluations per middleware instance. Mirrors
        the Kafka middleware's backpressure knob.
    deny_strategy:
        ``"ack"`` (default) or ``"term"``. ``"ack"`` marks the deny as
        processed so JetStream does not redeliver; ``"term"`` is
        semantically "abandon this message" -- either is safe once the
        DLQ publish succeeds.
    handler_error_strategy:
        ``"nak"`` (default) or ``"term"``. Determines what happens
        when the application handler raises on the allow path. ``nak``
        asks JetStream to redeliver after ``nack_delay``.
    nack_delay:
        Delay (seconds) passed to ``msg.nak(delay=...)`` when
        ``handler_error_strategy="nak"``. ``None`` uses the stream's
        default backoff.
    on_sidecar_error:
        ``"raise"`` (default) propagates ChioStreamingError when the
        sidecar is unreachable; the caller decides whether to nak/term.
        ``"deny"`` synthesises a deny receipt and routes through the
        normal DLQ path (fail-closed).
    """

    capability_id: str
    tool_server: str
    scope_map: Mapping[str, str] = field(default_factory=dict)
    receipt_subject: str | None = None
    max_in_flight: int = 64
    deny_strategy: DenyStrategy = "ack"
    handler_error_strategy: HandlerErrorStrategy = "nak"
    nack_delay: float | None = None
    on_sidecar_error: SidecarErrorBehaviour = "raise"

    def __post_init__(self) -> None:
        if not self.capability_id:
            raise ChioStreamingConfigError("ChioNatsConsumerConfig.capability_id must be non-empty")
        if not self.tool_server:
            raise ChioStreamingConfigError("ChioNatsConsumerConfig.tool_server must be non-empty")
        if self.max_in_flight < 1:
            raise ChioStreamingConfigError("ChioNatsConsumerConfig.max_in_flight must be >= 1")
        if self.deny_strategy not in ("ack", "term"):
            raise ChioStreamingConfigError("deny_strategy must be 'ack' or 'term'")
        if self.handler_error_strategy not in ("nak", "term"):
            raise ChioStreamingConfigError("handler_error_strategy must be 'nak' or 'term'")
        if self.on_sidecar_error not in ("raise", "deny"):
            raise ChioStreamingConfigError("on_sidecar_error must be 'raise' or 'deny'")


# ---------------------------------------------------------------------------
# Outcome
# ---------------------------------------------------------------------------


@dataclass
class NatsProcessingOutcome(BaseProcessingOutcome):
    """Outcome of processing a single NATS message."""

    message: NatsMsgLike | None = None


class ChioNatsMiddleware:
    """Chio-governed dispatcher for a NATS JetStream subscription.

    Callers own the fetch/subscribe loop; hand each message to
    :meth:`dispatch`.
    """

    def __init__(
        self,
        *,
        publisher: JetStreamPublisherLike,
        chio_client: ChioClientLike,
        dlq_router: DLQRouter,
        config: ChioNatsConsumerConfig,
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
    def config(self) -> ChioNatsConsumerConfig:
        return self._config

    @property
    def in_flight(self) -> int:
        return self._slots.in_flight

    async def dispatch(
        self,
        msg: NatsMsgLike,
        handler: MessageHandler,
    ) -> NatsProcessingOutcome:
        """Evaluate ``msg``, run the handler on allow, and ack/publish.

        Allow + success: receipt published, then ``ack`` (``acked=True``).
        Allow + handler error: no receipt, ``nak`` (or ``term``), ``acked=False``.
        Deny: DLQ envelope published, then ``ack`` (or ``term``).
        Sidecar failure: re-raises unless ``on_sidecar_error="deny"``.
        """
        await self._slots.acquire()
        try:
            return await self._process(msg, handler)
        finally:
            self._slots.release()

    async def _process(
        self,
        msg: NatsMsgLike,
        handler: MessageHandler,
    ) -> NatsProcessingOutcome:
        # Derivation precedence for request_id (each step keeps redeliveries
        # collapsed on the same id so downstream dedupe holds):
        #   1. Nats-Msg-Id header set by a deduping publisher.
        #   2. JetStream stream/consumer sequence from msg.metadata; nats-py
        #      exposes this on every JetStream-pulled Msg even when the
        #      publisher did not set a header.
        #   3. UUID fallback for core-NATS subscribers (no JetStream
        #      metadata) and producers that opted out of message ids.
        request_id = _derive_nats_request_id(msg)
        subject = msg.subject or ""
        tool_name = resolve_scope(scope_map=self._config.scope_map, subject=subject)
        parameters = self._parameters_for(msg, request_id=request_id)

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
                return await self._handle_deny(msg, receipt, request_id)
            raise

        if not receipt.is_allowed:
            return await self._handle_deny(msg, receipt, request_id)
        return await self._handle_allow(msg, receipt, request_id, handler)

    async def _handle_allow(
        self,
        msg: NatsMsgLike,
        receipt: ChioReceipt,
        request_id: str,
        handler: MessageHandler,
    ) -> NatsProcessingOutcome:
        envelope = build_envelope(
            request_id=request_id,
            receipt=receipt,
            source_topic=msg.subject,
        )
        # handler_error_strategy applies to handler failures only. Receipt
        # publish and ack errors are infrastructure failures; they
        # propagate so the caller can nak / retry without being silently
        # reclassified as handler errors.
        try:
            await invoke_handler(handler, msg, receipt)
        except Exception as exc:
            await self._negative_ack(msg)
            # term() terminally settles the message (JetStream drops it,
            # no redelivery); mirrors the deny-term path which also sets
            # acked=True. nak() leaves it pending for redelivery.
            acked = self._config.handler_error_strategy == "term"
            logger.warning(
                "chio-nats: handler raised for subject=%s; redelivered via %s: %s",
                msg.subject,
                self._config.handler_error_strategy,
                exc,
            )
            return NatsProcessingOutcome(
                allowed=True,
                receipt=receipt,
                request_id=request_id,
                message=msg,
                acked=acked,
                handler_error=exc,
            )

        if self._config.receipt_subject is not None:
            await self._publish_envelope(self._config.receipt_subject, envelope)
        await msg.ack()
        return NatsProcessingOutcome(
            allowed=True,
            receipt=receipt,
            request_id=request_id,
            message=msg,
            acked=True,
        )

    async def _handle_deny(
        self,
        msg: NatsMsgLike,
        receipt: ChioReceipt,
        request_id: str,
    ) -> NatsProcessingOutcome:
        record = self._dlq_router.build_record(
            source_topic=msg.subject or "",
            source_partition=None,
            source_offset=None,
            original_key=None,
            original_value=msg.data if msg.data else None,
            request_id=request_id,
            receipt=receipt,
        )
        await self._publish_dlq(record)
        if self._config.deny_strategy == "term":
            await msg.term()
        else:
            await msg.ack()
        return NatsProcessingOutcome(
            allowed=False,
            receipt=receipt,
            request_id=request_id,
            message=msg,
            dlq_record=record,
            acked=True,
        )

    async def _publish_envelope(self, subject: str, envelope: ReceiptEnvelope) -> None:
        # Envelope headers are list[tuple[str, bytes]]; NATS wants
        # Mapping[str, str]. Receipt ids and verdicts are ASCII.
        headers = _bytes_headers_to_str(envelope.headers)
        await self._publisher.publish(subject, envelope.value, headers=headers)

    async def _publish_dlq(self, record: DLQRecord) -> None:
        headers = _bytes_headers_to_str(record.headers)
        await self._publisher.publish(record.topic, record.value, headers=headers)

    async def _negative_ack(self, msg: NatsMsgLike) -> None:
        if self._config.handler_error_strategy == "term":
            await msg.term()
            return
        delay = self._config.nack_delay
        try:
            if delay is None:
                await msg.nak()
            else:
                await msg.nak(delay=delay)
        except TypeError:
            # Older nats-py versions reject the ``delay`` kwarg.
            await msg.nak()

    def _parameters_for(
        self,
        msg: NatsMsgLike,
        *,
        request_id: str,
    ) -> dict[str, Any]:
        # Body is not forwarded; policies evaluate on subject + headers
        # + body_hash. Guards that need the body re-hash using that.
        headers = normalise_headers(msg.headers)
        body = msg.data or b""
        params: dict[str, Any] = {
            "request_id": request_id,
            "subject": msg.subject,
            "headers": headers,
            "body_length": len(body),
            "body_hash": hash_body(body),
        }
        reply = msg.reply
        if reply:
            params["reply"] = reply
        return params


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bytes_headers_to_str(
    headers: list[tuple[str, bytes]],
) -> dict[str, str]:
    """Kafka-shaped ``list[tuple[str, bytes]]`` to NATS-shaped ``dict[str, str]``."""
    return {name: str(stringify_header_value(value)) for name, value in headers}


def _derive_nats_request_id(msg: NatsMsgLike) -> str:
    headers = msg.headers or {}
    msg_id = headers.get("Nats-Msg-Id")
    if msg_id:
        return f"chio-nats-{msg_id}"
    # JetStream Msg.metadata.sequence carries (stream, consumer) seqs.
    # In nats-py `metadata` is a property that raises NotJSMessageError on
    # core-NATS messages (not AttributeError), so getattr's default does not
    # catch it. Treat any exception as "no metadata available" and fall
    # through to the UUID path; request_id derivation is best-effort.
    try:
        metadata = getattr(msg, "metadata", None)
    except Exception:
        metadata = None
    if metadata is not None:
        try:
            sequence = getattr(metadata, "sequence", None)
            stream_seq = (
                getattr(sequence, "stream", None) if sequence is not None else None
            )
            stream_name = getattr(metadata, "stream", "") or ""
        except Exception:
            stream_seq = None
            stream_name = ""
        if stream_seq is not None:
            return f"chio-nats-js-{stream_name}-{stream_seq}"
    return new_request_id("chio-nats")


def build_nats_middleware(
    *,
    publisher: JetStreamPublisherLike,
    chio_client: ChioClientLike,
    config: ChioNatsConsumerConfig,
    dlq_router: DLQRouter | None = None,
    dlq_subject: str | None = None,
) -> ChioNatsMiddleware:
    """Construct the middleware with a ``DLQRouter`` wired up.

    Pass ``dlq_router`` for topic-map routing or ``dlq_subject`` for a
    single default subject.
    """
    if dlq_router is None:
        if not dlq_subject:
            raise ChioStreamingConfigError(
                "build_nats_middleware requires dlq_router or dlq_subject"
            )
        dlq_router = DLQRouter(default_topic=dlq_subject)
    return ChioNatsMiddleware(
        publisher=publisher,
        chio_client=chio_client,
        dlq_router=dlq_router,
        config=config,
    )


__all__ = [
    "ChioNatsConsumerConfig",
    "ChioNatsMiddleware",
    "DenyAckStrategy",
    "DenyStrategy",
    "HandlerErrorStrategy",
    "JetStreamPublisherLike",
    "NatsMsgLike",
    "NatsProcessingOutcome",
    "SidecarErrorBehaviour",
    "build_nats_middleware",
]
