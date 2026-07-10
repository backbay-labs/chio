"""Chio-governed Kafka consumer middleware.

EOS v2 transactional: a single Kafka transaction wraps the offset
commit plus the receipt produce (allow) or DLQ produce (deny). Abort
rolls back both. Atomicity covers Kafka state only; external handler
side-effects need the outbox pattern. Cross-cluster DLQ topics break
EOS; keep DLQ on the source cluster.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal, Protocol, runtime_checkable

# Explicit dep marker for chio-adapter-base. Every broker middleware's
# `_parameters_for` already returns metadata only (subject/topic, headers,
# body_length, body_hash) and never forwards the message body, so no per-
# call redaction is needed today. This import guards against the dep being
# silently dropped if a future broker forwards bodies and needs to wire
# `redact_args` in. See CHANGELOG [0.2.1] for the audit-table rationale.
from chio_adapter_base.redact import (  # noqa: F401
    RedactionPolicy,
    redact_args,
)
from chio_sdk.models import ChioReceipt

from chio_streaming.core import (
    BaseProcessingOutcome,
    ChioClientLike,
    Slots,
    evaluate_with_chio,
    invoke_handler,
    resolve_scope,
    synthesize_deny_receipt,
)
from chio_streaming.core import hash_body as _hash_body
from chio_streaming.core import new_request_id as _new_request_id
from chio_streaming.core import normalise_headers as _normalise_headers
from chio_streaming.dlq import DLQRecord, DLQRouter
from chio_streaming.errors import ChioStreamingConfigError, ChioStreamingError
from chio_streaming.receipt import (
    ReceiptEnvelope,
    build_envelope,
)

if TYPE_CHECKING:  # pragma: no cover - typing-only imports
    from chio_sdk.client import ChioClient

logger = logging.getLogger(__name__)


@runtime_checkable
class KafkaMessageLike(Protocol):
    """The ``confluent_kafka.Message`` surface the middleware reads."""

    def error(self) -> Any | None: ...
    def topic(self) -> str | None: ...
    def partition(self) -> int | None: ...
    def offset(self) -> int | None: ...
    def key(self) -> bytes | None: ...
    def value(self) -> bytes | None: ...
    def headers(self) -> list[tuple[str, bytes]] | None: ...


@runtime_checkable
class KafkaConsumerLike(Protocol):
    """The ``confluent_kafka.Consumer`` surface the middleware drives."""

    def poll(self, timeout: float) -> KafkaMessageLike | None: ...
    def commit(
        self,
        *,
        message: KafkaMessageLike | None = ...,
        asynchronous: bool = ...,
    ) -> Any: ...
    def close(self) -> None: ...


@runtime_checkable
class KafkaProducerLike(Protocol):
    """The ``confluent_kafka.Producer`` surface the middleware drives.

    Transactional methods are optional; the middleware falls back to
    non-transactional produce + commit when
    :class:`ChioConsumerConfig.transactional` is ``False``.
    """

    def produce(
        self,
        topic: str,
        value: bytes | None = ...,
        key: bytes | None = ...,
        headers: list[tuple[str, bytes]] | None = ...,
    ) -> None: ...

    def flush(self, timeout: float = ...) -> int: ...


@dataclass
class ChioConsumerConfig:
    """Configuration for :class:`ChioConsumerMiddleware`.

    Attributes
    ----------
    capability_id:
        Capability token id passed to the sidecar on every evaluation.
        Scoped to the consumer group.
    tool_server:
        Chio tool-server id for the Kafka cluster or logical bus.
    scope_map:
        Per-topic override of the Chio ``tool_name``. Falls back to
        ``events:consume:{topic}``.
    receipt_topic:
        Kafka topic to publish the receipt envelope to on allow.
        Required when ``transactional=True``.
    transactional:
        When ``True`` (default), the middleware drives a transactional
        producer; the caller must have already called
        ``Producer.init_transactions()``. When ``False`` the receipt /
        DLQ record is produced non-transactionally and the consumer
        offset is committed separately (at-least-once).
    max_in_flight:
        Concurrency cap. When exceeded, ``poll()`` blocks until a
        previous call completes. Defaults to 64.
    poll_timeout:
        Default timeout (seconds) passed to ``Consumer.poll``.
    produce_timeout:
        Timeout (seconds) for ``Producer.flush`` / transactional commit.
    transaction_timeout:
        Timeout (seconds) for ``begin_transaction`` /
        ``commit_transaction`` / ``send_offsets_to_transaction``.
    consumer_group_id:
        Group id used for ``send_offsets_to_transaction``. Required
        when ``transactional=True``.
    on_sidecar_error:
        ``"raise"`` (default) propagates :class:`ChioStreamingError`
        so Kafka redelivers. ``"deny"`` synthesises a deny receipt and
        routes through the DLQ (fail-closed). Only valid with
        ``transactional=False``; the transactional commit path cannot
        safely downgrade to a synthesised deny.
    """

    capability_id: str
    tool_server: str
    scope_map: Mapping[str, str] = field(default_factory=dict)
    receipt_topic: str | None = None
    transactional: bool = True
    max_in_flight: int = 64
    poll_timeout: float = 1.0
    produce_timeout: float = 10.0
    transaction_timeout: float = 10.0
    consumer_group_id: str | None = None
    on_sidecar_error: Literal["raise", "deny"] = "raise"

    def __post_init__(self) -> None:
        if not self.capability_id:
            raise ChioStreamingConfigError(
                "ChioConsumerConfig.capability_id must be a non-empty string"
            )
        if not self.tool_server:
            raise ChioStreamingConfigError(
                "ChioConsumerConfig.tool_server must be a non-empty string"
            )
        if self.max_in_flight < 1:
            raise ChioStreamingConfigError("ChioConsumerConfig.max_in_flight must be >= 1")
        if self.on_sidecar_error not in ("raise", "deny"):
            raise ChioStreamingConfigError("on_sidecar_error must be 'raise' or 'deny'")
        if self.on_sidecar_error == "deny" and self.transactional:
            raise ChioStreamingConfigError(
                "on_sidecar_error='deny' is only supported with transactional=False; "
                "the transactional commit path cannot safely synthesise a deny receipt"
            )
        if self.transactional:
            if not self.receipt_topic:
                raise ChioStreamingConfigError(
                    "ChioConsumerConfig.receipt_topic is required when transactional=True"
                )
            if not self.consumer_group_id:
                raise ChioStreamingConfigError(
                    "ChioConsumerConfig.consumer_group_id is required when transactional=True"
                )


@dataclass
class ProcessingOutcome(BaseProcessingOutcome):
    """Result of processing a single Kafka message.

    Attributes
    ----------
    allowed:
        ``True`` if Chio allowed and the handler ran successfully.
    receipt:
        The Chio receipt (allow or deny).
    request_id:
        Synthesised request id used for the evaluation.
    message:
        The originating Kafka message.
    dlq_record:
        Populated on deny with the DLQ record that was published.
    acked:
        ``True`` if the offset was committed; ``False`` if the
        transaction aborted. Alias: :attr:`committed`.
    handler_error:
        Populated when the handler raised; the transaction was aborted
        and the offset is uncommitted.
    """

    # dataclass field-order rule: base fields have defaults, so this must too.
    message: KafkaMessageLike | None = None

    @property
    def committed(self) -> bool:
        """Backward-compat alias for :attr:`acked` (old Kafka-only name)."""
        return self.acked


MessageHandler = Callable[[KafkaMessageLike, ChioReceipt], Awaitable[None] | None]
"""Application callback invoked on allow. Sync or async."""


class ChioConsumerMiddleware:
    """Chio-governed wrapper around a confluent-kafka Consumer.

    Parameters
    ----------
    consumer:
        The confluent-kafka ``Consumer`` (or duck-typed double). The
        middleware owns the poll/commit loop; subscription management
        is the caller's.
    producer:
        ``Producer`` for receipts and DLQ. When
        ``config.transactional=True`` it must already be initialised
        via ``init_transactions()``.
    chio_client:
        :class:`chio_sdk.client.ChioClient` (or compatible mock). The
        middleware does not own its lifecycle.
    dlq_router:
        :class:`DLQRouter` for denied events.
    config:
        :class:`ChioConsumerConfig`.
    """

    def __init__(
        self,
        *,
        consumer: KafkaConsumerLike,
        producer: KafkaProducerLike,
        chio_client: ChioClientLike,
        dlq_router: DLQRouter,
        config: ChioConsumerConfig,
    ) -> None:
        if consumer is None:
            raise ChioStreamingConfigError("consumer is required")
        if producer is None:
            raise ChioStreamingConfigError("producer is required")
        if chio_client is None:
            raise ChioStreamingConfigError("chio_client is required")
        if dlq_router is None:
            raise ChioStreamingConfigError("dlq_router is required")

        self._consumer = consumer
        self._producer = producer
        self._chio_client = chio_client
        self._dlq_router = dlq_router
        self._config = config
        self._closed = False
        self._slots = Slots(self._config.max_in_flight)

    @property
    def config(self) -> ChioConsumerConfig:
        return self._config

    @property
    def in_flight(self) -> int:
        return self._slots.in_flight

    def close(self) -> None:
        """Close the underlying Kafka consumer. Idempotent."""
        if self._closed:
            return
        self._closed = True
        try:
            self._consumer.close()
        except Exception:  # noqa: BLE001 - close is best-effort
            logger.exception("chio-streaming: error closing consumer")

    async def poll_and_process(
        self,
        handler: MessageHandler,
        *,
        timeout: float | None = None,
    ) -> ProcessingOutcome | None:
        """Poll one message, evaluate via Chio, dispatch.

        Allow + success: receipt produced and offset committed in one
        transaction. Allow + handler error: transaction aborted. Deny:
        DLQ produced + offset committed in one transaction. Returns
        ``None`` on poll timeout or broker error.
        """
        if self._closed:
            raise ChioStreamingError("cannot poll a closed Chio consumer middleware")
        poll_timeout = self._config.poll_timeout if timeout is None else timeout
        message = self._consumer.poll(poll_timeout)
        if message is None:
            return None
        err = message.error()
        if err is not None:
            # Let the caller handle broker-level errors; Chio only
            # governs application-payload events.
            logger.warning("chio-streaming: consumer error: %s", err)
            return None

        await self._acquire_slot()
        try:
            return await self._process_message(message, handler)
        finally:
            self._release_slot()

    async def _process_message(
        self,
        message: KafkaMessageLike,
        handler: MessageHandler,
    ) -> ProcessingOutcome:
        topic = message.topic() or ""
        # Derive request_id from (topic, partition, offset) so non-transactional
        # consumers that redeliver between produce and commit still collide on
        # the same request_id, honouring the README dedupe contract. In
        # transactional=True mode the EOS commit prevents redelivery, so the
        # derivation is redundant there.
        partition = message.partition()
        offset = message.offset()
        if partition is not None and offset is not None:
            request_id = f"chio-kafka-{topic}-{partition}-{offset}"
        else:
            request_id = _new_request_id("chio-kafka")
        tool_name = resolve_scope(scope_map=self._config.scope_map, subject=topic)
        parameters = self._parameters_for(message, request_id=request_id)

        try:
            receipt = await evaluate_with_chio(
                chio_client=self._chio_client,
                capability_id=self._config.capability_id,
                tool_server=self._config.tool_server,
                tool_name=tool_name,
                parameters=parameters,
                failure_context={
                    "topic": topic,
                    "partition": message.partition(),
                    "offset": message.offset(),
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
                return self._handle_deny(
                    message=message,
                    receipt=receipt,
                    request_id=request_id,
                )
            raise

        if not receipt.is_allowed:
            return self._handle_deny(
                message=message,
                receipt=receipt,
                request_id=request_id,
            )
        return await self._handle_allow(
            message=message,
            receipt=receipt,
            request_id=request_id,
            handler=handler,
        )

    async def _handle_allow(
        self,
        *,
        message: KafkaMessageLike,
        receipt: ChioReceipt,
        request_id: str,
        handler: MessageHandler,
    ) -> ProcessingOutcome:
        """Run the handler and commit atomically on success."""
        envelope = build_envelope(
            request_id=request_id,
            receipt=receipt,
            source_topic=message.topic(),
            source_partition=message.partition(),
            source_offset=message.offset(),
        )

        self._begin_transaction()
        handler_error: Exception | None = None
        committed = False
        try:
            try:
                await invoke_handler(handler, message, receipt)
                if self._config.receipt_topic is not None:
                    self._produce_envelope(self._config.receipt_topic, envelope)
                self._commit_transaction(message)
                committed = True
            except Exception as exc:
                handler_error = exc
                self._abort_transaction_safely()
        finally:
            # BaseException (SystemExit, KeyboardInterrupt,
            # CancelledError) bypasses the Exception handler above; the
            # transaction must still be aborted so the producer is not
            # left with an open tx that fences the next begin.
            if not committed and handler_error is None:
                self._abort_transaction_safely()
        acked = committed

        if handler_error is not None:
            logger.warning(
                "chio-streaming: handler raised for topic=%s offset=%s; aborted transaction: %s",
                message.topic(),
                message.offset(),
                handler_error,
            )

        return ProcessingOutcome(
            allowed=True,
            receipt=receipt,
            request_id=request_id,
            message=message,
            dlq_record=None,
            acked=acked,
            handler_error=handler_error,
        )

    def _handle_deny(
        self,
        *,
        message: KafkaMessageLike,
        receipt: ChioReceipt,
        request_id: str,
    ) -> ProcessingOutcome:
        """Publish the DLQ envelope and commit offset atomically."""
        record = self._dlq_router.build_record(
            source_topic=message.topic() or "",
            source_partition=message.partition(),
            source_offset=message.offset(),
            original_key=message.key(),
            original_value=message.value(),
            request_id=request_id,
            receipt=receipt,
        )

        self._begin_transaction()
        acked = False
        needs_abort = True
        try:
            try:
                self._produce_dlq(record)
                self._commit_transaction(message)
                acked = True
                needs_abort = False
            except Exception:
                self._abort_transaction_safely()
                needs_abort = False
                raise
        finally:
            # Only BaseException (SystemExit / CancelledError) reaches
            # here without having run the Exception branch; abort so
            # the producer does not fence the next begin. The flag
            # guards against a double-abort on ordinary Exceptions.
            if needs_abort:
                self._abort_transaction_safely()
        return ProcessingOutcome(
            allowed=False,
            receipt=receipt,
            request_id=request_id,
            message=message,
            dlq_record=record,
            acked=acked,
        )

    def _begin_transaction(self) -> None:
        """Begin a Kafka transaction (no-op when non-transactional)."""
        if not self._config.transactional:
            return
        begin = getattr(self._producer, "begin_transaction", None)
        if begin is None:
            raise ChioStreamingConfigError(
                "transactional=True but producer has no begin_transaction() "
                "method; make sure init_transactions() was called on a "
                "transactional confluent-kafka Producer"
            )
        begin()

    def _commit_transaction(self, message: KafkaMessageLike) -> None:
        """Send offsets and commit the transaction (or commit directly)."""
        if not self._config.transactional:
            # confluent-kafka's flush() returns the number of messages still
            # in the queue when the timeout elapses; committing the source
            # offset before the receipt/DLQ envelope is durably delivered
            # would silently lose the audit record. Raise so the caller's
            # try/except keeps the source offset uncommitted and Kafka
            # redelivers on the next poll.
            still_queued = self._producer.flush(self._config.produce_timeout)
            if still_queued:
                raise ChioStreamingError(
                    "Kafka flush left "
                    f"{still_queued} envelope(s) undelivered before non-"
                    "transactional offset commit; refusing to ack source",
                    topic=message.topic(),
                    partition=message.partition(),
                    offset=message.offset(),
                )
            self._consumer.commit(message=message, asynchronous=False)
            return

        # Send the offset inside the transaction so produce + offset
        # commit together. confluent-kafka expects the *next* offset
        # to consume (current + 1).
        topic = message.topic() or ""
        partition = message.partition() or 0
        offset = message.offset()
        if offset is None:
            raise ChioStreamingError(
                "cannot commit transaction for message without an offset",
                topic=topic,
                partition=partition,
            )
        next_offset = int(offset) + 1

        topic_partition = _build_topic_partition(topic, partition, next_offset)
        consumer_group_metadata = _consumer_group_metadata(
            consumer=self._consumer,
            fallback_group_id=self._config.consumer_group_id,
        )

        send_offsets = getattr(self._producer, "send_offsets_to_transaction", None)
        commit = getattr(self._producer, "commit_transaction", None)
        if send_offsets is None or commit is None:
            raise ChioStreamingConfigError(
                "transactional=True but producer is missing "
                "send_offsets_to_transaction / commit_transaction"
            )
        send_offsets(
            [topic_partition],
            consumer_group_metadata,
            self._config.transaction_timeout,
        )
        commit(self._config.transaction_timeout)

    def _abort_transaction_safely(self) -> None:
        """Call ``abort_transaction``; swallow absence and errors."""
        if not self._config.transactional:
            return
        abort = getattr(self._producer, "abort_transaction", None)
        if abort is None:
            logger.warning(
                "chio-streaming: producer has no abort_transaction(); commit may be non-atomic"
            )
            return
        try:
            abort(self._config.transaction_timeout)
        except Exception:  # noqa: BLE001 - abort must not mask the cause
            logger.exception("chio-streaming: abort_transaction raised; swallowing")

    def _produce_envelope(self, topic: str, envelope: ReceiptEnvelope) -> None:
        self._producer.produce(
            topic,
            value=envelope.value,
            key=envelope.key,
            headers=list(envelope.headers),
        )

    def _produce_dlq(self, record: DLQRecord) -> None:
        self._producer.produce(
            record.topic,
            value=record.value,
            key=record.key,
            headers=list(record.headers),
        )

    def _parameters_for(
        self,
        message: KafkaMessageLike,
        *,
        request_id: str,
    ) -> dict[str, Any]:
        # Body is not forwarded; policies evaluate on headers +
        # metadata. Guards that need the body re-hash using body_hash.
        header_dict = _normalise_headers(message.headers())
        key_bytes = message.key()
        key_repr: str | None
        if key_bytes is None:
            key_repr = None
        else:
            try:
                key_repr = key_bytes.decode("utf-8")
            except UnicodeDecodeError:
                key_repr = key_bytes.hex()
        body = message.value() or b""
        return {
            "request_id": request_id,
            "topic": message.topic(),
            "partition": message.partition(),
            "offset": message.offset(),
            "key": key_repr,
            "headers": header_dict,
            "body_length": len(body),
            "body_hash": _hash_body(body),
        }

    async def _acquire_slot(self) -> None:
        await self._slots.acquire()

    def _release_slot(self) -> None:
        self._slots.release()


def _build_topic_partition(topic: str, partition: int, offset: int) -> Any:
    """Build a TopicPartition for the producer's transaction API.

    Lazy import keeps the module usable for type-checking without
    confluent-kafka installed and lets tests skip this path via mocks.
    """
    try:
        from confluent_kafka import TopicPartition
    except ImportError:
        return _TopicPartition(topic=topic, partition=int(partition), offset=int(offset))
    return TopicPartition(topic=topic, partition=int(partition), offset=int(offset))


@dataclass(frozen=True)
class _TopicPartition:
    topic: str
    partition: int
    offset: int


def _consumer_group_metadata(
    *,
    consumer: KafkaConsumerLike,
    fallback_group_id: str | None,
) -> Any:
    """Fetch consumer group metadata for ``send_offsets_to_transaction``.

    Real confluent-kafka consumers expose ``consumer_group_metadata()``
    returning an opaque object. Mocks without it fall back to the plain
    group id string; the real client rejects that but test doubles
    accept it.
    """
    getter = getattr(consumer, "consumer_group_metadata", None)
    if getter is not None:
        return getter()
    if fallback_group_id is None:
        raise ChioStreamingConfigError(
            "consumer has no consumer_group_metadata() and no "
            "consumer_group_id fallback is configured"
        )
    return fallback_group_id


def build_middleware(
    *,
    consumer: KafkaConsumerLike,
    producer: KafkaProducerLike,
    chio_client: ChioClient | ChioClientLike,
    config: ChioConsumerConfig,
    dlq_router: DLQRouter | None = None,
    dlq_topic: str | None = None,
) -> ChioConsumerMiddleware:
    """Construct the middleware with a default :class:`DLQRouter`.

    Pass ``dlq_router`` for explicit routing or ``dlq_topic`` for a
    single default topic.
    """
    if dlq_router is None:
        if not dlq_topic:
            raise ChioStreamingConfigError("build_middleware requires dlq_router or dlq_topic")
        dlq_router = DLQRouter(default_topic=dlq_topic)
    return ChioConsumerMiddleware(
        consumer=consumer,
        producer=producer,
        chio_client=chio_client,
        dlq_router=dlq_router,
        config=config,
    )


__all__ = [
    "ChioClientLike",
    "ChioConsumerConfig",
    "ChioConsumerMiddleware",
    "KafkaConsumerLike",
    "KafkaMessageLike",
    "KafkaProducerLike",
    "MessageHandler",
    "ProcessingOutcome",
    "build_middleware",
]
