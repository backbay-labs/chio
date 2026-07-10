"""Redis Streams consumer-group middleware.

XADD-then-XACK, not atomic. A crash between the two leaves the source
entry in the PEL for ``XCLAIM`` / ``XAUTOCLAIM`` redelivery and costs
at worst a duplicate receipt or DLQ entry; downstream consumers must
dedupe on ``request_id``. Entries are ``{field: value}`` maps, treated
as the canonical payload for hashing and DLQ redrive.
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
    Slots,
    evaluate_with_chio,
    hash_body,
    invoke_handler,
    resolve_scope,
    synthesize_deny_receipt,
)
from chio_streaming.dlq import DLQRecord, DLQRouter
from chio_streaming.errors import ChioStreamingConfigError, ChioStreamingError
from chio_streaming.receipt import ReceiptEnvelope, build_envelope

logger = logging.getLogger(__name__)

DenyStrategy = Literal["ack", "keep"]
HandlerErrorStrategy = Literal["keep", "ack"]
SidecarErrorBehaviour = Literal["raise", "deny"]


@runtime_checkable
class RedisStreamsClientLike(Protocol):
    """The :class:`redis.asyncio.Redis` surface the middleware drives (``xadd`` / ``xack``).

    Callers own the ``XREADGROUP`` loop so fetching, blocking, and
    flow control stay in their hands.
    """

    async def xadd(
        self,
        name: str,
        fields: Mapping[str | bytes, str | bytes],
        id: str | bytes = ...,
        maxlen: int | None = ...,
        approximate: bool = ...,
    ) -> bytes: ...

    async def xack(
        self,
        name: str,
        groupname: str,
        *ids: str | bytes,
    ) -> int: ...


@dataclass
class ChioRedisStreamsConfig:
    """Configuration for :class:`ChioRedisStreamsMiddleware`.

    Attributes
    ----------
    capability_id:
        Capability token id every evaluation is scoped to.
    tool_server:
        Chio tool-server id for the Redis cluster.
    group_name:
        Consumer group name (passed to ``XACK``). All middleware
        instances sharing a group share the PEL.
    scope_map:
        Per-stream override of the Chio tool name. Falls back to
        ``events:consume:{stream}``.
    receipt_stream:
        Stream ``XADD``'d with receipt envelopes on allow. ``None``
        disables receipt publishing.
    receipt_maxlen:
        Optional ``MAXLEN`` for the receipt stream; paired with
        ``approximate=True`` for low-overhead trimming. ``None`` skips
        trimming (unbounded growth - fine for dev).
    dlq_maxlen:
        Optional ``MAXLEN`` for the DLQ stream.
    approximate_trim:
        Use approximate (``~``) trimming on XADD. Default ``True``;
        Redis's exact trim is rarely worth the cost.
    max_in_flight:
        Concurrency cap for in-flight evaluations.
    deny_strategy:
        ``"ack"`` (default) XACKs after publishing the DLQ envelope.
        ``"keep"`` leaves the entry in the PEL for manual triage via
        ``XAUTOCLAIM`` / ``XPENDING``.
    handler_error_strategy:
        ``"keep"`` (default) leaves the entry in the PEL for
        redelivery. ``"ack"`` XACKs despite the failure and publishes
        a handler-error receipt envelope (requires ``receipt_stream``;
        otherwise the entry would be dropped with no audit trail).
    """

    capability_id: str
    tool_server: str
    group_name: str
    scope_map: Mapping[str, str] = field(default_factory=dict)
    receipt_stream: str | None = None
    receipt_maxlen: int | None = None
    dlq_maxlen: int | None = None
    approximate_trim: bool = True
    max_in_flight: int = 64
    deny_strategy: DenyStrategy = "ack"
    handler_error_strategy: HandlerErrorStrategy = "keep"
    on_sidecar_error: SidecarErrorBehaviour = "raise"

    def __post_init__(self) -> None:
        if not self.capability_id:
            raise ChioStreamingConfigError("ChioRedisStreamsConfig.capability_id must be non-empty")
        if not self.tool_server:
            raise ChioStreamingConfigError("ChioRedisStreamsConfig.tool_server must be non-empty")
        if not self.group_name:
            raise ChioStreamingConfigError("ChioRedisStreamsConfig.group_name must be non-empty")
        if self.max_in_flight < 1:
            raise ChioStreamingConfigError("ChioRedisStreamsConfig.max_in_flight must be >= 1")
        if self.deny_strategy not in ("ack", "keep"):
            raise ChioStreamingConfigError("deny_strategy must be 'ack' or 'keep'")
        if self.handler_error_strategy not in ("keep", "ack"):
            raise ChioStreamingConfigError("handler_error_strategy must be 'keep' or 'ack'")
        if self.on_sidecar_error not in ("raise", "deny"):
            raise ChioStreamingConfigError("on_sidecar_error must be 'raise' or 'deny'")
        if self.handler_error_strategy == "ack" and self.receipt_stream is None:
            raise ChioStreamingConfigError(
                "handler_error_strategy='ack' requires receipt_stream to be "
                "set so a handler-error receipt is still published for audit"
            )


@dataclass
class RedisStreamsProcessingOutcome(BaseProcessingOutcome):
    """Result of processing a single stream entry."""

    stream: str = ""
    entry_id: str = ""


class ChioRedisStreamsMiddleware:
    """Chio-governed dispatcher for Redis Streams consumer-group entries.

    Callers own the ``XREADGROUP`` loop and hand each entry to
    :meth:`dispatch`. The middleware evaluates, runs the handler on
    allow, XADDs the receipt / DLQ envelope, and XACKs the source.
    """

    def __init__(
        self,
        *,
        client: RedisStreamsClientLike,
        chio_client: ChioClientLike,
        dlq_router: DLQRouter,
        config: ChioRedisStreamsConfig,
    ) -> None:
        if client is None:
            raise ChioStreamingConfigError("client is required")
        if chio_client is None:
            raise ChioStreamingConfigError("chio_client is required")
        if dlq_router is None:
            raise ChioStreamingConfigError("dlq_router is required")
        self._client = client
        self._chio_client = chio_client
        self._dlq_router = dlq_router
        self._config = config
        self._slots = Slots(config.max_in_flight)

    @property
    def config(self) -> ChioRedisStreamsConfig:
        return self._config

    @property
    def in_flight(self) -> int:
        return self._slots.in_flight

    async def dispatch(
        self,
        *,
        stream: str,
        entry_id: str,
        fields: Mapping[Any, Any],
        handler: MessageHandler,
    ) -> RedisStreamsProcessingOutcome:
        """Evaluate one stream entry and drive publish / XACK.

        ``fields`` may use ``bytes`` or ``str`` keys and values (the
        async client returns bytes by default); both are normalised
        for the sidecar call while raw bytes are preserved for DLQ
        redrive.

        Allow + success: XADD receipt, XACK source.
        Allow + handler error: leave in PEL (or XACK + error receipt).
        Deny: XADD DLQ, XACK source (or keep in PEL).
        Sidecar failure: re-raises unless ``on_sidecar_error="deny"``.
        """
        await self._slots.acquire()
        try:
            return await self._process(stream, entry_id, fields, handler)
        finally:
            self._slots.release()

    async def _process(
        self,
        stream: str,
        entry_id: str,
        fields: Mapping[Any, Any],
        handler: MessageHandler,
    ) -> RedisStreamsProcessingOutcome:
        # Derive request_id from the stream + entry_id so XCLAIM /
        # XAUTOCLAIM redelivery produces byte-identical receipts. A
        # fresh UUID per delivery would bypass downstream dedupe-by-
        # request-id and cause the signed receipt to diverge.
        request_id = f"chio-redis-{stream}-{entry_id}"
        tool_name = resolve_scope(scope_map=self._config.scope_map, subject=stream)
        normalised_fields = _normalise_fields(fields)
        body = _canonical_fields_bytes(normalised_fields)
        parameters = {
            "request_id": request_id,
            "stream": stream,
            "entry_id": entry_id,
            "group": self._config.group_name,
            "fields": normalised_fields,
            "body_length": len(body),
            "body_hash": hash_body(body),
        }

        try:
            receipt = await evaluate_with_chio(
                chio_client=self._chio_client,
                capability_id=self._config.capability_id,
                tool_server=self._config.tool_server,
                tool_name=tool_name,
                parameters=parameters,
                failure_context={
                    "topic": stream,
                    "offset": entry_id,
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
                    stream=stream,
                    entry_id=entry_id,
                    body=body,
                    receipt=receipt,
                    request_id=request_id,
                )
            raise
        if not receipt.is_allowed:
            return await self._handle_deny(
                stream=stream,
                entry_id=entry_id,
                body=body,
                receipt=receipt,
                request_id=request_id,
            )
        return await self._handle_allow(
            stream=stream,
            entry_id=entry_id,
            fields=fields,
            receipt=receipt,
            request_id=request_id,
            handler=handler,
        )

    async def _handle_allow(
        self,
        *,
        stream: str,
        entry_id: str,
        fields: Mapping[Any, Any],
        receipt: ChioReceipt,
        request_id: str,
        handler: MessageHandler,
    ) -> RedisStreamsProcessingOutcome:
        envelope = build_envelope(
            request_id=request_id,
            receipt=receipt,
            source_topic=stream,
            source_offset=None,
            extra_metadata={"source_entry_id": entry_id},
        )
        # handler_error_strategy applies to handler failures only. Receipt
        # XADD and XACK errors are infrastructure failures; they propagate
        # so Redis can redeliver via XCLAIM / XAUTOCLAIM instead of being
        # silently acked under handler_error_strategy="ack".
        try:
            await invoke_handler(
                handler,
                RedisStreamEntry(stream=stream, entry_id=entry_id, fields=fields),
                receipt,
            )
        except Exception as exc:
            acked = False
            if self._config.handler_error_strategy == "ack":
                # Config requires receipt_stream here so the failure
                # always leaves an audit trail.
                error_envelope = build_envelope(
                    request_id=request_id,
                    receipt=receipt,
                    source_topic=stream,
                    source_offset=None,
                    extra_metadata={
                        "source_entry_id": entry_id,
                        "handler_error": str(exc),
                    },
                )
                assert self._config.receipt_stream is not None
                ack_count = await self._xadd_and_xack(
                    stream=stream,
                    entry_id=entry_id,
                    envelope=error_envelope,
                )
                acked = ack_count > 0
                if not acked:
                    logger.warning(
                        "chio-redis: XACK returned 0 for stream=%s entry_id=%s "
                        "request_id=%s after handler error (claimed elsewhere?)",
                        stream,
                        entry_id,
                        request_id,
                    )
            logger.warning(
                "chio-redis: handler raised for stream=%s entry_id=%s "
                "request_id=%s; strategy=%s: %s",
                stream,
                entry_id,
                request_id,
                self._config.handler_error_strategy,
                exc,
            )
            return RedisStreamsProcessingOutcome(
                allowed=True,
                receipt=receipt,
                request_id=request_id,
                stream=stream,
                entry_id=entry_id,
                acked=acked,
                handler_error=exc,
            )

        if self._config.receipt_stream is not None:
            ack_count = await self._xadd_and_xack(
                stream=stream,
                entry_id=entry_id,
                envelope=envelope,
            )
        else:
            ack_count = await self._xack(stream, entry_id)
        acked = ack_count > 0
        if not acked:
            logger.warning(
                "chio-redis: XACK returned 0 for stream=%s entry_id=%s "
                "request_id=%s (entry claimed by another consumer?)",
                stream,
                entry_id,
                request_id,
            )
        return RedisStreamsProcessingOutcome(
            allowed=True,
            receipt=receipt,
            request_id=request_id,
            stream=stream,
            entry_id=entry_id,
            acked=acked,
        )

    async def _handle_deny(
        self,
        *,
        stream: str,
        entry_id: str,
        body: bytes,
        receipt: ChioReceipt,
        request_id: str,
    ) -> RedisStreamsProcessingOutcome:
        record = self._dlq_router.build_record(
            source_topic=stream,
            source_partition=None,
            source_offset=None,
            original_key=entry_id.encode("utf-8"),
            original_value=body if body else None,
            request_id=request_id,
            receipt=receipt,
            extra_metadata={"redis_entry_id": entry_id, "redis_group": self._config.group_name},
        )
        await self._xadd_dlq(record)
        acked = False
        if self._config.deny_strategy == "ack":
            ack_count = await self._xack(stream, entry_id)
            acked = ack_count > 0
            if not acked:
                logger.warning(
                    "chio-redis: XACK returned 0 on deny for stream=%s "
                    "entry_id=%s request_id=%s (entry claimed elsewhere?)",
                    stream,
                    entry_id,
                    request_id,
                )
        return RedisStreamsProcessingOutcome(
            allowed=False,
            receipt=receipt,
            request_id=request_id,
            stream=stream,
            entry_id=entry_id,
            dlq_record=record,
            acked=acked,
        )

    async def _xadd_envelope(self, stream: str, envelope: ReceiptEnvelope) -> None:
        """XADD the receipt envelope with header fields for discoverability."""
        fields: dict[str | bytes, str | bytes] = {
            "payload": envelope.value,
            "request_id": envelope.request_id,
            "receipt_id": envelope.receipt_id,
        }
        for name, value in envelope.headers:
            fields[name] = value
        await self._xadd(stream, fields, self._config.receipt_maxlen)

    async def _xadd_dlq(self, record: DLQRecord) -> None:
        """XADD the DLQ envelope with header fields for discoverability."""
        fields: dict[str | bytes, str | bytes] = {
            "payload": record.value,
            "key": record.key,
        }
        for name, value in record.headers:
            fields[name] = value
        await self._xadd(record.topic, fields, self._config.dlq_maxlen)

    async def _xadd(
        self,
        stream: str,
        fields: Mapping[str | bytes, str | bytes],
        maxlen: int | None,
    ) -> None:
        """XADD with optional MAXLEN trimming."""
        kwargs: dict[str, Any] = {}
        if maxlen is not None:
            kwargs["maxlen"] = maxlen
            kwargs["approximate"] = self._config.approximate_trim
        try:
            await self._client.xadd(stream, fields, **kwargs)
        except TypeError:
            # Clients without maxlen / approximate fall back to basic.
            await self._client.xadd(stream, fields)

    async def _xack(self, stream: str, entry_id: str) -> int:
        """XACK a single entry; return the ack count.

        ``0`` means the entry was not in the PEL (claimed elsewhere or
        already acked).
        """
        result = await self._client.xack(stream, self._config.group_name, entry_id)
        return int(result or 0)

    async def _xadd_and_xack(
        self,
        *,
        stream: str,
        entry_id: str,
        envelope: ReceiptEnvelope,
    ) -> int:
        """XADD the receipt envelope then XACK the source entry."""
        assert self._config.receipt_stream is not None
        await self._xadd_envelope(self._config.receipt_stream, envelope)
        return await self._xack(stream, entry_id)


@dataclass(frozen=True)
class RedisStreamEntry:
    """``(stream, entry_id, fields)`` view for handlers.

    Stable shape regardless of what the underlying client returned.
    Fields are not eagerly normalised; handlers that want raw bytes
    access ``fields`` directly.
    """

    stream: str
    entry_id: str
    fields: Mapping[Any, Any]


def _normalise_fields(fields: Mapping[Any, Any]) -> dict[str, Any]:
    """Coerce field keys and values to UTF-8 strings for the sidecar.

    redis-py returns bytes by default; string-decoded clients return
    str. Policies see a single string-keyed shape either way.
    """
    out: dict[str, Any] = {}
    for raw_key, raw_value in fields.items():
        key = _maybe_decode(raw_key)
        value = _maybe_decode(raw_value)
        out[str(key)] = value
    return out


def _maybe_decode(value: Any) -> Any:
    if isinstance(value, bytes | bytearray):
        try:
            return bytes(value).decode("utf-8")
        except UnicodeDecodeError:
            return bytes(value).hex()
    return value


def _canonical_fields_bytes(fields: Mapping[str, Any]) -> bytes:
    """Serialise a normalised fields dict deterministically for hashing."""
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def build_redis_streams_middleware(
    *,
    client: RedisStreamsClientLike,
    chio_client: ChioClientLike,
    config: ChioRedisStreamsConfig,
    dlq_router: DLQRouter | None = None,
    dlq_stream: str | None = None,
) -> ChioRedisStreamsMiddleware:
    """Construct the middleware with a default :class:`DLQRouter`.

    Pass ``dlq_router`` for topic-map routing or ``dlq_stream`` for a
    single default stream.
    """
    if dlq_router is None:
        if not dlq_stream:
            raise ChioStreamingConfigError(
                "build_redis_streams_middleware requires dlq_router or dlq_stream"
            )
        dlq_router = DLQRouter(default_topic=dlq_stream)
    return ChioRedisStreamsMiddleware(
        client=client,
        chio_client=chio_client,
        dlq_router=dlq_router,
        config=config,
    )


__all__ = [
    "ChioRedisStreamsConfig",
    "ChioRedisStreamsMiddleware",
    "DenyStrategy",
    "HandlerErrorStrategy",
    "RedisStreamEntry",
    "RedisStreamsClientLike",
    "RedisStreamsProcessingOutcome",
    "SidecarErrorBehaviour",
    "build_redis_streams_middleware",
]
