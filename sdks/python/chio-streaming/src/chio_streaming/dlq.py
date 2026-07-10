"""Dead-letter queue routing for Chio-denied Kafka events.

:class:`DLQRouter` decides which Kafka topic to route a denied event
to and decorates the payload with the denial reason, guard, and
:class:`chio_sdk.models.ChioReceipt` that produced the deny verdict.

Routing precedence (highest wins):

1. Exact match on ``topic_map[source_topic]``.
2. ``default_topic`` fallback.
3. ``ChioStreamingConfigError`` if neither is configured and the router
   is asked to route.

The payload returned by :meth:`DLQRouter.build_record` is meant for
immediate publication via the same transactional producer that commits
the consumer offset, so denial and commit remain atomic.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from chio_sdk.models import ChioReceipt

from chio_streaming.errors import ChioStreamingConfigError
from chio_streaming.receipt import (
    RECEIPT_HEADER,
    VERDICT_HEADER,
    canonical_json,
)


@dataclass(frozen=True)
class DLQRecord:
    """A Kafka-ready DLQ record.

    Attributes
    ----------
    topic:
        Destination DLQ topic.
    key:
        Record key (bytes). Mirrors the originating event's key when
        available so re-drive tools can still partition correctly; falls
        back to the synthetic ``request_id``.
    value:
        Canonical JSON envelope bytes.
    headers:
        Sequence of ``(name, bytes)`` header tuples ready to pass to
        confluent-kafka's ``Producer.produce(headers=...)`` kwarg.
    """

    topic: str
    key: bytes
    value: bytes
    headers: list[tuple[str, bytes]]


class DLQRouter:
    """Route denied events to the right Kafka DLQ topic.

    Parameters
    ----------
    default_topic:
        Fallback DLQ topic for topics not in ``topic_map``. When
        ``None``, routing a topic without an explicit mapping raises
        :class:`ChioStreamingConfigError`.
    topic_map:
        Mapping from source topic -> DLQ topic. Checked before
        ``default_topic``.
    include_original_value:
        When ``True`` (the default), the original event bytes are
        embedded as a UTF-8 string when decodable, otherwise as hex.
    """

    def __init__(
        self,
        *,
        default_topic: str | None = None,
        topic_map: Mapping[str, str] | None = None,
        include_original_value: bool = True,
    ) -> None:
        if default_topic is not None and not default_topic:
            raise ChioStreamingConfigError("default_topic must be a non-empty string or None")
        self._default_topic = default_topic
        self._topic_map: dict[str, str] = dict(topic_map or {})
        self._include_original_value = include_original_value

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def route(self, source_topic: str) -> str:
        """Return the DLQ topic to use for ``source_topic``.

        Raises :class:`ChioStreamingConfigError` when neither the map
        nor a default is configured.
        """
        if not source_topic:
            raise ChioStreamingConfigError("route() requires a non-empty source_topic")
        mapped = self._topic_map.get(source_topic)
        if mapped:
            return mapped
        if self._default_topic:
            return self._default_topic
        raise ChioStreamingConfigError(
            f"no DLQ topic configured for source_topic={source_topic!r} and no default_topic is set"
        )

    # ------------------------------------------------------------------
    # Envelope construction
    # ------------------------------------------------------------------

    def build_record(
        self,
        *,
        source_topic: str,
        source_partition: int | None,
        source_offset: int | None,
        original_key: bytes | None,
        original_value: bytes | None,
        request_id: str,
        receipt: ChioReceipt,
        extra_metadata: Mapping[str, Any] | None = None,
    ) -> DLQRecord:
        """Build a :class:`DLQRecord` for a denied event.

        The envelope captures:

        * the Chio verdict (``deny``), guard, and reason,
        * the receipt id and the full receipt (so the denial is
          self-describing without a receipt-store lookup),
        * the originating ``topic``/``partition``/``offset`` for
          operator triage and optional redrive,
        * the original record value (when
          ``include_original_value=True``) encoded as UTF-8 text when
          the bytes decode cleanly, else a ``{"hex": "..."}`` marker.
        """
        if receipt.is_allowed:
            raise ChioStreamingConfigError(
                "DLQRouter.build_record called with an authorized receipt; the "
                "DLQ path is reserved for non-authorizing receipts"
            )

        decision = receipt.decision
        verdict = "deny" if receipt.is_denied else "none"
        reason = (
            decision.reason
            if decision is not None and decision.reason is not None
            else "non-authorizing Chio receipt"
        )
        guard = decision.guard if decision is not None and decision.guard is not None else "unknown"
        metadata = dict(extra_metadata or {})

        payload: dict[str, Any] = {
            "version": "chio-streaming/dlq/v1",
            "request_id": request_id,
            "verdict": verdict,
            "reason": reason,
            "guard": guard,
            "receipt_id": receipt.id,
            "receipt": receipt.model_dump(mode="json", exclude_none=True),
            "source": {
                "topic": source_topic,
                "partition": (int(source_partition) if source_partition is not None else None),
                "offset": int(source_offset) if source_offset is not None else None,
            },
        }
        if metadata:
            payload["metadata"] = metadata
        if self._include_original_value and original_value is not None:
            payload["original_value"] = _encode_original_value(original_value)

        headers: list[tuple[str, bytes]] = [
            (RECEIPT_HEADER, receipt.id.encode("utf-8")),
            (VERDICT_HEADER, verdict.encode("utf-8")),
            ("X-Chio-Deny-Guard", guard.encode("utf-8")),
            ("X-Chio-Deny-Reason", reason.encode("utf-8")),
        ]
        key = original_key if original_key is not None else request_id.encode("utf-8")
        return DLQRecord(
            topic=self.route(source_topic),
            key=key,
            value=canonical_json(payload),
            headers=headers,
        )

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def default_topic(self) -> str | None:
        """Return the configured fallback DLQ topic (``None`` if unset)."""
        return self._default_topic

    def topic_for(self, source_topic: str) -> str | None:
        """Return the explicit mapping for ``source_topic`` (``None`` if unset)."""
        return self._topic_map.get(source_topic)


def _encode_original_value(value: bytes) -> dict[str, Any]:
    """Represent the original event bytes as a JSON-safe value."""
    try:
        return {"utf8": value.decode("utf-8")}
    except UnicodeDecodeError:
        return {"hex": value.hex()}


__all__ = [
    "DLQRecord",
    "DLQRouter",
]
