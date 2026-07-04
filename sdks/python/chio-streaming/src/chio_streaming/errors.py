"""Error types raised by the Chio streaming integration."""

from __future__ import annotations

from typing import Any

from chio_sdk.errors import ChioError


class ChioStreamingError(ChioError):
    """A Chio-governed Kafka event processing step was denied or failed.

    Carries the sidecar verdict so callers (and downstream audit
    pipelines) can inspect the guard that denied, the reason, and any
    structured hint the kernel emitted. :class:`ChioConsumerMiddleware`
    raises this for unrecoverable processing failures after the denial
    DLQ publish has been resolved.
    """

    def __init__(
        self,
        message: str,
        *,
        topic: str | None = None,
        partition: int | None = None,
        offset: int | None = None,
        request_id: str | None = None,
        guard: str | None = None,
        reason: str | None = None,
        receipt_id: str | None = None,
        decision: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, code="STREAMING_DENIED")
        self.message = message
        self.topic = topic
        self.partition = partition
        self.offset = offset
        self.request_id = request_id
        self.guard = guard
        self.reason = reason
        self.receipt_id = receipt_id
        self.decision = decision or {}

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dict of the populated fields."""
        payload: dict[str, Any] = {"code": self.code, "message": self.message}
        for key, value in (
            ("topic", self.topic),
            ("partition", self.partition),
            ("offset", self.offset),
            ("request_id", self.request_id),
            ("guard", self.guard),
            ("reason", self.reason),
            ("receipt_id", self.receipt_id),
        ):
            if value is not None:
                payload[key] = value
        if self.decision:
            payload["decision"] = dict(self.decision)
        return payload


class ChioStreamingConfigError(ChioError):
    """The Chio streaming middleware configuration is invalid.

    Raised when the consumer/producer wiring cannot be satisfied before
    any message is polled. Typical causes: no scope registered for a
    consumed topic, missing DLQ topic, missing transactional producer
    when ``transactional=True``.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, code="STREAMING_CONFIG_ERROR")


__all__ = [
    "ChioStreamingConfigError",
    "ChioStreamingError",
]
