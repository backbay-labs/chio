"""Error types raised by the Chio observability bridges."""

from __future__ import annotations

from typing import Any

from chio_sdk.errors import ChioError


class ChioObservabilityError(ChioError):
    """A bridge failed to publish a Chio receipt as a span.

    Carries contextual information about the receipt that failed so
    operators can correlate the failure back to a specific tool call
    without having to re-ingest the entire receipt stream.
    """

    def __init__(
        self,
        message: str,
        *,
        backend: str | None = None,
        receipt_id: str | None = None,
        tool_name: str | None = None,
        cause: BaseException | None = None,
    ) -> None:
        super().__init__(message, code="OBSERVABILITY_ERROR")
        self.message = message
        self.backend = backend
        self.receipt_id = receipt_id
        self.tool_name = tool_name
        self.cause = cause

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dict of the populated fields."""
        payload: dict[str, Any] = {"code": self.code, "message": self.message}
        for key, value in (
            ("backend", self.backend),
            ("receipt_id", self.receipt_id),
            ("tool_name", self.tool_name),
        ):
            if value is not None:
                payload[key] = value
        return payload


class ChioObservabilityConfigError(ChioError):
    """The observability bridge configuration is invalid.

    Raised at bridge construction time when required credentials, hosts,
    or dependencies are missing so the error surfaces before any
    receipts are dispatched.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, code="OBSERVABILITY_CONFIG_ERROR")


__all__ = [
    "ChioObservabilityConfigError",
    "ChioObservabilityError",
]
