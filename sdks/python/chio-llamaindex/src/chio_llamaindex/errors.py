"""Error types raised by the Chio LlamaIndex integration."""

from __future__ import annotations

from typing import Any

from chio_sdk.errors import ChioError


class ChioToolError(ChioError):
    """A Chio-governed LlamaIndex tool invocation was denied or failed.

    Carries the sidecar verdict so callers can inspect the guard that
    denied, the reason, and any structured hint the kernel emitted.
    """

    def __init__(
        self,
        message: str,
        *,
        tool_name: str | None = None,
        server_id: str | None = None,
        guard: str | None = None,
        reason: str | None = None,
        receipt_id: str | None = None,
        decision: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, code="TOOL_DENIED")
        self.message = message
        self.tool_name = tool_name
        self.server_id = server_id
        self.guard = guard
        self.reason = reason
        self.receipt_id = receipt_id
        self.decision = decision or {}

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dict of the populated fields."""
        payload: dict[str, Any] = {"code": self.code, "message": self.message}
        for key, value in (
            ("tool_name", self.tool_name),
            ("server_id", self.server_id),
            ("guard", self.guard),
            ("reason", self.reason),
            ("receipt_id", self.receipt_id),
        ):
            if value is not None:
                payload[key] = value
        if self.decision:
            payload["decision"] = dict(self.decision)
        return payload


class ChioLlamaIndexConfigError(ChioError):
    """The Chio LlamaIndex configuration is invalid.

    Raised when collection scoping, capability binding, or runner wiring
    cannot be satisfied before any tool is dispatched.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, code="LLAMAINDEX_CONFIG_ERROR")


__all__ = [
    "ChioLlamaIndexConfigError",
    "ChioToolError",
]
