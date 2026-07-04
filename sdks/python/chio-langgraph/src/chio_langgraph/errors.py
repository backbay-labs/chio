"""Error types raised by the Chio LangGraph integration."""

from __future__ import annotations

from typing import Any

from chio_sdk.errors import ChioError


class ChioLangGraphError(ChioError):
    """A Chio-governed LangGraph node invocation was denied or rejected.

    Raised when the Chio kernel denies a node's sidecar evaluation or
    when an :func:`chio_approval_node` receives a denial from the human
    approver. Carries the sidecar verdict so callers (and LangGraph's
    error surface) can inspect which guard denied, the reason, and any
    structured hint the kernel emitted.
    """

    def __init__(
        self,
        message: str,
        *,
        node_name: str | None = None,
        tool_server: str | None = None,
        tool_name: str | None = None,
        guard: str | None = None,
        reason: str | None = None,
        receipt_id: str | None = None,
        approval_id: str | None = None,
        decision: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, code="NODE_DENIED")
        self.message = message
        self.node_name = node_name
        self.tool_server = tool_server
        self.tool_name = tool_name
        self.guard = guard
        self.reason = reason
        self.receipt_id = receipt_id
        self.approval_id = approval_id
        self.decision = decision or {}

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dict of the populated fields."""
        payload: dict[str, Any] = {"code": self.code, "message": self.message}
        for key, value in (
            ("node_name", self.node_name),
            ("tool_server", self.tool_server),
            ("tool_name", self.tool_name),
            ("guard", self.guard),
            ("reason", self.reason),
            ("receipt_id", self.receipt_id),
            ("approval_id", self.approval_id),
        ):
            if value is not None:
                payload[key] = value
        if self.decision:
            payload["decision"] = dict(self.decision)
        return payload


class ChioLangGraphConfigError(ChioError):
    """The Chio LangGraph configuration is invalid.

    Raised when graph / node scope wiring cannot be satisfied before
    any node is dispatched. Typical causes: empty capability scope,
    a subgraph scope broader than its parent ceiling, or an
    ``chio_approval_node`` missing an approval policy.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, code="LANGGRAPH_CONFIG_ERROR")


__all__ = [
    "ChioLangGraphConfigError",
    "ChioLangGraphError",
]
