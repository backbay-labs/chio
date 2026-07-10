"""Error types raised by the Chio Prefect integration."""

from __future__ import annotations

from typing import Any

from chio_sdk.errors import ChioError


class ChioPrefectError(ChioError):
    """A Chio-governed Prefect task invocation was denied or failed.

    Carries the sidecar verdict so callers (and Prefect task run history)
    can inspect the guard that denied, the reason, and any structured hint
    the kernel emitted. The :func:`chio_prefect.chio_task` decorator
    converts this into a :class:`PermissionError` before handing control
    back to Prefect, so denied tasks fail with a PermissionError state
    (and, by default, are not retried on the PermissionError class alone
    unless the user configures a ``retry_condition_fn`` that explicitly
    accepts it).
    """

    def __init__(
        self,
        message: str,
        *,
        task_name: str | None = None,
        flow_run_id: str | None = None,
        task_run_id: str | None = None,
        capability_id: str | None = None,
        tool_server: str | None = None,
        guard: str | None = None,
        reason: str | None = None,
        receipt_id: str | None = None,
        decision: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, code="TASK_DENIED")
        self.message = message
        self.task_name = task_name
        self.flow_run_id = flow_run_id
        self.task_run_id = task_run_id
        self.capability_id = capability_id
        self.tool_server = tool_server
        self.guard = guard
        self.reason = reason
        self.receipt_id = receipt_id
        self.decision = decision or {}

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict of the populated fields."""
        payload: dict[str, Any] = {"code": self.code, "message": self.message}
        for key, value in (
            ("task_name", self.task_name),
            ("flow_run_id", self.flow_run_id),
            ("task_run_id", self.task_run_id),
            ("capability_id", self.capability_id),
            ("tool_server", self.tool_server),
            ("guard", self.guard),
            ("reason", self.reason),
            ("receipt_id", self.receipt_id),
        ):
            if value is not None:
                payload[key] = value
        if self.decision:
            payload["decision"] = dict(self.decision)
        return payload


class ChioPrefectConfigError(ChioError):
    """The Chio Prefect configuration is invalid.

    Raised when the decorator wiring cannot be satisfied before any task
    is dispatched. Typical causes: empty ``capability_id`` on
    :func:`chio_flow`, a task scope that is not a subset of its enclosing
    flow scope, or missing sidecar configuration.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, code="PREFECT_CONFIG_ERROR")


__all__ = [
    "ChioPrefectConfigError",
    "ChioPrefectError",
]
