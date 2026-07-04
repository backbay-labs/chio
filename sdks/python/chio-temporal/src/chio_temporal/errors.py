"""Error types raised by the Chio Temporal integration."""

from __future__ import annotations

from typing import Any

from chio_sdk.errors import ChioError


class ChioTemporalError(ChioError):
    """A Chio-governed Temporal Activity invocation was denied or failed.

    Carries the sidecar verdict so callers (and Temporal workflow history)
    can inspect the guard that denied, the reason, and any structured hint
    the kernel emitted. The :class:`chio_temporal.ChioActivityInterceptor`
    converts this into a ``temporalio.exceptions.ApplicationError`` marked
    ``non_retryable=True`` before handing control back to Temporal, so
    denied activities are not retried.
    """

    def __init__(
        self,
        message: str,
        *,
        activity_type: str | None = None,
        activity_id: str | None = None,
        workflow_id: str | None = None,
        run_id: str | None = None,
        guard: str | None = None,
        reason: str | None = None,
        receipt_id: str | None = None,
        decision: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, code="ACTIVITY_DENIED")
        self.message = message
        self.activity_type = activity_type
        self.activity_id = activity_id
        self.workflow_id = workflow_id
        self.run_id = run_id
        self.guard = guard
        self.reason = reason
        self.receipt_id = receipt_id
        self.decision = decision or {}

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dict of the populated fields."""
        payload: dict[str, Any] = {"code": self.code, "message": self.message}
        for key, value in (
            ("activity_type", self.activity_type),
            ("activity_id", self.activity_id),
            ("workflow_id", self.workflow_id),
            ("run_id", self.run_id),
            ("guard", self.guard),
            ("reason", self.reason),
            ("receipt_id", self.receipt_id),
        ):
            if value is not None:
                payload[key] = value
        if self.decision:
            payload["decision"] = dict(self.decision)
        return payload


class ChioTemporalConfigError(ChioError):
    """The Chio Temporal configuration is invalid.

    Raised when the worker / interceptor wiring cannot be satisfied
    before any Activity is dispatched. Typical causes: no
    :class:`WorkflowGrant` registered for a workflow_id, empty
    ``capability_id``, or attenuation beyond the parent grant's scope.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, code="TEMPORAL_CONFIG_ERROR")


__all__ = [
    "ChioTemporalError",
    "ChioTemporalConfigError",
]
