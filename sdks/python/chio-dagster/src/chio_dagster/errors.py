"""Error types raised by the Chio Dagster integration."""

from __future__ import annotations

from typing import Any

from chio_sdk.errors import ChioError


class ChioDagsterError(ChioError):
    """A Chio-governed Dagster asset / op invocation was denied or failed.

    Carries the sidecar verdict so callers (and Dagster event logs) can
    inspect the guard that denied, the reason, and any structured hint
    the kernel emitted. The :func:`chio_dagster.chio_asset` and
    :func:`chio_dagster.chio_op` decorators re-raise this as
    :class:`PermissionError` before handing control back to Dagster, so
    denied asset materializations surface as failed runs on the Dagster
    UI timeline.
    """

    def __init__(
        self,
        message: str,
        *,
        asset_key: str | None = None,
        op_name: str | None = None,
        partition_key: str | None = None,
        run_id: str | None = None,
        capability_id: str | None = None,
        tool_server: str | None = None,
        guard: str | None = None,
        reason: str | None = None,
        receipt_id: str | None = None,
        decision: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, code="ASSET_DENIED")
        self.message = message
        self.asset_key = asset_key
        self.op_name = op_name
        self.partition_key = partition_key
        self.run_id = run_id
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
            ("asset_key", self.asset_key),
            ("op_name", self.op_name),
            ("partition_key", self.partition_key),
            ("run_id", self.run_id),
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


class ChioDagsterConfigError(ChioError):
    """The Chio Dagster configuration is invalid.

    Raised when the decorator wiring cannot be satisfied before any asset
    is materialized. Typical causes: missing ``capability_id`` on
    :func:`chio_asset`, empty tool server, or an ``ChioIOManager`` wrapping
    an inner manager that doesn't implement the expected
    :class:`dagster.IOManager` interface.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, code="DAGSTER_CONFIG_ERROR")


__all__ = [
    "ChioDagsterConfigError",
    "ChioDagsterError",
]
