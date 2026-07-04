"""Error types raised by the Chio Ray integration."""

from __future__ import annotations

from typing import Any

from chio_sdk.errors import ChioError


class ChioRayError(ChioError):
    """A Chio-governed Ray task or actor method call was denied or failed.

    Carries the sidecar verdict so callers (and Ray task exception traces)
    can inspect the guard that denied, the reason, and any structured hint
    the kernel emitted. ``chio_ray.chio_remote`` and
    :meth:`ChioActor.requires` raise a :class:`PermissionError` whose
    ``__cause__`` is an :class:`ChioRayError`, so
    ``except PermissionError`` idioms work on the caller side and Ray
    propagates the exception unchanged through ``ray.get``.
    """

    def __init__(
        self,
        message: str,
        *,
        task_name: str | None = None,
        actor_class: str | None = None,
        method_name: str | None = None,
        capability_id: str | None = None,
        tool_server: str | None = None,
        guard: str | None = None,
        reason: str | None = None,
        receipt_id: str | None = None,
        decision: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, code="RAY_DENIED")
        self.message = message
        self.task_name = task_name
        self.actor_class = actor_class
        self.method_name = method_name
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
            ("actor_class", self.actor_class),
            ("method_name", self.method_name),
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


class ChioRayConfigError(ChioError):
    """The Chio Ray configuration is invalid.

    Raised when a decorator or actor base-class invariant cannot be
    satisfied before a task is dispatched. Typical causes: a method
    decorated with :meth:`ChioActor.requires` on a class that is not an
    :class:`ChioActor` subclass, a scope that is not a subset of the
    parent standing grant, or a missing ``capability_id`` on
    :func:`chio_remote`.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, code="RAY_CONFIG_ERROR")


__all__ = [
    "ChioRayConfigError",
    "ChioRayError",
]
