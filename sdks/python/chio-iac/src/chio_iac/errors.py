"""Error types raised by the Chio IaC integration.

The IaC wrapper surfaces three error classes:

* :class:`ChioIACError` -- a Chio-governed IaC operation (``terraform plan``,
  ``terraform apply``, a Pulumi program run, or a plan-review check) was
  denied or failed by the Chio sidecar. Carries the structured verdict so
  tooling can inspect the guard that denied and the reason.
* :class:`ChioIACConfigError` -- the IaC wrapper's configuration is invalid
  (missing ``capability_id``, missing binary, mismatched scope, etc.).
  Raised before any sidecar evaluation takes place.
* :class:`ChioIACPlanReviewError` -- the plan-review guard found
  out-of-scope resource types in a Terraform / Pulumi plan. Raised before
  ``terraform apply`` dispatches so the apply never touches the cloud.
"""

from __future__ import annotations

from typing import Any

from chio_sdk.errors import ChioError


class ChioIACError(ChioError):
    """A Chio-governed IaC operation was denied or failed.

    The structured error carries the sidecar verdict so callers and
    structured-log consumers can see which guard denied, the reason, and
    the receipt id (when the kernel issued one). The CLI wrapper
    converts :class:`ChioIACError` into a non-zero process exit; library
    callers can ``except ChioIACError`` normally.
    """

    def __init__(
        self,
        message: str,
        *,
        subcommand: str | None = None,
        capability_id: str | None = None,
        tool_server: str | None = None,
        tool_name: str | None = None,
        guard: str | None = None,
        reason: str | None = None,
        receipt_id: str | None = None,
        decision: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, code="IAC_DENIED")
        self.message = message
        self.subcommand = subcommand
        self.capability_id = capability_id
        self.tool_server = tool_server
        self.tool_name = tool_name
        self.guard = guard
        self.reason = reason
        self.receipt_id = receipt_id
        self.decision = decision or {}

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict of the populated fields."""
        payload: dict[str, Any] = {"code": self.code, "message": self.message}
        for key, value in (
            ("subcommand", self.subcommand),
            ("capability_id", self.capability_id),
            ("tool_server", self.tool_server),
            ("tool_name", self.tool_name),
            ("guard", self.guard),
            ("reason", self.reason),
            ("receipt_id", self.receipt_id),
        ):
            if value is not None:
                payload[key] = value
        if self.decision:
            payload["decision"] = dict(self.decision)
        return payload


class ChioIACConfigError(ChioError):
    """The Chio IaC configuration is invalid.

    Raised when the wrapper cannot satisfy its preconditions before any
    sidecar call. Typical causes: empty ``capability_id``, an unknown
    Terraform subcommand, a missing ``terraform`` binary, or a plan-review
    allowlist that conflicts with the caller-provided denylist.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, code="IAC_CONFIG_ERROR")


class ChioIACPlanReviewError(ChioIACError):
    """A Terraform / Pulumi plan contained out-of-scope resource types.

    The ``violations`` list is the set of ``(resource_type, reason)``
    pairs the guard flagged. The plan is considered in full and every
    violation is reported; the caller sees the complete denial set rather
    than the first entry only so they can correct the plan in one pass.
    """

    def __init__(
        self,
        message: str,
        *,
        violations: list[dict[str, Any]] | None = None,
        subcommand: str | None = None,
        capability_id: str | None = None,
    ) -> None:
        super().__init__(
            message,
            subcommand=subcommand,
            capability_id=capability_id,
            guard="PlanReviewGuard",
            reason=message,
        )
        self.violations: list[dict[str, Any]] = list(violations or [])

    def to_dict(self) -> dict[str, Any]:
        payload = super().to_dict()
        if self.violations:
            payload["violations"] = [dict(v) for v in self.violations]
        return payload


__all__ = [
    "ChioIACConfigError",
    "ChioIACError",
    "ChioIACPlanReviewError",
]
