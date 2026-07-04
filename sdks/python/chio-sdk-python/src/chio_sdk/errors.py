"""Chio SDK error types."""

from __future__ import annotations

from typing import Any


class ChioError(Exception):
    """Base error for all Chio SDK operations."""

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


class ChioConnectionError(ChioError):
    """Failed to connect to the Chio sidecar."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="CONNECTION_ERROR")


class ChioTimeoutError(ChioError):
    """Request to the Chio sidecar timed out."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="TIMEOUT")


class ChioDeniedError(ChioError):
    """The Chio kernel denied the request.

    The error carries structured deny context so developers can see exactly
    what was denied, which scope was needed versus granted, which guard
    denied, and what to do next. Only ``message`` is required; all other
    fields are keyword-only and optional so older call sites that pass a
    bare deny reason still work.
    """

    def __init__(
        self,
        message: str,
        *,
        guard: str | None = None,
        reason: str | None = None,
        tool_name: str | None = None,
        tool_server: str | None = None,
        requested_action: str | None = None,
        required_scope: str | None = None,
        granted_scope: str | None = None,
        reason_code: str | None = None,
        receipt_id: str | None = None,
        hint: str | None = None,
        docs_url: str | None = None,
    ) -> None:
        super().__init__(message, code="DENIED")
        self.message = message
        self.guard = guard
        self.reason = reason
        self.tool_name = tool_name
        self.tool_server = tool_server
        self.requested_action = requested_action
        self.required_scope = required_scope
        self.granted_scope = granted_scope
        self.reason_code = reason_code
        self.receipt_id = receipt_id
        self.hint = hint
        self.docs_url = docs_url

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dict of all populated fields.

        Useful for structured logging, test assertions, and for producing
        the same payload shape the sidecar emits on the wire.
        """
        payload: dict[str, Any] = {
            "code": self.code,
            "message": self.message,
        }
        field_map: dict[str, Any] = {
            "tool_name": self.tool_name,
            "tool_server": self.tool_server,
            "requested_action": self.requested_action,
            "required_scope": self.required_scope,
            "granted_scope": self.granted_scope,
            "guard": self.guard,
            "reason": self.reason,
            "reason_code": self.reason_code,
            "receipt_id": self.receipt_id,
            "hint": self.hint,
            "docs_url": self.docs_url,
        }
        for key, value in field_map.items():
            if value is not None:
                payload[key] = value
        return payload

    @classmethod
    def from_wire(cls, data: dict[str, Any]) -> "ChioDeniedError":
        """Build a ChioDeniedError from a sidecar 403 response body.

        Accepts any subset of the known fields. The human-readable
        ``message`` falls back to ``reason`` and then the literal string
        ``"denied"`` so the error is never empty.
        """
        message = (
            data.get("message")
            or data.get("reason")
            or "denied"
        )
        return cls(
            message,
            guard=data.get("guard"),
            reason=data.get("reason"),
            tool_name=data.get("tool_name"),
            tool_server=data.get("tool_server"),
            requested_action=data.get("requested_action"),
            required_scope=data.get("required_scope"),
            granted_scope=data.get("granted_scope"),
            reason_code=data.get("reason_code"),
            receipt_id=data.get("receipt_id"),
            hint=data.get("hint") or data.get("suggested_fix"),
            docs_url=data.get("docs_url"),
        )

    def __str__(self) -> str:
        """Human-readable multi-line error message.

        Only populated fields are shown. When nothing but the base
        ``message`` is set the output is a single line, preserving the bare
        ``str(err)`` shape.
        """
        lines: list[str] = []
        header = "Chio DENIED"
        if self.tool_name and self.tool_server:
            header = (
                f'Chio DENIED: tool "{self.tool_name}" '
                f'on server "{self.tool_server}"'
            )
        elif self.tool_name:
            header = f'Chio DENIED: tool "{self.tool_name}"'
        lines.append(header)

        sections: list[tuple[str, str]] = []
        if self.requested_action:
            sections.append(("What was denied", self.requested_action))
        if self.reason:
            sections.append(("Why it was denied", self.reason))
        if self.required_scope:
            sections.append(("What scope was needed", self.required_scope))
        if self.granted_scope:
            sections.append(("What scope was granted", self.granted_scope))
        if self.guard:
            sections.append(("Guard that denied", self.guard))
        if self.reason_code:
            sections.append(("Reason code", self.reason_code))
        if self.receipt_id:
            sections.append(("Receipt ID", self.receipt_id))
        if self.hint:
            sections.append(("Next steps", self.hint))
        if self.docs_url:
            sections.append(("Docs", self.docs_url))

        if not sections:
            # No enriched fields present: str(err) stays a single line.
            return self.message

        for label, value in sections:
            lines.append("")
            lines.append(f"  {label}:")
            for value_line in str(value).splitlines() or [""]:
                lines.append(f"    {value_line}")

        return "\n".join(lines)


class ChioValidationError(ChioError):
    """Local validation failed before contacting the sidecar."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="VALIDATION_ERROR")
