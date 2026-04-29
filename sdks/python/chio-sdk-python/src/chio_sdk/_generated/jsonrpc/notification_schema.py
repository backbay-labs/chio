# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 3ed943267c60942b5a63a39515fbbc1a553d614d895d142e307096a7a99c7da2
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, constr


class ChioJsonRpc20Notification(BaseModel):
    """
    JSON-RPC 2.0 notification envelope used by Chio for MCP and A2A wire framing. Mirrors the inline serde shape constructed in `crates/chio-mcp-adapter/src/transport.rs::send_notification` (lines 770-774) and the streaming-chunk and cancellation notifications in `crates/chio-mcp-edge/src/runtime/protocol.rs` and transport.rs (lines 401-407, 1384-1392). A notification is structurally a request with no `id` field; the receiver MUST NOT respond. Common Chio notification methods include 'notifications/initialized', 'notifications/cancelled', 'notifications/tasks/status', 'notifications/resources/updated', 'notifications/resources/list_changed', and the Chio-specific tool-streaming chunk method exposed as `CHIO_TOOL_STREAMING_NOTIFICATION_METHOD`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    jsonrpc: Literal["2.0"] = Field(
        ..., description="Protocol version literal. Always the string '2.0'."
    )
    method: constr(min_length=1) = Field(
        ...,
        description="Notification method name (for example 'notifications/initialized', 'notifications/cancelled', 'notifications/tasks/status').",
    )
    params: dict[str, Any] | list | None = Field(
        None,
        description="Method parameters. JSON-RPC 2.0 allows omission; Chio call sites typically supply at least an empty object.",
    )
