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


class ChioJsonRpc20Request(BaseModel):
    """
    JSON-RPC 2.0 request envelope used by Chio for MCP and A2A wire framing. Mirrors the inline serde shape constructed in `crates/chio-mcp-adapter/src/transport.rs::send_request` (lines 643-648) and the typed `A2aJsonRpcRequest<T>` in `crates/chio-a2a-adapter/src/protocol.rs` (lines 234-241). The `id` may be an integer, a string, or null; null is permitted on the wire because Chio relays peers that originate ids upstream and forward them verbatim. `params` is optional per JSON-RPC 2.0 (notifications and parameterless calls omit it), but most Chio call sites supply at least an empty object.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    jsonrpc: Literal["2.0"] = Field(
        ..., description="Protocol version literal. Always the string '2.0'."
    )
    id: int | constr(min_length=1) | None = Field(
        ...,
        description="Request correlation id. Chio adapters originate monotonic integer ids; relayed peer ids may be strings. Null is permitted per JSON-RPC 2.0 but discouraged for new requests because it is indistinguishable from a server-side parse failure response.",
    )
    method: constr(min_length=1) = Field(
        ...,
        description="RPC method name (for example 'tools/call', 'initialize', 'sampling/createMessage').",
    )
    params: dict[str, Any] | list | None = Field(
        None,
        description="Method parameters. JSON-RPC 2.0 allows omission for parameterless methods; structured params are typically an object, occasionally an array.",
    )
