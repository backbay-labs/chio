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

from pydantic import BaseModel, ConfigDict, Field, RootModel, constr, model_validator


class Error(BaseModel):
    """
    Error payload. Present only on failure. Mutually exclusive with `result`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    code: int = Field(
        ...,
        description="JSON-RPC 2.0 error code. Reserved range -32768..-32000 is implementation-defined; Chio uses -32600 (Invalid Request), -32601 (Method not found), -32602 (Invalid params), -32603 (Internal error), -32800 (request cancelled, MCP), -32002 (nested-flow policy denial, Chio), -32042 (URL elicitations required, Chio).",
    )
    message: constr(min_length=1) = Field(
        ..., description="Short human-readable error description."
    )
    data: Any | None = Field(
        None,
        description="Optional structured detail. Shape is method- or code-specific.",
    )


class ChioJsonRpc20Response1(BaseModel):
    """
    JSON-RPC 2.0 response envelope used by Chio for MCP and A2A wire framing. Mirrors the inline serde shapes constructed in `crates/chio-mcp-adapter/src/transport.rs::json_rpc_result` and `json_rpc_error` (lines 1299-1316) and the typed `A2aJsonRpcResponse<T>` / `A2aJsonRpcError` in `crates/chio-a2a-adapter/src/protocol.rs` (lines 243-255). Exactly one of `result` or `error` MUST be present, enforced via `oneOf`. The `error.code` field is an integer (Chio uses standard JSON-RPC reserved codes -32600 through -32603, MCP's -32800 for cancellation, and Chio extension codes such as -32002 for nested-flow policy denials and -32042 for URL elicitations required - see `map_nested_flow_error_code` in transport.rs lines 1280-1297). The `id` is null only when the server cannot determine the request id (parse error before the id was readable).
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    jsonrpc: Literal["2.0"] = Field(
        ..., description="Protocol version literal. Always the string '2.0'."
    )
    id: int | constr(min_length=1) | None = Field(
        ...,
        description="Echoes the request id. Null only for error responses where the server failed to parse the request id (parse error or invalid request, per JSON-RPC 2.0 section 5).",
    )
    result: Any = Field(
        ...,
        description="Method-specific success payload. Present only on success. Mutually exclusive with `error`. Shape is method-defined; commonly an object.",
    )
    error: Error | None = Field(
        None,
        description="Error payload. Present only on failure. Mutually exclusive with `result`.",
    )

    @model_validator(mode="after")
    def _success_excludes_error(self) -> "ChioJsonRpc20Response1":
        if "error" in self.model_fields_set:
            raise ValueError("JSON-RPC success response must not include error")
        return self


class ChioJsonRpc20Response2(BaseModel):
    """
    JSON-RPC 2.0 response envelope used by Chio for MCP and A2A wire framing. Mirrors the inline serde shapes constructed in `crates/chio-mcp-adapter/src/transport.rs::json_rpc_result` and `json_rpc_error` (lines 1299-1316) and the typed `A2aJsonRpcResponse<T>` / `A2aJsonRpcError` in `crates/chio-a2a-adapter/src/protocol.rs` (lines 243-255). Exactly one of `result` or `error` MUST be present, enforced via `oneOf`. The `error.code` field is an integer (Chio uses standard JSON-RPC reserved codes -32600 through -32603, MCP's -32800 for cancellation, and Chio extension codes such as -32002 for nested-flow policy denials and -32042 for URL elicitations required - see `map_nested_flow_error_code` in transport.rs lines 1280-1297). The `id` is null only when the server cannot determine the request id (parse error before the id was readable).
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    jsonrpc: Literal["2.0"] = Field(
        ..., description="Protocol version literal. Always the string '2.0'."
    )
    id: int | constr(min_length=1) | None = Field(
        ...,
        description="Echoes the request id. Null only for error responses where the server failed to parse the request id (parse error or invalid request, per JSON-RPC 2.0 section 5).",
    )
    result: Any | None = Field(
        None,
        description="Method-specific success payload. Present only on success. Mutually exclusive with `error`. Shape is method-defined; commonly an object.",
    )
    error: Error = Field(
        ...,
        description="Error payload. Present only on failure. Mutually exclusive with `result`.",
    )

    @model_validator(mode="after")
    def _error_excludes_result(self) -> "ChioJsonRpc20Response2":
        if "result" in self.model_fields_set:
            raise ValueError("JSON-RPC error response must not include result")
        return self


class ChioJsonRpc20Response(RootModel[ChioJsonRpc20Response1 | ChioJsonRpc20Response2]):
    root: ChioJsonRpc20Response1 | ChioJsonRpc20Response2 = Field(
        ...,
        description="JSON-RPC 2.0 response envelope used by Chio for MCP and A2A wire framing. Mirrors the inline serde shapes constructed in `crates/chio-mcp-adapter/src/transport.rs::json_rpc_result` and `json_rpc_error` (lines 1299-1316) and the typed `A2aJsonRpcResponse<T>` / `A2aJsonRpcError` in `crates/chio-a2a-adapter/src/protocol.rs` (lines 243-255). Exactly one of `result` or `error` MUST be present, enforced via `oneOf`. The `error.code` field is an integer (Chio uses standard JSON-RPC reserved codes -32600 through -32603, MCP's -32800 for cancellation, and Chio extension codes such as -32002 for nested-flow policy denials and -32042 for URL elicitations required - see `map_nested_flow_error_code` in transport.rs lines 1280-1297). The `id` is null only when the server cannot determine the request id (parse error before the id was readable).",
        title="Chio JSON-RPC 2.0 Response",
    )
