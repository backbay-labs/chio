# chio-anthropic-tools-adapter

Provider-native adapter that translates between the Anthropic Messages API's
tool-use wire format and Chio's provider-agnostic tool-call fabric. It
implements [`chio-tool-call-fabric`](../chio-tool-call-fabric/)'s
`ProviderAdapter` trait: `tool_use` content blocks in a `messages.create`
response lift into `ToolInvocation`s, and a caller-supplied verdict lowers
back into a `tool_result` block for the next turn. The adapter also owns the
live HTTP transport to `api.anthropic.com`: `send_messages` and
`send_messages_stream` perform the upstream call themselves.

## Responsibilities

- Forward a native `messages.create` request to
  `https://api.anthropic.com/v1/messages` over the shared HTTP transport
  (`x-api-key` plus the pinned `anthropic-version` header) and lift every
  `tool_use` content block in the response into a `ToolInvocation`
  (`send_messages`, `lift_batch`).
- Lower a verdict and an executed tool result back into an Anthropic
  `tool_result` content block: apply redactions on allow, emit an
  `is_error: true` block describing the `DenyReason` on deny
  (`lower_tool_result_block`).
- Gate a streaming `messages.create` response: buffer a `tool_use` block from
  `content_block_start` through `content_block_stop`, evaluate it, and
  release its SSE bytes only once the verdict allows (`send_messages_stream`,
  `gate_sse_stream`).
- Enforce a dual gate on Anthropic server tools (`computer_use`, `bash`,
  `text_editor`, and their date-suffixed wire names): the `computer-use`
  cargo feature must be compiled in and the manifest's `server_tools` list
  must name the tool.
- Pin the upstream API version (`anthropic-version: 2023-06-01`,
  `ANTHROPIC_VERSION`) and, when the `computer-use` feature is on, the
  `anthropic-beta: computer-use-2025-01-24` header.

## Public API

- `AnthropicAdapter` - adapter handle. `new` / `new_with_manifest` construct
  it; `send_messages` / `send_messages_stream` perform the live call;
  `lift_batch` / `lower_tool_result_block` are the batch lift/lower entry
  points; `gate_sse_stream` runs the streaming gate.
- `AnthropicAdapterConfig::new` - builds a config with `api_version` pinned
  to `ANTHROPIC_VERSION`.
- `chio_tool_call_fabric::ProviderAdapter` impl on `AnthropicAdapter` - `lift`
  / `lower`, the fabric's one-block-per-call contract.
- `chio_provider_adapter_core::Provider` impl on `AnthropicAdapter` -
  `provider_id` / `api_version` identity surface.
- `GatedSseStream` - `bytes`, `invocations`, `verdicts` returned by
  `gate_sse_stream`.
- `AnthropicServerToolGate` - `deny_all()`, `from_manifest()`, `allowed()`,
  `ensure_tool_allowed()`.
- `ToolUseBlock`, `ToolResultBlock` - native wire content-block types
  (`ToolResultBlock::allow` / `::deny` constructors).
- `transport::{anthropic_transport, anthropic_transport_from_env,
  MockTransport, HttpTransport}` and the pinned constants
  `ANTHROPIC_VERSION`, `ANTHROPIC_MESSAGES_PATH`, `COMPUTER_USE_BETA`.
- `AnthropicAdapterError` - local error enum wrapping transport, provider,
  and manifest errors, plus `ComputerUseFeatureDisabled`.

## Usage

```rust
use std::sync::Arc;
use chio_anthropic_tools_adapter::{
    anthropic_transport_from_env, AnthropicAdapter, AnthropicAdapterConfig,
};

let config = AnthropicAdapterConfig::new(
    "anthropic-1", "Anthropic Messages", "0.1.0", public_key_hex, "wks_prod",
);
let transport = anthropic_transport_from_env()?;
let adapter = AnthropicAdapter::new(config, Arc::new(transport));

let invocations = adapter.send_messages(request_body).await?;
```

## Feature flags

| Flag | Effect |
|------|--------|
| `computer-use` | Off by default. Compiles `native::ServerToolName` / `SERVER_TOOL_WIRE_NAMES` and adds the `anthropic-beta: computer-use-2025-01-24` header to outgoing requests. The manifest `server_tools` allowlist still gates the surface at runtime (see below); the feature alone does not admit a server-tool call. |

## Server-tool gate

`AnthropicServerToolGate::ensure_tool_allowed` fails closed for any tool name
`ServerTool::from_anthropic_wire_name` (in `chio-manifest`) recognizes as a
server tool, unless the manifest's `server_tools` list contains the matching
stable entry. The mapping covers the bare name and any `<name>_` plus an
8-digit date suffix, so a wire-name version bump cannot slip past the
allowlist:

| Anthropic wire name | Manifest entry |
|---|---|
| `computer_use`, `computer_use_YYYYMMDD` | `computer_use` |
| `bash`, `bash_YYYYMMDD` | `bash` |
| `text_editor`, `text_editor_YYYYMMDD` | `text_editor` |

Names `from_anthropic_wire_name` does not recognize (regular custom tools)
skip the gate entirely.

## Adapter-visible error taxonomy

Anthropic errors arrive as an HTTP-status JSON envelope (`error.type`,
`error.message`, `request_id`) or, mid-stream, as an `error` SSE event after a
200 response. Rows marked "HTTP transport boundary" are produced by
`chio_provider_adapter_core::http::map_transport_error` from the upstream
status; rows marked "current adapter path" are produced by this crate's lift,
lower, or streaming code.

`tests/error_taxonomy_doctest.rs` parses the table below at test time: it
requires every `ProviderError` variant except `Other` to appear, validates
each envelope's shape against its class, and drives the real adapter path for
the three adapter-internal classes (`BadToolArgs`, `Malformed`,
`VerdictBudgetExceeded`). Keep every envelope one valid inline JSON object.

<!-- error-taxonomy:start -->
| ProviderError class | Native or boundary envelope | Source | Adapter-visible behavior |
| ------------------- | --------------------------- | ------ | ------------------------ |
| `ProviderError::RateLimited` | `{"status":429,"headers":{"retry-after-ms":"1000"},"body":{"type":"error","error":{"type":"rate_limit_error","message":"rate limit reached"},"request_id":"req_rate"}}` | `urn:chio:error:provider:anthropic` (`CHIO-PROVIDER-ANTHROPIC`) + HTTP transport boundary | Anthropic provider adapter returned a normalized provider error. Preserve the retry hint as `retry_after_ms` when the native response carries one. Registry help: Inspect the provider error details and retry only when the adapter marks the failure transient. |
| `ProviderError::ContentPolicy` | `{"status":200,"body":{"type":"message","id":"msg_refusal","role":"assistant","content":[{"type":"text","text":""}],"stop_reason":"refusal"}}` | `urn:chio:error:provider:anthropic` (`CHIO-PROVIDER-ANTHROPIC`) + HTTP transport boundary | Anthropic provider adapter returned a normalized provider error. Surface provider refusal as content-policy denial rather than a tool execution error. Registry help: Inspect the provider error details and retry only when the adapter marks the failure transient. |
| `ProviderError::BadToolArgs` | `{"type":"tool_use","id":"toolu_bad_args","name":"get_weather","input":"not an object"}` | `urn:chio:error:provider:anthropic` (`CHIO-PROVIDER-ANTHROPIC`) + current adapter path | Anthropic provider adapter returned a normalized provider error. Fail closed when Anthropic emits a `tool_use.input` that cannot become canonical JSON object arguments. Registry help: Inspect the provider error details and retry only when the adapter marks the failure transient. |
| `ProviderError::Upstream5xx` | `{"status":529,"body":{"type":"error","error":{"type":"overloaded_error","message":"overloaded"},"request_id":"req_overloaded"}}` | `urn:chio:error:provider:anthropic` (`CHIO-PROVIDER-ANTHROPIC`) + HTTP transport boundary | Anthropic provider adapter returned a normalized provider error. Keep upstream 5xx and overload bodies visible for retry and audit policy. Registry help: Inspect the provider error details and retry only when the adapter marks the failure transient. |
| `ProviderError::TransportTimeout` | `{"transport":"timeout","endpoint":"https://api.anthropic.com/v1/messages","elapsed_ms":30000}` | `urn:chio:error:provider:anthropic` (`CHIO-PROVIDER-ANTHROPIC`) + HTTP transport boundary | Anthropic provider adapter returned a normalized provider error. Classify local transport timeout separately from Anthropic 504 `timeout_error` envelopes. Registry help: Inspect the provider error details and retry only when the adapter marks the failure transient. |
| `ProviderError::VerdictBudgetExceeded` | `{"provider":"anthropic","event":"content_block_start","observed_ms":300,"budget_ms":250}` | `urn:chio:error:provider:anthropic` (`CHIO-PROVIDER-ANTHROPIC`) + current adapter path | Anthropic provider adapter returned a normalized provider error. Preserve the fabric verdict-budget error when the evaluator misses the 250ms gate. Registry help: Inspect the provider error details and retry only when the adapter marks the failure transient. |
| `ProviderError::Malformed` | `{"event":"content_block_delta","data":{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{}"}}}` | `urn:chio:error:provider:anthropic` (`CHIO-PROVIDER-ANTHROPIC`) + current adapter path | Anthropic provider adapter returned a normalized provider error. Fail closed for impossible or out-of-order native SSE/message shapes. Registry help: Inspect the provider error details and retry only when the adapter marks the failure transient. |
<!-- error-taxonomy:end -->

`ProviderError::Other` is intentionally absent: a native Anthropic envelope
must map to a concrete class above or fail closed as `Malformed`.

## Testing

```bash
cargo test -p chio-anthropic-tools-adapter
cargo test -p chio-anthropic-tools-adapter --features computer-use
```

`tests/server_tools.rs` asserts different behavior on each side of the
`computer-use` gate (`cfg(not(feature = "computer-use"))` vs
`cfg(feature = "computer-use")` cases), so both invocations are needed for
full coverage.

## See also

- `chio-tool-call-fabric` - defines `ProviderAdapter` and the
  `ToolInvocation` / `VerdictResult` types this crate lifts and lowers.
- `chio-provider-adapter-core` - shared HTTP transport, SSE framing, and the
  streaming-allow helper this crate builds on.
- `chio-manifest` - `ToolManifest`, `ServerTool`, and the wire-name mapping
  behind the server-tool gate.
- `chio-kernel` - defines `ToolServerConnection`, the trait
  `chio-mcp-adapter` implements; this crate does not depend on it and
  integrates via `chio-tool-call-fabric` instead.
- `chio-provider-conformance` - replays recorded Anthropic fixtures through
  this adapter under the `fixtures-anthropic` feature.
- `chio-openai-adapter`, `chio-bedrock-converse-adapter` - sibling adapters
  implementing the same `ProviderAdapter` contract for other providers.
