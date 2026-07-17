# chio-anthropic-tools-adapter architecture

## Overview

The adapter is an untrusted edge component: it holds the live HTTP client to
`api.anthropic.com` and produces `chio_tool_call_fabric` types
(`ToolInvocation`, `ProviderResponse`) that a caller evaluates. Unlike
`chio-mcp-adapter`, which implements `chio-kernel`'s `ToolServerConnection`
trait directly, this crate has no dependency on `chio-kernel`: it implements
`chio-tool-call-fabric`'s provider-agnostic `ProviderAdapter` trait, and
callers supply their own verdict, either as a closure passed to the
streaming path or as a value produced between `lift_batch` and
`lower_tool_result_block` on the batch path. The crate is organized around
two parallel request shapes, batch (`adapter.rs`) and streaming SSE
(`adapter::streaming`), sharing wire types (`native.rs`), transport
(`transport.rs`), and the server-tool gate (`manifest.rs`). It does not own
kernel dispatch, manifest schema validation, generic HTTP/SSE parsing, or
fixture replay; those live in `chio-kernel`, `chio-manifest`,
`chio-provider-adapter-core`, and `chio-provider-conformance`.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Public facade: `AnthropicAdapter`, `AnthropicAdapterConfig`, `AnthropicAdapterError`, the `chio_provider_adapter_core::Provider` impl, and re-exports of the transport, native, manifest, and streaming surfaces. |
| `src/adapter.rs` | Batch `messages.create` lift/lower. Extracts `tool_use` blocks from a response payload (plain object, or a `body`/`response`/`payload`/`message` envelope), validates and builds `ToolInvocation`s, and lowers a verdict into a `tool_result` block. Implements `chio_tool_call_fabric::ProviderAdapter`. Declares `adapter::streaming` via `#[path = "streaming.rs"]`. |
| `src/streaming.rs` (module `adapter::streaming`) | SSE gate. Buffers a `tool_use` block from `content_block_start` through `content_block_stop`, evaluates it, and releases its bytes only on allow. Drives the `chio_tool_call_fabric::StreamPhase` state machine. |
| `src/native.rs` | Wire types: `ToolUseBlock`, `ToolResultBlock`, and (behind `computer-use`) `ServerToolName` / `SERVER_TOOL_WIRE_NAMES`. |
| `src/manifest.rs` | `AnthropicServerToolGate`, the manifest-backed server-tool allowlist. |
| `src/transport.rs` | Pinned Anthropic endpoint and header constants, `anthropic_transport(_from_env)` constructors, and `MockTransport`. Delegates HTTP mechanics to `chio_provider_adapter_core::http`. |
| `src/loaded_weights.rs` | `chio_core_types::LoadedWeights` impl for `AnthropicAdapter` that always fails: the Messages API exposes no runtime model bytes. |

## Request lifecycle

Batch (`send_messages`):

1. `post_messages` POSTs `request_body` to `ANTHROPIC_MESSAGES_PATH`; a
   non-2xx status or transport failure maps to a `ProviderError` via
   `map_transport_error` and returns before any lifting happens.
2. `lift_batch` unwraps a `body`/`response`/`payload`/`message` envelope if
   present, extracts every `tool_use` content block, validates each
   (`tool_use` type, non-empty trimmed `id`/`name`, object `input`), and
   builds one `ToolInvocation` per block.
3. The caller runs its own verdict per invocation and calls
   `lower_tool_result_block`; allow applies redactions to the executed
   `ToolResult`, deny emits an `is_error: true` block describing the
   `DenyReason`.

Streaming (`send_messages_stream` / `gate_sse_stream`):

1. The transport POSTs and buffers the full `text/event-stream` body; the
   shared SSE parser splits it into frames configured to reject unrecognized
   field names.
2. `StreamGate` walks the frames in order. `content_block_start` opens a
   block: non-tool blocks forward immediately, tool blocks start buffering.
   `content_block_delta` appends `input_json_delta` bytes for a buffering
   tool block. `content_block_stop` reassembles the input JSON, builds the
   `ToolInvocation`, and calls the caller's `evaluate` closure before
   releasing any of that block's buffered bytes.
3. Any failure, a deny verdict, an out-of-order frame, or a block buffer over
   4096 raw frames or 1 MiB, fails the whole call closed: `gate_sse_stream`
   returns `Err` and no bytes for any block, including already-processed
   non-tool or allowed blocks, are returned.

## Invariants and failure modes

- `lift_batch` / `lift_one` fail closed on a non-`tool_use` block type, an
  empty or whitespace-padded `id`/`name`, a non-object `input`, and (without
  the `computer-use` feature) any name `ServerTool::from_anthropic_wire_name`
  recognizes.
- The server-tool gate fails closed unless both the `computer-use` feature is
  compiled in and the manifest's `server_tools` lists the tool's stable
  entry; names the mapping does not recognize skip the gate.
- A streamed `tool_use` block that mixes a non-empty `content_block_start`
  input with `input_json_delta` frames is rejected as `BadToolArgs`:
  Anthropic's wire protocol starts a streamed tool block with an empty
  `input: {}`.
- Streaming allow verdicts must carry no redactions
  (`ensure_streaming_allow_no_redactions`); redaction only applies on the
  batch `lower_tool_result_block` path.
- `lower_tool_result_block` requires a non-empty, non-whitespace-padded
  `tool_use_id` and, on allow, a `ToolResult` that already carries `content`;
  it never fabricates either.
- `ANTHROPIC_VERSION` (`"2023-06-01"`) is asserted by unit tests in `lib.rs`
  and `transport.rs`; changing it means updating the constant and
  re-recording conformance fixtures in `chio-provider-conformance`.

## Dependencies

- `chio-core-types` (Cargo.toml aliases the dependency name to `chio_core`) -
  supplies `canonical_json_bytes` (used in `adapter.rs`) and the
  `LoadedWeightsUnavailable` type the `loaded_weights.rs` macro expansion
  returns.
- `chio-tool-call-fabric` - `ProviderAdapter`, `ToolInvocation`,
  `VerdictResult`, `ProviderError`, and the `StreamPhase` / `BlockKind` /
  `StreamEvent` state machine the streaming gate runs.
- `chio-provider-adapter-core` - `http` transport primitives
  (`HttpTransport`, `AuthScheme`, `MockHttpTransport`, `map_transport_error`),
  the shared SSE frame parser, `ensure_streaming_allow_no_redactions`, the
  `Provider` trait, and `impl_unavailable_loaded_weights!`.
- `chio-manifest` - `ToolManifest`, `validate_manifest`, and
  `ServerTool::from_anthropic_wire_name`.
- `async-trait` - the `ProviderHttpTransport` impl on `MockTransport`.
- `serde` / `serde_json` / `thiserror` - wire (de)serialization and
  `AnthropicAdapterError`.

## Extension points

Callers supply the verdict evaluator themselves: `send_messages_stream` /
`gate_sse_stream` take an `evaluate: FnMut(&ToolInvocation) ->
Result<VerdictResult, ProviderError>` closure, and the batch path expects the
caller to produce a `VerdictResult` between `lift_batch` and
`lower_tool_result_block`. The crate has no built-in kernel call.
