# chio-cohere-tools-adapter architecture

## Overview

The adapter owns the Cohere `/v2/chat` translation boundary: native
request/response bytes in, `chio_tool_call_fabric::ToolInvocation` out; a
verdict in, a native Cohere `tool` message out. It has no dependency on
`chio-kernel` or any policy engine. The caller (in production, the Chio
kernel; in `chio-provider-conformance`, a fixture replay) supplies the
`VerdictResult` for each invocation, either by calling `lower_tool_message`
directly (batch path) or through the `evaluate` closure passed to
`chat_stream` / `gate_sse_stream` (streaming path). The crate never decides
allow or deny on its own. `CohereAdapter` implements
`chio_provider_adapter_core::Provider` (`provider_id`, `api_version`) for
identity purposes; it does not implement `chio_tool_call_fabric::ProviderAdapter`.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | `CohereAdapterConfig`, `CohereAdapter`, the API-version pin check, batch lift (`lift_batch`, `invocation_from_tool_call`), verdict lowering (`lower_tool_message`), redaction application, and deny-reason formatting. |
| `src/transport.rs` | `Transport` trait, the pinned `COHERE_*` constants, `CohereTransport` (real `reqwest`-backed client via `chio_provider_adapter_core::http`), and `MockTransport` (hermetic, backed by `MockHttpTransport`). |
| `src/streaming.rs` | `gate_sse_stream`: SSE frame parsing and per-call verdict gating for the `/v2/chat` stream surface. |
| `src/native.rs` | Cohere v2 wire types: `ToolCallBlock`, `ToolCallFunction`, `ToolResultMessage`, `ToolResultContent`. |
| `src/loaded_weights.rs` | `chio_core::LoadedWeights` impl for `CohereAdapter`; always reports unavailable. |

## Request lifecycle

1. `chat` (batch) or `chat_stream` (SSE) calls `ensure_supported_api_version`,
   then `Transport::send_chat` or `send_chat_stream`.
2. `CohereTransport` POSTs the caller's raw `/v2/chat` JSON body to
   `COHERE_CHAT_HOST` + `COHERE_CHAT_PATH` with a `Bearer` header through
   `chio_provider_adapter_core::http::HttpTransport`; transport failures map
   to `ProviderError` via `map_transport_error`.
3. Batch: `lift_batch` validates the outer envelope
   (`chio_provider_adapter_core::response_body`), reads `message.tool_calls`,
   and calls `invocation_from_tool_call` per entry: validates `id`,
   `type == "function"`, and `function.name`, parses `arguments` as a JSON
   object, and re-encodes it as RFC 8785 canonical bytes.
4. Stream: `gate_sse_stream` parses SSE frames
   (`SseParseOptions::ignoring_unknown`) and for each `tool-call-end` frame
   (`tool_call` read from `data.tool_call` or `data.delta.tool_call`) runs
   `invocation_from_tool_call` (the same per-call validation as the batch
   path), then the caller's `evaluate` closure; a `Deny` or a
   redaction-bearing `Allow` aborts the call. Every frame's raw bytes are
   otherwise forwarded in order.
5. The caller, not this crate, produces the `VerdictResult` for each
   invocation, batch or streamed.
6. `lower_tool_message` applies `Allow` redactions (JSON Pointer paths) or
   formats a `Deny` reason, canonicalizes the result, and returns a
   `ToolResultMessage` for the next Cohere turn.

## Invariants and failure modes

- Every public entry point calls `ensure_supported_api_version` first:
  `config.api_version` and `transport.api_version()` must both equal
  `COHERE_API_VERSION` ("2025-04"), or the call fails closed before any
  transport send or provenance stamp. `CohereAdapter::new` itself stays
  infallible; only operational calls enforce the pin.
- Streaming gate failure is all-or-nothing per call to `gate_sse_stream`: the
  first denied tool call, or an allow verdict that requests redactions,
  returns `Err` and discards the whole buffered response. There is no
  partial forwarding.
- `tool_call.id`, `function.name`, and the `tool_call_id` passed to
  `lower_tool_message` must be non-empty and free of surrounding whitespace,
  or the call fails as `ProviderError::Malformed`.
- Tool call arguments must parse as a JSON object; anything else fails as
  `ProviderError::BadToolArgs`.
- `CohereTransport::new` / `with_base_url` / `from_env` refuse an empty API
  key (`TransportError::MissingApiKey`) rather than send an empty bearer
  token.
- `MockTransport` fails closed when its scripted response queue is
  exhausted, rather than returning an empty success.
- `README.md`'s error-taxonomy table (between the `error-taxonomy:start` /
  `:end` markers) is checked against live adapter behavior by
  `tests/error_taxonomy_doctest.rs`; the two must stay in sync.

## Dependencies

`chio-core` is aliased to `chio-core-types` (`Cargo.toml`: `chio-core = {
package = "chio-core-types" }`); it supplies `canonical::canonical_json_bytes`
and the `LoadedWeights` / `LoadedWeightsUnavailable` trait implemented in
`loaded_weights.rs`. `chio-tool-call-fabric` supplies the kernel-facing types
this adapter translates to and from (`ToolInvocation`, `VerdictResult`,
`ProviderError`, `ProviderRequest`, `Redaction`, `ProvenanceStamp`,
`Principal`, `DenyReason`). `chio-provider-adapter-core` supplies the HTTP
transport, SSE frame parser, response-envelope validator, and the
`impl_unavailable_loaded_weights!` macro used in `loaded_weights.rs`.
`async-trait` backs the `Transport` trait; `thiserror` backs `TransportError`
and `CohereAdapterError`.

## Extension points

`Transport` is the seam for outbound `/v2/chat` delivery: implement it to
point the adapter at something other than `CohereTransport`, as
`MockTransport` does for hermetic tests. `CohereAdapter::chat_stream` and
`gate_sse_stream` take an `evaluate` closure as the verdict seam; the crate
places no constraint on where that verdict comes from beyond the
`VerdictResult` shape.
