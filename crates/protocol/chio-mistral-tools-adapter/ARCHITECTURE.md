# chio-mistral-tools-adapter architecture

## Overview

The crate is an edge component: it faces the untrusted Mistral `chat/completions` API on one side and the `chio_tool_call_fabric` contract on the other. It does not evaluate policy itself; callers supply a verdict-evaluator closure (`FnMut(&ToolInvocation) -> Result<VerdictResult, ProviderError>`), and every send, lift, gate, and lower path re-checks the pinned API version before that closure or the network is touched. Mistral is OpenAI-compatible, so wire decoding and SSE gating are shared primitives from `chio-provider-adapter-core`; this crate supplies only the Mistral-specific transport, config, and version pin.

## Module map

| Path | Responsibility |
|---|---|
| `src/lib.rs` | `MistralAdapter`, `MistralAdapterConfig`, `MistralChatRequest`; send/lift/lower entry points; the API-version guard (`ensure_supported_api_version`); the `Provider` impl. |
| `src/transport.rs` | `Transport` trait; `MistralHttpTransport` (real HTTPS client, bearer auth); `MockTransport` (scripted, hermetic); pinned endpoint/version/env-var constants. |
| `src/native.rs` | `FunctionCallPart` / `FunctionResponsePart` - normalized decoded-call and lowered-response shapes. |
| `src/response.rs` | Response-envelope unwrapping, `content_filter` classification, `tool_calls[]` extraction. Crate-private. |
| `src/streaming.rs` | `gate_sse_stream` - SSE gating for `chat.completion.chunk` frames via the shared `gate_openai_sse_tool_calls` primitive. |
| `src/loaded_weights.rs` | `LoadedWeights` impl reporting Mistral runtime weights as unavailable. |
| `src/tests.rs` | Adapter-level unit tests (`#[cfg(test)]`). |

## Request lifecycle

Non-streaming (`send_chat_completion`):

1. Caller builds a `MistralChatRequest` and calls `send_chat_completion`.
2. `ensure_supported_api_version` requires `config.api_version` and `transport.api_version()` to both equal `MISTRAL_API_VERSION`; either drifting fails closed before serialization.
3. `MistralChatRequest::to_json_bytes` rejects an empty `model` or empty `messages`, then serializes.
4. `Transport::chat_completion` POSTs the body (`MistralHttpTransport` hits `POST /v1/chat/completions` with `Authorization: Bearer <key>`; `MockTransport` returns a scripted response and records the call).
5. `lift_batch` unwraps the response envelope, classifies `finish_reason: content_filter` as `ContentPolicy`, and extracts every `choices[].message.tool_calls[]` entry; no `tool_calls` at all is itself a `Malformed` error, not an empty success.
6. Each entry becomes a `ToolInvocation`: `id`/`name` must be non-empty and untrimmed, `args` must be a JSON object, and the arguments are re-encoded to canonical JSON (RFC 8785) with a `Principal::MistralProject` provenance stamp.
7. The caller evaluates each invocation and calls `lower_function_response`; allow applies JSON-Pointer redactions, deny renders a `{"error": ...}` payload naming the deny reason.

Streaming (`send_chat_completion_stream`):

1. The request is cloned with `stream = true`; the API-version pin is re-checked before the POST.
2. `Transport::chat_completion_stream` buffers the full SSE body (no incremental network read).
3. `gate_sse_stream` parses SSE frames and, for each `choices[].delta.tool_calls[]` (or `.message.tool_calls[]`) entry, builds a `ToolInvocation` and calls the caller's `evaluate` closure before appending the frame's raw bytes to the output.
4. An allow verdict carrying redactions, or any deny verdict, fails the whole stream closed rather than partially forwarding a gated chunk.
5. The result is a `GatedSseStream` (`GatedStream` alias): forwardable bytes plus the invocations and verdicts observed in stream order.

## Invariants and failure modes

- The `2025-04` pin is checked on every public entry point against both `config.api_version` and `transport.api_version()`; a deserialized config or a custom `Transport` claiming a stale contract cannot stamp `2025-04` provenance against a drifted snapshot.
- Transport failures fail closed: a timeout, non-2xx status, or `MockTransport` exhaustion becomes a `ProviderError`, never an empty success.
- `validate_function_call` rejects empty or whitespace-padded `id`/`name` and non-object `arguments` before a `ToolInvocation` is built.
- Streaming gating never forwards a `tool_calls` frame ahead of its verdict, and fails closed on an allow-with-redactions or a deny rather than partially applying it.
- `MistralHttpTransport::from_env` fails closed (`HttpTransportError::MissingEnvVar`) when `MISTRAL_API_KEY` is unset or empty rather than authenticating with an empty bearer token.
- `MockTransport` responses are FIFO-scripted; an unscripted call fails closed (`TransportError::MockExhausted`) rather than blocking or returning empty bytes.

## Dependencies

Internal: `chio-tool-call-fabric` supplies the provider-agnostic contract (`ToolInvocation`, `VerdictResult`, `ProviderError`, `ProviderId`, `Principal`, `ProvenanceStamp`, `DenyReason`, `Redaction`, `ToolResult`, `ProviderRequest`). `chio-provider-adapter-core` supplies the shared HTTP transport (`HttpTransport`, `AuthScheme`, `map_transport_error`), SSE parsing and gating (`gate_openai_sse_tool_calls`), the OpenAI-compatible `tool_calls[]` decoder (`openai_tool_call_to_function_call`, `response_body`), the `Provider` trait, and `impl_unavailable_loaded_weights!`. `chio-core` is aliased to `chio-core-types` in `Cargo.toml`; used directly for `canonical::canonical_json_bytes` and indirectly for the `LoadedWeights` impl the `impl_unavailable_loaded_weights!` macro expands into `loaded_weights.rs`.

External: `async-trait` for the `Transport` trait; `serde`/`serde_json` for wire and config types; `thiserror` for `TransportError` and `MistralAdapterError`; `tokio` for the async runtime. Dev-only: `wiremock` backs `tests/live_transport.rs`.

## Extension points

- `transport::Transport` - implement to point the adapter at a different HTTP client or test double; the crate ships `MistralHttpTransport` for production and `MockTransport` for hermetic tests.
