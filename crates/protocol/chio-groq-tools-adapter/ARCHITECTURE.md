# chio-groq-tools-adapter architecture

## Overview

The crate is an edge component: it faces the untrusted Groq `chat/completions`
API on one side and the `chio_tool_call_fabric` contract on the other. It does
not evaluate policy itself; callers supply a verdict-evaluator closure
(`FnMut(&ToolInvocation) -> Result<VerdictResult, ProviderError>`) to the
streaming path, or call `lower_function_response` directly on the batch path,
and every send, lift, gate, and lower operation re-checks the pinned API
version before that closure or the network is touched. Groq is
OpenAI-compatible, so wire decoding and SSE gating are shared primitives from
`chio-provider-adapter-core` - the same ones `chio-openai-adapter`'s
`provider-adapter` feature uses; this crate supplies only the Groq-specific
transport, config, and version pin.

## Module map

| Path | Responsibility |
|---|---|
| `src/lib.rs` | `GroqAdapter`, `GroqAdapterConfig`, `GroqAdapterError`; send/lift/lower entry points; the API-version guard (`ensure_supported_api_version`); outbound request-shape validation (`validate_chat_request_body`); the `Provider` impl. |
| `src/transport.rs` | `Transport` trait re-export; pinned `GROQ_*` constants; `groq_transport` / `groq_transport_from_env` / `groq_transport_config`; `MockTransport` (hermetic, backed by the shared `MockHttpTransport`). |
| `src/native.rs` | `FunctionCallPart` / `FunctionResponsePart` - normalized decoded-call and lowered-response shapes. |
| `src/response.rs` | Response-envelope unwrapping, safety-block / `content_filter` classification, `tool_calls[]` extraction. Crate-private (`mod response;`, not `pub`). |
| `src/streaming.rs` | `GroqAdapter::gate_sse_stream` - SSE gating for `chat.completion.chunk` frames via the shared `gate_openai_sse_tool_calls` primitive. |
| `src/loaded_weights.rs` | `LoadedWeights` impl reporting Groq runtime weights as unavailable. |
| `src/tests.rs` | Adapter-level unit tests (`#[cfg(test)]`, declared from `lib.rs`). |

## Request lifecycle

Non-streaming (`send_chat_completion`):

1. `ensure_supported_api_version` requires `config.api_version` to equal
   `GROQ_API_VERSION`; drift fails closed before serialization or any
   transport call.
2. `validate_chat_request_body` rejects a non-JSON or non-object body, an
   empty or whitespace-padded `model`, or an empty `messages` array.
3. `Transport::post_json` POSTs the body to `GROQ_CHAT_COMPLETIONS_PATH` with
   a `Bearer` header (`HttpTransport`) or returns a scripted response
   (`MockTransport`); failures map to `ProviderError` via
   `map_transport_error`.
4. `lift_batch` (via `response::function_calls`) unwraps the response
   envelope, classifies a `content_filter` finish reason or a
   `promptFeedback.blockReason` as `ContentPolicy`, and extracts every
   `choices[].message.tool_calls[]` entry; no `tool_calls` at all is itself a
   `Malformed` error, not an empty success.
5. Each entry becomes a `ToolInvocation` (`invocation_from_function_call`):
   `id` / `name` must be non-empty and untrimmed, `args` must be a JSON
   object, and the arguments are re-encoded to canonical JSON (RFC 8785)
   with a `Principal::GroqProject` provenance stamp.
6. The caller evaluates each invocation and calls `lower_function_response`;
   an allow applies JSON-Pointer redactions, a deny renders a
   `{"error": ...}` payload naming the deny reason.

Streaming (`send_chat_completion_stream`):

1. The same version and request-shape checks run before `Transport::post_sse`
   buffers the full SSE body (no incremental network read).
2. `gate_sse_stream` parses SSE frames (shared parser, `[DONE]` sentinel)
   and, for each `choices[].delta.tool_calls[]` (or `.message.tool_calls[]`
   on aggregated chunks) entry, builds a `ToolInvocation` via
   `invocation_from_function_call` and calls the caller's `evaluate` closure
   before appending the frame's raw bytes to the output.
3. An allow verdict carrying redactions, or any deny verdict, fails the whole
   stream closed (`ensure_streaming_allow_no_redactions`, enforced by the
   shared gate) rather than partially forwarding a gated chunk.
4. The result is a `GatedSseStream` (`GatedStream` alias): forwardable bytes
   plus the invocations and verdicts observed in stream order.

## Invariants and failure modes

- `GroqAdapterConfig::new` always pins `api_version` to `GROQ_API_VERSION`;
  every public operation re-checks the pin via `ensure_supported_api_version`
  and fails closed before a transport call, provenance stamp, or evaluator
  invocation.
- `validate_chat_request_body` runs before every POST, batch and streaming
  alike; a non-object body, empty or padded `model`, or empty `messages`
  never reaches the transport.
- `lift_batch` classifies a content-policy block before it attempts to
  decode any tool call, so a safety-blocked response never partially
  decodes.
- Decoded `id` and `name` must be non-empty and free of surrounding
  whitespace; decoded `arguments` must be a JSON object, not a bare value or
  scalar.
- `lower_function_response` requires a non-empty, unpadded `tool_call_id`
  regardless of verdict.
- `apply_redactions` requires every redaction path to be a JSON Pointer
  (`/`-prefixed) that resolves against the tool result; an empty path
  replaces the whole value.
- `groq_transport_from_env` fails closed (`HttpTransportError::MissingEnvVar`)
  when `GROQ_API_KEY` is unset or empty rather than authenticating with an
  empty bearer token.
- `MockTransport` responses are FIFO-scripted; an unscripted call fails
  closed (`HttpTransportError::MockExhausted`) rather than blocking or
  returning empty bytes.
- `README.md`'s error-taxonomy table (between the `error-taxonomy:start` /
  `:end` markers) is checked against live adapter behavior by
  `tests/error_taxonomy_doctest.rs`; the two must stay in sync.

## Dependencies

`chio-core` is aliased to `chio-core-types` (`Cargo.toml`: `chio-core = {
package = "chio-core-types" }`); it supplies `canonical::canonical_json_bytes`
for argument canonicalization. `chio-tool-call-fabric` supplies the
provider-agnostic contract this adapter translates to and from:
`ToolInvocation`, `VerdictResult`, `ProviderError`, `ProviderId::Groq`,
`Principal::GroqProject`, `DenyReason`, `Redaction`, `ProviderRequest`,
`ToolResult`. `GroqAdapter` does not implement fabric's `ProviderAdapter`
trait (the async single-call `lift`/`lower` contract `OpenAiAdapter`
implements); its own methods operate on a whole batch or stream directly.
`chio-provider-adapter-core` supplies every piece of OpenAI-compatible
dialect logic this crate reuses: `response_body` /
`openai_tool_call_to_function_call` (`response.rs`),
`gate_openai_sse_tool_calls` / `GatedStream` (`streaming.rs`), the `http`
transport module (`HttpTransport`, `MockHttpTransport`,
`ProviderHttpTransport`, `AuthScheme`, `map_transport_error`), the `Provider`
identity trait, and the `impl_unavailable_loaded_weights!` macro.
`chio-openai-adapter`'s `provider-adapter` feature draws on the same shared
crate for its own Chat Completions and Responses API paths; the two adapter
crates share no direct dependency on each other.

External: `async-trait` for the `Transport` trait; `serde` / `serde_json` for
wire and config types; `thiserror` for `GroqAdapterError`. Dev-only: `tokio`
(multi-thread rt) drives the async tests; `wiremock` backs
`tests/http_transport_replay.rs`.

## Extension points

- `transport::Transport` (`chio_provider_adapter_core::http::ProviderHttpTransport`)
  - implement to point the adapter at something other than the real
  `HttpTransport`, as `MockTransport` does for hermetic tests.
  `GroqAdapter::new` accepts any `Arc<dyn Transport>`.
- `send_chat_completion_stream` and `gate_sse_stream` take an `evaluate`
  closure as the verdict seam; the crate places no constraint on where that
  verdict comes from beyond the `VerdictResult` shape.
