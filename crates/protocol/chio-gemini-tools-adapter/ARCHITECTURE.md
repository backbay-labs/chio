# chio-gemini-tools-adapter architecture

## Overview

The crate is an untrusted edge adapter: it speaks Gemini's `generateContent` /
`streamGenerateContent` wire format on one side and the Chio
`chio-tool-call-fabric` contract (`ToolInvocation`, `VerdictResult`,
`ProviderError`) on the other. It has no dependency on `chio-kernel`; a caller
supplies kernel evaluation itself, either directly (batch: pass each
`lift_batch` invocation through the kernel, then call
`lower_function_response`) or through a closure the adapter drives while
streaming (`gate_sse_stream`'s `evaluate` parameter). Transport, HTTP auth, and
SSE framing are not reimplemented here; they come from the shared
`chio-provider-adapter-core` crate that every native provider adapter in this
workspace builds on.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | `GeminiAdapter`, `GeminiAdapterConfig`, the API-version guard (`ensure_supported_api_version`), batch lift (`lift_batch`, `invocation_from_function_call`), response lowering and its helpers, `GeminiAdapterError`, the `Provider` impl. |
| `src/transport.rs` | `Transport` trait, `GeminiTransport` (real client, built on `chio_provider_adapter_core::http`), `MockTransport` (hermetic test double), the pinned host/path/version constants. |
| `src/response.rs` (private) | Batch-response envelope unwrapping, Gemini safety-block classification, `functionCall` part extraction. |
| `src/streaming.rs` | `gate_sse_stream`: SSE frame parsing, per-candidate `functionCall` discovery, per-call verdict evaluation, fail-closed byte gating. |
| `src/native.rs` | `FunctionCallPart`, `FunctionResponsePart` - Gemini's wire-level content-part shapes. |
| `src/loaded_weights.rs` | `chio_core::LoadedWeights` impl via `impl_unavailable_loaded_weights!`; the Gemini API exposes no runtime model bytes. |

## Request lifecycle

Batch (`generate_content` / `lift_batch`):

1. `ensure_supported_api_version` checks that `config.api_version` and
   `transport.api_version()` both equal `GEMINI_API_VERSION`, before any
   network call.
2. `Transport::send_generate_content` POSTs to
   `/v1beta/models/<model>:generateContent` and buffers the response.
3. `response::function_calls` unwraps a `body` / `response` / `payload`
   envelope if present, classifies Gemini safety blocks as `ContentPolicy`,
   then collects every `functionCall` part (top-level or per-candidate). Zero
   parts is a `Malformed` error.
4. Each part is validated and its `args` canonicalized to RFC 8785 bytes, then
   stamped with fresh `Principal::GeminiProject` provenance into a
   `ToolInvocation`.
5. The caller evaluates each invocation against the kernel and calls
   `lower_function_response` with the verdict: `Allow` applies redactions to
   the tool result bytes, `Deny` produces a `{"error": "<reason>"}` payload.

Streaming (`generate_content_stream` / `gate_sse_stream`):

1. Same API-version guard, then `Transport::send_generate_content_stream`
   POSTs to `.../streamGenerateContent?alt=sse` and buffers the full SSE body.
2. `parse_sse_frames` (shared, unknown-field-rejecting) splits the body into
   frames; a frame without a `data:` payload passes through unexamined.
3. Each frame's `candidates[].content.parts[]` is scanned for `functionCall`
   parts. Each one is lifted through the same path as the batch case and
   handed to the caller's `evaluate` closure.
4. `ensure_streaming_allow_no_redactions` requires an `Allow` verdict with no
   redactions for every call; a `Deny` or a redacted `Allow` aborts the whole
   call before any bytes are returned.
5. On success, frame bytes accumulate in stream order into one output buffer,
   returned alongside every invocation and verdict observed.

## Invariants and failure modes

- The `v1beta` pin is enforced defensively: every public entrypoint checks
  both the config's and the transport's advertised API version before doing
  anything else, so a deserialized config or a custom `Transport` cannot
  smuggle a drifted upstream contract past provenance stamping.
- `gate_sse_stream` buffers the entire response before returning. A single
  denied or redacted `functionCall` anywhere in the stream fails the whole
  call; there is no partial-forward path.
- Safety-block classification (`promptFeedback.blockReason`,
  `candidates[].finishReason="SAFETY"`) runs only on the batch path
  (`response::function_calls`); streaming frames are not checked against it.
- `lift_batch` fails closed when a response contains no `functionCall` parts;
  `gate_sse_stream` does not, since a tool-call-free stream is a normal
  plain-text turn.
- `functionCall.args` must be a JSON object, and `functionCall` /
  `functionResponse` names must be non-empty with no surrounding whitespace;
  both fail closed (`BadToolArgs`, `Malformed`).
- A redaction path must be an empty string (whole-value replace) or a JSON
  Pointer starting with `/`; an unresolvable pointer fails closed as
  `Malformed` rather than silently skipping the redaction.
- `GeminiTransport::new` / `with_base_url` / `from_env` reject an empty API
  key before it can reach the wire (`TransportError::MissingApiKey`).

## Dependencies

Internal: `chio-core` (Cargo-aliased to `chio-core-types`) supplies
`canonical::canonical_json_bytes` for argument canonicalization and the
`LoadedWeights` trait `loaded_weights.rs` implements. `chio-tool-call-fabric`
supplies `ToolInvocation`, `ProvenanceStamp`, `Principal`, `VerdictResult`,
`DenyReason`, `Redaction`, and `ProviderError`. `chio-provider-adapter-core`
supplies the HTTP transport (`http` module), SSE frame parsing, `GatedStream`,
the `Provider` trait, and `ensure_streaming_allow_no_redactions`. External:
`async-trait` for the `Transport` trait, `serde` / `serde_json` for wire
types, `thiserror` for the local error enums.

## Extension points

`Transport` is the seam a consumer implements against: `GeminiAdapter::new`
takes any `Arc<dyn Transport>`, so a caller can point the adapter at a proxy
or a Gemini-compatible endpoint, or substitute `transport::MockTransport` for
hermetic tests, without touching `GeminiAdapter`'s lift/lower/gate logic.
