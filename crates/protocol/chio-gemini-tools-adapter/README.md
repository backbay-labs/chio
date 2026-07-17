# chio-gemini-tools-adapter

Provider-native adapter that mediates Google Gemini `generateContent` tool-use
traffic through the Chio kernel. Lifts `functionCall` parts out of a Gemini
response into `chio_tool_call_fabric::ToolInvocation`s for kernel evaluation,
and lowers a kernel verdict back into a `functionResponse` part for the next
turn. Pinned to upstream API version `v1beta` (`transport::GEMINI_API_VERSION`,
mirrored in `Cargo.toml`'s `[package.metadata.chio]`).

The crate owns lift/lower and transport only; it has no dependency on
`chio-kernel`. A caller drives evaluation itself: for batch calls, run each
`ToolInvocation` from `lift_batch` through the kernel and pass the verdict to
`lower_function_response`; for streaming calls, pass an `evaluate` closure to
`generate_content_stream` / `gate_sse_stream` that the adapter invokes per
`functionCall` frame.

## Responsibilities

- Forward a native `generateContent` / `streamGenerateContent` request to the
  Generative Language API and buffer the response (`GeminiTransport`, built on
  the shared `chio_provider_adapter_core::http` transport).
- Lift every `functionCall` part in a batch response into a
  canonically-encoded `ToolInvocation` stamped with `Principal::GeminiProject`
  provenance (`lift_batch`).
- Gate a `streamGenerateContent` SSE body frame by frame: evaluate each
  buffered `functionCall` against a caller-supplied verdict closure before any
  bytes are forwarded, and fail closed (return no bytes at all) if any call is
  denied or carries redactions (`gate_sse_stream`).
- Lower a kernel verdict and tool result into a `functionResponse` part:
  apply redactions on allow, emit a structured `{"error": ...}` payload on
  deny (`lower_function_response`).
- Classify Gemini safety blocks (`promptFeedback.blockReason`,
  `candidates[].finishReason=SAFETY`) as `ProviderError::ContentPolicy` on the
  batch response path.
- Reject any configured or transport-advertised API version other than
  `v1beta` before touching the network, stamping provenance, or lowering.

## Public API

- `GeminiAdapter` - adapter handle (`new`, `provider`, `api_version`,
  `config`, `transport`).
- `GeminiAdapter::generate_content` / `generate_content_stream` - proxy a
  request through the configured transport, then lift or gate the response.
- `GeminiAdapter::lift_batch` / `gate_sse_stream` - lift or gate an
  already-fetched response payload without going through the transport.
- `GeminiAdapter::lower_function_response` - lower a verdict and tool result
  into a `FunctionResponsePart`.
- `GeminiAdapterConfig::new` - builds a config with `api_version` pinned to
  `GEMINI_API_VERSION`; also carries `server_id`, `server_name`,
  `server_version`, `public_key`, and `project_id`.
- `native::{FunctionCallPart, FunctionResponsePart}` - Gemini's wire-level
  content-part shapes (re-exported at the crate root).
- `transport::{Transport, GeminiTransport, MockTransport}` - outbound
  transport trait, the real `reqwest`-backed client, and a hermetic test
  double. `Transport`, `GeminiTransport`, `GEMINI_API_VERSION`,
  `GEMINI_API_KEY_ENV`, and `GEMINI_GENERATE_CONTENT_HOST` are also
  re-exported at the crate root; `MockTransport` is reachable only via
  `transport::`.
- `GeminiAdapterError` - `Transport` / `Provider` error wrapper (`thiserror`).
- Implements `chio_provider_adapter_core::Provider` and, via
  `impl_unavailable_loaded_weights!`, `chio_core::LoadedWeights` (the Gemini
  API exposes no runtime model bytes).

## Adapter-visible error taxonomy

Gemini failures reach this crate two ways: as an HTTP status from the
Generative Language API (classified by the shared
`chio_provider_adapter_core::http::map_transport_error`, "HTTP transport
boundary" below) or as a shape the adapter itself rejects while lifting or
gating a 2xx body ("current adapter path"). `ProviderError::Other` never
appears; an unrecognized shape falls back to `Malformed`.

The table is parsed by `tests/error_taxonomy_doctest.rs`; keep each envelope
one valid inline JSON object.

<!-- error-taxonomy:start -->
| ProviderError class | Native or boundary envelope | Source | Trigger |
| -------------------- | ---------------------------- | ------- | ------- |
| `ProviderError::RateLimited` | `{"error":{"code":429,"message":"Resource has been exhausted (e.g. check quota).","status":"RESOURCE_EXHAUSTED"}}` | HTTP transport boundary | Status 429. `retry_after_ms` is currently hardcoded to `0`; no `Retry-After` header is read. |
| `ProviderError::ContentPolicy` | `{"promptFeedback":{"blockReason":"SAFETY","safetyRatings":[]}}` | current adapter path (batch only) | `promptFeedback.blockReason` is set, or any `candidates[].finishReason="SAFETY"`; also status 403. |
| `ProviderError::BadToolArgs` | `{"candidates":[{"content":{"parts":[{"functionCall":{"name":"get_weather","args":"not-an-object"}}]}}]}` | current adapter path | `functionCall.args` is not a JSON object; also 4xx statuses other than 429/403. |
| `ProviderError::Upstream5xx` | `{"error":{"code":503,"message":"The service is currently unavailable.","status":"UNAVAILABLE"}}` | HTTP transport boundary | Any 5xx status from the Generative Language API. |
| `ProviderError::TransportTimeout` | `{"transport":"timeout","endpoint":"https://generativelanguage.googleapis.com","timeout_ms":60000}` | HTTP transport boundary | The request exceeds the transport's configured timeout (60s default). |
| `ProviderError::VerdictBudgetExceeded` | `{"provider":"gemini","event":"functionCall","observed_ms":300,"budget_ms":250}` | current adapter path | The caller's verdict evaluator returns this error; `gate_sse_stream` propagates it unchanged. |
| `ProviderError::Malformed` | `{"candidates":[{"content":{"parts":[{"text":"no tool call here"}]}}]}` | current adapter path | `lift_batch` requires at least one `functionCall` part; also non-JSON bytes, an unparseable envelope, or a malformed `functionCall` / `functionResponse` shape. |
<!-- error-taxonomy:end -->

## Testing

`cargo test -p chio-gemini-tools-adapter`

This includes `benches/verdict_latency.rs`, a `#[test]` (not a Criterion
benchmark) asserting the cold-init gate-and-verdict path stays under a 500ms
p99 across 128 samples.

## See also

- `chio-tool-call-fabric` - `ToolInvocation`, `VerdictResult`, `ProviderError`,
  and the fabric contract this adapter targets.
- `chio-provider-adapter-core` - the shared HTTP transport, SSE framing, and
  response-envelope helpers this crate wires to Gemini's host and auth.
- `chio-provider-conformance` - replays the `fixtures/gemini/*.ndjson` corpus
  against this adapter (`tests/replay_gemini.rs`, feature `fixtures-gemini`).
