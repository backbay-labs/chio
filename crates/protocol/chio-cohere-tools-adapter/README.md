# chio-cohere-tools-adapter

Provider-native adapter that mediates Cohere `/v2/chat` tool-use traffic
through the Chio kernel. It forwards a native chat or streaming request to
the upstream endpoint, lifts the response's tool calls into
`chio-tool-call-fabric` types, and lowers a kernel verdict back into Cohere's
wire shape.

The adapter pins the upstream API to version `2025-04`
(`transport::COHERE_API_VERSION`). Every entry point checks both the
configured and the transport-advertised version against the pin and fails
closed on drift, before any request is sent or provenance is stamped.

## Responsibilities

- Forward a native `/v2/chat` request through `CohereTransport`
  (`reqwest`-backed, bearer auth, via the shared `chio-provider-adapter-core`
  HTTP transport) and lift `message.tool_calls` from the buffered response
  into `chio_tool_call_fabric::ToolInvocation`.
- Gate the SSE `/v2/chat` stream: buffer each `tool-call-end` frame, run the
  caller-supplied verdict, and abort the whole response if any call is
  denied or its allow verdict carries redactions.
- Lower a kernel `VerdictResult` and `ToolResult` into a Cohere `tool` role
  message, applying JSON-Pointer redactions and canonicalizing the result
  text.
- Stamp `ProvenanceStamp` with `Principal::CohereOrg` on every lifted
  invocation.
- Reject requests, verdicts, and lowering calls whenever the configured or
  transport-advertised API version drifts from the `2025-04` pin.
- Declare `chio_core::LoadedWeights` unavailable (the Cohere Chat API
  exposes no runtime model weight bytes).

## Public API

- `CohereAdapter` - adapter handle. `chat` and `chat_stream` drive a request
  end to end; `lift_batch` and `gate_sse_stream` lift tool calls without
  sending a request; `lower_tool_message` lowers a verdict; `provider`,
  `api_version`, `config`, `transport` are accessors.
- `CohereAdapterConfig::new` - builds a config with `api_version` pinned to
  `COHERE_API_VERSION`.
- `CohereAdapterError` - local enum uniting `transport::TransportError` and
  `ProviderError` via `From`; no `CohereAdapter` method returns it today.
- `transport::{CohereTransport, MockTransport, Transport, TransportError,
  COHERE_API_KEY_ENV, COHERE_API_VERSION, COHERE_CHAT_HOST,
  COHERE_CHAT_PATH}` - re-exported at the crate root.
- `native::{ToolCallBlock, ToolCallFunction, ToolResultMessage,
  ToolResultContent}` - Cohere v2 wire types, re-exported at the crate root.
- `streaming::GatedSseStream` - alias for
  `chio_provider_adapter_core::GatedStream`; returned by `chat_stream` and
  `gate_sse_stream`.

## Error taxonomy

The adapter projects upstream Cohere failures onto
`chio_tool_call_fabric::ProviderError`. The mapping is asserted by
`tests/error_taxonomy_doctest.rs` against this README.

<!-- error-taxonomy:start -->
| ProviderError class | Native envelope (inline JSON) | Source | Trigger |
|---|---|---|---|
| `ProviderError::RateLimited` | `{"status": 429, "body": {"message": "rate limit exceeded"}}` | HTTP transport boundary | Status 429 from the upstream API, mapped by `chio_provider_adapter_core::http::map_http_status`. `retry_after_ms` is hardcoded to `0`; no `Retry-After` header is read. |
| `ProviderError::ContentPolicy` | `{"status": 200, "body": {"finish_reason": "ERROR_TOXIC", "message": "refusal"}}` | HTTP transport boundary | Status 403 from the upstream API, mapped by `chio_provider_adapter_core::http::map_http_status`. The adapter does not parse `finish_reason` or other body fields from a 2xx response; only the HTTP status triggers this class. |
| `ProviderError::BadToolArgs` | `{"id": "call_1", "type": "function", "function": {"name": "get_weather", "arguments": "not-json"}}` | current adapter path | `tool_calls[].function.arguments` does not parse as a JSON object (`CohereAdapter::invocation_from_tool_call`); also 4xx statuses other than 429/403 from the upstream API. |
| `ProviderError::Upstream5xx` | `{"status": 503, "body": {"message": "service unavailable"}}` | HTTP transport boundary | Any 5xx status from the upstream API. |
| `ProviderError::TransportTimeout` | `{"transport": "timeout", "elapsed_ms": 5000}` | HTTP transport boundary | The request exceeds the transport's configured timeout (`HttpTransportError::Timeout`, mapped to `ProviderError::TransportTimeout`). |
| `ProviderError::VerdictBudgetExceeded` | `{"observed_ms": 300, "budget_ms": 250}` | current adapter path | The caller's verdict evaluator returns this error; `gate_sse_stream` propagates it unchanged. |
| `ProviderError::Malformed` | `{"event": "tool-call-end", "frame": "missing-tool_call"}` | current adapter path | `lift_batch` requires at least one `tool_calls` entry; also non-JSON payload bytes, an envelope field that is not a JSON object or string body, a malformed `tool_call` block, or a streamed `tool-call-end` frame missing `tool_call`. |
<!-- error-taxonomy:end -->

## API pin

| Field | Value |
|---|---|
| Pinned API version | `2025-04` |
| Default endpoint | `https://api.cohere.com` |
| ProviderId | `ProviderId::Cohere` |

Bumping `COHERE_API_VERSION` requires a deliberate PR with a fixture
re-record (`Cargo.toml` `[package.metadata.chio] cohere_api_version`).

## Testing

`cargo test -p chio-cohere-tools-adapter` runs the unit and integration
suites, including `tests/live_transport.rs` (the real `reqwest` transport
against a local `wiremock` server) and `tests/error_taxonomy_doctest.rs`
(checks the table above against live `ProviderError` paths).
`benches/verdict_latency.rs` is a `#[test]`-based budget check: cold-adapter
SSE gate-and-verdict latency must stay under 500ms at p99 over 128 samples.
No test requires a live Cohere API key.

## See also

- `chio-tool-call-fabric` - defines `ToolInvocation`, `VerdictResult`,
  `ProviderError`, and the other kernel-facing types this adapter translates
  to and from.
- `chio-provider-adapter-core` - shared HTTP transport, SSE frame parsing,
  and response-envelope validation this adapter wires to Cohere's host and
  auth.
- `chio-provider-conformance` - replays recorded Cohere fixtures through
  this adapter under its `fixtures-cohere` feature.
- `chio-anthropic-tools-adapter`, `chio-gemini-tools-adapter`,
  `chio-groq-tools-adapter`, `chio-mistral-tools-adapter`,
  `chio-ollama-tools-adapter` - sibling adapters for other providers built on
  the same `chio-provider-adapter-core` foundation.
