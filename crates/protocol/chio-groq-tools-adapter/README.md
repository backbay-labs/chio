# chio-groq-tools-adapter

Provider-native adapter that mediates Groq `chat/completions` tool-use traffic
through the Chio kernel fabric. It forwards a native request to
`api.groq.com`, lifts each returned `tool_calls[]` entry into a
`chio_tool_call_fabric::ToolInvocation`, and lowers a kernel verdict back into
the `tool`-role message Groq expects on the next turn.

Groq's `chat/completions` API is OpenAI-compatible, so the wire decoding and
SSE gating this adapter uses come from the shared `chio-provider-adapter-core`
crate - the same primitives `chio-openai-adapter`'s `provider-adapter` feature
uses for OpenAI's own Chat Completions surface. The two adapter crates share
no dependency on each other; this crate owns only the Groq-specific
transport, config, and the pinned upstream API version (`2025-04`).

## Responsibilities

- Forward `chat/completions` requests over HTTPS (production `HttpTransport`
  via `groq_transport` / `groq_transport_from_env`, or a scripted
  `MockTransport` for hermetic tests), buffering the full response before
  lifting or gating.
- Validate the outbound request body before every POST, batch or streaming:
  must be a JSON object with a non-empty, unpadded `model` and at least one
  `messages` entry.
- Lift each OpenAI-compatible `tool_calls[]` entry, batch or streamed, into a
  `ToolInvocation`: decode the JSON-encoded `arguments` string, re-encode it
  to canonical JSON (RFC 8785), and stamp `Principal::GroqProject`
  provenance.
- Gate streamed `chat.completion.chunk` SSE frames on a caller-supplied
  kernel verdict before forwarding any chunk carrying a `tool_calls` part.
- Lower a kernel `VerdictResult` and `ToolResult` into a `tool_call_id`-keyed
  response part: apply JSON-Pointer redactions on allow, render a
  `{"error": ...}` payload on deny.
- Classify a `content_filter` finish reason or a `promptFeedback.blockReason`
  as a content-policy denial instead of an empty success.
- Pin the upstream API version to `2025-04` and fail closed on drift before
  any request, lift, gate, or lower runs.
- Report `chio_core::LoadedWeights` as unavailable (Groq's `chat/completions`
  API exposes no runtime model bytes).

## Public API

- `GroqAdapterConfig::new(server_id, server_name, server_version, public_key,
  project_id)` - config with `api_version` pinned to `GROQ_API_VERSION`.
- `GroqAdapter::new(config, transport)` - adapter handle over any
  `Arc<dyn transport::Transport>`; `.provider()`, `.api_version()`,
  `.config()`, `.transport()`.
- `GroqAdapter::send_chat_completion` / `send_chat_completion_stream` - POST
  through the transport, then lift or gate the response.
- `GroqAdapter::lift_batch` / `gate_sse_stream` - lift or gate an
  already-buffered payload without a transport call.
- `GroqAdapter::lower_function_response` - lower a kernel verdict and
  `ToolResult` into a `FunctionResponsePart`.
- `native::{FunctionCallPart, FunctionResponsePart}` - normalized
  lifted-call and lowered-response shapes, re-exported at the crate root.
- `transport::{groq_transport, groq_transport_from_env, groq_transport_config,
  AuthScheme, HttpTransport, MockTransport, Transport, GROQ_API_VERSION,
  GROQ_CHAT_COMPLETIONS_HOST, GROQ_CHAT_COMPLETIONS_PATH, GROQ_API_KEY_ENV}` -
  `groq_transport`, `groq_transport_from_env`, `AuthScheme`, `HttpTransport`,
  `MockTransport`, `Transport`, and the version/host/path constants are
  re-exported at the crate root.
- `streaming::GatedSseStream` - alias for
  `chio_provider_adapter_core::GatedStream`.
- `GroqAdapterError` - adapter-local enum wrapping
  `transport::HttpTransportError` and `ProviderError`; no `GroqAdapter`
  method returns it today.
- `GroqAdapter` implements `chio_provider_adapter_core::Provider`.

## Error taxonomy

The adapter projects upstream Groq failures onto
`chio_tool_call_fabric::ProviderError`. The mapping is asserted by
`tests/error_taxonomy_doctest.rs` against this README.

<!-- error-taxonomy:start -->
| ProviderError class | Native or boundary envelope | Source | Trigger |
| -------------------- | ---------------------------- | ------- | ------- |
| `ProviderError::RateLimited` | `{"status": 429, "body": "rate limited"}` | `chio_provider_adapter_core::http::map_http_status` (status 429), via `GroqAdapter::post_chat_completion` (`src/lib.rs`) | Any non-2xx status 429 from `api.groq.com`. `retry_after_ms` is hardcoded to `0`; no `Retry-After` header is read. Exercised by `send_chat_completion_maps_upstream_status` (`src/tests.rs`). |
| `ProviderError::ContentPolicy` | `{"choices":[{"message":{"role":"assistant","content":""},"finish_reason":"content_filter"}]}` | `classify_content_policy` / `safety_block_reason` in `src/response.rs` | Any `choices[].finish_reason="content_filter"`, or a top-level `promptFeedback.blockReason` (also covered by `lift_batch_maps_safety_block_to_content_policy`); also HTTP status 403. |
| `ProviderError::BadToolArgs` | `{"choices":[{"message":{"tool_calls":[{"id":"call_bad_1","type":"function","function":{"name":"get_weather","arguments":"\"not-an-object\""}}]}}]}` | `validate_function_call` in `src/lib.rs`, called from `invocation_from_function_call` | Decoded `tool_calls[].function.arguments` is not a JSON object. Also covers a missing or empty request `model` / `messages` (`validate_chat_request_body`, `src/lib.rs`) and 4xx statuses other than 429/403. |
| `ProviderError::Upstream5xx` | `{"status": 503, "body": "overloaded"}` | `chio_provider_adapter_core::http::map_http_status` (5xx branch), via `GroqAdapter::post_chat_completion` (`src/lib.rs`) | Any 5xx status from `api.groq.com`. Exercised by `real_transport_maps_upstream_5xx_fail_closed` (`tests/http_transport_replay.rs`). |
| `ProviderError::TransportTimeout` | `{"transport":"timeout","endpoint":"https://api.groq.com","timeout_ms":60000}` | `chio_provider_adapter_core::http::map_transport_error` (`Timeout` branch), via `GroqAdapter::post_chat_completion` (`src/lib.rs`) | The request exceeds the transport's configured timeout (60s default, `groq_transport_config` in `src/transport.rs`). Exercised by `send_chat_completion_timeout_fails_closed` (`src/tests.rs`). |
| `ProviderError::VerdictBudgetExceeded` | `{"provider":"groq","event":"tool_calls","observed_ms":300,"budget_ms":250}` | caller-supplied verdict evaluator, propagated by `gate_openai_sse_tool_calls` (`chio-provider-adapter-core/src/streaming.rs`) | The caller's verdict evaluator returns this error; `GroqAdapter::gate_sse_stream` (`src/streaming.rs`) propagates it unchanged. |
| `ProviderError::Malformed` | `{"choices":[{"message":{"role":"assistant","content":"no tool call here"},"finish_reason":"stop"}]}` | `GroqAdapter::lift_batch` in `src/lib.rs` | Requires at least one `tool_calls` entry; also non-JSON SSE data (`parse_sse_frame` in `chio-provider-adapter-core/src/sse.rs`), an unparseable outer envelope, API-version drift (`ensure_supported_api_version`), or a malformed `tool_calls[]` shape. |
<!-- error-taxonomy:end -->

## API pin

| Field | Value |
|---|---|
| Pinned API version | `2025-04` |
| Default endpoint | `https://api.groq.com` |
| Chat completions path | `/openai/v1/chat/completions` |
| ProviderId | `ProviderId::Groq` |

Bumping `GROQ_API_VERSION` requires a deliberate PR with a fixture
re-record (`Cargo.toml` `[package.metadata.chio] groq_api_version`).

## Testing

`cargo test -p chio-groq-tools-adapter`

- `src/tests.rs` - adapter unit tests: API-version-drift fail-closed paths,
  request validation, lift/gate/lower, transport calls.
- `tests/error_taxonomy_doctest.rs` - cross-checks the error-taxonomy table
  above against the adapter's real `ProviderError` classification paths.
- `tests/http_transport_replay.rs` - exercises the real `HttpTransport`
  (bearer auth, the OpenAI-compatible request body, tool-call parsing)
  against a local `wiremock` server; no live network.
- `benches/verdict_latency.rs` - a `#[test]`-based budget check (cold
  `gate_sse_stream` verdict path under 500ms p99 over 128 samples). The
  `[[bench]]` entry has no `harness = false`, but it is also not part of the
  default `cargo test` target set; run it with
  `cargo test -p chio-groq-tools-adapter --benches`.

## See also

- `chio-provider-adapter-core` - shared HTTP transport, SSE parsing, and
  OpenAI-compatible decode/gate primitives this adapter builds on.
- `chio-tool-call-fabric` - defines `ToolInvocation`, `VerdictResult`,
  `ProviderError`, and the provenance types this adapter lifts into and
  lowers from.
- `chio-openai-adapter` - its `provider-adapter` feature uses the same
  `chio-provider-adapter-core` primitives for OpenAI's Chat Completions and
  Responses API. Neither crate depends on the other; Groq has no Responses
  API analog, and `GroqAdapter` does not implement the fabric
  `ProviderAdapter` trait the way `OpenAiAdapter` does.
- `chio-provider-conformance` - replays captured Groq fixtures against this
  adapter (`fixtures-groq` feature).
- `chio-anthropic-tools-adapter`, `chio-bedrock-converse-adapter`,
  `chio-cohere-tools-adapter`, `chio-gemini-tools-adapter`,
  `chio-mistral-tools-adapter`, `chio-ollama-tools-adapter` - sibling
  adapters on the same fabric, one per provider.
