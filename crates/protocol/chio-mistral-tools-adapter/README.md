# chio-mistral-tools-adapter

Provider-native adapter that mediates Mistral `chat/completions` tool-use traffic through the Chio kernel fabric. It forwards requests to `api.mistral.ai` over HTTPS, lifts each returned `tool_calls[]` entry into a `chio_tool_call_fabric::ToolInvocation`, and lowers a kernel verdict back into the `tool`-role message Mistral expects on the next turn.

Mistral's `chat/completions` API is OpenAI-compatible, so the wire decoding and SSE gating this adapter uses come from the shared `chio-provider-adapter-core` crate. This crate owns only the Mistral-specific transport, config, and the pinned upstream API version (`2025-04`).

## Responsibilities

- Forward `chat/completions` requests over HTTPS (`MistralHttpTransport`) or through a scripted `MockTransport` for hermetic tests, buffering the full response before lifting or gating.
- Lift each OpenAI-compatible `tool_calls[]` entry, batch or streamed, into a `ToolInvocation`: decode the JSON-encoded `arguments` string, re-encode it to canonical JSON (RFC 8785), and stamp `Principal::MistralProject` provenance.
- Gate streamed `chat.completion.chunk` SSE frames on a caller-supplied kernel verdict before forwarding any chunk carrying a `tool_calls` part.
- Lower a kernel `VerdictResult` and `ToolResult` into the `tool`-role response message: apply JSON-Pointer redactions on allow, render a `{"error": ...}` payload on deny.
- Pin the upstream API version to `2025-04` and fail closed on any drift between `config.api_version`, `transport.api_version()`, and the pin before a request, lift, gate, or lower runs.
- Classify Mistral's `content_filter` finish reason as a content-policy denial instead of an empty success.
- Report Mistral runtime model weights as unavailable, since `chat/completions` exposes no weight bytes.

## Public API

- `MistralAdapterConfig::new(server_id, server_name, server_version, public_key, project_id)` - config with `api_version` pinned to `MISTRAL_API_VERSION`.
- `MistralAdapter::new(config, transport)` - adapter handle over any `Arc<dyn transport::Transport>`; `.provider()`, `.api_version()`, `.config()`, `.transport()`.
- `MistralAdapter::send_chat_completion` / `send_chat_completion_stream` - POST through the transport, then lift or gate the response.
- `MistralAdapter::lift_batch` / `gate_sse_stream` - lift or gate already-buffered payload bytes without a transport call.
- `MistralAdapter::lower_function_response` - lower a kernel verdict and `ToolResult` into a `FunctionResponsePart`.
- `MistralChatRequest::{new, to_json_bytes}` - the `{ model, messages, tools, stream }` request body.
- `native::{FunctionCallPart, FunctionResponsePart}` - normalized lifted-call and lowered-response shapes; re-exported at the crate root.
- `transport::{Transport, MistralHttpTransport, MockTransport, TransportError}` - the wire contract, the real HTTPS client, and a scripted in-memory double.
- `MistralAdapterError` - adapter-local error wrapping `transport::TransportError`.
- `MistralAdapter` implements `chio_provider_adapter_core::Provider`.

## Error taxonomy

The adapter projects upstream Mistral failures onto `chio_tool_call_fabric::ProviderError`. The mapping is asserted by `tests/error_taxonomy_doctest.rs` against this README.

<!-- error-taxonomy:start -->
| ProviderError class | Native or boundary envelope | Source | Trigger |
| -------------------- | ---------------------------- | ------- | ------- |
| `ProviderError::RateLimited` | `{"status":429,"body":"rate limited"}` | HTTP transport boundary | Status 429 from `POST /v1/chat/completions`, classified by the shared `map_http_status`. `retry_after_ms` is currently hardcoded to `0`; no `Retry-After` header is read. |
| `ProviderError::ContentPolicy` | `{"id":"chatcmpl_safety","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":null},"finish_reason":"content_filter"}]}` | current adapter path (batch only) | `response::classify_content_policy` rejects any `choices[].finish_reason="content_filter"` before tool calls are extracted; also status 403 via the HTTP transport boundary. |
| `ProviderError::BadToolArgs` | `{"id":"chatcmpl_bad_args","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","tool_calls":[{"id":"call_bad_args_1","type":"function","function":{"name":"get_weather","arguments":42}}]},"finish_reason":"tool_calls"}]}` | current adapter path | `validate_function_call` rejects a `tool_calls[].function.arguments` that is not a JSON object; also raised by `MistralChatRequest::to_json_bytes` when `model` or `messages` is empty, and by 4xx statuses other than 429/403 via the HTTP transport boundary. |
| `ProviderError::Upstream5xx` | `{"status":503,"body":"service unavailable"}` | HTTP transport boundary | Any 5xx status from `api.mistral.ai`, classified by `map_http_status`. |
| `ProviderError::TransportTimeout` | `{"transport":"timeout","timeout_ms":60000}` | HTTP transport boundary | The request exceeds `MistralHttpTransport`'s configured timeout (60s default, set via `HttpTransportConfig::with_timeout`). |
| `ProviderError::VerdictBudgetExceeded` | `{"provider":"mistral","observed_ms":300,"budget_ms":250}` | current adapter path | The caller's verdict evaluator returns this error; `gate_sse_stream` runs it through the shared `gate_openai_sse_tool_calls`, which propagates the error unchanged before any bytes are forwarded. |
| `ProviderError::Malformed` | `{"id":"chatcmpl_no_tool","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"no tool call here"},"finish_reason":"stop"}]}` | current adapter path | `lift_batch` requires at least one `tool_calls` entry; also non-JSON bytes, an API-version drift (`ensure_supported_api_version`), an unparseable envelope field (`response_body`), or a malformed `tool_calls` shape. |
<!-- error-taxonomy:end -->

## API pin

| Field | Value |
|---|---|
| Pinned API version | `2025-04` |
| Default endpoint | `https://api.mistral.ai` |
| Chat completions path | `/v1/chat/completions` |
| ProviderId | `ProviderId::Mistral` |

## Testing

`cargo test -p chio-mistral-tools-adapter`

- `src/tests.rs` - adapter unit tests: API-version-drift fail-closed paths, lift/gate/lower, request encoding.
- `tests/error_taxonomy_doctest.rs` - cross-checks this README's error-taxonomy table against the adapter's real `ProviderError` classification paths.
- `tests/live_transport.rs` - exercises the real `MistralHttpTransport` (bearer auth, JSON POST, SSE streaming, 429 mapping) against a local `wiremock` server; no live network.
- `benches/verdict_latency.rs` - asserts the cold `gate_sse_stream` verdict path holds a 500ms p99 budget over 128 samples; runs under both `cargo test` and `cargo bench`.

## See also

- `chio-provider-adapter-core` - shared HTTP transport, SSE parsing, and OpenAI-compatible decode/gate primitives this adapter builds on.
- `chio-tool-call-fabric` - defines `ToolInvocation`, `VerdictResult`, `ProviderError`, and the provenance types this adapter lifts into and lowers from.
- `chio-provider-conformance` - replays captured Mistral fixtures against this adapter (`fixtures-mistral` feature).
- `chio-anthropic-tools-adapter`, `chio-bedrock-converse-adapter`, `chio-cohere-tools-adapter`, `chio-gemini-tools-adapter`, `chio-groq-tools-adapter`, `chio-ollama-tools-adapter` - sibling adapters on the same fabric, one per provider.
