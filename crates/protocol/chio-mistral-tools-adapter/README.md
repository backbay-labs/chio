# chio-mistral-tools-adapter

Provider-native adapter for Mistral `chat/completions` tool-use traffic.

## Transport

The adapter forwards a native request to Mistral's OpenAI-compatible
chat/completions API. `MistralHttpTransport` (backed by the shared
`chio-provider-adapter-core` HTTP client) POSTs to
`https://api.mistral.ai/v1/chat/completions` over HTTPS with an
`Authorization: Bearer <key>` header, buffers the response, and hands the bytes
to the lift/gate code below. The bearer key is injected by the caller
(`MistralHttpTransport::new`) or read from `MISTRAL_API_KEY` via
`MistralHttpTransport::from_env`; a missing key fails closed. `MockTransport`
implements the same contract for hermetic unit tests with scripted responses
and no network access.

Transport failures are fail-closed: a timeout, a non-2xx status, or a decode
error becomes a `ProviderError` and is never reported as an empty success.

The adapter pins the upstream API version to `2025-04` (see
`crate::transport::MISTRAL_API_VERSION`). Bumping the pin requires a deliberate
PR with a fixture re-record; the version string is also re-asserted by the
conformance harness.

## Surface

- `MistralAdapter::send_chat_completion` builds a `MistralChatRequest`
  (`{ model, messages, tools }`), POSTs it through the transport, and lifts the
  `tool_calls` in the response into `chio_tool_call_fabric::ToolInvocation`s.
- `MistralAdapter::send_chat_completion_stream` POSTs a streaming request and
  gates the SSE response so each `tool_calls` frame is held behind the kernel
  verdict before its enclosing chunk is forwarded.
- `MistralAdapter::lift_batch` lifts every `tool_calls` part in a non-streaming
  `chat/completions` response into a `chio_tool_call_fabric::ToolInvocation`.
- `MistralAdapter::gate_sse_stream` mediates `chat/completions stream` SSE
  payloads. Each `tool_calls` part is evaluated by the kernel before its
  enclosing chunk is forwarded.
- `MistralAdapter::lower_function_response` converts a kernel verdict and a
  canonical tool result into the tool-result payload Mistral consumes on the
  next turn (a `tool` role message carrying the matching `tool_call_id`).

## Error taxonomy

The adapter projects upstream Mistral failures onto
`chio_tool_call_fabric::ProviderError`. The mapping is asserted by
`tests/error_taxonomy_doctest.rs` against this README.

<!-- error-taxonomy:start -->
| ProviderError class | Native envelope (inline JSON) | urn:chio:error:* code | Notes |
|---|---|---|---|
| `ProviderError::RateLimited` | `{"status": 429, "body": {"error": {"type": "rate_limit_error", "code": "RESOURCE_EXHAUSTED"}}}` | `urn:chio:error:provider:rate-limited` | Maps Mistral quota exhaustion (HTTP 429). |
| `ProviderError::ContentPolicy` | `{"status": 200, "body": {"choices": [{"finish_reason": "content_filter", "message": {"role": "assistant", "content": null}}]}}` | `urn:chio:error:provider:content-policy` | Triggered by Mistral safety blocks (`finish_reason: content_filter`) on the assistant turn. |
| `ProviderError::BadToolArgs` | `{"choices": [{"message": {"tool_calls": [{"type": "function", "function": {"name": "get_weather", "arguments": 42}}]}}]}` | `urn:chio:error:adapter:bad-tool-args` | Adapter refuses non-object `arguments`. |
| `ProviderError::Upstream5xx` | `{"status": 503, "body": {"error": {"type": "overloaded_error", "code": "UNAVAILABLE"}}}` | `urn:chio:error:provider:upstream-5xx` | Surfaces Mistral infra outages (5xx). |
| `ProviderError::TransportTimeout` | `{"transport": "timeout", "elapsed_ms": 5000}` | `urn:chio:error:adapter:transport-timeout` | Raised when the HTTP call exceeds the configured budget. |
| `ProviderError::VerdictBudgetExceeded` | `{"observed_ms": 300, "budget_ms": 250}` | `urn:chio:error:kernel:verdict-budget` | Kernel refused to issue a verdict in time; fail-closed. |
| `ProviderError::Malformed` | `{"object": "chat.completion.chunk", "choices": "not-an-array"}` | `urn:chio:error:adapter:malformed` | Adapter cannot parse upstream payload. |
<!-- error-taxonomy:end -->

## API pin

| Field | Value |
|---|---|
| Pinned API version | `2025-04` |
| Default endpoint | `https://api.mistral.ai` |
| ProviderId | `ProviderId::Mistral` |
