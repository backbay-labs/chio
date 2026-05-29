# chio-groq-tools-adapter

Provider-native adapter for Groq `chat/completions` tool-use traffic. Groq
exposes an OpenAI-compatible chat/completions API, so the adapter forwards a
native request to `https://api.groq.com/openai/v1/chat/completions` with a
Bearer API key, lifts the returned `tool_calls` into the canonical fabric
types, runs the kernel verdict, and lowers the gated result back to a `tool`
message.

## Transport

The outbound call is driven by the shared `chio_provider_adapter_core::http`
transport. `GroqAdapter::send_chat_completion` POSTs a chat/completions request
body and lifts the response; `GroqAdapter::send_chat_completion_stream` POSTs a
streaming request and gates the buffered SSE body. Build a production transport
with `groq_transport(api_key)` (or `groq_transport_from_env()` to read
`GROQ_API_KEY`); unit tests use the hermetic `MockTransport`, which records
calls and returns scripted responses without touching the network.

The adapter pins the upstream API version to `2025-04` (see
`crate::transport::GROQ_API_VERSION`). Bumping the pin requires a deliberate
PR with a fixture re-record; the version string is also re-asserted by the
conformance harness.

## Surface

- `GroqAdapter::send_chat_completion` forwards a native chat/completions request
  to the upstream endpoint and lifts the tool calls in the response.
- `GroqAdapter::lift_batch` lifts every `tool_calls` entry in a non-streaming
  `chat/completions` response into a `chio_tool_call_fabric::ToolInvocation`.
- `GroqAdapter::gate_sse_stream` mediates `chat/completions` streaming SSE
  payloads. Each `tool_calls` entry is evaluated by the kernel before its
  enclosing chunk is forwarded.
- `GroqAdapter::lower_function_response` converts a kernel verdict and a
  canonical tool result into the tool-result payload returned on the next turn.

## Error taxonomy

The adapter projects upstream Groq failures onto
`chio_tool_call_fabric::ProviderError`. The mapping is asserted by
`tests/error_taxonomy_doctest.rs` against this README.

<!-- error-taxonomy:start -->
| ProviderError class | Native envelope (inline JSON) | urn:chio:error:* code | Notes |
|---|---|---|---|
| `ProviderError::RateLimited` | `{"status": 429, "body": {"error": {"type": "rate_limit_error", "code": "RESOURCE_EXHAUSTED"}}}` | `urn:chio:error:provider:rate-limited` | Maps Groq quota exhaustion (HTTP 429). |
| `ProviderError::ContentPolicy` | `{"status": 200, "body": {"stop_reason": "refusal", "promptFeedback": {"blockReason": "SAFETY"}}}` | `urn:chio:error:provider:content-policy` | Triggered by Groq safety blocks on the assistant turn. |
| `ProviderError::BadToolArgs` | `{"type": "function", "function": {"name": "get_weather", "arguments": "\"not-an-object\""}}` | `urn:chio:error:adapter:bad-tool-args` | Adapter refuses non-object decoded `arguments`. |
| `ProviderError::Upstream5xx` | `{"status": 503, "body": {"error": {"type": "overloaded_error", "code": "UNAVAILABLE"}}}` | `urn:chio:error:provider:upstream-5xx` | Surfaces Groq infra outages (5xx). |
| `ProviderError::TransportTimeout` | `{"transport": "timeout", "elapsed_ms": 5000}` | `urn:chio:error:adapter:transport-timeout` | Raised when the HTTP call exceeds the configured budget. |
| `ProviderError::VerdictBudgetExceeded` | `{"observed_ms": 300, "budget_ms": 250}` | `urn:chio:error:kernel:verdict-budget` | Kernel refused to issue a verdict in time; fail-closed. |
| `ProviderError::Malformed` | `{"event": "content_block_delta", "frame": "missing-functionCall"}` | `urn:chio:error:adapter:malformed` | Adapter cannot parse upstream payload. |
<!-- error-taxonomy:end -->

## API pin

| Field | Value |
|---|---|
| Pinned API version | `2025-04` |
| Default endpoint | `https://api.groq.com` |
| ProviderId | `ProviderId::Groq` |
