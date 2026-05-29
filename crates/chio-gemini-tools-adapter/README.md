# chio-gemini-tools-adapter

Provider-native adapter for Google Gemini `generateContent` tool-use traffic.

## Transport

The adapter forwards a native `generateContent` request to the Google
Generative Language API and feeds the response through its lift/gate code.
`GeminiTransport` is the real, `reqwest`-backed client (provided by the shared
`chio_provider_adapter_core::http` module): it POSTs to
`/v1beta/models/<model>:generateContent` (or `:streamGenerateContent?alt=sse`
for streaming) and authenticates with the API key carried as the `?key=` query
parameter, which is how the Generative Language API (Google AI Studio)
authenticates. The key is injected at construction (`GeminiTransport::new`) or
read from the `GEMINI_API_KEY` environment variable (`GeminiTransport::from_env`),
never embedded in library code; an empty key fails closed. `MockTransport`
backs hermetic tests with scripted responses and records every call.

The adapter pins the upstream API version to `v1beta` (see
`crate::transport::GEMINI_API_VERSION`). Bumping the pin requires a deliberate
PR with a fixture re-record; the version string is also re-asserted by the
conformance harness.

## Surface

- `GeminiAdapter::lift_batch` lifts every `functionCall` part in a non-streaming
  `generateContent` response into a `chio_tool_call_fabric::ToolInvocation`.
- `GeminiAdapter::gate_sse_stream` mediates `streamGenerateContent` SSE
  payloads. Each `functionCall` part is evaluated by the kernel before its
  enclosing chunk is forwarded.
- `GeminiAdapter::lower_function_response` converts a kernel verdict and a
  canonical tool result into a Gemini `functionResponse` part suitable for the
  next user turn.

## Error taxonomy

The adapter projects upstream Gemini failures onto
`chio_tool_call_fabric::ProviderError`. The mapping is asserted by
`tests/error_taxonomy_doctest.rs` against this README.

<!-- error-taxonomy:start -->
| ProviderError class | Native envelope (inline JSON) | urn:chio:error:* code | Notes |
|---|---|---|---|
| `ProviderError::RateLimited` | `{"status": 429, "body": {"error": {"type": "rate_limit_error", "code": "RESOURCE_EXHAUSTED"}}}` | `urn:chio:error:provider:rate-limited` | Maps Gemini quota exhaustion (HTTP 429). |
| `ProviderError::ContentPolicy` | `{"status": 200, "body": {"stop_reason": "refusal", "promptFeedback": {"blockReason": "SAFETY"}}}` | `urn:chio:error:provider:content-policy` | Triggered by Gemini safety blocks on the assistant turn. |
| `ProviderError::BadToolArgs` | `{"type": "tool_use", "name": "get_weather", "args": "not-an-object"}` | `urn:chio:error:adapter:bad-tool-args` | Adapter refuses non-object `args`. |
| `ProviderError::Upstream5xx` | `{"status": 503, "body": {"error": {"type": "overloaded_error", "code": "UNAVAILABLE"}}}` | `urn:chio:error:provider:upstream-5xx` | Surfaces Gemini infra outages (5xx). |
| `ProviderError::TransportTimeout` | `{"transport": "timeout", "elapsed_ms": 5000}` | `urn:chio:error:adapter:transport-timeout` | Raised when the HTTP call exceeds the configured budget. |
| `ProviderError::VerdictBudgetExceeded` | `{"observed_ms": 300, "budget_ms": 250}` | `urn:chio:error:kernel:verdict-budget` | Kernel refused to issue a verdict in time; fail-closed. |
| `ProviderError::Malformed` | `{"event": "content_block_delta", "frame": "missing-functionCall"}` | `urn:chio:error:adapter:malformed` | Adapter cannot parse upstream payload. |
<!-- error-taxonomy:end -->

## API pin

| Field | Value |
|---|---|
| Pinned API version | `v1beta` |
| Default endpoint | `https://generativelanguage.googleapis.com` |
| ProviderId | `ProviderId::Gemini` |
