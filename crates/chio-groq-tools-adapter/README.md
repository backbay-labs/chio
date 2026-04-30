# chio-groq-tools-adapter

Provider-native adapter for Groq `chat/completions` tool-use traffic.

The adapter pins the upstream API version to `2025-04` (see
`crate::transport::GROQ_API_VERSION`). Bumping the pin requires a deliberate
PR with a fixture re-record; the version string is also re-asserted by the
conformance harness.

## Surface

- `GroqAdapter::lift_batch` lifts every `tool_calls` part in a non-streaming
  `chat/completions` response into a `chio_tool_call_fabric::ToolInvocation`.
- `GroqAdapter::gate_sse_stream` mediates `chat/completions stream` SSE
  payloads. Each `tool_calls` part is evaluated by the kernel before its
  enclosing chunk is forwarded.
- `GroqAdapter::lower_function_response` converts a kernel verdict and a
  canonical tool result into a Groq `functionResponse` part suitable for the
  next user turn.

## Error taxonomy

The adapter projects upstream Groq failures onto
`chio_tool_call_fabric::ProviderError`. The mapping is asserted by
`tests/error_taxonomy_doctest.rs` against this README.

<!-- error-taxonomy:start -->
| ProviderError class | Native envelope (inline JSON) | urn:chio:error:* code | Notes |
|---|---|---|---|
| `ProviderError::RateLimited` | `{"status": 429, "body": {"error": {"type": "rate_limit_error", "code": "RESOURCE_EXHAUSTED"}}}` | `urn:chio:error:provider:rate-limited` | Maps Groq quota exhaustion (HTTP 429). |
| `ProviderError::ContentPolicy` | `{"status": 200, "body": {"stop_reason": "refusal", "promptFeedback": {"blockReason": "SAFETY"}}}` | `urn:chio:error:provider:content-policy` | Triggered by Groq safety blocks on the assistant turn. |
| `ProviderError::BadToolArgs` | `{"type": "tool_use", "name": "get_weather", "args": "not-an-object"}` | `urn:chio:error:adapter:bad-tool-args` | Adapter refuses non-object `args`. |
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
