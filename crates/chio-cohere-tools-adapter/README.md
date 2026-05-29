# chio-cohere-tools-adapter

Provider-native adapter for Cohere `/v2/chat` tool-use traffic.

The adapter forwards a native `/v2/chat` request to the upstream endpoint,
lifts the tool calls from the response into the canonical kernel types, runs
the verdict, and lowers the result back into Cohere's wire shape. The outbound
call is a real `reqwest`-backed HTTP transport (`CohereTransport`) that POSTs
to `https://api.cohere.com/v2/chat` with an `Authorization: Bearer` API key;
the shared `chio-provider-adapter-core` HTTP module owns the client, timeout,
and failure classification. Tests run against the hermetic `MockTransport` (and
a local mock server), so the suite makes no live network calls.

The adapter pins the upstream API version to `2025-04` (see
`crate::transport::COHERE_API_VERSION`). Bumping the pin requires a deliberate
PR with a fixture re-record; the version string is also re-asserted by the
conformance harness.

Cohere v2 surfaces tool calls as a `tool_plan` string plus a `tool_calls`
array on the assistant `message`. Tool results travel back as `tool` role
messages carrying `tool_call_id` and a content block list.

## Surface

- `CohereAdapter::chat` POSTs a native `/v2/chat` request body through the
  transport and lifts the tool calls from the buffered response.
- `CohereAdapter::chat_stream` POSTs a streaming `/v2/chat` request and gates
  the buffered SSE response frame by frame.
- `CohereAdapter::lift_batch` lifts every `tool_calls` block on the assistant
  `message` of a `/v2/chat` response into a
  `chio_tool_call_fabric::ToolInvocation`.
- `CohereAdapter::gate_sse_stream` mediates `/v2/chat` SSE stream payloads.
  Each `tool-call-end` frame is evaluated by the kernel before its enclosing
  bytes are forwarded.
- `CohereAdapter::lower_tool_message` converts a kernel verdict and a
  canonical tool result into a Cohere v2 `tool` role message suitable for
  the next user turn.

## Error taxonomy

The adapter projects upstream Cohere failures onto
`chio_tool_call_fabric::ProviderError`. The mapping is asserted by
`tests/error_taxonomy_doctest.rs` against this README.

<!-- error-taxonomy:start -->
| ProviderError class | Native envelope (inline JSON) | urn:chio:error:* code | Notes |
|---|---|---|---|
| `ProviderError::RateLimited` | `{"status": 429, "body": {"message": "rate limit exceeded"}}` | `urn:chio:error:provider:rate-limited` | Maps Cohere quota exhaustion (HTTP 429). |
| `ProviderError::ContentPolicy` | `{"status": 200, "body": {"finish_reason": "ERROR_TOXIC", "message": "refusal"}}` | `urn:chio:error:provider:content-policy` | Triggered by Cohere safety blocks on the assistant turn. |
| `ProviderError::BadToolArgs` | `{"id": "call_1", "type": "function", "function": {"name": "get_weather", "arguments": "not-json"}}` | `urn:chio:error:adapter:bad-tool-args` | Adapter refuses arguments that do not parse as a JSON object. |
| `ProviderError::Upstream5xx` | `{"status": 503, "body": {"message": "service unavailable"}}` | `urn:chio:error:provider:upstream-5xx` | Surfaces Cohere infra outages (5xx). |
| `ProviderError::TransportTimeout` | `{"transport": "timeout", "elapsed_ms": 5000}` | `urn:chio:error:adapter:transport-timeout` | Raised when the HTTP call exceeds the configured budget. |
| `ProviderError::VerdictBudgetExceeded` | `{"observed_ms": 300, "budget_ms": 250}` | `urn:chio:error:kernel:verdict-budget` | Kernel refused to issue a verdict in time; fail-closed. |
| `ProviderError::Malformed` | `{"event": "tool-call-end", "frame": "missing-tool_call"}` | `urn:chio:error:adapter:malformed` | Adapter cannot parse upstream payload. |
<!-- error-taxonomy:end -->

## API pin

| Field | Value |
|---|---|
| Pinned API version | `2025-04` |
| Default endpoint | `https://api.cohere.com` |
| ProviderId | `ProviderId::Cohere` |
