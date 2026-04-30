# chio-ollama-tools-adapter

Provider-native adapter for Ollama `/api/chat` tool-use traffic.

The adapter pins the upstream API version to `2025-04` (see
`crate::transport::OLLAMA_API_VERSION`). Bumping the pin requires a deliberate
PR with a fixture re-record; the version string is also re-asserted by the
conformance harness.

Ollama is a localhost daemon, not a hosted provider; the adapter defaults to
`http://localhost:11434` and the conformance corpus uses fully deterministic
fixtures. The optional `tests/localhost_replay.rs` lane boots a real daemon
through a CI service container when `OLLAMA_HOST` is set.

## Surface

- `OllamaAdapter::lift_batch` lifts every `tool_calls` entry on the assistant
  `message` of an `/api/chat` response into a
  `chio_tool_call_fabric::ToolInvocation`.
- `OllamaAdapter::gate_sse_stream` mediates `/api/chat` NDJSON stream
  payloads. Each `tool_calls` entry is evaluated by the kernel before its
  enclosing line is forwarded.
- `OllamaAdapter::lower_tool_message` converts a kernel verdict and a
  canonical tool result into an Ollama `tool` role message suitable for the
  next user turn.

## Error taxonomy

The adapter projects upstream Ollama failures onto
`chio_tool_call_fabric::ProviderError`. The mapping is asserted by
`tests/error_taxonomy_doctest.rs` against this README.

<!-- error-taxonomy:start -->
| ProviderError class | Native envelope (inline JSON) | urn:chio:error:* code | Notes |
|---|---|---|---|
| `ProviderError::RateLimited` | `{"status": 429, "body": {"error": "rate limit reached"}}` | `urn:chio:error:provider:rate-limited` | Maps Ollama daemon backpressure (HTTP 429). |
| `ProviderError::ContentPolicy` | `{"status": 200, "body": {"done_reason": "stop", "policy": "refusal"}}` | `urn:chio:error:provider:content-policy` | Triggered by safety-tuned model refusals on the assistant turn. |
| `ProviderError::BadToolArgs` | `{"role": "assistant", "tool_calls": [{"function": {"name": "get_weather", "arguments": "not-an-object"}}]}` | `urn:chio:error:adapter:bad-tool-args` | Adapter refuses non-object `arguments`. |
| `ProviderError::Upstream5xx` | `{"status": 503, "body": {"error": "model not loaded"}}` | `urn:chio:error:provider:upstream-5xx` | Surfaces daemon model-load or eviction outages (5xx). |
| `ProviderError::TransportTimeout` | `{"transport": "timeout", "elapsed_ms": 5000}` | `urn:chio:error:adapter:transport-timeout` | Raised when the localhost call exceeds the configured budget. |
| `ProviderError::VerdictBudgetExceeded` | `{"observed_ms": 300, "budget_ms": 250}` | `urn:chio:error:kernel:verdict-budget` | Kernel refused to issue a verdict in time; fail-closed. |
| `ProviderError::Malformed` | `{"event": "message", "frame": "missing-tool_calls"}` | `urn:chio:error:adapter:malformed` | Adapter cannot parse upstream payload. |
<!-- error-taxonomy:end -->

## API pin

| Field | Value |
|---|---|
| Pinned API version | `2025-04` |
| Default endpoint | `http://localhost:11434` |
| ProviderId | `ProviderId::Ollama` |

## Localhost integration test

`tests/localhost_replay.rs` is gated on the `OLLAMA_HOST` environment
variable. Set `OLLAMA_HOST=http://localhost:11434` (or another daemon URL)
to enable the lane locally. CI exposes the daemon through a service
container with a pre-pulled small model; the lane is optional on PR and
required on nightly per the M07 P4 rollout plan.
