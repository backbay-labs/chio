# chio-ollama-tools-adapter

Provider-native adapter for Ollama `/api/chat` tool-use traffic.

The adapter forwards a native `/api/chat` request to a running Ollama daemon
through the shared `chio_provider_adapter_core::http` transport, then lifts the
response tool calls into the canonical `chio_tool_call_fabric::ToolInvocation`,
runs the kernel verdict, and lowers the result back into Ollama's wire shape.
The reqwest-backed client, default headers, timeouts, and failure
classification live in the adapter core; `crate::transport` wires Ollama's
defaults onto it.

The adapter pins the upstream API version to `2025-04` (see
`crate::transport::OLLAMA_API_VERSION`). Bumping the pin requires a deliberate
PR with a fixture re-record; the version string is also re-asserted by the
conformance harness.

Ollama runs as a local daemon, not a hosted provider; the transport defaults to
`http://localhost:11434` with no authentication. Set `OLLAMA_HOST` to point at
another daemon URL and, for a remote gateway that fronts the daemon, set
`OLLAMA_API_KEY` to attach a bearer token.

## Surface

- `OllamaAdapter::chat` posts a non-streaming `/api/chat` request through the
  transport and lifts every `tool_calls` entry in the response.
- `OllamaAdapter::chat_stream` posts a streaming `/api/chat` request and gates
  the NDJSON tool-call frames behind a kernel verdict before forwarding bytes.
- `OllamaAdapter::lift_batch` lifts every `tool_calls` entry on the assistant
  `message` of an `/api/chat` response into a
  `chio_tool_call_fabric::ToolInvocation`.
- `OllamaAdapter::gate_sse_stream` gates `/api/chat` NDJSON stream payloads.
  Each `tool_calls` entry is evaluated by the kernel before its enclosing line
  is forwarded.
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
| Outbound pin header | `x-ollama-api-version: 2025-04` |
| Default endpoint | `http://localhost:11434` |
| ProviderId | `ProviderId::Ollama` |

## Replay test

`tests/localhost_replay.rs` has two lanes. The hermetic lane always runs: it
scripts the shared `MockTransport` with the recorded `ollama_localhost_replay`
fixture response and drives `OllamaAdapter::chat`, so it is deterministic and
needs no network. The opt-in live lane is gated on the `OLLAMA_HOST`
environment variable; set `OLLAMA_HOST=http://localhost:11434` (or another
daemon URL) to drive the real reqwest transport against a running daemon.
Optionally set `OLLAMA_MODEL` to choose the probe model.
