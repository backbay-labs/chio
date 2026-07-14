# chio-ollama-tools-adapter

Provider-native adapter that mediates Ollama `/api/chat` tool-use traffic through
the Chio kernel, pinned to upstream API version `2025-04`. It lifts Ollama's
`tool_calls` response shape into the canonical `chio_tool_call_fabric::ToolInvocation`,
runs each invocation through a caller-supplied kernel verdict, and lowers the
verdict and result back into Ollama's `tool` role message shape.

Ollama runs as a local daemon (default `http://localhost:11434`), not a hosted
provider with an account identity, so the adapter stamps the daemon host as
provenance instead of an org or project id. The reqwest-backed client, headers,
timeouts, and failure classification live in `chio_provider_adapter_core::http`;
`crate::transport` wires Ollama's localhost default, the `OLLAMA_HOST` /
`OLLAMA_API_KEY` overrides, and the version-pin header onto it.

## Responsibilities

- Post non-streaming (`chat`) and streaming (`chat_stream`) `/api/chat` requests
  through the shared HTTP transport.
- Lift every `tool_calls` entry on the assistant `message` into a `ToolInvocation`,
  synthesising a request id from the tool name and ordinal index since Ollama
  omits an explicit call id.
- Gate streamed NDJSON `tool_calls` frames behind a caller-supplied verdict
  closure, one line at a time, before admitting bytes to the forwarded output.
- Lower a kernel `VerdictResult` and `ToolResult` into an Ollama `tool` role
  `ToolResultMessage`, applying JSON-Pointer redactions and canonical-JSON-encoding
  the result.
- Classify upstream failures (HTTP status, transport timeout, content-policy
  refusal, malformed payload) into the `chio_tool_call_fabric::ProviderError`
  taxonomy.
- Fail closed on API-version drift: every public entry point rejects a config
  whose `api_version` is not the pinned `OLLAMA_API_VERSION` before touching the
  transport, the evaluator, or provenance.

## Public API

- `OllamaAdapter` - adapter handle over a config and a `transport::Transport`:
  `chat`, `chat_stream`, `lift_batch`, `gate_sse_stream`, `lower_tool_message`,
  plus accessors `provider`, `api_version`, `config`, `transport`.
- `OllamaAdapterConfig::new` - builds a config with `api_version` pinned to
  `OLLAMA_API_VERSION`; `org_id` is the host label stamped into `Principal::OllamaHost`.
- `OllamaAdapterError` - combines `ProviderError` and the adapter-core
  `HttpTransportError` in one enum. Adapter methods return `ProviderError`
  directly; transport failures are pre-classified by `map_transport_error` before
  they reach a caller.
- `native::{ToolCallPart, ToolCallFunction, ToolResultMessage}` - Ollama wire
  shapes, re-exported at the crate root.
- `streaming::GatedNdjsonStream` - `gate_sse_stream` output: forwarded `bytes`,
  evaluated `invocations`, and their `verdicts`.
- `transport` - `Transport`, `MockTransport`, `host_config`, `live_transport`,
  `live_transport_with_timeout`, `live_transport_for`; `OLLAMA_API_VERSION` and
  `OLLAMA_CHAT_HOST` are also re-exported at the crate root.
- `loaded_weights::OllamaLoadedWeights` - `LoadedWeights` impl for callers that
  hold local model bytes (`borrowed` / `owned` constructors). `OllamaAdapter`
  itself implements `LoadedWeights` as permanently unavailable, since the handle
  does not own model bytes.

## Error taxonomy

The adapter projects upstream Ollama failures onto `chio_tool_call_fabric::ProviderError`.
`tests/error_taxonomy_doctest.rs` parses this table out of the README and checks
it against adapter behavior, so keep both in sync.

<!-- error-taxonomy:start -->
| ProviderError class | Native envelope (inline JSON) | Raised by | Notes |
|---|---|---|---|
| `ProviderError::RateLimited` | `{"status": 429, "body": {"error": "rate limit reached"}}` | `map_http_status` (status 429) | HTTP 429 from the daemon or a bearer-auth gateway in front of it. |
| `ProviderError::ContentPolicy` | `{"status": 200, "body": {"done_reason": "stop", "policy": "refusal"}}` | `response::classify_content_policy` | A `"policy": "refusal"` field on the assistant turn's response body (also reachable via HTTP 403 through `map_http_status`). |
| `ProviderError::BadToolArgs` | `{"role": "assistant", "tool_calls": [{"function": {"name": "get_weather", "arguments": "not-an-object"}}]}` | `validate_tool_call` | `tool_calls[].function.arguments` is not a JSON object. |
| `ProviderError::Upstream5xx` | `{"status": 503, "body": {"error": "model not loaded"}}` | `map_http_status` (5xx) | Any 5xx status from the daemon. |
| `ProviderError::TransportTimeout` | `{"transport": "timeout", "elapsed_ms": 5000}` | `map_transport_error` | Outbound call exceeded the transport's configured timeout. |
| `ProviderError::VerdictBudgetExceeded` | `{"observed_ms": 300, "budget_ms": 250}` | caller's `evaluate` closure | The verdict evaluator did not return in time; the adapter propagates the error and fails closed. |
| `ProviderError::Malformed` | `{"event": "message", "frame": "missing-tool_calls"}` | `response.rs`, `streaming.rs`, `lib.rs` | Upstream payload could not be parsed: bad JSON, an unrecognised envelope field, or a non-UTF-8 stream. |
<!-- error-taxonomy:end -->

## API pin

| Field | Value |
|---|---|
| Pinned API version | `2025-04` (`transport::OLLAMA_API_VERSION`) |
| Outbound pin header | `x-ollama-api-version: 2025-04` (`transport::OLLAMA_API_VERSION_HEADER`) |
| Default endpoint | `http://localhost:11434` (`transport::OLLAMA_CHAT_HOST`), overridden by `OLLAMA_HOST` |
| ProviderId | `ProviderId::Ollama` |

Bumping the pin is a deliberate change: update `transport::OLLAMA_API_VERSION`,
the `[package.metadata.chio] ollama_api_version` value in `Cargo.toml`, and
re-record the fixtures this crate and `chio-provider-conformance` replay against.

## Testing

```
cargo test -p chio-ollama-tools-adapter
```

`tests/localhost_replay.rs` drives two lanes through `OllamaAdapter::chat`: a
hermetic lane (always runs) that scripts `MockTransport` with the recorded
`ollama_localhost_replay` fixture, and a live lane gated on the `OLLAMA_HOST`
environment variable (optionally `OLLAMA_MODEL`) that drives the real reqwest
transport against a running daemon. `tests/error_taxonomy_doctest.rs` checks the
table above against live `ProviderError` behavior. `benches/verdict_latency.rs`
is a `#[test]`, not a Criterion benchmark: it measures cold `gate_sse_stream`
latency over 128 samples and asserts p99 stays under 500ms.

## See also

- `chio-provider-adapter-core` - shared HTTP transport, NDJSON/SSE parsing
  helpers, and the `Provider` trait this adapter implements.
- `chio-tool-call-fabric` - defines `ToolInvocation`, `ProviderError`,
  `VerdictResult`, and the other cross-provider types this adapter lifts into
  and lowers from.
- `chio-provider-conformance` - replays this adapter's fixtures under the
  `fixtures-ollama` feature for cross-provider conformance checks.
