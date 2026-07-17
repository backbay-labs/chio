# chio-provider-adapter-core

Shared primitives for Chio's native provider-tool adapters (OpenAI, Anthropic,
Bedrock, Gemini, Groq, Mistral, Cohere, Ollama). It owns the mechanics that are
identical across providers - HTTP transport, SSE/NDJSON framing, verdict-gated
stream forwarding, and HTTP error classification - so each adapter crate only
encodes its provider's request shape, auth scheme, and response fields.

The crate is a pure library: it forbids `unsafe`, holds no kernel state, and
does not implement `ProviderAdapter` itself. That trait and the canonical
`ToolInvocation` shape live in `chio-tool-call-fabric`; this crate supplies the
transport, framing, and gating primitives a `lift`/`lower` implementation is
built from.

## Responsibilities

- Own the async HTTP transport (`ProviderHttpTransport`) that HTTP-backed
  adapters post through: client construction, auth header/query injection,
  timeout, and a hermetic scripted mock for tests.
- Parse upstream SSE and NDJSON streams into structured frames, retaining
  original bytes for exact forwarding.
- Classify upstream HTTP failures (status codes, connect/timeout/decode
  errors) into the shared `chio-tool-call-fabric::ProviderError` taxonomy.
- Gate the OpenAI-compatible `chat/completions` streaming tool-call shape on a
  kernel verdict before any bytes are forwarded downstream.
- Normalize batch-response transport envelopes (`body`/`response`/`payload`
  wrapping) and decode OpenAI-shaped `tool_calls[]` entries.
- Supply the `LoadedWeights` "unavailable" boilerplate for hosted providers
  that cannot expose loaded model bytes.

## Public API

- `http::{HttpTransportConfig, HttpTransport, ProviderHttpTransport, HttpResponse, HttpTransportError, AuthScheme}` -
  reqwest-backed transport: batch JSON POST and buffered SSE/NDJSON POST
  behind one auth-agnostic config.
- `http::{MockHttpTransport, RecordedCall, CallKind}` - FIFO-scripted
  transport double that records calls and fails closed (`MockExhausted`) once
  exhausted.
- `http::{map_http_status, map_transport_error, parse_ndjson_lines, DEFAULT_TIMEOUT}` -
  status/error classification into `ProviderError`, and Ollama-style NDJSON
  line parsing.
- `parse_sse_frames`, `SseFrame`, `SseParseOptions`, `UnknownSseFieldPolicy` -
  fail-closed SSE frame parser shared by every streaming adapter.
- `gate_openai_sse_tool_calls`, `DecodedToolCall` - verdict-gated decode loop
  for the OpenAI-compatible `chat/completions` SSE shape (used by Groq and
  Mistral).
- `response_body`, `nested_response_body`, `openai_tool_call_to_function_call` -
  transport-envelope unwrapping and OpenAI-shaped `tool_calls[]` decoding for
  batch responses.
- `Provider` - identity trait (`provider_id`, `api_version`) an adapter type
  implements to identify itself.
- `GatedStream` - `{bytes, invocations, verdicts}` result of a gated stream
  pass.
- `ensure_streaming_allow_no_redactions`, `deny_reason_text` - fail-closed
  verdict enforcement and `DenyReason` rendering shared by the streaming and
  batch paths.
- `loaded_weights_unavailable`, `impl_unavailable_loaded_weights!` -
  boilerplate `chio_core::LoadedWeights` impl for hosted APIs that cannot
  expose model bytes.

## Testing

`cargo test -p chio-provider-adapter-core`

## See also

- `chio-tool-call-fabric` - defines `ProviderAdapter`, `ToolInvocation`,
  `VerdictResult`, `DenyReason`, and `ProviderError`, consumed here.
- `chio-core-types` (depended on as `chio-core`) - defines `LoadedWeights` and
  `LoadedWeightsUnavailable`.
- `chio-anthropic-tools-adapter`, `chio-bedrock-converse-adapter`,
  `chio-cohere-tools-adapter`, `chio-gemini-tools-adapter`,
  `chio-groq-tools-adapter`, `chio-mistral-tools-adapter`,
  `chio-ollama-tools-adapter`, `chio-openai-adapter` - per-provider adapters
  built on these primitives.
