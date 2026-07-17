# chio-provider-adapter-core architecture

## Overview

`chio-provider-adapter-core` is the outbound edge shared by every native
provider-tool adapter (OpenAI, Anthropic, Bedrock, Gemini, Groq, Mistral,
Cohere, Ollama). It carries requests from the kernel's tool-call fabric to an
untrusted upstream provider API and buffers the response. It is a pure library
(no kernel state, `#![forbid(unsafe_code)]`); the trust-sensitive work it owns
is validating transport config and auth material eagerly at construction, and
gating streamed tool calls on a kernel verdict before any byte reaches the
caller.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Public facade: `Provider` trait, `GatedStream`, verdict-enforcement helpers, `LoadedWeights` "unavailable" boilerplate, and re-exports from `response`, `sse`, `streaming`. |
| `src/http.rs` | Public (`pub mod`). HTTP transport: `HttpTransportConfig`, `AuthScheme`, `HttpTransport`, `ProviderHttpTransport`, status/error classification, NDJSON parsing, `MockHttpTransport`. |
| `src/sse.rs` | Private. Fail-closed SSE frame parser (`parse_sse_frames`), byte-exact retention, done-sentinel and event/type cross-check handling. |
| `src/streaming.rs` | Private. `gate_openai_sse_tool_calls`: decodes OpenAI-compatible streaming tool calls and gates emission on a kernel verdict. |
| `src/response.rs` | Private. Batch-response envelope unwrapping and OpenAI-shaped `tool_calls[]` decoding. |

## Request and stream lifecycle

1. An adapter builds a `HttpTransportConfig` and calls `HttpTransport::new`,
   which validates the base URL and auth material before returning a client -
   a malformed config never reaches the network.
2. The adapter posts through `ProviderHttpTransport` (typically held as
   `Arc<dyn ProviderHttpTransport>`): `post_json` for batch calls, `post_sse`
   or `post_ndjson` for streaming. Default headers resolve once at
   construction; query-param auth is appended per request; a non-2xx response
   becomes `HttpTransportError::Status`.
3. Batch responses go through `response_body` to unwrap the transport
   envelope, then `openai_tool_call_to_function_call` decodes each
   `tool_calls[]` entry.
4. Streamed SSE bodies go through `parse_sse_frames` into `SseFrame`s that
   retain their original bytes. For the OpenAI-compatible shape,
   `gate_openai_sse_tool_calls` decodes each frame's tool calls, invokes the
   caller's `invoke` closure to build a `ToolInvocation`, calls `evaluate` for
   a kernel `VerdictResult`, and enforces allow-with-no-redactions via
   `ensure_streaming_allow_no_redactions` before appending the frame's raw
   bytes to the forwarded output.
5. `map_http_status` / `map_transport_error` translate status and transport
   failures into the shared `chio-tool-call-fabric::ProviderError` taxonomy.

## Invariants and failure modes

- `HttpTransport::new` rejects an empty or whitespace-padded `base_url`, a
  non-`http`/`https` scheme, and embedded userinfo, query strings, or
  fragments before building a client.
- `validate_auth_scheme` runs at construction: bearer and header values
  reject empty or padded strings, bearer tokens additionally reject internal
  whitespace and control bytes, and a query parameter's name is validated
  separately from its value so a rejected name never echoes the secret.
- `parse_sse_frames` requires valid UTF-8 and JSON `data`; under
  `UnknownSseFieldPolicy::Reject` an unrecognized field fails the frame, and
  under `with_event_type_cross_check` a mismatched `event`/`type` pair or an
  unnamed data frame fails closed.
- `gate_openai_sse_tool_calls` requires every verdict to be
  `VerdictResult::Allow` with empty redactions; a `Deny` or a redacted
  `Allow` fails the whole stream rather than forwarding a partial result.
- `parse_ndjson_lines` fails closed on any non-empty line that is not valid
  JSON.
- `MockHttpTransport` fails closed with `MockExhausted` when its scripted
  response queue is empty, so a missing test expectation is a failure, not a
  false success.
- Direct `reqwest::Client` construction and sends are marked
  `CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST`, the repo's sanctioned egress point
  for outbound provider calls.

## Dependencies

- `chio-tool-call-fabric` - `ProviderId`, `ProviderError`, `ToolInvocation`,
  `VerdictResult`, `DenyReason`: the vocabulary every helper here speaks.
- `chio-core` (aliased in `Cargo.toml` to the `chio-core-types` package) -
  `LoadedWeights`, `LoadedWeightsUnavailable`.
- `reqwest` (`json`, `query`, `rustls`) - the HTTP client behind
  `HttpTransport`.
- `async-trait` - makes `ProviderHttpTransport` dyn-compatible so adapters
  hold `Arc<dyn ProviderHttpTransport>` and swap in `MockHttpTransport` for
  tests.
- `serde_json`, `thiserror`, `tokio` - payload decoding, `HttpTransportError`,
  and the async runtime.
- Dev-only: `chio-test-support`, `wiremock` - back the `http.rs` integration
  tests against a bound mock server.

## Extension points

- `ProviderHttpTransport` - implement to replace `HttpTransport`, or use
  `MockHttpTransport` to script upstream responses in tests.
- `Provider` - an adapter implements `provider_id`/`api_version` to identify
  itself.
- `gate_openai_sse_tool_calls`'s `invoke` and `evaluate` closures - where a
  provider adapter wires its native call struct and verdict lookup into the
  shared gate loop.
