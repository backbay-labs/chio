# chio-groq-tools-adapter architecture note

## Boundaries

- `lib.rs` owns the public adapter handle, configuration, provider identity, lift/lower entrypoints, and the `Provider` implementation.
- `tests.rs` owns adapter-level unit tests for API pinning, request validation, lifting, lowering, transport calls, and stream gating.
- `transport.rs` owns the shared HTTP transport wiring for Groq's OpenAI-compatible `chat/completions` endpoint, including Bearer auth, pinned endpoint constants, and the `2025-04` API-version header.
- `native.rs` owns the adapter's normalized Groq content shapes: decoded function calls and gated function responses.
- `streaming.rs` owns buffered SSE mediation for OpenAI-compatible `chat.completion.chunk` frames and gates streamed `tool_calls` before release.
- `loaded_weights.rs` owns the explicit "unavailable" implementation for providers that cannot expose runtime model bytes.

## Request and API-Version Pins

`GroqAdapterConfig::new` pins `api_version` to `GROQ_API_VERSION`; the adapter
fails closed when a deserialized or mutated config drifts from that pin before
send, lift, stream gating, provenance stamping, or lowering. An adapter-local
request-shape guard parses outbound request bytes on both batch and streaming
send paths before `post_json` or `post_sse` and fails closed unless the request
is a JSON object with a non-empty, unpadded `model` and at least one `messages`
entry, so a malformed, non-object, empty-model, or no-message request cannot be
posted upstream. `response.rs` owns OpenAI-compatible response-envelope
classification and shared `tool_calls` decoding as an internal trust boundary.

## Constraints

- Preserve public API compatibility for `GroqAdapter`, `GroqAdapterConfig`, transport constructors, `FunctionCallPart`, and `FunctionResponsePart`.
- Preserve the raw-byte `send_chat_completion` and `send_chat_completion_stream` entrypoints.
- Preserve canonical JSON byte stability for decoded `function.arguments`.
- Preserve fail-closed behavior for malformed upstream payloads, invalid arguments, transport failures, bad lower-response bytes, and streaming verdict failures.
- Preserve the pinned upstream API version `2025-04`.

## Dependents

- `crates/protocol/chio-provider-conformance` depends on Groq fixture behavior and API-version pins.
- `examples/cross-provider-policy` depends on the captured Groq fixture path for cross-provider verdict equality, not on private parsing helpers.
- `streaming.rs` depends on the OpenAI-compatible `tool_calls` decoder.
