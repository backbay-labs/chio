# chio-groq-tools-adapter architecture note

## Boundaries

- `lib.rs` owns the public adapter handle, configuration, provider identity, lift/lower entrypoints, and the `Provider` implementation.
- `transport.rs` owns the shared HTTP transport wiring for Groq's OpenAI-compatible `chat/completions` endpoint, including Bearer auth, pinned endpoint constants, and the `2025-04` API-version header.
- `native.rs` owns the adapter's normalized Groq content shapes: decoded function calls and gated function responses.
- `streaming.rs` owns buffered SSE mediation for OpenAI-compatible `chat.completion.chunk` frames and gates streamed `tool_calls` before release.
- `loaded_weights.rs` owns the explicit "unavailable" implementation for providers that cannot expose runtime model bytes.

## Pain Points

- `GroqAdapterConfig::new` pins `api_version` to `GROQ_API_VERSION`, and the adapter now fails closed when a deserialized or mutated config drifts from that pin before send, lift, stream gating, provenance stamping, or lowering.
- The outbound request entrypoints still accept raw bytes and trust callers to provide a valid OpenAI-compatible chat/completions request before crossing the transport boundary.
- A malformed, non-object, empty-model, or no-message request can therefore be posted upstream before the adapter discovers any local contract violation, which weakens fail-closed behavior and pushes request-shape enforcement onto the provider.
- `response.rs` now owns OpenAI-compatible response-envelope classification and shared `tool_calls` decoding; that trust boundary should stay internal and should not be weakened by moving parsing back into `lib.rs`.

## Constraints

- Preserve public API compatibility for `GroqAdapter`, `GroqAdapterConfig`, transport constructors, `FunctionCallPart`, and `FunctionResponsePart`.
- Preserve the raw-byte `send_chat_completion` and `send_chat_completion_stream` entrypoints while tightening what they accept before transport.
- Preserve canonical JSON byte stability for decoded `function.arguments`.
- Preserve fail-closed behavior for malformed upstream payloads, invalid arguments, transport failures, bad lower-response bytes, and streaming verdict failures.
- Preserve the pinned upstream API version `2025-04`.
- Do not touch fixture corpus or generated artifacts in this slice.

## Dependents

- `crates/chio-provider-conformance` depends on Groq fixture behavior and API-version pins.
- `examples/cross-provider-policy` depends on the captured Groq fixture path for cross-provider verdict equality, not on private parsing helpers.
- `streaming.rs` depends on the OpenAI-compatible `tool_calls` decoder; moving it requires updating only the internal module import.

## Planned Improvement

Add an adapter-local request-shape guard that parses outbound request bytes before transport and fails closed unless the request is a JSON object with a non-empty, unpadded `model` and at least one `messages` entry. Invoke it on both batch and streaming send paths before `post_json` or `post_sse`. This is architectural because it moves native request contract enforcement into the adapter boundary while preserving public construction and response parsing APIs.
