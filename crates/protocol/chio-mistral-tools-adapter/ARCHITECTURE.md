# chio-mistral-tools-adapter architecture note

## Boundaries

- `lib.rs` owns the public adapter handle, configuration, provider identity, lift/lower entrypoints, and the `Provider` implementation.
- `tests.rs` owns adapter-level unit tests for API pinning, lifting, lowering, transport calls, and stream gating.
- `transport.rs` owns the shared HTTP transport wiring for Mistral's OpenAI-compatible `chat/completions` endpoint, including Bearer auth, endpoint constants, and the `2025-04` API-version header.
- `native.rs` owns the adapter's normalized Mistral content shapes: decoded function calls and gated function responses.
- `streaming.rs` owns buffered SSE mediation for OpenAI-compatible `chat.completion.chunk` frames and gates streamed `tool_calls` before release.
- `loaded_weights.rs` owns the explicit "unavailable" implementation for providers that cannot expose runtime model bytes.

## API-Version Pin

`MistralAdapterConfig::new` pins `api_version` to `MISTRAL_API_VERSION`. Outbound
paths fail closed unless both `config.api_version` and `transport.api_version()`
equal `MISTRAL_API_VERSION` before send, lift, stream gating, provenance
stamping, or lowering, so neither a deserialized or mutated config nor a custom
`Arc<dyn Transport>` claiming a stale upstream contract can stamp `2025-04`
provenance against a drifted snapshot. `response.rs` owns Mistral
response-envelope classification and shared OpenAI-compatible `tool_calls`
decoding as an internal trust boundary.

## Constraints

- Preserve public API compatibility for `MistralAdapter`, `MistralAdapterConfig`, transport constructors, `FunctionCallPart`, and `FunctionResponsePart`.
- Preserve canonical JSON byte stability for decoded `function.arguments`.
- Preserve fail-closed behavior for malformed upstream payloads, invalid arguments, transport failures, bad lower-response bytes, and streaming verdict failures.
- Preserve the pinned upstream API version `2025-04`.

## Dependents

- `crates/protocol/chio-provider-conformance` depends on Mistral fixture behavior and API-version pins.
- Cross-provider equality checks depend on the captured Mistral fixture path for canonical invocation bytes.
- `streaming.rs` depends on the OpenAI-compatible `tool_calls` decoder.
