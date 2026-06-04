# chio-mistral-tools-adapter architecture note

## Boundaries

- `lib.rs` owns the public adapter handle, configuration, provider identity, lift/lower entrypoints, and the `Provider` implementation.
- `transport.rs` owns the shared HTTP transport wiring for Mistral's OpenAI-compatible `chat/completions` endpoint, including Bearer auth, endpoint constants, and the `2025-04` API-version header.
- `native.rs` owns the adapter's normalized Mistral content shapes: decoded function calls and gated function responses.
- `streaming.rs` owns buffered SSE mediation for OpenAI-compatible `chat.completion.chunk` frames and gates streamed `tool_calls` before release.
- `loaded_weights.rs` owns the explicit "unavailable" implementation for providers that cannot expose runtime model bytes.

## Pain Points

- `MistralAdapterConfig::new` pins `api_version` to `MISTRAL_API_VERSION`, and the adapter now fails closed when a deserialized or mutated config drifts from that pin before send, lift, stream gating, provenance stamping, or lowering.
- The remaining drift boundary is the injectable `Arc<dyn Transport>`: the trait advertises `api_version()`, but the adapter does not currently verify that the injected transport reports the same pin as the config before outbound calls.
- A custom transport can therefore claim a stale upstream contract while the adapter stamps `2025-04` provenance and exposes `Provider::api_version()` from config.
- `response.rs` now owns Mistral response-envelope classification and shared OpenAI-compatible `tool_calls` decoding; that trust boundary should stay internal and should not move back into the public adapter surface.

## Constraints

- Preserve public API compatibility for `MistralAdapter`, `MistralAdapterConfig`, transport constructors, `FunctionCallPart`, and `FunctionResponsePart`.
- Preserve canonical JSON byte stability for decoded `function.arguments`.
- Preserve fail-closed behavior for malformed upstream payloads, invalid arguments, transport failures, bad lower-response bytes, and streaming verdict failures.
- Preserve the pinned upstream API version `2025-04`.
- Do not edit generated artifacts or fixture corpora in this slice.

## Dependents

- `crates/chio-provider-conformance` depends on Mistral fixture behavior and API-version pins.
- Cross-provider equality checks depend on the captured Mistral fixture path for canonical invocation bytes.
- `streaming.rs` depends on the OpenAI-compatible `tool_calls` decoder; moving it requires updating only the internal module import.

## Planned Improvement

Extend the adapter-local API-pin guard so outbound paths fail closed unless both `config.api_version` and `transport.api_version()` equal `MISTRAL_API_VERSION`. This is architectural because it makes the injected transport boundary part of the same runtime contract as provenance stamping and fixture pins while preserving the public construction API and the existing internal response module boundary.
