# chio-gemini-tools-adapter architecture note

## Boundaries

- `lib.rs` owns the public adapter handle, configuration, provider identity, lift/lower entrypoints, and the `Provider` implementation.
- `transport.rs` owns outbound HTTP wiring for Gemini `generateContent` and `streamGenerateContent`, including query-parameter API-key auth and the `v1beta` path pin.
- `native.rs` owns the public Gemini content-part shapes used by callers and tests.
- `streaming.rs` owns buffered SSE frame mediation for `streamGenerateContent` and gates `functionCall` frames before forwarding bytes.
- `loaded_weights.rs` owns the explicit "unavailable" implementation for providers that cannot expose runtime model bytes.

## Pain points

- `GeminiAdapterConfig::new` pins `api_version` to `GEMINI_API_VERSION`, and the adapter now fails closed when a deserialized or mutated config drifts from that pin before send, lift, stream gating, provenance stamping, or lowering.
- The remaining drift boundary is the injectable `Arc<dyn Transport>`: the trait advertises `api_version()`, but the adapter does not currently verify that the injected transport reports the same pin as the config before outbound calls.
- A custom transport can therefore claim a stale upstream contract while the adapter stamps `v1beta` provenance and exposes `Provider::api_version()` from config.
- `response.rs` now owns Gemini response-envelope classification and `functionCall` extraction; that trust boundary should stay internal and should not be weakened by moving parsing back into `lib.rs`.

## Constraints

- Preserve public API compatibility for `GeminiAdapter`, `GeminiAdapterConfig`, `Transport`, `FunctionCallPart`, and `FunctionResponsePart`.
- Preserve canonical JSON byte stability for lifted tool arguments.
- Preserve fail-closed behavior for malformed upstream payloads, invalid tool arguments, bad lower-response bytes, and streaming verdict failures.
- Preserve the pinned upstream API version `v1beta`.
- Do not touch fixture corpus or generated artifacts in this slice.

## Dependents

- `crates/chio-provider-conformance` depends on Gemini fixture behavior and API-version pins.
- `examples/cross-provider-policy` depends on the captured Gemini fixture path for cross-provider verdict equality, not on private response parsing helpers.
- No downstream crate should depend on private `lib.rs` parsing helpers.

## Planned improvement

Extend the adapter-local API-pin guard so outbound paths fail closed unless both `config.api_version` and `transport.api_version()` equal `GEMINI_API_VERSION`. This is architectural because it makes the injected transport boundary part of the same runtime contract as provenance stamping and fixture pins while preserving the public construction API and the internal response module boundary.
