# chio-gemini-tools-adapter architecture note

## Boundaries

- `lib.rs` owns the public adapter handle, configuration, provider identity, lift/lower entrypoints, and the `Provider` implementation.
- `transport.rs` owns outbound HTTP wiring for Gemini `generateContent` and `streamGenerateContent`, including query-parameter API-key auth and the `v1beta` path pin.
- `native.rs` owns the public Gemini content-part shapes used by callers and tests.
- `streaming.rs` owns buffered SSE frame mediation for `streamGenerateContent` and gates `functionCall` frames before forwarding bytes.
- `loaded_weights.rs` owns the explicit "unavailable" implementation for providers that cannot expose runtime model bytes.

## API-Version Pin

`GeminiAdapterConfig::new` pins `api_version` to `GEMINI_API_VERSION`. Outbound
paths fail closed unless both `config.api_version` and `transport.api_version()`
equal `GEMINI_API_VERSION` before send, lift, stream gating, provenance stamping,
or lowering, so neither a deserialized or mutated config nor a custom
`Arc<dyn Transport>` claiming a stale upstream contract can stamp `v1beta`
provenance against a drifted snapshot. `response.rs` owns Gemini
response-envelope classification and `functionCall` extraction as an internal
trust boundary.

## Constraints

- Preserve public API compatibility for `GeminiAdapter`, `GeminiAdapterConfig`, `Transport`, `FunctionCallPart`, and `FunctionResponsePart`.
- Preserve canonical JSON byte stability for lifted tool arguments.
- Preserve fail-closed behavior for malformed upstream payloads, invalid tool arguments, bad lower-response bytes, and streaming verdict failures.
- Preserve the pinned upstream API version `v1beta`.

## Dependents

- `crates/protocol/chio-provider-conformance` depends on Gemini fixture behavior and API-version pins.
- `examples/cross-provider-policy` depends on the captured Gemini fixture path for cross-provider verdict equality, not on private response parsing helpers.
- No downstream crate depends on private `lib.rs` parsing helpers.
