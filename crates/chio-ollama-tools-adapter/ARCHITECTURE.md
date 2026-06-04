# chio-ollama-tools-adapter architecture note

## Boundaries

- `lib.rs` owns the public adapter handle, configuration, provider identity, lift/lower entrypoints, and the `Provider` implementation.
- `transport.rs` owns the shared HTTP transport wiring for Ollama's `/api/chat` endpoint, including localhost defaults, optional gateway bearer auth, and the `2025-04` API-version pin.
- `native.rs` owns the adapter's normalized Ollama content shapes: decoded tool calls and lowered tool-result messages.
- `streaming.rs` owns buffered NDJSON mediation for streaming `/api/chat` frames and gates streamed `tool_calls` before release.
- `loaded_weights.rs` owns the explicit adapter-handle unavailable path plus a separate loaded-weights wrapper for callers that can provide local model bytes.

## Pain Points

- `OllamaAdapterConfig.api_version` is public and serializable, so persisted or hand-built configs can drift away from the crate pin even though the README and fixtures define a single supported API snapshot. The adapter now fails closed before outbound calls, captured lifting, streamed gating, direct tool-call lifting, and lower-response helpers when that config pin drifts.
- The conformance corpus records `x-ollama-api-version: 2025-04`, but `transport::resolve_config` currently builds real HTTP transports with no default headers.
- A live Ollama transport can therefore omit the same API snapshot header that fixtures and downstream replay gates treat as part of the adapter contract.

## Constraints

- Preserve public API compatibility for `OllamaAdapter`, `OllamaAdapterConfig`, transport constructors, loaded-weights helpers, `ToolCallPart`, `ToolCallFunction`, and `ToolResultMessage`.
- Preserve canonical JSON byte stability for decoded `tool_calls[].function.arguments` and lowered tool-result messages.
- Preserve fail-closed behavior for malformed upstream payloads, invalid arguments, transport failures, bad lower-response bytes, and streaming verdict failures.
- Preserve the pinned upstream API version `2025-04`.
- Do not edit generated artifacts or fixture corpora in this slice.

## Dependents

- `crates/chio-provider-conformance` depends on Ollama fixture behavior and API-version pins.
- `tests/localhost_replay.rs` depends on the recorded Ollama fixture and the shared mock transport path.
- Cross-provider equality checks depend on the captured Ollama fixture path for canonical invocation bytes.
- `streaming.rs` and direct native lifting depend on the same config pin as outbound transport because both stamp provider provenance.

## Planned Improvement

Make the Ollama transport config stamp `x-ollama-api-version: 2025-04` on every real HTTP transport path, including default localhost, `OLLAMA_HOST` overrides, optional remote-gateway bearer auth, and explicit `live_transport_for` construction. This is architectural because it aligns live outbound transport with the replay fixture contract and the adapter's provenance/API pin without changing the public adapter config shape.
