# chio-openai Architecture Note

## Boundaries

- `src/lib.rs` owns the stable default surface: Chat Completions and Responses
  API tool-call extraction, manifest conversion, and direct kernel execution.
- `src/adapter.rs` is feature gated behind `provider-adapter` and owns
  Responses API lift/lower into `chio-tool-call-fabric` shapes.
- `src/streaming.rs` is feature gated behind `provider-adapter` and owns SSE
  frame buffering, event ordering, tool-call argument assembly, and verdict
  release.
- `src/transport.rs` is feature gated behind `provider-adapter` and owns the
  outbound `/v1/responses` and `/v1/chat/completions` HTTP boundary over the
  shared `chio-provider-adapter-core` transport.

## Pain Points

- The default extraction helpers and the provider-adapter lift path share
  OpenAI tool-call validation, but the large `src/lib.rs` file still carries
  much of the stable public surface. Changing that shape would be high-risk
  API work, so this slice does not move those public types.
- The buffered transport status boundary is now normalized before body parsing
  for `/v1/responses` and `/v1/chat/completions`, so injected transports and
  real HTTP transports share the same fail-closed taxonomy.
- `OpenAiAdapterConfig.api_version` is public on the provider-adapter config,
  and callers can construct or mutate a stale Responses API snapshot while the
  adapter still stamps that value into provenance.
- Batch lift, lower, streaming gates, and outbound transport all share the same
  Responses API snapshot contract, but they do not currently enforce that the
  configured `api_version` equals `responses.2026-04-25` before work begins.

## Security And API Constraints

- Keep the default feature build free of `chio-tool-call-fabric` and
  `chio-provider-adapter-core`.
- Preserve existing public exports and the pinned Responses API version
  `responses.2026-04-25`.
- Preserve canonical JSON bytes for successful tool-call invocations.
- Preserve fail-closed behavior: upstream status errors must map to concrete
  `ProviderError` classes before any body is interpreted as a tool response.
- Do not introduce live-network dependencies into tests.

## Affected Dependents

- `crates/chio-provider-conformance` consumes the OpenAI provider-adapter
  behavior through replay fixtures.
- Downstream callers that inject `MockHttpTransport` or another custom
  `ProviderHttpTransport` depend on `OpenAiTransport` enforcing the same
  status taxonomy as the real reqwest-backed transport.

## Planned Improvement

Add an adapter-local API-version guard that accepts only
`responses.2026-04-25`, then invoke it before batch lift, lower, streaming
evaluation, and outbound transport. This makes the Responses API snapshot pin a
runtime contract across every provider-adapter trust boundary while preserving
the default feature surface and the public config shape.
