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
- `src/tests.rs` owns the default-surface unit coverage for manifest
  conversion, tool-call extraction, direct kernel execution, and response
  rendering.

## API-Version Pin

The default extraction helpers and the provider-adapter lift path share OpenAI
tool-call validation. The buffered transport status boundary is normalized before
body parsing for `/v1/responses` and `/v1/chat/completions`, so injected
transports and real HTTP transports share the same fail-closed taxonomy.

`OpenAiAdapterConfig.api_version` is public, so callers can construct or mutate a
Responses API snapshot that the adapter stamps into provenance. An adapter-local
API-version guard accepts only `responses.2026-04-25` and runs before batch lift,
lower, streaming evaluation, and outbound transport. The Responses API snapshot
pin is therefore a runtime contract across every provider-adapter trust boundary.

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

- `crates/protocol/chio-provider-conformance` consumes the OpenAI provider-adapter
  behavior through replay fixtures.
- Downstream callers that inject `MockHttpTransport` or another custom
  `ProviderHttpTransport` depend on `OpenAiTransport` enforcing the same
  status taxonomy as the real reqwest-backed transport.
