# chio-tool-call-fabric Architecture

## Boundaries

- `lib.rs` is the public crate facade and should only own crate docs plus reexports.
- `types.rs` owns provider ids, principals, provenance stamps, invocation values, redactions, receipt ids, deny reasons, verdict results, and value-level validation.
- `adapter.rs` owns opaque provider request/response/result byte wrappers and the `ProviderAdapter` trait.
- `error.rs` owns the shared provider error taxonomy consumed by provider adapters.
- `stream.rs` owns the provider stream state machine and buffering limits.
- `provenance.rs` owns detached provenance signing and verification.
- `tests/` owns property invariants, lift/lower fixture byte stability, and public stream transition behavior.

## Pain Points

- The root module now stays a facade, while `types.rs`, `adapter.rs`,
  `error.rs`, `stream.rs`, and `provenance.rs` own the implementation surface.
- `ToolInvocation::validate` fails closed on provider/provenance mismatch and
  non-canonical argument bytes, and provider conformance replay calls that
  contract before comparing captured invocations.
- The same validation boundary still accepts a provider-specific principal for
  the wrong provenance provider when the top-level provider fields match.
  Cross-provider principal provenance is load-bearing receipt and policy input,
  so adapters must not be able to lift an OpenAI invocation carrying a Bedrock
  IAM principal into trusted fabric state.
- Existing property generators now cover all provider ids, so new provider enum
  variants are less likely to drift silently from generated invariants.

## Security And API Constraints

- Preserve all root-level public type paths and serialized wire shapes.
- Keep `ProviderAdapter` dyn-compatible and preserve the async trait signature.
- Preserve canonical JSON byte stability for lift/lower fixtures and signed provenance.
- Validation must be additive; existing public structs remain constructible for compatibility, but callers can explicitly fail closed before trusting an invocation.
- Do not weaken fail-closed provider error taxonomy or streaming state machine behavior.

## Affected Dependents

- Provider adapters construct `ToolInvocation` and consume `ProviderError`.
- Provider conformance replays compare adapter output against captured invocation bytes.
- CLI replay validation parses `ToolInvocation` from trace artifacts.
- Tee frame tests include lift/lower fixture bytes.

## Planned Improvement

Tighten `ToolInvocation::validate` so the owning fabric type binds
`provenance.principal` to `provenance.provider` after confirming the invocation
and provenance provider fields match. This is architectural because the fabric
crate is the single provider-agnostic boundary between native adapters and Chio
verdict/receipt machinery; downstream conformance should not need separate ad
hoc checks to decide whether provider identity is internally coherent.
