# chio-tool-call-fabric

Provider-agnostic tool-call types and traits shared by every Chio LLM provider
adapter. The crate defines the wire shape a native adapter's `lift` produces
(`ToolInvocation`), the verdict shape its `lower` consumes (`VerdictResult`),
and the streaming state machine that buffers a provider's tool-call block
until a verdict resolves. It holds no provider-specific logic and performs no
I/O.

`chio-openai-adapter`, `chio-anthropic-tools-adapter`, and
`chio-bedrock-converse-adapter` implement `ProviderAdapter` directly.
`chio-gemini-tools-adapter`, `chio-groq-tools-adapter`,
`chio-mistral-tools-adapter`, `chio-cohere-tools-adapter`, and
`chio-ollama-tools-adapter` consume the same `ToolInvocation` /
`ProviderError` / `VerdictResult` vocabulary in their own lift/lower functions
without implementing the trait. `chio-kernel` consumes `ToolInvocation` and
`VerdictResult` through a single conversion shim (`provider_verdict`) so the
fabric vocabulary never leaks further into kernel internals.

## Responsibilities

- Define the provider identity vocabulary: `ProviderId` (eight providers),
  `Principal` (one variant per provider's native identity scope), and
  `ProvenanceStamp`.
- Define `ToolInvocation` and `ToolInvocation::validate`, the fail-closed
  check binding `provenance.principal` to `provenance.provider` and requiring
  canonical-JSON (RFC 8785) `arguments` bytes.
- Define `VerdictResult`, `DenyReason`, and `Redaction`, the shapes a `lower`
  implementation turns back into provider-native bytes.
- Define the `ProviderAdapter` trait (`provider`, `api_version`, `lift`,
  `lower`) native adapters implement.
- Define the streaming state machine (`stream::StreamPhase`) that buffers a
  tool-call block across `Idle -> Buffering -> Emitting -> Closed`.
- Provide detached provenance signing (`provenance::sign_provenance` /
  `verify_signed_provenance`) so a `ProvenanceStamp` is attestable without the
  surrounding receipt.
- Pin the lift/lower wire contract with byte-stable canonical-JSON fixtures
  under `fixtures/lift_lower/{openai,anthropic,bedrock}/`.

## Public API

- `types::{ProviderId, Principal, ProvenanceStamp}` - provider identity vocabulary.
- `types::{ToolInvocation, ToolInvocationValidationError}` - the canonical
  tool-call shape and its fail-closed validator.
- `types::{VerdictResult, DenyReason, Redaction, ReceiptId}` - the verdict
  shape a `lower` consumes.
- `adapter::{ProviderAdapter, ProviderRequest, ProviderResponse, ToolResult}` -
  the trait every native adapter implements, plus its opaque byte wrappers.
- `error::ProviderError` - shared provider error taxonomy.
- `stream::{StreamPhase, StreamEvent, StreamError, BlockKind, BufferedBlock}` -
  the streaming state machine, paired with the budget constants
  `DEFAULT_MAX_BUFFERED_BLOCK_BYTES` and `DEFAULT_MAX_BUFFERED_RAW_FRAMES`.
- `provenance::{sign_provenance, verify_signed_provenance, SignedProvenance}` -
  detached provenance signing.

## Usage

```rust
use chio_tool_call_fabric::ToolInvocation;

fn admit(invocation: &ToolInvocation) -> Result<(), Box<dyn std::error::Error>> {
    // Fail closed before trusting a lifted or replayed invocation.
    invocation.validate()?;
    Ok(())
}
```

## Feature flags

| Flag | Effect |
|------|--------|
| `schema-subsumption` | Promotes invariant (h) in `tests/invariants.rs` from a structural self-check to a `jsonschema` assertion once the canonical `chio-tool-call-fabric.v1` schema is vendored. |

## Testing

`cargo test -p chio-tool-call-fabric`

`CHIO_BLESS_LIFT_LOWER=1 cargo test -p chio-tool-call-fabric --test lift_lower_fixtures`
regenerates `fixtures/lift_lower/**` from the in-source builders after a
deliberate shape change. CI never sets it.

## See also

- `chio-provider-adapter-core` - shared HTTP/SSE primitives built on these types.
- `chio-openai-adapter`, `chio-anthropic-tools-adapter`,
  `chio-bedrock-converse-adapter` - implement `ProviderAdapter` directly.
- `chio-gemini-tools-adapter`, `chio-groq-tools-adapter`,
  `chio-mistral-tools-adapter`, `chio-cohere-tools-adapter`,
  `chio-ollama-tools-adapter` - use the fabric's lift/lower vocabulary without
  implementing `ProviderAdapter`.
- `chio-kernel` - converts `ToolInvocation` and `VerdictResult` at the kernel
  boundary via `provider_verdict`.
- `chio-provider-conformance` - replays captured invocations against this contract.
- `chio-cli` - the `replay` subcommand parses `ToolInvocation` from trace artifacts.
