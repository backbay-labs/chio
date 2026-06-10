# chio-bedrock-converse-adapter Architecture Note

## Module Boundaries

- `lib.rs` is the public facade. It owns `BedrockAdapterConfig`, adapter construction, IAM-principal initialization entry points, and the public re-exports for native Bedrock blocks and transports.
- `adapter.rs` owns batch Converse lifting and lowering: Bedrock `toolUse` blocks become Chio fabric `ToolInvocation`s, and Chio verdicts become Bedrock `toolResult` blocks.
- `streaming.rs` owns deterministic ConverseStream gating. It buffers tool-use frames until a complete JSON argument object exists, evaluates the Chio verdict, and forwards only allowed frames.
- `transport.rs` owns request conversion into AWS SDK Bedrock Runtime types, region and operation gates, timeout mapping, SDK error taxonomy mapping, and hermetic mock transport behavior.
- `iam_principals.rs` owns signed IAM principal mapping and STS identity caching before adapter construction.
- `native.rs` owns the small serde-facing Bedrock `toolConfig`, `toolUse`, and `toolResult` subset that fixtures and callers use.

## Request Trust Boundary

Batch and streaming lift paths treat Bedrock `toolUseId` and tool names as
trust-boundary identifiers and reject surrounding whitespace before provenance or
canonical arguments are produced. The outbound SDK request conversion path in
`transport.rs` signs and sends caller-supplied message content to Bedrock; it
rejects empty or whitespace-padded `modelId` values before request signing, since
`modelId` selects the Bedrock model or inference profile and a padded value would
cross the SigV4 boundary instead of failing closed in Chio. JSON request-envelope
parsing and SDK request conversion share one validator, so both construction paths
enforce the same invariant.

## Security And API Constraints

- Preserve public API compatibility.
- Preserve the v1 region and API pins: `us-east-1` and `bedrock.converse.v1`.
- Fail closed before network dispatch: malformed request identifiers return `TransportError::MalformedRequest`.
- Preserve canonical JSON byte stability for lifted tool arguments.
- Do not add ambient AWS authority or expand supported Bedrock operations.

## Affected Dependents

- `BedrockAdapter::converse` depends on `Transport::converse` to reject malformed outbound request shapes before any AWS call.
- Hermetic SDK transport tests depend on `transport.rs` request conversion matching the live SDK shape.
- Provider conformance fixtures depend on lift/lower semantics.
- No downstream crate needs a public API or fixture change.
