# chio-bedrock-converse-adapter Architecture Note

## Current Boundaries

- `lib.rs` is the public facade. It owns `BedrockAdapterConfig`, adapter construction, IAM-principal initialization entry points, and the public re-exports for native Bedrock blocks and transports.
- `adapter.rs` owns batch Converse lifting and lowering: Bedrock `toolUse` blocks become Chio fabric `ToolInvocation`s, and Chio verdicts become Bedrock `toolResult` blocks.
- `streaming.rs` owns deterministic ConverseStream gating. It buffers tool-use frames until a complete JSON argument object exists, evaluates the Chio verdict, and forwards only allowed frames.
- `transport.rs` owns request conversion into AWS SDK Bedrock Runtime types, region and operation gates, timeout mapping, SDK error taxonomy mapping, and hermetic mock transport behavior.
- `iam_principals.rs` owns signed IAM principal mapping and STS identity caching before adapter construction.
- `native.rs` owns the small serde-facing Bedrock `toolConfig`, `toolUse`, and `toolResult` subset that fixtures and callers use.

## Pain Points

- Batch and streaming lift paths already treat Bedrock `toolUseId` and tool names as trust-boundary identifiers and reject surrounding whitespace before provenance or canonical arguments are produced.
- The outbound SDK request conversion path in `transport.rs` is a separate trust boundary: it signs and sends caller-supplied message content to Bedrock. That path currently checks only that string identifiers are non-empty.
- Existing transport tests cover padded `toolUseId`, `toolUse.name`, and `toolResult.toolUseId`, but the same boundary still accepts a padded `modelId`.
- `modelId` selects the Bedrock model or inference profile. Sending a caller-supplied padded value to the SDK pushes malformed identity material across the SigV4 boundary instead of failing closed in Chio.
- The mock transport does not exercise the SDK conversion path, so the transport module itself needs targeted boundary tests.

## Security And API Constraints

- Preserve public API compatibility. The fix should stay inside the transport conversion boundary.
- Preserve the v1 region and API pins: `us-east-1` and `bedrock.converse.v1`.
- Preserve fail-closed behavior before network dispatch. Malformed request identifiers should return `TransportError::MalformedRequest`.
- Preserve canonical JSON byte stability for lifted tool arguments. This slice should not touch batch lifting or streaming argument reconstruction.
- Do not add ambient AWS authority or expand supported Bedrock operations.

## Affected Dependents

- `BedrockAdapter::converse` depends on `Transport::converse` to reject malformed outbound request shapes before any AWS call.
- Hermetic SDK transport tests depend on `transport.rs` request conversion matching the live SDK shape.
- Provider conformance fixtures depend on lift/lower semantics, but this slice does not change response lifting or fixture format.
- No downstream crate should need a public API or fixture change.

## Planned Material Improvement

Make the outbound Bedrock SDK request conversion boundary reject empty or whitespace-padded `modelId` values before request signing. Prove it with a hermetic SDK transport red test that records zero dispatched requests, then share the same validator with JSON request-envelope parsing so both construction paths enforce the same invariant.
