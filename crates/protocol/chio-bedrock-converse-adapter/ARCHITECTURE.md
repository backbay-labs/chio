# chio-bedrock-converse-adapter architecture

## Overview

The adapter is an untrusted edge component: it speaks Bedrock Converse JSON
to AWS Bedrock Runtime on one side and the Chio `ProviderAdapter` contract to
the kernel on the other, so the kernel evaluates every lifted tool call
before any Bedrock-sourced content is trusted. A single `Transport` trait
separates wire I/O (`AwsSdkTransport`, SigV4 via the AWS SDK for Rust) from
lift/lower and streaming-gate logic, so `MockTransport` exercises the same
adapter code hermetically. Construction can be gated behind IAM principal
resolution: an adapter built through the signed-config constructors cannot
exist until its caller ARN has been resolved against a signed,
Sigstore-verified mapping.

## Module map

| Path | Responsibility |
|------|-----------------|
| `src/lib.rs` | Public facade. `BedrockAdapterConfig` (region/API pin, IAM caller fields), `BedrockAdapter` construction and accessors, `BedrockAdapterError`, transport-error-to-fabric-error mapping (`map_transport_error`), and the crate's `pub use` re-exports. |
| `src/adapter.rs` | Batch lift/lower: Converse JSON envelope parsing, `toolConfig`-declared-name enforcement, `toolUse` to `ToolInvocation` lifting, verdict-to-`toolResult` lowering (allow with redactions, deny with a structured reason), and the `ProviderAdapter` trait impl. Mounts `streaming` via `#[path = "streaming.rs"]`. |
| `src/streaming.rs` (mounted as `adapter::streaming`) | `ConverseStream` event gating: a `StreamGate` state machine buffers `contentBlockStart`/`contentBlockDelta` frames per tool-use block, reconstructs JSON input at `contentBlockStop`, evaluates the caller-supplied verdict closure, and forwards frames only on allow. |
| `src/transport.rs` | `Transport` trait, `AwsSdkTransport` (SigV4 live calls via `aws-sdk-bedrockruntime`), `MockTransport` (scripted replay), JSON-to/from-`Document` conversion, and AWS SDK error taxonomy mapping (`map_sdk_error`). |
| `src/native.rs` | Bedrock wire types: `ToolConfig`, `ToolSpec`, `ToolUseBlock`, `ToolResultBlock`, `ToolResultStatus`. |
| `src/iam_principals.rs` | Signed `iam_principals.toml` loading and Sigstore bundle verification, ARN parsing and wildcard matching, `AwsStsCallerIdentityProvider` with process-wide identity caching. |
| `src/loaded_weights.rs` | `chio_core::LoadedWeights` impl for `BedrockAdapter` via `impl_unavailable_loaded_weights!`; Amazon Bedrock Converse does not expose runtime loaded model bytes. |

## Lift and lower

**Batch Converse.** `BedrockAdapter::converse` calls `Transport::converse`.
`AwsSdkTransport` rejects an empty or whitespace-padded `model_id` before
invoking the AWS SDK's signed `converse()` call under a 30-second timeout,
then re-encodes the SDK's typed `ConverseOutput` back to Bedrock Converse
JSON. `lift_batch` parses those bytes (unwrapping a `body`/`response`/
`payload` envelope field if present), validates any declared `toolConfig`
names, and lifts each `toolUse` block into a `ToolInvocation` carrying a
`ProvenanceStamp`. Once the kernel returns a verdict, `lower_tool_result`
(explicit `tool_use_id`) or the `ProviderAdapter::lower` trait method (id
read from the `ToolResult` JSON's `toolUseId` field) builds a `toolResult`
block: allow applies JSON Pointer redactions and wraps the output as Bedrock
content unless it already looks like Bedrock content; deny discards the tool
output and emits a `{"chio": {"verdict": "deny", ...}}` payload with
`status: "error"`.

**ConverseStream gating.** `gate_converse_stream` parses `raw` as an array
(or an `events`/`eventStream`-wrapped object) of one-key Bedrock event
objects and drives a `StreamGate` state machine: `contentBlockStart` with a
`toolUse` opens an `ActiveToolBlock`, `contentBlockDelta` appends
`delta.toolUse.input` fragments up to `DEFAULT_MAX_BUFFERED_RAW_FRAMES` /
`DEFAULT_MAX_BUFFERED_BLOCK_BYTES`, and `contentBlockStop` completes the
JSON, lifts a `ToolInvocation`, and calls the caller's `evaluate` closure.
`ensure_streaming_allow_no_redactions` fails the whole gate closed on deny or
on an allow that requests redactions; only then are the block's buffered
frames released.

## Invariants and failure modes

- Region and API surface are pinned redundantly: `BedrockAdapterConfig::validate`,
  `BedrockAdapter::new`, and `Transport::validate_operation` each reject
  drift from `us-east-1` / `bedrock.converse.v1` independently.
- `toolUseId` and tool `name` are trust-boundary identifiers. The lift path
  and the outbound SDK request-conversion path both reject empty or
  whitespace-padded values, so a padded id fails on the way in from Bedrock
  or before it is ever SigV4-signed on the way out.
- Streaming releases no bytes for a tool-use block until its verdict is
  known: deny, evaluator error, and allow-with-redactions all fail the
  entire `gate_converse_stream` call closed before any buffered frame for
  that block is forwarded.
- Per-block streaming buffers are bounded by `DEFAULT_MAX_BUFFERED_RAW_FRAMES`
  and `DEFAULT_MAX_BUFFERED_BLOCK_BYTES` (from `chio_tool_call_fabric::stream`).
- IAM principal resolution is fail-closed and runs before a signed-config
  adapter can exist: missing config, missing Sigstore bundle, rejected
  signature, invalid TOML, an unsupported `config_version`, and an unmapped
  caller ARN all reject at construction.
- STS `GetCallerIdentity` resolves at most once per process (`OnceLock`);
  every adapter built via `new_with_signed_iam_principals_config_from_sts` in
  that process shares the cached identity.
- `ProviderError::Other` is never produced by this adapter; every failure
  classifies into one of the seven remaining `ProviderError` variants
  (cross-checked against `README.md`'s taxonomy table by
  `tests/error_taxonomy_doctest.rs`).

## Dependencies

- `chio-tool-call-fabric` (workspace) - `ProviderAdapter`, `ProviderError`,
  `ToolInvocation`, `VerdictResult`, `Principal`, `ReceiptId`, `Redaction`,
  and the streaming primitives (`StreamPhase`, `StreamEvent`,
  `DEFAULT_MAX_BUFFERED_*`) this crate implements against.
- `chio-provider-adapter-core` (workspace) - `Provider` trait,
  `ensure_streaming_allow_no_redactions`, `impl_unavailable_loaded_weights!`.
- `chio-core` is aliased to `chio-core-types`
  (`path = "../../core/chio-core-types"`); only
  `canonical::canonical_json_bytes` is used, to canonicalize lifted tool
  arguments.
- `chio-attest-verify` (workspace) - `AttestVerifier` / `ExpectedIdentity`
  for Sigstore-bundle verification of the signed IAM principal config.
- `aws-sdk-bedrockruntime` (workspace-pinned `1.130.0`), `aws-sdk-sts`,
  `aws-smithy-runtime-api`, `aws-smithy-types`, `aws-types` - the live SigV4
  transport and STS identity resolution.
- `tokio` - the async transport and the per-call timeout wrapper around the
  SDK future.
- Dev-only: `aws-smithy-http-client` (`test-util` feature) supplies
  `StaticReplayClient` so `tests/sdk_transport.rs` runs the real SDK
  serialize/deserialize path with no network access; `http` builds the
  replayed request/response.

## Extension points

`Transport` is the seam for a different Bedrock deployment or fixture
source: implement `region`, `supports_operation`, and `converse` to target
it. The two shipped implementations are `AwsSdkTransport` (live, SigV4) and
`MockTransport` (scripted, in-memory).
