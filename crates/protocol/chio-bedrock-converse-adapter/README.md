# chio-bedrock-converse-adapter

Adapts Amazon Bedrock Runtime Converse and ConverseStream tool-use traffic to
the Chio `ProviderAdapter` contract: Bedrock `toolUse` content blocks lift
into fabric `ToolInvocation`s, and kernel verdicts lower into Bedrock
`toolResult` content blocks. The live transport signs every call with SigV4
through the AWS SDK for Rust and is pinned to one AWS region and one Bedrock
API surface for v1. It is one of Chio's native provider adapters, alongside
sibling crates such as `chio-anthropic-tools-adapter` that translate other
providers' tool-call dialects into the same fabric contract.

## Responsibilities

- Drive the live Bedrock Runtime `Converse` operation through
  `aws-sdk-bedrockruntime` (SigV4-signed) and re-encode its typed response
  back to Bedrock Converse JSON (`transport::AwsSdkTransport`).
- Lift `toolUse` content blocks from a batch Converse response into
  `ToolInvocation`, enforcing any declared `toolConfig` tool names
  (`BedrockAdapter::lift_batch`).
- Lower a kernel `VerdictResult` into a Bedrock `toolResult` block: JSON
  Pointer redactions on the allow path, a structured `chio` denial payload on
  the deny path (`BedrockAdapter::lower_tool_result`).
- Gate `ConverseStream` tool-use events: buffer `contentBlockStart` /
  `contentBlockDelta` frames per block, evaluate the completed JSON input
  against a caller-supplied verdict closure, and release frames only on
  allow (`BedrockAdapter::gate_converse_stream`).
- Resolve the calling IAM principal from a signed `iam_principals.toml` and
  its Sigstore bundle before any tool-use traffic can be lifted, with an STS
  `GetCallerIdentity` bootstrap path.
- Reject construction or configuration that drifts from the v1 region and
  API pin.

## Public API

- `BedrockAdapter` - adapter handle; `new`, `new_with_signed_iam_principals_config`,
  `new_with_signed_iam_principals_config_from_sts`, `converse`, `lift_batch`,
  `lower_tool_result`, `gate_converse_stream`, `principal_owner`,
  `matched_iam_principal_pattern`.
- `BedrockAdapterConfig` - server identity, the pinned region/API version, and
  IAM caller fields; `new`, `with_assumed_role_session_arn`, `validate`,
  `principal`.
- `BedrockAdapterError` - construction and config errors (`UnsupportedRegion`,
  `UnsupportedApiVersion`, `Transport`, `IamPrincipals`).
- `transport::{Transport, AwsSdkTransport, MockTransport, TransportError,
  ConverseRequest, BedrockOperation}` - `BEDROCK_REGION` and
  `BEDROCK_CONVERSE_API_VERSION` are re-exported at the crate root.
- `iam_principals::{IamPrincipalsConfig, IamPrincipalMapping,
  AwsStsCallerIdentityProvider, BedrockCallerIdentity,
  ResolvedBedrockPrincipal, IamPrincipalConfigError}` - re-exported at the
  crate root, along with `DEFAULT_IAM_PRINCIPALS_CONFIG_PATH`.
- `native::{ToolConfig, ToolSpec, ToolUseBlock, ToolResultBlock,
  ToolResultStatus}` - Bedrock wire types, re-exported at the crate root.
- `adapter::streaming::GatedConverseStream` - the bytes, events, invocations,
  and verdicts returned by `gate_converse_stream`.
- `BedrockAdapter` implements `chio_tool_call_fabric::ProviderAdapter`,
  `chio_provider_adapter_core::Provider`, and `chio_core::LoadedWeights`
  (always unavailable, since Amazon Bedrock Converse does not expose runtime
  loaded model bytes).

## Pinned surface

| Constant | Value |
|----------|-------|
| `BEDROCK_REGION` | `us-east-1` |
| `BEDROCK_CONVERSE_API_VERSION` | `bedrock.converse.v1` |
| workspace `aws-sdk-bedrockruntime` | `1.130.0` |

`BedrockAdapterConfig::validate` and `BedrockAdapter::new` reject any other
region or API version at construction; `Transport::validate_operation`
re-checks the region on every call. Bumping the SDK pin or region requires a
fixture re-record PR against the Bedrock conformance fixtures in
`chio-provider-conformance`.

## IAM principal mapping

Production initialization should use
`BedrockAdapter::new_with_signed_iam_principals_config_from_sts`: it resolves
STS `GetCallerIdentity` once per process, loads `config/iam_principals.toml`,
verifies the adjacent `config/iam_principals.toml.sigstore-bundle.json`
through the `chio-attest-verify` `AttestVerifier`, and resolves the caller to
the shared `Principal::BedrockIam` shape. Mapping entries are ordered; the
first exact or `*` wildcard match against the caller ARN wins. For an STS
assumed-role caller, the adapter keeps the original assumed-role session ARN
in `assumed_role_session_arn` and stores the canonical IAM role ARN
separately in `caller_arn`.

Fails closed on a missing config file, a missing Sigstore bundle, a rejected
signature, invalid TOML, an unsupported `config_version`, and a caller ARN
with no matching mapping (`IamPrincipalConfigError`).

## Adapter-visible error taxonomy

Bedrock Runtime surfaces batch failures as AWS JSON error envelopes and
ConverseStream failures as event-stream exception objects such as
`throttlingException` and `internalServerException`. `BedrockAdapter::converse`
maps the live `AwsSdkTransport` Converse path's AWS SDK errors (rows marked
`AWS Bedrock Runtime boundary`) as follows: throttling to `RateLimited`;
model-timeout, internal-server, and service-unavailable exceptions to
`Upstream5xx` (status 408, 500, and 503 respectively); validation,
access-denied, and other service exceptions to `Malformed`. The local
per-call timeout wrapper, not an AWS-emitted exception, produces
`TransportTimeout` (marked `transport boundary`). Rows marked `current
adapter path` are produced directly by the lift, streaming, or evaluator
code in this crate.

The table is parsed by `tests/error_taxonomy_doctest.rs`; keep each envelope
as one valid inline JSON object.

<!-- error-taxonomy:start -->
| ProviderError class | Native or boundary envelope | Source | Adapter-visible behavior |
| ------------------- | --------------------------- | ------ | ------------------------ |
| `ProviderError::RateLimited` | `{"event":"throttlingException","operation":"ConverseStream","message":"Rate exceeded","retry_after_ms":1000}` | `urn:chio:error:provider:bedrock` (`CHIO-PROVIDER-BEDROCK`) + AWS Bedrock Runtime boundary | Bedrock Converse provider adapter returned a normalized provider error. Preserve the retry hint when Bedrock exposes one, and classify throttling separately from service 5xx. Registry help: Inspect the provider error details and retry only when the adapter marks the failure transient. |
| `ProviderError::ContentPolicy` | `{"status":200,"operation":"Converse","body":{"stopReason":"guardrail_intervened","output":{"message":{"content":[{"text":"blocked by guardrail"}]}},"trace":{"guardrail":{"action":"INTERVENED"}}}}` | `urn:chio:error:provider:bedrock` (`CHIO-PROVIDER-BEDROCK`) + AWS Bedrock Runtime boundary | Bedrock Converse provider adapter returned a normalized provider error. Surface Bedrock guardrail intervention as content-policy denial rather than a tool execution error. Registry help: Inspect the provider error details and retry only when the adapter marks the failure transient. |
| `ProviderError::BadToolArgs` | `{"toolUse":{"toolUseId":"tooluse_bad_args","name":"get_weather","input":"not an object"}}` | `urn:chio:error:provider:bedrock` (`CHIO-PROVIDER-BEDROCK`) + current adapter path | Bedrock Converse provider adapter returned a normalized provider error. Fail closed when Bedrock emits `toolUse.input` that cannot become canonical JSON object arguments. Registry help: Inspect the provider error details and retry only when the adapter marks the failure transient. |
| `ProviderError::Upstream5xx` | `{"event":"internalServerException","operation":"ConverseStream","status":500,"message":"Internal server error"}` | `urn:chio:error:provider:bedrock` (`CHIO-PROVIDER-BEDROCK`) + AWS Bedrock Runtime boundary | Bedrock Converse provider adapter returned a normalized provider error. Keep Bedrock service-side 5xx and unavailable envelopes visible for retry and audit policy. Registry help: Inspect the provider error details and retry only when the adapter marks the failure transient. |
| `ProviderError::TransportTimeout` | `{"transport":"timeout","provider":"bedrock","operation":"Converse","elapsed_ms":30000}` | `urn:chio:error:provider:bedrock` (`CHIO-PROVIDER-BEDROCK`) + transport boundary | Bedrock Converse provider adapter returned a normalized provider error. Classify local timeout separately from Bedrock service exceptions. Registry help: Inspect the provider error details and retry only when the adapter marks the failure transient. |
| `ProviderError::VerdictBudgetExceeded` | `{"provider":"bedrock","event":"contentBlockStart","observed_ms":300,"budget_ms":250}` | `urn:chio:error:provider:bedrock` (`CHIO-PROVIDER-BEDROCK`) + current adapter path | Bedrock Converse provider adapter returned a normalized provider error. Preserve the fabric verdict-budget error when the evaluator misses the 250ms stream gate. Registry help: Inspect the provider error details and retry only when the adapter marks the failure transient. |
| `ProviderError::Malformed` | `{"event":"contentBlockDelta","data":{"contentBlockIndex":0,"delta":{"toolUse":{"input":"{}"}}}}` | `urn:chio:error:provider:bedrock` (`CHIO-PROVIDER-BEDROCK`) + current adapter path | Bedrock Converse provider adapter returned a normalized provider error. Fail closed for impossible or out-of-order native ConverseStream shapes. Registry help: Inspect the provider error details and retry only when the adapter marks the failure transient. |
<!-- error-taxonomy:end -->

`ProviderError::Other` is intentionally absent: every Bedrock-visible failure
must map to one of the seven classes above, or fail closed as `Malformed`
when the shape cannot be trusted.

## Testing

`cargo test -p chio-bedrock-converse-adapter`

`tests/sdk_transport.rs` injects a `StaticReplayClient` as the AWS SDK's HTTP
client, so the real Converse serialize/deserialize path runs with no network
access. `tests/error_taxonomy_doctest.rs` parses the taxonomy table above out
of this file and cross-checks it against `ProviderError`.
`benches/verdict_latency.rs` is a `#[test]`-based bench target asserting a
500ms p99 cold-init-to-verdict budget over `MockTransport`.

## See also

- `chio-tool-call-fabric` - defines `ProviderAdapter`, `ProviderError`, and
  the fabric types this crate implements against.
- `chio-provider-adapter-core` - supplies the `Provider` trait and the
  shared streaming-gate and loaded-weights helpers used here.
- `chio-anthropic-tools-adapter` - sibling provider adapter with the same
  lift/lower/gate shape for Anthropic tool calls.
- `chio-provider-conformance` - exercises this adapter's fixtures behind its
  `fixtures-bedrock` feature.
