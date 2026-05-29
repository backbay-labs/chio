# chio-bedrock-converse-adapter

Mediates Amazon Bedrock Runtime Converse and ConverseStream tool-use traffic
in Chio.

## Transport

The live transport, `transport::AwsSdkTransport`, calls the Bedrock Runtime
Converse operation through the AWS SDK for Rust (`aws-sdk-bedrockruntime`),
which signs every request with SigV4. It is built from an
`aws_types::sdk_config::SdkConfig` (the shape the AWS default credential and
region chain produces, via `aws_config::defaults(..).load().await`) or from
caller-supplied static credentials, and is pinned to `us-east-1`. The SDK
lifts the model's `toolUse` blocks; `BedrockAdapter::converse` drives the call
and feeds the response to `lift_batch`.

`transport::MockTransport` records intended calls and replays scripted Converse
responses, so the adapter is exercised without contacting AWS. Hermetic tests
(`tests/sdk_transport.rs`) inject a `StaticReplayClient` as the SDK HTTP client
to run the real Converse serialize/deserialize path offline.

## Pinned upstream SDK and region

- AWS SDK crate: `aws-sdk-bedrockruntime = "1.130.0"`, pinned once in the
  root workspace `Cargo.toml` and inherited by this crate.
- Region: `us-east-1` only for v1.
- API marker: `bedrock.converse.v1`, exposed as
  `chio_bedrock_converse_adapter::transport::BEDROCK_CONVERSE_API_VERSION`.

Bumping the SDK version, region, or API marker is a deliberate PR that must
re-record the Bedrock conformance fixtures.

## Implementation Status

| Deliverable                                                               | Status |
| ------------------------------------------------------------------------- | ------ |
| Workspace SDK pin, `us-east-1` gate, native types, transport trait        | done |
| AWS-SDK-backed `Converse` transport (SigV4) plus recording `MockTransport` | done |
| `ProviderAdapter::lift`/`lower` for batch `Converse` toolUse/toolResult blocks | done |
| `ConverseStream` buffering with verdict at `contentBlockStart` for `toolUse` | done |
| IAM principal disambiguation via signed `config/iam_principals.toml` and STS bootstrap | done |
| 12 Bedrock conformance fixtures and cold-init budget evidence             | done |
| Cross-provider demo with byte-equal verdicts across OpenAI, Anthropic, and Bedrock | done |
| Release audit row, provider integration guide, and Bedrock error taxonomy doctest | this PR |

## Crate layout

```text
crates/chio-bedrock-converse-adapter/
  Cargo.toml      workspace SDK dependency, pin metadata, lints
  README.md       this file
  src/
    iam_principals.rs signed IAM mapping loader, STS identity cache
    lib.rs        BedrockAdapter, BedrockAdapterConfig, error type
    native.rs     toolConfig, toolUse, toolResult wire types
    transport.rs  Transport trait, AwsSdkTransport, MockTransport, region and API pins
  config/
    iam_principals.toml          default signed-config path
    iam_principals.example.toml  operator template
```

## Scope

The transport permits only the `Converse` and `ConverseStream` operations and
rejects any region other than `us-east-1`. Native structs cover the subset
needed by lift/lower: `toolConfig`, `toolUse`, and `toolResult`.

## IAM Principal Mapping

Production Bedrock initialization should use
`BedrockAdapter::new_with_signed_iam_principals_config_from_sts`. It performs
one STS `GetCallerIdentity` call per process, loads
`config/iam_principals.toml`, verifies the adjacent Sigstore bundle, and then
resolves the caller to the shared `Principal::BedrockIam` shape.

The required bundle path is the TOML path plus `.sigstore-bundle.json`:

```text
config/iam_principals.toml
config/iam_principals.toml.sigstore-bundle.json
```

The verifier is the shared `chio-attest-verify` `AttestVerifier` surface.
Operators must pass the expected Sigstore certificate identity and OIDC issuer
from their deployment policy. Missing config, missing bundle, rejected
signature, invalid TOML, unsupported schema, and unmapped callers all fail
closed before tool-use traffic is lifted.

Mapping order matters. The first exact or `*` wildcard match wins. For STS
assumed-role callers, the adapter preserves the original
`arn:aws:sts::...:assumed-role/.../...` session ARN in
`assumed_role_session_arn` and stores the canonical IAM role ARN in
`caller_arn`; it does not collapse the two fields.

## Adapter-visible error taxonomy

Bedrock Runtime surfaces batch failures as AWS JSON error envelopes and
ConverseStream failures as event-stream exception objects such as
`throttlingException` and `internalServerException`. Rows marked
`AWS Bedrock Runtime boundary` are emitted by the live `AwsSdkTransport`
Converse path: `BedrockAdapter::converse` maps the SDK error taxonomy into the
adapter-visible classes below (throttling to `RateLimited`, service 5xx to
`Upstream5xx`, model timeout to a transport error, validation/access errors to
`Malformed`). Rows marked `current adapter path` are emitted by the lift/lower,
streaming, or evaluator path.

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

`ProviderError::Other` is intentionally absent. Native Bedrock envelopes must
map to a concrete class above, or fail closed as `Malformed` when the shape
cannot be trusted.

## Building

```bash
cargo build -p chio-bedrock-converse-adapter
```

## House rules

- No em dashes (U+2014) anywhere in code, comments, or documentation.
- Workspace clippy lints `unwrap_used = "deny"` and `expect_used = "deny"`
  apply; no exceptions.
- No `todo!()`, `unimplemented!()`, or bare `panic!()` in trust-boundary
  paths.
- Fail-closed: invalid region or API-surface config rejects at construction.

## References

- Fabric trait surface: `crates/chio-tool-call-fabric/src/lib.rs`.
- Sibling adapter convention:
  `crates/chio-anthropic-tools-adapter/`.
