# chio-bedrock-converse-adapter

Provider-native scaffold for Amazon Bedrock Runtime Converse and
ConverseStream tool-use traffic in Chio.

## Pinned upstream SDK and region

- AWS SDK crate: `aws-sdk-bedrockruntime = "1.130.0"`, pinned once in the
  root workspace `Cargo.toml` and inherited by this crate.
- Region: `us-east-1` only for v1.
- API marker: `bedrock.converse.v1`, exposed as
  `chio_bedrock_converse_adapter::transport::BEDROCK_CONVERSE_API_VERSION`.

Bumping the SDK version, region, or API marker is a deliberate PR that must
re-record the Bedrock conformance fixtures. This scaffold does not construct
an AWS client and does not make network calls in tests or normal builds.

## M07.P4 ticket sequence

| Ticket | Deliverable                                                               | Status |
| ------ | ------------------------------------------------------------------------- | ------ |
| T1     | Crate scaffold, workspace SDK pin, `us-east-1` gate, native types, transport trait | done |
| T2     | `ProviderAdapter::lift`/`lower` for batch `Converse` toolUse/toolResult blocks | done |
| T3     | `ConverseStream` buffering with verdict at `contentBlockStart` for `toolUse` | done |
| T4     | IAM principal disambiguation via signed `config/iam_principals.toml` and STS bootstrap | done |
| T5     | 12 Bedrock conformance fixtures and cold-init budget evidence             | done |
| T6     | Cross-provider demo with byte-equal verdicts across OpenAI, Anthropic, and Bedrock | done |
| T7     | Release audit row, provider integration guide, and Bedrock error taxonomy doctest | this PR |

## Crate layout

```text
crates/chio-bedrock-converse-adapter/
  Cargo.toml      workspace SDK dependency, pin metadata, lints
  README.md       this file
  src/
    iam_principals.rs signed IAM mapping loader, STS identity cache
    lib.rs        BedrockAdapter, BedrockAdapterConfig, error type
    native.rs     toolConfig, toolUse, toolResult scaffold types
    transport.rs  Transport trait, MockTransport, region and API pins
  config/
    iam_principals.toml          default signed-config path
    iam_principals.example.toml  operator template
```

## Scope in this scaffold

The transport scaffold permits only the `Converse` and `ConverseStream`
operations and rejects any region other than `us-east-1`. Native structs cover
only the subset needed by later lift/lower work: `toolConfig`, `toolUse`, and
`toolResult`.

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
`throttlingException` and `internalServerException`. This crate currently owns
offline lift/lower, deterministic stream gating, and mockable transport
validation. Rows marked `AWS Bedrock Runtime boundary` pin the
adapter-visible taxonomy that the eventual live SDK transport must preserve.
Rows marked `current adapter path` are emitted by the current lift/lower,
streaming, or evaluator path.

The table is parsed by `tests/error_taxonomy_doctest.rs`; keep each envelope
as one valid inline JSON object.

<!-- error-taxonomy:start -->
| ProviderError class | Native or boundary envelope | Source | Adapter-visible behavior |
| ------------------- | --------------------------- | ------ | ------------------------ |
| `ProviderError::RateLimited` | `{"event":"throttlingException","operation":"ConverseStream","message":"Rate exceeded","retry_after_ms":1000}` | AWS Bedrock Runtime boundary | Preserve the retry hint when Bedrock exposes one, and classify throttling separately from service 5xx. |
| `ProviderError::ContentPolicy` | `{"status":200,"operation":"Converse","body":{"stopReason":"guardrail_intervened","output":{"message":{"content":[{"text":"blocked by guardrail"}]}},"trace":{"guardrail":{"action":"INTERVENED"}}}}` | AWS Bedrock Runtime boundary | Surface Bedrock guardrail intervention as content-policy denial rather than a tool execution error. |
| `ProviderError::BadToolArgs` | `{"toolUse":{"toolUseId":"tooluse_bad_args","name":"get_weather","input":"not an object"}}` | current adapter path | Fail closed when Bedrock emits `toolUse.input` that cannot become canonical JSON object arguments. |
| `ProviderError::Upstream5xx` | `{"event":"internalServerException","operation":"ConverseStream","status":500,"message":"Internal server error"}` | AWS Bedrock Runtime boundary | Keep Bedrock service-side 5xx and unavailable envelopes visible for retry and audit policy. |
| `ProviderError::TransportTimeout` | `{"transport":"timeout","provider":"bedrock","operation":"Converse","elapsed_ms":30000}` | transport boundary | Classify local timeout separately from Bedrock service exceptions. |
| `ProviderError::VerdictBudgetExceeded` | `{"provider":"bedrock","event":"contentBlockStart","observed_ms":300,"budget_ms":250}` | current adapter path | Preserve the fabric verdict-budget error when the evaluator misses the 250ms stream gate. |
| `ProviderError::Malformed` | `{"event":"contentBlockDelta","data":{"contentBlockIndex":0,"delta":{"toolUse":{"input":"{}"}}}}` | current adapter path | Fail closed for impossible or out-of-order native ConverseStream shapes. |
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

- Trajectory doc:
  `.planning/trajectory/07-provider-native-adapters.md` Phase 4 Task 1.
- Fabric trait surface: `crates/chio-tool-call-fabric/src/lib.rs`.
- Existing scaffold convention:
  `crates/chio-anthropic-tools-adapter/`.
