# Provider Integrations

Chio's provider-native adapter track mediates closed provider tool-call APIs
before they cross the Chio trust boundary. The supported M07 set is OpenAI
Responses, Anthropic Messages, and Amazon Bedrock Converse. All three adapters
lift native tool-call shapes into the shared `ProviderAdapter` fabric, run the
same kernel verdict path, and lower allowed or denied results back into the
provider's native response shape.

## Pinned Versions

| Provider | Adapter crate | Upstream pin | Scope | Re-record rule |
| -------- | ------------- | ------------ | ----- | -------------- |
| OpenAI | `chio-openai` with `provider-adapter` feature | Responses API snapshot `2026-04-25` | Responses API batch and SSE tool-call traffic | Pin bumps must update the crate metadata, README, fixture corpus, and event-name table. |
| Anthropic | `chio-anthropic-tools-adapter` | `anthropic-version: 2023-06-01` | Messages API tool-use traffic; `computer-use` beta behind feature and manifest allowlist | Header bumps must re-record Anthropic fixtures and re-check server-tool allowlist behavior. |
| Bedrock | `chio-bedrock-converse-adapter` | `aws-sdk-bedrockruntime = "1.130.0"`; `bedrock.converse.v1`; region `us-east-1` | Bedrock Runtime `Converse` and `ConverseStream` tool-use traffic | SDK, API marker, or region bumps must re-record Bedrock fixtures and re-run principal mapping checks. |

Live provider calls are not automatic CI requirements. Fixture replay is the
release gate; live API re-records are deliberate pin-bump work.

## Shared Error Taxonomy

The shared fabric error taxonomy is documented in each adapter README and
checked by per-crate `error_taxonomy_doctest.rs` tests. Provider-specific
envelopes must map to one of these classes:

| Shared class | Meaning |
| ------------ | ------- |
| `ProviderError::RateLimited` | Native rate-limit or quota envelope with retry metadata when present. |
| `ProviderError::ContentPolicy` | Provider-side refusal, guardrail intervention, or policy block that should not be treated as a tool execution failure. |
| `ProviderError::BadToolArgs` | Native tool-call arguments cannot become canonical JSON object arguments. |
| `ProviderError::Upstream5xx` | Provider service-side 5xx, overload, or unavailable envelope. |
| `ProviderError::TransportTimeout` | Local transport timeout before a trustworthy provider response exists. |
| `ProviderError::VerdictBudgetExceeded` | Chio verdict evaluation missed the streaming boundary budget. |
| `ProviderError::Malformed` | Impossible, unsupported, or out-of-order native shape. |

`ProviderError::Other` is not a release-quality mapping target. New provider
envelopes must either map to a concrete class above or fail closed as
`Malformed` until their semantics are understood.

## Bedrock IAM Principal Disambiguation

Bedrock is the only M07 provider whose caller identity is an AWS IAM
principal. Production initialization must use
`BedrockAdapter::new_with_signed_iam_principals_config_from_sts`, which:

1. Calls STS `GetCallerIdentity` once per process.
2. Loads `config/iam_principals.toml`.
3. Verifies the adjacent `config/iam_principals.toml.sigstore-bundle.json`.
4. Resolves the caller ARN and account id to a Chio owner.
5. Fails closed before lift if the config, signature, schema, or mapping is
   missing or invalid.

For STS assumed-role callers, Chio preserves both identities. The canonical IAM
role ARN is recorded as `caller_arn`, and the original
`arn:aws:sts::...:assumed-role/.../...` session ARN is recorded as
`assumed_role_session_arn`. Operators must not collapse those fields because
different assumed-role sessions can carry different operational provenance.

## Deferred Providers

| Provider | Deferred reason | Expected path |
| -------- | --------------- | ------------- |
| Vertex AI | Structurally close to Bedrock, but Google IAM, quota semantics, and fixture capture need a separate principal contract. | Add after the fabric trait and Bedrock IAM contract have stabilized. |
| Cohere | Smaller tool-call surface and lower immediate deployment pressure than the three M07 providers. | Reuse the shared taxonomy and conformance harness once a pin is selected. |
| Mistral | Similar to Cohere: tractable, but not part of the M07 release claim. | Add as a follow-on provider adapter with its own README taxonomy table and fixture corpus. |
