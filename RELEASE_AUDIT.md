# Release Audit

This root audit addendum records M07 provider-native adapter evidence that is
gated by ticket-level release checks. The broader repo-local release decision
record remains in `docs/release/RELEASE_AUDIT.md`.

## M07 Provider-Native Adapter Evidence

| Milestone | Surface | Evidence | Pinned versions | Signing requirement | Status |
| --------- | ------- | -------- | --------------- | ------------------- | ------ |
| M07 | OpenAI Responses, Anthropic Messages, and Bedrock Converse adapters | Conformance corpus under `crates/chio-provider-conformance/fixtures/{openai,anthropic,bedrock}/`; Bedrock includes 12 NDJSON sessions covering basic tool use, streaming, thinking, throttling retry, principal unknown deny, and kernel deny synthetic tool result | OpenAI Responses snapshot `2026-04-25`; Anthropic header `anthropic-version: 2023-06-01`; Bedrock Runtime SDK `aws-sdk-bedrockruntime = "1.130.0"` with API marker `bedrock.converse.v1` in `us-east-1` | Bedrock production initialization must load signed `config/iam_principals.toml` with adjacent `config/iam_principals.toml.sigstore-bundle.json`; missing, unsigned, stale, or unmapped principal config fails closed before tool traffic is lifted | Local M07 evidence recorded; live provider re-records remain deliberate pin-bump work |

## Gate Commands

M07.P4.T7 records the following local release-audit checks:

```bash
cargo test -p chio-bedrock-converse-adapter --test error_taxonomy_doctest
grep -q 'M07' RELEASE_AUDIT.md
grep -q 'iam_principals.toml' RELEASE_AUDIT.md
test -f docs/integrations/providers.md
```
