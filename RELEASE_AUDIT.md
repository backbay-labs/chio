# Release Audit

This root audit addendum records provider-native adapter evidence for the
OpenAI Responses, Anthropic Messages, and Bedrock Converse adapters. The
broader repo-local release decision record is in `docs/release/RELEASE_AUDIT.md`.

## Provider-Native Adapter Evidence

| Surface | Evidence | Pinned versions | Signing requirement | Status |
| ------- | -------- | --------------- | ------------------- | ------ |
| OpenAI Responses, Anthropic Messages, and Bedrock Converse adapters | Conformance corpus under `crates/chio-provider-conformance/fixtures/{openai,anthropic,bedrock}/`; Bedrock includes 12 NDJSON sessions covering basic tool use, streaming, thinking, throttling retry, principal unknown deny, and kernel deny synthetic tool result | OpenAI Responses snapshot `2026-04-25`; Anthropic header `anthropic-version: 2023-06-01`; Bedrock Runtime SDK `aws-sdk-bedrockruntime = "1.130.0"` with API marker `bedrock.converse.v1` in `us-east-1` | Bedrock production initialization must load signed `config/iam_principals.toml` with adjacent `config/iam_principals.toml.sigstore-bundle.json`; missing, unsigned, stale, or unmapped principal config fails closed before tool traffic is lifted | Local evidence recorded; live provider re-records remain deliberate pin-bump work |

## Gate Commands

The following commands verify the provider-adapter evidence:

```bash
cargo test -p chio-bedrock-converse-adapter --test error_taxonomy_doctest
grep -q 'iam_principals.toml' RELEASE_AUDIT.md
test -f docs/integrations/providers.md
```
