# M07 Adoption Beachhead Audit

Date: 2026-04-30
Ticket: M07.P0.T1
Source of truth: `.planning/trajectory-2/07-adoption-beachhead-pack.md`

## Purpose

This audit anchors the Wave 3 M07 adoption beachhead work before provider
adapter pack II, framework TypeScript packages, MCP wrapping, templates, and
TTFRH gates start landing in parallel worktrees. The baseline below records
the trajectory-1 provider-native adapter surface that M07 extends.

## trajectory-1 M07 surface snapshot

Measured in this worktree on 2026-04-30.

| Surface | Baseline | Evidence |
| --- | ---: | --- |
| Provider fabric providers | 3 | `ProviderId::{OpenAi, Anthropic, Bedrock}` in `crates/chio-tool-call-fabric/src/lib.rs` |
| Native provider adapters | 3 | `crates/chio-openai`, `crates/chio-anthropic-tools-adapter`, `crates/chio-bedrock-converse-adapter` |
| Provider conformance fixtures | 36 | 12 NDJSON fixtures each under `crates/chio-provider-conformance/fixtures/{openai,anthropic,bedrock}/` |
| Fabric lift/lower fixtures | 9 | 3 JSON fixtures each under `crates/chio-tool-call-fabric/fixtures/lift_lower/{openai,anthropic,bedrock}/` |
| Cross-provider verdict-equality oracle | 3-provider oracle | `crates/chio-provider-conformance/tests/cross_provider_equality.rs` compares OpenAI, Anthropic, and Bedrock weather-tool allow verdicts |

## Fabric Trait Surface

The trajectory-1 fabric contract is already implemented in
`crates/chio-tool-call-fabric/src/lib.rs` and remains the compatibility anchor
for M07 provider expansion:

- `ProviderId` has `OpenAi`, `Anthropic`, and `Bedrock`.
- `Principal` maps provider identity to OpenAI org, Anthropic workspace, or
  Bedrock IAM principal metadata.
- `ProvenanceStamp` carries provider, request id, API version, principal, and
  receipt time.
- `ToolInvocation` carries normalized provider id, tool name, canonical JSON
  argument bytes, and provenance.
- `VerdictResult` lowers kernel allow or deny results back to provider-native
  response bytes through `ProviderAdapter::lower`.
- `ProviderAdapter` exposes `provider`, `api_version`, `lift`, and `lower`.

## M07 Expansion Target

M07 keeps the existing fabric shape and grows the provider matrix from 3 to 8
providers by adding Gemini, Mistral, Groq, Ollama, and Cohere. The target
fixture expansion is 60 new provider-conformance NDJSON fixtures, preserving
the 12-fixture-per-provider trajectory-1 pattern. When P4 re-cardinalizes the
oracle, the expected cross-provider verdict-equality set becomes 8 providers
instead of 3.

## Reproduction Commands

```bash
for provider in openai anthropic bedrock; do
  printf '%s ' "$provider"
  find "crates/chio-provider-conformance/fixtures/$provider" -maxdepth 1 -name '*.ndjson' -type f | wc -l | tr -d ' '
  printf '\n'
done

find crates/chio-tool-call-fabric/fixtures/lift_lower -type f -name '*.json'
```

## Notes For Follow-On Tickets

- M07.P0.T2 owns the additive `ProviderId` enum extension. This audit should
  remain a baseline snapshot, not the enum-change patch.
- M07.P4 owns the provider-conformance fixture corpus expansion and the
  cross-provider oracle cardinality change.
- M07.P5 owns TTFRH bench enforcement. This audit only records the pre-work
  substrate and does not certify first-receipt timing.
