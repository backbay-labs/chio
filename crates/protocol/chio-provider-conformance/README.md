# chio-provider-conformance

Replays checked-in NDJSON captures of provider tool-call traffic through
Chio's eight native provider adapters (OpenAI, Anthropic, Bedrock, Gemini,
Mistral, Groq, Ollama, Cohere) and asserts the adapter's lifted invocations,
kernel verdicts, and lowered tool results are canonical-JSON-byte-identical to
what was captured. It is conformance tooling, not a runtime dependency:
replay never opens a live connection, and no kernel or adapter crate depends
on it. A `record` binary re-captures the OpenAI, Anthropic, and Bedrock
corpora against live provider APIs when credentials are available.

## Responsibilities

- Own the NDJSON capture schema (`chio-provider-conformance.capture.v1`) used
  by every fixture and by the `record` binary.
- Validate fixture identity on load: schema marker, non-empty and unpadded
  identifiers, `fixture_id` bound to the NDJSON filename stem, and no
  provider drift within one file.
- Replay batch and streaming captures through each adapter's lift/gate path
  and assert the reconstructed invocations and kernel verdicts match the
  capture after RFC 8785 canonical JSON encoding.
- Replay lowered tool-result bytes for fixtures that capture a lowering step.
- Re-record the OpenAI, Anthropic, and Bedrock corpora from their live APIs,
  synthesizing allow verdicts and rewriting fixtures atomically.

Each provider's fixture directory covers single and parallel tool calls,
streaming (where the API supports it), long-context input, and
error/deny/safety-refusal scenarios; `fixtures/openai/EVENTS.md` documents
the OpenAI corpus in detail.

## Public API

Re-exported at the crate root (`chio_provider_conformance::*`) unless noted:

- `CaptureRecord`, `CaptureDirection`, `CapturedVerdictKind`, `CAPTURE_SCHEMA`
  - the NDJSON capture schema.
- `fixture_root`, `provider_fixture_dir`, `provider_fixture_path` - generic
  fixture path helpers.
- `assert_canonical_json_eq`, `assert_verdict_eq`, `canonical_json_bytes_for`,
  `AssertionError` - canonical JSON and verdict comparison
  (`assertions::assert_canonical_bytes_eq` compares already-encoded bytes and
  is module-path only).
- `load_fixture`, `ProviderCaptureFixture`, `ReplayMode`, `ReplayOutcome`,
  `ReplayError`, `CapturedVerdict`, `ComparableInvocation` - fixture loading
  and generic replay types (`replay::ComparableProvenance` is the
  `provenance` field type, also module-path only).
- `LoadedWeights`, `LoadedWeightsUnavailable`, `loaded_weights_hash_of`,
  `loaded_weights_hash_of_chunks` - re-exported from `chio-core-types`.
- `replay_<provider>_fixture`, `<provider>_fixture_dir`,
  `<provider>_fixture_paths` for `openai`, `anthropic`, `bedrock`, `gemini`,
  `mistral`, `groq`, `ollama`, `cohere` - one set per feature flag below.

`record` (bin): `--provider <openai|anthropic|bedrock>` and
`--scenario <fixture_id>` (the fixture id without `.ndjson`; path separators
are rejected).

## Usage

```bash
cargo run -p chio-provider-conformance --features fixtures-openai \
  --bin record -- --provider openai --scenario openai_basic_single_tool_call
```

`record` only supports the three providers below; it reads credentials from
the environment and fails closed if any are missing.

| Provider | Environment |
|----------|-------------|
| `openai` | `OPENAI_API_KEY`, `OPENAI_ORGANIZATION` |
| `anthropic` | `ANTHROPIC_API_KEY`, `CHIO_ANTHROPIC_WORKSPACE_ID` |
| `bedrock` | `AWS_PROFILE`, or `AWS_ACCESS_KEY_ID` plus `AWS_SECRET_ACCESS_KEY` |

## Feature flags

All default off (`default = []`). Each gates the matching adapter dependency
and its `replay_<provider>_fixture` / `<provider>_fixture_dir` /
`<provider>_fixture_paths` triplet.

| Flag | Adapter enabled |
|------|------------------|
| `fixtures-openai` | `chio-openai-adapter` (`provider-adapter` feature, imported as `chio_openai`) |
| `fixtures-anthropic` | `chio-anthropic-tools-adapter` (`computer-use` feature) and `chio-manifest` |
| `fixtures-bedrock` | `chio-bedrock-converse-adapter` |
| `fixtures-gemini` | `chio-gemini-tools-adapter` |
| `fixtures-mistral` | `chio-mistral-tools-adapter` |
| `fixtures-groq` | `chio-groq-tools-adapter` |
| `fixtures-ollama` | `chio-ollama-tools-adapter` |
| `fixtures-cohere` | `chio-cohere-tools-adapter` |

## Testing

```bash
cargo test -p chio-provider-conformance --all-features
```

`tests/cross_provider_equality.rs` only compiles with all eight
`fixtures-*` features enabled at once; each `tests/replay_<provider>.rs`
needs just its own feature. Replay and the unit tests need no credentials or
network access; only `record` does.

## See also

- `chio-tool-call-fabric` - defines `ToolInvocation`, `VerdictResult`, and
  `ProviderAdapter`; this crate replays and asserts against them.
- `chio-openai-adapter`, `chio-anthropic-tools-adapter`,
  `chio-bedrock-converse-adapter`, `chio-gemini-tools-adapter`,
  `chio-mistral-tools-adapter`, `chio-groq-tools-adapter`,
  `chio-ollama-tools-adapter`, `chio-cohere-tools-adapter` - the eight
  adapters this harness replays fixtures against.
- `chio-weights` - dev-dependency consumer; reuses the capture schema and
  `fixtures/cross_provider/manifest.toml` for its own cross-provider
  model-card equivalence test.
