# chio-provider-conformance architecture

## Overview

This crate is a conformance test harness, not a runtime dependency: nothing
in the kernel or adapter crates depends on it, and it is unpublished
(`publish = false`). It answers one question for each of Chio's eight native
provider adapters: does lifting, gating, and lowering a captured provider
payload reproduce the exact canonical-JSON bytes recorded for it? Fixture
replay never performs live I/O; every adapter under replay is constructed
with `MockTransport` (or, for OpenAI, no transport at all) and driven purely
from captured bytes. The one component that does touch the network or a
cloud CLI is the `record` binary, which re-captures the OpenAI, Anthropic,
and Bedrock corpora against their live APIs. `chio-weights` is the only
in-tree consumer, as a dev-dependency that reuses the capture schema and the
cross-provider fixture manifest for a model-card equivalence test.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Crate root. Declares `assertions`, `capture`, `loaded_weights`, `replay` as public modules and re-exports their key items. |
| `src/capture.rs` | NDJSON capture schema: `CaptureRecord`, `CaptureDirection`, `CapturedVerdictKind`, `CAPTURE_SCHEMA`, generic fixture path helpers. |
| `src/assertions.rs` | RFC 8785 canonical JSON and `VerdictResult` equality assertions; `AssertionError`. |
| `src/loaded_weights.rs` | Re-export of the loaded-weights digest contract; the trait itself is defined in `chio-core-types`, not here. |
| `src/replay.rs` | Replay module root: `ReplayError`, `ProviderCaptureFixture`, `ReplayMode`, `ReplayOutcome`, `CapturedVerdict`, `ComparableInvocation`/`ComparableProvenance`. Declares the private submodules below and re-exports their entrypoints. |
| `src/replay/fixture.rs` | `load_fixture` and fixture identity validation, per-provider `ensure_<provider>`/header/principal extraction, per-provider stream-chronology checks, fixture dir/path helpers. |
| `src/replay/payload.rs` | Provider-specific payload predicates ("does this response carry a tool call") and header extraction shared by `fixture.rs`. |
| `src/replay/stream.rs` | Reconstructs SSE bytes, the Bedrock event-list JSON array, and Ollama NDJSON from captured `upstream_event` records. |
| `src/replay/assert.rs` | Replayed-invocation and replayed-verdict assertions, per-provider lowered-response assertions, and `futures_lite_block_on` (a no-op-waker poll loop) for driving the OpenAI/Anthropic/Bedrock async `ProviderAdapter::lower` synchronously. |
| `src/replay/openai.rs` | `replay_openai_fixture`: batch and SSE-stream replay through `chio_openai::OpenAiAdapter`. |
| `src/replay/anthropic.rs` | `replay_anthropic_fixture`: batch and SSE-stream replay through `AnthropicAdapter`, built with a `MockTransport` and a conformance `ToolManifest` (server tools, signed public key). |
| `src/replay/bedrock.rs` | `replay_bedrock_fixture`: batch and Converse-stream replay through `BedrockAdapter`, with the IAM principal sourced from captured headers. |
| `src/replay/additional_providers.rs` | `replay_{gemini,mistral,groq,ollama,cohere}_fixture`: batch (plus stream for Ollama/Cohere) replay and lowered-response assertion for each. |
| `src/replay/tests.rs` | `#[cfg(test)]` unit tests for fixture-loading fail-closed behavior. |
| `src/bin/record.rs` | `record` binary entrypoint; declares its submodules and `RecordError`. |
| `src/bin/record/cli.rs` | `clap` CLI (`--provider`, `--scenario`); loads and validates the `ScenarioSeed`; dispatches to the provider-specific recorder. |
| `src/bin/record/record.rs` | Builds the live request `CaptureRecord` from the seed, stamps provider headers, and the generic `capture_record` constructor. |
| `src/bin/record/fixture.rs` | Assembles a `RecordPlan` into a `RecordedFixture` (synthesizes `kernel_verdict` records, rebuilds per-provider lowered-request records from templates) and writes it atomically. |
| `src/bin/record/invoke.rs` | Extracts `ToolInvocation`s from live provider responses and wraps each in a synthesized allow `VerdictResult`. |
| `src/bin/record/credentials.rs` | Loads provider credentials from environment variables; resolves the Bedrock IAM principal via `aws sts get-caller-identity`. |
| `src/bin/record/http.rs` | `curl`-based JSON POST used for the OpenAI and Anthropic live requests. |
| `src/bin/record/{openai,anthropic,bedrock}.rs` | Live record path per provider: OpenAI and Anthropic POST to their REST APIs via `curl`; Bedrock shells to `aws bedrock-runtime converse`. Bedrock streaming is an unconditional error. |
| `src/bin/record/util.rs` | RFC 3339 timestamps, id sanitization, and SSE-text parsing into capture records. |

## Replay path

1. `load_fixture` reads one NDJSON file, parses each line as a
   `CaptureRecord`, and validates schema, non-empty/unpadded identifiers,
   the filename-bound `fixture_id`, and single-provider consistency.
2. The provider entrypoint (for example `replay_openai_fixture`) builds an
   adapter from the header and principal fields captured in the fixture's
   `upstream_request` records, backed by `MockTransport` or no transport.
3. `upstream_response` records replay through the adapter's batch lift path;
   `upstream_event` records are reassembled into SSE, NDJSON, or an event-list
   JSON array and replay through the adapter's streaming gate, which releases
   each buffered tool-call block only after a caller-supplied verdict lookup
   resolves it.
4. Reconstructed invocations and verdicts are compared to the fixture's
   `kernel_verdict` records after canonical JSON encoding; a byte mismatch,
   an unexpected invocation, or a missing one fails the replay.
5. For fixtures with a lowered-response record, the captured verdict replays
   through the adapter's lowering path and the output bytes are compared the
   same way.

## Record path

1. `record --provider <p> --scenario <s>` loads the existing fixture as a
   seed: the `capture_mode`-tagged initial request plus any lowered-request
   templates.
2. Credentials come from environment variables (Bedrock additionally shells
   to `aws sts get-caller-identity` for the IAM principal).
3. The seeded request replays against the live upstream endpoint (`curl` for
   OpenAI/Anthropic, the AWS CLI for Bedrock); the response or SSE stream is
   captured verbatim.
4. Tool invocations are extracted from the live response and wrapped in a
   synthesized `VerdictResult::Allow`; the recorder never calls a real kernel
   and cannot produce a deny record.
5. Lowered-request records are rebuilt from the seed's templates with the new
   invocation ids substituted in.
6. Records are serialized to a `.ndjson.tmp` file, then renamed over the
   original fixture (atomic replace).

## Invariants and failure modes

- Fixture identity is fail-closed: empty or whitespace-padded
  `schema`/`provider`/`fixture_id`/`invocation_id` values, a `fixture_id`
  that does not match the NDJSON filename stem, or mixed `provider` values
  within one file all reject before any replay runs.
- Every provider replay asserts an exact count match between captured
  `kernel_verdict` records and reconstructed verdicts, and between
  lowered-request records and lowered responses; a leftover or missing entry
  on either side fails closed.
- OpenAI, Anthropic, and Bedrock stream replay additionally enforce verdict
  chronology: a `kernel_verdict` record must not precede the stream event
  that completes its tool-call block (`response.output_item.done`,
  `content_block_stop`, `contentBlockStop`).
- Comparisons are RFC 8785 canonical JSON byte equality, not structural
  equality; on mismatch the assertion error reports a truncated (240-byte)
  UTF-8 preview rather than the raw bytes.
- `chio-tool-call-fabric::ProviderAdapter` defines only `lift` and `lower`;
  the batch (`lift_batch`) and streaming (`gate_sse_stream`,
  `gate_converse_stream`) entrypoints this harness calls are inherent
  methods on each concrete adapter, not part of the shared trait.
- `record` only supports OpenAI, Anthropic, and Bedrock, always synthesizes
  an allow verdict, and never exercises a deny path; deny/error fixtures for
  those three providers are hand-authored, not recorder output. The fixture
  write is atomic so a failed run cannot leave a half-written file on disk.
- `fixtures/cross_provider/manifest.toml` documents the 8-provider
  verdict-equality oracle matrix, but this crate's own
  `tests/cross_provider_equality.rs` hardcodes the same provider/fixture
  list in Rust rather than parsing the file; the two must be kept in sync by
  hand. (`chio-weights`' equivalence test does parse this manifest.)

## Dependencies

- `chio-tool-call-fabric` (non-optional): defines `ToolInvocation`,
  `VerdictResult`, `ProviderAdapter`, `ProviderError`, and the provenance and
  principal types this crate replays and asserts against.
- `chio-core` is aliased to `chio-core-types`
  (`chio-core = { package = "chio-core-types", ... }`), so `chio_core::` in
  this crate's source is the core protocol-types crate, not the `chio-core`
  facade. It supplies `canonical::canonical_json_bytes`, `Error`, `Keypair`
  (for the Anthropic conformance manifest's public key), and the
  loaded-weights digest contract re-exported from `loaded_weights.rs`.
- `chio-openai` is aliased to `chio-openai-adapter`
  (`features = ["provider-adapter"]`); `chio_openai::OpenAiAdapter` in
  source is that crate.
- One optional adapter dependency per `fixtures-*` feature:
  `chio-anthropic-tools-adapter` (+ `chio-manifest` for `ToolManifest`),
  `chio-bedrock-converse-adapter`, `chio-gemini-tools-adapter`,
  `chio-mistral-tools-adapter`, `chio-groq-tools-adapter`,
  `chio-ollama-tools-adapter`, `chio-cohere-tools-adapter`.
- `clap` (derive) drives the `record` CLI; `chrono` formats capture
  timestamps; `serde`, `serde_json`, and `thiserror` back the capture schema
  and error types throughout.
