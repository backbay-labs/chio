# Empirical Chapter Strengthening

The v0 evaluation chapter assumes a "deployed admission kernel" producing receipts whose sensor-state attestation is uniformly faithful. The clawdstrike substrate carries the attestation field on every receipt, but the field's provenance varies sharply by emission site. The strengthening below cuts the chapter to what the code actually supports today and proposes measurements that survive that cut.

## Audit of what's measurable today

### Per-field provenance of `EndpointSensorState`

The struct lives at `clawdstrike/crates/libs/clawdstrike-policy-event/src/edr.rs:2175` (provider record) and `:2191` (sensor state container). Each `EndpointProviderState` field's actual provenance, traced through `endpoint_sensor_state_from_macos_host` at `apps/agent/src-tauri/src/api_server.rs:24360`:

- `provider_id`, `provider_kind`: structurally enumerated for three providers ("agent-api", "macos.endpoint_security", "macos.network_extension"). Real.
- `installed`, `active`: derived from `host_status.install_state` and `provider.runtime` (api_server.rs:24906-24917). Real for the NE provider, real-but-stubbed for the ES provider (see below).
- `healthy`, `degraded`, `degradation_reasons`: derived from runtime state, install state, drop and miss counts, full-disk-access, last_error (api_server.rs:24925-24962). Real wherever the upstream provider sample is real.
- `dropped_event_count`, `deadline_miss_count`: pulled from `provider.counters` (api_server.rs:24918-24923). Real if the provider emits them.
- `full_disk_access`: provider-kind-specific (api_server.rs:24924). Real for ES (when the helper runs); None for NE and AgentApi.
- `last_seen`: from provider sample or set to now() if active (api_server.rs:24975). Coarse but real.

The verifier-side discipline is real: `require_provider_degradation_consistency` (edr.rs:14753) rejects any receipt where the degradation signals contradict the `degraded` flag; `require_sensor_state_evidence` (edr.rs:12977) requires every counted field (provider_count, healthy_count, degraded_count, provider_ids, sensor_state_hash) to match an evidence-hash row, and the `for_sensor_state` rule_id assertion (edr.rs:12992) is fail-closed.

The single most consequential observation: the AgentApi provider record is hard-coded `installed: true, active: true, healthy: true, degraded: false` at api_server.rs:24365-24377. This is a structural constant, not a measurement. The corpus's "healthy AgentApi" cells are therefore non-evidence; they should not be claimed as attested.

### Emission site asymmetry

`endpoint_sensor_state_from_macos_host` is called at exactly six sites (api_server.rs:9572, 9790, 9927, 10621, 18201, 22763) covering response-execution receipts and the sensor-state receipt itself. Every other receipt emitter uses the placeholder `EndpointSensorState::single_active_agent("agent-api")` (single record, AgentApi provider, healthy, no degradation), called from 13 emitter functions (api_server.rs:22511, 22558, 22582, 22616, 22645, 22656, 22667, 22680, 22701, 22722, and three more) covering detection, policy_decision, telemetry_privacy, graph_slice, simulation, policy_event_replay, policy_event_impact, deception_materialization, deception_cleanup, deception_rotation, plan, rollback, and acknowledgement receipts.

Implication: receipts in the deployed substrate carry one of two sensor-state populations. Type A (response-execution and the sensor-state receipt itself) carries a snapshot of the macOS host with the ES and NE providers reflected. Type B (everything else) carries a synthetic single-provider attestation. The §6 chapter cannot credibly cite "every signed receipt carries a sensor-state attestation reflecting kernel posture"; the honest claim is "the response-execution receipt carries a host snapshot; other families carry a structurally valid but placeholder attestation that the verifier accepts under the current consistency rules."

### Existing fixtures and tests that exercise sensor attestation

Three tests in `edr.rs` produce real attestations across realistic provider populations:

- `endpoint_sensor_state_receipt_binds_provider_health` (edr.rs:17468). Two-provider attestation (healthy AgentApi, degraded ES with `dropped_event_count: 2`, `deadline_miss_count: 1`, missing FDA). Signs, verifies, mutates `providerCount` / `providerIds` / `activeProviderCount` evidence rows and confirms each mutation is rejected by `validate()`.
- `endpoint_sensor_state_receipt_rejects_duplicate_provider_ids` (edr.rs:17670). Confirms duplicate provider id is rejected.
- `endpoint_provider_degradation_receipt_requires_degraded_provider` (edr.rs:17713). Builds a single degraded ES provider, signs the degradation receipt, mutates `providerId` / `degradationReasons` / `fullDiskAccess` / finding-id, confirms each is rejected.

Two `api_server.rs` tests exercise the host-snapshot path:

- `endpoint_sensor_state_marks_unknown_macos_providers_degraded` (api_server.rs:31492). Empty `CombinedSystemExtensionStatus` produces an ES provider with installed=false, active=false, healthy=false, degraded=true, and `provider runtime unknown` reason.
- `endpoint_sensor_state_marks_loss_deadline_and_fda_evidence_degraded` (api_server.rs:31511). Crafted host status with drop=2, miss=1, FDA evidence; the resulting ES provider record reflects all three degradation signals.

These five tests are the entire evidentiary base for the empirical chapter. There is no chio fixture file naming sensor attestation, no replay-corpus member exercising it, and no Criterion bench against any of the receipt-signing or sensor-state validation paths. The parent paper's bench scripts at `papers/programmable-sovereignty/bench/run-*.sh` measure chio kernel paths, not clawdstrike sensor attestation; they are reusable as a template but not as a tool.

### Cost overheads

No latency measurement exists today. Producing the attestation calls `endpoint_sensor_state_content_hash` (edr.rs:2656) plus a handful of evidence-row hashes; expected O(microseconds). Verifier-side `require_sensor_state_evidence` re-runs the same hash plus five hash-equality checks. Storage per receipt: ~600-900 JSON bytes for a three-provider attestation after canonicalization. None of this is measured.

## Proposed measurements

### Measurement 1: Verifier-side admission decidability on a witness pair

- Metric: For two attestation populations sharing identical receipt body bytes, does the verifier discharge `validate()` plus `requiredSetCovered`-equivalent logic to opposite verdicts on every pair?
- Script: New test `sensor_grounded_admission_distinguishes_witness_pair` added to `crates/libs/clawdstrike-policy-event/src/edr.rs`, modeled on `endpoint_sensor_state_receipt_binds_provider_health` (edr.rs:17468). Constructs a healthy two-provider attestation, a degraded two-provider attestation with ES marked degraded, both sharing a `ResponseExecution` body. Asserts the first satisfies a required-set predicate (all providers healthy) and the second does not.
- Inputs: Self-contained, no external fixture needed.
- Expected: Two-attestation pair separating cleanly on the predicate.
- Pass/fail: A pair exists in the test suite that produces distinct verdicts under a constitution-style required-set check, with both verdicts derivable from the attestation alone.
- Cost: One day.
- Reader takeaway: The headline existence claim is exhibited at the binary level, not just the type level.

### Measurement 2: Attestation-population coverage across the receipt-family taxonomy

- Metric: For each `EndpointDecisionReceiptFamily`, which emitter function produces it, and what sensor-state population (real-host vs `single_active_agent`) does it carry?
- Script: New shell script `papers/sensor-grounded-admission/bench/run-attestation-coverage.sh`. Greps `apps/agent/src-tauri/src/api_server.rs` for the emitter functions, tags each as host-snapshot or placeholder, emits a LaTeX-includable table.
- Inputs: The api_server source tree at the build's `CHIO_SOURCE`.
- Expected: Two families (response-execution, sensor-state) tagged host-snapshot; the remaining 11 tagged placeholder.
- Pass/fail: Table prints under thirteen rows, each tagged consistently with the per-emitter audit above.
- Cost: One day.
- Reader takeaway: The substrate distinguishes "attestation-bearing" from "attestation-faithful". The paper carries this honestly rather than claiming uniform faithfulness.

### Measurement 3: Validate-side rejection rate under attestation mutation

- Metric: For each of the six evidence rows the validator hash-binds (`providerCount`, `activeProviderCount`, `healthyProviderCount`, `degradedProviderCount`, `providerIds`, `sensorStateHash`), what fraction of single-row mutations does `validate()` reject?
- Script: Extend `edr.rs` test `endpoint_sensor_state_receipt_binds_provider_health` into a parameterized property test (using `proptest` if already in the workspace, otherwise hand-rolled enumeration). Mutate each evidence row in turn; assert `validate()` returns `Err`.
- Inputs: The existing keypair seed `[14u8; 32]`; the two-provider attestation; rotation over six rows.
- Expected: 6/6 rejection. The current test asserts 3 mutations; the proposal extends to all six.
- Pass/fail: 6/6 mutations rejected by `validate()` with a string the test can substring-match.
- Cost: One day.
- Reader takeaway: The verifier-side integrity check is exhaustive on the evidence surface that the constitution-required-set predicate would consult.

### Measurement 4: Canonical-JSON subject-digest distinction across attestation populations

- Metric: For pairs of receipts with identical body bytes but distinct attestations, do their canonical-JSON subject digests differ?
- Script: New test `sensor_attestation_distinguishes_subject_digest` in `edr.rs`. Build a receipt with attestation A and the same receipt with attestation B; canonicalize via the existing `hush_core::canonicalize_json` (api_server.rs:71) path that signs the receipt; compute the subject digest under both; assert inequality. Conversely, identical body + identical attestation yields identical digest.
- Inputs: Same two-attestation pair as Measurement 1.
- Expected: Distinct digests under distinct attestations, identical under identical.
- Pass/fail: A test asserts both halves and they pass.
- Cost: One day.
- Reader takeaway: The §6 subject-digest-discipline paragraph is grounded in a passing test, not a claim about canonicalization.

### Measurement 5: Sensor-state attestation production cost

- Metric: Latency p50/p99 to construct, sign, and validate a sensor-state attestation on a baseline machine (MacBook Pro M1 Max, matching the parent paper's bench bar).
- Script: New Criterion bench `crates/libs/clawdstrike-policy-event/benches/sensor_attestation.rs` plus a `papers/sensor-grounded-admission/bench/run-sensor-attestation.sh` wrapper that mirrors `papers/programmable-sovereignty/bench/run-dispatch-allow.sh`. Three benchmarks: build-attestation, sign-attestation, validate-attestation, each on a three-provider input.
- Inputs: A canned `EndpointSensorState` fixture, a fixed keypair, a fixed policy snapshot.
- Expected: build under 10us, sign 50-200us (Ed25519 over the canonical JSON), validate 20-100us (the validator re-hashes evidence rows).
- Pass/fail: The bench produces a number per stage and the totals are within an order of magnitude of the parent paper's dispatch numbers.
- Cost: Two to three days, including landing the Criterion bench in the clawdstrike workspace (which currently has none).
- Reader takeaway: Sensor attestation is not free, but the cost is comparable to one Ed25519 signature and a small canonicalization, not a separate enforcement path.

### Measurement 6: Attestation byte size in canonical encoding

- Metric: Median canonical-JSON byte length of the `sensor_state` field for a real three-provider attestation; same for a placeholder-only attestation.
- Script: Add a small Rust binary or test under `crates/libs/clawdstrike-policy-event/tests/` that serializes both populations through `hush_core::canonicalize_json` and prints the byte count and the storage delta over a placeholder.
- Inputs: The same two attestations.
- Expected: 200-400 bytes for placeholder, 600-1200 bytes for a three-provider real attestation; growth is roughly linear in provider count.
- Pass/fail: A reported byte count for each population, with the delta within a factor of three of the order-of-magnitude estimate.
- Cost: One day.
- Reader takeaway: The receipt ledger pays bounded per-receipt storage for attestation; the absolute cost is small enough that an opt-out optimization is not warranted.

## What this evaluation cannot promise

- A measurement over a multi-month deployment corpus. None exists; v0's "multi-month window" is aspirational. The proposal replaces it with substrate-property results on a tagged revision.
- A pairing of body-identical receipts produced under live attestation drift. Placeholder paths dominate the families likely to produce body collisions; host-snapshot paths produce bodies that rarely collide. The proposal substitutes a constructed pair in a test for an observed pair in a corpus.
- A false-attestation rate. The substrate has no out-of-band auditor; the §6 chapter already declines to report this, and the proposal endorses the decline.
- Any claim resting on the ES extension. The Swift monitor at `apps/agent/src-tauri/macos/system-extension/endpoint-security/Sources/EndpointSecurityExtension/Monitor.swift` does not call `es_new_client` or `es_subscribe`; it is an in-memory recorder consuming synthetic events. The proposal phrases every ES-touching measurement as a verifier-side property, not an enforcement-side rate.

The two subsystems whose attestation reflects real state are the NE provider (the egress policy reload path at api_server.rs:11921 is real) and the package-manager hooks. The bench and tests should call these out rather than aggregating them with the ES placeholder.

## A credible Table 2 for the chapter

| Metric                                  | Script                                  | Value (target)         | Status     |
|-----------------------------------------|-----------------------------------------|------------------------|------------|
| Witness pair: distinct verdicts          | `cargo test sensor_grounded_admission_distinguishes_witness_pair` | passes | measured |
| Attestation-population coverage          | `bench/run-attestation-coverage.sh` | 2 host-snapshot, 11 placeholder | measured |
| Validate-side mutation rejection          | `cargo test -p clawdstrike-policy-event -- sensor_state` | 6 of 6 rows | measured |
| Subject-digest distinction               | `cargo test sensor_attestation_distinguishes_subject_digest` | passes | measured |
| Build, sign, validate latency p50/p99    | `bench/run-sensor-attestation.sh` | bench output | measured |
| Canonical attestation byte size          | `cargo test -p clawdstrike-policy-event -- sensor_attestation_byte_size` | placeholder vs real | measured |
| Deployment-corpus partition-contingency rate | (none) | unreported | withheld |
| False-attestation rate                    | (none) | unreported | withheld |

Two withheld rows are explicit and named, matching the parent paper's discipline of marking rather than estimating.

## Sequencing

Measurements 1, 2, 3, 4, and 6 are each one day and independent. They can land in a single week without blocking on any new infrastructure. Measurement 5 requires landing a Criterion bench harness in the clawdstrike workspace; expect two to three additional days for the harness plus one day for the bench script and LaTeX output wiring.

Total time-to-evaluable-chapter on the proposed scope: under two weeks of focused work, no executor or scheduler shipping required. The chapter is credibly fillable at the stated theorem strength under the proposed cuts; the original v0 prose about a deployment corpus must be replaced with substrate-property language and the eight-row table above.
