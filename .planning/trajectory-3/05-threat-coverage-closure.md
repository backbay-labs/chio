# Milestone 05: Threat-Coverage Closure

## Lens

Security. M05 closes the three named carry-forward gaps from
trajectory-2 and reclassifies every remaining advisory threat into a
defensible state. The lens is single (threat-coverage hygiene). Work
is bounded by D14: weights_hash_spoof partial -> covered, the M06
dispatch_allow placeholder replaced with a real check, the third M06
placeholder evicted, and the eight remaining `pending` advisory
threats either flipped to `covered` or carried by an explicit
`deferred_to` reference. New threat IDs introduced by trajectory-3
M07 (mobile) and M10 (distribution) are out of scope and land under
those milestones.

## Why this is on the trajectory

**Release-gate anchor:** RELEASE_AUDIT.

trajectory-2 M05 introduced the threat-coverage table and shipped the
CI gate `scripts/check-threat-coverage.sh` load-bearing on
`spec/security/chio-threat-model.v1.json` via the workflow
`.github/workflows/threat-model-coverage.yml`. The trajectory-2
verdict closed the milestone with three rows still flagged
`partial` or `placeholder` and eight rows flagged `pending`:

- `weights_hash_spoof`: `coverage_state: pending` in the JSON,
  `coverage_state: partial` in `spec/security/coverage.yaml`. The
  M10 audit cites the gap as "loaded-weight recomputation depends on
  chio-providers exposing a recomputable digest". The kernel binding
  surface in `crates/chio-kernel/src/weights_binding.rs` accepts a
  caller-supplied `loaded_weights_hash: &str` and trusts it; nothing
  Chio-owned independently recomputes the digest. The conformance
  test stub at
  `crates/chio-conformance/tests/threats/weights_hash_spoof.rs` is
  still `unimplemented!()` with a comment naming `M05.P5.T3` as the
  owner.
- `dispatch_allow` (M06 perf-pack placeholder): the Criterion bench
  `crates/chio-kernel/benches/dispatch_allow.rs` body is
  `c.bench_function("dispatch_allow", |b| b.iter(|| black_box(0_u64)))`
  with the comment "Body fills in once the async-kernel pivot
  lands." This is a measurement-shaped lie; trajectory-2 M06 P5.T1
  audit row records it as partial-quality evidence.
- Third M06 placeholder: `dispatch_allow_dhat.rs` ships a dhat
  allocation-count probe with both budgets (`total_blocks` and
  `total_bytes`) hard-coded to `0` and the probe body
  `std::hint::black_box(0_u64)`. It is the second harness sharing
  the `dispatch_allow` name and the second placeholder; the
  trajectory-3 M05 narrative names it as the third evictable
  placeholder.

The M08 reviewer (NCC Group or Trail of Bits) cross-checks the M05
closure as one of the named third-party evidence artifacts in their
report. M05 cannot ship a credible cross-check artifact while three
placeholders and eleven pending rows remain.

## Prior-art reckoning

trajectory-2 M05 shipped:

- `spec/security/chio-threat-model.v1.json` with the
  `coverage_state` enum `{covered, partial, pending}`. trajectory-2
  D25 widened the enum from a binary covered/uncovered shape.
- `scripts/check-threat-coverage.sh` reading the JSON and gating the
  workflow `.github/workflows/threat-model-coverage.yml`. The script
  treats `partial` and `pending` as PASS unconditionally today; that
  tolerance is the load-bearing surface M05 P5 flips.
- `crates/chio-conformance/tests/threats/<id>.rs` per-threat stub
  files (`mod.rs` declares the modules; `common.rs` holds shared
  fixtures). 11 of the 17 stub files still call `unimplemented!()`.
- `docs/security/threat-coverage.md` regenerated coverage doc with a
  Partial heading.

trajectory-2 M10 shipped:

- `spec/security/coverage.yaml` (the documentation-companion
  surface) with three M10-owned threat rows: `passkey_credential_theft`
  (covered), `audience_confusion` (covered), and `weights_hash_spoof`
  (partial, with a `partial_reason` block citing the chio-providers
  hash-recompute gap).
- `crates/chio-weights/src/card.rs::weights_hash_of` which already
  computes `hex::encode(Sha256::digest(bytes))`. The helper is
  public; the gap is the absence of a recomputed loaded-weights
  digest on the provider side.

trajectory-2 M06 shipped:

- The two `dispatch_allow*.rs` placeholder benches under
  `crates/chio-kernel/benches/` and the M06 follow-up audit row
  naming "Replace the placeholder probe with the real
  dispatch/canonicalization path and report allocation-count
  reduction attributable to reduced reserialization."

What M05 changes:

- weights_hash_spoof flips partial -> covered with a recomputable
  loaded-weight digest path under `chio-provider-conformance`.
- dispatch_allow Criterion + dhat placeholders evicted; replaced
  with real wall-clock and allocation-count measurements through
  the production dispatch path.
- The eight `pending` advisory threats are reclassified: two
  (`pq_signature_downgrade`, `tee_quote_forgery`) flip to `covered`
  on existing test bodies; six receive `deferred_to` references to
  M07 / M10 / trajectory-4.
- `scripts/check-threat-coverage.sh` flips to fail-closed on
  `partial` and on `pending` lacking a `deferred_to` field.
- `spec/security/coverage.yaml` and the JSON converge; one is the
  documentation companion of the other and the M05 audit doc
  records which is the gate-read surface.

What M05 preserves:

- The threat-model JSON shape, the `coverage_state` enum, and the
  per-threat stub-file convention under
  `crates/chio-conformance/tests/threats/`.
- The `chio-threat-model.schema.json` validator.
- The cosign-attested model-card surface in `chio-weights`.

## Hard counts (measured 2026-04-30)

Reproduce with the commands in parentheses. Update the numbers if
they drift; do not silently let them drift.

- `spec/security/chio-threat-model.v1.json`: 17 threat objects
  (`python3 -c "import json; print(len(json.load(open('spec/security/chio-threat-model.v1.json'))['threats']))"`).
- `coverage_state: partial` rows in JSON: 0
  (`python3 -c "import json; d=json.load(open('spec/security/chio-threat-model.v1.json')); print(sum(1 for t in d['threats'] if t.get('coverage_state')=='partial'))"`).
- `coverage_state: placeholder` rows in JSON: 0 (the enum admits
  `{covered, partial, pending}`; `placeholder` is not a state, the
  trajectory-2 narrative used the word as shorthand for the
  dispatch_allow benches).
- `coverage_state: pending` rows in JSON: 11
  (`python3 -c "import json; d=json.load(open('spec/security/chio-threat-model.v1.json')); print(sum(1 for t in d['threats'] if t.get('coverage_state')=='pending'))"`).
- `coverage_state: covered` rows in JSON: 6 (capability_token_theft,
  kernel_impersonation, tool_server_escape, native_channel_replay,
  resource_exhaustion_dos, delegation_chain_abuse).
- `spec/security/coverage.yaml` rows: 3 (passkey_credential_theft
  covered, audience_confusion covered, weights_hash_spoof partial).
- `coverage.yaml` vs JSON divergence: 3 rows
  (`passkey_credential_theft`, `audience_confusion`,
  `weights_hash_spoof` are all `covered` or `partial` in YAML but
  `pending` in JSON). The CI gate reads JSON; YAML is documentation.
- Per-threat stub files calling `unimplemented!()`: 11 of 17
  (`grep -l 'unimplemented!' crates/chio-conformance/tests/threats/*.rs | wc -l`).
- Per-threat stub files with populated test bodies: 6 of 17
  (the six trajectory-1 covered IDs).
- `crates/chio-kernel/benches/dispatch_allow*.rs`: 2 placeholder
  benches (Criterion + dhat) with a third sibling `dispatch_deny.rs`
  that is also placeholder-shaped but is OUT of M05 scope per D14.
- `chio-providers` crate existence: NO
  (`grep -l '^name = "chio-providers"' crates/*/Cargo.toml` returns
  nothing). M05 does not create it; the LoadedWeights trait lands
  under `chio-provider-conformance`.

The ten numbers above are the measurable starting points. The
audit doc Section 2 reproduces them at P0 wave-opener merge.

## Workspace dependency state

No new workspace-level pins. M05 reuses:

- `sha2` (already pinned via `chio-weights`); the LoadedWeights
  recompute path uses the existing `Sha256` constructor.
- `serde`, `serde_json` (already pinned); coverage.yaml writer +
  JSON gate reader.
- `criterion`, `dhat` (already pinned); dispatch_allow real-check
  measurements ride the existing harness.
- `thiserror` (already pinned); the new `LoadedWeightsUnavailable`
  error variant uses it.

The LoadedWeights trait surface lands in `chio-provider-conformance`
(existing crate); no new crate boundary is introduced. This honors
D14 bounded-scope per research finding §1.

## Scope

### In

- `weights_hash_spoof`: partial -> covered. New `LoadedWeights`
  trait surface in `chio-provider-conformance`. Per-adapter
  implementations or explicit `LoadedWeightsUnavailable` returns for
  pure-API providers. Kernel binding at
  `crates/chio-kernel/src/weights_binding.rs` calls the recompute
  path and refuses fail-closed when the recomputed digest disagrees
  with the cosign-attested card or when the provider returns
  `LoadedWeightsUnavailable`. Conformance test body at
  `crates/chio-conformance/tests/threats/weights_hash_spoof.rs`
  asserts positive round-trip, spoof rejection, and unavailable
  rejection. JSON state flips `pending` -> `covered`; YAML row flips
  `partial` -> `covered`.
- `dispatch_allow` (Criterion bench): placeholder evicted. The bench
  at `crates/chio-kernel/benches/dispatch_allow.rs` drives a real
  `DispatchRequest` through `ChioKernel::evaluate_capability` (or
  the post-async-pivot equivalent) and reports a wall-clock median
  + 95% CI on the reference runner.
- `dispatch_allow_dhat` (third M06 placeholder): allocation-count
  probe replaced. The bench at
  `crates/chio-kernel/benches/dispatch_allow_dhat.rs` reports
  `total_blocks` / `total_bytes` against a measured budget (not
  `0`), recorded in the audit doc Section 3 closure log.
- Path-of-record decision for dispatch_allow: P0 reconciles the
  freeze (`crates/chio-attest-verify/src/dispatch_allow.rs`) against
  the tree (`crates/chio-kernel/benches/dispatch_allow*.rs`). The
  recommended outcome is to amend the freeze in `freezes.yml` to
  point at the chio-kernel benches (matching the live tree); the
  alternative is to create the chio-attest-verify file and move the
  benches there. P0.T1 records the decision.
- Reclassification of the eight remaining `pending` threats:
  - `pq_signature_downgrade` and `tee_quote_forgery`: flip to
    `covered`. Both already carry partially populated
    `covered_by_tests` arrays; M05 fills the test bodies and flips
    the state.
  - `ssrf_via_http_substrate`, `pii_phi_exposure`,
    `agent_velocity_abuse`, `cumulative_data_exfiltration`,
    `behavioral_sequence_attack`, `wasm_guard_resource_exhaustion`,
    `passkey_credential_theft`, `audience_confusion`: receive
    `deferred_to` references to M07 / M10 / trajectory-4 milestones.
    `passkey_credential_theft` and `audience_confusion` flip to
    `covered` per their existing M10 closure; the YAML / JSON
    reconciliation in P0 names which.
- CI gate flip: `scripts/check-threat-coverage.sh` edits to fail
  closed on `coverage_state: partial` and on
  `coverage_state: pending` lacking a `deferred_to` field. Unit
  tests for the script's state matrix.
- Audit doc closure: `.planning/trajectory-3/audits/M05-threat-coverage.md`
  Section 3 closure log filled row-by-row; Section 4 records the
  CI run URL of the post-flip gate and the M08 reviewer cross-ref
  hook.
- Doc regeneration: `docs/security/threat-coverage.md` rewritten so
  the Partial heading is empty.

### Out (and why)

- New threat IDs from M07 (mobile) or M10 (distribution). D14 caps
  scope at the three named gaps + classification; new mobile or
  distribution surfaces ship their own coverage rows under those
  milestones.
- Widening the `coverage_state` enum further. trajectory-2 D25
  already widened it; further enum changes are out of scope.
- Crate consolidation or new crate creation. Per D14 and the
  research finding §1, the LoadedWeights trait lands under the
  existing `chio-provider-conformance` rather than a new
  `chio-providers` crate. The trajectory-2 narrative was
  aspirational; the chio-providers crate does not exist and creating
  it widens scope past D14.
- Replacing `chio-policy` evaluator semantics or the
  `chio-attest-verify` Sigstore single-source-of-truth. M05
  consumes those surfaces; trajectory-1 M06 owns them.
- Side-channel hardening (dudect timing, miri, shuttle). Out of
  M05 scope; trajectory-1 M02/M05 own those surfaces.

## Phases

### P0: Audit baseline + threat-coverage row count snapshot + coverage.yaml/JSON reconciliation (S, 1.0 day, 1 ticket)

P0 is a non-trust-boundary wave-opener: it fills the audit doc Section
2 with hard counts, enumerates the coverage.yaml-vs-JSON divergence
explicitly, decides the dispatch_allow path-of-record (freeze amend
vs file move), and emits the freeze amendment if needed. P0 runs
while M04 is still mid-freeze on `chio-attest-verify/src/**`.

- M05.P0.T1 - Open the M05 audit doc; populate Section 2 with the
  ten hard counts above; enumerate the three coverage.yaml-vs-JSON
  divergent rows; emit the freeze-amendment PR for
  `m05-threat-coverage-pivot.path_globs` (point at
  `crates/chio-kernel/benches/dispatch_allow*.rs` instead of
  `crates/chio-attest-verify/src/dispatch_allow.rs`); enumerate
  every consumer of `spec/security/coverage.yaml` (grep across
  `.planning/trajectory-2/audits/`, `.planning/trajectory-3/audits/`,
  and `docs/security/`).

### P1: weights_hash_spoof partial -> covered (M, 4.0 days, 3 tickets)

P1 ships the LoadedWeights trait surface, per-adapter implementations
or unavailable returns, the kernel binding refusal wiring, and the
conformance test body. It runs in parallel with P0 close because
the touched paths (`chio-provider-conformance`, `chio-weights`,
`chio-kernel`, `chio-conformance`) are not under the M04 freeze.

- M05.P1.T1 - LoadedWeights trait surface in
  `chio-provider-conformance`. Add the trait, the
  `LoadedWeightsUnavailable` error type, and a chunked-digest
  default impl that adapters can override with a streaming reader.
  Wire kernel binding refusal at
  `crates/chio-kernel/src/weights_binding.rs` to call the recompute
  path and refuse fail-closed on digest mismatch or on
  `LoadedWeightsUnavailable`.
- M05.P1.T2 - Per-adapter LoadedWeights implementations. Pure-API
  providers (Anthropic, Bedrock, Cohere, Gemini, Groq, Mistral)
  return `LoadedWeightsUnavailable`. Local providers (Ollama, the
  test fixture used by the conformance harness) return a real
  recomputed digest. MCP and A2A adapters return
  `LoadedWeightsUnavailable` (no native loaded-weights surface).
- M05.P1.T3 - Conformance test body at
  `crates/chio-conformance/tests/threats/weights_hash_spoof.rs`:
  positive round-trip (digest matches card), spoof rejection
  (digest mismatch), unavailable rejection (pure-API provider).
  JSON `coverage_state` flips `pending` -> `covered`; coveredBy
  array populated. `coverage.yaml` row flips `partial` -> `covered`.

### P2: dispatch_allow real check (M, 3.5 days, 2 tickets)

P2 starts only after M04.P5.T5 closes (the `m04-m05-attest-verify-coupling`
freeze). The path-of-record from P0.T1 dictates whether the work
edits `crates/chio-kernel/benches/` directly (recommended) or moves
the benches under `chio-attest-verify`. The narrative below assumes
the recommended outcome; if P0 picks file-move, T1 grows by ~0.5d.

- M05.P2.T1 - `DispatchRequest` fixture + production dispatch path
  thread-through. Construct a representative request using existing
  Chio fixtures; call `ChioKernel::evaluate_capability` (or its
  post-async-pivot successor) end-to-end. Record the reference
  runner contract (4-core Linux, warm cache, in-memory stores) and
  document it in
  `crates/chio-kernel/benches/README.md` per the M06 follow-up.
- M05.P2.T2 - Replace the Criterion `0_u64` probe in
  `crates/chio-kernel/benches/dispatch_allow.rs` with a real
  measurement of the dispatch-allow path; record the median + 95%
  CI on the reference runner. Update the M06 follow-up audit row
  with the numbers.

### P3: third M06 placeholder evicted (S, 2.0 days, 1 ticket)

P3 closes the dhat probe. Per research §3 the third placeholder is
the dhat sibling of the Criterion bench. If P0/P2 uncover a fourth
distinct placeholder (e.g. an unbenched stub in
`chio-attest-verify`), the M05 audit doc records it under Section 3
Closure Log under a `<m06 placeholder #4>` row; P3 does not invent
work to evict.

- M05.P3.T1 - Replace the dhat probe in
  `crates/chio-kernel/benches/dispatch_allow_dhat.rs` with a
  measurement against a real `DispatchRequest`. Replace the
  `0_u64` budgets with measured numbers from the reference runner
  (D08-style honest threshold rule applies: record the real number
  even if it exceeds an internal expectation). Record the budget in
  the audit doc Section 3.

### P4: coverage gate flip + advisory threats classified (M, 4.0 days, 3 tickets)

P4 lands the gate flip and the eight remaining advisory
reclassifications atomically per the freeze
`m05-threat-coverage-pivot`. The flip and the source edits are one
trust-boundary closure; partial landing leaves the gate
inconsistent.

- M05.P4.T1 - Flip `pq_signature_downgrade` and
  `tee_quote_forgery` from `pending` to `covered`. Both already
  have populated `covered_by_tests` arrays; populate the test
  bodies at
  `crates/chio-conformance/tests/threats/pq_signature_downgrade.rs`
  and `.../tee_quote_forgery.rs` and flip the JSON state.
- M05.P4.T2 - Reclassify the six remaining advisory pending
  threats. `passkey_credential_theft` and `audience_confusion` flip
  to `covered` per their existing M10 closure (per the YAML / JSON
  reconciliation P0 surfaced). `ssrf_via_http_substrate`,
  `pii_phi_exposure`, `agent_velocity_abuse`,
  `cumulative_data_exfiltration`, `behavioral_sequence_attack`,
  `wasm_guard_resource_exhaustion` receive `deferred_to`
  references to M07 / M10 / trajectory-4 (the specific
  ticket/milestone is recorded per row).
- M05.P4.T3 - Edit `scripts/check-threat-coverage.sh` to fail
  closed on `coverage_state: partial` and on
  `coverage_state: pending` lacking a `deferred_to` field. Add a
  unit test under `scripts/tests/check-threat-coverage.test.sh`
  that exercises the four state-matrix cells (covered, partial,
  pending-with-deferred_to, pending-without-deferred_to). The
  workflow `.github/workflows/threat-model-coverage.yml` keeps the
  same script entry; only the script's branch logic flips.

### P5: closeout audit + M08 reviewer-handoff (S, 1.5 days, 2 tickets)

P5 closes the audit doc and emits the M08 cross-ref hook. The CI
run of the post-flip gate (from P4.T3) is the load-bearing evidence
the M08 reviewer cites.

- M05.P5.T1 - Regenerate `docs/security/threat-coverage.md` so the
  Partial heading is empty. Verify zero `partial` and zero
  `pending`-without-`deferred_to` rows in the JSON; verify the
  workflow run is green.
- M05.P5.T2 - Close `.planning/trajectory-3/audits/M05-threat-coverage.md`
  Section 4: paste the CI run URL of the post-flip gate; emit the
  M08 reviewer cross-ref hook (a markdown anchor the M08 audit doc
  cites in its evidence-pack section); update the closure
  attestations row.

## Cross-milestone interactions

- `m04-m05-attest-verify-coupling` freeze (in `freezes.yml`):
  M04.P3 close (mutation-gate flip on chio-attest-verify) is a
  precondition for M05.P2 opening dispatch_allow work. The freeze
  start_trigger is `M04.P3.T1`; end_trigger is `M04.P5.T5`. P0 and
  P1 of M05 may run while the M04 freeze is active because their
  paths do not overlap. P2 / P3 / P4 wait for the M04 freeze to
  close.
- `m05-threat-coverage-pivot` freeze (in `freezes.yml`): M05's own
  freeze locks `spec/security/chio-threat-model.v1.json`,
  `crates/chio-conformance/tests/threats/**`,
  `crates/chio-attest-verify/src/policy.rs`, and (per P0.T1
  amendment) `crates/chio-kernel/benches/dispatch_allow*.rs` plus
  `docs/security/threat-coverage.md` for P1-P4. The amendment to
  the path_globs is the P0.T1 deliverable; without it the live
  benches sit outside the freeze.
- M03 (Hosted CI Truth + Reproducible Builds): the post-flip CI
  run that M05.P4.T3 produces relies on the M03-restored hosted
  runner lane. M05.P4.T3 lands after M03 P3.T1 closes the hosted
  CI restoration; the M05 audit doc cites the M03 audit doc for
  the runner configuration.
- M04 (Mutation + Verdict Matrix Promotion): the dispatch_allow
  real check lands after the M04 mutation-gate flip on
  `chio-attest-verify`. M04 P5.T5 close releases the
  `m04-m05-attest-verify-coupling` freeze.
- M08 (Independent Crypto + Protocol Review): cross-checks the M05
  closure. The M05 audit doc emits a stable cross-ref hook
  (markdown anchor + the post-flip CI run URL). M08 does not re-run
  the gate; they confirm it exists and that the artifacts they
  reviewed match what the gate attested.
- trajectory-2 M10: consumed `coverage.yaml` as the load-bearing
  surface for the three M10 threat rows (passkey, audience,
  weights). M05 P0 enumerates the M10 audit's references to
  coverage.yaml; P4.T2 updates the YAML row at the same merge as
  the JSON flip to keep the two surfaces in sync.

## Risks and mitigations

1. **chio-providers crate creation widens M05 scope past D14.** The
   trajectory-2 narrative names a `chio-providers` crate; the crate
   does not exist. Creating it would add a new crate boundary and
   force PRs across every adapter. Mitigation: M05 implements the
   `LoadedWeights` trait under the existing
   `chio-provider-conformance` crate (research §1 option 1). The
   `freezes.yml` rationale and the M05 audit doc record the
   decision so trajectory-4 can revisit the crate boundary without
   re-litigating M05 scope.
2. **dispatch_allow path mismatch between freeze and tree.** The
   freeze names `crates/chio-attest-verify/src/dispatch_allow.rs`
   but the live placeholder lives in
   `crates/chio-kernel/benches/dispatch_allow*.rs`. Mitigation:
   P0.T1 emits a freeze amendment pointing at the chio-kernel
   benches. If reviewer prefers the file-move, P2.T1 grows by ~0.5d
   to host the move. Either way the load-bearing path is recorded
   in the M05 audit doc Section 3.
3. **dispatch_allow real check turns up a perf regression.**
   Replacing the `0_u64` probe with the real path raises the
   allocation budget from 0 to a real number. The budget assertion
   in `dispatch_allow_dhat.rs` will need to change. If the real
   number exceeds an internal expectation, D08-style honest
   threshold rule applies: M05 records the real number and does
   not slip M08 to chase a tighter budget.
4. **Third M06 placeholder may not be cleanly closable.** If P0 / P2
   uncover that the third placeholder is not a well-scoped artifact
   but a posture (e.g. the gate's tolerance of `partial` itself),
   P3 collapses into P5 and the M05 audit doc records the collapse.
   Do not invent a placeholder to evict.
5. **Coverage.yaml vs JSON divergence has downstream consumers.**
   `coverage.yaml` is referenced by the trajectory-2 M10 audit and
   by the M05.P5.T1 doc-generator wiring. Mitigation: P0.T1
   enumerates consumers via grep across `.planning/audits/`. P4.T2
   updates YAML and JSON in one merge to keep them coherent.
6. **Advisory-threat reclassification surfaces hidden test debt.**
   Eight pending threats need test bodies or `deferred_to` refs.
   For threats whose mitigations are explicitly marked `planned`
   (e.g. ssrf_via_http_substrate, pii_phi_exposure), `deferred_to`
   is honest; populating the test body would be sandbagging.
   Mitigation: P4.T2 ticket spec distinguishes "covered today" from
   "deferred with reference"; the M05 audit doc records the
   per-row decision.
7. **Freeze double-locking on `chio-attest-verify/src/`.** M04 and
   M05 both freeze the directory. Mitigation: the
   `m04-m05-attest-verify-coupling` freeze sequences the handoff;
   M04.P5.T5 merge closes both the M04 freeze and the coupling
   freeze before M05.P2 opens. The orchestrator's
   `m{nn}-freeze-guard` checks accept the handoff atomically.

## Success criteria

- `spec/security/chio-threat-model.v1.json` carries zero
  `coverage_state: partial` rows and zero `coverage_state: pending`
  rows lacking a `deferred_to` field. The 17 threats land in either
  `covered` (with populated test bodies) or `pending` with explicit
  `deferred_to`.
- `crates/chio-conformance/tests/threats/<id>.rs` test bodies are
  populated for every `covered` threat; no file calls
  `unimplemented!()` for a `covered` threat.
- `scripts/check-threat-coverage.sh` fails closed on `partial` and
  on `pending` lacking `deferred_to`. The unit test under
  `scripts/tests/check-threat-coverage.test.sh` covers the four
  state-matrix cells.
- `crates/chio-kernel/benches/dispatch_allow.rs` and
  `dispatch_allow_dhat.rs` run real measurements through the
  production dispatch path; budgets and CI thresholds are recorded
  in the M05 audit doc Section 3.
- `.planning/trajectory-3/audits/M05-threat-coverage.md` Section 2
  hard counts and Section 3 closure log are filled row-by-row;
  Section 4 cites the post-flip CI run URL and emits the M08
  reviewer cross-ref hook.
- `docs/security/threat-coverage.md` regenerated; Partial heading
  is empty.
- The M08 reviewer cross-checks closure in their report
  (M08 audit doc references the M05 audit doc + the post-flip CI
  run URL).
