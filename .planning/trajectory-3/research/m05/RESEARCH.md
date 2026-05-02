# M05 Threat-Coverage Closure: Research

Research baseline for trajectory-3 M05. Anchors: D14 (closure scope
bounded), freeze `m05-threat-coverage-pivot`, freeze
`m04-m05-attest-verify-coupling`, RELEASE_AUDIT release gate.

Snapshot date: 2026-04-30. Worktree:
`.worktrees/trajectory-3/`.

## weights_hash_spoof gap analysis (chio-providers digest)

### Why it is partial today

Three artifacts disagree about the current state and the disagreement
itself is part of the gap:

1. `spec/security/coverage.yaml` records `weights_hash_spoof` as
   `coverage_state: partial`, owned by M10, closed by M10.P4.T5,
   `partial_reason` cites "loaded-weight recomputation depends on
   chio-providers exposing a recomputable digest".
2. `spec/security/chio-threat-model.v1.json` records the same threat
   ID as `coverage_state: pending` (no `coveredBy` array, no
   `covered_by_tests` array). The JSON is the source the CI gate
   reads.
3. `crates/chio-conformance/tests/threats/weights_hash_spoof.rs`
   still calls `unimplemented!()` with a comment naming
   `M05.P5.T3` as the owner that must populate the body.

The threat-coverage CI gate (`scripts/check-threat-coverage.sh`)
treats the JSON as source of truth and accepts both `pending` and
`partial` as PASS. Coverage.yaml is a documentation companion. The
hard gap M05 must close is: (a) the JSON state, (b) the test body
under `crates/chio-conformance/tests/threats/weights_hash_spoof.rs`,
and (c) a recomputable loaded-weight digest that the test body can
exercise without trusting a caller-supplied hash.

### What "loaded-weight recomputation" means today

`crates/chio-weights/src/card.rs::weights_hash_of` already computes
`hex::encode(Sha256::digest(bytes))` over a byte slice; the helper is
public and the kernel binding refusal calls it. The gap is upstream:

`crates/chio-kernel/src/weights_binding.rs` defines

```rust
pub struct WeightsBindingRequest<'a> {
    pub loaded_weights_hash: &'a str,
    ...
}
```

and `evaluate_weights_binding` checks
`card.weights_hash == request.loaded_weights_hash`. The string is
caller-supplied. A malicious provider can pass any hash that matches
the cosign-signed model card; the card itself is honest, but the
"loaded weights" side is not independently recomputed by a Chio-owned
surface. The trajectory-2 M10 audit flags this gap and parks closure
on a "chio-providers hash-recompute" landing.

### Where the recomputable digest must live

The crate `chio-providers` does NOT exist in the workspace. The
trajectory-2 narrative is aspirational. The provider surface today is
spread across per-vendor adapter crates:

- `chio-anthropic-tools-adapter`
- `chio-bedrock-converse-adapter`
- `chio-cohere-tools-adapter`
- `chio-gemini-tools-adapter`
- `chio-groq-tools-adapter`
- `chio-mistral-tools-adapter`
- `chio-ollama-tools-adapter`
- `chio-mcp-adapter`
- `chio-a2a-adapter`

The shared substrate is `chio-provider-conformance` (replay harness
for fixtures, no live binding surface). For M05's purposes the fix
path is the smallest of three options:

1. Extend `chio-provider-conformance` with a `LoadedWeights` trait
   that returns either a streaming reader or a chunked digest, then
   use that surface in the kernel binding refusal path. Adapters
   implement it per-provider; pure-API providers (Anthropic, OpenAI,
   Bedrock) cannot expose loaded weights and explicitly return a
   typed `LoadedWeightsUnavailable` error which the kernel rejects
   fail-closed.
2. Add a small `chio-providers` crate that owns the
   `LoadedWeightsDigest` trait and a `Recompute` adapter. Adapter
   crates depend on it. This matches the trajectory-2 narrative name
   but adds a new crate (D14 wants bounded scope; review with PL).
3. Inline the trait under `chio-weights` (no new crate). Adapters
   gain a dev-dep on `chio-weights` only when they implement loaded
   weights.

Recommended path for the IMPLEMENT phase: option 1. Reuses an
existing crate, no new crate boundary, satisfies D14 bounded-scope.

### Test-body shape

The `weights_hash_spoof.rs` test body asserts that:

- Provider claims `loaded_weights_hash = X` while the recomputed
  loaded weights hash to `Y != X`. Kernel binding refuses with the
  documented error code.
- Pure-API providers explicitly return `LoadedWeightsUnavailable`.
  Kernel binding refuses fail-closed.
- A correct round-trip succeeds (positive case as a guard against
  always-fail bugs).

## dispatch_allow real-check design

### What is in tree today

Two placeholder benches under `crates/chio-kernel/benches/`:

- `dispatch_allow.rs`: a Criterion bench whose body is
  `c.bench_function("dispatch_allow", |b| b.iter(|| black_box(0_u64)))`.
  Comment line 2: "Body fills in once the async-kernel pivot lands."
- `dispatch_allow_dhat.rs`: a dhat allocation-count bench whose
  probe is `std::hint::black_box(0_u64)` and whose budgets are both
  `0`. Comment in the trajectory-2 M06 audit: "scaffold for the
  current placeholder M05 dispatch_allow probe".

The trajectory-3 M05 narrative (line 67) names
`crates/chio-attest-verify/src/dispatch_allow.rs` as the closure
target. That file does not exist; the actual surface is in
`chio-kernel`. The freeze `m05-threat-coverage-pivot` lists
`crates/chio-attest-verify/src/dispatch_allow.rs` in `path_globs` but
the live placeholder lives elsewhere. The IMPLEMENT phase must
either (a) create the new module under chio-attest-verify and move
the dispatch-allow check there, or (b) amend the freeze and the
narrative to point at chio-kernel benches. Option (a) matches the
freeze and the narrative; option (b) is a planning amendment.

### What the real check shape looks like

The trajectory-2 M06 audit (P5.T1 evidence row, line 202-204) names
the missing evidence: "Replace the placeholder probe with the real
dispatch/canonicalization path and report allocation-count reduction
attributable to reduced reserialization."

Real-check shape:

1. Construct a representative `DispatchRequest` (capability +
   action + canonical action bytes). Reuse an existing Chio fixture.
2. Call the production kernel dispatch-allow path through
   `ChioKernel::evaluate_capability` or the equivalent post-async
   pivot surface.
3. Capture dhat `total_blocks` and `total_bytes`. Assert they
   bound under a measured budget (not `0`).
4. Capture Criterion median + 95% CI on the wall-clock dispatch and
   compare against a reference-runner baseline. Reference-runner
   contract carries over from the M06 audit (4-core Linux runner,
   warm cache, in-memory stores).

### Evidence the real check produces

- Numeric allocation-count baseline that closes the
  `partial`-quality M06 P5.T1 evidence row.
- A real Criterion sample of dispatch-allow that the M04 mutation
  gate and any future canonicalization regression checks can
  consume.

## Third M06 placeholder identification

The trajectory-3 M05 narrative names "the M06 dispatch_allow
placeholder (introduced as a stub during the perf pack), and a third
M06 placeholder evicted in the trajectory-2 close." Tracing
placeholders in the trajectory-2 closeout:

1. `dispatch_allow_dhat.rs` (dhat allocation-count placeholder).
2. `dispatch_allow.rs` (Criterion bench placeholder).
3. The threat-coverage CI gate's tolerance of `partial` itself.

The trajectory-2 M06 audit and `M06-FOLLOWUPS.md` only name a single
placeholder family (`dispatch_allow` benches). The trajectory-3 M05
narrative speaks of "the M06 dispatch_allow placeholder ... AND a
third M06 placeholder", which suggests a distinction between (1) the
dhat probe and (2) the Criterion probe. They share a name but they
are separate harnesses with separate budgets and separate failure
modes; it is consistent with the trajectory-3 narrative to treat them
as two evictable placeholders.

Working interpretation for IMPLEMENT phase:

- Eviction 1: dhat probe under `dispatch_allow_dhat.rs` swapped for
  the real allocation-count check.
- Eviction 2: Criterion probe under `dispatch_allow.rs` swapped for
  the real wall-clock check.

If the IMPLEMENT phase uncovers a third distinct placeholder (e.g.
`bench_dispatch_allow` Criterion symbol elsewhere, or a stub in
`crates/chio-attest-verify` that the freeze hints at but is not yet
visible in tree), the agent should record it in
`.planning/trajectory-3/audits/M05-threat-coverage.md` Section 3
Closure Log under a `<m06 placeholder #3>` row. Open question for
the IMPLEMENT phase below.

## Threat-coverage CI gate state

### Today

`scripts/check-threat-coverage.sh` reads the JSON, then for each
threat ID:

| state in JSON | gate result |
|--------|---------|
| `covered` (or unset, treated as covered) | passes when the test stub exists and does not still call `unimplemented!()` |
| `partial` | PASS unconditionally |
| `pending` | PASS unconditionally |
| any other string | FAIL with explicit "unknown coverage_state" message |

The gate also checks that the per-threat stub file at
`crates/chio-conformance/tests/threats/<id>.rs` exists when state is
empty/`covered`, and that it does not contain `unimplemented!()`
outside line comments. The CI workflow
`.github/workflows/threat-model-coverage.yml` invokes the script on
PR + push to main, and additionally runs
`cargo test -p chio-spec-codegen --test threat_model_schema_test` and
`cargo test -p chio-conformance --test threats`.

### Coverage table snapshot (raw counts)

`spec/security/chio-threat-model.v1.json` carries 17 threats:

- 6 `covered`: capability_token_theft, kernel_impersonation,
  tool_server_escape, native_channel_replay, resource_exhaustion_dos,
  delegation_chain_abuse.
- 11 `pending`: ssrf_via_http_substrate, pii_phi_exposure,
  agent_velocity_abuse, cumulative_data_exfiltration,
  behavioral_sequence_attack, wasm_guard_resource_exhaustion,
  pq_signature_downgrade, tee_quote_forgery, passkey_credential_theft,
  audience_confusion, weights_hash_spoof.
- 0 `partial`. 0 `placeholder`.

Coverage.yaml lists 3 entries (passkey, audience, weights). Two are
`covered` (passkey, audience) and one is `partial` (weights).
Coverage.yaml is documentation; the JSON is what the gate reads. The
JSON has the partial-state pending rows still encoded as `pending`.

### To flip the gate to fail-on-partial (and pending, by transitivity)

The script's two unconditional-pass branches must change. M05 P4 must:

1. Edit `scripts/check-threat-coverage.sh` so `partial` and
   `pending` both fail unless they carry a documented escape hatch.
   Trajectory-2 M10 audit references a `deferred_to` field that is
   not yet checked by the script; add the check.
2. Move the 11 `pending` threats off pending. The three M05-scoped
   ones flip to `covered`. The remaining 8 are advisory threats that
   D14 says M05 must classify (P4 phase): each flips to `covered`
   with a populated test body, OR carries a `deferred_to` reference
   to a trajectory-3 M07 / M10 milestone.
3. Populate every per-threat test body
   (`crates/chio-conformance/tests/threats/<id>.rs`) so none calls
   `unimplemented!()`.
4. Land the gate flip atomically with the source edits per freeze
   `m05-threat-coverage-pivot` (P1-P4 covers the source files; P5
   takes the gate flip).

## Per-phase research findings (P0-P5)

### P0: audit baseline + threat-coverage row count snapshot

- Open `.planning/trajectory-3/audits/M05-threat-coverage.md`. Fill
  Section 2 hard counts: 0 partial, 0 placeholder, 11 pending in JSON;
  1 partial entry in coverage.yaml. Note coverage.yaml vs JSON
  divergence as an explicit P0 artifact.
- Cross-reference with `spec/security/coverage.yaml` to record the
  documentation-vs-source divergence.

### P1: weights_hash_spoof partial -> passing

- Build `LoadedWeights` trait under `chio-provider-conformance` (or
  `chio-providers` per planning amendment).
- Wire kernel binding refusal to call recompute path when adapter
  exposes loaded weights; reject `LoadedWeightsUnavailable`
  fail-closed.
- Populate
  `crates/chio-conformance/tests/threats/weights_hash_spoof.rs` test
  body (positive + spoof + unavailable cases).
- Flip the JSON entry to `covered`; add `coveredBy` array.
- Update coverage.yaml partial row to `covered`.

### P2: dispatch_allow placeholder replaced with real check

- Move or create `crates/chio-attest-verify/src/dispatch_allow.rs`
  per the freeze and narrative; OR amend the freeze to point at
  `crates/chio-kernel/benches/dispatch_allow*.rs`. Recommend the
  former (matches freeze).
- Build a real `DispatchRequest` fixture; thread it through the
  production dispatch-allow path.
- Replace dhat probe with measured allocation budget, set numeric
  budget from a recorded reference-runner number.
- Replace Criterion probe with a wall-clock measurement.
- Record numbers in
  `.planning/trajectory-3/audits/M05-threat-coverage.md` Section 3
  Closure Log.

### P3: third M06 placeholder evicted

- IMPLEMENT phase identifies the third placeholder (Criterion bench
  vs dhat bench split, or another stub uncovered by the audit). See
  Open Questions.
- Eviction is symmetric to P2.

### P4: remaining advisory threats classified

- 8 advisory pending threats remain after the M05-scoped three flip
  to `covered` (ssrf_via_http_substrate, pii_phi_exposure,
  agent_velocity_abuse, cumulative_data_exfiltration,
  behavioral_sequence_attack, wasm_guard_resource_exhaustion,
  pq_signature_downgrade, tee_quote_forgery).
- Two of these (pq_signature_downgrade, tee_quote_forgery) already
  have populated `covered_by_tests` arrays; flipping their state
  from `pending` to `covered` is largely an honest reclassification
  with body fills.
- Six need either `deferred_to` references to trajectory-3 M06/M07
  /M10 milestones, or test-body fills under
  `crates/chio-conformance/tests/threats/`.

### P5: coverage gate flip + closeout audit + M08 reviewer handoff

- Edit `scripts/check-threat-coverage.sh` to fail on `partial` and
  on `pending` lacking a `deferred_to` field.
- Add a unit test for the script behavior under each state matrix
  cell.
- Close `.planning/trajectory-3/audits/M05-threat-coverage.md`
  Section 4 with the CI run URL and the M08 reviewer cross-ref.
- Update `docs/security/threat-coverage.md` (regenerated doc) so the
  Partial heading is empty.

## Coordination with M04 (attest-verify freeze)

Both M04 and M05 touch `crates/chio-attest-verify/src/`. The freeze
`m04-m05-attest-verify-coupling` (path_globs:
`crates/chio-attest-verify/src/**`) sequences this:

- M04.P3 close (mutation-gate flip on chio-attest-verify) must land
  before M05.P2 opens dispatch_allow.rs work. The freeze
  `start_trigger: M04.P3.T1` and `end_trigger: M04.P5.T5` covers the
  whole window.
- M05's freeze `m05-threat-coverage-pivot` re-locks the same
  directory plus `policy.rs` and `dispatch_allow.rs` once M04
  releases.
- The trust-boundary handoff is documented in `freezes.yml` lines
  130-140. M05 must not begin attest-verify edits until the M04
  freeze ends.

Practical effect: M05.P0 (baseline) and M05.P1 (weights_hash_spoof,
which lives in chio-weights / chio-kernel / chio-conformance, NOT in
chio-attest-verify) can run while M04 is mid-freeze. M05.P2 starts
only after M04.P5.T5 merges.

## External-vendor handoff (M08)

M08 (Independent Crypto + Protocol Review, NCC Group or Trail of
Bits) cross-checks the M05 closure per:

- M05 narrative line 19: "the M08 reviewer is expected to
  cross-check the closure in their report."
- M05 narrative line 113: "the M08 reviewer cross-checks closure in
  their report."
- M05 audit doc Section 4: "Closure attestations: the M08 reviewer
  cross-checks closure: <quote / cross-ref>".

The M05 deliverable to M08 is:

1. The closed `chio-threat-model.v1.json` (zero partial, zero
   placeholder, every pending row has a `deferred_to` reference).
2. The CI run URL of the post-flip threat-model-coverage gate.
3. The M05 audit doc with the row-by-row before / after.
4. The reproduced loaded-weight digest path under chio-weights /
   provider-conformance for the reviewer to walk.

The audit artifact M08 cites in their report is the M05 audit doc
hash + the CI run URL. M08 does not re-run the gate; they confirm
the gate exists and the artifacts they reviewed match what the gate
attested.

## Risk register

1. **chio-providers crate creation widens M05 scope past D14 bound.**
   Mitigation: implement `LoadedWeights` trait under existing
   `chio-provider-conformance` crate (option 1 above). Avoid new
   crate boundary unless PL approves an amendment.

2. **Real dispatch_allow check turns up a perf regression.** Replacing
   the `0_u64` placeholder probe with the real path will raise the
   allocation budget from 0 to a real number; the budget assertion
   in `dispatch_allow_dhat.rs` will need to change. If the real
   number exceeds an internal expectation (D08-style honest
   threshold rule applies), the M05 audit doc records it; M05 does
   not slip M08 to chase a tighter budget.

3. **Third M06 placeholder may not be cleanly closable.** If the
   IMPLEMENT phase finds the "third placeholder" is not a
   well-scoped artifact but a posture (e.g. the gate's tolerance of
   `partial` itself), then P3 collapses into P5 and the M05 audit
   records the collapse with a one-paragraph note. Do not invent a
   placeholder to evict.

4. **Coverage.yaml vs JSON divergence may have downstream consumers.**
   `spec/security/coverage.yaml` is referenced by the M10 audit
   (line 67) and by M05 P5.T5 doc-generator wiring. Updating it
   atomically with the JSON requires P0 to enumerate consumers
   before P1 starts. Mitigation: P0 grep across all
   `.planning/audits/` for `coverage.yaml` references.

5. **Advisory-threat reclassification surfaces hidden test debt.**
   Eight pending threats need test bodies or `deferred_to` refs.
   For threats whose mitigations are explicitly marked `planned`
   (e.g. ssrf_via_http_substrate, pii_phi_exposure), `deferred_to`
   is honest; populating the test body would be sandbagging. P4
   ticket spec must distinguish "covered today" from "deferred with
   reference."

6. **Freeze double-locking on chio-attest-verify/src/.** M04 and M05
   both freeze the directory through their own freeze IDs. The
   coupling freeze `m04-m05-attest-verify-coupling` sequences them
   but the orchestrator's `m{nn}-freeze-guard` checks must accept
   the handoff. Mitigation: confirm M04.P5.T5 merge closes both the
   M04 and the coupling freeze before M05.P2 opens.

7. **dispatch_allow path mismatch between freeze and tree.** The
   freeze names `crates/chio-attest-verify/src/dispatch_allow.rs`
   but the existing placeholder lives in `crates/chio-kernel/
   benches/dispatch_allow*.rs`. P0 must reconcile and either move
   the placeholder or amend the freeze.

## Recommended ticket scaffold

P0 (1 ticket):

- M05.P0.T1: open audit doc, fill hard-count baseline (0 partial /
  0 placeholder / 11 pending in JSON, 1 partial in coverage.yaml),
  enumerate coverage.yaml consumers, reconcile freeze path globs vs
  tree.

P1 (3 tickets):

- M05.P1.T1: `LoadedWeights` trait surface in
  chio-provider-conformance + integration with kernel binding
  refusal.
- M05.P1.T2: per-adapter implementations or explicit
  `LoadedWeightsUnavailable` returns for pure-API providers.
- M05.P1.T3: weights_hash_spoof.rs test body + JSON state flip +
  coverage.yaml flip.

P2 (2 tickets):

- M05.P2.T1: dispatch_allow.rs surface decision (move to
  chio-attest-verify per freeze, or amend freeze) + real check
  scaffold.
- M05.P2.T2: replace dhat probe with measured budget + replace
  Criterion probe with real wall-clock measurement.

P3 (1-2 tickets):

- M05.P3.T1: identify the third M06 placeholder. If found, evict.
- M05.P3.T2 (conditional): close the third placeholder if distinct
  from the M05.P2 work.

P4 (3 tickets):

- M05.P4.T1: pq_signature_downgrade + tee_quote_forgery
  reclassification (test bodies + JSON flip).
- M05.P4.T2: six remaining advisory threats: populate test bodies
  or `deferred_to` references.
- M05.P4.T3: regenerate `docs/security/threat-coverage.md`.

P5 (3 tickets):

- M05.P5.T1: edit `scripts/check-threat-coverage.sh` to fail on
  partial + pending-without-deferred_to.
- M05.P5.T2: unit-test the script's state matrix.
- M05.P5.T3: close audit doc, append M08 cross-ref hook.

Ticket count: 12-13 across 6 phases. Effort weeks 3/5/7 per the
narrative.

## Open questions for IMPLEMENT phase

1. **chio-providers vs chio-provider-conformance.** Does the PL
   accept option 1 (extend chio-provider-conformance with the
   `LoadedWeights` trait) over option 2 (new chio-providers crate)?
   D14 prefers bounded scope; option 1 fits.

2. **Third M06 placeholder identity.** Is the "third placeholder"
   the Criterion `dispatch_allow.rs` (paired with the dhat
   `dispatch_allow_dhat.rs` as a separate harness), or is it a
   distinct artifact this research did not surface? Specifically,
   should P3 grep all chio-attest-verify and chio-kernel benches +
   tests for `unimplemented!`, `todo!`, or `black_box(0_u64)` to
   enumerate placeholders before deciding?

3. **dispatch_allow file location.** Should
   `crates/chio-attest-verify/src/dispatch_allow.rs` be created
   (matching the freeze and narrative), or should the freeze be
   amended to point at the chio-kernel benches (matching the tree)?
   This is a planning amendment if the freeze changes.

4. **Coverage.yaml fate.** Once the JSON has zero partial / zero
   pending-without-deferred_to, does coverage.yaml stay as a
   documentation companion, or get retired in favor of the JSON
   alone? M10 audit cites coverage.yaml as the load-bearing surface
   for the three M10 threat rows; retiring it requires a
   coordinated update.

5. **Advisory-threat `deferred_to` granularity.** D14 names "M07
   mobile, M10 distribution" as out of scope for M05. Should
   passkey_credential_theft (which has a M10 closure already) keep
   its `deferred_to: M10.P2.T6` reference, or flip to `covered`?
   Coverage.yaml says `covered`; JSON says `pending`. P4 must pick
   one.

6. **M08 reviewer artifact format.** Does NCC Group / Trail of Bits
   expect the M05 audit doc as plain markdown, or as a bundled
   evidence package alongside the gate-flip CI URL? Coordinate with
   M08 P0 ticket spec.
