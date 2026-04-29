# M05 Trust-Boundary Audit: Adversarial Receipts + Guard Escape + Threat-Model-as-Code

**Trajectory:** trajectory-2
**Milestone:** M05
**Wave:** W2
**Status:** TEMPLATE (orchestrator fills as phases close)
**Audit start:** <fill at P0 wave-opener merge>
**Audit close:** <fill at P5 final ticket merge>

## 1. Audit scope

M05 attacks the *semantically valid attack* band that sits between the
trajectory-1 M02 byte-decoder boundary and the trajectory-1 M03
capability-algebra layer: receipts that decode cleanly, inputs that satisfy
the type system, modules that pass the manifest verifier, but that
nonetheless represent a hostile state. The lens is adversarial quality.

The milestone curates the *answer key* the trajectory-1 suite was missing:
forty curated adversarial vectors across eight attack classes (clock-rewound,
future-dated, replayed-nonce, partial-signature, scope-superset,
revocation-rollback, anchor-grafted, sigstore-bundle-payload-mismatch); a
single new libFuzzer target (`wasm_guard_escape`) plus hand-curated escape
companion fixtures across at least 25 escape classes; a per-tenant
`expected_identity` policy file surface in `chio-attest-verify` replacing
inline regex composition; and the conversion of
`spec/security/chio-threat-model.v1.json` from documentation into a
load-bearing CI gate via `chio-spec-codegen`.

This is the central artifact for trajectory-2 trust-boundary attestation:
the threat-model coverage gate fails closed when any threat ID lacks a
green test, which means M03's two new IDs and M10's three new IDs cannot
land without populated test bodies referencing M05 corpus or escape-class
tests.

## 2. Pre-flight checklist (mark off at P0 close)

- [ ] Cargo.lock wave-opener ticket M05.P0.T1 merged (toml direct-dep on chio-attest-verify; arbitrary on chio-wasm-guards/tests)
- [ ] freezes.yml entry `m05-adversarial-corpus-pivot` is in effect (start_trigger M05.P1.T1 merged) covering P1..P5
- [ ] CODEOWNERS regen for `crates/chio-adversarial-suite/**`, `fuzz/fuzz_targets/wasm_guard_escape.rs`, `crates/chio-wasm-guards/tests/escape/**`, `crates/chio-attest-verify/src/policy.rs`, `spec/security/chio-threat-model.v1.json`, `crates/chio-conformance/tests/threats/**`
- [ ] Security x2 review reviewer instances configured (different seeds, no shared scratchpad)
- [ ] Cross-freeze ordering: M05.P4 lands AFTER M03.P3 closes (overlap on `crates/chio-attest-verify/src/policy.rs` between `m05-adversarial-corpus-pivot` and `m03-attest-verify-pivot`)
- [ ] M02 verdict-matrix runner availability tracked as soft dep on M05.P2.T4 (manifest producer)
- [ ] M03 PQ identity certificate format availability tracked for `pq_identity_regexps` reserved field in M05.P4.T1

## 3. Per-phase evidence

### P0 wave-opener
- Tickets merged:
  - M05.P0.T1 (Pin toml + arbitrary direct deps; refresh Cargo.lock) merged_sha: <fill>
- Cargo.lock diff: <fill range>
- Build green: <fill ci link or commit>

### P1 chio-adversarial-suite crate genesis
- Tickets merged:
  - M05.P1.T1 (Genesis chio-adversarial-suite crate with case schema + cases/ skeleton) merged_sha: <fill>
  - M05.P1.T2 (15 vectors: clock-rewound, future-dated, replayed-nonce) merged_sha: <fill>
  - M05.P1.T3 (15 vectors: partial-signature, scope-superset, revocation-rollback; algebra-oracle headers) merged_sha: <fill>
  - M05.P1.T4 (10 vectors: anchor-grafted, sigstore-bundle-payload-mismatch) merged_sha: <fill>
  - M05.P1.T5 (Wire suite into chio-kernel-core test run as required check) merged_sha: <fill>
  - M05.P1.T6 (Wire suite into chio-attest-verify test run as required check) merged_sha: <fill>
- Cargo.lock diff: <fill>
- Build green: <fill>
- Vector count at P1 close: <fill 40 expected>

### P2 Cross-promotion plumbing
- Tickets merged:
  - M05.P2.T1 (--mode adversarial in promote_fuzz_seed.sh with pending-flag triage gate) merged_sha: <fill>
  - M05.P2.T2 (fuzz/corpus_metadata.toml indexing every seed by source/class/threat_id) merged_sha: <fill>
  - M05.P2.T3 (cargo fuzz cmin sweep + minimization report) merged_sha: <fill>
  - M05.P2.T4 (chio-adversarial-suite manifest.json producer for M02) merged_sha: <fill>
- Cargo.lock diff: <fill>
- Build green: <fill>

### P3 WASM guard escape harness
- Tickets merged:
  - M05.P3.T1 (fuzz_targets/wasm_guard_escape.rs + 8 hand-curated seeds) merged_sha: <fill>
  - M05.P3.T2 (Escape classes: undeclared-imports, oversize-memory, fuel-exhaustion) merged_sha: <fill>
  - M05.P3.T3 (Escape classes: table-grow-abuse, deep-recursion, host-reentry) merged_sha: <fill>
  - M05.P3.T4 (Escape classes: malformed-component-encoding, signed-but-malicious modules) merged_sha: <fill>
  - M05.P3.T5 (Determinism gate aggregating all escape classes into typed GuardError) merged_sha: <fill>
- Cargo.lock diff: <fill>
- Build green: <fill>
- Frozen config snapshot at `crates/chio-wasm-guards/tests/escape/config.frozen.toml` checked in: <fill yes/no>

### P4 expected_identity policy hardening
- Tickets merged:
  - M05.P4.T1 (TenantPolicy schema with reserved pq_identity_regexps and 90-day staleness horizon) merged_sha: <fill>
  - M05.P4.T2 (TenantPolicy loader: Sigstore-signed; fail-closed on stale signatures) merged_sha: <fill>
  - M05.P4.T3 (Replace inline ExpectedIdentity at every workspace call site with expected_for_tenant) merged_sha: <fill>
  - M05.P4.T4 (docs/security/expected-identity-migration.md per-call-site listing) merged_sha: <fill>
- Cargo.lock diff: <fill>
- Build green: <fill>
- Bootstrap policy file hash recorded: <fill>

### P5 Threat-model-as-code
- Tickets merged:
  - M05.P5.T1 (chio-threat-model.schema.json validating v1 JSON) merged_sha: <fill>
  - M05.P5.T2 (chio-spec-codegen --threat-model emits one stub per threat ID) merged_sha: <fill>
  - M05.P5.T3 (Test bodies for the six initial threat IDs) merged_sha: <fill>
  - M05.P5.T4 (CI gate threat-model-coverage required-on-PR, fails on uncovered IDs) merged_sha: <fill>
  - M05.P5.T5 (docs/security/threat-coverage.md generated) merged_sha: <fill>
  - M05.P5.T6 (coveredBy cross-link in JSON; CI assertion every adversarial vector cites a threat ID) merged_sha: <fill>
- Cargo.lock diff: <fill>
- Build green: <fill>

## 4. Trust-boundary attestations

For trust-boundary milestones, every PR was reviewed by:
- Security reviewer instance A: <fill handle or seed>
- Security reviewer instance B: <fill handle or seed>
- Human-side reviewer: @bb-connor

Per-phase PR attestation log (filled by orchestrator):

- P0 PRs reviewed: <fill PR numbers> -- attestation status: <fill>
- P1 PRs reviewed: <fill> -- attestation status: <fill>
- P2 PRs reviewed: <fill> -- attestation status: <fill>
- P3 PRs reviewed: <fill> -- attestation status: <fill>
- P4 PRs reviewed: <fill> -- attestation status: <fill>
- P5 PRs reviewed: <fill> -- attestation status: <fill>

Hot-fix bypass log (record any `hotfix/* + [trajectory-2]` overrides
during `m05-adversarial-corpus-pivot`):
<fill or "no overrides">

## 5. Decisions in force

- D13 (Adversarial vector format and corpus location: JSON at `crates/chio-adversarial-suite/cases/<class>/<sha>.json` with `{ class, expected_verdict, expected_reason }`)
- D14 (Auto-promoted vectors land with `pending: true`; threat-coverage gate treats pending as not-yet-covered)

## 6. Threat-model coverage at close (LOAD-BEARING)

This section is the central artifact of M05. It maps every threat ID in
`spec/security/chio-threat-model.v1.json` to the test or fixture that
covers it. The `threat-model-coverage` CI gate fails closed if any row
below is missing a green test reference.

### Threat IDs at trajectory-2 entry (six baseline)

- `capability_token_theft` -- covered by <fill: e.g. M05 corpus class +
  test path under crates/chio-conformance/tests/threats/>
- `kernel_impersonation` -- covered by <fill>
- `tool_server_escape` -- covered by <fill: M05.P3 wasm guard escape
  classes>
- `native_channel_replay` -- covered by <fill: M05.P1 replayed-nonce
  class>
- `resource_exhaustion_dos` -- covered by <fill: M05.P3
  fuel-exhaustion / oversize-memory escape classes>
- `delegation_chain_abuse` -- covered by <fill: M05.P1
  scope-superset/revocation-rollback classes; cross-link to M04 P3
  proptests>

### Threat IDs added by sibling milestones (M05 owns the gate; producers append rows in P0)

- `pq_signature_downgrade` (added by M03.P0.T4) -- covered by <fill: M03
  P1 bit-flip property test, P2 crypto_floor migration test>
- `tee_quote_forgery` (added by M03.P0.T4) -- covered by <fill: M03 P3-P4
  TDX/SEV-SNP/Nitro fixture corpora>
- `passkey_credential_theft` (added by M10.P0.T3) -- covered by <fill:
  M10 P1 fixture corpus, P2 audience-confusion proptest>
- `audience_confusion` (added by M10.P0.T3) -- covered by <fill: M10
  P2.T4 audience-confusion proptest>
- `weights_hash_spoof` (added by M10.P0.T3) -- covered by <fill: M10
  P4.T5 kernel binding refusal; partial coverage flagged in M10 audit doc
  per the risk register>

### Adversarial vector inventory

- Vector count at trajectory-2 close: <fill>
- Pending (auto-promoted, not yet triaged) count: <fill 0 expected at close;
  pending vectors block trajectory close per D14>
- Algebra-oracle cross-link count (M03 invariant references): <fill>

### Escape class inventory

- libFuzzer target `wasm_guard_escape` corpus size: <fill>
- Companion fixture escape classes: <fill at-least-25 expected>
- All escape attempts yield typed `GuardError`: <fill yes/no>

### CI gate status at close

- `threat-model-coverage` gate green and required-on-PR: <fill yes/no>
- `adversarial-suite` gate green and required-on-PR: <fill yes/no>
- `wasm-guard-escape` nightly libFuzzer lane status: <fill>

## 7. Cross-trajectory artifact handoffs

Produced by M05, consumed downstream:

- `crates/chio-adversarial-suite/` corpus + `manifest.json` -- consumed by
  M02 (verdict matrix oracle; M05.P2.T4 ships producer), M08 (arena
  auto-promotes scenarios into the corpus through M05.P2.T1 promoter).
- `fuzz/fuzz_targets/wasm_guard_escape.rs` -- consumed by M02
  ClusterFuzzLite matrix; regression net for M07 new provider adapters and
  M08 arena-promoted scenarios.
- `crates/chio-attest-verify/src/policy.rs` per-tenant policy surface --
  consumed by every `ExpectedIdentity` call site in the workspace; the
  reserved `pq_identity_regexps` field accepts M03's ML-DSA cert identities
  once that surface stabilises.
- `spec/security/chio-threat-model.v1.json` (now load-bearing) and the
  generated `crates/chio-conformance/tests/threats/<id>.rs` test stubs --
  consumed by every PR's `threat-model-coverage` gate. M03 appends two
  rows in its P0; M10 appends three rows in its P0; both reference M05
  corpus or escape classes in their `coveredBy` field.
- `docs/security/threat-coverage.md` -- regenerated on every PR touching
  the threat model or corpus; the public-facing coverage report.
- `scripts/promote_fuzz_seed.sh --mode adversarial` -- consumed by M08
  arena post-tournament promotion.

Cross-doc invariants enforced (EXECUTION-BOARD section 3):
- M05 freeze on `crates/chio-attest-verify/src/policy.rs` overlaps with
  M03 freeze on the same crate; sequenced so M05.P4 lands AFTER M03.P3
  closes.
- Auto-promoted vectors land with `pending: true` per D14; coverage gate
  treats pending as not-yet-covered.
- Existing `mitigations[].status` enum and `surfaces` taxonomy in
  `chio-threat-model.v1.json` are frozen for trajectory-2; only `coveredBy`
  is added.

## 8. Halt-and-resume events

If this milestone hit any halt triggers from AUTONOMOUS-PROMPT or
HANDOFF-PROMPT, the event log entry goes here. Examples that would trigger
a halt: a WASM guard escape harness panic (P0 incident per
EXECUTION-BOARD section 7); threat-model-coverage gate failing on an
uncovered threat ID after merge; cross-promotion noise saturating the
corpus before triage; Sigstore policy signing recursion bootstrap failure.

<fill or "no halt events">

## 9. Close-out signature

- Final commit on `main`: <fill 40hex sha>
- Final ticket merged: M05.P5.T6
- Audit closed by: @bb-connor
- Audit close date: <fill yyyy-mm-dd>
