# M04 Trust-Boundary Audit: Recursive Delegation + Revocation Oracle

**Trajectory:** trajectory-2
**Milestone:** M04
**Wave:** W2
**Status:** TEMPLATE (orchestrator fills as phases close)
**Audit start:** <fill at P0 wave-opener merge>
**Audit close:** <fill at P5 final ticket merge>

## 1. Audit scope

M04 treats delegation and revocation as two halves of one structural
property: a delegation DAG whose sub-trees can be cut atomically, where
every cut propagates to the verifier within a bounded staleness window. The
load-bearing question is whether a revocation issued at authority A is
observable to verifier V before V signs its next allow receipt, and whether
re-delegation can attenuate without ever widening.

This milestone is the federation half trajectory-1 M03 deferred plus the
recursive-delegation half v3.18 retreated from. It introduces a new crate
`crates/chio-revocation-oracle/` (sparse-Merkle CRL-Lite, signed epoch
roots, sub-second freshness checks), a `Capability::Delegate` mint helper
behind `delegation_v2` feature flag, four new Lean theorems in
`Capability/Delegation.lean`, a new TLA module `DelegationDepthBound.tla`,
and four new Kani harnesses (capping the workspace public set at 14).

This is on the trajectory because the trajectory-1 M03 algebra is formal
only at the single-step level, and trajectory-1 M05's async-kernel
migration finally unblocks polling without blocking dispatch. Without M04,
operators have no sub-second revocation propagation path and no formal
attenuation guarantee under recursive composition.

## 2. Pre-flight checklist (mark off at P0 close)

- [ ] Cargo.lock wave-opener ticket M04.P0.T1 merged (rs_merkle 1.5)
- [ ] freezes.yml entry `m04-revocation-oracle-pivot` is in effect (start_trigger M04.P1.T1 merged)
- [ ] freezes.yml entry `m04-delegation-pivot` is in effect (start_trigger M04.P3.T1 merged)
- [ ] P3 overlap acknowledged: m04-revocation-oracle-pivot ending overlaps m04-delegation-pivot starting; both freezes active for M04.P3.T1..M04.P3.T5; the m04-freeze-guard required-check unions the path_globs of both rows during the overlap window (canonical record: `overlap_with` field on each row in `freezes.yml`)
- [ ] CODEOWNERS regen for `crates/chio-revocation-oracle/**`, `crates/chio-credentials/src/revocation*.rs`, `crates/chio-federation/src/revocation*.rs`, `crates/chio-core-types/src/capability*.rs`, `crates/chio-kernel/src/delegation*.rs`, `formal/lean4/Chio/Capability/Delegation.lean`, `formal/tla/DelegationDepthBound.tla`
- [ ] Security x2 review reviewer instances configured (different seeds, no shared scratchpad)
- [ ] M04.P0.T4 freeze wiring on `crates/chio-core-types/src/capability.rs` and `crates/chio-federation/src/lib.rs` covering P3-P4 in effect
- [ ] M03 `m03-attest-verify-pivot` close confirmed before `m04-revocation-oracle-pivot` end_trigger (cross-freeze ordering in freezes.yml)
- [ ] M03 HybridBackend availability tracked as soft_dep on M04.P1.T3
- [ ] M06 `CanonicalBytes` newtype landing tracked as soft dep for M04.P3.T2

## 3. Per-phase evidence

### P0 wave-opener
- Tickets merged:
  - M04.P0.T1 (Pin rs_merkle 1.5 and refresh Cargo.lock) merged_sha: <fill>
  - M04.P0.T2 (Scaffold chio-revocation-oracle crate) merged_sha: <fill>
  - M04.P0.T3 (Open M04 audit doc with starting counts) merged_sha: <fill>
  - M04.P0.T4 (Wire freeze on capability.rs and federation lib.rs for P3-P4) merged_sha: <fill>
- Cargo.lock diff: <fill range>
- Build green: <fill ci link or commit>
- Starting counts captured: 10 Kani harnesses, 1 TLA module, 0 Lean delegation theorems, 254 LoC revocation surface

### P1 Sparse-Merkle CRL-Lite primitives
- Tickets merged:
  - M04.P1.T1 (RevocationOracle public API) merged_sha: <fill>
  - M04.P1.T2 (Append-only sparse-Merkle backend, in-memory only) merged_sha: <fill>
  - M04.P1.T3 (Per-epoch signed root with Signer trait stub for M03 drop-in) merged_sha: <fill>
  - M04.P1.T4 (Four named proptest invariants on inclusion/non-inclusion/root-sig/epoch-monotone) merged_sha: <fill>
  - M04.P1.T5 (Verifier-side freshness check, fail-closed default) merged_sha: <fill>
  - M04.P1.T6 (Criterion bench p99 < 200us at 10K subjects) merged_sha: <fill>
- Cargo.lock diff: <fill>
- Build green: <fill>

### P2 Federation gossip + RevocationView cache
- Tickets merged:
  - M04.P2.T1 (RevocationRootGossip message in chio-federation) merged_sha: <fill>
  - M04.P2.T2 (Push path with 250ms epoch batching) merged_sha: <fill>
  - M04.P2.T3 (Pull / catch-up path for epoch gaps) merged_sha: <fill>
  - M04.P2.T4 (RevocationView arc-swap cache in chio-kernel-core) merged_sha: <fill>
  - M04.P2.T5 (E2E gossip integration: 500ms median across 100 trials, N=3 peers) merged_sha: <fill>
  - M04.P2.T6 (Wire chio-credentials passport-revocation events into oracle) merged_sha: <fill>
- Cargo.lock diff: <fill>
- Build green: <fill>

### P3 Delegation primitive + signed-receipt envelope
- Tickets merged:
  - M04.P3.T1 (Capability::delegate mint helper with attenuation enforcement) merged_sha: <fill>
  - M04.P3.T2 (DelegationReceipt schema + canonical-JSON encoding) merged_sha: <fill>
  - M04.P3.T3 (Three new proptest invariants on delegate weakening/extension/revocation cascade) merged_sha: <fill>
  - M04.P3.T4 (Kernel integration behind delegation_v2 feature flag, default OFF) merged_sha: <fill>
  - M04.P3.T5 (SDK breakage audit; feature-gate Capability::Delegate variant pub re-export) merged_sha: <fill>
- Cargo.lock diff: <fill>
- Build green: <fill>

### P4 Formal sweep: Lean + Apalache + Kani
- Tickets merged:
  - M04.P4.T1 (Land Capability/Delegation.lean skeleton with four theorem statements) merged_sha: <fill>
  - M04.P4.T2 (Prove Lean theorems 1+2: delegate_no_widen, attenuation_monotone) merged_sha: <fill>
  - M04.P4.T3 (Prove Lean theorems 3+4: revocation_is_cut, compose_preserves_algebra; theorem 3 may ship as axiom) merged_sha: <fill>
  - M04.P4.T4 (DelegationDepthBound.tla + MCDelegationDepthBound.cfg with three safety invariants) merged_sha: <fill>
  - M04.P4.T5 (Four Kani harnesses; cap at 14 covered_symbols) merged_sha: <fill>
  - M04.P4.T6 (RevocationFreshness invariant added to RevocationPropagation.tla; MAPPING.md and proof-manifest.toml updated) merged_sha: <fill>
- Lean theorem 3 status: <fill "theorem (closed proof)" or "axiom (with assumptions.toml entry)">
- Cargo.lock diff: <fill>
- Build green: <fill>

### P5 End-to-end acceptance and feature-flag flip
- Tickets merged:
  - M04.P5.T1 (3-tier swarm acceptance: planner -> coder -> tester; revoke kills children within 500ms median) merged_sha: <fill>
  - M04.P5.T2 (Receipt-chain proof: no allow receipt has seen_epoch >= revoke_epoch) merged_sha: <fill>
  - M04.P5.T3 (Flip delegation_v2 to default ON in chio-kernel Cargo.toml) merged_sha: <fill>
  - M04.P5.T4 (Final audit-doc pass with closing counts) merged_sha: <fill>
  - M04.P5.T5 (Update formal/assumptions.toml; narrow ASSUME-NETWORK-TRANSPORT iff RevocationFreshness discharges) merged_sha: <fill>
- Cargo.lock diff: <fill>
- Build green: <fill>
- Median revoke-to-deny latency across 100 trials: <fill ms>

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
during `m04-revocation-oracle-pivot` or `m04-delegation-pivot`):
<fill or "no overrides">

## 5. Decisions in force

- D11 (Kani harness ceiling for trajectory-2 close: cap at 14)
- D12 (delegation_v2 ships behind feature flag, default-on after acceptance)

## 6. Threat-model coverage at close

M04 is the producer of delegation and revocation rows in
`spec/security/chio-threat-model.v1.json`. Coverage for delegation- and
revocation-shaped threats is asserted via:

- `delegation_chain_abuse` (existing trajectory-1 M03 threat ID; M04
  refines coverage) -- covered by the three new proptest invariants in
  M04.P3.T3 (`delegate_strictly_weakens`,
  `delegate_chain_extension_monotone`,
  `delegate_revoked_parent_revokes_children`), the four Lean theorems in
  M04.P4 (`delegate_no_widen`, `attenuation_monotone`,
  `revocation_is_cut`, `compose_preserves_algebra`), and the
  DelegationDepthBound.tla invariants from M04.P4.T4
  (`DepthBoundedByRoot`, `AttenuatedAtEachStep`,
  `RevokedSubtreeNotObservable`).
- `RevocationFreshness` invariant (additive to existing
  `RevocationPropagation.tla` per M04.P4.T6) backs the bounded staleness
  window enforced at verifier side (M04.P1.T5) and the gossip path
  (M04.P2.T2/T3/T5).
- Capability::Delegate signed-receipt envelope (M04.P3.T1/T2) is exercised
  by the end-to-end swarm acceptance test (M04.P5.T1) and the receipt-chain
  proof (M04.P5.T2).

Cross-reference: M05.P5 threat-model-coverage gate consumes the
`coveredBy` cross-link added by M04 in the relevant rows of
`spec/security/chio-threat-model.v1.json`.

Kani public harness count at close: <fill 14 expected>.
TLA modules at close: <fill 2 expected: RevocationPropagation +
DelegationDepthBound>.
Lean delegation theorems at close: <fill 4 expected; record theorem-vs-axiom
status per theorem>.
Oracle insert + proof-emit p99 at 10K subjects: <fill us>.

## 7. Cross-trajectory artifact handoffs

Produced by M04, consumed downstream:

- `chio-revocation-oracle` sparse-Merkle CRL-Lite -- consumed by M09
  (economic layer reads epoch-stamped roots when attributing revenue),
  M10 (custody issuer pushes WebAuthn credential revocation through the
  oracle per M10.P2.T3).
- `Capability::Delegate` mint helper + DelegationReceipt envelope --
  consumed by M09 (revenue attribution across delegated kernels), M10
  (passkey-issued capabilities are a delegation shape), M07 (framework
  adapters opt into `delegation_v2` explicitly per M04.P3.T5).
- Federation gossip path (`RevocationRootGossip`) -- consumed by every
  verifier participating in the federation peer graph.
- `RevocationView` arc-swap cache in chio-kernel-core -- consumed by every
  dispatch path that consults revocation state.
- New Lean theorems in `formal/lean4/Chio/Capability/Delegation.lean` and
  the `DelegationDepthBound.tla` module -- consumed by formal/MAPPING.md
  and the `formal-tla` / `lean-build` CI gates.

Cross-doc invariants enforced (EXECUTION-BOARD section 3):
- Cross-freeze ordering: `m03-attest-verify-pivot` must close before
  `m04-revocation-oracle-pivot` end_trigger so the per-epoch signed root in
  M04.P1.T3 can drop in the M03 HybridBackend without a re-shape.
- Intra-M04 P3 overlap: `m04-revocation-oracle-pivot` (ending at
  M04.P3.T5) and `m04-delegation-pivot` (starting at M04.P3.T1) are
  simultaneously active across M04.P3.T1..M04.P3.T5. The
  `m04-freeze-guard` required-check unions the `path_globs` of both
  rows during this window. Recorded canonically via the `overlap_with`
  field on each row in `freezes.yml`.
- Kani public harness cap is exactly 14 (10 baseline + 4 new); future
  delegation properties land as nightly-only or private harnesses.
- `formal/tla/RevocationPropagation.tla` is extended additively by
  M04.P4.T6; existing invariant names are preserved.

## 8. Halt-and-resume events

If this milestone hit any halt triggers from AUTONOMOUS-PROMPT or
HANDOFF-PROMPT, the event log entry goes here. Examples that would trigger
a halt: Lean theorem 3 (`revocation_is_cut`) graph-theoretic development
exceeds budget and cannot ship as theorem-or-axiom; Apalache state-space
blowup on DelegationDepthBound.tla beyond the bounded PR config (DEPTH_MAX=4,
PEERS=3); sparse-Merkle insert p99 > 200us at 10K subjects; gossip storm
under high revoke rate exceeding the 250ms epoch batching budget.

<fill or "no halt events">

## 9. Close-out signature

- Final commit on `main`: <fill 40hex sha>
- Final ticket merged: M04.P5.T5
- Audit closed by: @bb-connor
- Audit close date: <fill yyyy-mm-dd>
