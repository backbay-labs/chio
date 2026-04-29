# Milestone 04: Recursive Delegation + Revocation Oracle

## Lens

Single lens: capability algebra + revocation. This milestone treats delegation
and revocation as two halves of one structural property: a delegation DAG
whose sub-trees can be cut atomically, where every cut propagates to the
verifier within a bounded staleness window. Throughput, DX, and economic
shape are downstream concerns; the load-bearing question is whether a
revocation issued at authority A is observable to verifier V before V signs
its next allow receipt, and whether re-delegation can attenuate without
ever widening.

## Why this is on the trajectory

trajectory-1 M03 (`.planning/trajectory/03-capability-algebra-properties.md`)
shipped the base capability algebra: 18 named proptest invariants, 10 Kani
public harnesses, the Apalache-checked `formal/tla/RevocationPropagation.tla`
module modelling concurrent revocation across N authorities, and Lean
modules at `formal/lean4/Chio/Chio/Core/{Capability,Revocation,Scope}.lean`
plus `formal/lean4/Chio/Chio/Proofs/{Monotonicity,Revocation}.lean`. The
algebra is now formal at the single-step level. trajectory-1 M03 explicitly
deferred federation property work ("Should `chio-federation` get its own
property crate now, or reuse `chio-core-types` and `chio-credentials`
invariants over a federation harness? Defer to milestone 04.") and walked
back recursive delegation under the v3.18 bounded-claim retreat.

trajectory-1 M05 (`.planning/trajectory/05-async-kernel-real.md`) removed the
process-wide `&mut self` bottleneck on `ChioKernel::evaluate_tool_call` and
moved store reads onto interior-mutability primitives. Until M05 landed, a
sub-second revocation oracle was unreachable: every kernel-level state
transition serialised through `std::sync::Mutex<RevocationStore>`. M05
unblocks polling without blocking dispatch.

trajectory-2 M03 (`.planning/trajectory-2/03-pq-hybrid-and-tee-quote-verifier.md`,
sibling milestone in this wave) consolidates ML-DSA-65 hybrid signatures
into `chio-attest-verify`. The revocation oracle in this milestone signs
its epoch roots through that surface; the bridge is recorded as a
`soft_deps` entry on the relevant tickets, not as a hard `depends_on`,
because both milestones land in the same wave and their merge order is
managed by the freeze schedule rather than by ticket dependency.

This milestone is the federation half trajectory-1 M03 deferred plus the
recursive-delegation half v3.18 retreated from. The base algebra is the
foundation; this milestone climbs the next two storeys.

## Prior-art reckoning

What trajectory-1 already shipped that overlaps with this milestone:

- `formal/tla/RevocationPropagation.tla` (M03 Phase 3) models per-process
  revocation epochs and the safety invariants `NoAllowAfterRevoke`,
  `MonotoneLog`, `AttenuationPreserving`. **Preserved.** This milestone adds
  a sibling module `formal/tla/DelegationDepthBound.tla` and adds a
  `RevocationFreshness` invariant to the existing module without
  renaming any state variable.
- `crates/chio-core-types/src/capability.rs` ships `DelegationLink`,
  `DelegationLinkBody`, `validate_delegation_chain` with `max_depth`
  enforcement, and the `Error::DelegationDepthExceeded` variant.
  **Preserved.** This milestone adds a `Capability::Delegate` mint helper
  that wraps the existing chain construction in a signed-receipt envelope;
  it does not re-shape `DelegationLink` itself.
- Existing revocation storage: `crates/chio-kernel/src/revocation_store.rs`
  (17 lines, in-memory trait), `crates/chio-kernel/src/revocation_runtime.rs`
  (45 lines), `crates/chio-store-sqlite/src/revocation_store.rs`
  (192 lines, SQLite persistence). **Preserved.** This milestone introduces
  a new crate `chio-revocation-oracle` that consumes the existing trait;
  the SQLite store gains a sparse-Merkle-aware variant via composition,
  not replacement.
- Existing Lean modules at `formal/lean4/Chio/Chio/Core/Revocation.lean`
  and `formal/lean4/Chio/Chio/Proofs/Revocation.lean`. **Preserved.** This
  milestone adds `formal/lean4/Chio/Chio/Capability/Delegation.lean` with
  four new theorems; it imports the existing `Core/Revocation.lean` for
  the cut definition.
- 10 Kani public harnesses in
  `formal/rust-verification/kani-public-harnesses.toml`. **Preserved.**
  This milestone adds exactly 4 new harnesses focused on delegation,
  bringing total public harness count to 14. We do NOT widen Kani further
  per Quality Hawk discipline; the marginal proof-time cost on the PR
  lane grows super-linearly past 14.

What this milestone deliberately re-attacks:

- **v3.18 bounded-claim retreat on recursive delegation.** The v3.18 audit
  concluded that without a formal model of multi-tier delegation, the
  protocol could not promise attenuation under composition. trajectory-1
  M03 then deliberately bounded its claims to single-step delegation. This
  milestone closes that gap with Lean theorems 1-4 and the
  `DelegationDepthBound.tla` model.
- **Sub-second revocation propagation.** trajectory-1 M03's
  `RevocationPropagation.tla` is a model; production has no revocation
  gossip path beyond bilateral federation. This milestone delivers the
  oracle and wires it into the federation gossip surface.

What is unambiguously new:

- `crates/chio-revocation-oracle/` (new crate). Sparse-Merkle CRL-Lite
  primitives, signed epoch roots, freshness-bounded verifier checks,
  offline-grace configuration. New code; nothing in trajectory-1 occupies
  this surface.
- `Capability::Delegate` mint helper that emits a signed receipt for each
  mint, distinct from the existing `DelegationLink::sign`. The link is the
  cryptographic primitive; the mint helper is the receipt-emitting
  envelope.
- `formal/tla/DelegationDepthBound.tla` and the four Lean theorems in
  `Capability/Delegation.lean`.
- Federation gossip plumbing for signed roots in `chio-federation`.

## Hard counts (measured 2026-04-29)

Reproduce with the commands in parentheses. Update the date and numbers if
you re-run; do not silently let them drift.

- `crates/chio-core-types/src/capability.rs`: 3700 lines, 52 `pub` items,
  35 references to `Delegate`/`delegate`/`Delegation`/`delegation`.
  `DelegationLink` defined at line 2073; `validate_delegation_chain` at
  line 2184; `Error::DelegationDepthExceeded` at line 2188.
  (`wc -l`, `grep -c '^pub '`, `grep -c 'Delegate\|delegate\|Delegation\|delegation'`,
   `grep -n 'DelegationLink\|validate_delegation_chain'`)
- Existing revocation surface (5 files):
  - `crates/chio-kernel/src/revocation_store.rs` 17 lines (trait only)
  - `crates/chio-kernel/src/revocation_runtime.rs` 45 lines
  - `crates/chio-store-sqlite/src/revocation_store.rs` 192 lines
  - `crates/chio-kernel/benches/revocation_lookup.rs` (M05 bench)
  - `crates/chio-cli/tests/trust_revocation.rs` (CLI integration)
  Total: 254 lines under 3 implementation files.
  (`find crates -name '*revocation*' -o -name 'revocation*'`,
   `wc -l <hits>`)
- `crates/chio-federation/`: 3 files, 3400 LoC total
  (`bilateral.rs` 334, `lib.rs` 2620, `trust_establishment.rs` 446). No
  current revocation-gossip path; `bilateral.rs` carries trust
  establishment but not signed-root distribution.
  (`wc -l crates/chio-federation/src/*.rs`)
- `crates/chio-credentials/src/passport.rs` carries the
  `LifecycleStatus::Revoked` enum variant and four passport-lifecycle
  proptest invariants from trajectory-1 M03. We consume them; we do not
  duplicate them in this milestone.
  (`grep -n "Revoked\|revoked" crates/chio-credentials/src/passport.rs`)
- Lean inventory (`ls formal/lean4/Chio/Chio/Core/`,
  `ls formal/lean4/Chio/Chio/Proofs/`):
  - Core: `Capability.lean`, `Protocol.lean`, `Receipt.lean`,
    `Revocation.lean`, `Scope.lean`
  - Proofs: `AeneasEquivalence.lean`, `Evaluation.lean`, `FormalClosure.lean`,
    `Monotonicity.lean`, `Protocol.lean`, `Receipt.lean`, `Revocation.lean`
  This milestone adds one new namespace `Chio/Capability/` with one file
  `Delegation.lean` containing four theorems. No existing file is
  modified beyond import additions.
- TLA inventory (`ls formal/tla/`): `RevocationPropagation.tla`,
  `MCRevocationPropagation.cfg`, `counterexamples/`. This milestone adds
  `DelegationDepthBound.tla` and `MCDelegationDepthBound.cfg`.
- Kani public harness count: 10 (file `formal/rust-verification/kani-public-harnesses.toml`,
  `covered_symbols`). This milestone raises the count to 14, capped.
  Future milestones may add private (non-public) harnesses; the public
  set is gated.
- `cargo tree -p chio-credentials -d` shows no second copy of any crate
  today; do not regress that.

## Workspace dependency state

Pinned in `[workspace.dependencies]` of root `Cargo.toml` today and reused
without re-pinning:

- `tokio = { version = "1", features = ["full"] }` (from trajectory-1 M05)
- `dashmap = "6"` (from trajectory-1 M05)
- `arc-swap = "1"` (from trajectory-1 M05)
- `serde`, `serde_json`, `thiserror`, `proptest`, `criterion`
- `ed25519-dalek` (existing, used by `DelegationLink::sign`)

Added or pinned by this milestone (re-check crates.io for the
then-current latest patch on the day work opens; record exact pinned
version in the audit doc):

- `rs_merkle = "1.5"` for sparse-Merkle tree primitives. Pinned at the
  workspace root because both `chio-revocation-oracle` and
  `chio-store-sqlite` consume it. Rationale: pure-Rust, no `unsafe`,
  permissive license, mature on crates.io. Alternative considered:
  `merkle-tree-rs` (rejected: unmaintained, last release 2022).

PQ signatures: the milestone uses `chio-attest-verify` (trajectory-2 M03)
for signing oracle epoch roots. `chio-attest-verify` already pins its own
PQ crate; this milestone adds a workspace dep on `chio-attest-verify`
itself (path dependency, no version bump) and references the M03 surface
through it. Recorded as a `soft_deps` string sentence on the relevant
tickets; tickets do not hard-block on M03 ticket IDs because M03 sits in
the same wave.

`chio-revocation-oracle` Cargo.toml dependency surface (informative; the
exact set is finalised in P1.T1):

```toml
[dependencies]
chio-core-types = { path = "../chio-core-types" }
chio-credentials = { path = "../chio-credentials" }
rs_merkle = { workspace = true }
ed25519-dalek = { workspace = true }
serde = { workspace = true, features = ["derive"] }
thiserror = { workspace = true }
tokio = { workspace = true }
arc-swap = { workspace = true }

[dev-dependencies]
proptest = { workspace = true }
```

## Scope

In:

- New crate `crates/chio-revocation-oracle/`. Sparse-Merkle CRL-Lite over
  `(subject_id, epoch_nonce)` pairs with append-only insertion, inclusion
  and non-inclusion proofs, per-epoch signed roots, and a verifier-side
  freshness check capped at 1s of staleness with a configurable offline
  grace window (fail-closed default: 0s grace, deny on stale view).
- Federation gossip: `chio-federation` gains a `RevocationRootGossip`
  message and a push-based dissemination path on the bilateral and
  multi-peer surfaces. Roots are signed via the trajectory-2 M03
  PQ-hybrid surface in `chio-attest-verify`.
- `RevocationView` cache in `chio-kernel-core` so verifiers consult the
  oracle without a SQLite roundtrip on every dispatch. The cache is the
  read-side; writes go through the oracle's append-only insert.
- Recursive delegation primitive: `Capability::Delegate` mint emits a
  canonical-JSON signed receipt for each mint. Scope ⊆, budget ≤, expiry
  ≤ (attenuation only; no widening). The receipt envelope uses
  `CanonicalBytes` from trajectory-2 M06 (`soft_deps` string sentence).
- Lean module `formal/lean4/Chio/Capability/Delegation.lean` with four
  theorems:
  1. `delegate_no_widen`: `delegate(delegate(c, a), b)` strictly weakens.
  2. `attenuation_monotone`: attenuation is monotone under composition.
  3. `revocation_is_cut`: revocation is a cut in the delegation DAG.
  4. `compose_preserves_algebra`: composition preserves the capability
     algebra invariants from trajectory-1 M03.
- New TLA module `formal/tla/DelegationDepthBound.tla` plus
  `MCDelegationDepthBound.cfg`, model-checked under Apalache pinned
  `0.50.x` (matches trajectory-1 M03's pin). Models multi-tier delegation
  flows; safety invariants `DepthBoundedByRoot`, `AttenuatedAtEachStep`,
  `RevokedSubtreeNotObservable`.
- Kani harness expansion by 4 (total 14, capped). New harnesses live in
  `crates/chio-kernel-core/src/kani_public_harnesses.rs` per the
  trajectory-1 M03 layout.
- Bridge: proptest invariants in `crates/chio-core-types/tests/`
  reference the same generators that the Lean theorems' Rust witnesses
  exercise; we add three new invariants (named in P3) and re-use the
  trajectory-1 M03 generators in `formal/diff-tests/src/generators.rs`.
- Kernel integration behind feature flag `delegation_v2`. Default OFF
  until P5 acceptance flips it ON.
- End-to-end acceptance harness: 3-tier swarm (planner -> coder ->
  tester) demonstrates that revoking the planner kills both children
  mid-call within 500 ms median, proven by the receipt chain.

Out (and why):

- Off-line revocation timestamping with external chain finality. Cited as
  out-of-scope by `formal/assumptions.toml` `ASSUME-CHAIN-FINALITY`. We
  rely on PQ-signed roots only; chain anchoring is trajectory-2 M09
  lineage territory.
- SQLite-backed variant of the sparse-Merkle store. P1 ships the
  in-memory variant only; the SQLite backend is deferred to a follow-on
  milestone and is out of scope here. Existing `chio-store-sqlite`
  revocation tables are unchanged.
- New protocol features beyond the delegation envelope. The wire shape of
  `DelegationLink` is preserved.
- chio-mesh / kernel-as-block-producer (Wildcard V07). Explicitly
  out-of-scope per the trajectory-2 README; revocation gossip uses the
  existing federation surface, not a mesh consensus protocol.
- Cross-process kernel sharding for the oracle. Single-process oracle per
  kernel; gossip is bilateral and many-to-many at the federation peer
  graph.
- Widening Kani public harnesses past 14. Future delegation properties
  that need symbolic execution land as nightly-only or private harnesses,
  not on the PR public lane.
- Replacing `formal/tla/RevocationPropagation.tla` with a unified module.
  We add a new module and a new invariant; we do not refactor the
  existing module.
- Version-negotiation TLA (Protocol M13). Low-traffic surface; deferred
  per round-2 synthesis and not opened in trajectory-2.
- IETF -01 standards work (Protocol M15). External standards work was
  excluded from trajectory-2 scope.

## Phases

Six phases. P0 is wave-opener housekeeping; P1-P3 are sequential and
load-bearing; P4 is the formal-methods sweep that runs on the merged P3
surface; P5 is the acceptance gate that flips the feature flag.

### P0 - Wave-opener Cargo.lock bump and oracle crate scaffold

- `M04.P0.T1` Pin `rs_merkle = "1.5"` and refresh `Cargo.lock`.
- `M04.P0.T2` Scaffold `crates/chio-revocation-oracle/` with empty
  `lib.rs`, `Cargo.toml`, and a placeholder integration test.
- `M04.P0.T3` Open audit doc `.planning/audits/M04-delegation-revocation.md`
  recording starting counts (10 Kani harnesses, 1 TLA module, 0 Lean
  delegation theorems, 254 LoC of revocation surface).
- `M04.P0.T4` Wire the freeze on `crates/chio-core-types/src/capability.rs`
  and `crates/chio-federation/src/lib.rs` for the duration of P3-P4.

### P1 - Sparse-Merkle CRL-Lite primitives in chio-revocation-oracle

- `M04.P1.T1` Define the public API: `RevocationOracle`,
  `RevocationKey = (SubjectId, EpochNonce)`, `EpochRoot`,
  `InclusionProof`, `NonInclusionProof`. Insert + lookup + proof-emit.
- `M04.P1.T2` Implement append-only sparse-Merkle backend using
  `rs_merkle`. In-memory variant first; SQLite backend deferred to a
  later milestone (delete the SQLite-backed variant from scope here).
- `M04.P1.T3` Per-epoch signed root: epoch tick produces a new root
  signed via the trajectory-2 M03 PQ-hybrid surface. Stub the
  signer behind a trait so the M03 implementation can drop in without a
  re-shape.
- `M04.P1.T4` Property tests: inclusion proof soundness, non-inclusion
  proof soundness, root-signature verification, epoch monotonicity. Each
  invariant has a name (see P1.T4 ticket).
- `M04.P1.T5` Verifier-side freshness check with configurable offline
  grace; fail-closed default (0s grace, deny on stale).
- `M04.P1.T6` Criterion bench: insert and proof-emit p99 < 200 us at
  10K subjects.

### P2 - Federation gossip + RevocationView cache

- `M04.P2.T1` Define `RevocationRootGossip` message in
  `chio-federation`: `{epoch, root, signature, signer_id, ts}`.
- `M04.P2.T2` Push path: when `chio-revocation-oracle` advances epoch,
  the federation peer manager broadcasts the signed root to bilateral
  peers. Backpressure through the existing federation channel.
- `M04.P2.T3` Pull / catch-up path: a peer behind by N epochs requests
  the gap; sender replies with a sequence of signed roots.
- `M04.P2.T4` `RevocationView` cache in `chio-kernel-core`: read-only
  `arc-swap`-backed view that the verifier consults during dispatch.
  Cache is updated by the gossip task; readers never block writers.
- `M04.P2.T5` Integration test asserting end-to-end: oracle insert at
  authority A is observable to verifier V (different kernel) within 500
  ms median across 100 trials on a single-host gossip mesh. Topology
  pinned: N=3 peers, 0-cost localhost links, in-process tokio runtime.
- `M04.P2.T6` Wire `chio-credentials` passport-revocation events into
  the oracle so passport-level revocation cascades through the same
  surface.

### P3 - Delegation primitive + signed-receipt envelope

- `M04.P3.T1` Add `Capability::Delegate` mint helper to
  `chio-core-types/src/capability.rs`. Signature: `pub fn delegate(parent: &Capability, attenuation: ScopeAttenuation) -> Result<DelegationReceipt>`.
  Wraps the existing `DelegationLink::sign` and emits a canonical-JSON
  receipt. Scope ⊆, budget ≤, expiry ≤ enforced before signing.
- `M04.P3.T2` Receipt schema: `DelegationReceipt` carries `parent_chain`,
  `attenuation`, `signed_at`, `nonce`. Canonical-JSON encoded; uses the
  trajectory-2 M06 `CanonicalBytes` newtype (soft dep).
- `M04.P3.T3` Three new proptest invariants in
  `crates/chio-core-types/tests/property_capability_algebra.rs`:
  - `delegate_strictly_weakens`
  - `delegate_chain_extension_monotone`
  - `delegate_revoked_parent_revokes_children`
- `M04.P3.T4` Kernel integration behind `delegation_v2` feature flag in
  `crates/chio-kernel/`. Flag default OFF; verifier consults oracle on
  every delegated dispatch when ON.
- `M04.P3.T5` SDK breakage audit. The `Capability` enum is `pub` from
  `chio-core-types`; adding a `Delegate` variant is breaking unless
  gated. Mitigation: the variant lives behind `cfg(feature = "delegation_v2")`
  in the consumer crate; trajectory-2 M07 adapters opt in explicitly.

### P4 - Formal sweep: Lean + Apalache + Kani

- `M04.P4.T1` Land `formal/lean4/Chio/Chio/Capability/Delegation.lean`
  with skeleton and the four theorem statements (no proofs yet). Wire
  into `lakefile.lean` so `lake build` discovers it.
- `M04.P4.T2` Prove theorems 1 and 2 (`delegate_no_widen`,
  `attenuation_monotone`). These extend the existing
  `Proofs/Monotonicity.lean` results to the recursive case.
- `M04.P4.T3` Prove theorems 3 and 4 (`revocation_is_cut`,
  `compose_preserves_algebra`). Theorem 3 imports
  `Core/Revocation.lean`; theorem 4 imports `Spec/Properties.lean`.
- `M04.P4.T4` Land `formal/tla/DelegationDepthBound.tla` and
  `MCDelegationDepthBound.cfg`. Three safety invariants
  (`DepthBoundedByRoot`, `AttenuatedAtEachStep`,
  `RevokedSubtreeNotObservable`). Wire into the `formal-tla` PR job.
- `M04.P4.T5` Add 4 Kani harnesses to
  `crates/chio-kernel-core/src/kani_public_harnesses.rs` and update
  `formal/rust-verification/kani-public-harnesses.toml` to 14 covered
  symbols. Harness names: `verify_delegate_no_widen`,
  `verify_delegation_receipt_canonical`,
  `verify_revocation_view_freshness`,
  `verify_oracle_inclusion_soundness`. Cap is 14; do not exceed.
- `M04.P4.T6` Add `RevocationFreshness` invariant to the existing
  `formal/tla/RevocationPropagation.tla` (additive only; preserves all
  existing invariant names). Update `formal/MAPPING.md` with the new
  rows. Update `formal/proof-manifest.toml`.

### P5 - End-to-end acceptance and feature-flag flip

- `M04.P5.T1` 3-tier swarm acceptance test in
  `crates/chio-revocation-oracle/tests/swarm_revocation_e2e.rs`. Spins
  up planner, coder, tester as separate kernels; revoking the planner
  cap kills both children mid-call. Median latency from revoke to deny
  receipt < 500 ms across 100 trials.
- `M04.P5.T2` Receipt-chain proof: after the swarm test, walk the
  receipt log and assert that every allow receipt issued after the
  revoke timestamp is signed against an oracle root with
  `seen_epoch < revoke_epoch` (these are the legitimate
  causal-allow-before-revoke histories admitted by trajectory-1 M03's
  `NoAllowAfterRevoke`); no allow receipt has `seen_epoch >=
  revoke_epoch`.
- `M04.P5.T3` Flip `delegation_v2` to default ON in
  `crates/chio-kernel/Cargo.toml`. Land migration note at
  `docs/migrations/M04-delegation-v2.md`.
- `M04.P5.T4` Final audit-doc pass: record final counts (14 Kani
  harnesses, 2 TLA modules, 4 Lean delegation theorems, oracle LoC,
  median revoke-to-deny latency).
- `M04.P5.T5` Update `formal/assumptions.toml`: narrow
  `ASSUME-NETWORK-TRANSPORT` if the gossip path's signed-root delivery
  invariant in `RevocationFreshness` discharges the cross-peer
  ordering claim; otherwise leave untouched. Sign-off requires the
  `formal-verification` owner per trajectory-1 M03's discipline.

Ticket sizing per phase:
- P0: 4 tickets, 0.25-0.5 days each.
- P1: 6 tickets, 0.5-2 days each.
- P2: 6 tickets, 1-2 days each.
- P3: 5 tickets, 1-2 days each.
- P4: 6 tickets, 0.5-2 days each.
- P5: 5 tickets, 0.5-1.5 days each.

## Cross-milestone interactions

Hard deps on artefacts (named, not just by milestone):

- trajectory-1 M03 (`.planning/trajectory/03-capability-algebra-properties.md`):
  the 18 named proptest invariants and 10 Kani harnesses are the
  baseline this milestone extends. Specifically, the named invariants
  `validate_attenuation_monotonic_under_chain_extension` and
  `delegation_depth_bounded_by_root` (in
  `crates/chio-core-types/tests/property_capability_algebra.rs`) and the
  Kani harness `verify_delegation_chain_step` are the load-bearing
  baseline for theorems 1, 2, and 4.
- trajectory-1 M03's `formal/tla/RevocationPropagation.tla`. This
  milestone adds an invariant; it does not replace the module.
- trajectory-1 M05 async kernel (`crates/chio-kernel/src/kernel/mod.rs`
  post-async-migration) so the oracle freshness check does not block
  dispatch.
- trajectory-1 M03 `formal/MAPPING.md` and `formal/proof-manifest.toml`.
  We extend both.
- trajectory-2 M03 PQ-hybrid surface in `chio-attest-verify`. Soft dep
  via `soft_deps` string sentence; tickets do not hard-block on M03
  ticket IDs because both milestones are in the same wave. Intra-wave
  ordering is enforced by the cross-freeze invariant in
  `freezes.yml` ("m03-attest-verify-pivot must close before
  m04-revocation-oracle-pivot's end_trigger so revocation roots can be
  PQ-signed"); see the carrying soft_dep on M04.P1.T3.
- trajectory-2 M06 `CanonicalBytes` newtype. Soft dep; the
  delegation-receipt envelope uses it but degrades cleanly to
  `Vec<u8>` if M06 lands later.

Soft deps and sibling consumers:

- trajectory-2 M09 economic layer consumes the `Capability::Delegate`
  primitive to attribute revenue across kernels. This milestone owns
  the primitive; M09 owns the attribution.
- trajectory-2 M10 hardware custody binds passkey assertions to
  audience-bound capabilities; the binding is a delegation shape.
- trajectory-2 M07 framework adapters opt into `delegation_v2`
  explicitly.

## Risks and mitigations

- **Sparse-Merkle insertion p99 blows past 200 us at 10K subjects.**
  Mitigation: P1.T6 lands the bench gate before P1.T2 ships the real
  backend; if the gate is red, drop to a hashed-list fallback for the
  first epoch and re-attack the tree backend in a follow-on milestone.
  Acceptance latency target (P5.T1) is 500 ms median; oracle insert
  latency need not be the bottleneck if gossip is.
- **Federation gossip storm under high revoke rate.** A cluster with N
  peers issuing R revokes per second produces O(N*R) gossip messages.
  Mitigation: P2.T2 batches roots per epoch tick (default 250 ms) so
  message rate is bounded by epoch frequency, not revoke frequency.
  Configuration knob; fail-closed default at 250 ms.
- **Lean theorem 3 (`revocation_is_cut`) requires a graph-theoretic
  development that does not exist in the current Lean modules.**
  Mitigation: P4.T3 budgets 2 days for the auxiliary graph theory; if
  the proof exceeds budget, the theorem ships as `axiom` with a
  documented `formal/assumptions.toml` entry and is reattacked in a
  follow-on. The proptest invariant
  `delegate_revoked_parent_revokes_children` covers the property
  empirically in the meantime.
- **Apalache state-space blowup on `DelegationDepthBound.tla`.**
  Mitigation: bound `DEPTH_MAX = 4` and `PEERS = 3` in the PR config;
  larger configs run nightly only. Mirrors trajectory-1 M03's pattern.
- **`Capability` enum addition is breaking for downstream SDK
  consumers.** Mitigation: the `Delegate` variant is gated behind
  `delegation_v2` and the public re-export is feature-gated. Migration
  note in P5.T3 documents the upgrade path. This is consistent with
  trajectory-1 M05's `legacy-sync` pattern.
- **Kani harness budget creep above 14.** Mitigation: P4.T5 documents
  the cap in the audit doc. Future delegation properties land as
  nightly-only or private harnesses; the public PR set is gated at 14.
- **PQ-signed root throughput.** ML-DSA-65 sign is ~10x slower than
  Ed25519. Mitigation: roots are signed once per epoch (default 250
  ms), not once per insert; a 4-core node easily sustains 4 PQ signs
  per second. Bench gate confirms.

## Success criteria

- `crates/chio-revocation-oracle/` exists with non-trivial
  `lib.rs`, signed epoch-root path, and 4+ named proptest invariants
  green at `PROPTEST_CASES=256` on PR.
- Federation gossip path delivers oracle inserts to a remote verifier
  within 500 ms median across 100 trials (P2.T5 integration test green).
- 4 Lean theorems in `formal/lean4/Chio/Chio/Capability/Delegation.lean`
  build under `lake build` in CI. Theorem 3 may ship as `axiom` with a
  documented assumption entry; the other three must be `theorem` with
  closed proofs.
- `formal/tla/DelegationDepthBound.tla` and `MCDelegationDepthBound.cfg`
  exist; PR `formal-tla` job runs
  `apalache-mc check --inv=DepthBoundedByRoot
  --inv=AttenuatedAtEachStep --inv=RevokedSubtreeNotObservable
  --length=10` green.
- `formal/rust-verification/kani-public-harnesses.toml`
  `covered_symbols` lists exactly 14 entries (10 baseline + 4 new).
- `formal/MAPPING.md` has new rows for delegation theorems and
  oracle invariants. `scripts/check-mapping.sh` exits 0.
- 3-tier swarm acceptance test (P5.T1) green; median revoke-to-deny
  latency < 500 ms across 100 trials on the reference 4-core Linux
  runner.
- `delegation_v2` feature default-on in `crates/chio-kernel/Cargo.toml`
  after P5.T3.
- Audit doc `.planning/audits/M04-delegation-revocation.md` final pass
  with starting and ending counts, latency numbers, and the
  `assumptions.toml` ledger updated (or explicitly documented as
  unchanged).
- `cargo test --workspace`, `cargo clippy --workspace -- -D warnings`,
  `cargo fmt --all -- --check`, and `lake build` are all green on the
  P5 merge commit.
