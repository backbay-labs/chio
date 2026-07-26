# FV-D1: Distributed-time revocation propagation model

Status: Implemented (2026-07-15; local evidence complete, hosted temporal streak pending)
Theme: D - Widen the verified frontier
Effort: L
Depends on: none
Feeds: scopes ASSUME-NETWORK-TRANSPORT without retiring it; [FV-E5](FV-E5-lane-ratchets.md) (temporal-lane promotion), [FV-E2](FV-E2-counterexample-regression-pipeline.md) (counterexample retention)
Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md) (G4, G5), `formal/MAPPING.md`, `formal/assumptions.toml`

## Summary

`formal/proof-manifest.toml` states that ASSUME-NETWORK-TRANSPORT cannot be discharged by the local freshness model alone. This work supplies the missing distributed model: signer-pinned revocation gossip over lossy, reordering, duplicating channels with bounded clock skew, per-authority high-water marks, and explicit partitions. The deliverables are a preserved local safety invariant, wall-clock stale-evaluation denial, eventual observation under fair gossip, and partition suspend/resume semantics. The implementation registers the smaller partition-bound and gossip-fairness assumption and stages the retirement walk, but it does not retire ASSUME-NETWORK-TRANSPORT before same-revision bounded, temporal, negative, and production-projection evidence exists. The model is grounded action-by-action in `crates/trust/chio-federation/src/revocation_gossip.rs`, which remains the semantic source of truth.

## Motivation and evidence

- The deferral is explicit and machine-adjacent. `formal/proof-manifest.toml` L177-198: `RevocationFreshness` (~L344 of the TLA file) constrains `rev_epoch[a][c] < clock` against a SINGLE shared clock variable; it "does NOT model multiple gossip peers, vector-clock-ordered delivery, or any other cross-peer ordering primitive". The manifest anchor `m04_p5_t5_assumptions_decision = "ASSUME-NETWORK-TRANSPORT-unchanged"` (L197) is the open item this plan closes.
- The assumption just became load-bearing. The iroh federation transport crate (`chio-federation-transport-iroh`, transport-only seam, 4 lanes) landed as launch scope (PR #960), so revocation roots now actually cross a real network between kernels. An unbounded staleness window between a revoke at authority A and observation at authority B is now a production security property, not a modeling nicety.
- The existing model cannot express the failure modes the assumption covers. Verified in `formal/tla/RevocationPropagation.tla` this session: `Propagate(m)` (L209-216) consumes each message exactly once from the unordered `pending` set, so duplication is unrepresentable; `WF_vars(PropagateAny)` (L283-286) forces eventual delivery, so loss is unrepresentable; `clock` is one shared integer (L136), so skew is unrepresentable; there are no partitions.
- The local model's `RevocationEventuallySeen` property relies on model-only `WF_vars(PropagateAny)`. `formal/MAPPING.md` records that boundary and states that `ASSUME-NETWORK-TRANSPORT` remains audited without promising delivery. A distributed model must replace this model-only condition with a registered operational fairness assumption before narrowing the transport boundary.
- The operational mitigation is real but informal. Signer pinning in `crates/trust/chio-federation/src/revocation_gossip.rs` is named by the manifest as the current mitigation; the model makes invalid-frame rejection explicit and states convergence only under registered weak fairness.

## Current state

TLA side (`formal/tla/RevocationPropagation.tla`, 410 lines, read in full):

- Actions: `Attenuate` (L181), `Revoke` (L194, broadcasts one message per other authority and stamps `rev_epoch` with the shared clock), `Propagate` (L209, installs strictly newer epochs), `Evaluate` (L225, allow iff `rev_epoch[a][c] = 0`), `PropagateAny` (L246, the named-action workaround for Apalache PDR-017 fairness encoding).
- Invariants: `NoAllowAfterRevoke` (L302), `MonotoneLog` (L314), `AttenuationPreserving` (L326), `RevocationFreshness` (L344), aggregated as `SafetyInv` (L354). Liveness: `RevocationEventuallySeen` (L407), checked via `--temporal=` only in the nightly lane.
- CI: `apalache-safety.yml` runs the safety invariants PR-time, path-scoped, over the cfg/spec pairs listed at L71-72 of the workflow. `apalache-temporal.yml` is nightly/manual only and its header (L10-12) forbids promotion "until the underlying property is fixed and the run is reliably green".
- Toolchain: Apalache 0.50.1 pinned (`tools/install-apalache.sh` L14). Existing specs avoid recursive set definitions; `RevocationCutCompleteness` (under `formal/apalache/`) maintains an incremental descendants closure as state to keep SMT depth 1. Any new spec inherits both constraints.

Rust side (`crates/trust/chio-federation/src/revocation_gossip.rs`, 1019 lines, read in full):

- `RevocationRootGossip` (L52) carries a `SignedEpochRoot` plus a pinned `signer_id` and `ts_unix_ms`; `validate_envelope` (L113) drops schema, epoch-mirror, and signer-id mismatches fail-closed.
- `RevocationGossipPushQueue` (L242): per-peer FIFO with epoch coalescing in `enqueue_signed_root` (L295: older-epoch roots are dropped, same-epoch replaced, strictly-higher epochs evict everything queued below them, capacity eviction pops the oldest); `flush_batches_at` (L323) drains per-peer batches.
- Catch-up: `RevocationCatchupRequest` (L376, range capped at `REVOCATION_CATCHUP_MAX_EPOCHS = 4096`, L191), `RevocationCatchupResponse::validate_response` (L459, strictly contiguous ascending epochs, `CatchupGap` otherwise), `respond_to_catchup` (L503, serves the contiguous suffix it retains and never fabricates, per the `RevocationCatchupHistory` contract at L487-493).
- Receiver merge point: signature verification against the pinned signer, then `RevocationView::install_if_newer` (named in `formal/proof-manifest.toml` covered_rust_symbols, L81).

## Design

### Model shape

New spec `DistributedRevocation` (companion to, not a replacement of, `RevocationPropagation.tla`; the existing spec keeps covering the local revocation gate).

State, per authority `a` in `AUTHS` and origin authority `o`:

- `now[a]` : per-authority local clock, advanced independently but constrained by `\A a, b : now[a] - now[b] <= SKEW` (bounded skew replaces the single shared `clock`).
- `hwm[a][o]` : per-authority, per-origin revocation high-water mark (the model image of `RevocationView::install_if_newer` plus the strictly-monotone catch-up validation).
- `targetRevokedEpoch[o]` : the first origin epoch that revokes the modeled
  target. Root advancement without target revocation permits the production
  case where a fresh nonzero snapshot allows an unrelated subject.
- `queue[a][b]` : the sender-side coalesced push queue (image of `RevocationGossipPushQueue`).
- `chan[a][b]` : in-flight frames as a function `Frame -> Nat` (a bag encoded as a counting function, since Apalache 0.50.1 handles functions better than the Bags module), so duplication is a counter increment and loss is a decrement without delivery.
- `part` : symmetric set of blocked authority pairs (partition relation), maintained incrementally as state (same discipline as the `RevocationCutCompleteness` closure) so connectivity checks stay SMT-shallow.
- `epochIssuedAt[o][e]` and `viewIssuedAt[a][o]` : signed-root timestamps used
  by the production wall-clock freshness projection.
- `viewAuthentic[a][o]`, `allowRevoked[a][o]`, and `allowFresh[a][o]` : signer
  provenance and local revocation/freshness evidence recorded by installs and
  allow decisions.

Signer pinning and forgery: frames carry their origin. The concrete
`scripts/check-distributed-revocation-refinement.sh` gate exercises
`forged_root_is_rejected_by_pinned_signer`, while `formal/assumptions.toml`
ASSUME-ED25519 remains the cryptographic primitive boundary. `InjectForged`
accepts adversarial input at any modeled epoch and `RejectForged` consumes it
without changing a high-water mark or authenticity bit. The calibrated signer
mutation installs that frame and falsifies `SignerPinnedHighWater`, including
when its epoch does not exceed the genuine origin epoch.

### Rust-to-action map

| Rust surface (`revocation_gossip.rs` unless noted) | Model action | Semantics carried over |
| --- | --- | --- |
| oracle epoch tick -> `enqueue_signed_root` (L295) | `QueueRoot(o)` | per-peer coalescing: queued epochs below the current origin epoch are discarded; only the max survives |
| `flush_batches_at` (L323) | `Send(o, b)` | moves the queued max epoch into `chan[o][b]` (increment) |
| transport (iroh lanes) | `Duplicate(f)`, `Lose(f)`, delivery choice | bag increment; bag decrement; delivery picks any in-flight frame (reordering is inherent) |
| verify + `RevocationView::install_if_newer` (kernel-core) | `Deliver(o, a, e)` | `hwm[a][o]' = max(hwm, e)`; strictly-older frames leave the view unchanged |
| `RevocationCatchupRequest::new` (L390) + `respond_to_catchup` (L503) + `validate_response` (L459) | `Catchup(a, o, o)` | direct-origin one-shot merge, enabled only when `(a,o)` is not in `part`; justified by the contiguous-suffix, signer-pinning, and never-fabricate contracts |
| kernel evaluate against local view | `Evaluate(a, c)` | allow only when no revocation is locally observed and the installed root timestamp passes the production wall-clock freshness predicate |
| `Revoke` at origin | `Revoke(o, revokesTarget)` | advances the origin epoch, optionally records the modeled target's first revoked epoch, records `now[o]` as the signed-root timestamp, and advances the origin's own view; `QueueRoot` performs fanout |
| network partition / heal | `Cut(S)`, `Heal(S)` | mutate `part`; `Cut` disables `Deliver`/`Catchup` across the cut, `Heal` re-enables |

### Properties

1. `ClockSkewBound` (safety, assumption-scoped). Independently advancing authority clocks remain within the configured pairwise skew bound.
2. `SignerPinnedHighWater` (safety, cryptography-scoped). Every installed root remains authentic and at or below the genuine pinned origin epoch.
3. `NoAllowAfterRevokeDistributed` (safety, preserved). Every allow receipt was issued when the issuing authority's own view had no observed revocation.
4. `StaleEvaluationDenied` (safety, production-grounded). An evaluation may allow only when the installed root timestamp is not in the future and its wall-clock age is within `FreshnessBound`. This mirrors the production freshness predicates. It does not bound raw evaluation count.
5. `RevocationEventuallyObservedDistributed` (liveness, nightly only). Under weak fairness on observation progress and partition healing, every revoke is eventually observed by every eventually-connected authority. `DistributedRevocationTemporal.tla` checks one arbitrary ordered pair. A separate bounded check maps one selected pair in the full temporal relation to that scalar spec at the PR constants; it is not an unbounded refinement across every authority pair. The module expands weak fairness into primitive temporal logic because Apalache 0.50.1 does not support `WF` or `ENABLED` in a checked temporal property.
6. `PartitionSuspendResume` (safety plus conditional liveness). The safety
   invariant proves that a cut freezes the peer high-water mark and installed
   timestamp. Post-heal resumption is supplied separately by the scheduled
   temporal property and the deterministic catch-up schedule.

Property-to-lane summary (the deliberate design point: everything load-bearing is a safety invariant in the reliable lane):

| Property | Kind | Lane | Bounds (PR / nightly) |
| --- | --- | --- | --- |
| `ClockSkewBound` | behavioral safety aggregate | apalache-safety, PR | SKEW=2 at both constant sets |
| `SignerPinnedHighWater` | behavioral safety aggregate | apalache-safety, PR | AUTHS=2, EPOCH_MAX=3 / AUTHS=3, EPOCH_MAX=4 |
| `NoAllowAfterRevokeDistributed` | behavioral safety aggregate | apalache-safety, PR | AUTHS=2, EPOCH_MAX=3 / AUTHS=3, EPOCH_MAX=4 |
| `StaleEvaluationDenied` | behavioral safety aggregate | apalache-safety, PR | FRESHNESS=2, SKEW=2 at both bounds |
| `PartitionSuspendResume` | behavioral safety aggregate | apalache-safety, PR | PARTITION_BOUND=3 at both bounds |
| `DistributedDomainsOK` | exact initial function-domain shape | apalache-safety, PR | length 0 at both constant bounds |
| `RevocationEventuallyObservedDistributed` | liveness, `--temporal=` | apalache-temporal, scheduled, non-required | arbitrary ordered pair at EPOCH_MAX=3 and length 24; selected-pair full-model refinement at two authorities, three epochs, and length 5; explicit fair witness at length 3 |
| Production schedule traces | executable ITF validation | apalache-safety plus strict proof report | four deterministic scenarios |

### Assumption narrowing (the retirement walk, staged precisely)

`formal/assumptions.toml` states the protocol: retirement requires named
model evidence plus a concrete implementation-refinement gate, and the result
is mirrored in `formal/proof-manifest.toml` `discharged_assumptions`. The
implementation stages these edits, but does not claim retirement:

1. Add `ASSUME-GOSSIP-FAIRNESS-PARTITION-BOUND` to `assumptions` and `required_assumption_ids`. It names recurring connected opportunities under weak fairness, bounded clock skew, and operator-bounded partition healing. It assumes no finite delivery-step or evaluation-count bound; loss, duplication, reordering, and invalid frames remain modeled.
2. Keep `ASSUME-NETWORK-TRANSPORT` required. Authentication and fairness/partition scope are narrowed in prose, but no retired or discharged row is added.
3. Leave `formal/proof-manifest.toml` `discharged_assumptions` empty. Record
   the scoped model and the rejected count claim in notes, then update the
   decision anchor to pending narrowing rather than discharge.
4. Update `docs/reference/CLAIM_REGISTRY.md`: keep ASSUME-NETWORK-TRANSPORT approved with scope, add the new fairness assumption, and prohibit an end-to-end or finite-evaluation-count claim.
5. Update `formal/MAPPING.md`: rows for the new invariants, and replace the existing model-only fairness boundary with the newly registered operational assumption where the distributed liveness property applies.

### Toolchain decision: handwritten TLA+

Options weighed:

- Plain TLA+: zero new toolchain; but the channel-bag, per-authority-clock model is the exact spec shape where untyped TLA+ errors (function vs operator, record shape drift) burn review time, and there is no way to unit-test the model before model checking.
- Quint (Informal Systems): typed front-end compiling to Apalache-checkable TLA; `quint run` gives executable random simulations that double as fast model tests and produce concrete traces for [FV-E2](FV-E2-counterexample-regression-pipeline.md). Cost: an npm-distributed CLI is a new pinned toolchain in a supply-chain-strict repo (the cargo-vet human gate discipline from the iroh work applies), and Quint pins its own compatible Apalache range, which must agree with the repo's 0.50.1 pin.

Decision: use handwritten TLA+. Apalache 0.50.1 consumes the reviewed artifact
directly. Quint would add an npm supply-chain boundary and a generated drift
lane without changing the checked semantics. The TLA+ header records this
decision.

## Implementation plan

1. Semantics extraction and review packet. Write the Rust-to-action table into the new spec's header comment; add `formal/MAPPING.md` rows (placeholder-marked until the invariants exist). Files: `formal/tla/generated/DistributedRevocation.tla` header (or `formal/tla/DistributedRevocation.tla` on fallback), `formal/MAPPING.md`.
2. Handwritten model. Add the bounded PR, scheduled, and temporal configs.
   Deterministic production schedules generate exact trace-check modules and
   replace the proposed Quint simulations.
3. Safety lane. Files: `formal/tla/MCDistributedRevocation.cfg` (PR bounds: AUTHS=2, EPOCH_MAX=3, FRESHNESS=2, SKEW=2; scheduled bounds larger) and exact-domain configs. The depth-bounded lane checks `BehavioralSafetyInv`; `DistributedDomainsOK` checks exact function domains plus partition and origin consistency in `Init`. Transition-domain induction is not claimed because Apalache 0.50.1 cannot initialize the model's arbitrary nested function sets.
4. Temporal lane. Files: `formal/tla/MCDistributedRevocationTemporal.cfg`, the bounded full-to-scalar refinement module and config, and the explicit fair-observation witness module and config. `scripts/check-distributed-revocation-temporal.sh` runs all three from the existing `.github/workflows/apalache-temporal.yml` job. The lane stays scheduled/manual and non-required per its own header; promotion is [FV-E5](FV-E5-lane-ratchets.md)'s ratchet, not this plan's.
5. Falsifiability evidence. Files: `formal/apalache/_negative_tests/DistributedRevocation_*.tla` broken variants (target-revocation check skipped, signer pin skipped so a forged root installs, skew bound removed, catch-up allowed across a partition, and freshness skipped). Each variant must produce a counterexample, archived per [FV-E2](FV-E2-counterexample-regression-pipeline.md).
6. Production-schedule projection gate. Add
   `crates/trust/chio-federation/tests/distributed_revocation_refinement.rs`
   with deterministic loss, duplication, reorder, partition-heal, and catch-up
   schedules over the production gossip queue, validation, and
   `RevocationView::install_if_newer` path. Emit the observed actions as ITF
   and check their exact scalar projections with
   `formal/tla/trace/TraceCheckDistributedRevocation.tla`.
   `scripts/check-distributed-revocation-refinement.sh` runs the Rust
   scenarios and trace check fail-closed.
7. Assumption scope registration. Update `formal/assumptions.toml`, `formal/proof-manifest.toml`, `docs/reference/CLAIM_REGISTRY.md`, and `formal/MAPPING.md` without adding a discharged-assumption row.

## CI and gating changes

- `apalache-safety.yml`: the behavioral and exact-initial-domain checks are PR-path-scoped on `formal/tla/**`. Exact domain shape uses the default encoding at length 0. Scheduled runs retain length 6 while expanding behavioral safety to AUTHS=3 and EPOCH_MAX=4, then repeat the initial-shape check at those constants. Jointly increasing width and path depth to length 8 exceeds the one-hour scheduled budget and is not claimed.
- `apalache-temporal.yml`: the existing non-required liveness job checks the
  bounded refinement, non-vacuity witness, and distributed property after the
  local property. The header's do-not-promote rule remains unchanged.
- `formal/proof-manifest.toml` adds
  `scripts/check-distributed-revocation-refinement.sh` as a strict gate. No
  compiler-drift job is needed for handwritten TLA+.

## Acceptance criteria

- [x] `DistributedRevocation` models loss, duplication, reordering (bag channels), bounded skew (`SKEW`), per-origin high-water marks, coalescing queues, catch-up, and partitions, with the Rust-to-action table in the spec header matching `revocation_gossip.rs` functions by name.
- [x] `ClockSkewBound` and `SignerPinnedHighWater` hold at PR and scheduled bounds, and the registered unbounded-skew and forged-signer mutations falsify them.
- [x] `NoAllowAfterRevokeDistributed` holds in the distributed model at PR and scheduled bounds.
- [x] `StaleEvaluationDenied` holds as a safety invariant at PR and scheduled bounds and matches the production wall-clock freshness predicate.
- [x] `RejectedRawEvaluationCountBound` produces a calibrated counterexample under scheduler delay or loss and repeated same-tick evaluation; the finite raw-evaluation claim remains explicitly unproved.
- [x] `PartitionSuspendResume` freeze safety holds across repeated cut/heal
  cycles; scheduled temporal evidence and the production schedule separately
  establish conditional post-heal catch-up.
- [ ] `RevocationEventuallyObservedDistributed` is checked in the nightly temporal lane; its flake rate is recorded for [FV-E5](FV-E5-lane-ratchets.md).
- [x] All negative-test variants produce counterexamples (falsifiability shown).
- [x] `scripts/check-distributed-revocation-refinement.sh` drives production
  gossip and revocation-view code through deterministic loss, duplicate,
  reorder, partition-heal, and catch-up scenarios. Its fail-closed validator
  checks every adjacent projected action, and pinned Apalache checks every
  exact emitted scalar projection. This is not a full-state refinement proof.
- [x] The narrower authentication plus fairness/partition contract is registered, `ASSUME-NETWORK-TRANSPORT` remains required, and CLAIM_REGISTRY plus MAPPING prohibit stronger end-to-end and finite-evaluation-count wording.
- [x] Quint decision recorded: either the committed-compiled-TLA pipeline is in place with a pinned installer, or the fallback to hand-written TLA+ is documented in the spec header.

## Risks and mitigations

- State explosion from bag channels and per-authority clocks. Mitigate: counting-function encoding instead of the Bags module; small PR bounds with nightly escalation; cap in-flight frames per channel with a `CHAN_CAP` model-checking bound. The sender queue and catch-up caps do not establish a production bound on transport replay or duplication.
- The temporal lane is known-unreliable, and this plan adds to it. Mitigate: the load-bearing wall-clock freshness denial is a safety invariant; liveness is conditional and corroborating, not gating.
- TLA+ is untyped. Mitigate: static model-shape checks, bounded positive runs,
  calibrated negative witnesses, and the production ITF projection all fail
  closed.
- Model-code drift as `revocation_gossip.rs` evolves. Mitigate: MAPPING.md rows are enforced by `scripts/check-mapping.sh` name-grep; the Rust-to-action table names concrete functions so review of a gossip change has a checklist; [FV-A4](FV-A4-mirror-drift-hashes.md) abstraction anchors already force review when the registered gossip items change.
- Narrowed assumption still too strong for reality (relay outages; n0 free relays are only funded through 2026-12-31 for the iroh transport). Mitigate: the fairness assumption is written as eventually-heal with an operator-declared bound, which an operator can satisfy with self-hosted relays; the model's partition semantics make the degraded mode explicit instead of hidden.

## Resolved questions

- The original `B` raw-evaluation question is resolved by rejection. The
  production contract has wall-clock units and no evaluation-rate limiter.
- Catch-up uses a direct-origin one-shot max merge. Explicit request and
  contiguous-response validation remain visible in the production schedule.
- Pheromone gossip is explicitly out of scope.
- `RevocationPropagation.tla` remains as the minimal local-gate model.

## Decisions

- The local temporal lane is complete: the full-to-scalar projection passed at
  length 5 in 811.737 seconds, the explicit fair witness passed at length 3 in
  1.991 seconds, and arbitrary-pair eventual observation passed at length 24
  in 429.525 seconds.
- The legacy unbounded eventuality check reached its 3,602-second timeout
  without an invariant or tool error. It remains non-evidence and is not used
  to promote the hosted lane.
- `ASSUME-NETWORK-TRANSPORT` remains registered. Local model completion does
  not authenticate production transport delivery or justify assumption
  retirement.

- Handwritten TLA+ is the artifact of record. The Quint pilot was rejected
  because the pinned Apalache checker already accepts the required model and
  an npm compiler would add a second supply-chain boundary without improving
  the checked artifact.
- `StaleEvaluationDenied` mirrors the production wall-clock freshness
  predicate. Production does not rate-limit evaluations. Weak fairness cannot
  prove a finite raw-evaluation bound, so `RejectedRawEvaluationCountBound`
  is deliberately outside `SafetyInv` and has a registered calibrated witness.
- Catch-up is a one-shot high-water merge in the model. The production
  projection schedule still drives the explicit bounded request, contiguous
  response validation, pinned signature verification, and ascending
  `RevocationView::install_if_newer` calls.
- A cut freezes the affected view high-water mark and timestamp. Loss and duplication may
  continue in channel state, but delivery and catch-up cannot mutate the cut
  peer until `Heal` restores connectivity.
- `partitionTicks` advances with each endpoint's local clock. At the declared
  partition bound that endpoint's clock cannot advance again until `Heal`;
  this is the explicit model image of the operator-bounded partition
  assumption, not production retry logic.
- Exact initial shape and behavioral safety use separate checks.
  `DistributedDomainsOK` checks the concrete `Init` function domains plus
  partition and origin consistency at length 0. The normal PR and scheduled
  behaviors retain their depth bounds for `BehavioralSafetyInv`. No
  arbitrary-state domain induction is claimed because Apalache 0.50.1 cannot
  initialize the model's nested function sets for that proof shape.
- `DistributedRevocationTemporal.tla` checks one arbitrary ordered pair with
  revoke, observe, cut-once, heal, and explicit stutter actions. Weak fairness
  is expanded as primitive temporal logic over exact state-derived enabledness
  because Apalache 0.50.1 rejects `WF` and `ENABLED` in temporal properties.
  Omitted actions are irrelevant to the liveness projection or can only
  advance observation. The full safety model permits repeated cut/heal cycles
  and retains every transport action.
- `DistributedRevocationTemporalRefinement.tla` maps one selected ordered pair
  from the full model's temporal relation into the scalar spec. The scheduled
  length-5 check establishes that bounded mapping at the PR constants only.
  `DistributedRevocationTemporalWitness.tla` executes revoke, observe, then an
  infinite-stutter-capable state in which both fairness enabledness predicates
  are false, preventing a purely vacuous fairness antecedent from going
  unnoticed.
- Per-origin matrices are a distributed abstraction. The production schedule
  gate exercises one pinned origin against the shipped single-snapshot
  `RevocationView`; multi-origin view isolation is not claimed as production
  refinement evidence.
- The revocation model does not cover pheromone gossip.
- The small local `RevocationPropagation` model remains in place because it
  cheaply checks the local gate independently of distributed channel state.
- `ASSUME-GOSSIP-FAIRNESS-PARTITION-BOUND` is registered alongside
  `ASSUME-NETWORK-TRANSPORT`. Neither is retired or discharged by this model.

## Validation status

- Static implementation is complete: distributed model and configs, five
  calibrated mutations plus one rejected-claim witness, production schedule tests, ITF validator, strict
  projection gate, safety and temporal workflow wiring, mapping, assumptions,
  manifest, and claim controls.
- PR exact-initial-shape and depth-6 behavioral Apalache checks pass with
  Apalache 0.50.1. The expanded scheduled domain check passes at length 0 and
  the three-authority, four-epoch behavioral check passes at length 6. The
  arbitrary-pair temporal projection passes at length 24 with explicit
  stuttering. The selected-pair refinement passes at length 5 and the explicit
  fair-observation witness passes at length 3.
- All 16 registered negative entries reproduce their exact invariant violation
  and a retained ITF artifact, including the six distributed entries.
- The temporal lane flake rate is unmeasured and remains frozen in
  `releases.toml`.
- The strict production trace-projection run passes all four Rust schedules,
  both kernel freshness tests, ITF validation, and four exact projected TLA
  checks.
- No assumption retirement is claimed.

## Manifest and registry updates

- `formal/assumptions.toml`: add `ASSUME-GOSSIP-FAIRNESS-PARTITION-BOUND` as required and keep `ASSUME-NETWORK-TRANSPORT` required; do not retire either.
- `formal/proof-manifest.toml`: record pending narrowing, leave `discharged_assumptions` empty, and add the production-projection script to `gate_commands`.
- `formal/MAPPING.md`: rows for each new named invariant and the liveness property (source, Rust path constrained, assumption discharge, one-liner); replace the local model-only fairness boundary with the registered distributed assumption where applicable.
- `formal/theorem-inventory.json`: no Lean changes required by this plan; add cross-reference notes only if a Lean-side freshness lemma is later tied in.
- `docs/reference/CLAIM_REGISTRY.md`: adjust the ASSUME-NETWORK-TRANSPORT row and add the replacement assumption; both edits ride the same PR as the assumptions.toml change because CLAIM_REGISTRY is a claim-gate input (`proof-manifest.toml` L113-119).
