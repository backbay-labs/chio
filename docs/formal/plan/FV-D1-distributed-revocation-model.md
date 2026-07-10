# FV-D1: Distributed-time revocation propagation model

Status: Proposed (2026-07-09)
Theme: D - Widen the verified frontier
Effort: L
Depends on: none
Feeds: narrows ASSUME-NETWORK-TRANSPORT (the discharge the proof manifest is explicitly waiting for); [FV-E5](FV-E5-lane-ratchets.md) (temporal-lane promotion), [FV-E2](FV-E2-counterexample-regression-pipeline.md) (counterexample retention)
Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md) (G4, G5), [FV-A2](FV-A2-aeneas-generated-equivalence.md) (committed-generated-artifact pattern), `formal/MAPPING.md`, `formal/assumptions.toml`

## Summary

`formal/proof-manifest.toml` (L173-198) states that ASSUME-NETWORK-TRANSPORT cannot be discharged today: `RevocationFreshness` in `formal/tla/RevocationPropagation.tla` covers only the local freshness gate, and "the formal discharge is deferred until a distributed-time TLA model ships". This document specifies that model: signer-pinned revocation gossip over lossy, reordering, duplicating channels with bounded clock skew, per-authority high-water marks, and explicit partitions. The deliverables are a preserved local safety invariant, a bounded-staleness property (the end-to-end form of RevocationFreshness), eventual observation under fair gossip, and partition suspend/resume semantics. The outcome NARROWS the assumption rather than retiring it outright: ASSUME-NETWORK-TRANSPORT is replaced by a smaller, explicitly registered partition-bound and gossip-fairness assumption. The model is grounded action-by-action in `crates/trust/chio-federation/src/revocation_gossip.rs`, which this plan reads as the semantic source of truth.

## Motivation and evidence

- The deferral is explicit and machine-adjacent. `formal/proof-manifest.toml` L177-198: `RevocationFreshness` (~L311 of the TLA file) constrains `rev_epoch[a][c] < clock` against a SINGLE shared clock variable; it "does NOT model multiple gossip peers, vector-clock-ordered delivery, or any other cross-peer ordering primitive". The manifest anchor `m04_p5_t5_assumptions_decision = "ASSUME-NETWORK-TRANSPORT-unchanged"` (L197) is the open item this plan closes.
- The assumption just became load-bearing. The iroh federation transport crate (`chio-federation-transport-iroh`, transport-only seam, 4 lanes) landed as launch scope (PR #960), so revocation roots now actually cross a real network between kernels. An unbounded staleness window between a revoke at authority A and observation at authority B is now a production security property, not a modeling nicety.
- The existing model cannot express the failure modes the assumption covers. Verified in `formal/tla/RevocationPropagation.tla` this session: `Propagate(m)` (L176-183) consumes each message exactly once from the unordered `pending` set, so duplication is unrepresentable; `WF_vars(PropagateAny)` (L250-253) forces eventual delivery, so loss is unrepresentable; `clock` is one shared integer (L103), so skew is unrepresentable; there are no partitions.
- Registry drift already exists here. `formal/MAPPING.md` cites "ASSUME-PROPAGATE-FAIRNESS (weak fairness on `Propagate`)" in the `RevocationEventuallySeen` row, but `formal/assumptions.toml` (44 lines, read in full this session) defines no such ID. The fairness assumption this model makes explicit must be registered for real, which also repairs that dangling reference (a G4 instance).
- The operational mitigation is real but informal. Signer pinning in `crates/trust/chio-federation/src/revocation_gossip.rs` is named by the manifest as the current mitigation; the model turns "pinning plus catch-up eventually converges within a bound" from folklore into a checked property.

## Current state

TLA side (`formal/tla/RevocationPropagation.tla`, 377 lines, read in full):

- Actions: `Attenuate` (L148), `Revoke` (L161, broadcasts one message per other authority and stamps `rev_epoch` with the shared clock), `Propagate` (L176, installs strictly newer epochs), `Evaluate` (L192, allow iff `rev_epoch[a][c] = 0`), `PropagateAny` (L213, the named-action workaround for Apalache PDR-017 fairness encoding).
- Invariants: `NoAllowAfterRevoke` (L269), `MonotoneLog` (L281), `AttenuationPreserving` (L293), `RevocationFreshness` (L311), aggregated as `SafetyInv` (L321). Liveness: `RevocationEventuallySeen` (L374), checked via `--temporal=` only in the nightly lane.
- CI: `apalache-safety.yml` runs the safety invariants PR-time, path-scoped, over the cfg/spec pairs listed at L71-72 of the workflow. `apalache-temporal.yml` is nightly/manual only and its header (L10-12) forbids promotion "until the underlying property is fixed and the run is reliably green".
- Toolchain: Apalache 0.50.1 pinned (`tools/install-apalache.sh` L14). Existing specs avoid recursive set definitions; `RevocationCutCompleteness` (under `formal/apalache/`) maintains an incremental descendants closure as state to keep SMT depth 1. Any new spec inherits both constraints.

Rust side (`crates/trust/chio-federation/src/revocation_gossip.rs`, 1019 lines, read in full):

- `RevocationRootGossip` (L52) carries a `SignedEpochRoot` plus a pinned `signer_id` and `ts_unix_ms`; `validate_envelope` (L113) drops schema, epoch-mirror, and signer-id mismatches fail-closed.
- `RevocationGossipPushQueue` (L242): per-peer FIFO with epoch coalescing in `enqueue_signed_root` (L295: older-epoch roots are dropped, same-epoch replaced, strictly-higher epochs evict everything queued below them, capacity eviction pops the oldest); `flush_batches_at` (L323) drains per-peer batches.
- Catch-up: `RevocationCatchupRequest` (L376, range capped at `REVOCATION_CATCHUP_MAX_EPOCHS = 4096`, L191), `RevocationCatchupResponse::validate_response` (L459, strictly contiguous ascending epochs, `CatchupGap` otherwise), `respond_to_catchup` (L503, serves the contiguous suffix it retains and never fabricates, per the `RevocationCatchupHistory` contract at L487-493).
- Receiver merge point: signature verification against the pinned signer, then `RevocationView::install_if_newer` (named in `formal/proof-manifest.toml` covered_rust_symbols, L81).

## Design

### Model shape

New spec `DistributedRevocation` (companion to, not a replacement of, `RevocationPropagation.tla`; the existing spec keeps covering the local-gate discharge already cited by RETIRED-SQLITE-CROSS-ROW evidence).

State, per authority `a` in `AUTHS` and origin authority `o`:

- `now[a]` : per-authority local clock, advanced independently but constrained by `\A a, b : now[a] - now[b] <= SKEW` (bounded skew replaces the single shared `clock`).
- `hwm[a][o]` : per-authority, per-origin revocation high-water mark (the model image of `RevocationView::install_if_newer` plus the strictly-monotone catch-up validation).
- `queue[a][b]` : the sender-side coalesced push queue (image of `RevocationGossipPushQueue`).
- `chan[a][b]` : in-flight frames as a function `Frame -> Nat` (a bag encoded as a counting function, since Apalache 0.50.1 handles functions better than the Bags module), so duplication is a counter increment and loss is a decrement without delivery.
- `part` : symmetric set of blocked authority pairs (partition relation), maintained incrementally as state (same discipline as the `RevocationCutCompleteness` closure) so connectivity checks stay SMT-shallow.
- `stale[a][o]` : bounded staleness counter, see below.
- `receipt_log[a]` : as today, for `NoAllowAfterRevoke`.

Signer pinning and forgery: frames carry their origin, and forgery is excluded by ASSUME-SIG-CHECK / ASSUME-ED25519 (both registered; `docs/reference/CLAIM_REGISTRY.md` L35-36). The model therefore only ever delivers well-signed frames; a tampered or unverifiable frame is the `Lose` action, because the Rust receiver drops it before `install_if_newer` (module doc, `revocation_gossip.rs` L7-10). This is the precise sense in which the narrowed assumption is smaller: the "not silently rewritten below signature checks" half of ASSUME-NETWORK-TRANSPORT collapses into the already-registered crypto assumptions plus a checked drop action.

### Rust-to-action map

| Rust surface (`revocation_gossip.rs` unless noted) | Model action | Semantics carried over |
| --- | --- | --- |
| oracle epoch tick -> `enqueue_signed_root` (L295) | `QueueRoot(o, e)` | per-peer coalescing: queued epochs strictly below `e` are discarded; only the max survives |
| `flush_batches_at` (L323) | `Send(o, b)` | moves the queued max epoch into `chan[o][b]` (increment) |
| transport (iroh lanes) | `Duplicate(f)`, `Lose(f)`, delivery choice | bag increment; bag decrement; delivery picks any in-flight frame (reordering is inherent) |
| verify + `RevocationView::install_if_newer` (kernel-core) | `Deliver(a, f)` | `hwm[a][f.origin]' = max(hwm, f.epoch)`; strictly-older frames absorbed |
| `RevocationCatchupRequest::new` (L390) + `respond_to_catchup` (L503) + `validate_response` (L459) | `Catchup(a, b, o)` | one-shot: `hwm[a][o]' = max(hwm[a][o], hwm[b][o])`, enabled only when `(a,b)` not in `part`; justified by the contiguous-suffix and never-fabricate contract |
| kernel evaluate against local view | `Evaluate(a, c)` | allow iff no revocation for `c` at or below `hwm[a][origin(c)]`; appends receipt; increments `stale[a][o]` for every origin with an unobserved revoke |
| `Revoke` at origin | `Revoke(o, c)` | stamps epoch from `now[o]`, enqueues to every subscribed peer |
| network partition / heal | `Cut(S)`, `Heal(S)` | mutate `part`; `Cut` disables `Deliver`/`Catchup` across the cut, `Heal` re-enables |

### Properties

1. `NoAllowAfterRevoke` (safety, preserved). Identical statement to the existing spec: every allow receipt was issued when the issuing authority's own view had no revocation. This is the local gate and must remain invariant under every new channel behavior; if the distributed model breaks it, the model (not the property) is wrong.
2. `BoundedStalenessInv` (safety, the load-bearing new claim). After `Revoke(o, c)` at epoch `e`, any correct authority `a` with `(a, o)` connected performs at most `B` `Evaluate` actions on capabilities from `o` before `hwm[a][o] >= e`. Encoded as a safety invariant on the `stale[a][o]` counter (`stale[a][o] <= B` whenever connected), NOT as a temporal property. This deliberately keeps the end-to-end form of RevocationFreshness inside the reliable `--inv=` PR lane instead of the known-unreliable temporal lane. `stale` freezes while `(a, o)` is partitioned and resumes counting on heal, which is exactly the suspend/resume semantics below.
3. `RevocationEventuallyObservedDistributed` (liveness, nightly only). Under weak fairness on delivery-or-catchup for connected pairs, every revoke is eventually observed by every eventually-connected authority. Same `~>` shape as today's `RevocationEventuallySeen` (L365-375), quantifiers pushed inside the leads-to per the Apalache 0.50.1 restriction documented in the existing spec header.
4. `PartitionSuspendResume` (safety). During a partition the staleness counter for cut pairs does not increase the bound obligation (suspension), and within `B_heal` post-`Heal` delivery/catch-up steps the high-water marks reconverge. Also encoded with counters, so it stays in the safety lane.

Property-to-lane summary (the deliberate design point: everything load-bearing is a safety invariant in the reliable lane):

| Property | Kind | Lane | Bounds (PR / nightly) |
| --- | --- | --- | --- |
| `NoAllowAfterRevoke` (distributed) | safety, `--inv=` | apalache-safety, PR | AUTHS=3, EPOCH_MAX=4 / AUTHS=4, EPOCH_MAX=6 |
| `BoundedStalenessInv` | safety, `--inv=` | apalache-safety, PR | B=3, SKEW=2 / B=4, SKEW=3 |
| `PartitionSuspendResume` | safety, `--inv=` | apalache-safety, PR | B_heal=3 / B_heal=4 |
| `DomainsOK` (shape) | safety, `--inv=` | apalache-safety, PR | same |
| `RevocationEventuallyObservedDistributed` | liveness, `--temporal=` | apalache-temporal, nightly, non-required | AUTHS=3 / AUTHS=4 |
| Quint simulation scenarios | executable, `quint run` | scheduled drift job only | 10k runs per scenario |

### Assumption narrowing (the retirement walk, done precisely)

`formal/assumptions.toml` L31-37 states the protocol: a retired assumption MUST NOT appear in `required_assumption_ids`, MUST cite the discharging artifact in `discharged_by`, lands via a P3 ticket, and is mirrored in `formal/proof-manifest.toml` `discharged_assumptions`. The narrowing PR therefore makes exactly these edits:

1. Add the replacement assumption to `assumptions` and `required_assumption_ids`: `ASSUME-GOSSIP-FAIRNESS-PARTITION-BOUND | audited_transport | Between correct, non-partitioned bilateral peers, queued revocation gossip or catch-up is eventually delivered, and partitions eventually heal within the operator's declared bound. Message loss, duplication, reordering, and bounded clock skew are NOT assumed away; they are modeled. | P2,P8,P9`. This is strictly smaller than ASSUME-NETWORK-TRANSPORT: it assumes only fairness-plus-heal, not integrity (now carried by ASSUME-ED25519/ASSUME-SIG-CHECK plus the fail-closed drop path) and not ordering (modeled).
2. Move `ASSUME-NETWORK-TRANSPORT` out of `required_assumption_ids` into `retired_assumption_ids`, with a `retired_assumptions` row whose `discharged_by` cites `BoundedStalenessInv`, `NoAllowAfterRevoke` (distributed variant), `PartitionSuspendResume`, and the signer-pinning call sites (`revocation_gossip.rs::validate_envelope`, `RevocationView::install_if_newer`).
3. Mirror the row in `formal/proof-manifest.toml` `discharged_assumptions` (same `id|artifacts|call_sites|prose` format as the RETIRED-SQLITE-CROSS-ROW row at L170), replace the L173-198 deferral comment with a pointer to the new model, and update `m04_p5_t5_assumptions_decision`.
4. Update `docs/reference/CLAIM_REGISTRY.md`: the ASSUME-NETWORK-TRANSPORT row (L42) moves to the retired/downgraded narrative and the new fairness assumption gets an `approved_with_scope` row.
5. Update `formal/MAPPING.md`: rows for the new invariants, and fix the dangling `ASSUME-PROPAGATE-FAIRNESS` reference by pointing it at the newly registered ID.

### Toolchain decision: Quint pilot with committed compiled TLA

Options weighed:

- Plain TLA+: zero new toolchain; but the channel-bag, per-authority-clock model is the exact spec shape where untyped TLA+ errors (function vs operator, record shape drift) burn review time, and there is no way to unit-test the model before model checking.
- Quint (Informal Systems): typed front-end compiling to Apalache-checkable TLA; `quint run` gives executable random simulations that double as fast model tests and produce concrete traces for [FV-E2](FV-E2-counterexample-regression-pipeline.md). Cost: an npm-distributed CLI is a new pinned toolchain in a supply-chain-strict repo (the cargo-vet human gate discipline from the iroh work applies), and Quint pins its own compatible Apalache range, which must agree with the repo's 0.50.1 pin.

Recommendation: Quint pilot, with the compiled TLA committed and reviewed, mirroring the committed-generated-artifact pattern of [FV-A2](FV-A2-aeneas-generated-equivalence.md). Author `formal/quint/DistributedRevocation.qnt`; commit the compiled `formal/tla/generated/DistributedRevocation.tla`; PR-time Apalache consumes only the committed TLA (no npm on the PR path); a scheduled drift job recompiles and diffs. If the Quint/Apalache version pin cannot be reconciled with 0.50.1, fall back to hand-written TLA+ and record the decision in the spec header; nothing else in this plan changes.

## Implementation plan

1. Semantics extraction and review packet. Write the Rust-to-action table into the new spec's header comment; add `formal/MAPPING.md` rows (placeholder-marked until the invariants exist). Files: `formal/tla/generated/DistributedRevocation.tla` header (or `formal/tla/DistributedRevocation.tla` on fallback), `formal/MAPPING.md`.
2. Quint pilot. Files to add: `formal/quint/DistributedRevocation.qnt`; `tools/install-quint.sh` (pinned version plus tarball SHA256, same shape as `tools/install-apalache.sh`); `scripts/check-quint-compile-drift.sh` (recompile and byte-diff against the committed TLA); the committed compiled TLA. Include at least three `quint run` simulation scenarios (duplicate storm, partition-heal, skewed clocks) checked into `formal/quint/scenarios/`.
3. Safety lane. Files: `formal/tla/MCDistributedRevocation.cfg` (PR bounds: AUTHS=3, EPOCH_MAX=4, B=3, SKEW=2; nightly bounds larger); add the cfg|spec pair to the pair list in `.github/workflows/apalache-safety.yml` (L71-72); implement `NoAllowAfterRevoke`, `BoundedStalenessInv`, `PartitionSuspendResume`, `DomainsOK` as `--inv=` targets.
4. Temporal lane. Files: `formal/tla/MCDistributedRevocationTemporal.cfg`; a second job in `.github/workflows/apalache-temporal.yml` checking `RevocationEventuallyObservedDistributed` via `--temporal=`. The lane stays scheduled/manual and non-required per its own header; promotion is [FV-E5](FV-E5-lane-ratchets.md)'s ratchet, not this plan's.
5. Falsifiability evidence. Files: `formal/apalache/_negative_tests/DistributedRevocation_*.tla` broken variants (signer pin skipped so a forged higher epoch installs; skew bound removed; catch-up allowed across a partition). Each variant must produce a counterexample, archived per [FV-E2](FV-E2-counterexample-regression-pipeline.md).
6. Assumption-narrowing PR (separate, lands only after 3-5 are green). Files: `formal/assumptions.toml`, `formal/proof-manifest.toml`, `docs/reference/CLAIM_REGISTRY.md`, `formal/MAPPING.md`, `formal/theorem-inventory.json` (if any Lean cross-reference rows are added).

## CI and gating changes

- `apalache-safety.yml`: one new cfg|spec pair; already PR-path-scoped on `formal/tla/**`, so no trigger changes. PR wall-clock budget must be measured at the PR bounds before merge; if the new spec exceeds it, PR runs the smaller AUTHS=2 cfg and nightly runs AUTHS=3+.
- `apalache-temporal.yml`: one new non-required job. The header's do-not-promote rule (L10-12) is respected verbatim; this plan adds coverage to the lane without changing its status.
- New scheduled job (may live inside `apalache-safety.yml`'s schedule leg): `scripts/check-quint-compile-drift.sh`, gated on the Quint toolchain being installable; failure opens an issue rather than blocking PRs (the committed TLA is the artifact of record).
- No gate command changes in `formal/proof-manifest.toml` `gate_commands` until the narrowing PR, which adds the drift script if the Quint route survives the pilot.

## Acceptance criteria

- [ ] `DistributedRevocation` models loss, duplication, reordering (bag channels), bounded skew (`SKEW`), per-origin high-water marks, coalescing queues, catch-up, and partitions, with the Rust-to-action table in the spec header matching `revocation_gossip.rs` functions by name.
- [ ] `NoAllowAfterRevoke` holds in the distributed model at PR and nightly bounds.
- [ ] `BoundedStalenessInv` holds as a safety invariant (`--inv=`) at PR bounds, and its statement is documented as the end-to-end form of `RevocationFreshness`.
- [ ] `PartitionSuspendResume` holds: staleness obligations suspend during a cut and reconverge within `B_heal` after heal.
- [ ] `RevocationEventuallyObservedDistributed` is checked in the nightly temporal lane; its flake rate is recorded for [FV-E5](FV-E5-lane-ratchets.md).
- [ ] All negative-test variants produce counterexamples (falsifiability shown).
- [ ] The narrowing PR performs the full retirement walk: new `ASSUME-GOSSIP-FAIRNESS-PARTITION-BOUND` registered; `ASSUME-NETWORK-TRANSPORT` in `retired_assumption_ids` with `discharged_by`; `discharged_assumptions` mirror row; CLAIM_REGISTRY and MAPPING updated; the dangling `ASSUME-PROPAGATE-FAIRNESS` reference in MAPPING.md resolved.
- [ ] Quint decision recorded: either the committed-compiled-TLA pipeline is in place with a pinned installer, or the fallback to hand-written TLA+ is documented in the spec header.

## Risks and mitigations

- State explosion from bag channels and per-authority clocks. Mitigate: counting-function encoding instead of the Bags module; small PR bounds with nightly escalation; cap in-flight frames per channel with a `CHAN_CAP` constant (justified by the Rust queue's own capacity bound and the 4096 catch-up cap).
- The temporal lane is known-unreliable, and this plan adds to it. Mitigate: the load-bearing claim (`BoundedStalenessInv`) is deliberately a safety invariant in the reliable lane; liveness is corroborating, not gating.
- Quint supply chain and version pinning. Mitigate: committed compiled TLA is the reviewed artifact; npm install is pinned by version and hash and runs only in scheduled jobs; documented fallback to plain TLA+.
- Model-code drift as `revocation_gossip.rs` evolves. Mitigate: MAPPING.md rows are enforced by `scripts/check-mapping.sh` name-grep; the Rust-to-action table names concrete functions so review of a gossip change has a checklist; [FV-A4](FV-A4-mirror-drift-hashes.md) hash mirrors can later pin the table to file hashes.
- Narrowed assumption still too strong for reality (relay outages; n0 free relays are only funded through 2026-12-31 for the iroh transport). Mitigate: the fairness assumption is written as eventually-heal with an operator-declared bound, which an operator can satisfy with self-hosted relays; the model's partition semantics make the degraded mode explicit instead of hidden.

## Open questions

- Value of `B` (evaluations before observation) at PR bounds vs the operator-facing statement: is `B` a pure model constant, or should it be derived from `DEFAULT_EPOCH_TICK_MS` and the flush cadence so the prose claim has units?
- Should catch-up be modeled as the one-shot max-merge above, or as an explicit request/response pair so `CatchupGap` handling is itself model-visible? (One-shot is proposed; the response validation is a local fail-closed check already covered by Rust tests at `revocation_gossip.rs` L966-997.)
- Does the narrowed assumption's scope need to mention the pheromone gossip lane (`pheromone_gossip.rs`) explicitly out-of-scope, or is revocation-only scoping clear enough from the property names?
- Whether `RevocationPropagation.tla` should eventually be folded into the distributed spec or kept as the minimal local-gate model (proposal: keep both; the small one is cheap and its invariant names are load-bearing for existing discharge rows).

## Manifest and registry updates

- `formal/assumptions.toml`: add `ASSUME-GOSSIP-FAIRNESS-PARTITION-BOUND` (required); move `ASSUME-NETWORK-TRANSPORT` to `retired_assumption_ids` plus a `retired_assumptions` row with `discharged_by` naming `BoundedStalenessInv`, distributed `NoAllowAfterRevoke`, `PartitionSuspendResume`, and the signer-pinning call sites.
- `formal/proof-manifest.toml`: new `discharged_assumptions` row mirroring the above; delete/replace the L173-198 deferral comment; update `m04_p5_t5_assumptions_decision` and `m04_p5_t5_rationale_anchor`; add the drift script to `gate_commands` if the Quint route ships.
- `formal/MAPPING.md`: rows for each new named invariant and the liveness property (source, Rust path constrained, assumption discharge, one-liner); repair the `ASSUME-PROPAGATE-FAIRNESS` dangling reference.
- `formal/theorem-inventory.json`: no Lean changes required by this plan; add cross-reference notes only if a Lean-side freshness lemma is later tied in.
- `docs/reference/CLAIM_REGISTRY.md`: adjust the ASSUME-NETWORK-TRANSPORT row and add the replacement assumption; both edits ride the same PR as the assumptions.toml change because CLAIM_REGISTRY is a claim-gate input (`proof-manifest.toml` L113-119).
