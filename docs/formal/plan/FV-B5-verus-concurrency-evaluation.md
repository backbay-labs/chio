# FV-B5: Verus evaluation for unbounded concurrency conservation

Status: Executed (2026-07-23; evaluation complete, no lane created; the FV-E5 enforcement precondition is the sole blocker)
Theme: B - Aim the formal tools at the actual bug generator
Effort: M (hard-capped at two weeks; the decision rule below fires at the cap regardless of progress)
Depends on: [FV-B3](FV-B3-budget-conservation-law.md) (the law and its four lanes), [FV-B4](FV-B4-loom-registry-and-dst.md) (the bounded evidence this evaluation aims to exceed); sequencing: no lane decision until at least one existing lane has completed the [FV-E5](FV-E5-lane-ratchets.md) promotion runbook
Feeds: [FV-E5](FV-E5-lane-ratchets.md) (a promoted lane registers a new ratchet), the Lane 3 (Creusot) retention decision
Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md) (G3 residue), [../CURRENT_STATE.md](../CURRENT_STATE.md) (Lanes 3-5, concurrency estate), [FV-A4](FV-A4-mirror-drift-hashes.md) (mirror discipline if the artifact stays model-only)

## Summary

Every witness of the FV-B3 conservation law is bounded in at least one
dimension: the Kani harness fixes the operation-sequence length, the Apalache
ledger fixes amounts and trace length, Loom fixes the preemption count, and
deterministic simulation fixes the schedule corpus. Nothing proves the law
under unbounded concurrent interleavings. Verus
(https://github.com/verus-lang/verus), an SMT-backed deductive verifier for
Rust, is the one candidate tool whose concurrency framework (VerusSync
tokenized state machines) can state and prove that missing cell on executable
Rust. It is also largely redundant with Creusot, Kani, and Aeneas on the
sequential extraction surface, and it requires code to be written inside its
`verus!` macro dialect against a pinned rustc.

This document therefore specifies an evaluation spike, not a lane: prove the
FV-B3 partition law and terminal uniqueness for a concurrent multi-hold ledger
protocol in VerusSync, falsify it with a seeded broken variant, measure the
toolchain cost, and then apply a written decision rule with two independent
outcomes: (a) promote a narrow concurrency-only lane, (b) assess Verus as a
Creusot replacement. The spike registers no lane, appears in no manifest, and
supports no public claim.

## Motivation and evidence

- The 2026-07 bug family (the five fixed commits catalogued in FV-B3) lived on
  the drop/cancel unwind surface, which is concurrent by construction: guard
  drops race tool-server futures, store mutations, and admission hooks. The
  reassessed G3 boundary in [GAP_ANALYSIS.md](../GAP_ANALYSIS.md) closes the
  modeling gap but every retained witness is bounded.
- Coverage matrix for the FV-B3 law today:

  | Evidence | Interleaving | Bound |
  | --- | --- | --- |
  | Lean `Proofs/ReservationLedger.lean`, Creusot contract | sequential fold | unbounded amounts, single thread |
  | Kani `verify_reservation_ledger_conservation` | sequential | six-step sequences plus boundary phases |
  | Apalache `PostAdmissionDropGuard` | concurrent | `BudgetMax = 4`, bounded length |
  | Loom registry (10 models) | concurrent, real code | three preemptions |
  | DST nightly | concurrent, real kernel | 10,000 seeded schedules |

  The empty cell is concurrent-and-unbounded. VerusSync tokenized state
  machines prove invariants over all schedules and all amounts by requiring
  each transition to carry linear ghost tokens, so a proof is a proof for every
  interleaving, not a searched subset.
- Verus is the wrong tool for the rest of the estate, and this spec says so to
  keep the evaluation narrow. Its deductive-contract core duplicates what
  Creusot, Kani, and the Aeneas extraction already triple-cover on
  `formal_aeneas.rs`, a surface deliberately restricted to the subset those
  tools handle well. Verus does not verify async executable functions, so the
  kernel's admission and drop paths stay out of reach regardless of outcome;
  any artifact models the concurrent store protocol, not the async call path.
- External track record is real but research-grade: verified concurrent and
  systems code at SOSP/OSDI scale (verified storage, a confidential-VM
  security module, Kubernetes controller verification). The project describes
  itself as under active development without stability guarantees and pins
  specific rustc toolchains per release. That posture is compatible with this
  estate only through the same exact-version-plus-sha256 pinning already used
  for Aeneas and Charon.

## Current state

- Concurrency evidence is the FV-B4 estate: ten Loom models under three
  preemptions (229.86 seconds locally) and 10,000 deterministic schedules
  (63.24 seconds), both advisory nightly lanes with no hosted streak.
- The pure ledger algebra exists three times (Kani, Creusot, Lean) over
  `formal_aeneas.rs::ledger_apply`, all sequential. The concrete store binding
  is runtime evidence (lanes (c) and (d) of FV-B3), not refinement.
- Every registered gate in `releases.toml` is advisory and six are frozen. No
  lane has completed the FV-E5 promotion runbook. Adding a seventh proof
  toolchain before one lane has crossed that bar would widen the estate while
  its enforcement layer is still unexercised, which is why the decision rule
  below has an enforcement precondition.

## Design

### Spike target

One artifact: a VerusSync tokenized state machine `ReservationLedgerSync`
stating the FV-B3 law for concurrently held reservations against one store.
Multiple actors concurrently authorize, reverse, release, and reconcile
distinct holds; the machine proves, for every interleaving and every amount:

1. Partition: `reserved = committed + released + retained + outstanding` at
   every reachable state (clause 1 of the FV-B3 law).
2. Terminal uniqueness: a hold token, once terminal, admits no further
   transition (clause 2).
3. Fail-closed arithmetic: any transition whose checked arithmetic would
   overflow is not enabled (the `ledger_apply` posture, lifted to the
   concurrent setting).

Sketch (sharding strategy is a spike deliverable, not a commitment):

```rust
tokenized_state_machine! { ReservationLedgerSync {
    fields {
        #[sharding(map)]
        pub holds: Map<HoldId, HoldState>,   // per-hold linear tokens
        #[sharding(variable)]
        pub totals: LedgerTotals,            // the four-bucket partition
    }

    #[invariant]
    pub fn conservation(&self) -> bool {
        self.totals.committed + self.totals.released
            + self.totals.retained + self.totals.outstanding
            == self.totals.reserved
    }
    // transitions: authorize, reverse, release, reconcile; terminal holds
    // yield no token, so no transition can consume them.
} }
```

Child splits (clause 3) are out of spike scope; the sequential
`SiblingSumBudget.lean` theorems remain the clause 3 anchor.

### Falsifiability

Standing rule 1 applies before any result counts. The spike must include at
least two deliberately broken variants that Verus rejects with a failed proof:
one that re-enables a transition on a terminal hold (the terminal-uniqueness
mutation) and one that skips a checked-add guard (the overflow mutation). A
spike whose broken variants verify is a failed spike, whatever the green
artifact says.

### Linkage posture

The artifact starts model-level, exactly like the Apalache ledger. Verus code
must live inside the `verus!` dialect, so the production
`budget_store.rs` bodies cannot be included unmodified the way the Creusot
lane includes `formal_aeneas.rs`. Two linkage routes exist and choosing
between them is a promotion-time decision, not a spike task:

- Mirror: keep the state machine as a model and bind it to the
  `BudgetMutationKind` vocabulary with an FV-A4 drift hash (mechanism already
  exists; weakest linkage).
- Absorption: Verus erases ghost code and compiles to ordinary callable Rust,
  so a verified transition core could be absorbed under standing rule 2. That
  rewrites production surfaces consumed by four existing lanes and is
  explicitly out of scope until a lane decision exists.

The spike documents the absorption cost estimate; it does not perform it.

### Decision rule

Applied at the two-week cap. Outcome (a), promote a concurrency-only lane, is
taken only if all of the following hold:

1. The three spike properties verify unboundedly and both broken variants
   fail verification.
2. The toolchain pins cleanly: exact release tag plus sha256 for the Verus
   binary and its required rustc, following the Aeneas/Charon pinning pattern,
   with a cold install plus full verification wall time that fits the nightly
   budget (under 15 minutes end to end).
3. At least one existing lane has completed the FV-E5 promotion runbook. This
   is an enforcement precondition, not a technical one: new advisory lanes are
   cheap to add and expensive to keep honest, and the estate should first
   demonstrate it can promote what it already has.
4. The lane charter is written down as concurrency-only. Any proposal to point
   Verus at the sequential extraction surface is rejected in review by citing
   this document.

Outcome (b), the Creusot retention question, is assessed independently and
only if (a)'s criterion 1 holds. The known obstacle is stated here so the
assessment starts honest: Lane 3's value is contracts over an unconditional
include of unmodified production code, which Verus cannot reproduce; a
replacement therefore requires the absorption route for all nine contract
twins. Expected resolution is negative unless the Why3find and four-solver
chain becomes a measured maintenance problem. A negative resolution is
recorded in this file, not silently dropped.

If neither outcome's criteria hold, the spike artifacts are archived under
`formal/experiments/verus-eval/` with a closing note in this file, and no
follow-up issue is filed. An unpromoted experiment is a completed experiment,
not debt.

## Implementation plan

1. Phase 1 - toolchain. Pin one Verus release (tag plus sha256 plus required
   rustc) in a self-contained `formal/experiments/verus-eval/` workspace,
   isolated from the main workspace exactly like
   `formal/rust-verification/creusot-core` (its own `[workspace]`). Record
   cold-install wall time.
2. Phase 2 - sequential warm-up. Port `ledger_apply` semantics into the
   dialect and prove the sequential partition law. This calibrates effort
   against the known Creusot and Lean proofs of the same algebra and produces
   the absorption cost estimate.
3. Phase 3 - the concurrent artifact. `ReservationLedgerSync` with the three
   spike properties.
4. Phase 4 - falsification. Both broken variants, committed alongside the
   green artifact with their failing output captured.
5. Phase 5 - decision. Apply the decision rule, record the outcome and
   measurements in this file, and open the lane-integration spec only if
   outcome (a) is taken.

## CI and gating changes

None during the spike. No workflow, no registry row, no manifest entry, no
MAPPING row, no ratchet. Standing rule 3 binds lanes, and the spike is not a
lane; the promotion path (if taken) ships registry, MAPPING, coverage-map,
and `releases.toml` entries in its own reviewed change, per the runbook.

## Acceptance criteria

- [x] Pinned toolchain with recorded versions, hashes, and cold-install time.
- [x] Sequential `ledger_apply` port verified; effort and absorption cost
  recorded.
- [x] `ReservationLedgerSync` proves partition, terminal uniqueness, and
  fail-closed arithmetic with no bound on schedules or amounts.
- [x] Both broken variants fail verification with captured output.
- [x] Wall-time measurements for full verification recorded.
- [x] The decision rule is applied at or before the two-week cap and the
  outcome is recorded in this file, including a negative one.
- [x] No manifest, registry, claim, or workflow change lands with the spike.

## Outcome (2026-07-23)

The spike executed in a single day, well inside the cap. Artifacts and the
append-only measurement log live in `formal/experiments/verus-eval/`.

Technical result: the ledger crate verifies 19 items in 1.7 seconds
(sequential calibration 8, concurrent machine 11) against the pinned
`release/0.2026.07.18.3a4d30b` toolchain, whose vstd verified locally
(2055 items, 79.5 seconds). `ReservationLedgerSync` proves the partition
equation and the u64 fail-closed bound as state invariants and terminal
uniqueness by token consumption plus id non-reuse, for every interleaving
with no schedule, actor, or amount bound and no `assume`, `admit`, or
trusted escape. Both falsification variants are rejected on exactly the
invariant they attack. One design fact worth keeping: the partition
equation alone does not catch the terminal mutation (a double disposition
moves amounts between buckets and rebalances); only the
outstanding-equals-hold-sum coupling invariant kills it. The falsification
pass is what forces that stronger invariant to exist.

Decision rule, criterion by criterion:

1. Proofs and falsification: holds.
2. Toolchain pinning and CI budget: holds for the hosted execution
   platform. The x86-linux binary asset installs behind the recorded
   sha256 in seconds and full verification is about 2 seconds. Caveat for
   aarch64-linux development hosts: upstream ships no arm64-linux binary
   asset, and the upstream z3 4.12.5 arm64-glibc zip contains an x86-64
   binary (caught by the installer's architecture gate), so both build
   from pinned source; the measured one-time cold build is 16 minutes
   25 seconds, just over the 15-minute line. Both upstream defects are
   recorded in the experiment's measurement log.
3. Enforcement precondition: fails, and it is the sole blocker. All
   fifteen registered lanes are advisory and six are frozen; no lane has
   completed the FV-E5 promotion runbook. A later revisit does not need a
   new spike; it needs a promoted lane.
4. Concurrency-only charter: holds (this spec and the experiment README).

Decision: no lane is created. The artifacts stay archived in place under
`formal/experiments/verus-eval/` per the archive rule above.

Outcome (b), Creusot retention: negative, as expected. Lane 3's value is
contracts over an unconditional include of unmodified production code,
which Verus cannot reproduce; replacing it means absorbing all nine
contract twins through the `verus!` dialect, which the Phase 1 estimate
prices at weeks of restructuring across the inputs of all four consuming
lanes plus vstd entering the production build graph. The warm-up shows
the contract algebra itself ports in hours, so the obstacle is the input
contract, not the proofs. Reopen only if the Why3find and four-solver
chain becomes a measured maintenance problem.

## Risks and mitigations

- Toolchain churn: Verus tracks rustc nightlies and `vstd` changes between
  releases. Mitigation: exact pinning, an isolated workspace, and the standing
  option to archive; nothing in the main workspace depends on the experiment.
- Dialect seduction: once the tool is in-tree, sequential surfaces look like
  easy wins and the estate grows a fourth opinion on solved problems.
  Mitigation: decision-rule criterion 4 makes the concurrency-only charter
  citable in review.
- Model drift: a model-level state machine can diverge from
  `budget_store.rs` semantics silently. Mitigation: the promotion spec must
  choose mirror-with-drift-hash or absorption before the lane exists; the
  spike itself claims nothing, so drift during the spike costs nothing.
- Proof effort exceeds the cap: tokenized state machines have a real learning
  curve. Mitigation: the cap is the mitigation; a partial artifact plus a
  recorded negative decision is a valid and useful outcome.

## Resolved decisions

- The spike targets the FV-B3 law and nothing else. Wasm boundaries, protocol
  typestates, and distributed revocation stay with their existing owners.
- Async executable verification is not evaluated. Verus does not support it,
  and the kernel call path is async; this is recorded as a standing scope
  boundary, not a temporary one.
- The evaluation does not touch `formal_aeneas.rs`, its four consuming lanes,
  or any production crate.
- Hosted execution is out of scope for the spike; local evidence with recorded
  wall times is sufficient for the decision rule, because the spike makes no
  claim that would require hosted qualification.

## Manifest and registry updates

None. This section exists to state that explicitly: the spike produces no
`proof-manifest.toml`, `theorem-inventory.json`, `MAPPING.md`,
`.kani/harnesses.toml`, or `releases.toml` change. All registry work belongs
to the promotion spec that outcome (a) would open.
