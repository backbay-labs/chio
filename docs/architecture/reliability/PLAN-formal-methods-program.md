# PLAN-formal-methods: Formal-methods program: enforce what exists, spec the two broken protocols, exercise the seams

- Status: Draft (proposed, wave-3 reliability program)
- Date: 2026-07-04
- Extends: none
- Depends on: RFC-0002 (unconditional post-admission unwind), RFC-0003 (dispatch-intent journal), RFC-0011 (control-plane replication soundness)
- Closes findings: F41, F42, F43, F45, F46, F52 (medium); F44, F47, F48 (low) (see ./README.md and the wave-3 readiness review)

## Summary

Chio ships a large formal-methods surface (TLA+/Apalache safety invariants, a
Lean 4 theory, Kani proof harnesses, Creusot contracts, Aeneas equivalence, and
loom concurrency suites) whose green status overstates what it measures. Five
concrete gaps are load-bearing: the MAPPING.md traceability gate is real,
fail-closed, and wired into no workflow (F41); every Kani invocation carries
`--no-unwinding-checks`, which silently truncates loop exploration on TCB
authorization code (F42); the documented `kani-public-pr` PR lane does not
exist, so no prover runs before push-to-main (F43); the three loom suites
compile to empty test binaries because no lane sets the `loom` cfg (F52); and
half the "covered" `formal_core` surface is an uncalled mirror with no
production caller while the Creusot lane's `covered_symbols` claims coverage it
does not prove (F45, F46). This plan is an engineering schedule that (1)
enforces what already exists (days), (2) writes two new adversarial models,
`ReceiptLifecycle.tla` and `BudgetReplication.tla`, that are the design proofs
for RFC-0002/0003 and RFC-0011 (weeks), (3) adds a proptest state machine over
the SQLite receipt-store lifecycle that would have caught the RFC-0007 retention
brick (days), (4) closes the model-mirror gap by binding `formal_core` to
production or honestly demoting the claim, and (5) fences the failure classes
that are not formal-methods work and routes them to the load-chaos program plan.
Every gate lands fail-closed: a non-zero exit denies the merge or the release.

## Motivation

The article lens (Ubicloud, "PostgreSQL and the OOM Killer") demands that
internal accounting be trustworthy or loudly broken, that a component dying
mid-operation have a known blast radius, and that recovery be durable. The
formal-methods stack is Chio's strongest claim to those properties, and the
wave-3 review found it to be a faithful Committed_AS analogy: every lane is
green, every number is plausible, and several of them measure a truncated or
uncalled artifact rather than the property they advertise.

Blast radius, per finding:

- F41. Trigger: any PR adds or renames a TLA invariant or a `#[kani::proof]`
  harness without a MAPPING.md row. Effect: no CI signal, because the gate that
  claims to fail the build (`formal/MAPPING.md:7-9`) is referenced by no
  workflow. The ledger silently rots; this has already happened (two unmapped
  harnesses today, plus a citation to a workflow file that does not exist).
  Impact: auditors and the HITRUST evidence bridge trust a stale document, and
  unmapped proofs lose their assumption-discharge linkage.
- F42. Trigger: a verified function gains a loop whose trip count can exceed 8,
  or a harness's `kani::assume` bounds loosen. Effect: CBMC unrolls only 8
  iterations and, with unwinding checks disabled, emits no unwinding-assertion
  failure; the harness reports `SUCCESSFUL` over a truncated state space.
  Impact: the nightly Kani lane and release qualification stay green while a
  real bug in iterations greater than 8 ships with a "verified" label on TCB
  authorization code.
- F43. Trigger: a PR changes `verify_capability`/`evaluate`/normalized-merge
  semantics in a way that breaks a Kani harness, Lean theorem, or Creusot
  contract. Effect: PR CI passes (it runs no prover) and the PR merges; the
  break is first seen by push-to-main release qualification or the nightly
  sweep. Impact: main is red for formal proofs after the fact, and other work
  stacks on the proof-breaking commit during the window.
- F52. Trigger: a concurrency regression lands in one of the three modeled hot
  paths (kernel session create/lookup/terminal race, exporter ring-sender vs
  shutdown, wasm-guard instance pre-reload vs checkout), all inside the TCB or
  its evidence pipeline. Effect: every lane compiles the loom files to empty
  binaries that pass. Impact: the interleaving coverage these files advertise is
  zero; a shipped race reaches production undetected.
- F45/F46. Trigger: production budget-hold accounting, DPoP admission, guard
  short-circuit, or receipt-field coupling changes semantics the mirror does not
  mirror. Effect: Lean/Kani/Creusot/Aeneas all still pass because they verify an
  uncalled mirror; `proof-manifest.toml` still lists the symbols as covered.
  Impact: the formal-evidence bundle overstates implementation linkage on the
  most security-relevant kernel semantics.

## Current behavior (verified 2026-07-04)

Every citation below was re-read against live code today; the current
signatures are quoted.

### The traceability gate is real and unwired (F41)

`scripts/check-mapping.sh` is a functional, fail-closed bash script. It extracts
every top-level named TLA invariant from `formal/tla/RevocationPropagation.tla`
and every `#[kani::proof]` harness from
`crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs`, then asserts each
appears as a backtick-wrapped token in a MAPPING.md table row, exiting 1 on any
miss (`scripts/check-mapping.sh:192-196`, "Failing closed"). Running it today:

```
check-mapping: FAIL - 2 Kani harness(es) defined in
  crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs
  but not cited in formal/MAPPING.md:
  - public_sign_receipt_accepts_matching_content_hash
  - public_sign_receipt_refuses_content_hash_mismatch
```

`crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs` currently defines
20 harnesses (`#[kani::proof]` at lines 115, 125, 163, 201, 239, 263, 288, 360,
377, 394, 422, 456, 483, 581, 872, 986, 1126, 1176, 1235, 1247); MAPPING.md maps
18. The two content-hash harnesses (`fn` lines 395 and 423) have no row.
`formal/MAPPING.md:7-9` states the file "is enforced by
`scripts/check-mapping.sh` ... and fails the build if any appear in the source
but are not represented as a row here." No workflow runs it: a repo-wide grep
finds `check-mapping` only in `formal/MAPPING.md`,
`formal/issue-templates/property-counterexample.md`,
`compliance/hitrust/narratives/formal-evidence-bridge.md`, and the script
itself; there are zero hits in `.github/`, `scripts/ci-workspace.sh`, or the
`ci.yml` "Workspace structural gates" step (`.github/workflows/ci.yml:73-95`).
Separately, `formal/MAPPING.md:74` cites
`.github/workflows/apalache-nightly.yml`; that file does not exist (the only
Apalache workflows are `apalache-safety.yml` and `apalache-temporal.yml`).

### Every Kani invocation truncates loops silently (F42)

The flag `--no-unwinding-checks` is on every lane:

- `scripts/check-kani-public-core.sh:55`: `cargo kani -p chio-kernel-core --lib
  --harness "$harness" --default-unwind 8 --no-unwinding-checks`.
- `scripts/check-kani-core.sh:11`: `cargo kani -p chio-kernel-core --lib
  --default-unwind 8 --no-unwinding-checks`.
- `scripts/run-kani-manifest.sh:233-234`: `CMD=(cargo kani -p "$crate" --lib
  --harness "$harness" --default-unwind "$unwind" --no-unwinding-checks)`.
- `.github/workflows/nightly.yml:136-137`: the kani sweep runs `cargo kani -p
  chio-kernel-core --lib --harness "${harness}" --default-unwind 8
  --no-unwinding-checks`.
- `.kani/harnesses.toml:8-9` documents the flag as part of the standard
  invocation; `default_unwind = 8` on nearly every harness, with one outlier at
  `default_unwind = 4` (`.kani/harnesses.toml:277`).

With `--no-unwinding-checks`, CBMC does not emit an unwinding-assertion failure
when 8 iterations are insufficient. The input-bounding helpers
`assume_single_unconstrained_invoke_grant` (`kani_public_harnesses.rs:96`) and
`assume_single_normalized_tool_grant` (`kani_public_harnesses.rs:104`) keep most
current harnesses within the bound, so the flag is presently benign, but nothing
detects the day a harness's `assume` loosens or a verified function grows a
longer loop.

### The PR-tier prover lane does not exist (F43)

`.github/workflows/ci.yml:12-17` states the PR tier is "intentionally fast" and
that "the Kani lanes run nightly (kani-public-nightly)"; this comment is the
only Kani mention in `ci.yml`, and there is no Kani job. Three artifacts
document a `kani-public-pr` job as if it ran:

- `.github/workflows/nightly.yml:68-69`: "The PR job (kani-public-pr in ci.yml)
  only runs `lanes.pr`".
- `.kani/harnesses.toml:5-6` ("Each `[[harness]]` entry pins one (crate,
  harness) pair the CI `kani-public-pr` job iterates") and `:14` ("lane = pr
  Always runs on every PR and on push-to-main").
- `formal/rust-verification/kani-public-harnesses.toml:51-52`: "The full sweep
  is ~2.2 min locally, within the 6-minute PR budget, so every harness lands in
  `lanes.pr`".

Release qualification (`.github/workflows/release-qualification.yml:3-6`)
triggers on `workflow_dispatch` plus push to `main` only, and its own comment
(`:14-17`) references "the same Aeneas/Charon, Creusot, and Kani builds as the
PR-tier CI lane" that does not run them. The earliest formal gate is therefore
push-to-main, not pre-merge.

### The loom suites are empty binaries (F52; F44 meta-level)

Three loom files exist and none is ever exercised:

- `crates/kernel/chio-kernel/tests/loom_concurrency.rs:1-11`: gated on
  `cfg(any(loom, chio_kernel_loom))`, importing `loom::*` and `std` only; it
  builds a hand-rolled `ModelSession` rather than the production session table.
  Line 1 is `#![cfg_attr(not(any(loom, chio_kernel_loom)), allow(dead_code))]`,
  so the ordinary lane compiles an empty test binary.
- `crates/observability/chio-otel-receipt-exporter/tests/loom_ring_sender_vs_shutdown.rs:1-6`:
  gated on `cfg(loom)`, and it imports the real production type
  `chio_otel_receipt_exporter::queue_core::BoundedDropOldestQueue`. This suite
  already drives shipped code and is the template for the others.
- `crates/guards/chio-wasm-guards/tests/loom_instance_pre_reload_vs_checkout.rs:1-6`:
  gated on `cfg(loom)`, importing only loom primitives (a hand-built model).

The `loom` cfg is registered but never set: the workspace `Cargo.toml:326`
declares `loom = "0.7"`; `crates/kernel/chio-kernel/Cargo.toml:84` takes the
dev-dep and `:195` registers `check-cfg = ["cfg(dhat)", "cfg(loom)",
"cfg(chio_kernel_loom)"]`; the exporter (`:23`, `:30`) and wasm-guards (`:66`,
`:97`) do the same for `cfg(loom)`. A grep across `.github/`, `scripts/`,
`xtask/`, `ci-gates/`, and `Makefile` for `--cfg loom`/`chio_kernel_loom`
returns zero invocations. F44's residual is meta-level: `formal/MAPPING.md:82`
presents the by-construction TLA model `KernelTransitionCancelSafe.tla` as
constraining `crates/kernel/chio-kernel/src/budget_store.rs` and
`evaluate.rs::evaluate`, which reads as concurrency coverage that the loom suite
does not provide.

### Half the covered formal_core is an uncalled mirror (F45, F46)

`crates/kernel/chio-kernel-core/src/formal_core.rs:1-7` documents "Pure helpers
shared by runtime code and formal verification lanes" and carries
`#![allow(dead_code)]`. Two of its surfaces are genuinely shared:
`classify_time_window` (`formal_core.rs:24`) is imported and called by
`capability_verify.rs:39,185`, and the `normalized.rs` subset helpers are on the
real path. The rest are not. The mirror functions `budget_precheck` (`:109`),
`budget_commit` (`:133`), `dpop_admits` (`:160`), `guard_pipeline_allows`
(`:186`), `revocation_snapshot_denies` (`:194`), and `receipt_fields_coupled`
(`:200`) have zero production callers: a workspace grep for calls (excluding
`formal_core.rs`, `formal_aeneas.rs`, Kani, and tests) returns only field and
binding matches on the unrelated control-plane names `budget_commit_index` /
`budget_commit: Option<BudgetWriteCommitView>`
(`crates/platform/chio-control-plane/src/trust_control/service_types/cluster_budget.rs:333,377`
and `budget_handlers.rs`), never a call to `formal_core::budget_commit`. Yet
`formal/proof-manifest.toml:72-76` lists `formal_core::classify_time_window`,
`budget_commit`, `dpop_admits`, `guard_pipeline_allows`, and
`receipt_fields_coupled` under `covered_rust_symbols`.

The Creusot lane restates the same overreach.
`formal/rust-verification/creusot-core/src/lib.rs` is the entire Creusot proof
surface: seven pure one-liner contract functions
(`time_window_valid_contract`, `budget_commit_remaining_contract`,
`optional_u32_cap_subset_contract`, `required_true_preserved_contract`,
`dpop_admits_contract`, `revocation_snapshot_denies_contract`,
`receipt_fields_coupled_contract`), importing only `creusot_std`.
`scripts/check-creusot-core.sh:11-14` runs `cargo creusot prove` inside that
standalone crate and nowhere else. But
`formal/rust-verification/creusot-contracts.toml:7-25` lists
`chio_kernel_core::capability_verify::verify_capability`, `evaluate::evaluate`,
`receipts::sign_receipt`, and the `NormalizedScope::is_subset_of` family under
`covered_symbols`, and `:28-34` asserts `contract_goals` about those functions
themselves. Because `creusot-core` does not import `chio-kernel-core` and no
parity test binds the two, a semantic change in `formal_core` leaves the Creusot
lane green while it proves the old formula.
`scripts/check-rust-verification-gates.sh:36-40` only checks schema match plus a
non-empty `covered_symbols`, and `:43-46` exits before any prover when
`CHIO_RUST_VERIFICATION_METADATA_ONLY=1`.

### The two liveness/distributed gaps (F47, F48)

`RevocationEventuallySeen` (`formal/tla/RevocationPropagation.tla:374-375`,
`AnyRevocationObserved ~> AllObservedRevocationsCaughtUp`, gated on weak
fairness of propagation) runs only in `apalache-temporal.yml`
(`workflow_dispatch` plus nightly cron), which carries the verbatim warning "Do
not promote this workflow to a required check until the underlying property is
fixed and the run is reliably green" (`apalache-temporal.yml:11-12`). The safety
lane (`apalache-safety.yml`) runs on pull requests path-scoped to
`formal/apalache/**` and `formal/tla/**` (`:7-14`), checking six `cfg|spec`
pairs (`:67-72`) at `--length=6` (`:63`); it carries no temporal property. The
fairness assumption the MAPPING.md row cites (`ASSUME-PROPAGATE-FAIRNESS`,
`MAPPING.md:45`) is not registered in `formal/assumptions.toml` (grep count 0).
The runtime is fail-closed regardless: `consult_revocation_view`
(`crates/kernel/chio-kernel/src/kernel/delegation.rs:46`) applies
`verify_snapshot_freshness` (`:89`), which returns `Err(...)` when `age_ms >
max_staleness_ms` (`:101-104`), with
`DEFAULT_REVOCATION_VIEW_MAX_STALENESS_MS: u64 = 500` (`:34`).

F48 is the conceded distributed-time gap. `RevocationFreshness`
(`RevocationPropagation.tla:311-313`) quantifies against a single shared `clock`
variable, and `formal/proof-manifest.toml:173-198` states plainly that
`ASSUME-NETWORK-TRANSPORT` "remains an audited assumption ... rather than a
discharged one", that the model "does NOT model multiple gossip peers,
vector-clock-ordered delivery, or any other cross-peer ordering primitive", and
that "the formal discharge is deferred until a distributed-time TLA model
ships". The runtime defenses (signer-id pin in
`crates/trust/chio-federation/src/revocation_gossip.rs`, `CatchupGap` in
`crates/trust/chio-federation-transport-iroh/src/catchup.rs`, monotone
`install_if_newer` in
`crates/kernel/chio-kernel-core/src/revocation_view.rs`) each fail closed but
their cross-peer composition is unmodeled.

## Design

The program has five workstreams. Sizes are rough; CI tiers and honest runtimes
are called out per item.

### Workstream 1: enforce what exists (days)

1. Fix the two live MAPPING failures, then wire the gate. Add rows for
   `public_sign_receipt_accepts_matching_content_hash` and
   `public_sign_receipt_refuses_content_hash_mismatch` to the "Kani public
   harnesses" table in `formal/MAPPING.md`, each citing
   `covered_rust_symbols sign_receipt` and the WYSIWYS content-hash recompute
   goal. Correct `formal/MAPPING.md:74` to cite `apalache-safety.yml` and
   `apalache-temporal.yml` instead of the nonexistent `apalache-nightly.yml`.
   Then add one step to the PR-tier job in `.github/workflows/ci.yml`,
   immediately after the "Workspace structural gates" step (the step at
   `ci.yml:73-95`):

   ```yaml
   - name: Formal traceability gate
     run: bash ./scripts/check-mapping.sh
   ```

   This is a pure grep gate: sub-second runtime, PR tier, fail-closed by the
   script's existing `exit 1`. No new job, no new runner.

2. Land the documented `kani-public-pr` job (F43). Add a job to `ci.yml`,
   path-scoped to `crates/kernel/chio-kernel-core/**`, `formal/**`, and
   `.kani/**`, that installs `cargo-kani` and iterates `lanes.pr` from
   `formal/rust-verification/kani-public-harnesses.toml` (the kernel-core schema
   the docs already reference). Reuse the harness-union shell from the nightly
   step at `nightly.yml:107-141` so PR and nightly read the same source of
   truth. Documented budget: ~2.2 min for the full kernel-core sweep, within the
   stated 6-minute PR budget. To hold that budget, the PR lane MAY keep
   `--no-unwinding-checks`; the nightly lane becomes the sufficiency oracle
   (item 3). Make the check required only once observed green on ten consecutive
   main pushes, to avoid a flaky-prover merge block. If the budget is not met in
   practice, correct `ci.yml:12-17`, `nightly.yml:68-69`,
   `.kani/harnesses.toml:5-6,14`, and `kani-public-harnesses.toml:51-52` to
   state that the earliest formal gate is push-to-main release qualification,
   rather than leaving those claims false.

3. Remove `--no-unwinding-checks` from the sufficiency lane (F42). Drop the flag
   from `nightly.yml:137` and from `scripts/check-kani-core.sh:11`,
   `scripts/check-kani-public-core.sh:55`, and
   `scripts/run-kani-manifest.sh:234`. When a harness then reports
   unwinding-assertion insufficiency, either add `#[kani::unwind(n)]` above the
   harness or raise `default_unwind` for its row in `.kani/harnesses.toml` /
   `kani-public-harnesses.toml` until the proof is complete under an explicit,
   auditable bound. Keep the flag PR-side only if item 2's wall-clock demands
   it. The nightly must fail loudly on any truncated proof; that is the whole
   point of the lane.

4. Run the three loom suites on a schedule (F52). Add a job (a new
   `loom-nightly.yml`, or a leg in `nightly.yml`) that runs, with a bounded
   preemption budget so exploration terminates:

   ```yaml
   - name: loom interleaving suites
     env:
       RUSTFLAGS: "--cfg loom"
       LOOM_MAX_PREEMPTIONS: "3"
     run: |
       cargo test --release -p chio-kernel --test loom_concurrency
       cargo test --release -p chio-otel-receipt-exporter --test loom_ring_sender_vs_shutdown
       cargo test --release -p chio-wasm-guards --test loom_instance_pre_reload_vs_checkout
   ```

   A single `--cfg loom` activates all three (the kernel gate is
   `any(loom, chio_kernel_loom)`, so `loom` alone suffices; the exporter and
   wasm-guards crates carry `[target.'cfg(not(loom))'.dependencies]` sections
   that swap the loom shim cleanly, and the kernel takes `loom` as a plain
   dev-dependency). `LOOM_MAX_PREEMPTIONS` bounds the factorial blowup; expect
   single-digit minutes at 2-3. As a follow-on (not a blocker for the lane),
   port the kernel `ModelSession` and the wasm-guard model to the production
   session-table and instance-pool types, mirroring what the exporter suite
   already does with `BoundedDropOldestQueue`, so the lane checks shipped code
   rather than a hand-rebuilt model.

5. Fix stale labels (F41, F44, F47). Amend `formal/MAPPING.md:82` to state that
   `KernelTransitionCancelSafe` holds by construction (single await bracketed by
   an armed drop guard) and does not model concurrent Commit-vs-Cancel races, so
   the row is not read as concurrency coverage. Register
   `ASSUME-PROPAGATE-FAIRNESS` in `formal/assumptions.toml` so the fairness
   dependency `MAPPING.md:45` cites is tracked in the audited-assumption
   registry.

### Workstream 2: prove the design (weeks)

Two new adversarial models. Both are Apalache-checked and live under
`formal/apalache/` beside the existing kernel-state models
(`KernelTransitionCancelSafe.tla`, `ReceiptBeforeAllow.tla`,
`MonotoneLogApalache.tla`, `RevocationCutCompleteness.tla`), each with an
`MC*.cfg`. They are appended to the six `cfg|spec` pairs in the here-doc of
`apalache-safety.yml:67-72`. Distributed models need a deeper bound than the
safety default; run the two new specs at `--length=6` on the PR-triggered
safety lane for a smoke bound and at `--length=12` on a nightly leg for depth.

1. `ReceiptLifecycle.tla` (+ `MCReceiptLifecycle.cfg`), ~180-240 spec lines.
   Models the dispatch/effect/append contract that RFC-0002 and RFC-0003 make
   good: a call transitions `Idle -> Admitted -> Dispatched -> Effected ->
   Appended`, and the adversary can fire `DropFuture` (cancel the evaluate
   future after admission), `CrashProcess` (kill the kernel between effect and
   append), and `StoreFail` (the receipt store rejects the append). The safety
   invariant is that no behavior ends in a state where `Effected` holds but no
   receipt (or cancellation receipt) is `Appended` and no operator incident
   marker is set. This is the machine-checked form of RFC-0002's
   `PostAdmissionDropGuard` contract ("a receipt and reservation release on
   every drop path", closing F02) and RFC-0003's effect-before-receipt crash
   window (closing F04/F31/F70); those RFCs own the runtime changes, this model
   owns the design proof. MAPPING.md gains a row binding the invariant to
   `crates/kernel/chio-kernel/src/kernel/*` (the `PostAdmissionDropGuard` path)
   and `crates/platform/chio-store-sqlite/src/receipt_store.rs`.

2. `BudgetReplication.tla` (+ `MCBudgetReplication.cfg`), ~200-280 spec lines.
   Models the quorum witness in
   `crates/platform/chio-control-plane/src/trust_control/cluster/deltas.rs`,
   whose current signature is:

   ```rust
   // deltas.rs:625
   fn budget_write_quorum_commit_view_locked(
       cluster: &mut ClusterRuntimeState,
       budget_seq: u64,
   ) -> BudgetWriteCommitView
   ```

   Today it counts a peer as a witness when `cursor.seq >= budget_seq`, where
   the peer cursor is drawn from a different sequence domain than the local
   write. The abstract state carries, per node, a locally-allocated `usage.seq`
   and a per-peer pull cursor; actions are `LocalWrite` (advance `usage.seq`),
   `Replicate` (a peer acknowledges an origin's write), and adversarial
   `ReplayPage`/`StaleCursor` (a peer returns a non-advancing or rewinding
   page). The safety invariant is the one the current witness violates: a write
   may be reported `quorum_committed = true` only if a quorum of distinct
   origins have acknowledged that specific write, never by comparing a local
   `usage.seq` against cursors from another sequence domain. This is the design
   proof RFC-0011 references by name for its rewrite of
   `budget_write_quorum_commit_view_locked` to per-origin acks, and for the
   strict cursor monotonicity RFC-0011 adds to `sync_peer_budgets`
   (`fn sync_peer_budgets(state: &TrustServiceState, client: &TrustControlClient,
   peer_url: &str) -> Result<u64, CliError>`, `deltas.rs:394`),
   `budget_cursor_from_event` (`deltas.rs:808`), and `budget_cursor_from_usage`
   (`deltas.rs:817`). Targets F16. A second invariant, per-round budget
   termination, witnesses that no puller loop can run unbounded on a replaying
   peer (RFC-0011's F15).

### Workstream 3: exercise the code (days)

Add a proptest state machine over the SQLite receipt-store lifecycle. It is the
runtime complement to `ReceiptLifecycle.tla` and would have caught the RFC-0007
retention brick (F23/F24/F30) that no unit test caught.

New test file
`crates/platform/chio-store-sqlite/src/receipt_store/tests/lifecycle_state_machine.rs`
(the `tests/` module dir already exists, e.g. `tests/insert.rs`), ~250-350 LOC.
Add `proptest` and `proptest-state-machine` under `[dev-dependencies]` in
`crates/platform/chio-store-sqlite/Cargo.toml` (neither is a dependency there
today). The model drives the real `SqliteReceiptStore`
(`receipt_store.rs:103`) through the verified entry points, whose current
signatures are:

```rust
// receipt_store.rs:537
pub fn append_chio_receipt_canonical_returning_seq(
    &self,
    canonical: Arc<CanonicalBytes>,
) -> Result<u64, ReceiptStoreError>

// receipt_store.rs:564
pub fn append_chio_receipt_consuming_authorization(
    &self,
    receipt: &ChioReceipt,
    consumption: &AuthorizationReceiptConsumption,
) -> Result<(), ReceiptStoreError>

// receipt_store/evidence_retention.rs:93
pub fn archive_receipts_before(
    &mut self,
    cutoff_unix_secs: u64,
    archive_path: &str,
) -> Result<u64, ReceiptStoreError>
```

plus a reopen of the same database path, with a `Crash` transition that drops
and re-opens the connection mid-sequence.

Reference model and transition taxonomy (fail-closed, no `unwrap`/`expect`):

```rust
/// Abstract expectation the real store is checked against after each step.
struct ReceiptStoreModel {
    highest_seq: u64,
    appended: BTreeSet<u64>,
    archived_before_secs: u64,
}

/// One generated step. `payload_seed` deterministically derives a valid
/// canonical receipt so shrinking stays meaningful.
#[derive(Clone, Debug)]
enum Transition {
    Append { payload_seed: u64 },
    Archive { cutoff_unix_secs: u64 },
    Reopen,
    Crash,
}

#[derive(Debug)]
enum LifecycleViolation {
    SeqRegressed { expected_min: u64, observed: u64 },
    AppendedRowMissingAfterReopen { seq: u64 },
    ArchivedRowStillLive { seq: u64 },
    Store(ReceiptStoreError),
}

fn apply_append(
    store: &SqliteReceiptStore,
    canonical: Arc<CanonicalBytes>,
    model: &mut ReceiptStoreModel,
) -> Result<(), LifecycleViolation> {
    match store.append_chio_receipt_canonical_returning_seq(canonical) {
        Ok(seq) if seq > model.highest_seq => {
            model.highest_seq = seq;
            model.appended.insert(seq);
            Ok(())
        }
        Ok(seq) => Err(LifecycleViolation::SeqRegressed {
            expected_min: model.highest_seq.saturating_add(1),
            observed: seq,
        }),
        Err(e) => Err(LifecycleViolation::Store(e)),
    }
}
```

The `Archive`, `Reopen`, and `Crash` arms follow the same shape: every fallible
call is matched into a typed `LifecycleViolation`, never unwrapped. The
post-condition after every transition: `highest_seq` never regresses
(append-only), every seq in `appended` minus the archived set is queryable
after a `Reopen` or `Crash`, and no archived seq remains live. Any divergence
fails the property; the store's own errors surface as
`LifecycleViolation::Store`, never swallowed. This is the exact class of
sequencing bug (append, then archive across a reopen, then query) that bricked
retention in RFC-0007.

CI placement: PR tier with a bounded case count (256 cases, 32 transitions
each), plus a nightly deep sweep (4096 cases, 128 transitions) in
`nightly.yml`. Register the named property functions as
`"<file>::<fn>"` pairs in the `INVARIANTS` array of
`scripts/check-proptest-coverage.sh` (invoked at `ci.yml:71`, step "Proptest
invariant coverage"), updating its count comment, so the test cannot silently
drop out of the suite. PR runtime is seconds; the nightly sweep is low
single-digit minutes.

### Workstream 4: close the model-mirror gap (F45, F46)

Pick one disposition per mirrored symbol and apply it; do not leave the claim as
is.

- Bind to production where cheap. Extract the branch logic of the budget-store
  admission decision, the DPoP admission decision, and the guard short-circuit
  into calls to `formal_core::budget_commit`, `dpop_admits`, and
  `guard_pipeline_allows`, exactly as `capability_verify.rs:185` already calls
  `classify_time_window`. Once a production caller exists, the Kani/Creusot/Lean
  proofs constrain shipped behavior and `proof-manifest.toml` is honest.
- Otherwise demote the claim. Split the `covered_rust_symbols` list in
  `formal/proof-manifest.toml` (the `formal_core::*` entries at `:72-76`) into
  `shared_code_symbols` (called on the runtime path: `classify_time_window`,
  the `NormalizedScope::is_subset_of` family, `sign_receipt`,
  `verify_capability`, `evaluate`) and `model_mirror_symbols` (the uncalled
  helpers). Split `creusot-contracts.toml:7-25` `covered_symbols` into
  `proved_symbols` (the seven `creusot-core` contracts actually run by
  `cargo creusot prove`) and `informational_targets` (the kernel symbols, which
  are proved by Kani, not Creusot).
- Add a differential guard either way. A unit test in `chio-kernel-core`
  asserts bit-for-bit agreement between each `formal_core` helper and its
  `creusot-core` mirror (and, where bound, the production branch) over
  exhaustive boolean and boundary inputs, so the duplicated formulas cannot
  silently drift (for example, flipping a time-window boundary from `<` to
  `<=`). Extend `scripts/check-rust-verification-gates.sh` so that
  `CHIO_RUST_VERIFICATION_METADATA_ONLY=1` still runs the differential test even
  when the heavy provers are skipped, closing the `:43-46` early-exit hole for
  the parity property.

### Workstream 5: scope fence (F44, F48, and the memory/metrics findings)

State plainly which failure classes are NOT formal-methods work, so effort is
not spent proving properties of objects that need a different harness. These
route to the load-chaos program plan (PLAN-load-chaos):

- Fault injection under real components. The chaos and attack-simulation
  fixtures under `fixtures/proof-room/runtime-security/` are signed
  `status: passed` assertions that no harness produces; the eight whitelisted
  chaos cases (receipt-log-unavailable, duplicate-nonce-race,
  registry-split-brain, clock-skew-expiry-bypass, tool-restart-lost-lease-cache,
  policy-reload-during-dispatch, revocation-oracle-unavailable,
  sandbox-profile-drift) must be induced by a booted-component fault harness,
  not a model. That harness, its report freshness gate, and the fixture refresh
  are load-chaos scope.
- Bounded memory / ENOMEM behavior belongs to RFC-0004 and the load-chaos soak
  lane, not to a proof. TLA cannot bound RSS.
- Observability and alerting wiring belongs to RFC-0009.
- Sustained-p99, TTFRH, and healthcare-capacity measurement (the synthetic
  benches the review flagged) are load-chaos and benchmark work; formal methods
  does not measure latency.
- F48's multi-peer integration test (adversarially reorder/replay catchup frames
  across three-plus iroh peers, assert every anomaly ends in deny/reject) is
  load-chaos over the iroh transport. What formal methods owns for F48 is the
  deferred distributed-time extension of `RevocationPropagation.tla`
  (per-peer logical clocks plus a gossip channel with reorder/duplicate/drop
  actions), scheduled after Workstream 2 as the natural follow-on to
  `BudgetReplication.tla`.
- F44's runtime cancellation-safety integration test (a tokio-level abort around
  `evaluate`/commit/receipt append) is owned by RFC-0002's test plan; this plan
  owns only the model-honesty label fix (Workstream 1, item 5).

## Wire, schema, and receipt impact

None to signed wire payloads. This plan changes no receipt kind, no
canonical-JSON envelope, and no `spec/schemas/**` file. The only schema-adjacent
edits are to formal-evidence metadata that is not on the wire:
`formal/MAPPING.md` rows, the `covered_rust_symbols` split in
`formal/proof-manifest.toml`, and the `covered_symbols` split in
`formal/rust-verification/creusot-contracts.toml`. Where proof-room fixture
content is embedded into product binaries, signed payloads remain canonical
JSON (RFC 8785) and are untouched; the TOML split is a key rename and
re-grouping within an unsigned audit document. The two new `.tla`/`.cfg` files
and the new proptest and loom test files are source, not wire artifacts.

## Migration and compatibility

- Ordering. Workstream 1 items 1 and 5 (fix the two MAPPING rows, correct the
  `apalache-nightly.yml` citation, register the fairness assumption) MUST land
  in the same PR as the `check-mapping.sh` wiring, or that PR is red on its own
  merge. This is the only hard ordering constraint.
- Feature-flag the required status. `kani-public-pr` and the loom lane are added
  as non-required checks first and promoted to required only after an observed
  green streak on main, so a flaky prover or a loom timeout does not block
  unrelated merges. `check-mapping.sh` is safe to make required immediately once
  its two current failures are fixed, because it is deterministic.
- Backward compatibility. No consumer reads the formal-evidence TOML by the old
  `covered_symbols` key name at runtime; the split is internal to the audit
  bundle and the gate scripts, which are updated in the same change
  (`check-rust-verification-gates.sh` validates the new keys). Auditors reading
  MAPPING.md see strictly more accurate rows.
- Staged rollout. Workstream 1 (days) lands first as a single hardening PR
  series. Workstream 3 (proptest, days) and Workstream 4 (mirror binding, days)
  follow independently. Workstream 2 (the two TLA models, weeks) lands last and
  does not gate the cheaper work.

## Test and verification plan

- Unit. The differential parity test (Workstream 4) is the named test that
  proves `formal_core` helpers, their `creusot-core` mirrors, and any bound
  production branch agree bit-for-bit over exhaustive boolean and boundary
  inputs. It fails closed on any drift.
- Property. `receipt_store::tests::lifecycle_state_machine` (Workstream 3) is
  the named proptest that proves append/archive/reopen/crash preserve the
  append-only and no-archived-row-live invariants; it is the runtime witness for
  the RFC-0007 brick class.
- Model. `MCReceiptLifecycle.cfg` and `MCBudgetReplication.cfg` are the named
  Apalache configs; the receipt-lifecycle safety invariant (no `Effected`
  without `Appended` or incident marker) and the budget-quorum safety invariant
  (no `quorum_committed` without a distinct-origin ack quorum) are the specific
  properties that must hold at `--length=6` on the PR safety lane and
  `--length=12` nightly.
- Loom. The three named suites (`loom_concurrency`,
  `loom_ring_sender_vs_shutdown`, `loom_instance_pre_reload_vs_checkout`) must
  execute under `--cfg loom` and pass with `LOOM_MAX_PREEMPTIONS >= 2`; a
  non-zero exit fails the lane.
- Kani sufficiency. The nightly Kani sweep, with `--no-unwinding-checks`
  removed, must pass with explicit per-harness unwind bounds; an
  unwinding-assertion failure is a hard fail, not a silent truncation.
- Tie-ins. The `ReceiptLifecycle.tla` invariant is the design proof
  cross-checked by RFC-0002's and RFC-0003's runtime tests;
  `BudgetReplication.tla` is the design proof cross-checked by RFC-0011's
  false-quorum and replication chaos scenarios in the load-chaos program plan.

## Acceptance criteria

- `bash scripts/check-mapping.sh` exits 0 in a clean tree and runs on every PR;
  adding an unmapped harness or invariant fails a PR.
- `formal/MAPPING.md` cites no nonexistent workflow (line 74 corrected), and
  `ASSUME-PROPAGATE-FAIRNESS` appears in `formal/assumptions.toml`.
- A `kani-public-pr` job runs `lanes.pr` on PRs touching kernel-core or formal
  sources, or all four documents that describe it are corrected to state the
  earliest formal gate is push-to-main.
- No Kani lane in `nightly.yml` or the sufficiency scripts passes
  `--no-unwinding-checks`; the nightly fails on unwind insufficiency.
- A scheduled lane runs all three loom suites under `--cfg loom` and is green.
- `formal/proof-manifest.toml` and `creusot-contracts.toml` distinguish
  shared/proved symbols from model-mirror/informational symbols, and a
  differential test binds the mirror to its counterparts.
- `ReceiptLifecycle.tla` and `BudgetReplication.tla` exist, are listed in the
  `apalache-safety.yml` here-doc, pass at the stated bounds, and each has a
  MAPPING.md row.
- `receipt_store::tests::lifecycle_state_machine` is registered in
  `check-proptest-coverage.sh` and passes.
- The scope-fence section is reflected in the load-chaos program plan's backlog
  (fault-injection harness, iroh multi-peer reorder test) with explicit
  ownership.

## Risks and alternatives

- Prover flakiness blocking merges. Kani and Apalache can be slow or
  memory-hungry on shared CI. Mitigation: add both lanes non-required first,
  path-scope them, and bound Apalache length and loom preemptions. Promote to
  required only after a green streak.
- Removing `--no-unwinding-checks` turns green red. This is the intended
  signal; the risk is a burst of newly-failing harnesses. Mitigation: land the
  flag removal on the nightly first (not the PR lane), triage each
  insufficiency by adding an explicit `#[kani::unwind(n)]`, and only then
  consider PR-side.
- Binding `formal_core` to production changes hot-path code. Extracting branch
  logic into the shared helpers touches the money and admission paths.
  Mitigation: the differential parity test and the existing Kani harnesses gate
  the extraction; if any extraction is not clearly behavior-preserving, take
  the demote-and-differential-test path instead, which is pure metadata plus a
  test.
- Modeling effort under-delivers. TLA models can drift from the code they claim
  to constrain (the exact failure this plan fixes elsewhere). Mitigation: each
  new model ships with a MAPPING.md row naming the Rust path, and the RFC that
  owns the code owns a runtime test that cross-checks the invariant.
- Alternative considered and rejected: make `check-mapping.sh` advisory
  (non-blocking). Rejected; an advisory traceability gate is the status quo
  that let two harnesses drift. Fail-closed or it does not hold.
- Alternative considered and rejected: keep `--no-unwinding-checks` everywhere
  and rely on review to bound loops. Rejected; review cannot see a future loop
  growth, which is precisely the F42 trigger.

## Rollout and sequencing

1. Workstream 1 (days), single hardening PR series: fix the two MAPPING rows and
   the stale citations, wire `check-mapping.sh`, register the fairness
   assumption, add the `kani-public-pr` job and the loom lane as non-required,
   and remove `--no-unwinding-checks` from the nightly sufficiency lane. This is
   the highest-value, lowest-risk work and lands first.
2. Workstream 3 (days), independent PR: the proptest state machine plus its
   dev-dependencies and coverage-gate registration.
3. Workstream 4 (days), independent PR(s): the `proof-manifest.toml` /
   `creusot-contracts.toml` splits, the differential parity test, and any
   behavior-preserving `formal_core` bindings.
4. Workstream 2 (weeks): `ReceiptLifecycle.tla` lands alongside or after
   RFC-0002 and RFC-0003 (it is their design proof); `BudgetReplication.tla`
   lands alongside or after RFC-0011 (it is its design proof, referenced there
   by name). Neither gates the earlier workstreams.
5. Workstream 5 routing is a documentation and backlog action taken up front (it
   costs nothing and prevents misdirected effort), with the actual harnesses
   owned by the load-chaos program plan. The deferred distributed-time TLA
   extension for F48 follows `BudgetReplication.tla`.
