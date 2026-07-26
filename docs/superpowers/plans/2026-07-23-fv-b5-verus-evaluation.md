# FV-B5 Verus Concurrency Evaluation Implementation Plan

> Implement in order. Do not begin a later phase while an earlier phase's
> acceptance gate is red. The two-week cap is absolute: on day 14 the decision
> phase runs against whatever exists, including a partial artifact.

**Goal:** Execute the [FV-B5](../../formal/plan/FV-B5-verus-concurrency-evaluation.md)
spike: prove the FV-B3 conservation law for a concurrent multi-hold ledger
protocol in a VerusSync tokenized state machine, unbounded in schedules and
amounts; falsify it with two broken variants; measure toolchain cost; apply
the spec's decision rule and record the outcome.

**Architecture:** Everything lives under `formal/experiments/verus-eval/`, a
self-contained workspace following the `formal/rust-verification/creusot-core`
pattern (its own `[workspace]` table; `formal/` is outside the root members
globs, so the root `Cargo.toml` is not edited). The artifact is model-level.
The only file outside the experiment directory this plan may edit is
`docs/formal/plan/FV-B5-verus-concurrency-evaluation.md`, at close-out.

**Normative spec:** the FV-B5 plan spec. Where this plan and the spec
disagree, the spec wins.

## Global constraints

- No em dashes in code, comments, or documentation.
- The two-week cap and the day-5 and day-8 checkpoints below are hard.
- No claims: nothing in the experiment may be cited by
  `docs/reference/CLAIM_REGISTRY.md`, `formal/proof-manifest.toml`,
  `formal/MAPPING.md`, `docs/formal/COVERAGE.md`, or `releases.toml`.
- Pinning is fail-closed: exact release tag plus asset sha256 for the Verus
  binary, `rust-toolchain.toml` pinning the release's required rustc, and an
  install script that refuses on digest mismatch.
- Every working session appends one line to `MEASUREMENTS.md` (date, phase,
  hours, verification wall time). The decision rule consumes these numbers;
  an unrecorded measurement is a red gate, not missing bookkeeping.
- The green artifact and its mutations share sources behind cfg features; the
  default build is always the green artifact.
- The root workspace clippy denies do not reach the experiment workspace;
  executable code in it still avoids `unwrap` and `expect` except where the
  proof dialect requires a construct, and each such site carries a comment.

## Existing contracts that must remain green

- Root workspace untouched: until Phase 4, `git status` shows changes only
  under `formal/experiments/verus-eval/`.
- `cargo build --workspace`, tests, clippy, and fmt on the root workspace are
  unaffected by the experiment's presence.
- `crates/kernel/chio-kernel-core/src/formal_aeneas.rs`,
  `crates/kernel/chio-kernel/src/budget_store.rs`, and all six evidence lanes:
  untouched.
- The FV-B5 row in `docs/formal/ROADMAP.md` stays `Proposed` until Phase 4
  records the outcome.

## Directory layout

```
formal/experiments/verus-eval/
  README.md               charter, pinned versions, exact verification command
  MEASUREMENTS.md         effort log and wall times (append-only)
  tools/install-verus.sh  pinned fail-closed installer
  tools/run-falsification.sh
  falsification/          captured failing verifier output (committed)
  ledger/
    Cargo.toml            own [workspace]; publish = false
    rust-toolchain.toml   the pinned rustc the release requires
    src/lib.rs            module wiring
    src/sequential.rs     Phase 1 warm-up
    src/sync.rs           Phase 2 tokenized state machine
    src/mutations.rs      Phase 3 broken variants, cfg-gated
```

## Phase 0: Toolchain (day 1)

1. Resolve the newest tagged Verus release at execution time. Record the tag,
   the release-asset sha256, and the required rustc version in the
   `tools/install-verus.sh` header and `README.md`.
2. Write `tools/install-verus.sh` mirroring `tools/install-apalache.sh`:
   idempotent, downloads to `~/.local/share/verus/<tag>`, verifies the pinned
   digest before extraction, links the binary into `~/.local/bin`, and allows
   reuse of an existing install only through an explicit
   `VERUS_TRUST_EXISTING=1` opt-in.
3. Create the `ledger/` package (edition 2021, `publish = false`, its own
   `[workspace]`), pin `rust-toolchain.toml`, and add the `vstd` dependency in
   the form the pinned release documents.
4. Verify a minimal spec function end to end. Record cold-install wall time
   and first-verification wall time. Record the exact verification command in
   `README.md` (prefer the release's cargo integration if it ships one,
   otherwise the direct binary invocation).

Acceptance gate: the installer succeeds twice in a row on a clean prefix
(idempotence), a deliberately corrupted digest is refused, the minimal
function verifies, and both wall times are in `MEASUREMENTS.md`.

## Phase 1: Sequential warm-up (days 2-4)

1. `src/sequential.rs`: transcribe the `ledger_apply` semantics into the
   dialect, keeping the field vocabulary of
   `formal_aeneas.rs::ReservationLedger` (`reserved` meaning outstanding,
   `committed`, `released`, `retained`) and the op encoding `0..=3`. The
   module header states it is a hand transcription with no drift hash and no
   claim.
2. Contract parity with the original: invalid operations and every checked-add
   overflow return the unchanged state with `valid == false`; valid operations
   preserve the partition. State both as `ensures` clauses.
3. Prove the fold lemma: any sequence of valid operations preserves the
   partition sum (the analogue of Lean's `ledger_conservation`).
4. Write the absorption cost note in `MEASUREMENTS.md`: what rewriting the
   production `formal_aeneas.rs` surface into the dialect would perturb (the
   Charon and Aeneas extraction inputs, the Creusot unconditional include and
   its body-sync gate, the Kani harnesses, the committed Lean snapshots), with
   a rough effort figure. This note is an input to decision outcome (b).

Acceptance gate: verification passes with zero errors; effort hours, wall
time, and an annotation-to-code line ratio are recorded; the absorption note
exists. Checkpoint: if this gate is still red at the end of day 5, skip
directly to Phase 4 and record a negative technical result.

## Phase 2: Concurrent artifact (days 5-9)

1. `src/sync.rs`: `tokenized_state_machine!` `ReservationLedgerSync`. Opening
   sharding strategy: `#[sharding(map)]` for per-hold tokens
   (`HoldId -> HoldState`, terminal states yield no further token) plus
   `#[sharding(variable)]` for the four-bucket totals. If that pairing fights
   the invariant proofs, fall back to the release's documented alternatives
   and record the final choice and the reason in `README.md`; the spec names
   the sharding strategy as a spike deliverable.
2. Transitions `authorize`, `reverse`, `release`, `reconcile`, each with
   overflow-guarded enabling conditions.
3. The three spike properties as named lemmas matching the spec: conservation
   at every reachable state, terminal uniqueness (no transition can consume a
   terminal hold's token), and fail-closed arithmetic (no enabled transition
   overflows).
4. Record full-verification wall time for the concurrent module alone.

Acceptance gate: all three properties verify with no bound on schedules,
actors, or amounts. Grep the module for `assume`, `admit`, and loop bounds:
each hit is either removed or carries a written justification, otherwise the
gate is red. Checkpoint: if the invariant set is not closing by the end of
day 8, descope to conservation-only, record the descope in `MEASUREMENTS.md`,
and continue; a descoped artifact fails decision criterion 1 honestly.

## Phase 3: Falsification (days 10-11)

1. `src/mutations.rs` behind two features, `mutation_terminal` and
   `mutation_overflow`. Each variant alters exactly one transition: the first
   re-enables an operation on a terminal hold, the second drops one
   checked-add guard.
2. `tools/run-falsification.sh` verifies each mutated configuration and
   captures the verifier output to `falsification/terminal.log` and
   `falsification/overflow.log`. The script exits nonzero if a mutation
   verifies; the failure direction is enforced by the tool, not by reading
   logs.
3. Re-verify the default build green after the mutation work.

Acceptance gate: both committed logs show failed verification, the runner
enforces the direction, and the default build is green.

## Phase 4: Decision and close-out (days 12-14)

1. Evaluate the spec's decision rule. Criterion 2 is measured: cold install
   plus full verification under 15 minutes, from `MEASUREMENTS.md`. Criterion
   3 is checked against `releases.toml` and `scripts/lane-gate.sh`: has any
   existing lane completed the promotion runbook.
2. Write the outcome (b) memo: the cost of reproducing the nine Creusot
   contract twins through the absorption route, against Lane 3's unconditional
   production include. The spec expects a negative resolution; write the memo
   either way.
3. Edit `docs/formal/plan/FV-B5-verus-concurrency-evaluation.md`: resolve
   every acceptance checkbox to checked or explicitly failed, and append an
   Outcome section with the measurements, the criterion-by-criterion result,
   and the decision. If criteria 1, 2, and 4 held and only the enforcement
   precondition (criterion 3) failed, name it as the sole blocker so a later
   revisit does not rerun the spike.
4. If outcome (a) is taken, open the lane-integration spec as a separate
   document; every registry, MAPPING, coverage, and `releases.toml` change
   belongs there. Otherwise the artifacts stay in place under
   `formal/experiments/verus-eval/` with the closing note, per the spec's
   archive rule.

Acceptance gate: the spec file records the outcome; the working tree has no
diff outside `formal/experiments/verus-eval/` and the spec file; the final
commit message states the decision.

## Commit discipline

Conventional commits, at least one per phase, so no phase's work can be lost
to a later failure. Experiment code and prose are held to the same standard
as production: no scaffolding comments, no phase or session markers in code,
no placeholder text.
