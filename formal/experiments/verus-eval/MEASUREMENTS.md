# FV-B5 measurements

Append-only. One line per working session plus named measurements. The
decision rule in the FV-B5 spec consumes these numbers; an unrecorded
measurement is a red acceptance gate.

## Session log

| Date | Phase | Work | Wall time |
| --- | --- | --- | --- |
| 2026-07-23 | 0 | Release resolution, installer, x86 asset digest | - |
| 2026-07-23 | 0 | vstd verification on aarch64 (2055 items, 0 errors) | 79.5 s |
| 2026-07-23 | 1 | `ledger_apply` transcription, step and fold lemmas (8 items) | 2.1 s verify |
| 2026-07-23 | 2 | Sum lemmas plus `ReservationLedgerSync` (11 items) | 1.8 s verify |
| 2026-07-23 | 3 | Both mutations rejected on their target invariants | ~4 s each |
| 2026-07-23 | 0 | Scripted clean-prefix cold install (z3 and Verus source builds, vstd verified) | 16 m 25.65 s |
| 2026-07-23 | 0 | Second installer run on the existing install (relink path) | 0.016 s |
| 2026-07-23 | 0 | Corrupted-pin refusal test in an isolated prefix | refused, exit 2 |
| 2026-07-23 | 4 | Decision rule applied; outcome recorded in the spec | - |

## Phase 0 acceptance notes

- The x86 sha256 gate cannot execute on this host (the platform switch
  takes the source-build path); the pinned digest was computed directly
  from the downloaded release asset. A hosted x86 run exercises that gate.
- The full ledger crate re-verified (19 items, 1.7 s) and the
  falsification runner passed against the freshly installed toolchain.

## Phase 1 findings

- Annotation-to-code ratio in `sequential.rs`: roughly 148 spec and proof
  lines against 82 executable lines (1.8:1). The full contract (exact
  no-op on rejection, aggregate-overflow rejection, terminal absorption,
  step and fold conservation) verified without any manual SMT coaxing;
  the only iteration was mechanical API renames against the pinned vstd
  (`verus_state_machines_macros`, `Set` now always finite) and one
  nat/int cast.
- Absorption cost estimate: rewriting the production `formal_aeneas.rs`
  surface inside `verus!` would break the inputs of all four consuming
  lanes at once: Charon parses the plain Rust source (macro-wrapped code
  changes the extraction input), the Creusot body-sync gate includes the
  file verbatim, the Kani harnesses and kernel callers would need the
  Verus toolchain in the workspace build graph, and every committed Lean
  snapshot equivalence would shift. Weeks of restructuring, not days, and
  it puts vstd into the production dependency graph. If a lane is ever
  created, mirror-plus-drift-hash (FV-A4 pattern) is the realistic
  linkage, not absorption.

## Phase 2 findings

- Sharding: `map` per-hold tokens plus `variable` totals worked as
  planned; no fallback strategy was needed. The hold-sum coupling
  invariant needed the classic arbitrary-order map-sum lemma
  (`lemma_holds_sum_remove`, proved by strong induction with a
  commutation step); z3 discharged it without fuel or trigger tuning.
- All three spike properties hold with no schedule, actor, or amount
  bound: conservation and the u64 bound as state invariants,
  terminal uniqueness by token consumption plus the `used` set (no id
  re-admission). Grep audit: no `assume`, `admit`, `external_body`, or
  trusted escape in the artifact.

## Phase 3 findings

- `mutation_terminal` (commit retains the hold token): rejected,
  `could not show invariant inv_outstanding_is_hold_sum on the post
  state` at the commit inductive lemma. `falsification/terminal.log`.
- `mutation_overflow` (authorize drops the checked-add guard): rejected,
  `could not show invariant inv_u64_bound on the post state` at the
  authorize inductive lemma. `falsification/overflow.log`.
- Both failures land on exactly the invariant each mutation attacks,
  which also demonstrates the machine's invariant obligations are real.

## Toolchain findings

- Upstream publishes no aarch64-linux Verus binary asset for
  `release/0.2026.07.18.3a4d30b` (assets: x86-linux, x86/arm64-macos,
  x86-win). aarch64 hosts must build from source. Criterion 2 input.
- The upstream z3 4.12.5 `arm64-glibc-2.35` release zip contains an x86-64
  ELF binary; the installer's architecture gate caught it. aarch64 hosts
  therefore build z3 from pinned source (`z3-4.12.5`, commit
  `a7b564cafe3b96c8a868388bc4b96b319facea44`) as well. Criterion 2 input.
