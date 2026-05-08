# Trajectory 5 - Lane A: Realize the Floor

**Status**: planned. **Owner-class**: Substrate eng (Lane A from trj4 EXECUTION-BOARD), with formal-methods support for sub-lane A4/A5.

**Window**: ~8 weeks, parallelizable with Lane B (no inter-lane dependency).

## What this lane is

Lane A is the assurance-floor lane. It absorbs the trj4 carry-forwards under
TRJ4-010..014, TRJ4-015..018, and TRJ4-040..047, and re-frames them with
**real-evidence** acceptance criteria. The release work synthesis is explicit:

> "Mutation kill 31% -> >=65% trust-boundary, >=80% on `chio-attest-verify`.
>  README banner reflects observed kill, not target."
>
> ".planning/trajectory-5/debate/00-SYNTHESIS.md", lines 77-78.

> "All 20 `audits/evidence/threats/*.json` files contain real `caught >= 1`
>  data with non-1970 `ran_at`."
>
> ".planning/trajectory-5/debate/00-SYNTHESIS.md", lines 79-81 (with
> threat-count corrected per Wave 3 review; see "Authoritative threat
> count" footnote below).

## Trj5 ship-bar items Lane A owns

Trj5 closes when three things are observably true (synthesis lines 146-158).
Lane A is wholly responsible for ship-bar item 1, partially for item 2:

1. **Ship-bar 1** (Lane A): "README mutation banner reads >=65% with the
   per-crate breakdown attached and a non-placeholder evidence directory."
2. **Ship-bar 2** (Lane B owns wiring; Lane A owns the evidence floor that
   trust-boundary mutation gives auditors confidence in the wired primitives).

## Sub-lane summary

| Sub-lane | Title | Source ticket(s) | Effort |
|---|---|---|---|
| A1 | Mutation uplift to >=65% / >=80% | TRJ4-010, TRJ4-011 | L |
| A2 | Threat-evidence backfill (20 files) | TRJ4-040..049 | L |
| A3 | Kani harnesses on three deferred crates | TRJ4-012, TRJ4-013, TRJ4-014 | L |
| A4 | TLA+ rewrites + apalache-temporal required | TRJ4-015..018 | M |
| A5 | Lean4 `negotiation_safety` against executable model | (new, from synthesis Quality #3) | M |

(`TRJ4-019` (proptest hosted-vs-portable equivalence) is **deferred to
trj6** per Wave 3 review; rationale recorded in planning docs's
"On the dropped TRJ4-019" section and in `SCOPE-LOCK.md`.)

Detailed per-sub-lane scope, acceptance, and evidence is in `PLAN.md`. Concrete
tickets live in planning docs. Sub-lane-specific deep dives live in
`mutation-budget.md`, `threat-evidence-backfill.md`, `kani-harness-design.md`,
`tla-rewrites.md`, and `lean4-fix.md`.

## Dependencies

- **Lane B**: none. Lane A can run end-to-end without Lane B's wiring work.
  The honest reading is the reverse: Lane B's protocol-realization claims are
  only credible if Lane A's mutation kill clears the floor on the same crates
  where Lane B is wiring single-entry verifiers and fail-closed receipt
  paths.
- **Lane C**: none.
- **Lane A internal**: A2 takes a soft dependency on A1's mutation
  infrastructure (the per-row gate at
  `scripts/check-threat-coverage-mutants.sh` runs cargo-mutants under the
  hood). A4 sub-tickets release work-A4.3/A4.4 depend on release work-A4.1/A4.2 landing.

## Week-by-week timeline

The plan assumes one substrate engineer on A1+A2+A3, one formal-methods
engineer on A4+A5, both starting Week 1. If only one engineer is available,
add 4-6 weeks.

| Week | Sub-lane focus | Concrete output |
|---|---|---|
| 1 | A1 baseline; A4 ReceiptBeforeAllow split | First per-crate kill numbers in `releases.toml`; `Allow` action split into `LogReceipt` + `PublishAllow`. |
| 2 | A1 attest-verify push; A4 RevocationCutCompleteness | `chio-attest-verify` >= 50% on first sweep; `RevocationCutCompleteness` rewritten with bounded transitive closure depth >= 3. |
| 3 | A1 attest-verify >= 80%; A4 EpochMax 4->6 | First `chio-attest-verify` survivor file annotated with `# unreachable:` justifications; `EpochMax = 6` lands. |
| 4 | A1 remaining 5 crates >= 65%; A4 apalache-temporal required | Two consecutive nightly green runs on `mutants.yml`; `apalache-temporal.yml` flips from advisory to required. |
| 5 | A2 backfill 6 weak rows (native_channel_replay etc.); A3 chio-attest-verify Kani | First six `audits/evidence/threats/*.json` files carry real `caught >= 1` runs; `crates/chio-attest-verify/src/kani_public_harnesses.rs` lands with >= 4 `#[kani::proof]` functions. |
| 6 | A2 backfill 7 more rows; A3 chio-anchor Kani; A5 Lean refinement | Twelve threat-evidence files real; `chio-anchor` Kani harness merged; Lean4 `negotiation_safety` re-stated to take an executable-model term. |
| 7 | A2 backfill final rows; A3 chio-weights Kani | Twenty threat-evidence files real; all three Kani harnesses passing nightly. |
| 8 | A1 banner update; A4/A5 closeout; Evidence Gate sweep | README mutation banner re-rendered to **observed** kill, not target; release work ship-bar 1 closed. |

## Acceptance (visible from outside the project)

The following must all be true on the release work closeout commit:

- `bash scripts/check-threat-coverage-mutants.sh` (default mode, no
  `--dry-run`) returns exit 0 with no `bootstrap_placeholder`,
  `inconsistent_bootstrap`, `bootstrap_expired`, or `zero_kills` rows.
- `releases.toml [per_crate_kill_rate_percent]` lists each of the six
  trust-boundary crates with a numeric kill rate; the lowest is `>=65` and
  `chio-attest-verify` is `>=80`.
- `README.md` mutation banner cites the lowest per-crate kill rate observed
  (see `mutation-budget.md` for exact format), not the target.
- `mutants.yml` shows two consecutive successful nightly runs with
  `status_at_capture: success`.
- `audits/evidence/threats/<id>.json` for all 20 threat IDs satisfies the
  trio `caught >= 1`, `needs_real_run: false`, `ran_at` is a real ISO-8601
  timestamp from 2026 (not `1970-01-01T00:00:00Z`). If Wave 1 triage
  flips one or more rows to `BLOCKED-BY-ARCHITECTURE` (R3 escalation
  fires when count exceeds 2), the close bar reads "<n> of 20 covered,
  <m> deferred to trj6"; the synthesis ship-bar 1 narrows accordingly,
  and the README banner reflects the narrowed claim.
- `crates/chio-attest-verify/src/kani_public_harnesses.rs`,
  `crates/chio-anchor/src/kani_public_harnesses.rs`,
  `crates/chio-weights/src/kani_public_harnesses.rs` each exist with >= 4
  `#[kani::proof]` functions and pass nightly Kani CI.
- `apalache-temporal.yml` is in the required CI lane (not advisory).
- `formal/lean4/Chio/Chio/Proofs/HandshakeNegotiation.lean` proves
  `negotiation_safety` by refinement against an executable-model term that
  is shared with the Rust verifier signature, not by `rfl` against its own
  definition.

## CI workflow inventory (R2 MAJOR Section 10.2)

Every Lane A close-bar artifact gates on one or more
`.github/workflows/*.yml` files. The full inventory:

| Workflow | Touch type | Owning ticket |
|---|---|---|
| `mutants.yml` | modify (un-flake; per-crate runs) | mutation evidence item, mutation evidence item |
| `mutants-banner.yml` | modify (banner script reads observed kill rate) | mutation evidence item |
| `mutants-fuzz-cocoverage.yml` | confirm-no-touch (Wave 1 verifies this workflow does not need Lane A changes) | mutation exclusion audit (audit) |
| `nightly.yml` | modify (multi-crate Kani lane; lines 102-128) | Kani multi-crate manifestb |
| `ci.yml` | modify (`kani-public-pr` job lines 478-590) | Kani multi-crate manifestb |
| `apalache-safety.yml` | modify (add new invariants to cfg) | release work-A4.1, release work-A4.2 |
| `apalache-temporal.yml` | gate-promotion (advisory -> required) | release work-A4.4 |
| `lean.yml` | create (new workflow for Lean toolchain CI) | release work-A5.1 |
| `close-bar-tracker.yml` | confirm-no-touch (existing workflow runs `scripts/check-release work-evidence-gate.sh` once Wave 1 lands the script; Lane A close-bar promotion does not edit the workflow itself) | (n/a) |

Each Lane A ticket that changes CI names the workflow file diff
in its acceptance section.

## Anti-patterns this lane explicitly refuses

The release work Quality Skeptic identified the failure modes that re-fired the trj4
erratum (`.planning/trajectory-5/debate/04-quality-verification-skeptic.md`,
lines 25-31, 35-37, 50-52). Lane A acceptance forbids each:

- A threat-evidence file with `caught: 0`, `needs_real_run: true`, or
  `ran_at: "1970-01-01T00:00:00Z"`.
- A README banner that names a target rate ("Mutation kill: 65%+") rather
  than an observed rate.
- A Kani file that imports `kani::` but contains zero `#[kani::proof]`
  functions, or whose harnesses pass under `kani::assume(false)`.
- A Lean theorem proven by `rfl` against the same definition that defines
  the function under test.
- An `apalache-temporal.yml` job marked `continue-on-error: true` after
  release work-A4.4 lands.

## Authoritative threat count (Wave 3 reconciliation)

The synthesis (`debate/00-SYNTHESIS.md` line 79) names "21" threat
evidence files. The on-disk count under `audits/evidence/threats/` is
**20** (verified 2026-05-07: `ls audits/evidence/threats/ | wc -l`
returns 20; `grep -c '"id":' spec/security/chio-threat-model.v1.json`
returns 20).

**Lane A targets the on-disk count of 20** as the authoritative
number. The synthesis "21" is a minor arithmetic drift; Wave 3 patches
the master docs (`SHIP-BAR-TRACKER.md`, `EXECUTION-BOARD.md`,
`SCOPE-LOCK.md`, `KICKOFF-CHECKLIST.md`, top-level `README.md`,
`architecture/RISK-REGISTER.md`) to use 20 consistently. The synthesis
is not re-opened; the patch carries a footnote explaining the drift.

## Assumptions (called out for the parent agent)

The agent had to make one residual assumption because the codebase was
ambiguous:

1. **TLA+ property names.** The synthesis names `RevocationCutCompleteness`,
   `ReceiptBeforeAllow`, `RevocationEventuallySeen`. Today
   `formal/tla/RevocationPropagation.tla` only exports
   `RevocationEventuallySeen` (line 379). The other two property names do
   not exist yet. Lane A treats TRJ4-015 and TRJ4-016 as **introducing**
   those properties as part of the rewrite, which matches the original
   ticket text ("rewrite", "split"). See `tla-rewrites.md` for the exact
   target shape.
