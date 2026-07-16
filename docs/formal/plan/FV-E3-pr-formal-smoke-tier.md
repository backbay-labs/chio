# FV-E3: A PR-time formal smoke tier

Status: Implemented (2026-07-09)
Theme: E - Verify the verification, and make lanes bite
Effort: S
Depends on: none
Feeds: [FV-E5](FV-E5-lane-ratchets.md),
[FV-A4](FV-A4-mirror-drift-hashes.md),
[FV-E1](FV-E1-spec-mutation-testing.md)
Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md),
`.github/workflows/README.md`, [FV-E4](FV-E4-fuzz-plumbing-repair.md)

## Summary

`.github/workflows/formal-pr-smoke.yml` provides path-scoped pull-request
feedback for Lean, Kani, and Rust verification metadata. A lightweight scope
job classifies the changed files before a proof toolchain is installed. The
workflow has five verification jobs:

1. `lean-build (lake + sorry scan + manifest cross-ref)` runs
   `scripts/check-formal-proofs.sh` with cached elan and Lake state.
2. `kani-public-pr (lanes.pr sweep)` runs the 25 public kernel-core harnesses
   declared in `formal/rust-verification/kani-public-harnesses.toml`.
3. `kani-manifest-pr (non-core lanes.pr sweep)` runs the 16 PR harnesses for
   chio-attest-verify, chio-anchor, and chio-weights from
   `.kani/harnesses.toml`.
4. `rust-verification-metadata (schema only, no proofs)` runs
   `scripts/check-rust-verification-gates.sh` with
   `CHIO_RUST_VERIFICATION_METADATA_ONLY=1`.
5. `fuzz-corpus-smoke-pr` validates the locked corpus, metadata, and target
   ownership contracts for affected paths.

The mutation workflow now has a path-scoped `pull_request` trigger for six
trust-boundary crates. Each matrix entry checks the PR diff before installing
Rust or cargo-mutants. Same-repository PRs retain comment and survivor-issue
triage; fork PRs skip token writes while the mutation result remains enforced.

The new checks are not branch-protection requirements at introduction. Strict
Creusot checks and the complete Kani union remain nightly and in release
qualification.

## Decisions

- Use a dedicated workflow instead of expanding the required `ci.yml` job.
  This preserves the existing required contexts and makes each formal lane's
  cost and result visible independently.
- Trigger on path-scoped pull requests and manual dispatch, not push to main.
  Nightly provides merge-skew coverage without adding a second proof run for
  every merge.
- Classify paths once in a cheap `formal scope` job. Manual dispatch selects
  every lane; PRs select only the affected verification jobs.
- Make `scripts/check-kani-public-core.sh` consume the TOML registry directly.
  Its default is `--lane pr`, `--lane all` supplies the nightly union, and
  `--list` supports proof-free integrity checks.
- Keep non-core Kani coverage in a separate job. This preserves a precise
  25-harness public-core check while retaining the 16 non-core PR harnesses.
- Keep strict Creusot off the PR path. The PR job is named and logged as
  metadata-only so it cannot be mistaken for proof execution.
- Revive the existing mutation PR machinery rather than delete it. Package
  selection happens before tool installation and global mutation-control
  changes deliberately select all six packages.
- Skip GitHub comment and issue writes for fork PRs. Read-only fork tokens do
  not weaken mutation execution or gate enforcement.
- Keep Kani and elan versions in lockstep with `nightly.yml`; cache keys include
  the pinned versions and Lean toolchain identity.

## Path Scopes

The workflow-level filter is the union of all relevant paths. The scope job
then applies these narrower sets:

| Job | Primary paths |
| --- | --- |
| Lean | `formal/lean4/**`, proof and theorem registries, assumptions, claim registry, proof-check script |
| Core Kani | kernel-core, core-types, revocation-oracle, public harness registry, core runner |
| Non-core Kani | attest-verify, anchor, weights, multi-crate manifest and runner |
| Rust metadata | `formal/rust-verification/**`, metadata gate script |

Workflow, root Cargo, lockfile, and Rust toolchain changes select every
applicable Rust lane. Editing the formal workflow selects all four lanes.

The mutation workflow filters to the six trust-boundary crate source trees,
their mutation configuration, shared mutation scripts, `releases.toml`, and
the workflow itself. A per-package diff check prevents untouched matrix entries
from paying setup or mutation costs.

## Runtime Budget

These values remain estimates until hosted runs provide measurements:

| Job | Cold estimate | Warm estimate | Dominant cost |
| --- | --- | --- | --- |
| lean-build | 4-6 min | 1-3 min | elan and Lake build |
| kani-public-pr | 12-15 min | 8-10 min | Kani setup and 24 harnesses |
| kani-manifest-pr | 15-45 min | 10-35 min | feature builds and 12 harnesses |
| rust-verification-metadata | about 2 min | about 1 min | checkout and schema checks |
| mutants-pr, per selected crate | 15-45 min | similar | baseline build and in-diff mutants |

The Kani registries retain their existing lane membership. No harness was moved
between PR and nightly-only lanes. Runtime pressure must be addressed with
measured evidence before changing coverage.

## CI And Gating Changes

- `formal-pr-smoke.yml` adds four advisory verification check contexts plus the
  lightweight scope context.
- `mutants.yml` gains an active, path-scoped PR trigger; its evidence-gated
  advisory-to-blocking state machine remains controlled by `releases.toml`.
- `nightly.yml` calls the same registry-driven public-core runner with
  `--lane all`, then runs the non-core PR and nightly manifest lanes.
- The four existing required contexts are unchanged. Promotion is governed by
  [FV-E5](FV-E5-lane-ratchets.md).

## Acceptance Criteria

- [x] The public-core runner lists exactly the 24 registered PR harnesses
  without invoking Kani.
- [x] The non-core manifest runner lists exactly 16 registered PR harnesses
  when chio-kernel-core is excluded.
- [x] The Rust metadata job name and log explicitly state that no proofs run.
- [x] Unrelated documentation paths do not trigger the formal workflow.
- [x] Mutation matrix entries select only touched crates unless shared mutation
  controls changed.
- [x] Fork PRs do not attempt comment or issue writes, while gate enforcement
  remains active.
- [x] Nightly and PR core Kani jobs use the same registry-driven runner.
- [x] Kani and elan pins match between PR and nightly workflows.
- [ ] Observe a hosted Lean PR failure for a broken proof or introduced
  `sorry`, then record the run.
- [ ] Observe a hosted core Kani PR run executing all 25 harnesses.
- [ ] Measure three warm hosted Kani runs and keep the public-core job at or
  below 10 minutes, or propose named lane changes with evidence.
- [ ] Observe mutation comment, advisory result, and under-one-minute no-op
  behavior on a same-repository PR.

## Risks And Mitigations

- Kani runtime may exceed the estimates. Keep the workflow path-scoped and use
  hosted measurements before changing lane membership.
- A path filter can miss a dependency. Nightly still runs the complete lanes;
  covered-symbol changes must include scope review.
- Cached Kani or elan state can become stale after a version bump. Versioned
  keys roll both caches when pins change.
- A path-scoped check marked required too early can remain in an expected state
  on unrelated PRs. Required-check promotion must first add a run-always
  successful no-op path.

## Manifest And Registry Updates

- `.kani/harnesses.toml` and
  `formal/rust-verification/kani-public-harnesses.toml` retain their harness and
  lane membership. Only their cadence descriptions change.
- `releases.toml` is unchanged. Check promotion metadata belongs to
  [FV-E5](FV-E5-lane-ratchets.md).
- `.github/workflows/README.md` records the new checks as present but not
  required.
- `formal/OWNERS.md` assigns maintenance of PR path scopes and pin lockstep to
  the formal owners.
