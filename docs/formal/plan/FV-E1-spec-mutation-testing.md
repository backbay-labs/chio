# FV-E1: Mutation testing for specifications and proof models

Status: Implemented (2026-07-16; local full-cycle evidence complete, hosted runs pending)
Theme: E - Verify the verification, and make lanes bite
Effort: M
Depends on: [FV-B2](FV-B2-regression-negative-tests.md)
Feeds: [FV-E5](FV-E5-lane-ratchets.md), [FV-C5](FV-C5-proof-coverage-map.md)
Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md),
`formal/apalache/_negative_tests/README.md`, `docs/fuzzing/mutants.md`

## Result boundary

The implementation measures whether formal properties react when their
modeled system changes. It does not mutate the property being checked and it
does not turn a high kill ratio into a correctness claim. A survivor is a
sensitivity lead that needs one of three dispositions: strengthen the
property or oracle, remove dead model code, or document semantic equivalence.

Three scheduled jobs are implemented:

1. `spec-mutants` changes allowlisted TLA+ actions and runs Apalache 0.50.1.
2. `proof-mutants` discovers Rust model mutations with cargo-mutants 25.3.1,
   applies them in a scratch worktree, and runs the clean Kani core lane.
3. `lean-mutants` is a non-ratcheted pilot over allowlisted computable Lean
   definitions. A failed `lake build` kills the mutant.

The two scored lanes use the same activation formula:

```text
killed / (killed + survived + timeout)
```

Rust compilation failures may be classified as `unviable` and are excluded
from that lane's ratio. The TLA+ lane admits only exact, curated, type-valid
probes. A parser or type failure there is a fail-closed execution error, not an
excluded verdict. Timeouts remain in the denominator and therefore reduce the
activation ratio.

## Measured local evidence

- The full specification campaign enumerated 33 mutants across seven sources,
  killed 32, timed out one, and produced no survivor or unviable result. Global
  activation was 96.97 percent, and every source met its 90 percent target.
  The retained v1 report is bound to commit
  `7b24142e8523fe08e501063dbf3d4f6cea3397be`, completed at
  `2026-07-16T11:08:14Z`, and has SHA-256
  `82878e03aaafa1ceeb1f791386cffd57f9f88453b24113bd51e43b67996a66c2`.
- The retained Lean pilot enumerated 45 mutants, killed 33, and left 12
  survivors with no timeout, for 73.333 percent activation. This pilot remains
  visible but does not participate in the scored release ratchet.
- The full Rust campaign enumerated 166 mutants across both registered model
  files, killed 160, left one survivor, classified five as unviable, and had
  no timeout. Global activation was 99.379 percent and viability was 96.988
  percent. The survivor that widens the budget admission predicate is tracked
  by issue #1019.

## Rule zero

Only the system under verification is mutable.

- TLA+ mutation is limited to actions explicitly listed in
  `formal/apalache/spec-mutants-allowlist.toml`. The loader proves that each
  action is reachable from `Next`, rejects `Init` and `Next`, and rejects any
  action in the configured invariant's transitive definition closure.
- Rust mutation is limited to `formal_core.rs` and `formal_aeneas.rs` through
  both the focused config and repository-relative `-f` arguments. Kani
  harness files and all harness assertions and assumptions are outside the
  discovery set. Every emitted span must also fall inside the declared Rust
  function body, excluding the Creusot contract attributes above functions.
- Lean mutation is limited to declarations classified as `def` and named in
  `formal/lean4/lean-mutants-allowlist.toml`. The parser never admits a
  theorem, lemma, axiom, or non-allowlisted definition.

Every allowlist and parser has a synthetic fail-closed self-test.

## TLA+ action mutation

### Inventory

`scripts/spec-mutants.py --list` deterministically enumerates 31 exact curated
probes and two mandatory registered historical seeds over the seven positive
safety models currently run by `apalache-safety.yml`, including
`PostAdmissionDropGuard`. The allowlist schema is
`chio.spec-mutants-allowlist.v1`. Every probe names one source, reachable
action, exact match, exact replacement, classification, and rationale. The two
admitted classifications are:

- `guard-weakening`, which deletes or weakens an exact action guard;
- `post-state-corruption`, which changes an exact primed-state expression.

The runner rejects missing, duplicate, ambiguous, or out-of-action matches.
It does not synthesize broad lexical mutations or edit model scaffolding,
typing predicates, invariants, `Init`, or `Next`. The production model-check
bound is 6 for six sources and 8 for `PostAdmissionDropGuard`.

The 33-entry inventory is sorted by source, action, position, operator, and
replacement. Each identifier is a stable SHA-256 projection of that identity.
A scheduled sample of 16 is deterministic and stratified: both historical
seeds and at least one probe from each of the seven sources are mandatory, and
the remaining positions rotate through a commit-seeded, epoch-indexed
permutation. `--sample-epoch` reproduces a scheduled selection locally.

### Registered negative preflight

Every scored run first invokes `scripts/check-apalache-negative.sh`. That is
the same fail-closed runner used by the `apalache-negative` job, including its
exact invariant and outcome parser and strict ITF validation. The shared
implementation is `scripts/lib/apalache_evidence.py`.

The inventory records two historical variants as mandatory seeds:

- deletion of `HasAllowReceipt(a, c)` from `PublishAllow`;
- replacement of `DescendsFrom(c, root)` by `c = root` in `Revoke`.

The seed validator requires the production expression, the corresponding
replacement in the broken action, and a matching entry in the negative
registry. Both seeds run in every sample and full campaign. Every registered
negative must pass before generated mutants run.

Every scored run also checks all seven unmodified positive models before any
generated mutant. Each clean model uses the same isolated inputs, bound,
configuration, invariant parser, and `--no-deadlock` posture as its mutants.
The clean baseline has a separate 10,800-second budget matching the safety lane;
generated mutants retain their 300-second limit. A timeout, violation,
malformed result, or tool failure aborts the campaign. The report records exact
one-per-model positive baseline evidence so scheduled lane scoring and
full-cycle promotion cannot treat a pre-existing model failure as mutation
sensitivity.

`PostAdmissionDropGuard` at length 8 and `RevocationPropagation` at length 6
also use that 10,800-second safety-lane budget. Their complete invariant sets
remain unchanged; the larger envelope accommodates the longest bounded solver
branches without turning host contention into a false gate failure.

### Verdicts and report

For generated mutants, exit 0 with the exact `NoError` outcome is `survived`.
The exact `ExecutionsTooShort` outcome is also `survived` only when one bounded
no-error summary and no numbered violation trace corroborate it. Exit 12 with
the exact `Error` outcome and one valid ITF trace is `killed`.
Generated runs use `--no-deadlock`, so disabling an action cannot masquerade
as an invariant kill. The registered negative preflight also disables deadlock
checking and requires an exact configured-invariant violation.
Wall timeout is `timeout` and counts as not killed. Because the allowlist
contains exact type-valid edits, a parser or type failure is an invalid curated
probe and aborts the run. Any `unviable` verdict, other exit, missing outcome,
wrong invariant, malformed trace, duplicate trace, or tool-version drift also
aborts the run.

Scheduled execution requires a clean worktree. The explicit `--allow-dirty`
escape is for local implementation testing and records both status and tracked
diff hashes, so such a report cannot be promoted as clean full-cycle evidence.

The atomic report is `target/formal/spec-mutants-report.json`, schema
`chio.spec-mutants-report.v1`. It records the commit, sample seed, source and
configuration hashes, exact commands, tool versions, model bounds, wall
times, log and trace hashes, registered negative results, per-mutant verdicts,
positive baseline results, and timeout-aware global and per-source aggregates.
Activation requires at
least 90 percent globally and separately for every sampled source. A sample
can provide an early sensitivity signal, but only a clean full 33-probe
campaign is eligible as activation evidence.

## Rust proof-model mutation

### Tool limitation and execution decision

cargo-mutants 25.3.1 accepts only `cargo` or `nextest` as `--test-tool`.
It cannot execute an arbitrary Kani wrapper through that option. The original
native substitution design is therefore unsupported by the pinned tool.

The implemented execution mode is explicit in every report:

1. Run cargo-mutants 25.3.1 discovery with
   `formal/rust-verification/formal-mutants.toml`.
2. Repeat both repository-relative `-f` filters in shards `0/3`, `1/3`, and
   `2/3` with `--no-shuffle --list --json --diff`.
3. Require the merged shard identities and diff hashes to equal an unsharded
   control inventory, require both model files, and select a rotating window
   of 15 from a commit-seeded permutation and the recorded epoch.
4. Require a clean tracked worktree and create a detached temporary worktree
   at the exact report commit.
5. Run `scripts/kani-mutant-killer.sh` once before mutation. A failing or
   timed-out baseline aborts the measurement.
6. Reproduce each cargo-mutants span replacement, run the Kani core lane,
   record the result, restore the source, and require a clean scratch tree
   before continuing. The oracle checks the directly affected harnesses first
   and stops on a failure; when they pass, it runs the unchanged complete core
   lane. This is fail-fast ordering, not a reduced harness set.

The runner distinguishes Kani proof failures (`killed`), compilation failures
(`unviable`), successful proofs (`survived`), and wall timeouts. Unknown
non-zero output is an infrastructure error, not a kill.

The report is `target/formal/proof-mutants/outcomes.json`, schema
`chio.proof-mutants-report.v1`. `mutants.json` preserves every cargo-mutants
diff and `commands.json` preserves all three shard commands, the unsharded
control, and Kani commands. The report states
`native_test_tool_supported = false` so downstream readers cannot mistake the
fallback for native cargo-mutants scoring.

The runner records the actual cargo-mutants, Kani, rustc, and Python versions.
Its default per-run cap is 5,400 seconds because the compound clean baseline
and each surviving mutant run the priority harnesses followed by the complete
core lane. The pinned arm64 toolchain can exceed 1,800 seconds while repeating
the sound inclusion oracle, so the outer cap preserves the unchanged oracle
with measured headroom.
On the integrated tree, cargo-mutants 25.3.1 discovers 166 focused Rust
mutants. The non-divisible inventory uses the general rotating schedule rather
than the former ten-epoch aligned schedule. Every sample includes both model
files, and cycle coverage is measured from recorded mutant identities.

## Lean sensitivity pilot

`scripts/lean-mutants.py` enumerates comparison, Boolean literal, and Boolean
connective mutations in allowlisted definitions under `Chio/Core`,
`Chio/Treaty`, and `Chio/Json`. A
rotating sample of five runs after a clean `lake build` baseline in a detached
scratch worktree. A nonzero build counts as a kill only when its log contains a
Lean source diagnostic; an unclassified tool or infrastructure failure aborts
the run. A successful build is a survivor, and a wall timeout is reported
separately. The clean baseline has an independent 1,800-second timeout while
each mutant retains a 300-second timeout. Both bounds are recorded in the
report. Ignored `.lake` trees are excluded from the frozen input snapshot, and
comparison discovery excludes the `>` in Lean function arrows. This pilot is
not an activation ratchet.

With the Treaty and canonical targets integrated, ten consecutive epochs cover
the 47-mutant pilot inventory. The two canonical-JSON targets exercise the
domain predicates protected by `escape_string_inj` and `render_int_inj`.

The report is `target/formal/lean-mutants/report.json`, schema
`chio.lean-mutants-report.v1`. It records both the exact Lake version and the
project's pinned Lean toolchain. Every Lean survivor uses the same issue
disposition workflow as TLA+ and Rust survivors.

## CI and issue disposition

- `.github/workflows/apalache-safety.yml` contains the scheduled
  `spec-mutants` job and runs the mutator self-test on relevant pull requests.
- `.github/workflows/proof-mutants.yml` contains pull-request control tests,
  a scheduled `proof-mutants` job, and the scheduled Lean pilot.
- `proof-mutants.yml` is included in the shared 30-day fuzz and mutation
  budget. Its scheduled budget policy is warning-only so measurement remains
  available when the cap is exceeded.
- Reports and run directories upload with 30-day retention and
  `if-no-files-found: error`.
- `scripts/file-mutation-survivors.py` creates idempotent GitHub issues using
  the stable `mutation-id` in the issue body. Duplicate or ambiguous issue
  evidence fails closed.

The scheduled scored jobs preserve their runner exit after uploading
artifacts. A below-target score is therefore visible as a failed scheduled
measurement even while the release posture remains advisory.

## Coverage and ratchet integration

`formal/mutation/registry.toml` maps all seven specification targets and both
Rust model files to conservative Rust surfaces. `cargo xtask gen
proof-coverage` reads this registry into the existing `mutants` column and
records the lane, report, activation target, and measurement status. Cross
package targets remain unattributed with related surfaces instead of being
assigned an arbitrary primary owner.

A target receives `measurement=full-cycle` only when its registry entry has a
`latest_full_cycle` table backed by the exact report under
`formal/mutation/evidence/`. The generator verifies the report SHA-256,
schema, clean-worktree marker, commit, completion time, full-cycle flag,
the canonical full-inventory digest, normalized pinned tool versions, the
complete lane input set and hashes from both the current checkout and the
report's ancestor commit, per-mutant verdicts, aggregate counts, per-target
source attribution, and timeout-aware activation ratio. For
the specification lane, it also requires all 33 registered probes, zero
unviable results, and activation of at least 90 percent both globally and for
each of the seven source aggregates.

Every report input must resolve to a non-symlink regular repository file. The
retained report under `formal/mutation/evidence/` must meet the same file rule.
The specification lane input set includes all positive and negative model
sources, CFGs, sibling TLA+ imports, registered runtime tests, registries, and
runner controls. The proof lane input set includes both local Cargo manifests,
workspace `Cargo.toml`, `Cargo.lock`, `.cargo/config.toml`, every Rust source
below the kernel-core and core-types `src` trees, the scheduled
`scripts/proof-mutants.sh`
entrypoint, and the mutation, Kani, and toolchain controls.
Missing, extra, stale, symlink, and non-regular inputs reject promotion. A
tree object, unrelated commit, or unavailable evidence commit also rejects
promotion. Until the report meets this contract, coverage renders
`measurement=pending`.

Every `latest_full_cycle` count and ratio is source-scoped: each registry
target records the aggregate for its own specification or Rust model path.
Promotion recomputes every source aggregate from mutant verdicts and requires
the exact source set, configured target, and a passing result for every source.
Specification mutants must have zero unviable results. Proof mutants must meet
the 80 percent viability floor both globally and for each model file. Both
lanes use the existing registry schema.

## Decisions

- Timeouts remain in the score denominator and are never relabeled as killed.
- Specification mutation admits only exact type-valid curated probes and the
  two registered historical seeds. Parser or type failures fail the campaign.
- Rust compilation failures are recorded as unviable, with an 80 percent
  viability floor globally and for each source.
- Lean remains a sensitivity pilot until its survivor disposition and
  activation posture justify a separate ratchet.

## Manifest and registry updates

- `formal/mutation/registry.toml` records source-scoped retained observations
  for seven specification targets and two Rust proof-model targets.
- `formal/mutation/evidence/` retains the exact full-cycle specification and
  Rust reports bound to the implementation commit. Lean pilot output remains a
  runtime artifact and is not promoted as scored evidence.
- `formal/proof-manifest.toml`, `formal/MAPPING.md`, and generated
  `docs/formal/COVERAGE.md` consume the mutation registry without converting a
  sensitivity score into a correctness claim.

## Prepared-tree evidence

The exact-probe TLA+ campaign requires an integrated clean full-cycle report;
no prepared-tree activation result is claimed. The following Rust
measurements used B1/B2 HEAD
`0b6384c12ebacaa7feb6c056748cb061a409c850` plus the prepared E1 worktree. They
validate Rust-lane discovery and baseline execution but are not checked-in
full-cycle observations.

- cargo-mutants 25.3.1 discovered 104 focused Rust mutants: 34 in
  `formal_core.rs` and 70 in `formal_aeneas.rs`. Three deterministic shards
  contained 35, 35, and 34 mutants and merged to the byte-identical
  unsharded inventory.
- Kani 0.67.0 completed the clean mutation-oracle baseline with 35 of 35
  harnesses successful and no failures.

Rust discovery was repeated after FV-A1 and the authenticated generated-code
equivalence work changed the mutated model surface; the current integrated
inventory is recorded above.

The retained integrated full cycle is bound to prerequisite commit
`a871396bffd010500f680c035e7b52c1867f38e2`, measured at
`2026-07-16T18:59:33Z`, with SHA-256
`d51114555cd3c2d3294c1b808d2e061a8611f2ce7f6067b735d725b00f59271c`. It
enumerated 54 mutants in `formal_core.rs` and 112 in `formal_aeneas.rs`, killed
50 and 110 respectively, left one survivor in `formal_core.rs`, classified
three and two as unviable, and recorded no timeout. Both source-scoped
activation ratios exceeded the 90 percent target and both viability ratios
exceeded the 80 percent floor.

[FV-E5](FV-E5-lane-ratchets.md) registers the scheduled `spec-mutants` and
`proof-mutants` gates with `activation_target = 90`, and the generic lane
parser validates that field. Historical success may count only when the job
itself met the target, because the scored runners return non-zero below
target. The Lean pilot remains outside the ratchet.

## Local commands

```bash
python3 scripts/spec-mutants.py --list
python3 scripts/spec-mutants.py --sample-from-head --sample-size 16
python3 scripts/spec-mutants.py --full

cargo mutants \
  --config formal/rust-verification/formal-mutants.toml \
  --package chio-kernel-core \
  --list
./scripts/proof-mutants.sh --sample-size 15 --activation-target 90
./scripts/proof-mutants.sh --full --activation-target 90

python3 scripts/lean-mutants.py --list
python3 scripts/lean-mutants.py --sample-size 5
```

## Acceptance status

- [x] `scripts/spec-mutants.py --list` is deterministic and byte-identical at
  the same source revision.
- [x] The clean full 33-probe Apalache campaign records both historical seeds
  as killed, zero unviable results, and at least 90 percent activation globally
  and for every source.
- [x] Rule zero is enforced by allowlist, reachability, property-closure, and
  synthetic tests.
- [ ] The scheduled real `spec-mutants` job has produced a stratified
  16-probe report within budget, and a clean full 33-probe campaign has
  produced activation evidence. Local full-cycle evidence is retained; the
  hosted scheduled sample remains pending.
- [x] The pinned real cargo-mutants discovery command re-enumerates both Rust
  model files on the integrated tree: 166 mutants across both files, with
  sharded and unsharded inventories identical.
- [ ] The scheduled real `proof-mutants` job has completed a Kani-scored
  sample. Local full-cycle Kani scoring is retained; the hosted scheduled
  sample remains pending.
- [x] A real full-cycle Rust kill ratio is recorded and every survivor has an
  issue. The retained report records 160 killed, one survivor, five unviable,
  and no timeout; issue #1019 tracks the survivor.
- [x] The unit-test mutation exclusion rationales name the measured
  co-coverage lane and distinguish proof models from oracle harnesses.
- [x] One real Lean pilot is recorded and every survivor has a disposition
  issue. The 45-mutant pilot killed 33 and left 12 survivors with no timeout;
  issues #999 through #1010 track those survivors.

The implementation is complete with retained local full-cycle evidence.
Scheduled hosted samples remain advisory and must populate their own workflow
artifacts before they can contribute hosted history.
