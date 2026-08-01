# Mutation testing with cargo-mutants

The trust-boundary mutation-testing lane runs
[`cargo-mutants`](https://mutants.rs) as an advisory companion to the
libFuzzer trust-boundary corpus.
libFuzzer searches for inputs that crash or panic; cargo-mutants searches
for *surviving mutants* -- code edits the test suite fails to notice. A
high libFuzzer corpus catch-rate plus a high cargo-mutants catch-ratio
together give a much stronger guarantee that the trust-boundary code is
actually exercised by tests.

This lane is owned by `agent-role: fuzz-rust` and lives alongside the
fuzz infrastructure in `docs/fuzzing/`.

The judged catch-ratio lifecycle remains separate from pass/fail workflow
postures. `scripts/mutants-gate.sh` owns mutation evidence and its reviewed
counter in `releases.toml`; `scripts/lane-gate.sh` owns stateless GitHub job
history for proof and corpus lanes. Neither script substitutes for the other.

## Pinned version

`cargo-mutants` is pinned to the **25.x** series for compatibility with
the current configuration layout. Do **not** float to 26.x without
re-running the source-doc compatibility review and updating the pin in
both this document and the CI workflow. The CI install line is:

```bash
cargo install cargo-mutants --version '~25' --locked
```

## Configuration layout

cargo-mutants 25.x reads its configuration exclusively from the
workspace-root `.cargo/mutants.toml`. Per-crate `crates/<name>/mutants.toml`
files are NOT auto-discovered, and even when loaded explicitly via
`--config` their globs are matched relative to the source-tree root rather
than the per-crate root. All per-crate scoping is therefore consolidated
into the single workspace-root file with workspace-rooted globs (e.g.
`crates/kernel/chio-kernel-core/src/evaluate.rs`).

| Path                                         | Role                                                  |
|----------------------------------------------|-------------------------------------------------------|
| `.cargo/mutants.toml`                        | Single source of truth: timeouts, examined trust-boundary modules per crate, workspace-wide skip list |

A second discovery rule constrains the layout: cargo-mutants walks `mod`
declarations and does NOT expand `include!` macros. Two crates in this
workspace use `include!`:

- `chio-credentials/src/lib.rs` `include!`s 13 files. Only `trust_tier`
  and the `cfg`-gated `fuzz` are real `mod`s. Globs are written against
  `lib.rs` (which carries all of the included source for discovery
  purposes) plus `trust_tier.rs`.
- `chio-policy/src/evaluate.rs` `include!`s `evaluate/{context,engine,
  matchers,outcomes,tests}.rs`. The glob targets `evaluate.rs` itself,
  not the sub-files.

Workspace-level knobs of note (in `.cargo/mutants.toml`):

- `additional_cargo_test_args = ["--workspace", "--exclude", "chio-cpp-kernel-ffi"]` --
  the C++ FFI crate ships through a separate vcpkg/conan lane and is not
  exercised by the default workspace test invocation.
- `timeout_multiplier = 3.0` -- cargo-mutants reruns the full test
  suite per mutant; the 3x guard prevents slow-test flakes from getting
  scored as TIMEOUT (which masquerades as a surviving mutant).
- `minimum_test_timeout = 60` -- floor in seconds, so the multiplier
  cannot collapse below the cold-cache build time on a CI host.

### Why narrow `examine_globs`

cargo-mutants generates one or more mutants for every applicable
expression. Without scoping, that explodes into thousands of
candidates per crate; most of them in pure-data, logging, or generated
code where mutation has no semantic value. The workspace-root
`examine_globs` narrows the examined source set to the trust-boundary
modules listed below.

#### `chio-kernel-core`

Examined: the pure-compute verdict path (`evaluate.rs`,
`capability_verify.rs`, `scope.rs`, `receipts.rs`, `passport_verify.rs`,
`guard.rs`, `normalized.rs`).

Excluded: `lib.rs` (re-exports), `clock.rs` / `rng.rs` (platform
adapters), `formal_*.rs` and `kani_*.rs` (formal-methods scaffolding),
`fuzz.rs` (libFuzzer entry points already covered by the trust-boundary
fuzz lane).

#### `chio-policy`

Examined: the HushSpec evaluator state machine (`evaluate.rs` +
`evaluate/{engine,matchers,outcomes,context}.rs`), the compiler bridge
(`compiler.rs`), conditional activation (`conditions.rs`), regex-based
detectors (`detection.rs`, `regex_safety.rs`), `extends`-chain
plumbing (`merge.rs`, `resolve.rs`), schema validation (`validate.rs`),
and decision-receipt construction (`receipt.rs`).

Excluded: `models.rs` (pure data), `version.rs` (constant), embedded
YAML rulesets (`rulesets/**`).

#### `chio-guards`

Examined: the fail-closed `pipeline.rs` and the boundary-enforcing
guards -- `shell_command.rs` (PR #13 hardening lane), forbidden / allowlist
path checks, egress + internal-network filters, secret-leak,
patch-integrity, MCP tool gating, prompt-injection, jailbreak (both the
heuristic and ML detectors), input-injection, response-sanitization,
data-flow, behavioral-sequence, behavioral-profile, both velocity
guards, and the CUA / code-execution / browser-automation /
remote-desktop / content-review / memory-governance / post-invocation
guards.

Excluded: `action.rs` (pure types), `text_utils.rs` (pure helpers),
the advisory pipeline + `embedding_anomaly.rs` (advisory by design), and
the `external/` adapter tree (remote-process bridges that need
integration testing, not mutation).

#### `chio-credentials`

Examined: `lib.rs` (which `include!`s the trust-boundary set: portable
JWT VC verify, SD-JWT VC verify, portable reputation credential verify,
the OID4VCI issuance flow, the OID4VP presentation flow + verifier,
presentation construction / verify, presentation challenge binding,
cross-issuer trust packs, the issuer / trust-anchor registry, OID4VCI /
OID4VP discovery, artifact normalization, passport verifier glue, and
credential-side policy intersection) plus the real-`mod` `trust_tier.rs`.

Excluded: `fuzz.rs` (libFuzzer entry points covered by the
trust-boundary fuzz lane).

## Formal model co-coverage

Two scheduled mutation lanes measure whether the verification properties can
detect changes to their models:

- `spec-mutants` mutates only exact allowlisted TLA+ action-body sites and uses
  Apalache 0.50.1 as the oracle. Eligible actions must be reachable from
  `Next`. It never edits `Init`, `Next`, configured invariant definitions or
  their transitive definition closure, or temporal-property definition bodies.
  Every unmodified positive model must pass the same bounded invariant oracle
  before mutants are scored. The nightly sample contains at least 16 mutants
  selected deterministically from
  a rotating window over a commit-seeded permutation. The recorded epoch makes
  each window reproducible and covers the inventory across consecutive runs on
  an unchanged revision.
- `proof-mutants` uses cargo-mutants 25.3.1 to enumerate the two pure Rust
  model files, in the explicit shards `0/3`, `1/3`, and `2/3`. Every discovery
  command repeats repository-relative `-f` filters for `formal_core.rs` and
  `formal_aeneas.rs`, and the merged inventory must equal an unsharded control.
  A scratch worktree applies each selected mutation and runs the clean Kani
  core lane as the oracle. Harnesses that directly exercise the mutable model
  modules run first; a passing priority set is always followed by the complete
  core lane, while a proof failure stops immediately.

cargo-mutants 25.3.1 accepts only `cargo` and `nextest` for `--test-tool`; it
cannot invoke a Kani shell command through that option. The proof lane records
the scratch-worktree fallback as its execution mode and preserves the exact
cargo-mutants diffs, shard commands, source hashes, Kani logs, and verdicts.
It runs a clean Kani baseline before applying any mutation. A failing baseline
aborts the measurement.

Both lanes require a clean scheduled worktree and emit the timeout-aware ratio
`killed / (killed + survived + timeout)`. Unviable mutations are excluded from
that denominator, while timeouts reduce the score. The specification lane
rejects any unviable curated probe. The proof lane additionally requires at
least 80 percent viable mutants globally and for each model file, preventing
compile failures from inflating activation. Reports and generated coverage
attribution are registered in `formal/mutation/registry.toml`.
Surviving mutants receive idempotent GitHub issues keyed by their stable
mutation identifier.

The same scheduled workflow carries a non-ratcheted Lean sensitivity pilot.
`scripts/lean-mutants.py` changes comparisons, Boolean literals, and Boolean
connectives only inside definitions listed in
`formal/lean4/lean-mutants-allowlist.toml`; declarations classified as
theorems, lemmas, or axioms are never mutation candidates. A failed `lake
build` kills the mutant only when the log contains a Lean source diagnostic;
unknown tool failures abort the run. A successful build records a survivor
and files the same disposition issue used by the two scored lanes.
The allowlist includes the canonical-JSON domain predicates
`IsLiteralScalar` and `CanonicalInteger`, which calibrate sensitivity of the
named `escape_string_inj` and `render_int_inj` proof surfaces.
Approved sources are restricted to the bounded `Core`, `Treaty`, and `Json`
model roots. The clean Lean build has a separate 1,800-second budget; mutant
builds keep the 300-second bound recorded in the allowlist.

```bash
python3 scripts/spec-mutants.py --list
python3 scripts/spec-mutants.py --sample-from-head --sample-size 16

cargo mutants \
  --config formal/rust-verification/formal-mutants.toml \
  --package chio-kernel-core \
  --list
./scripts/proof-mutants.sh --sample-size 15 --activation-target 90
./scripts/lean-mutants.py --sample-size 5
```

The formal files remain excluded from the unit-test mutation configuration.
Their exclusion means the cargo test oracle is inappropriate, not that the
files are unmeasured.

## Local-developer workflow

```bash
# One-time install (or upgrade) - pinned to 25.x.
cargo install cargo-mutants --version '~25' --locked

# Run only the mutants generated against changed files in your branch.
# `--in-diff` takes a unified-diff text file path, NOT a git ref, so we
# capture the diff first. This is the same invocation the mutants-pr CI
# job uses.
git diff origin/main...HEAD > /tmp/diff.patch
cargo mutants --in-diff /tmp/diff.patch

# Full sweep on a single crate (slow; budget hours per crate).
cargo mutants --package chio-kernel-core
```

Tip: a clean `cargo test --workspace --exclude chio-cpp-kernel-ffi`
must pass and be deterministic before running cargo-mutants. Flaky
tests poison the report and surface as false TIMEOUT verdicts.

## CI lane

Workflow: `.github/workflows/mutants.yml`.
Two jobs:

- `mutants-pr` -- triggered when a PR changes source or mutation controls for
  one of the six trust-boundary crates. Untouched matrix packages stop before
  installing Rust or cargo-mutants. A selected package runs
  `cargo mutants --in-diff "$GIT_DIFF" --no-shuffle --jobs 2` with its
  per-crate `mutants.toml`. Same-repository PRs receive a summary comment and
  survivor issues beyond the configured cap; fork PRs skip those token writes
  while still enforcing the mutation result.
  The workflow sets `CHIO_MUTANTS_GATE=blocking`; the actual pass/fail
  posture still comes from `scripts/mutants-gate.sh` and
  `releases.toml::[mutants]`. Empty `cycle_end_tag` or a recorded
  nightly success streak below `required_consecutive_nightly_successes`
  keeps the lane advisory. A non-empty `cycle_end_tag` plus the required
  streak flips the PR gate to blocking.
- `mutants-nightly` -- scheduled `cron: '0 5 * * *'` on a 4-hour
  budget per crate. Runs the full sweep, uploads `mutants.out/` as a
  workflow artifact, and reports against the per-crate
  `target_catch_ratio_percent` threshold via `scripts/mutants-gate.sh`.

Selected packages in both jobs run `scripts/check-mutants-rationale.sh` before
spending mutation budget. That check fails closed if an `exclude_globs` entry
in the workspace or per-crate `mutants.toml` files lacks a nearby `rationale:`
comment.

The PR job sets `GH_FUZZ_BUDGET_CAP_MODE=fail`, so an exhausted shared fuzz
and mutation budget stops the qualification run. The scheduled job sets the
mode to `warn` and remains available for measurement continuity.

The lane is **advisory** until the required evidence exists, then flips
to **blocking** through a release-owned PR. The state machine is driven
by the `[mutants]` table in `releases.toml` at the repo root:

- `target_catch_ratio_percent = 80`
- `required_consecutive_nightly_successes = 2`
- `observed_consecutive_nightly_successes = 0` until a CODEOWNERS-reviewed
  evidence PR records the two successful nightlies
- `cycle_end_tag = ""` until the first release after the evidence streak

`scripts/mutants-gate.sh` stays advisory until both conditions are true:
`cycle_end_tag` is non-empty and the observed nightly streak is at least
the required streak.

### Evidence-gated activation

The first qualifying release after the evidence streak performs the flip
without manual edits. `.github/workflows/release-binaries.yml` runs a
`mutants-gate-flip` job after the `release` job succeeds:

1. Checks out `main` and reads the
   current `cycle_end_tag`, `target_catch_ratio_percent`,
   `required_consecutive_nightly_successes`, and
   `observed_consecutive_nightly_successes` values with the same
   pure-bash extractor as `scripts/mutants-gate.sh` (so the writer and
   reader cannot drift).
2. If `cycle_end_tag` is still empty but the observed nightly streak is
   below the required streak, logs `waiting for nightly evidence` and
   opens no PR. This prevents a release from creating a false required
   gate before the two-consecutive >= 80 condition is actually recorded.
3. If the evidence streak is present, writes the just-released tag (e.g.
   `v0.6.0`) into `releases.toml` via a single-line regex replace
   guarded against an already-flipped file.
4. Opens a single PR via `peter-evans/create-pull-request` titled
   `chore(mutants): activate blocking gate after cycle <tag>` against
   `main`. Reviewer merge is what activates the blocking posture; the
   workflow itself never pushes directly to the target branch.

After merge, `scripts/mutants-gate.sh` reads the non-empty
`cycle_end_tag` and the recorded evidence streak, then switches the
`mutants-pr` gate from "exit 0 below target" (advisory) to "exit 1
below target" (blocking). PR comments emitted by `mutants-pr` switch
from advisory to blocking mode once gate metadata activates blocking.

If the workflow re-runs against an older tag (workflow_dispatch, repush,
etc.) the empty-string regex guard makes the write a no-op, so a single
release cannot accidentally overwrite a previously activated flip.

### Override paths

There are two override paths once the gate is blocking. Both leave an
audit trail; pick the one that matches the situation.

**1. Title-based override (preferred / permanent).** A maintainer opens
a PR that clears `cycle_end_tag` in `releases.toml`, includes
`mutants-gate-override` in the PR title, and merges. The lane returns to
advisory for one cycle. CODEOWNERS routes any edit on `releases.toml` to
`Chio maintainers` (principal-engineer review), so the override cannot land
without explicit sign-off. Use this path when the project needs to
re-enter advisory mode for an entire release cycle (e.g. a large
refactor temporarily depresses the catch ratio while tests are
rewritten). Suggested PR title:

```
chore(mutants): re-enter advisory cycle [mutants-gate-override]
```

**2. Env-var escape hatch (single-run, in-flight CI).** When a single
mutants-nightly or mutants-pr run needs to ship without a full
CODEOWNERS-reviewed PR (e.g. a release-train hot-fix at 2 AM), set the
environment variable `MUTANTS_GATE_OVERRIDE_REASON=<reason>` for that
run only. `scripts/mutants-gate.sh` then:

- emits a loud `WARN mutants-gate-override engaged` line on stderr,
- appends a row to `docs/fuzzing/mutants-overrides.log` (timestamp,
  package, exit code, cycle_end_tag, actor, reason),
- downgrades the verdict from blocking-fail to advisory-pass (exit 0).

```bash
# Hot-fix CI run with the env-var escape hatch.
MUTANTS_GATE_OVERRIDE_REASON='hot-fix release v0.7.1; followup #NNN' \
  bash scripts/mutants-gate.sh
```

The env-var path is intentionally noisy: every override appends a row
that survives in git, and the WARN line surfaces in the workflow
summary. House rule: every env-var override must be backed by an issue
or PR in the `reason` field; bare reasons like `'idk'` will be
challenged in retrospective.

CODEOWNERS gate on `releases.toml` (the permanent path) and the
append-only `docs/fuzzing/mutants-overrides.log` (the in-flight path)
are the two complementary audit surfaces required by the source-doc
override paragraph.

### Rollback dry-run

Once the blocking gate is active, every release-cycle rollback
must be rehearsed locally before merge. The dry-run command intentionally
uses a failing mutant exit code and a one-run override reason:

```bash
MUTANTS_PACKAGE=chio-kernel-core \
MUTANTS_EXIT=1 \
MUTANTS_GATE_OVERRIDE_REASON='rollback dry-run; followup PR #465' \
  bash scripts/mutants-gate.sh
```

Expected result:

- stderr contains `WARN mutants-gate-override engaged`.
- stdout ends with `posture=blocking verdict=override`.
- `docs/fuzzing/mutants-overrides.log` receives one append-only row
  with package, exit code, cycle tag, actor, and rollback reason.

If the dry-run fails, do not clear `cycle_end_tag`. Fix the script or
audit-log path first, then retry the rollback rehearsal.

## Triage policy

Surviving mutants beyond a per-crate budget open a fingerprinted issue.
If the repository labels already exist, the filing script attaches
`mutants-survivor` and `triage`; missing labels are skipped so issue
filing still succeeds. Per-crate budgets and the rolling catch-ratio
target (>= 80%) are recorded in `releases.toml` as
`pr_survivor_issue_budget`, `nightly_wall_budget_hours_per_crate`, and
`target_catch_ratio_percent`. On PRs, `scripts/mutants-comment.sh`
lists the first `MUTANTS_PR_SURVIVOR_CAP` survivors inline.
`scripts/mutants-autofile-issue.sh` files one issue per survivor beyond
that cap, using a SHA-256 fingerprint over package, source location,
verdict, and mutation text to dedupe repeated reports.

A surviving mutant can be addressed in one of three ways:

1. **Add or strengthen a test** that catches the mutant. This is the
   default and preferred path -- the mutant has identified a real test
   gap.
2. **Refactor the code** so the mutant becomes equivalent (no behaviour
   change) and gets pruned by cargo-mutants. Acceptable when the test
   gap is genuinely uninteresting.
3. **Skip via `exclude_globs`** in the workspace-root `.cargo/mutants.toml`,
   with a comment justifying the skip and a cross-reference to the
   triage issue. This requires CODEOWNERS sign-off on `.cargo/mutants.toml`.

Skip comments must include `rationale:` in or near the `exclude_globs`
entry. The rationale should name the reason the mutant is not a useful
production-code signal, for example equivalent code, generated code,
test-only scaffolding, fuzz harness entry points, or an integration-only
remote-process bridge. Bare skips fail `scripts/check-mutants-rationale.sh`.

## README mutation banner

`README.md` carries a scoped trust-boundary mutation baseline under the
project tagline. The value is not a project-wide current score: the
source baseline is partial and combines full sweeps with bounded shards.
`scripts/update-mutants-banner.sh` derives the value from
`docs/fuzzing/trust-boundary-mutants-baseline.toml`; it does not run
`cargo-mutants`. `.github/workflows/mutants-banner.yml` runs nightly and
opens `chore(mutants): update kill-score banner` for maintainer review
when that bookkeeping value changes.

## Cocoverage with the fuzz corpus

The nightly `mutants-fuzz-cocoverage.yml` workflow replays the
accumulated fuzz corpus against surviving mutants. The intuition:

- cargo-mutants produces a "surviving mutant" when the unit test
  suite fails to distinguish the original from the mutation - the
  mutant is a test-gap signal.
- The fuzz corpus under `fuzz/corpus/<target>/` is a DIFFERENT oracle
  (libFuzzer-accumulated adversarial inputs) that may notice the
  mutation when the unit tests didn't.
- Cross-oracle reduction in missed-mutant count: expected **5-15%**
  per the source-doc estimate.

Workflow lives at `.github/workflows/mutants-fuzz-cocoverage.yml`.
Implementation script at `scripts/mutants-fuzz-cocoverage.sh`.
Nightly only; never runs on the PR lane (would duplicate cost
without adding signal). Always advisory: the workflow never blocks
merges, and the script always exits 0.

The mapping from cargo-mutants source-file paths to libFuzzer target
directories under `fuzz/corpus/` is in
`scripts/mutants-fuzz-cocoverage.sh::map_source_to_fuzz_target`.
Add new mappings there when new fuzz targets land. Unmapped survivors
are counted in the report but skip the replay step (intentional;
silent fall-through to an unrelated corpus would inflate the "caught"
metric and corrupt the audit story).

Output artifacts (uploaded with 30-day retention):

- `cocoverage-out/<package>/summary.json` - machine-readable counts
  (survivors, mapped, attempted, caught) plus the 5-15% expected
  reduction band.
- `cocoverage-out/<package>/report.md` - human-readable rollup.
- `cocoverage-out/<package>/replay.log` - per-target replay detail.
- `mutants-out/<package>/` - the cargo-mutants outcomes that drove
  the replay.

## Cross-references

- `.cargo/mutants.toml` -- workspace-root config (timeouts + per-crate
  scoping consolidated into a single file; cargo-mutants 25.x does not
  load per-crate `mutants.toml`).
- `releases.toml` -- per-crate budgets and the advisory / blocking flip
  signal.
- `docs/fuzzing/trust-boundary-mutants-baseline.toml` -- committed source
  for the README mutation banner.
- `docs/fuzzing/continuous.md` -- complementary libFuzzer corpus lane.
- Upstream cargo-mutants documentation: <https://mutants.rs>.
