# Mutation testing with cargo-mutants

The M02 P2 mutation-testing lane runs [`cargo-mutants`](https://mutants.rs)
as an advisory companion to the libFuzzer corpus shipped in M02 P1.
libFuzzer searches for inputs that crash or panic; cargo-mutants searches
for *surviving mutants* -- code edits the test suite fails to notice. A
high libFuzzer corpus catch-rate plus a high cargo-mutants catch-ratio
together give a much stronger guarantee that the trust-boundary code is
actually exercised by tests.

This lane is owned by `agent-role: fuzz-rust` and lives alongside the
fuzz infrastructure in `docs/fuzzing/`.

## Pinned version

`cargo-mutants` is pinned to the **25.x** series (decision 12 in
`.planning/trajectory/02-fuzzing-post-pr13.md`). Do **not** float to
26.x without re-running the source-doc decision and updating the pin in
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
`crates/chio-kernel-core/src/evaluate.rs`).

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
`fuzz.rs` (libFuzzer entry points already covered by the M02 P1 lane).

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
the advisory pipeline + `spider_sense.rs` (advisory by design), and
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

Excluded: `fuzz.rs` (libFuzzer entry points covered by the M02 P1
lane).

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

Workflow: `.github/workflows/mutants.yml` (lands in **M02.P2.T2**).
Two jobs:

- `mutants-pr` -- triggered on PR. Runs
  `cargo mutants --in-diff "$GIT_DIFF" --no-shuffle --jobs 4` against
  the PR diff and posts a comment via `scripts/mutants-comment.sh`.
  Always advisory; never blocks merge.
- `mutants-nightly` -- scheduled `cron: '0 5 * * *'` on a 4-hour
  budget per crate. Runs the full sweep, uploads `mutants.out/` as a
  workflow artifact, and gates against the per-crate 80% catch-ratio
  threshold via `scripts/mutants-gate.sh`.

The lane is **advisory** for one release cycle, then flips to
**blocking** automatically. The flip is driven by the `cycle_end_tag`
field in `releases.toml` at the repo root (schema landed in M02.P2.T2):
empty -> advisory, non-empty -> blocking.

### Auto-flip mechanic (M02.P3.T1)

The first post-Phase-3 release performs the flip without manual edits.
`.github/workflows/release-binaries.yml` runs a `mutants-gate-flip` job
after the `release` job succeeds:

1. Checks out the `project/roadmap-04-25-2026` branch and reads the
   current `cycle_end_tag` value with the same pure-bash extractor as
   `scripts/mutants-gate.sh` (so the writer and reader cannot drift).
2. If the value is still empty, writes the just-released tag (e.g.
   `v0.6.0`) into `releases.toml` via a single-line regex replace
   guarded against an already-flipped file.
3. Opens a single PR via `peter-evans/create-pull-request` titled
   `chore(mutants): activate blocking gate after cycle <tag>` against
   `project/roadmap-04-25-2026`. Reviewer merge is what activates the
   blocking posture; the workflow itself never pushes directly to the
   roadmap branch.

After merge, `scripts/mutants-gate.sh` reads the non-empty
`cycle_end_tag` and switches `mutants-nightly` from "exit 0 on miss"
(advisory) to "exit 1 on miss" (blocking). PR comments emitted by
`mutants-pr` swap their advisory label for a blocking one in M02.P3.T2.

If the workflow re-runs against an older tag (workflow_dispatch, repush,
etc.) the empty-string regex guard makes the write a no-op, so a single
release cannot accidentally overwrite a previously activated flip.

### Override paths (M02.P3.T2)

There are two override paths once the gate is blocking. Both leave an
audit trail; pick the one that matches the situation.

**1. Label-based override (preferred / permanent).** A maintainer opens
a PR that clears `cycle_end_tag` in `releases.toml`, labels the PR
`mutants-gate-override`, and merges. The lane returns to advisory for
one cycle. CODEOWNERS routes any edit on `releases.toml` to
`@bb-connor` (principal-engineer review), so the override cannot land
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

## Triage policy

Surviving mutants beyond a per-crate budget open an issue tagged
`mutants-survivor`. Per-crate budgets and the rolling catch-ratio target
(>= 80%) are recorded in `releases.toml` (M02.P2.T2). When the nightly
sweep crosses the budget the gate posts a single rollup issue rather
than one per mutant; subsequent nightly runs update the same issue
in-place to avoid noise.

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
  per the source doc Round-2 (NEW) section.

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

This lane closes M02 P2 (T7).

## Cross-references

- `.planning/trajectory/02-fuzzing-post-pr13.md`, sections "Mutation-testing
  approach (phase 3 deliverable)", "Mutation-testing CI shape (Phase 3)",
  and Round-2 (NEW) P3.T7 (re-homed to Phase 2 as M02.P2.T7).
- `.planning/trajectory/tickets/M02/P2.yml` -- atomic ticket spec for this
  lane (T1 = config, T2 = workflow + `releases.toml`, T7 = cocoverage).
- `.cargo/mutants.toml` -- workspace-root config (timeouts + per-crate
  scoping consolidated into a single file; cargo-mutants 25.x does not
  load per-crate `mutants.toml`).
- `releases.toml` -- per-crate budgets and the advisory / blocking flip
  signal (lands with M02.P2.T2).
- `docs/fuzzing/continuous.md` -- complementary libFuzzer corpus lane.
- Upstream cargo-mutants documentation: <https://mutants.rs>.
