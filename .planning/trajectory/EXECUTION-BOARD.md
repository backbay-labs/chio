# EXECUTION BOARD: Chio Trajectory Autonomous Run

Synthesized from a parallel 7-lens debate (worktree topology, wave orchestration,
file ownership, ticket granularity, review pipeline, CI budget, failure modes).
This is the canonical operations doc for executing the next-10 trajectory in one
autonomous flow with massive parallelism across execution / review / integration
waves.

Genesis: 2026-04-25. House rules: no em dashes, fail-closed, conventional commits,
clippy `unwrap_used = "deny"`.

---

## 0. Scope

This board operationalizes the ten milestones in `.planning/trajectory/01-*.md`
through `10-*.md`. It does not repeat their content; it adds the layer that lets
a swarm of executor + reviewer agents land them concurrently on `main` without
corrupting state.

Inputs:
- 10 milestone docs + `README.md` + `COLD-READER-NOTES.md`
- Existing trajectory file `.planning/trajectory/OWNERS.toml` (to be created in
  pre-flight; see section 1)

Outputs:
- All ten milestones merged to `main`
- `tickets/manifest.yml` reflecting `merged` for every ticket
- `EXECUTION-LOG.ndjson` audit trail
- Reproducible-build CI green, conformance suite green, replay byte-equivalence
  green, no regressions on existing tests

Non-goals: releases, design partner work, certifications. Pure engineering.

---

## 1. Pre-flight checklist

These artifacts must exist and be reviewed before Wave 0 starts. Each is a Wave
0 ticket carrying a human-confirmation gate.

| # | Artifact | Path | Owner | Blocking |
|---|----------|------|-------|----------|
| 1 | Ownership manifest | `.planning/trajectory/OWNERS.toml` | sequencer | yes |
| 2 | Generated CODEOWNERS | `CODEOWNERS` (regen from #1) | sequencer | yes |
| 3 | Freeze register | `.planning/trajectory/freezes.yml` | sequencer | yes |
| 4 | Ticket manifest | `.planning/trajectory/tickets/manifest.yml` (generated) | sequencer | yes |
| 5 | Per-phase ticket files | `.planning/trajectory/tickets/M{nn}/P{n}.yml` | each milestone | yes |
| 6 | Decisions register | `.planning/trajectory/decisions.yml` | sequencer | yes (12 Wave-1 decisions are already locked in `README.md`) |
| 7 | Execution-state seed | `.planning/trajectory/EXECUTION-STATE.json` | orchestrator | yes |
| 8 | Audit-log path | `.planning/trajectory/EXECUTION-LOG.ndjson` | orchestrator | yes |
| 9 | (deprecated: sccache + R2 bucket) | in-session execution; local Cargo cache only | n/a | not blocking |
| 10 | (deprecated: self-hosted runner pool) | in-session execution via Bash; sub-agents via Agent tool | n/a | not blocking |
| 11 | GitHub branch ruleset + `m05-freeze-guard` | freeze-path enforcement on `main` (origin is github.com; no pre-receive hooks). Useful safety net even for solo trajectory once contributors arrive. | infra | M05 P1 start |
| 12 | `Cargo.lock` merge driver | `.gitattributes` + driver script | sequencer | yes |
| 13 | `formal/OWNERS.md` slot fill | resolves to `@bb-connor` under single-owner trajectory; placeholder `formal/OWNERS.md` still lands in M03 P1 | user | M03 close, not Wave 1 |
| 14 | (deprecated: was `@chio/m05-freeze` GitHub team) | single-owner trajectory: freeze enforced via branch ruleset path restriction + `m05-freeze-guard` required check; human-side reviewer is `@bb-connor` | n/a | not blocking |
| 15 | PR #13 shepherd named | M02 Wave 1 unblock; under single-owner this resolves to `@bb-connor`; an amendment can lock `decisions.yml` row | user | M02 start |
| 16 | manifest query toolchain pinned | `mikefarah/yq` v4.x plus `jq`; Wave 0 commits `scripts/install-orchestrator-tools.sh` with both versions pinned before any autonomous launch | sequencer | yes |

PR #13 is treated as Wave 0. It must be merged before M02 phase 1 starts.

---

## 2. Wave plan

A wave is a saturation-of-parallelism cohort: the maximal set of tickets whose
dependency closure is satisfied AND whose file-ownership write-sets are mutually
disjoint, capped by the per-wave concurrency ceiling. Sub-waves split a wave
when an internal merge-conflict hazard forces sequencing.

### Wave 0 (external): PR #13 fuzzing baseline

In flight at the user's GitHub. Not enumerated below.

### Wave 1a: foundation, fully parallel (no PR #13 dependency)

| Milestone | Phases | Approx tickets | Notes |
|-----------|--------|----------------|-------|
| M01 | P1 (schemas), P2 (vectors) | ~11 | spec/schemas/ + tests/bindings/vectors/ disjoint trees |
| M03 | P1 (proptest invariants in chio-core-types + chio-kernel-core) | ~5 | uses formal/diff-tests/ generators |
| M09 | P1 (cargo-vet baseline + deny.toml hardening), P2 (SBOM + SLSA L2 provenance) | ~7 | unblocks M06 |
| Wave-opener | one workspace `Cargo.toml` lock-bump PR per milestone, queued through sequencer | 4 | order: M09 -> M03 -> M01 -> (M02 deferred to 1b) |

Wave 1a sustained concurrency: bounded by Cargo.lock sequencing, shared_paths
collisions, the dependency DAG, and the parallelism Claude Code permits in
one thread (typically ~10-20 concurrent Agent tool calls in practice). NOT
a runner pool.

### Wave 1b: foundation, post-PR-13

| Milestone | Phases | Approx tickets | Notes |
|-----------|--------|----------------|-------|
| M01 | P3 (codegen pipeline: Rust + Python + TS) | ~6 | depends on P1+P2 |
| M02 | P1 (eleven new fuzz targets) | ~8 | requires PR #13 merged |
| M03 | P2 (Kani 5->10), P3 (Apalache RevocationPropagation) | ~7 | |
| M09 | P3 (`chio-attest-verify` crate + Sigstore signing) | ~4 | unblocks M06 P2 |

### Wave 1 gate

Workspace build/test/clippy/fmt green; conformance vectors verify across all six
SDK toolchains; cargo-vet baseline imports four upstream feeds; cargo-deny clean.

### Wave 2a: trust-boundary nets + conformance packaging

| Milestone | Phases | Tickets | Notes |
|-----------|--------|---------|-------|
| M04 | P1 (corpus + golden infra), P2 (CI gate + `--bless` workflow), P3 (cross-version compatibility) | ~13 | uses M01 P1+P2 vectors |
| M01 | P4 (conformance suite packaging) | ~5 | depends on M01 P3; unblocks M07/M08 consumers |
| M02 | P2 (mutation testing scaffold, advisory), P4 (triage + corpus operations) | ~7 | M02 P4 runs concurrent with P2-P3 per its own scope note |

### Wave 2b: M05 + M06 (serial within each milestone) + replay subcommand + M01 hardening

| Milestone | Phases | Notes |
|-----------|--------|-------|
| M05 | P0 -> P1 -> P2 -> P3 -> P4 atomic, sub-wave per phase | freeze on `crates/chio-kernel/src/kernel/mod.rs` and `session.rs` |
| M06 | P1 -> P2 -> P3 -> P4 atomic, requires M05 P1.T3 sha + M09 P3 sha | `bindgen!` async = true from day one (load-bearing); P4 = per-guard observability |
| M04 | P4 (`chio replay` subcommand) | depends on M04 P3 |
| M01 | P5 (differential + CI hardening) | depends on M02 P1 fuzz infra and M01 P3 codegen |

M05 and M06 sub-waves interleave: M06 P1 waits on M05 P1.T3 publish; M05 P2
proceeds while M06 P1 lands. M04 P4 and M01 P5 land in parallel with M05/M06
provided they touch no shared paths.

### Wave 2 gate

Adds: replay byte-equivalence, Loom interleaving suite (8 tests), criterion
no-regress vs merge-base, Apalache PROCS=4 CAPS=8.

### Wave 3: adapter + runtime breadth + replay invariance

| Milestone | Phases | Tickets | Notes |
|-----------|--------|---------|-------|
| M07 | P1 (tool-call fabric + provenance contract), P2 (OpenAI Responses), P3 (Anthropic), P4 (Bedrock + cross-provider demo) | ~20 | provider crates parallel after P1; M07 P1 sequences first |
| M08 | P1 (browser package), P2 (Workers/Edge/Deno), P3 (decision-only ticket) | ~11 | M08 ships at P2; P3 is a single decision ticket (~1 day) that records the trust-boundary review verdict (Approved/Rejected) under `08-browser-edge-sdk.md` "Trust-boundary review checkboxes" and either closes M08 with a "not pursued, rationale recorded" note OR opens a follow-on milestone. P3 does NOT implement signing in this trajectory. |
| M04 | P5 (property-based replay invariance), P6 (differential anchored-root verification) | ~6 | depends on M03 P3 (Apalache) and M04 P4 |

### Wave 3 gate

Adds: provider conformance against recorded fixtures, browser/edge wasm-pack
matrix, per-runtime size budgets, replay invariance proof.

### Wave 4: operability + reproducibility

| Milestone | Phases | Tickets |
|-----------|--------|---------|
| M10 | P1 (`chio-tee` shadow), P2 (`chio-replay` runner + CLI), P2.5 (fixture-graduation boundary), P3 (OTel GenAI fold-in) | ~18 |
| M02 | P3 (mutation gate flips blocking) | ~2 |
| M09 | P4 (reproducible-build CI + consumer verification recipe) | ~4 |

### Wave 4 gate

Adds: reproducible-build verification (M09 P4 final), mutation-testing gate
becomes blocking via `releases.toml` flip.

---

## 3. Worktree + branch topology

### Layout

All worktrees share `.git` via the primary checkout at
`/Users/connor/Medica/backbay/standalone/arc/`.

```
.worktrees/
  wave-W1/
    m01-spec-codegen/
      p1.t1-add-capability-schema/
      p1.t2-add-receipt-schema/
      ...
    m02-fuzzing/
    m03-capability-algebra/
    m09-supply-chain/
  wave-W2/
    m04-deterministic-replay/
    m05-async-kernel/
    m06-wasm-guard/
  wave-W3/
  wave-W4/
  _archive/    # deleted-but-tarballed worktrees, 90-day retention
```

`.worktrees/` is in `.gitignore` (already conventional in the repo).

### Branch naming regex

```
^wave/W(?P<wave>[1-4])/m(?P<milestone>0[1-9]|10)/p(?P<phase>[0-9]+(\.[0-9]+)?)\.t(?P<ticket>[0-9]+(\.[a-z0-9]+)?)-(?P<slug>[a-z0-9][a-z0-9-]{2,48})$
```

Plus `hotfix/<slug>` for the M05 freeze-bypass lane.

### `git worktree add` template

```bash
git -C "$ORCHESTRATOR_ROOT" worktree add \
  --track -b "wave/W${WAVE}/m${MM}/p${P}.t${T}-${SLUG}" \
  ".worktrees/wave-W${WAVE}/m${MM}-${MILESTONE_SLUG}/p${P}.t${T}-${SLUG}" \
  "${BASE_REF}"
```

`BASE_REF` rules:
- Phase 0 of a milestone uses `origin/main`.
- Subsequent phases inside the same milestone use the previous phase's tip ref
  (stacked PRs via git-spice).
- Cross-milestone tickets always base off `origin/main`.

### Cargo target + cache

- Per-worktree `target/` (default Cargo behavior). Do NOT set a shared
  `CARGO_TARGET_DIR`; documented Cargo footgun under high concurrency.
- Local sccache (optional, single-machine). `SCCACHE_DIR=~/.cache/sccache/chio`.
  No remote backend (no R2, no S3). No per-wave subdir partitioning. If
  sccache is not installed, fall back to native Cargo incremental +
  per-worktree `target/`.
- `~/.cargo/config.toml` (optional):
  ```toml
  [build]
  rustc-wrapper = "sccache"   # only if installed
  incremental = false
  [profile.dev]
  debug = "line-tables-only"
  ```

Hit-rate target: best-effort. The single-machine local cache is
warm-after-first-build; cross-worktree dedup is the main win.

### Push cadence

Push every commit, open PR per phase. PR rate-limit mitigation: 4 GitHub App
installations with token rotation; jitter 0-10s on post-commit hook.

### Stacked vs flat PRs

- Within a milestone phase that has sequential tickets (M05's 24): stack via
  `git-spice`. Reviewers see phase-trains, not 200 PRs.
- Across milestones: flat against `main`.

### Teardown

On PR merge: `git worktree remove --force`, tarball the worktree to
`.worktrees/_archive/wave-WX/mNN/pP.tT.tar.zst` (90-day retention). Per-worktree
`target/` dies; sccache survives.

---

## 4. Ticket model

A ticket is **an atomic mergeable PR sized 0.5-2 engineer-days**, identified by
`M{nn}.P{n}.T{n}[.{k}]` where `.k` allows splits without renumbering siblings.

### Schema (per-phase YAML)

```yaml
- id: M05.P1.T3
  milestone: M05
  phase: 1
  title: "Move receipt signing onto mpsc-backed signing task"
  status: pending
  effort_days: 1.5
  owner_glob:
    - "crates/chio-kernel/src/kernel/evaluator.rs"
    - "crates/chio-kernel/src/kernel/mod.rs"
  shared_paths: ["Cargo.lock"]
  depends_on: [M05.P1.T1, M05.P0.T2]
  soft_deps: [M03.P1.T3]
  gate_check:
    cmd: "cargo test -p chio-kernel --test receipt_signing_async"
  worktree_branch: "wave/W2/m05/p1.t3-mpsc-receipt-signing"
  agent_role: kernel-rust
  review_required: ["@bb-connor"]
  first_commit_sha: null
  merged_sha: null
  opened_ts: null
  merged_ts: null
```

### Storage

```
.planning/trajectory/tickets/
  manifest.yml         # generated flat array, sorted by id
  schema.json          # JSON Schema; CI validates manifest.yml
  STATUS.md            # human rollup, regenerated by `chio-trajectory status`
  M01/
    P1.yml             # one file per phase
    P2.yml
    ...
  M02/...
  ...
```

`manifest.yml` is regenerated from the per-phase files; per-phase files are the
source of truth. Both are committed; CI validates consistency.

### State machine

```
pending -> in_progress     (when worktree branch is created and first commit pushed)
in_progress -> review      (when PR is opened with green pre-merge CI)
review -> blocked          (reviewer requests changes, OR a hard dep regressed)
review -> merged           (only after gate_check.cmd passes on the merge commit)
blocked -> in_progress     (after blocker resolves)
in_progress -> blocked     (rare; agent voluntarily yields)
```

Hard rules:
- No `pending → review` (must pass through `in_progress`).
- No `review → merged` if `gate_check.cmd` exits non-zero on the merge commit.
- No transition to `in_progress` if any `depends_on` ticket is not `merged`.
- `blocked` requires a `block_reason` (ticket id or free-text issue link).

### Effort calibration

`scripts/calibrate-effort.sh` runs nightly:
- `actual_days / effort_days` ratio per S/M/L bucket per agent role
- Trailing 20-ticket median; if drift >40% from 1.0, post a daily-digest comment
  proposing a multiplier adjustment for new estimates in that bucket
- Records calibration in `tickets/CALIBRATION.md`. Never retroactively rewrites
  closed tickets.

### Roll-up queries

```bash
# Is M01 phase 1 complete?
# yq -p=yaml -o=json keeps the same jq-style syntax against YAML input.
yq -p=yaml -o=json -e 'all(.[] | select(.milestone=="M01" and .phase==1); .status=="merged")' \
  .planning/trajectory/tickets/manifest.yml

# What can the orchestrator launch RIGHT NOW?
yq -p=yaml -o=json '[.[] | select(.status=="pending") | select(
      [.depends_on[] as $d | any(.[]; .id==$d and .status=="merged")] | all
    )]' .planning/trajectory/tickets/manifest.yml

# Shared-path collisions in active tickets
yq -p=yaml -o=json '[.[] | select(.status=="in_progress") | {id, shared_paths}]
    | map(.shared_paths[]) | group_by(.) | map(select(length>1))' \
  .planning/trajectory/tickets/manifest.yml
```

---

## 5. File ownership manifest

Granularity: per-module-or-subdirectory glob. Source of truth:
`.planning/trajectory/OWNERS.toml`. CODEOWNERS is generated; CI fails if it has
drifted.

### Excerpt (full manifest in OWNERS.toml)

```
# Spec / wire / corpus
spec/schemas/**/*.json                              -> M01
tests/bindings/vectors/**                           -> M01
tests/conformance/**                                -> M01, M07, M08
tests/replay/fixtures/**                            -> M04, M07 (adds), M10 (--bless graduate)

# Kernel - the contended crate
crates/chio-kernel/src/kernel/mod.rs                -> M05 (FROZEN during M05 P1-P3)
crates/chio-kernel/src/session.rs                   -> M05 (FROZEN)
crates/chio-kernel/src/receipt_*.rs                 -> M04 (golden basis), M05 (signature shape)
crates/chio-kernel-core/**                          -> M03 (algebra), M05 (async-shape)
crates/chio-kernel-browser/**                       -> M08

# Algebra and core
crates/chio-core-types/src/capability*.rs           -> M03
crates/chio-core-types/src/scope*.rs                -> M03
crates/chio-core-types/src/receipt*.rs              -> M01 (wire), M04 (golden)
crates/chio-core-types/src/provenance*.rs           -> M01 (schema), M07 (consumer)

# Tower / WASM / Anchor
crates/chio-tower/src/middleware/**                 -> M05
crates/chio-tower/src/host_call.rs                  -> M06
crates/chio-tower/src/adapter.rs                    -> M07
crates/chio-wasm-guards/src/host.rs                 -> M06
crates/chio-wasm-guards/src/registry.rs             -> M06 (NEW)
crates/chio-wasm-guards/src/hot_reload.rs           -> M06 (NEW)
wit/chio-guard/world.wit                            -> M06
wit/chio-guards-redact/world.wit                    -> M10 (M06 reserves namespace placeholder)
crates/chio-attest-verify/**                        -> M09 (NEW crate)

# Tee / replay / providers
crates/chio-tee/**                                  -> M10 (NEW)
crates/chio-tee-frame/**                            -> M10 (NEW)
crates/chio-tool-call-fabric/**                     -> M07 (NEW)
crates/chio-openai/**                               -> M07
crates/chio-conformance/**                          -> M01

# SDKs
sdks/typescript/packages/browser/**                 -> M08
sdks/typescript/packages/workers/**                 -> M08
sdks/typescript/packages/edge/**                    -> M08
sdks/typescript/packages/conformance/src/browser-subset.ts -> M08
sdks/typescript/packages/wire/**                    -> M01 (codegen target)
sdks/python/**/_generated/**                        -> M01 (regenerate-only)
sdks/python/**                                      -> M01

# Formal / fuzz
formal/lean4/**                                     -> M03
formal/tla/**                                       -> M03
formal/rust-verification/**                         -> M03
fuzz/fuzz_targets/**                                -> M02
fuzz/corpora/**                                     -> M02 (seeded from M01)

# Cross-cutting (sequencer)
Cargo.toml (workspace)                              -> SEQUENCER
Cargo.lock                                          -> SEQUENCER
deny.toml                                           -> M09
rust-toolchain.toml                                 -> FROZEN
.github/workflows/ci.yml                            -> SEQUENCER (lane-by-lane)
CODEOWNERS                                          -> SEQUENCER (generated)
README.md, AGENTS.md, CLAUDE.md                     -> SEQUENCER (signed sections)
.planning/trajectory/**                             -> SEQUENCER
```

### Workflow lane ownership

Each top-level job inside a workflow is tagged `# owner: M0X`; the freeze-guard
validates against OWNERS.toml.

| Workflow | Lane (job id) | Owner |
|----------|---------------|-------|
| `ci.yml` | `lint`, `fmt`, `test` | SEQUENCER (frozen) |
| `ci.yml` | `fuzz-smoke` | M02 |
| `ci.yml` | `apalache` | M03 |
| `ci.yml` | `bench-regression` | M05 |
| `ci.yml` | `replay-bytewise` | M04 |
| `ci.yml` | `slsa-provenance` | M09 |
| `nightly.yml` | `apalache-liveness` | M03 |
| `nightly.yml` | `long-fuzz` | M02 |
| `release-binaries.yml` | full file | M09 |
| `release-npm.yml` | full file | M08 |
| `release-pypi.yml` | full file | M01 |
| `web-sdk.yml` (NEW) | full file | M08 |
| `oss-fuzz.yml` (NEW) | full file | M02 |
| `sigstore-mirror.yml` (NEW) | full file | M09 |

### Freeze protocol (kernel/mod.rs during M05 P1-P3)

Two independent server-side locks (origin is github.com, which does not expose
pre-receive hooks; the freeze rests on CODEOWNERS + branch ruleset):

1. **CODEOWNERS hard lock**. During the freeze window, CODEOWNERS lists
   `@bb-connor` for `crates/chio-kernel/src/kernel/mod.rs`,
   `kernel/session_ops.rs`, `crates/chio-kernel/src/session.rs`. Encoded as a
   date range in OWNERS.toml; CODEOWNERS is regenerated by the freeze-guard
   workflow. Single-owner: collapses to self-merge discipline.
2. **Branch ruleset + required status check**. A GitHub branch ruleset on
   `main` enforces:
   (a) the required status check `m05-freeze-guard` (workflow diffs the PR;
       fails if any frozen path changed and the PR title does not begin with
       `[M05]`);
   (b) optional path restriction (matters once contributors beyond
       `@bb-connor` exist).
   Branch rulesets, unlike legacy branch protection, can restrict file paths
   directly; this replaces what a pre-receive hook would do on a self-hosted
   origin.

The freeze window is announced in a pinned issue with a Slack template at start
of P1 and end of P3. Local clones may install
`scripts/hooks/pre-commit-freeze-warn` for an early-warning signal; the
authoritative enforcement is server-side.

### `Cargo.lock` merge protocol

- Custom merge driver via `.gitattributes`: `Cargo.lock merge=cargo-lock-regen`.
  Driver runs `cargo update --workspace` (regenerates the lockfile from the
  current Cargo.toml state) then asserts reproducibility via
  `cargo metadata --locked` on the result. **Precondition**: any conflicts in
  `Cargo.toml` (workspace or member manifests) must already be resolved by
  the human reviewer or the merge-queue rebase before this driver runs; the
  driver assumes a single coherent Cargo.toml tree as input and will not
  attempt to merge dep-version conflicts.
- PRs that touch `Cargo.toml` (workspace or member) or `Cargo.lock` route
  through GitHub's merge queue with concurrency=1.
- Pure-code PRs bypass the lockfile queue.
- Wave-1 lock-bump order: M09 → M03 → M01 → M02. Bumps land before any feature
  work in that milestone.

### Hand-off protocol

When ownership transfers (e.g. M01 → M07 for `spec/schemas/provider/`):

1. Closing milestone tags path-set in OWNERS.toml: `frozen-after: <commit-sha>`
   and writes `HANDOFF.md` under the milestone dir.
2. New milestone files hand-off PR updating OWNERS.toml. Two reviews required:
   outgoing primary owner + sequencer.
3. Outgoing milestone retains "veto rights" entry for one wave.
4. Every load-bearing file gets a `// owned-by: M0X` header; the
   `m05-freeze-guard` workflow (and equivalent owner-guard workflows for other
   contended files) parses these headers in PR diffs and fails the required
   status check if a header changes without a co-signed hand-off PR. (Pre-
   receive hooks are not available on github.com origins; enforcement is
   server-side via required checks + branch ruleset path restrictions.)

### No verifier or trust-boundary stubs

A milestone that depends on a verifier or trust-boundary crate (e.g. M06
depending on `chio-attest-verify`) **blocks** until the owning milestone
lands the real fail-closed crate. There are no pre-implementation stubs,
trait-only crates, or `unimplemented!`-shaped placeholders for verifier or
attestation surfaces in the merge train. Rationale: a stub that returns
`Ok(verified)` or panics is a vulnerability the moment a feature flag flips
or a build option drifts.

Hard rules:

- `todo!()`, `unimplemented!()`, and `panic!()` are forbidden in any path
  matching `crates/**/verify*`, `crates/chio-attest-verify/**`,
  `crates/chio-credentials/**`, `crates/chio-policy/**`, and the
  trust-boundary set defined in section 7. Test-only `panic!` requires
  `#[cfg(test)]` plus Security x2 approval on the test rationale.
- Divergence detector: `rg -n 'todo!\(|unimplemented!\(|panic!\(' <paths>`
  fails any trust-boundary PR unless the diff also includes a Security x2
  signoff comment with a test-only justification.
- M09 P3 lands the trait, error types, and the real `SigstoreVerifier`
  implementation in **one** PR. Consumers (M06 P2) may not merge before
  M09 P3's integration tests pass on `main`.

Wave plan already sequences M09 P3 (Wave 1b) before M06 P2 (Wave 2b), so no
stubs are needed.

### Generated-file policy

- `_generated/` subdirs are regenerate-only. Pre-commit hook hashes generated
  dirs against `make regen-bindings` output; mismatch blocks commit.
- Generated files carry a `// DO NOT EDIT - regenerate via 'make regen-<lang>'`
  header with the schema git SHA that produced them.
- Tool versions pinned in `tools/codegen-versions.toml` and run inside Docker
  images with digest pins. Reproducible.

---

## 6. Execution model

The orchestrator is Claude (this Claude Code session). Executor and reviewer
agents are sub-agents spawned via the Agent tool with role-specific prompts
and model parameters. Build / test / clippy / fmt gates run in this session
via Bash against local git worktrees. There is no self-hosted CI runner pool,
no AWS spot fleet, no Cloudflare R2 sccache backend, and no infrastructure
spend. The earlier multi-engineer-team draft of this section assumed a Tier
A self-hosted pool at ~$146/month plus R2 cache; that assumption is dropped
for the single-owner / Claude-Code-driven trajectory.

### What runs where

| Concern | Where | Notes |
|---------|-------|-------|
| Per-ticket gate (fmt/clippy/build/test/deny) | Orchestrator session, Bash | Run by orchestrator before declaring an executor sub-agent finished. |
| Wave gate (full workspace gate matrix per section 9) | Orchestrator session, Bash | Run on the wave-integration tip before advancing. |
| Loom interleavings (M05) | Orchestrator session, Bash | `LOOM_MAX_PREEMPTIONS=3`, 10-minute per-suite cap. |
| Apalache (M03 `RevocationPropagation.tla`) | Orchestrator session, Bash | `apalache-mc` binary installed locally via `tools/install-apalache.sh`. |
| Kani harnesses (M03 expanded set, 10 total) | Orchestrator session, Bash | Slow harnesses gated to wave-close, not per-ticket. |
| Criterion benches (M05) | Orchestrator session, Bash | Numbers are not portable across hosts; orchestrator records host fingerprint (CPU, kernel, governor) alongside each run; cross-session deltas are advisory. |
| `cargo-mutants` PR-incremental (M02) | Orchestrator session, Bash | `--in-diff origin/main` at wave-close on the four target crates; 15-30 min/gate. |
| `cargo-mutants` full sweep | Out of scope as a scheduled lane | The orchestrator has no nightly cron. Full sweep runs at release-cycle boundaries on demand. |
| ClusterFuzzLite PR smoke (`cflite_pr.yml`) | GitHub Actions hosted, public-repo free tier | 60-120s/target, changed-target only. Self-capped at 1,800 min/30d via `scripts/check-fuzz-budget.sh` to leave headroom inside the public-repo 2,000 min/month free tier. |
| ClusterFuzzLite weekly soak (`cflite_batch.yml`) | GitHub Actions hosted | One rotated target per night, full 18-day rotation. |
| OSS-Fuzz continuous fuzz | OSS-Fuzz infra, free, post-acceptance | M02 P2 deliverable; infra prepared in `infra/oss-fuzz/`. |
| Public CI signal workflows (`spec-drift.yml`, `chio-replay-gate.yml`, `web-sdk.yml`, `m05-freeze-guard.yml`, etc.) | GitHub Actions hosted, public-repo free tier | Authored as Wave 0 / per-milestone deliverables. They run on push and serve as a public-facing CI signal redundant with the orchestrator's in-session gates. They are NOT the orchestrator's primary execution lane. |

### Concurrency

The concurrency cap is whatever parallelism Claude Code permits in one
thread (typically ~10-20 concurrent Agent tool calls in practice); the
load-bearing bounds are shared_paths collisions and the dependency DAG,
not a runner pool. The bottleneck is integration: full workspace
`cargo build && cargo test` on the merge-train branch is the chokepoint,
and the Cargo.lock + downstream rebuild cascade dominates well before any
agent-count limit.

### Cargo target + cache

- Per-worktree `target/` (default Cargo behavior). Do NOT set a shared
  `CARGO_TARGET_DIR`; documented Cargo footgun under high concurrency.
- Local sccache optional. No remote backend. If sccache is installed on
  the orchestrator host, the orchestrator lets it use the user's local
  cache directory (`~/.cache/sccache`); no S3/R2 setup required or
  recommended.

### Bench numbers

Bench numbers are valid against the local host fingerprint only. The
orchestrator records `host.cpu`, `host.kernel`, `host.governor`,
`host.htoff` at each bench-run start. Cross-session deltas without a
matching fingerprint are advisory; M05's 10% p99 regression gate is
authoritative only for runs against a fixed merge-base on a single
fingerprint.

### Public-CI workflow concurrency keys (when authored)

```yaml
# Per-PR (cancel old runs)
concurrency:
  group: pr-${{ github.ref }}
  cancel-in-progress: true

# Per-main-push (never cancel)
concurrency:
  group: main-${{ github.sha }}
  cancel-in-progress: false
```

### Cost note

GitHub Actions hosted runners only. No self-hosted, no external cache.
Cost is whatever GHA bills the repo account; ClusterFuzzLite + the
authored CI workflows share the public-repo 2,000-min/month free tier
(self-capped at 1,800/30d for fuzz). OSS-Fuzz is free post-acceptance.
Claude Code orchestrator usage is billed separately to the user.

---

## 7. Review pipeline

### Reviewer roster (7 roles)

| Role | Owns | Catches |
|------|------|---------|
| Gatekeeper | every ticket | mechanical: build, clippy `-D warnings`, fmt, conventional-commits, em dashes, `unwrap`/`expect`, secrets, scope creep, Cargo.lock churn |
| Spec | every ticket | implementation matches ticket spec; no claim-widening; no silent dropped criteria |
| Security | trust-boundary crates | fail-closed semantics, attestation invariants, `unsafe` justification, constant-time compares |
| Test | every ticket | tests exist, fail without the change, cover acceptance criteria, no flake under 20x re-run |
| Performance | bench-tagged or hot-path tickets | bench delta within budget, no allocation in hot loop, no sync I/O on async path |
| Cross-Doc | every ticket | spec/PROTOCOL.md drift, AGENTS.md crate map, RELEASE_AUDIT/QUALIFICATION/BOUNDED_OPERATIONAL_PROFILE consistency, Chio/ARC naming |
| Integration | wit/, contracts/, sdks/, bindings-ffi changes | downstream crate compile, SDK regen, ABI compat |

Tickets self-tag in frontmatter (`reviewers: [security, perf]`); Gatekeeper
verifies tags match the diff.

### Routing rules

Every ticket: Gatekeeper + Spec + Test + Cross-Doc unconditionally. Specialists
by file glob.

**Trust-boundary set** (Security x2 mandatory; Performance routed in addition only when bench-tagged or hot-path):

```
crates/chio-kernel/**
crates/chio-kernel-core/**
crates/chio-credentials/**
crates/chio-policy/**
crates/chio-guards/**
crates/chio-data-guards/**
crates/chio-wasm-guards/**
crates/chio-api-protect/**
crates/chio-did/**
crates/chio-anchor/**
crates/chio-envoy-ext-authz/**
crates/chio-attest-verify/**       (PLANNED-NEW: lands in M09 P3; the
                                    preflight crate-existence check should
                                    skip this entry until M09 P3 merges)
crates/chio-store-sqlite/src/**  (security-relevant store paths only;
                                  the migration tree stays Performance)
```

| Trigger | Adds |
|---------|------|
| Any path in the trust-boundary set above | Security (x2) |
| Bench-tagged, `chio-kernel*` (perf-only paths), `chio-mercury*`, `chio-store-sqlite/migrations/**`, `chio-tower/**`, `chio-http-core/**` | Performance (in addition to Security x2 if the path is also trust-boundary) |
| `wit/**`, `contracts/**`, `sdks/**`, `chio-bindings-ffi/**`, `chio-cpp-kernel-ffi/**` | Integration |
| `spec/**`, `docs/**`, `.planning/**` | Cross-Doc as primary |
| `formal/**`, `deny.toml`, workspace `Cargo.toml` | Security + Integration |

### In-wave concurrent review

Reviewer fan-out fires on every push, not at wave-end. Wall-clock bounded by
slowest reviewer (Integration), not sum. Integration runs twice: in-wave on the
isolated branch, post-wave on merge-train candidate.

### Two-reviewer rule

Required for any diff touching trust-boundary crates, `formal/**`,
`deny.toml`, `wit/**` (ABI surface), or workspace-level `Cargo.toml` deps.
Two **independent** Security Reviewer instances must both approve.
Independence is achieved in-thread by spawning two Plan-role sub-agents
with different `model` parameters (one `opus`, one `sonnet`), no shared
scratchpad, and prompts that present only the diff and the role checklist
(no prior reviewer's verdict). Disagreement escalates to halt-and-ping.

### Auto-fix policy

Reviewer auto-fixes via fixup commit (separate from executor's commit) for:
`cargo fmt` drift, trailing whitespace, missing newline at EOF, em-dash → hyphen,
conventional-commit reformat, `Cargo.lock` regen.

Reviewer bounces back for: any logic change, signature change, test addition,
or any change touching trust-boundary crates (no auto-fix on security paths
ever).

### Anti-rubber-stamp QA

1. **Canary fixtures**. ~12 pinned known-bad diffs (planted unwrap, em dash,
   policy bypass, scope creep, flake, spec mismatch). Every reviewer instance
   gets one canary as ~2% of workload. Missing a canary auto-suspends that
   reviewer instance and pages.
2. **Sample audit**. 5% of approved tickets re-reviewed post-merge by a fresh
   reviewer with no access to prior approval. Disagreement >5% triggers panel
   review.
3. **Blocking-rate watchdog**. Each reviewer instance's block/approve ratio
   tracked; rates drifting >2σ from cohort median (rubber-stamping AND
   nitpicking) trigger calibration review.

### Blocking vs advisory matrix

Blocking: build failure, test failure, clippy violation, em dash, new
unwrap/expect outside tests, secret detected, out-of-scope file modified,
malformed conventional commit, missing acceptance criterion, fail-closed
regression, WIT/contract drift without SDK regen, doc/code contradiction in
source-of-truth, performance regression beyond budget, flake (>0 fails in 20x).

Advisory: naming style nits, missing doc on private item, test name not
behavior-shaped, suggested refactor for follow-up.

### Escalation triggers (8)

Reviewer halts and pages user when:
1. Cross-doc contradiction between `spec/PROTOCOL.md` and a top-three claim doc
2. Security regression in trust-boundary crate not mechanically classifiable
3. Scope creep where executor modified >2 out-of-scope files after one bounce
4. Test flake reproducible but not localizable
5. Two reviewers disagree on the same blocking finding
6. Three consecutive bounces on same ticket without convergence
7. Secret-pattern hit (always page; never auto-redact)
8. Formal/proof drift in `formal/**` or invariant change in `chio-kernel-core`
   not paired with formal update

---

## 8. Orchestrator state machine

```
PLAN -> SPAWN -> RUN -> REVIEW -> INTEGRATE -> GATE -> {ADVANCE | BISECT | HALT}
                       |
                       +---> RETRY_TICKET (per-ticket gate fail)
                       +---> ESCALATE (retry budget exhausted)

BISECT -> ROLLBACK (culprit found) -> ADVANCE
BISECT -> HALT (timeout)
```

| State | Entry | Exit |
|-------|-------|------|
| PLAN | last wave advanced or cold start | resolve cohort from frontier |
| SPAWN | cohort sized | provision N worktrees |
| RUN | worktrees up | per-ticket gates run |
| REVIEW | gates green | reviewer agent reads diff |
| INTEGRATE | review pass | merge to `wave-N-integration` branch |
| GATE | all wave tickets merged | full per-wave matrix |
| ADVANCE | gate green | merge integration → main, recompute frontier |
| BISECT | gate red | git bisect against wave commits |
| ROLLBACK | culprit found | revert PR, re-gate the smaller set |
| RETRY_TICKET | per-ticket gate red | re-spawn ticket |
| ESCALATE | retry budget exhausted | open `chio-trajectory-blocked` issue |
| HALT | bisect timeout or escalate | wait for human resume |

### Concurrency cap

Sub-wave concurrency is bounded by the dependency DAG and shared_paths
collisions, plus the parallelism Claude Code permits in one thread
(typically ~10-20 concurrent Agent tool calls). We are integration-bound:
the per-wave gate (workspace build + workspace test) is the chokepoint,
and the Cargo.lock + downstream rebuild cascade dominates well before any
agent-count limit.

---

## 9. Gate matrix

Two tiers: per-wave blocking, and rolling sampled.

| Gate | Runs | Tier | Wall budget | Blocking | Failure action |
|------|------|------|-------------|----------|----------------|
| `cargo fmt --all -- --check` | every ticket pre-merge | per-ticket | 30s | yes | reject ticket |
| `cargo clippy --workspace -- -D warnings` | every ticket pre-merge | per-ticket | 4 min | yes | reject ticket |
| `cargo deny check` | every ticket pre-merge | per-ticket | 1 min | yes | reject ticket |
| `cargo build --workspace` | post-integrate | per-wave | 2-8 min | yes | bisect |
| `cargo nextest run --workspace` | post-integrate | per-wave | 12 min | yes | bisect |
| Conformance vector pack (M01) | post-integrate, after M01 P2 lands | per-wave | 3 min | yes | revert wave |
| Replay byte-equivalence (M04) | post-integrate, after M04 P1 lands | per-wave | 5 min | yes | revert wave |
| Loom interleavings (M05, 8 tests) | post-integrate, on `kernel/` touch | conditional | 6 min | yes | revert offending ticket |
| Criterion bench delta | post-integrate, when M05 active | conditional | 7 min | regress >10% | flag, no auto-revert |
| Kani harnesses (10) | post-integrate, on capability/policy crate touch | per-wave | 10 min | yes | revert offending ticket |
| Apalache `RevocationPropagation.tla` | post-integrate, PROCS=4 CAPS=8 | per-wave | 6 min | yes | revert offending ticket |
| Reproducible build diff (M09) | nightly | sampled | 25 min | yes after M09 P3 | block next wave |
| libFuzzer corpora smoke | nightly | sampled | 60 min | no | open issue |
| `cargo-mutants --in-diff` | wave-gate (advisory) | sampled | 15-30 min | advisory until M02 P3+1 release, then yes | block next wave's integrate |
| OSS-Fuzz | continuous, off-site | sampled | n/a | no | triage in chio-fuzz-triage |

Anything that exceeds 12 min is sampled, not blocking, unless it is the
load-bearing safety net for an active milestone (Loom for M05, Replay for
everything Wave 2+).

### Mid-wave abort policy

Ship the passers, retry the failers, with two hard exceptions:

- **Exception 1**: if a failed ticket is on the dependency-satisfied path of a
  passing ticket in the same wave, both are held. The passing ticket is
  un-merged from the integration branch and re-queued.
- **Exception 2**: M05 P0..P4 sub-waves are atomic. Any failure inside an M05
  sub-wave rolls back the entire sub-wave because the freeze on `kernel/mod.rs`
  makes partial integration meaningless.

### Gate-failure recovery

```
1. Tag wave-N integration commit as WAVE_N_HEAD.
2. Identify failing test set F = {pass at WAVE_(N-1)_HEAD, fail at WAVE_N_HEAD}.
3. git bisect WAVE_N_HEAD WAVE_(N-1)_HEAD with a script running F.
4. Bisect identifies culprit commit C.
5. Open revert PR for C; merge if the revert PR's wave gate passes.
6. Wave N re-integrated minus C; C goes to retry queue with bisect log.
7. If F bisects to a merge of two non-adjacent commits (interaction bug),
   revert both; queue a combined retry.
```

Bisect timeout: 90 min wall. Beyond that, wave wholesale-reverted to
WAVE_(N-1)_HEAD and re-planned with a smaller cohort.

### Flake quarantine

Each post-integrate test runs 3x. Only deterministic failures trigger BISECT.
Flaky-classified failures route to `chio-flaky-quarantine` lane, the wave
advances, and the flake is opened as an issue. Precedent: `f8e7bac40` (TTL
session-restore re-ignore).

---

## 10. Autonomy boundary

Tag legend: **A** = allowed, **C** = requires-confirm, **F** = forbidden.

| # | Action class | Tag | Notes |
|---|--------------|-----|-------|
| 1 | Add a workspace dep already present transitively | A | `cargo tree` proves it's not novel |
| 2 | Add a brand-new external crate dep | C | Touches M09 supply-chain |
| 3 | Bump existing crate (patch) | C | Even patch can shift deny.toml advisories |
| 4 | Bump existing crate (minor/major) | F | Always halt |
| 5 | Edit `deny.toml` | F (non-M09) / A (M09) | M09 owns wholesale |
| 6 | Edit `AGENTS.md` or `CLAUDE.md` | F | Source-of-truth files |
| 7 | Add a new GitHub Actions workflow | A (M02/M09) / F (other) | Per ownership |
| 8 | Modify existing CI workflow | C | Wave-gate effects |
| 9 | Touch existing migrations or `tests/replay/fixtures/` golden corpus | F | Determinism canary; M04 owner only via human approval |
| 10 | Drop, `#[ignore]`, or rename a passing test | F | Period |
| 11 | Add a new test | A | Encourage |
| 12 | Add `#[allow(clippy::...)]` | F | Workspace policy |
| 13 | Add a new crate under `crates/` | C | Confirms it matches owning milestone's plan |
| 14 | Substantive trust-boundary edit (any crate in the trust-boundary set; non-comment, non-blank diff in code, WIT, schema, Cargo deps, workflow permissions, security-asserting tests, or generated signed-shape artifacts) | F unless the milestone explicitly owns the path; if owned, then C with Security x2 + human confirmation; halt-and-ping otherwise. Detection: `scripts/classify-trust-diff.sh` strips blank/comment-only chunks and labels the PR `trust-boundary/substantive` or `trust-boundary/cosmetic`; required check fails without one of those two labels. |
| 15 | Cosmetic trust-boundary edit (comment-only, formatting, doc-only inside a trust-boundary crate) | C with one Security reviewer |
| 16 | Touch `formal/` | C | M03 owner; needs human eyes |
| 17 | Touch `wit/chio-guard/` | F (non-M06) / A (M06) | Owned namespace |
| 18 | Force-push, amend, rebase shared branches | F | Always |
| 19 | Create release tag, edit `releases.toml` | F | Trajectory excludes releases |
| 20 | Resolve merge conflict | C | Especially `kernel/mod.rs` (M05 freeze risk) |

---

## 11. Divergence detection

Run on the executor's branch BEFORE entering the review queue.

1. **Cargo metadata coherence**. `cargo metadata --no-deps --format-version 1`
   on the executor's branch. Every claimed-created or claimed-modified crate
   must appear (or be deleted). Every added dep must resolve. Hallucinated
   `chio-attest-verify::verify_blob` import without the crate in metadata =
   halt.
2. **Symbol existence grep**. For each public symbol the ticket spec names,
   `rg -n '\b<symbol>\b' --type rust crates/`. Zero hits when spec demands ≥1 =
   hallucination.
3. **Test results not stubbed**. `cargo nextest run --message-format
   libtest-json` parsed against executor's claimed pass/fail. A test the
   executor "ran" that doesn't appear in the JSON stream never ran. New
   `#[ignore]` is divergence unless ticket spec authorizes.
4. **CI-equivalent gate locally**. Orchestrator independently runs the
   CLAUDE.md one-liner; disagreement with executor's PR description = lie.
5. **Conventional-commits regex**:
   `^(feat|fix|docs|test|refactor|chore|build|ci|perf)(\(.+\))?: .+`.
6. **Em-dash scan**. The orchestrator scans the PR diff for the UTF-8
   byte sequence 0xE2 0x80 0x94, which encodes U+2014. The scan
   command itself is `rg -n -e $'\u2014' <diff-file>` (zsh and
   bash 4.2+ expand the `\u2014` sequence inside ANSI-C $'...'
   quoting to the corresponding UTF-8 bytes at runtime, so the literal
   U+2014 character is never typed in this doc and the scan rule does
   not flag itself). Any hit on the diff auto-rejects.
7. **Banned-API drift**. `rg -n '\.unwrap\(\)|\.expect\('` on diff. Workspace
   clippy bans these; if clippy passes (executor `#[allow]`'d), orchestrator
   catches.
8. **PR state truth check**. `gh pr view 13 --json state,mergedAt` for any
   ticket gating on it.
9. **Spec/codegen drift (M01-touching)**. Recompute `MANIFEST.sha256`; reject
   if executor's claimed hash mismatches recomputed.
10. **Cross-doc invariant guard**. Ticket touching one of the seven cross-doc
    invariants (canonical-JSON corpus, `chio-attest-verify`,
    `chio-tee-frame.v1`, `chio-tower`, `chio:guard@0.2.0`, capability algebra,
    Apalache lane) outside its owning milestone = automatic halt-and-ping
    even if the diff "works."

---

## 12. Retry, cascade, halt-and-ping

### Retry policy

- **Per-ticket cap: 3 attempts**. Past 3, halt-and-ping.
- **Attempt 1 failure**: retry **same executor**, with failure log injected.
  Backoff 30s.
- **Attempt 2 failure**: retry **fresh executor**, no shared diff context (only
  ticket spec + sanitized failure summary; do not let it copy the broken
  approach). Backoff 2 min.
- **Attempt 3 failure**: halt-and-ping. No third executor.
- **Divergence-class failures** (hallucinated symbols, fabricated test results)
  skip directly to halt-and-ping on attempt 1.
- **Flake-class failures** get one automatic re-run of the same artifact. If
  still flaking, halt-and-ping; do not retry the ticket.

### Cascade-failure protocol

When ticket M07.P2.T3 fails terminally and T4/T5/T6 depend on it:

- **Default: halt the dependency subtree**. Move dependents to `blocked` with
  `blocked_on: M07.P2.T3`. Do NOT stub.
- **Stubbing forbidden by default**. Stubs in security-critical Rust become
  permanent.
- **Exception (opt-in)**: if and only if ticket spec contains
  `degraded_scope_acceptable: true` plus a `stub_contract:` block. M03
  invariants and M09 attestation tickets must never carry this flag.
- **Other-wave tickets** (independent subtrees) continue.

### Halt-and-ping triggers

The orchestrator halts and pings the user when:

1. Two consecutive wave-gate failures
2. One divergence-class detection (single occurrence, no second-strike)
3. Reviewer-flagged scope creep on ≥2 tickets in 24h
4. Test-flake rate >5% over the last 50 ticket attempts
5. Any forbidden-class action attempted by an executor (table 10 row F)
6. Security-critical file change exceeding ticket's
   `expected_diff_lines * 1.5`
7. PR #13 not merged after Wave 2 starts (planning-state corruption)
8. Cargo.lock churn >25 lines in a single ticket
9. Cross-doc invariant violation (#11.10)
10. Two reviewers disagree on the same ticket
11. Same ticket exhausts retry cap

(The earlier draft included a "halt budget tripped: >5 halts in any 24h
period" trigger; dropped under the single-owner / Claude-Code-driven
trajectory. Halt = pause until the user replies in chat.)

---

## 13. State persistence + audit log

### `EXECUTION-STATE.json`

Atomic writes via `tmp + fsync + rename`, with `.bak` rotation.

```json
{
  "schema_version": "1",
  "started_at": "2026-04-25T14:32:11Z",
  "last_checkpoint_at": "2026-04-25T18:04:02Z",
  "current_wave": 1,
  "halt": {
    "halted": false,
    "reason": null,
    "trigger_event_id": null,
    "halted_at": null
  },
  "milestones": {
    "M01": { "status": "in_progress", "phase": "P2", "owner_branch": "trajectory/m01" }
  },
  "tickets": {
    "M01.P1.T3": {
      "status": "merged",
      "attempts": 1,
      "executor_id": "exec-7af3",
      "branch": "trajectory/m01/p1-t3",
      "pr_number": 217,
      "merged_at": "2026-04-25T17:11:03Z",
      "diff_stats": { "files": 4, "insertions": 88, "deletions": 12 },
      "divergence_checks": { "passed": 10, "failed": 0 }
    }
  },
  "wave_gate_history": [
    { "wave": 1, "result": "pass", "at": "...", "build_ms": 412013 }
  ],
  "pr_state_cache": {
    "13": { "state": "OPEN", "fetched_at": "..." }
  }
}
```

### `EXECUTION-LOG.ndjson`

NDJSON, append-only, rotate at 100 MB. One event per line.

Common envelope:
```json
{ "event_id": "01HV3...", "ts": "...", "type": "...", "wave": 1,
  "ticket_id": "M01.P2.T7", "actor": "orchestrator|executor:exec-7af3|...",
  "payload": { ... } }
```

Event types: `ticket_scheduled`, `ticket_executor_started`,
`ticket_executor_finished`, `divergence_check_run`, `wave_gate_run`,
`pr_opened`, `pr_review_verdict`, `pr_merged`, `retry_scheduled`,
`halt_triggered`, `halt_cleared_by_user`, `state_snapshot_written`,
`boundary_violation_attempted`, `resume`.

Every line is independently jq-parseable.

---

## 14. Resume protocol

On orchestrator startup (cold or warm):

1. **Load state**. If `EXECUTION-STATE.json` malformed, fall back to `.bak`. If
   both malformed, halt-and-ping with corruption.
2. **Verify halt status**. If `halt.halted == true`, do nothing except print
   reason + trigger event ID. Wait for user to clear via explicit JSON edit
   plus a `user_note` (forces moment of reflection; alarm-fatigue mitigation).
3. **Reconcile in-flight tickets**. For every ticket in `in_progress`,
   `in_review`, or `executing`:
   - `gh pr view <pr_number> --json state,mergeable,statusCheckRollup`
   - Merged → mark `merged`, advance dependents
   - Closed without merge → mark `failed`, increment `attempts`, route to retry
   - Still open → re-attach orchestrator's monitor; do not relaunch executor
4. **Re-check PR #13** and other gating PRs from `pr_state_cache`. If state
   changed, recompute wave eligibility.
5. **Recompute schedulable set** from dep graph + state. Do not trust
   in-memory queue.
6. **Replay last 100 lines** of audit log for missed anomalies (executor branch
   opened but no verdict recorded → likely crash; mark `failed`).
7. **Write `resume` event**.
8. **Then start scheduling**.

Invariant: state-on-disk + GitHub state are the only sources of truth.

---

## 15. Sequenced kickoff

### Day 0: pre-flight

User completes (in any order):
- (deprecated; single-owner trajectory does not need an `m05-freeze` team)
- Name M02 PR-#13 shepherd in `decisions.yml`
- Fill `formal/OWNERS.md` primary + backup (M03 close blocker, not Wave 1)
- Provision 2× c7a.4xlarge spot + c7i.2xlarge bench runners
- Provision Cloudflare R2 bucket for sccache
- Approve OWNERS.toml + freezes.yml + tickets/ pre-flight PR

Orchestrator:
- Initialize `EXECUTION-STATE.json` + `EXECUTION-LOG.ndjson`
- Generate CODEOWNERS from OWNERS.toml
- Configure GitHub branch ruleset on `main` with restricted file paths
  (frozen kernel + load-bearing files) and required status checks
  (`m05-freeze-guard`, owner-guard variants)
- Install `Cargo.lock` merge driver
- Run `cargo fmt --all -- --check && cargo clippy --workspace -- -D warnings &&
  cargo test --workspace` baseline; record `WAVE_0_HEAD` sha

### Wave 1a kickoff

Orchestrator schedules in this order:
1. Wave-opener lock-bump PRs (M09 → M03 → M01) through sequencer queue
2. M01 P1 + M01 P2 + M03 P1 + M09 P1 + M09 P2 ticket cohort
3. Executor agents spawn in parallel up to whatever Claude Code permits in
   one thread, bounded by the dependency DAG and shared_paths collisions;
   per-ticket reviewers fan out as branches push

When PR #13 merges, scheduler unblocks Wave 1b; M02 P1 + M01 P3 + M03 P2/P3 +
M09 P3 join.

### Wave 1 close

Orchestrator runs Wave 1 gate. On pass: merge `wave-1-integration` to `main`,
recompute frontier, advance to Wave 2a.

### Subsequent waves

Same pattern. Wave 2b interleaves M05 + M06 sub-waves with M05's freeze
window enforced via three-lock protocol. Wave 3 starts when M01 ProvenanceStamp
sha + M03 capability-invariants sha are both in `main`. Wave 4 starts when
M06 P1 namespace placeholder + M07 P1 traffic source both in `main`.

---

## 16. Open user prerequisites (before kickoff)

| # | Action | Owner | Blocks |
|---|--------|-------|--------|
| 1 | Approve OWNERS.toml + freezes.yml + tickets/ pre-flight PR | user | all |
| 2 | (deprecated; single-owner trajectory) | n/a | not blocking |
| 3 | Name PR #13 shepherd (single-owner: implicitly `@bb-connor`; lock `decisions.yml` row in an amendment) | user | M02 P1 start (Wave 1b) |
| 4 | `formal/OWNERS.md` (single-owner: `@bb-connor`) | user | M03 close (not Wave 1) |
| 5 | (deprecated: Tier A self-hosted runners) | n/a | not blocking; in-session execution |
| 6 | (deprecated: Tier C bench runner) | n/a | not blocking; bench runs in-session, host fingerprint recorded |
| 7 | (deprecated: Cloudflare R2 bucket) | n/a | not blocking; local sccache only |
| 8 | Confirm 2,000 GHA runner-min/month budget for ClusterFuzzLite (public-repo free tier; already locked in `decisions.yml`) | user | M02 P2 start |

---

## 17. Cross-references

- Genesis: 7-agent debate (worktree, orchestration, ownership, granularity,
  review, CI, failure modes), 2026-04-25
- Trajectory index: `.planning/trajectory/README.md`
- Cold-reader findings: `.planning/trajectory/COLD-READER-NOTES.md`
- Per-milestone planning: `.planning/trajectory/0{1..9}-*.md`,
  `.planning/trajectory/10-*.md`
- House rules: `CLAUDE.md`, `AGENTS.md`
- Spec: `spec/PROTOCOL.md`

This board is the canonical operational doc. Any drift between this and a
milestone doc is reconciled by editing both in the same PR.
