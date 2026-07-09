# FV-E3: A PR-time formal smoke tier

Status: Proposed (2026-07-09)
Theme: E - Verify the verification, and make lanes bite
Effort: S
Depends on: none (highest-priority wiring fix in the theme)
Feeds: [FV-E5](FV-E5-lane-ratchets.md) (posture promotion of every lane created here), [FV-A4](FV-A4-mirror-drift-hashes.md) (PR-cheap drift checks slot into the same workflow), [FV-E1](FV-E1-spec-mutation-testing.md)
Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md) (G1), `.github/workflows/README.md`, [FV-E4](FV-E4-fuzz-plumbing-repair.md), [FV-B4](FV-B4-loom-registry-and-dst.md)

## Summary

Nothing proof-shaped runs on pull requests today (gap G1): the comment in `nightly.yml` near line 69 references a "kani-public-pr in ci.yml" job that exists nowhere; `mutants.yml` triggers only on schedule and dispatch so its `mutants-pr` job (gated on `github.event_name == 'pull_request'`) can never fire; and no workflow path-triggers on `formal/lean4/**`, so a PR editing Lean proofs merges without a `lake build`. The only PR-time formal gates are the path-scoped Apalache safety workflow and the diff-tests crate inside the required workspace test lane. This document specifies a new path-scoped workflow, `.github/workflows/formal-pr-smoke.yml`, with three jobs (Lean build, the Kani lanes.pr sweep, and an honestly labeled rust-verification metadata check), plus a decision to revive the dead mutants-pr job, plus the stale-comment fixes that must land in the same change. Everything starts advisory-adjacent (not branch-protection required); promotion sequencing is deferred to [FV-E5](FV-E5-lane-ratchets.md).

## Motivation and evidence

All verified this session:

- `nightly.yml:67-70` describes a two-tier split ("The PR job (kani-public-pr in ci.yml) only runs `lanes.pr`; nightly runs everything") whose PR half does not exist in any workflow file.
- `formal/rust-verification/kani-public-harnesses.toml:59-82` defines `lanes.pr` with all 20 kernel-core public harnesses and notes (lines 51-53) the full sweep is ~2.2 minutes locally, "within the 6-minute PR budget". `lanes.nightly_only` is empty (lines 84-86). The lane was designed for PRs and runs only at 04:23 UTC.
- `.kani/harnesses.toml:5-6` says each entry pins a pair "the CI `kani-public-pr` job iterates", and line 14 says `lane = "pr"` "Always runs on every PR and on push-to-main". Both statements are false today.
- `mutants.yml:41-51` has `on: schedule` + `workflow_dispatch` only; its own comment (lines 42-45) admits the `mutants-pr` job "stays inert". The file header (line 1) still says "cargo-mutants required lane", and `docs/fuzzing/mutants.md` describes mutants-pr as "triggered on PR".
- `scripts/check-formal-proofs.sh` (lake build + sorry scan + manifest cross-ref) runs only via `scripts/ci-workspace.sh:12`, which release qualification invokes on push-to-main, and effectively nightly through the formal-qualification job's proof report. A Lean-only PR gets zero feedback.
- Consequence (G1): a PR can break any proof, harness, or registry and the breakage surfaces the next morning or at release qualification, after the author has moved on.

## Current state

- PR-tier CI is intentionally fast and Linux-only per the `ci.yml` header (lines 12-20), which explicitly lists the proof report and Kani lanes as living elsewhere. Required check contexts are "Build, lint, test", "MSRV build and test", "cargo-vet (locked supply-chain audit)", "cargo-deny (supply-chain bans/advisories/licenses)" (`ci.yml:6-10`); rulesets match by the `name:` field.
- Path-scoped PR formal gates that DO exist: `apalache-safety.yml` (paths at lines 7-14, 6 specs at `--length=6`) and `cargo test --workspace` covering `chio-formal-diff-tests` inside the required check job (`ci.yml:173-177`).
- Nightly has everything needed to copy: sha-pinned elan install with cache (`nightly.yml:183-227`), pinned kani install (`nightly.yml:98-105`, `CHIO_KANI_VERSION: 0.67.0` at line 21), the lanes.pr harness loop (lines 107-140), and the multi-crate manifest runner `scripts/run-kani-manifest.sh` (supports `--lane pr`, `--exclude-crate`, `--list`).
- Full Creusot install is a git clone + opam + `./INSTALL` (`nightly.yml:277-286`); the metadata-only escape hatch `CHIO_RUST_VERIFICATION_METADATA_ONLY=1` reduces `scripts/check-rust-verification-gates.sh` to schema/coverage-declaration checks (lines 43-46 of that script).

## Design

### New workflow vs additions to ci.yml

Recommendation: a new `.github/workflows/formal-pr-smoke.yml`. Reasons: (a) the required "Build, lint, test" context is a monolith matched by name; folding formal steps into it would make every PR pay the toolchain cost and would couple formal breakage to the workspace gate before the lanes have a track record; (b) these jobs are path-scoped, and `apalache-safety.yml` is the established precedent for a path-scoped PR formal workflow; (c) separate jobs give separate check names, which FV-E5 promotes independently. The workflow triggers on `pull_request` with per-job path conditions, plus `workflow_dispatch` for manual runs.

Path-scoping caveat that the design must own: a branch-protection-required check that never reports (because paths did not match) blocks the PR as "Expected". While the lanes are advisory this does not matter, and pure `paths:` triggers are fine. At promotion time (FV-E5), the promoted job switches to the run-always-and-self-skip pattern: trigger on all PRs, first step computes whether relevant paths changed (`git diff --name-only` against the merge base, same technique as `cflite_pr.yml:117-126`), and heavy steps condition on that output so the job still reports success cheaply on unrelated PRs. This is recorded here so promotion is a posture flip, not a redesign.

Workflow skeleton (top matter; per-job detail in the subsections below):

```yaml
name: formal-pr-smoke
on:
  pull_request:
    paths:
      - "formal/lean4/**"
      - "formal/proof-manifest.toml"
      - "formal/theorem-inventory.json"
      - "formal/assumptions.toml"
      - "formal/rust-verification/**"
      - "crates/kernel/chio-kernel-core/src/**"
      - "crates/core/chio-core-types/src/**"
      - ".kani/harnesses.toml"
      - "scripts/check-formal-proofs.sh"
      - "scripts/run-kani-manifest.sh"
      - ".github/workflows/formal-pr-smoke.yml"
  workflow_dispatch:
permissions:
  contents: read
concurrency:
  group: formal-pr-smoke-${{ github.ref }}
  cancel-in-progress: true
env:
  # Must stay in lockstep with .github/workflows/nightly.yml (and vice versa).
  CHIO_KANI_VERSION: 0.67.0
  CHIO_ELAN_VERSION: v4.2.1
  CHIO_ELAN_TARBALL_SHA256: 4e717523217af592fa2d7b9c479410a31816c065d66ccbf0c2149337cfec0f5c
```

Workflow-level `paths:` is the union; each job additionally guards on its own path subset via a changed-files step so a Lean-only PR does not pay for a Kani install (GitHub `paths:` filters exist only at workflow level for `pull_request`).

### Job (a): lean-build

- `name: lean-build (lake + sorry scan + manifest cross-ref)`.
- Paths: `formal/lean4/**`, `formal/proof-manifest.toml`, `formal/theorem-inventory.json`, `formal/assumptions.toml`, `scripts/check-formal-proofs.sh`, `.github/workflows/formal-pr-smoke.yml`.
- Steps: checkout; elan install copied verbatim from `nightly.yml:183-227` (sha256-verified tarball `CHIO_ELAN_VERSION`/`CHIO_ELAN_TARBALL_SHA256`, `~/.elan` cache keyed on version + tarball sha + `hashFiles('formal/lean4/Chio/lean-toolchain')`); a second cache for `formal/lean4/Chio/.lake` keyed on the lean-toolchain hash plus lakefile/lake-manifest hashes, with a restore-key fallback so incremental builds survive source-only changes; then run `bash scripts/check-formal-proofs.sh` whole.
- Can the script run whole, or does it need a flag to skip the python cross-ref pass? Verified by reading it this session: it has no flags at all; it runs `lake build` (lines 13-17), the sorry scan with an rg-to-grep fallback (lines 19-34), and a stdlib-only python pass (lines 36-401; it even ships its own TOML-subset parser at lines 47-115 for hosts without tomllib). The python pass costs seconds and requires only `docs/reference/CLAIM_REGISTRY.md` to exist (line 399). No new flag is needed; run it whole.
- Runtime estimate (labeled estimate; measured in phase 1): 22 `.lean` modules, no mathlib. Cold: elan download + toolchain install 1-2 min, `lake build` 1-3 min, cross-ref seconds; total 4-6 min. Warm (both caches hit): 1-3 min total. The lean-toolchain pin is `v4.28.0-rc1`; the toolchain cache makes the rc pin a non-issue for runtime.

### Job (b): kani-pr

- `name: kani-public-pr (lanes.pr sweep)`. Deliberately resurrects the documented name so `nightly.yml`'s comment and `.kani/harnesses.toml`'s description become true again with minimal editing (both still get their file references corrected, see (e)).
- Paths: `crates/kernel/chio-kernel-core/src/**`, `crates/core/chio-core-types/src/**` (the lanes.pr harnesses witness `chio_core_types` symbols too, per `covered_symbols` in `kani-public-harnesses.toml:38-40`), `.kani/harnesses.toml`, `formal/rust-verification/kani-public-harnesses.toml`, `scripts/run-kani-manifest.sh`, `.github/workflows/formal-pr-smoke.yml`.
- Steps: checkout; rust toolchain; `cargo install kani-verifier --locked --version "${CHIO_KANI_VERSION}"` + `cargo kani setup` with `CHIO_KANI_VERSION` set to the same pinned value as `nightly.yml:21` (0.67.0) and a comment requiring the two stay in lockstep; then the same lanes.pr loop as `nightly.yml:113-140` but reading only `lanes.pr`; then optionally `bash scripts/run-kani-manifest.sh --lane pr --exclude-crate chio-kernel-core` for the other manifest crates (phase 2, once kernel-core timings are measured; those paths join the scope then).
- Caching (investigated options): cache `~/.cargo/bin/{kani,cargo-kani}` plus `~/.kani` (the `cargo kani setup` bundle) keyed on `CHIO_KANI_VERSION` + runner OS. `Swatinem/rust-cache` handles the target dir as in nightly. Realistic totals (estimates until measured): cold = kani-verifier compile 2-4 min + setup bundle download 1-2 min + sweep; warm = cache restore under 1 min + sweep. Sweep itself: ~2.2 min measured locally for all 20 harnesses [v], and `.kani/harnesses.toml:44-46` notes CI runner overhead is typically 2-3x with the heaviest harness ~31 s local, so budget 5-7 min for the CI sweep. Realistic warm total: 8-10 min; cold: 12-15 min.
- That exceeds the 6-minute figure the harness manifest advertises for the sweep alone; this is acceptable for a path-scoped job that fires only when kernel-core, core-types, or the harness registries change, and the manifest provides the documented relief valve: `lanes.nightly_only` exists precisely so the slowest concrete-fixture harnesses can be demoted if the lane creeps past ~10 minutes, with the toml's own note (lines 56-58) that this strictly reduces PR coverage, never nightly coverage.

### Job (c): rust-verification posture (Creusot)

Full Creusot on PR is not viable: the toolchain is built from a pinned git rev via opam (`nightly.yml:277-286`), tens of minutes of OCaml/why3 compilation with no cheap cross-run cache short of baking a container image. Recommendation:

- PR job `name: rust-verification-metadata (schema only, no proofs)` running `CHIO_RUST_VERIFICATION_METADATA_ONLY=1 bash scripts/check-rust-verification-gates.sh`. This is exactly the existing metadata mode (verifies the three lane TOMLs exist, schema-match, and declare coverage; `check-rust-verification-gates.sh:6-46`), costs seconds, and the job name says out loud that it proves nothing. Paths: `formal/rust-verification/**`, the script itself, this workflow.
- Strict Creusot/Kani core gates stay nightly in formal-qualification. The honesty backstop is [FV-E5](FV-E5-lane-ratchets.md), which makes the proof report record `mode = strict | metadata_only` so a metadata-only run can never satisfy the release claim rule. Without FV-E5 this job would be a fig leaf; with it, the split is honest: PR = registry shape, nightly = proofs, release = strict-mode report required.

### Job/decision (d): mutants-pr revival

Two defensible options were weighed:

- Delete the dead job and the header claim. Honest, but it discards working machinery: the gate script, survivor-issue budget, comment bot, and the whole `releases.toml` activation lifecycle (`releases.toml:44-59`) were built around a PR lane; deletion leaves the evidence-gated blocking flip with no enforcement point.
- Revive it (recommended): add a `pull_request` trigger to `mutants.yml` with `paths:` scoped to the six trust-boundary crates' `src/**` plus the mutation configs. `--in-diff` keeps the mutant set proportional to the diff (`mutants.yml:183-193` already implements it, including the diff-file capture). Budget: a typical PR generates 0-30 in-diff mutants; the dominant cost is the per-crate baseline build. Add a cheap first step per matrix job that skips the crate when the diff does not touch it (10 lines of `git diff --name-only | grep`), so untouched crates no-op in under a minute instead of building. Posture: the lane is ALREADY advisory by construction; `scripts/mutants-gate.sh` exits 0 while `cycle_end_tag` is empty and the nightly evidence streak is 0 (`releases.toml:68,85`), so no `continue-on-error` is added (the existing header comment at `mutants.yml:77-80` explains why it must stay absent). Infra failures will red a non-required check, which is the correct signal. Ratcheting to required is FV-E5's job. Per [FV-E4](FV-E4-fuzz-plumbing-repair.md) item 6, the revived job's budget step sets `GH_FUZZ_BUDGET_CAP_MODE: fail` explicitly: the block's own comment (`mutants.yml:139-141`), `docs/fuzzing/continuous.md`, and the contract test `scripts/tests/fuzz-budget-hard-halt.test.sh` all define PR budget gates as hard halts (the test rejects a warn setting in exactly this block), while today the step silently inherits the script's warn default.

### (e) Stale-comment fixes in the same change

These land in the same PR so the docs and reality converge exactly once:

1. `nightly.yml:67-70`: point the comment at `formal-pr-smoke.yml`'s kani-public-pr job (the job exists again; only the file reference "in ci.yml" is wrong).
2. `.kani/harnesses.toml:5-6` and `:14`: name the actual workflow file; "Always runs on every PR" becomes "runs on PRs touching the scoped paths via formal-pr-smoke.yml, and nightly".
3. `mutants.yml:1` header: "required lane" becomes "advisory lane, evidence-gated to blocking per releases.toml"; the `on:` comment at lines 42-45 is rewritten for the revived trigger; the hard-halt claim at lines 16-17 and 139-141 is aligned with the configured cap mode per FV-E4.
4. `docs/fuzzing/mutants.md` CI-lane section: matches the revived trigger and paths scope.
5. `docs/formal/GAP_ANALYSIS.md` G1: marked addressed with a pointer here (when the workflow lands, not when this document does).

### Runtime budget table

| Job | Fires on | Cold estimate | Warm estimate | Dominant cost |
| --- | --- | --- | --- | --- |
| lean-build | formal/lean4/**, proof registries | 4-6 min | 1-3 min | elan + lake build (cached) |
| kani-public-pr | kernel-core, core-types, kani registries | 12-15 min | 8-10 min | kani install (cached) + 20-harness sweep |
| rust-verification-metadata | formal/rust-verification/** | ~2 min | ~1 min | checkout + python |
| mutants-pr (revived) | six trust-boundary crates | 15-45 min/crate touched | same | baseline build + in-diff mutants |

All figures except the ~2.2 min local sweep [v] are estimates to be replaced with measured values in phase 3.

### Required-check names (for FV-E5 promotion)

GitHub rulesets match reported check names (`ci.yml:3-10`, `.github/workflows/README.md:18-27`). The names to register when promotion happens: `lean-build (lake + sorry scan + manifest cross-ref)`, `kani-public-pr (lanes.pr sweep)`, `rust-verification-metadata (schema only, no proofs)`, and per-crate `mutants-pr (<crate>)`. Promotion order and streak thresholds are defined in [FV-E5](FV-E5-lane-ratchets.md); nothing here touches branch protection.

## Implementation plan

1. Phase 1 - land `.github/workflows/formal-pr-smoke.yml` with jobs (a) and (c) (files to add: `.github/workflows/formal-pr-smoke.yml`; files to modify: none). Lean and metadata jobs first because they are cheap and dependency-free.
2. Phase 2 - add job (b) kani-public-pr to the same workflow; measure cold/warm timings on 3 real PRs; decide whether the multi-crate `run-kani-manifest.sh --lane pr` step joins now or waits (files to modify: `.github/workflows/formal-pr-smoke.yml`).
3. Phase 3 - revive mutants-pr (files to modify: `.github/workflows/mutants.yml`: add `pull_request` trigger with paths, add the per-crate diff-touch skip step, set `GH_FUZZ_BUDGET_CAP_MODE: fail` explicitly on the PR budget step per the hard-halt contract, [FV-E4](FV-E4-fuzz-plumbing-repair.md) item 6).
4. Phase 4 - stale-comment sweep in the same PR as phase 3 (files to modify: `.github/workflows/nightly.yml`, `.kani/harnesses.toml`, `.github/workflows/mutants.yml` header, `docs/fuzzing/mutants.md`, `docs/formal/GAP_ANALYSIS.md`).
5. Phase 5 - replace the estimate table above with measured numbers (files to modify: this document); hand off to [FV-E5](FV-E5-lane-ratchets.md) with `[gates.*]` entries for the new lanes.

## CI and gating changes

- New workflow `formal-pr-smoke.yml` (pull_request + workflow_dispatch), three jobs, none branch-protection required at introduction.
- `mutants.yml` gains a `pull_request` trigger; the job's advisory posture is unchanged (driven by `releases.toml` through `scripts/mutants-gate.sh`).
- Concurrency groups per job keyed on PR ref with `cancel-in-progress: true`, matching the `apalache-safety.yml` pattern (its lines 19-21), so force-pushes do not stack Kani runs.
- No change to the four existing required contexts. Promotion to required is exclusively via FV-E5's runbook (streak evidence, posture-flip PR, manual ruleset edit).
- Version pins: `CHIO_KANI_VERSION`, `CHIO_ELAN_VERSION`, `CHIO_ELAN_TARBALL_SHA256` duplicated from `nightly.yml` env with lockstep comments both ways (an FV-A4-style drift check on these pins is noted there).

## Acceptance criteria

- [ ] A PR touching only `formal/lean4/Chio/Chio/Core/Receipt.lean` triggers lean-build and fails if the proof does not compile or contains `sorry`.
- [ ] A PR touching `crates/kernel/chio-kernel-core/src/scope.rs` triggers kani-public-pr and runs exactly the 20 `lanes.pr` harnesses.
- [ ] A PR touching only docs triggers none of the new jobs.
- [ ] kani-public-pr warm runtime is at or under 10 minutes over 3 measured PRs, or a demotion of named harnesses to `lanes.nightly_only` is proposed with the measurements attached.
- [ ] `rust-verification-metadata` job name and log output state that no proofs run.
- [ ] mutants-pr fires on a PR touching a trust-boundary crate, posts its comment, and exits advisory-pass with the standard `mutants-gate:` line; untouched matrix crates no-op in under 1 minute.
- [ ] Zero remaining references to a nonexistent job: `grep -rn "kani-public-pr" .github/ .kani/` resolves every hit to the real job in `formal-pr-smoke.yml`.
- [ ] `mutants.yml` header no longer claims a required lane, and the mutants-pr budget step's hard-halt comment is backed by an explicit `GH_FUZZ_BUDGET_CAP_MODE: fail` (enforced by `scripts/tests/fuzz-budget-hard-halt.test.sh`).
- [ ] Pin lockstep: `grep CHIO_KANI_VERSION .github/workflows/*.yml` shows identical values with lockstep comments.

## Risks and mitigations

- Kani CI runtime lands well above the estimates. Mitigation: measured before promotion; `lanes.nightly_only` demotion path documented in the manifest itself; the job is path-scoped so the blast radius is kernel PRs only.
- Cache poisoning or stale kani bundles after a version bump. Mitigation: cache keys include `CHIO_KANI_VERSION` and the elan tarball sha; bumping the pin rolls the key.
- Path filters silently miss a file that can break proofs (e.g. a core-types type used by a harness moves crates). Mitigation: nightly still runs everything; [FV-A4](FV-A4-mirror-drift-hashes.md) hashes close the drift class; scope lists are reviewed whenever `covered_symbols` changes.
- Reviving mutants-pr annoys contributors with a red non-required check on flaky infra. Mitigation: advisory posture plus the survivor comment makes failures actionable; if infra flake dominates, flip to `continue-on-error` temporarily with a dated TODO rather than deleting the trigger.
- Required-check "Expected" deadlock if someone marks a paths-triggered job required prematurely. Mitigation: the self-skip pattern is specified above and FV-E5's runbook makes it a promotion precondition.

## Open questions

- Should kani-public-pr also run on `push` to main (matching the old `.kani/harnesses.toml:14` claim) to catch merge-skew, or is nightly enough? Proposal: add push-to-main in phase 2 if the warm runtime is under 5 minutes; otherwise nightly suffices.
- Does the multi-crate `--lane pr` sweep (attest-verify 4, anchor 4, weights 4 harnesses) join kani-public-pr or become a fourth job with its own paths? Defer to phase 2 measurements.
- Container image with preinstalled Creusot to make a strict PR lane feasible eventually? Out of scope; revisit after FV-E5 lands mode recording and the demand is demonstrated.

## Manifest and registry updates

- `releases.toml`: no edits in this document's scope; FV-E5 adds `[gates.lean-build]`, `[gates.kani-public-pr]`, `[gates.rust-verification-metadata]` entries referencing the check names above.
- `.kani/harnesses.toml` and `formal/rust-verification/kani-public-harnesses.toml`: comment corrections only (phase 4); no lane membership changes.
- `.github/workflows/README.md`: add the new workflow to the required-check inventory section as "present, not yet required", so the ruleset documentation stays authoritative.
- `formal/OWNERS.md`: note the PR-tier obligation next to the existing nightly obligations.
