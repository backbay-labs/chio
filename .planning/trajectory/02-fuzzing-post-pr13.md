# Milestone 02 - Post-PR-13 Fuzzing Trajectory

Owner: security/testing track. Status: planned. Anchors: PR #13 (production fuzz baseline), `RELEASE_AUDIT`, `QUALIFICATION`, `BOUNDED_OPERATIONAL_PROFILE`, `spec/PROTOCOL.md`.

Cross-doc references:

- M03 (proptest invariants) - kissing cousin of this milestone. Share fixture infrastructure (`tests/fixtures/`), seed generators, and any KAT vectors. A proptest counterexample should be promotable to a libFuzzer seed and vice versa.
- M05 (kernel async refactor) - the trust-boundary fuzz net specified here is the safety harness that lets M05 land without regressing the canonical-JSON / capability / receipt code paths. M05 must not start until phase 1 here is green.
- M06 (wasm-guards manifest) - this milestone fuzzes the wasm guard pre-instantiation validator and signed-sidecar verify path; M06 reuses the `chio-attest-verify` crate that lands in M09 (supply chain). Coordinate so the manifest fuzzer in phase 1 below covers the sigstore path before M06 adopts it; the fuzz target then reuses the same crate.

### M02 vs M03 oracle ownership (no overlap)

To prevent duplicated coverage with M03 (capability algebra properties), each oracle owns a distinct bug class:

| Bug class | Caught by | Owner doc |
|-----------|-----------|-----------|
| Decoder panic, unbounded allocation, slice OOB on adversarial bytes | libFuzzer + ASan harness | M02 (this doc) |
| Logical violation of capability subset, attenuation, deny-overrides on well-formed inputs | proptest invariant | M03 phase 1 |
| Bounded-input mathematical identity (intersection associativity, revocation idempotence) | Kani harness | M03 phase 2 |
| Concurrent-revocation safety / liveness | Apalache TLA+ | M03 phase 3 |
| Trust-boundary decode -> evaluator pipeline crash on adversarial bytes | libFuzzer harness that calls `evaluate(...)` after decoding | M02 (`mcp_envelope_decode`, `acp_envelope_decode` invoke evaluator post-decode) |
| Constant-time leak on signature/MAC compare | `dudect` harness | M02 phase 3 (this doc) |

Shared infrastructure (single source of truth):

- Generators: M03 owns reusable `Arbitrary` / `Strategy` impls in `formal/diff-tests/src/generators.rs`. M02 fuzz targets that need structured inputs (`capability_receipt`, `oid4vp_presentation`) consume those generators via `arbitrary::Arbitrary` adapters; M02 does not duplicate them.
- Seed promotion: an M03 proptest counterexample minimized to bytes lands in `fuzz/corpus/<target>/<sha>.bin` via `scripts/promote_fuzz_seed.sh`. An M02 libFuzzer crash whose root cause is an algebra bug (rather than a decode bug) opens a sibling proptest in M03 via the same script's `--mode proptest` flag.
- Cross-reference: any M02 fuzz target whose input shape exactly matches an M03 proptest invariant must cite the M03 invariant name in a `// algebra-oracle: <invariant_name>` comment so reviewers can confirm the proptest is the logical oracle and the fuzz target is only checking the decoder.

## PR #13 status (live)

As of this revision PR #13 ("test: harden production fuzzing baseline") is `state=OPEN` (`mergeable=MERGEABLE`, head `56836d3a`). It is the dependency that gates phase 0 of this milestone. If this milestone is picked up before PR #13 lands, phase 0 below absorbs the PR-#13 review-and-merge work; if PR #13 has already merged, phase 0 is complete and the milestone starts at phase 1.

The seven targets shipped by PR #13 are:

```
fuzz/fuzz_targets/canonical_json.rs
fuzz/fuzz_targets/capability_receipt.rs
fuzz/fuzz_targets/manifest_roundtrip.rs
fuzz/fuzz_targets/merkle_checkpoint.rs
fuzz/fuzz_targets/policy_parse_compile.rs
fuzz/fuzz_targets/sql_parser.rs
fuzz/fuzz_targets/tool_action.rs
```

with checked-in corpora under `fuzz/corpus/<target>/`, a smoke-on-PR + scheduled-matrix workflow at `.github/workflows/fuzz.yml`, plus fuzz-derived hardening already merged into `crates/chio-guards/src/shell_command.rs` and `crates/chio-policy/src/models.rs` (the YAML panic fix). Re-running these targets from the corpus must remain green for the lifetime of this milestone.

## Goal

Take the seven-target fuzz baseline and grow it into a sustained, coverage-guided assurance program: every untrusted-input boundary in Chio has a libFuzzer harness, runs continuously (OSS-Fuzz, ClusterFuzzLite, or self-hosted), is paired with mutation testing on the trust-boundary crates, has a constant-time-ness check on the few code paths that need it, and crashes flow automatically into tracked issues with seed-promotion regression tests guarding the fix.

## Why now

PR #13 covers kernel-internal serializer and parser surfaces but leaves the externally reachable trust boundaries unfuzzed. The same surfaces that PR #13 hardened (shell command obfuscation, YAML panic handling) suggest the unfuzzed crates carry equivalent latent bugs. Federation, credentials, and anchor-proof verification will gate `RELEASE_AUDIT` evidence; we cannot ship those release gates without harness coverage on their decoders. The kernel-async refactor in M05 needs this fuzz net underneath it before it lands.

## In scope

- New libFuzzer targets for every untrusted decode/parse boundary listed under "Code touchpoints".
- Continuous remote fuzzing (OSS-Fuzz upstream submission, or ClusterFuzzLite, or a self-hosted runner pool, decided in phase 1).
- Mutation-testing CI lane (`cargo-mutants`) gated on the trust-boundary crates with a concrete catch-ratio target.
- Long-running soak schedule (12h nightly, 72h weekly) with corpus minimization.
- Coverage-guided corpus growth: `cargo fuzz coverage` reports merged into the corpus, dead-seed pruning.
- Crash triage automation: artifact upload to issues, seed-to-test-case promotion script, CI guard preventing regression.
- `dudect`-style timing-leak harness for constant-time-required code paths (signature verify, MAC eq, capability scope subset check).

## Out of scope

- Formal verification, model checking, symbolic execution.
- Property testing migration (proptest stays where it lives; share fixtures with M03).
- Runtime ASan/UBSan in production binaries.
- The seven targets shipped in PR #13 (already covered).
- Cluster-side fuzzing of non-Chio code under `clusters/`.

## Success criteria (measurable)

- At least 11 additional `fuzz/fuzz_targets/*.rs` files merged: `jwt_vc_verify`, `oid4vp_presentation`, `did_resolve`, `anchor_bundle_verify`, `mcp_envelope_decode`, `a2a_envelope_decode`, `acp_envelope_decode`, `wasm_preinstantiate_validate`, `wit_host_call_boundary`, `chio_yaml_parse`, `openapi_ingest`, plus `receipt_log_replay` from (NEW) P1.T8 (target: 12; floor: 11).
- A documented continuous-fuzzing deployment running on the same cadence with build/run runbook checked into `docs/fuzzing/continuous.md`. The choice of OSS-Fuzz vs ClusterFuzzLite vs self-hosted is made in phase 1 (see "Continuous fuzzing decision" below).
- `cargo-mutants` 25.x CI lane reporting >= 80% mutant catch ratio on `chio-kernel-core`, `chio-policy`, `chio-guards`, `chio-credentials`. Lane is required for PR merge on those crates after the one-cycle advisory window.
- Nightly schedule: each fuzz target runs >= 30 min/target with ASan on Linux; weekly soak runs each target for 72h cumulative across the matrix.
- Crash-to-issue automation: any libFuzzer crash on the scheduled job opens (or updates) a GitHub issue with the minimized reproducer attached, labelled `fuzz-crash`, and the seed is auto-promoted into a regression test under the owning crate's `tests/regression_<sha>.rs` via a PR template. CI fails if any committed regression test ceases to exist.
- `dudect` harness reports `t < 4.5` (no leak signal) for capability MAC compare, JWT signature verify, and capability scope-subset check on a 1M-sample run.

## Continuous fuzzing decision (phase 1 deliverable)

Three viable paths. Pick one in phase 1 and document the rationale in `docs/fuzzing/continuous.md`. A fallback path is required.

| Option | Pros | Cons | Eligibility |
|--------|------|------|-------------|
| OSS-Fuzz (upstream) | Free CPU, reputable, integrates with sanitizer matrix, public crash-reporting. | Project must be open source AND accepted by the OSS-Fuzz maintainers; acceptance can take weeks; project must commit to triage SLOs. | `bb-connor/arc` is public, so eligibility-on-paper is satisfied; acceptance-in-practice is not guaranteed. |
| ClusterFuzzLite (GitHub Actions) | Runs on the existing GitHub Actions account (hosted or self-hosted runners), no upstream gating, reuses `fuzz.yml` infrastructure. | Burns hosted-runner minutes (or requires a self-hosted runner pool); no central crash dashboard, we own triage. | Always available. |
| Self-hosted libFuzzer fleet | Full control over CPU, sanitizer matrix, retention; can tune for our budget. | We own everything: provisioning, monitoring, security, on-call. | Always available; budget-dependent. |

Default decision: pursue OSS-Fuzz acceptance and stand up ClusterFuzzLite on hosted GitHub runners as the bridge until acceptance, then keep ClusterFuzzLite as the documented fallback. A self-hosted fleet is the escape hatch if hosted runner minutes blow the budget.

User decision required in phase 1: pick the primary path and ratify a CPU-minute budget cap.

## Mutation-testing approach (phase 3 deliverable)

- Tooling: `cargo-mutants` 25.x. Pin the version in CI (`cargo install cargo-mutants --version '~25'`) and in `docs/fuzzing/mutants.md`. Re-pin once 26.x stabilizes; do not float.
- Scope (in priority order):
  - `chio-kernel-core` (capability validation, guard pipeline, receipt signing).
  - `chio-policy` (HushSpec parse/compile, evaluator).
  - `chio-guards` (native guard set including `ShellCommandGuard`).
  - `chio-credentials` (JWT VC verify, OID4VP, SD-JWT).
- Out of scope for the lane (skip-list): pure plumbing (logging, `Display` impls, error `From` conversions), generated code, pure data structs without behavior.
- Catch-ratio target: >= 80% mutants caught per crate. Advisory for one release cycle, blocking thereafter.
- Runtime budget: cargo-mutants is slow. Estimate 2-6 hours per crate per full sweep on a hosted-runner-class CPU. Lane therefore runs nightly on a self-hosted or scheduled runner, never on every PR. PR-level lane runs only the mutants generated against changed files (`--in-diff`).
- Determinism gating: the lane requires `cargo test` to be green and deterministic on the target crate. Flaky tests are quarantined with `#[ignore]` and tracked.

## Timing-leak (`dudect`) harness (phase 3 deliverable)

- Tooling: `dudect-bencher` crate (latest 0.x); dedicated nightly runner pinned to a quiet host; require two consecutive sub-threshold runs before declaring pass.
- Target functions:
  - JWT/Ed25519 signature verify in `chio-credentials` (`verify_chio_passport_jwt_vc_json`, `verify_chio_passport_sd_jwt_vc`).
  - Capability MAC equality compare in `chio-kernel-core` / `chio-core` (constant-time receipt MAC check).
  - Capability scope subset check (the policy boolean evaluator path used by capability validation).
- Layout: `crates/chio-credentials/tests/dudect/` and `crates/chio-kernel-core/tests/dudect/`, gated behind a `dudect` feature so they do not run on every `cargo test`.
- Pass criterion: `t < 4.5` on a 1M-sample run, two runs in a row.

## Phase breakdown

Each phase below names: an effort tag (S = 1-3 days, M = 4-8 days, L = 9-15 days), a day estimate, an exact first-commit (conventional message + files touched), an atomic task list `Pn.Tn`, and a single named exit test (file path + symbol). The exit test is the authoritative pass/fail gate for the phase.

### Phase 0 - PR #13 baseline (S, 1-2 days)

Land/confirm the seven-target baseline from PR #13 (open as of this writing). Targets, corpora, CI smoke + scheduled matrix, and the `ShellCommandGuard` / `HushSpec::parse` hardening must all be in `main`. Nothing else in this milestone may regress what PR #13 ships. Promote any review feedback into PR #13 directly rather than starting phase 1 on top of an unmerged baseline.

First commit (only if PR #13 needs a follow-up):

- Subject: `test(fuzz): re-anchor seven-target baseline post-merge sanity`
- Files touched: `fuzz/fuzz_targets/*.rs` (no edits, sanity-only), `.github/workflows/fuzz.yml` (no edits), `docs/fuzzing/baseline.md` (new, 1 page).

Atomic tasks:

- P0.T1 - confirm PR #13 status `MERGED` via `gh pr view 13`; if not, no Phase 1 work begins.
- P0.T2 - run all seven targets locally for 60s each from their corpora; record clean exit in `docs/fuzzing/baseline.md`.
- P0.T3 - confirm scheduled `fuzz.yml` matrix ran green at least once on `main` after merge.

Exit test: workflow run `.github/workflows/fuzz.yml` job `fuzz-smoke` green on first `main` commit after merge. The seven `fuzz/corpus/<target>/` directories must each have at least one seed.

### Phase 1 - Trust-boundary harness expansion (L, 10-15 days)

Add 11 new fuzz targets in this order: credentials (`jwt_vc_verify`, `oid4vp_presentation`, `did_resolve`), anchors (`anchor_bundle_verify`), wire envelopes (`mcp_envelope_decode`, `a2a_envelope_decode`, `acp_envelope_decode`), wasm guard pre-instantiation (`wasm_preinstantiate_validate`, `wit_host_call_boundary`), config and ingest (`chio_yaml_parse`, `openapi_ingest`). Each target ships with at least 8 hand-curated seeds plus replay tests for any panic found during initial runs (mirroring the PR #13 pattern). Update `fuzz.yml` matrix to include the new targets in the scheduled job. Continuous-fuzzing path is locked (OSS-Fuzz primary, ClusterFuzzLite bridge per `.planning/trajectory/README.md` decision 2); Phase 1 only documents and stages, Phase 2 deploys.

First commit:

- Subject: `feat(fuzz): add jwt_vc_verify libFuzzer target with curated seed corpus`
- Files touched: `fuzz/fuzz_targets/jwt_vc_verify.rs` (new), `fuzz/Cargo.toml` (add `chio-credentials = { path = "../crates/chio-credentials", features = ["fuzz"] }`), `fuzz/corpus/jwt_vc_verify/00_minimal_jwt.bin` ... `07_revoked_lifecycle.bin` (eight seeds), `crates/chio-credentials/Cargo.toml` (add `fuzz = []` feature), `crates/chio-credentials/src/lib.rs` (`pub mod fuzz` shim under `#[cfg(feature = "fuzz")]`), `.github/workflows/fuzz.yml` (extend matrix with `jwt_vc_verify`).

Atomic tasks:

- P1.T1 - credentials family: `jwt_vc_verify`, `oid4vp_presentation`, `did_resolve`. One target per commit; each commit follows the first-commit shape above with the family-appropriate crate.
- P1.T2 - anchor family: `anchor_bundle_verify`.
- P1.T3 - wire-envelope family: `mcp_envelope_decode`, `a2a_envelope_decode`, `acp_envelope_decode`. Each fans out per-envelope-type via `arbitrary::Arbitrary` selector.
- P1.T4 - wasm-guards family: `wasm_preinstantiate_validate`, `wit_host_call_boundary`. Coordinate signed-sidecar surface with M06 owner (do NOT fork sigstore-rs invocation; reuse `chio-attest-verify` once M09 lands it; until then, gate the signed-module branch behind `#[cfg(feature = "attest_verify")]`).
- P1.T5 - config / ingest: `chio_yaml_parse`, `openapi_ingest`.
- P1.T6 - extend `.github/workflows/fuzz.yml` matrix to include all 11 new targets in the scheduled job; PR-smoke lane stays at the PR #13 profile.
- P1.T7 - write `docs/fuzzing/continuous.md` capturing the locked OSS-Fuzz-primary / ClusterFuzzLite-bridge decision, the 2,000 GHA runner-min/month budget cap, the escape hatch, and the cross-reference to Phase 2 deployment steps.

Exit test: scheduled run of `.github/workflows/fuzz.yml` job `fuzz-scheduled` reports `passed=18` (7 baseline + 11 new) on the first nightly after the last Phase-1 commit. The named test that proves a target is wired correctly is the per-target `<target>_smoke` cargo test under `fuzz/tests/smoke.rs` (new in P1.T1) which runs each target for 1s on its corpus and asserts no panic.

### Phase 2 - Continuous fuzzing fleet (M, 6-9 days)

Execute the locked decision: submit OSS-Fuzz `project.yaml` and stand up ClusterFuzzLite on hosted GitHub Actions as the bridge / fallback. Land the corpus-sync job that pulls minimized corpora back into the repo weekly, gated on a maintainer review.

First commit:

- Subject: `feat(fuzz): add ClusterFuzzLite continuous workflow with 2000-min/month cap`
- Files touched: `.github/workflows/cflite_pr.yml` (new), `.github/workflows/cflite_batch.yml` (new), `.github/workflows/cflite_cron.yml` (new), `.clusterfuzzlite/Dockerfile` (new), `.clusterfuzzlite/build.sh` (new), `.clusterfuzzlite/project.yaml` (new), `docs/fuzzing/continuous.md` (extend Phase-1 stub with operational runbook).

Atomic tasks:

- P2.T1 - ClusterFuzzLite bridge live (see "ClusterFuzzLite implementation" section).
- P2.T2 - OSS-Fuzz application (see "OSS-Fuzz application steps" section); track acceptance in a Phase-2 issue.
- P2.T3 - corpus-sync workflow `.github/workflows/fuzz_corpus_sync.yml` (new): weekly cron, opens a PR titled `chore(fuzz): sync minimized corpus <date>` with `gitleaks` scan output attached, requires manual maintainer approval before merge.
- P2.T4 - upstream-dep skip-list at `fuzz/upstream_skips.toml` with sunset dates; CI lane that fails Phase-2 corpus-sync PRs if any skip is past sunset.
- P2.T5 - on OSS-Fuzz acceptance, repoint the bug-tracker integration; ClusterFuzzLite stays on as documented fallback per decision 2.

Exit test: ClusterFuzzLite workflow `.github/workflows/cflite_batch.yml` succeeds on its first scheduled run AND the runner-minute total across `cflite_pr.yml` + `cflite_batch.yml` + `cflite_cron.yml` over the trailing 30-day window stays below the 2,000-minute cap (asserted by `scripts/check-fuzz-budget.sh`, new). OSS-Fuzz acceptance is NOT a Phase-2 exit gate (acceptance lag is a known risk, mitigated by ClusterFuzzLite bridge); acceptance closes the Phase-2 follow-up issue but does not block downstream phases.

### Phase 3 - Mutation testing and timing harness (M, 7-10 days)

Add the `cargo-mutants` lane per the scoped plan above. Land the `dudect` harness per the scoped plan above. Both lanes run on a dedicated nightly runner; neither blocks PRs in the first cycle (advisory window, decision 12).

First commit:

- Subject: `feat(ci): add cargo-mutants advisory lane for chio-kernel-core`
- Files touched: `.cargo/mutants.toml` (new, workspace-level config), `crates/chio-kernel-core/mutants.toml` (new, per-crate skip list), `.github/workflows/mutants.yml` (new), `scripts/mutants-comment.sh` (new), `docs/fuzzing/mutants.md` (new).

Atomic tasks:

- P3.T1 - workspace `cargo-mutants` config + per-crate skip lists for `chio-kernel-core`, `chio-policy`, `chio-guards`, `chio-credentials`.
- P3.T2 - `.github/workflows/mutants.yml` with two jobs: `mutants-pr` (`--in-diff` only, advisory) and `mutants-nightly` (full sweep on the four crates).
- P3.T3 - `scripts/mutants-comment.sh` (post-job): parses `mutants.out/outcomes.json`, posts a PR comment in the format defined under "Mutation-testing CI shape".
- P3.T4 - threshold-enforcement logic in `.github/workflows/mutants.yml`: reads `CHIO_MUTANTS_GATE` env var (`advisory` until cycle ends, then `blocking`); the env var flips automatically once `releases.toml` records the next post-Phase-3 release tag (see "Mutation-testing CI shape").
- P3.T5 - `dudect` harness scaffolding: `crates/chio-credentials/tests/dudect/jwt_verify.rs`, `crates/chio-kernel-core/tests/dudect/mac_eq.rs`, `crates/chio-kernel-core/tests/dudect/scope_subset.rs`, all gated behind `dudect` feature.
- P3.T6 - `.github/workflows/dudect.yml` nightly schedule, two-consecutive-run pass rule, fail on `t >= 4.5`.

Exit test: nightly workflow `.github/workflows/mutants.yml` job `mutants-nightly` posts a `mutants.out/outcomes.json` with `caught_ratio >= 0.80` on each of the four crates AND `.github/workflows/dudect.yml` records `t < 4.5` on two consecutive nightlies for each of the three target functions (`verify_chio_passport_jwt_vc_json`, capability MAC eq, scope-subset check).

### Phase 4 - Triage and corpus operations (S, 3-5 days, runs concurrent with phases 2-3)

Crash-to-issue GitHub Action, seed-promotion script, regression-test guard, triage runbook.

First commit:

- Subject: `feat(fuzz): add crash-to-issue automation and seed promotion script`
- Files touched: `.github/workflows/fuzz_crash_triage.yml` (new), `.github/ISSUE_TEMPLATE/fuzz_crash.yml` (new), `scripts/promote_fuzz_seed.sh` (new), `scripts/check-regression-tests.sh` (new), `CODEOWNERS` (new at repo root, with `tests/regression_*.rs @bb-connor` line and `crates/*/tests/regression_*.rs @bb-connor`), `docs/fuzzing/triage.md` (new).

Atomic tasks:

- P4.T1 - crash-to-issue Action (see "Crash-triage automation" section).
- P4.T2 - `scripts/promote_fuzz_seed.sh` with `--mode {libfuzzer,proptest}` (proptest mode opens a sibling M03 invariant under `crates/<owner>/tests/property_*.rs`).
- P4.T3 - `scripts/check-regression-tests.sh` invoked from `.github/workflows/ci.yml` to fail the build if any committed `tests/regression_<sha>.rs` is deleted.
- P4.T4 - `CODEOWNERS` line gating regression-test deletions (deletion requires `@bb-connor` review).
- P4.T5 - `docs/fuzzing/triage.md` runbook (severity bands, dedupe-by-input-hash, time-to-fix SLOs).

Exit test: a synthetic test crash injected via `scripts/inject-fake-crash.sh` (new, dev-only) opens a GitHub issue tagged `fuzz-crash`, attaches a minimized reproducer, and the named workflow run `.github/workflows/fuzz_crash_triage.yml` exits 0. The regression-test-deletion guard is verified by `tests/ci_guards/regression_deletion_test.sh` (new) which simulates a deletion and asserts the CI guard fails.

## OSS-Fuzz application steps (Phase 2)

Implementation checklist. Submit at the start of Phase 2; ClusterFuzzLite stays the bridge until acceptance lands.

1. Fork `google/oss-fuzz` to `bb-connor/oss-fuzz`. Branch: `add-chio`.
2. Create `projects/chio/project.yaml` with:

   ```yaml
   homepage: "https://github.com/bb-connor/arc"
   language: rust
   primary_contact: "whelan.connor11@gmail.com"
   auto_ccs:
     - "whelan.connor11@gmail.com"
   main_repo: "https://github.com/bb-connor/arc.git"
   sanitizers:
     - address
     - undefined
     - memory
   architectures:
     - x86_64
   fuzzing_engines:
     - libfuzzer
   help_url: "https://github.com/bb-connor/arc/blob/main/docs/fuzzing/triage.md"
   ```

3. Create `projects/chio/Dockerfile`:

   ```dockerfile
   FROM gcr.io/oss-fuzz-base/base-builder-rust
   RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev
   RUN git clone --depth 1 https://github.com/bb-connor/arc.git $SRC/chio
   WORKDIR $SRC/chio
   COPY build.sh $SRC/build.sh
   ```

4. Create `projects/chio/build.sh` (delegates to in-tree `fuzz/Cargo.toml`):

   ```bash
   #!/usr/bin/env bash
   set -euxo pipefail
   cd "$SRC/chio"
   cargo +nightly fuzz build --release
   for tgt in $(ls fuzz/fuzz_targets | sed 's/.rs$//'); do
     cp "fuzz/target/x86_64-unknown-linux-gnu/release/${tgt}" "$OUT/${tgt}"
     if [ -d "fuzz/corpus/${tgt}" ]; then
       (cd "fuzz/corpus/${tgt}" && zip -r "$OUT/${tgt}_seed_corpus.zip" .)
     fi
   done
   ```

5. Sanitizer matrix: `address` and `undefined` are required for acceptance; `memory` is best-effort (Rust + MSan is fragile, document failures rather than block).
6. Project metadata: `criticality_score` self-rating: `medium` (security-critical kernel for AI agent tool access, pre-1.0). License: same as upstream `bb-connor/arc` (verify before submission).
7. Contact: `whelan.connor11@gmail.com` listed as `primary_contact` and in `auto_ccs`. Add a second backup contact before submission (TBD-backup; track in Phase 2 issue).
8. Open the OSS-Fuzz integration PR using the `bb-connor/oss-fuzz` fork. Track acceptance in a milestone-tagged issue; expected lag 2-6 weeks.
9. While waiting, ClusterFuzzLite carries continuous coverage. On acceptance, repoint the bug-tracker integration in `.clusterfuzzlite/project.yaml` to OSS-Fuzz (set `report_to_oss_fuzz: true`) but keep ClusterFuzzLite running as the documented fallback.
10. Triage SLO commitment to OSS-Fuzz upstream: 24h acknowledgement, 7d fix-or-defer for `Critical`, 30d for `High`. Documented in `docs/fuzzing/triage.md`.

## ClusterFuzzLite implementation (Phase 2)

Three workflow files, fixed schedule, fixed duration cap, GCS-equivalent corpus storage, GitHub Issues bug-tracker.

**Hosting model**: All fuzz lanes run on GitHub Actions hosted runners (no self-hosted, no Tier A spot pool). The 2,000 min/month public-repo free tier is the hard ceiling; `scripts/check-fuzz-budget.sh` self-caps at 1,800 min/30d to leave headroom for other workflows. OSS-Fuzz post-acceptance is the route to sustained continuous fuzzing without burning the GHA cap.

- `.github/workflows/cflite_pr.yml` - **PR smoke (GHA hosted)**. PR-triggered. **Default mode: changed-target sampling.** Per `fuzz/target-map.toml` (committed at Wave 0), each fuzz target maps to a set of source-path globs; the workflow runs only the targets whose globs intersect the PR diff (bounded by `min_targets: 1`, `max_targets: 6` per PR; if no target maps a changed path, the workflow runs the canonical-JSON smoke target as a sanity check). Each selected target runs for 120s; concurrency-cancel on push; storage in GitHub Actions artifacts. Empirical sizing (typical PRs touch 2-3 targets): ~3 targets x 120s x ~50 PRs/month = ~300 min/month, comfortably under the 900 min/month PR-fuzz slice of the 1,800 min/30d cap. **All-target mode** (18 targets x 120s = 36 min/PR) is opt-in via PR label `fuzz: full` for release-cut PRs and trust-boundary edits; under the cap this allows ~25 all-target runs/month. If the trailing-30d sum exceeds 1,800 min minus the 900 min nightly slice = 900 min for PR fuzzing, `scripts/check-fuzz-budget.sh` refuses to enable `fuzz: full` until the next 30-day window and surfaces the cap-hit through the orchestrator halt-and-ping channel.
- `.github/workflows/cflite_batch.yml` - **sampled nightly (GHA hosted)**. Scheduled `cron: '0 4 * * *'`. Runs ONE rotated target per night (full sweep over an 18-day rotation) for `fuzz-seconds: 1800` (30 min). Uploads minimized corpus and crashes. Monthly: 1 target x 30 min x 30 days = 900 runner-min.
- `.github/workflows/cflite_cron.yml` - **deleted**. The trajectory's earlier "weekly soak on Tier A" plan is dropped along with Tier A; OSS-Fuzz is the post-acceptance soak path.
- **OSS-Fuzz lane** (best-effort, free, post-acceptance): `infra/oss-fuzz/` directory with the `project.yaml`, `Dockerfile`, and `build.sh` per OSS-Fuzz integration docs. Submit application `https://github.com/google/oss-fuzz/blob/master/docs/getting-started/new-project-guide.md` early in M02 P2; acceptance lead time is typically 2-6 weeks, so OSS-Fuzz is treated as a future bonus, not a load-bearing path. While waiting, ClusterFuzzLite carries continuous coverage within the GHA cap.
- Duration cap enforcement: `scripts/check-fuzz-budget.sh` (new) is invoked from `cflite_pr.yml` and `cflite_batch.yml` post-run, queries `gh run list --workflow cflite_*.yml --created '>30d ago' --json durationMs` and fails the workflow (and disables itself by setting a repo variable consumed by the next run) if cumulative GHA-hosted fuzz minutes exceed **1,800 in the trailing 30-day window**. Headroom: 200 min/month before the public-repo 2,000 min cap.
- Corpus-storage backend: GitHub Storage (ClusterFuzzLite default `storage-repo`) using a sibling repo `bb-connor/arc-fuzz-corpus` (new, private). NOT GCS: keeping everything in the GitHub control plane avoids new cloud-billing surfaces and keeps the budget cap legible. The corpus repo is referenced from `.clusterfuzzlite/project.yaml` `storage-repo` field.
- Bug-tracker integration: GitHub Issues on `bb-connor/arc` with label `fuzz-crash` (set via `report-issues: true` and `report-ooms: false` in `cflite_batch.yml`). Pre-OSS-Fuzz acceptance, this is the only crash sink. Post-acceptance, OSS-Fuzz also files; we accept the dedupe burden as part of running both lanes.

## Mutation-testing CI shape (Phase 3)

- Pinned tool: `cargo-mutants` 25.x. Install line in `mutants.yml`: `cargo install cargo-mutants --version '~25' --locked`.
- Workspace config: `.cargo/mutants.toml` with global `additional_cargo_test_args = ["--workspace", "--exclude", "chio-cpp-kernel-ffi"]`, `timeout_multiplier = 3.0`, `minimum_test_timeout = 60`.
- Per-crate skip lists: `crates/chio-kernel-core/mutants.toml`, `crates/chio-policy/mutants.toml`, `crates/chio-guards/mutants.toml`, `crates/chio-credentials/mutants.toml`. Each lists `examine_globs` (the trust-boundary modules) and `exclude_globs` (logging, `Display`, generated code, pure data structs).
- Workflow: `.github/workflows/mutants.yml` with two jobs:
  - `mutants-pr`: triggered on PR, runs `cargo mutants --in-diff "$GIT_DIFF" --no-shuffle --jobs 4` against the changed-files set, posts a comment via `scripts/mutants-comment.sh`. Always advisory.
  - `mutants-nightly`: scheduled `cron: '0 5 * * *'` on a 4-hour budget per crate, runs full sweep, uploads `mutants.out/` as artifact, gates against the 80% threshold per crate per the env var below.
- Comment-bot output format (`scripts/mutants-comment.sh`):

  ```
  ### cargo-mutants advisory report

  | Crate | Mutants | Caught | Missed | Timeout | Catch ratio |
  |-------|---------|--------|--------|---------|-------------|
  | chio-kernel-core | 142 | 121 | 18 | 3 | 85.2% |

  Top 5 missed mutants:
  1. crates/chio-kernel-core/src/normalized.rs:142 - `replace > with >=`
  ...

  Mode: advisory | Threshold: 80% | Cycle: pre-release-X (advisory)
  ```

- Threshold-enforcement logic for "advisory now / blocking after one release cycle" (decision 12):
  - Source of truth: `releases.toml` at repo root (new, written by Phase 3 first commit), with two keys: `phase3_merge_tag = "vX.Y.Z"` and `cycle_end_tag = ""` (filled in by the next release tag after Phase 3).
  - `.github/workflows/mutants.yml` reads `releases.toml` via `scripts/mutants-gate.sh`. If `cycle_end_tag` is empty, gate is `advisory` (workflow exits 0 even on miss). If `cycle_end_tag` is non-empty, gate is `blocking` (workflow exits 1 on miss).
  - Flip is automatic: a release-creation hook in `.github/workflows/release-binaries.yml` writes the new tag into `cycle_end_tag` once, in a single PR titled `chore(mutants): activate blocking gate after cycle <tag>`.
  - Override: a maintainer can re-enter advisory mode by clearing `cycle_end_tag` in a PR labelled `mutants-gate-override`; the override PR requires CODEOWNERS review on `releases.toml`.

## Crash-triage automation (Phase 4)

- Workflow: `.github/workflows/fuzz_crash_triage.yml` triggers on `workflow_run` of `fuzz.yml` and `cflite_*.yml` with conclusion `failure`.
- Steps: download crash artifact -> run `cargo fuzz tmin` to minimize -> compute sha256 of minimized input -> dedupe against open issues by sha256 substring match (idempotent) -> open or update GitHub issue.
- Issue template: `.github/ISSUE_TEMPLATE/fuzz_crash.yml` with required fields:
  - `target`: dropdown of the 18 fuzz target names.
  - `input_sha256`: text, prefilled by the workflow.
  - `minimized_reproducer`: file attachment (the crash bytes), <= 4 KiB or upload as gist.
  - `stack_trace`: code block, prefilled.
  - `severity`: dropdown `critical|high|medium|low` (per `docs/fuzzing/triage.md` bands; default `medium` for first-time triage).
  - `affected_crates`: checklist.
- Regression-test promotion path: `scripts/promote_fuzz_seed.sh <target> <input_path>` writes the input to `crates/<owner>/tests/regression_<input_sha8>.rs` as a `#[test]` that calls the same entry point the fuzz target wraps. The owning crate is determined by `fuzz/owners.toml` (new, maps target -> crate). The script also moves the seed into `fuzz/corpus/<target>/<sha>.bin` so the next fuzz run starts with it.
- CODEOWNERS gate that prevents deletion: `CODEOWNERS` (new file, repo root) lines:

  ```
  /crates/*/tests/regression_*.rs @bb-connor
  /tests/regression_*.rs @bb-connor
  /fuzz/corpus/** @bb-connor
  ```

  Combined with branch-protection rule on `main` requiring CODEOWNERS review for any path matching the above. Plus `scripts/check-regression-tests.sh` invoked from `.github/workflows/ci.yml` does an explicit `git diff --diff-filter=D` check against the merge base and fails if any regression test file disappeared without a paired issue link in the PR body.

## Observability (3-month milestone success measurement)

The milestone is "succeeding" three months after Phase 1 lands when the dashboard below shows movement on each metric. The dashboard is a single Markdown report `docs/fuzzing/dashboard.md` regenerated weekly by `.github/workflows/fuzz_dashboard.yml` (new, Phase 4 follow-up; not on the critical path) from the GitHub API + ClusterFuzzLite artifacts.

| Metric | Source | Healthy direction | 3-month target |
|--------|--------|-------------------|----------------|
| crashes-found-per-week | issues labelled `fuzz-crash` opened in trailing 7d | initially up (we should be finding bugs), then trending toward zero on already-fuzzed surfaces | At least 1 distinct crash found in the first month; trending toward 0/week on the original 18 targets by month 3. New targets from "NEW" tasks below should keep finding crashes. |
| distinct-coverage-edges | `cargo fuzz coverage` summary, summed across the 18 targets | strictly up | At least 30% growth over the Phase-1-merge baseline by month 3. |
| regression-test-count | `git ls-files 'crates/**/tests/regression_*.rs' \| wc -l` | strictly up | At least 1 regression test per `fuzz-crash` issue closed; floor of 5 by month 3. |
| mutants-caught-ratio (per crate) | `mutants.out/outcomes.json` from latest `mutants-nightly` | up, then stable >= 80% | All four crates >= 80% by month 3 (the blocking-gate prerequisite). |
| dudect-t-statistic (per function) | latest `dudect.yml` artifact | < 4.5, stable | Three target functions < 4.5 on every nightly for the trailing 30 days by month 3. |
| ClusterFuzzLite minutes used (trailing 30d) | `gh run list` aggregate | <= 2,000 | Strictly under cap every week; trip an issue if crossed. |

Dashboard render shape:

```
# Chio fuzz dashboard - regenerated <UTC date>

## crashes-found-per-week (trailing 12 weeks)
<sparkline>
## distinct-coverage-edges by target
<table>
## regression-test-count by crate
<table>
## mutants-caught-ratio by crate (advisory|blocking)
<table>
## dudect-t-statistic by function
<table>
## ClusterFuzzLite budget (trailing 30d)
<bar with cap line>
```

A monthly review meeting (or async write-up) consumes this dashboard. Two consecutive red months on any metric opens a milestone-revision issue.

## Sub-tasks added in Round 2 (NEW, M02-scope)

These three tasks are in scope for M02 but were not in the prior revision. Each is sized to land within the existing phase budget; see the per-phase atomic-task lists for placement.

- (NEW) P1.T8 - **`receipt_log_replay` fuzz target**. Today the receipt log is exercised by `merkle_checkpoint` (PR #13) which fuzzes the Merkle commitment shape but not the log-replay code path. Add a libFuzzer target that feeds an arbitrary append-only stream of `Receipt` bytes through the replay verifier (`chio-kernel-core::replay::verify_receipt_chain` or equivalent) and asserts no panic, no allocation > 16 MiB, and that the verifier returns either `Ok` or `Err` (not `unwrap` on a malformed prior-hash). This target catches a class of bug that `merkle_checkpoint` cannot: corrupted-or-reordered chains during recovery. Coordinates with M04 (deterministic replay) which consumes the same code path; the M04 fixtures double as fuzz seeds. Lifts the success-criteria target floor from 10 to 11 and the recommended count from 11 to 12.

- (NEW) P2.T6 - **structure-aware mutator for canonical-JSON inputs**. libFuzzer's bit-flip mutator wastes cycles on inputs that the canonical-JSON serializer rejects up front (RFC 8785 violations). Land a thin custom mutator (`fuzz/mutators/canonical_json.rs`) registered via `LLVMFuzzerCustomMutator` that round-trips through `chio-core::canonical_json::serialize` after each mutation, ensuring the input remains shape-valid. Wire it to the four targets that decode canonical JSON (`canonical_json`, `capability_receipt`, `manifest_roundtrip`, `mcp_envelope_decode`). Expected effect: >= 2x distinct-coverage-edges per CPU-second on those targets. Measure via the dashboard. Pre-empts a known M03 / M04 cross-doc question about whether shape-valid mutation is worth the engineering cost; this lane answers it inside M02.

- (NEW) P3.T7 - **mutation-testing co-coverage report against fuzz corpora**. cargo-mutants asks "did the test suite catch this mutant?". A natural extension: did the *fuzz corpus* catch it? Add a nightly `mutants-fuzz-cocoverage.yml` workflow that, for each of the four mutation-tested crates, replays the relevant fuzz corpus (via `cargo fuzz run <target> -- -runs=0` against the in-tree corpus) under each surviving mutant and re-classifies "missed by tests but caught by fuzz corpus" as a separate column in the dashboard. Expected effect: a 5-15% reduction in the missed-mutant count, an audit-ready cross-oracle story, and a concrete reason to keep the corpus checked in. Runs nightly only; out of scope for PR lane.

## Dependencies

- PR #13 merged into `main` (blocking phase 1).
- Stable `nightly-2026-04-24` toolchain pin (PR #13 uses it; do not drift without coordinating).
- GitHub Actions runner budget for nightly 30-min/target plus weekly 72h soak. May require a self-hosted runner if hosted minutes blow the budget.
- OSS-Fuzz repo eligibility (project must be public; `bb-connor/arc` is, so eligibility is satisfied; acceptance is not guaranteed).
- The boundary crates listed below already expose decode entry points (verified against current `main`); a thin `pub mod fuzz` shim behind a `fuzz` feature may still be needed to keep the harness layer out of the public API.

## Risks and mitigations

- *CI minutes blowout from soak runs.* Mitigation: soak runs go to a self-hosted or scheduled nightly runner, not on PRs. PR lane stays at the PR #13 smoke profile.
- *OSS-Fuzz rejection or long acceptance lag.* Mitigation: ClusterFuzzLite fallback is a first-class plan B with a documented runbook; phase 2 success does not require upstream acceptance.
- *Mutation-testing flake from non-deterministic tests.* Mitigation: gate the lane behind a deterministic test subset, mark known-flaky tests `#[ignore]` for the mutants run, track in a quarantine list.
- *False positives from `dudect` on noisy hosts.* Mitigation: pin the timing harness to a dedicated runner, require two consecutive runs above threshold before flagging.
- *Refactor churn on `lib.rs`-only crates.* Mitigation: introduce thin `pub mod fuzz` modules behind a `fuzz` feature flag; do not destabilize public APIs.
- *Crash-triage automation spam.* Mitigation: dedupe by minimized-input hash, rate-limit issue creation, require human label to escalate severity.
- *Corpus exfil (sensitive data).* Seeds may end up containing real-looking secrets, tokens, or PII (especially credentials and OpenAPI ingest). Mitigation: a corpus-intake review step (the maintainer-review gate on the weekly corpus-sync job), an `.gitleaks`-style scan in the corpus-promotion PR, and a written rule that no production-issued JWTs or DIDs can be seeded.
- *False-positive crashes from unstable upstream deps.* libFuzzer crashes inside transitive crates (e.g. a yanked YAML parser) waste triage cycles. Mitigation: pin all fuzz-target deps in `fuzz/Cargo.toml`, bisect any unexplained crash to its dep before filing as a Chio bug, maintain an upstream-bug skip list with sunset dates.
- *Fuzz-target rot during refactors.* When the underlying decode entry function is renamed or moved (likely during M05 kernel-async work) the fuzz target silently builds but no longer hits the intended boundary. Mitigation: add a `#[cfg(test)] fn smoke_target()` per target that asserts the target reaches a known sentinel; run that sentinel in the PR-smoke lane; review every fuzz-target diff in the same PR as the refactor that touches the underlying surface.

## Code touchpoints

Verified against current `main` in this revision; each entry includes the actual decode entry point that the harness will call.

- `fuzz/fuzz_targets/` (PR #13 directory; add 11 new targets here).
- `fuzz/Cargo.toml` (new dependencies on the boundary crates; PR #13's `Cargo.lock` is the baseline).
- `.github/workflows/fuzz.yml` (extend matrix; PR #13 is the baseline file).
- `crates/chio-credentials/src/portable_jwt_vc.rs` - entry: `pub fn verify_chio_passport_jwt_vc_json(...)` (line ~106).
- `crates/chio-credentials/src/oid4vp.rs` - entries: `pub fn verify_signed_oid4vp_request_object(...)` (line ~606), `pub fn verify_oid4vp_direct_post_response(...)` (line ~884), plus the `Deserialize` + `validate(&self)` pairs on the request/response structs.
- `crates/chio-credentials/src/presentation.rs` - entry: `pub fn verify_passport_presentation_response(...)` / `_with_policy` (lines ~37, ~45).
- `crates/chio-credentials/src/portable_sd_jwt.rs` - entry: `pub fn verify_chio_passport_sd_jwt_vc(...)` (line ~375).
- `crates/chio-did/src/lib.rs` - entry: `pub fn resolve_did_arc(value: &str, options: &ResolveOptions) -> Result<DidDocument, DidError>` (line ~246), plus `DidLikeUri::resolve_with_options`.
- `crates/chio-anchor/src/bundle.rs` - entries: `pub fn verify_proof_bundle(...)` (line ~46) and `pub fn verify_checkpoint_publication_records(...)` (line ~130). The `AnchorProofBundle` `Deserialize` derive is the upstream byte-to-struct boundary.
- `crates/chio-mcp-adapter/src/transport.rs` - decode boundary is the `serde::Deserialize` on the `JsonRpcRequest` / response types declared at the top of the file (the `pub fn spawn`/`shutdown` are I/O plumbing, not the fuzz target). Wrap with a `pub mod fuzz` shim that calls `serde_json::from_slice::<JsonRpcRequest>(data)`.
- `crates/chio-mcp-edge/src/runtime.rs` - entry: `McpEdge::handle_jsonrpc(&mut self, message: Value) -> Option<Value>` (line ~675). The fuzz harness will construct an edge with a stub transport and feed parsed JSON through this method.
- `crates/chio-a2a-adapter/src/protocol.rs` - decode boundary: the `Deserialize` derives on `A2aSendMessageRequest`, `A2aGetTaskRequest`, `A2aSubscribeToTaskRequest`, `A2aCancelTaskRequest`, `A2aTaskPushNotificationConfig`, `A2aMessage`, `A2aPart`, etc. Harness fans out one fuzz per envelope type then calls a verifier.
- `crates/chio-a2a-adapter/src/transport.rs` - private `parse_sse_stream(...)` (line ~1) is also in scope: feed it an arbitrary byte stream and assert it returns `Ok(Incomplete)` or `Ok(Complete)` without panicking. Re-export under the `fuzz` feature.
- `crates/chio-acp-edge/src/lib.rs` - entries: `ChioAcpEdge::handle_jsonrpc(...)` (line ~589) and `handle_jsonrpc_with_kernel(...)` (line ~779), plus the `Deserialize` derives on `AcpCapability`, `PermissionRequest`, etc.
- `crates/chio-wasm-guards/src/component.rs` - entry: `ComponentBackend::load_module(&mut self, wasm_bytes: &[u8], fuel_limit: u64)` (line ~79). Targets the wasm-bytes-to-instance boundary.
- `crates/chio-wasm-guards/src/manifest.rs` - entries: `pub fn load_manifest(wasm_path: &str)` (line ~118), `pub fn verify_wasm_hash(wasm_bytes, expected_hex)` (line ~138), `pub fn verify_abi_version(version)` (line ~153), `pub fn load_signature_sidecar(...)` (line ~212), `pub fn verify_signed_module(...)` (line ~258), `pub fn verify_guard_signature(...)` (line ~338). Coordinate with M06 / M09 sigstore-verify.
- `crates/chio-wasm-guards/src/abi.rs` - decode boundary: `Deserialize` derives on `GuardRequest` / `GuardVerdict` / related types. Fuzz with `serde_json::from_slice`.
- `crates/chio-config/src/loader.rs` - entries: `pub fn load_from_file(path: &Path)` (line ~18) and `pub fn load_from_str(yaml: &str)` (line ~26). The latter is the libFuzzer target.
- `crates/chio-config/src/schema.rs` - decode boundary: `Deserialize` derives on `ChioConfig` and friends. The `chio_yaml_parse` target wraps `loader::load_from_str` which exercises this.
- `crates/chio-openapi-mcp-bridge/src/lib.rs` - entry: `OpenApiMcpBridge::from_spec(spec_input: &str, config: BridgeConfig)` (line ~119). Also `from_parsed_spec` (line ~125) for a deeper-in-the-stack target if YAML/JSON parse swamps the fuzzer.
- `scripts/promote_fuzz_seed.sh` (new), `docs/fuzzing/{continuous.md, triage.md, mutants.md}` (new).
- `docs/README.md` index update.

## Open questions

- Do we need a fuzz target for `chio-store-sqlite` write paths, or does the existing `sql_parser` target plus property tests suffice? (Recommendation: defer to a follow-up milestone unless OSS-Fuzz finds a path in.)
- Should the mutation-testing catch ratio gate be advisory or blocking on first introduction? (Recommendation: advisory for one release cycle, blocking thereafter; matches "Mutation-testing approach" above.)
- Is there appetite to fuzz the C++ peer (`crates/chio-cpp-kernel-ffi`) via a separate libFuzzer harness in this milestone, or punt to a C++-specific milestone?
- Where does the `dudect` runner live - shared self-hosted CI host, or a dedicated bare-metal box? Affects budget and procurement timeline.
- Do we want to publish minimized corpora to a public S3-equivalent bucket for community contribution, or keep them in-repo only? (See the corpus-exfil risk.)
