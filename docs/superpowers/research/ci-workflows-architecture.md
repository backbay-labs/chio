# CI Workflow Architecture Research: .github/workflows

Repository: `/Users/connor/Medica/backbay/standalone/arc` (Chio, formerly ARC)
Scope: GitHub Actions workflow sprawl, redundancy, and a first-principles redesign.
Constraint: read-only research. No code, scripts, workflows, or configs were modified.

## Executive summary

The repo has **73 workflow files** under `.github/workflows/` plus a `README.md` and
no other supporting structure. There are **zero reusable workflows** (`workflow_call`)
and **zero composite actions** (`.github/actions/` does not exist) despite 51 of the 73
workflows redundantly re-declaring the same Rust toolchain setup (checkout +
`dtolnay/rust-toolchain` + `Swatinem/rust-cache`). The setup boilerplate is copied,
not shared.

The single largest cluster is **18 thin "one-script gate" workflows** (15 of them the
`chio-pheromone-*` family, plus `chio-treaty-bound-provenance`,
`chio-live-treaty-buyer-closure`, `chio-proof-package`), each a 33-60 line file whose
only real work is `run: bash scripts/check-<name>.sh`. The `README.md` in the workflows
directory explicitly defends keeping these as 15 separate files; that rationale is
real but addressable (see "Rebuttal" below).

Action SHA-pinning is excellent (only **1 unpinned action** across all 73 files:
`actions/setup-dotnet@v4`). Concurrency and least-privilege permissions are applied
inconsistently: **28 of 73** files lack a `concurrency:` block and **6** lack a
top-level `permissions:` block.

The net effect: a contributor opening a PR can trigger 25-30 separate top-level checks,
each spinning up its own runner and rebuilding the Rust workspace, with no shared cache
strategy and no merge queue. This is the dominant CI cost and review-surface problem.

---

## 1. Full inventory

Legend for triggers: PR = pull_request, push = push, sched = schedule (cron),
disp = workflow_dispatch, run = workflow_run, rel = release.

### Core build / test / lint
| File | Name | Triggers | Purpose (jobs) |
| --- | --- | --- | --- |
| ci.yml | CI | push, PR | Primary gate: check, msrv, cargo-vet, cargo-deny, check-regression-tests |
| chio-runtime.yml | Chio Runtime | PR, push, disp | Runtime crate gate (matrix) |
| chio-arena-determinism.yml | chio-arena-determinism | PR, push | Determinism gate (arena-determinism) |
| chio-replay-gate.yml | chio-replay-gate | PR, push | Large gate: replay-gate, macos-smoke, seed-immutable, proptest, differential, cross-version |
| check-registries.yml | check-registries | push, PR | no-implementation-backed registry check |
| ttfrh.yml | ttfrh | PR, push | in-process-bench, container-lane (time-to-first-receipt-hash) |
| eval-receipt-bundle.yml | eval-receipt-bundle | PR, push | schema-lint on receipt bundles |

### Pheromone / per-feature single-script gates (the big cluster)
| File | Name | Triggers | Purpose |
| --- | --- | --- | --- |
| chio-pheromone-relay.yml | Chio Pheromone Relay | PR, push | one script gate (shape A) |
| chio-pheromone-relay-ops.yml | Chio Pheromone Relay Ops | PR, push | one script gate (shape A) |
| chio-pheromone-relay-observability.yml | ... Observability | PR, push | one script gate (shape B, node 22) |
| chio-pheromone-relay-alert-routing.yml | ... Alert Routing | PR, push | one script gate (shape C, node 24) |
| chio-pheromone-relay-alert-delivery.yml | ... Alert Delivery | PR, push | one script gate (shape C) |
| chio-pheromone-relay-alert-handoff.yml | ... Alert Handoff | PR, push | one script gate (shape C) |
| chio-pheromone-relay-alert-assurance.yml | ... Alert Assurance | PR, push | one script gate (shape C) |
| chio-pheromone-relay-alert-assurance-archive.yml | ... Archive | PR, push | one script gate (shape D) |
| chio-pheromone-relay-alert-assurance-archive-package.yml | ... Archive Package | PR, push | one script gate (shape D) |
| chio-pheromone-relay-alert-assurance-archive-hardening.yml | ... Archive Hardening | PR, push | one script gate (shape D) |
| chio-pheromone-relay-alert-assurance-export.yml | ... Export | PR, push | one script gate (shape D) |
| chio-pheromone-relay-alert-assurance-external-retention.yml | ... External Retention | PR, push | one script gate (shape D) |
| chio-pheromone-directory-lifecycle.yml | ... Directory Lifecycle | PR, push | one script gate (shape A) |
| chio-pheromone-runtime.yml | Chio Pheromone Runtime | PR, push | one script gate (shape A) |
| chio-pheromone-transit.yml | Chio Pheromone Transit | PR, push | one script gate (shape A) |
| chio-treaty-bound-provenance.yml | Chio Treaty-Bound Provenance | PR, push, disp | one script gate |
| chio-live-treaty-buyer-closure.yml | Chio Live Treaty Buyer Closure | PR, push, disp | one script gate |
| chio-proof-package.yml | Chio Proof Package | PR, push, sched, disp | one script gate |

### Formal / spec / conformance
| File | Name | Triggers | Purpose |
| --- | --- | --- | --- |
| apalache-safety.yml | apalache-safety | disp, sched, PR(paths) | TLA+ safety subset check |
| apalache-temporal.yml | apalache-temporal | disp, sched | TLA+ liveness (revocation-eventually-seen) |
| spec-drift.yml | spec-drift | push, PR | codegen-no-diff, header-stamp, vectors-byte-stable, schema-coverage, cross-lang-bytes |
| schema-breaking-change.yml | schema-breaking-change | PR | breaking-change advisory |
| audit-log-schema-lint.yml | audit-log-schema-lint | PR, push, disp | audit-log export schema lint |
| conformance-matrix.yml | conformance-matrix | PR, sched, disp | vectors-byte-stable, peer-lock, external-consumer-smoke |
| verdict-matrix.yml | verdict-matrix | PR, push, disp | rust-kernel, python-go-required, deployment-shape-smoke |
| provider-conformance.yml | Provider conformance | PR, push | openai/cross-provider/ollama replay fixtures |
| vectors-staleness.yml | vectors-staleness | sched, disp | vectors-freshness + notify |

### Security / supply chain / provenance
| File | Name | Triggers | Purpose |
| --- | --- | --- | --- |
| cargo-vet.yml | cargo-vet | disp, push, PR(paths) | supply-chain audit (also a job inside ci.yml) |
| cve-monitor.yml | CVE Monitor | disp, sched, PR | CVE monitoring |
| sbom.yml | SBOM | disp, push, sched, run | publish-sbom |
| slsa.yml | slsa | run | collect-digests, provenance (SLSA) |
| reproducible-build.yml | Reproducible Build | push, disp | builder-a, builder-b, reproducibility-gate |
| tuf-rebake.yml | tuf-rebake | sched, disp | TUF metadata rebake |
| transitive-surface.yml | Transitive Surface | push, PR | transitive dependency surface |
| threat-model-coverage.yml | threat-model-coverage | PR, push, disp | threat-model coverage gate |
| admin-override-audit.yml | admin-override-audit | PR(closed), disp | audit admin overrides |

### Fuzzing / mutation / property
| File | Name | Triggers | Purpose |
| --- | --- | --- | --- |
| fuzz.yml | fuzz | sched, disp | scheduled fuzz with budget |
| fuzz_corpus_sync.yml | fuzz_corpus_sync | sched, disp | corpus sync |
| fuzz_crash_triage.yml | fuzz-crash-triage | run | crash triage on fuzz completion |
| cflite_pr.yml | cflite_pr | PR(paths,labeled) | ClusterFuzzLite PR (opt-in `fuzz: full` label) |
| cflite_batch.yml | cflite_batch | sched, disp | ClusterFuzzLite nightly batch |
| mutants.yml | mutants | sched, disp | mutants-pr, mutants-nightly |
| mutants-banner.yml | mutants-banner | sched, disp | update README mutants banner |
| mutants-fuzz-cocoverage.yml | mutants-fuzz-cocoverage | sched, disp | co-coverage analysis |
| dudect.yml | dudect | sched, disp | constant-time measurement (measure, correlate) |

### Performance / benchmarks
| File | Name | Triggers | Purpose |
| --- | --- | --- | --- |
| bench-regression.yml | bench-regression | sched, disp | Criterion perf regression (nightly only) |
| sustained-p99-nightly.yml | sustained-p99-nightly | sched, disp | sustained p99 latency |
| browser-kernel-twiggy.yml | browser-kernel-twiggy | sched, disp | wasm bundle-size (twiggy) |

### SDK / per-language / packaging
| File | Name | Triggers | Purpose |
| --- | --- | --- | --- |
| jvm.yml | JVM SDK | push, PR | jvm-build |
| web-sdk.yml | web-sdk | push, PR | build-wasm, conformance, diff-tests |
| chio-cpp.yml | Chio C++ SDK | push, PR | cmake, conformance, hardening, packaging, guard-and-kernel, drogon |
| sdk-parity.yml | SDK Parity | disp, PR, push | cross-SDK parity |
| demo-pages.yml | demo-pages | push, disp | build + deploy demo pages |

### Release
| File | Name | Triggers | Purpose |
| --- | --- | --- | --- |
| release-binaries.yml | Release Binaries | push, disp | build, release, checksum-index, mutants-gate-flip (45 KB) |
| release-cpp.yml | Release C++ SDKs | push, disp | qualify, publish-conan, publish-vcpkg |
| release-npm.yml | Release npm | push, disp | plan, build, publish, release-attest (37 KB) |
| release-pypi.yml | Release PyPI | push, disp | plan, build, publish, release-attest |
| release-qualification.yml | Release Qualification | disp, push | qualify gate |
| release-tagged.yml | release-tagged | rel | append-compat-row on tagged release |

### TEE / images / infra
| File | Name | Triggers | Purpose |
| --- | --- | --- | --- |
| chio-tee-fips.yml | chio-tee-fips | PR, push, disp | FIPS smoke in TEE |
| chio-tee-image.yml | chio-tee-image | PR, push, disp | TEE image smoke |
| chio-tee-corpus-expire.yml | chio-tee-corpus-expire | sched, disp | TEE corpus expiry |
| sidecar-image.yml | Sidecar Image | push, disp | build-and-push sidecar image |

### Ops / monitoring
| File | Name | Triggers | Purpose |
| --- | --- | --- | --- |
| nightly.yml | nightly | sched, disp | proptest, kani-public, formal-qualification, coverage |
| healthcare-pilot-pagerduty-heartbeat.yml | ... heartbeat | sched, disp | PagerDuty heartbeat |

---

## 2. Redundancy clusters and sprawl

### 2.1 Setup boilerplate is copied, never shared (the root cause)
- **51 of 73** workflows reference the Rust toolchain (`dtolnay/rust-toolchain` /
  `Swatinem/rust-cache` / rustup).
- **29 of 73** use `Swatinem/rust-cache`.
- **Zero** reusable workflows (`workflow_call` appears in 0 files).
- **Zero** composite actions (`.github/actions/` does not exist).

Every one of those 51 files independently re-pins `actions/checkout`,
`dtolnay/rust-toolchain`, and (in 29 cases) `Swatinem/rust-cache`. Any SHA bump,
toolchain change, or cache-key policy change must be applied 50+ times by hand. This
is the textbook case for a `setup-rust` composite action.

### 2.2 The 18 thin single-script gates
18 files are <=60 lines and do nothing but check out, set up Rust (and sometimes Node),
and run one `scripts/check-*.sh`. 15 are the `chio-pheromone-*` family. Per the
directory `README.md`, the bodies fall into 4 near-identical "shapes" (A/B/C/D)
differing only in: presence of a `permissions: contents: read` block, presence of the
rust-cache step, presence of `setup-node`, and node version (22 vs 24). These
differences are exactly what `workflow_call` inputs or composite-action inputs exist to
parameterize.

### 2.3 Release family fragmentation (6 files)
`release-binaries` (45 KB), `release-npm` (37 KB), `release-pypi` (22 KB),
`release-cpp` (13 KB), `release-qualification`, `release-tagged`. All share the
plan/build/publish/attest skeleton (npm and pypi literally have identical job names:
plan, build, publish, release-attest). No shared release composite. Combined ~130 KB.

### 2.4 Fuzz family (5 files) and mutation family (3 files)
- Fuzz: `fuzz`, `fuzz_corpus_sync`, `fuzz_crash_triage`, `cflite_pr`, `cflite_batch`.
- Mutation: `mutants`, `mutants-banner`, `mutants-fuzz-cocoverage`.
All scheduled or workflow_run except `cflite_pr`. These are independent enough to keep
distinct, but they belong logically under a nightly umbrella, not as 8 top-level
entries.

### 2.5 Conformance/verdict overlap
`conformance-matrix`, `verdict-matrix`, `provider-conformance`, `vectors-staleness`,
and `web-sdk` all run a `vectors-byte-stable`-style conformance step. There is duplicated
conformance logic across at least 3 workflows.

### 2.6 Trigger / scheduling hygiene
- **Cron storm**: 24 distinct cron entries. Most are spread (good: `:17`, `:23`, `:37`,
  `:47` offsets to dodge the top-of-hour storm), but there is no single nightly
  orchestrator; each scheduled workflow is its own cold-start runner.
- **28 of 73** files have no `concurrency:` group (no auto-cancel of superseded PR runs):
  includes all 15 pheromone files, `release-*` (3), `slsa`, `ttfrh`, `web-sdk`,
  `provider-conformance`, `eval-receipt-bundle`, `admin-override-audit`,
  `audit-log-schema-lint`, `reproducible-build`, `healthcare-pilot-pagerduty-heartbeat`,
  `chio-cpp`.
- **6 of 73** files have no top-level `permissions:` block (token scope inherited):
  `chio-pheromone-directory-lifecycle`, `-relay-observability`, `-relay-ops`, `-relay`,
  `-runtime`, `-transit` (the shape-A/B pheromone files).

### 2.7 What is already good
- **Action pinning**: only 1 unpinned action repo-wide (`actions/setup-dotnet@v4` in a
  release workflow). Everything else is pinned to a 40-char SHA with a version comment.
- **Path filters**: most PR-triggered gates already carry `on.paths` scoping.
- **Matrices**: used in 10 files (chio-cpp, mutants, chio-runtime, fuzz, release-npm,
  web-sdk, dudect, mutants-fuzz-cocoverage, release-pypi, release-binaries).
- **Off-PR scheduling**: heavy lanes (bench, dudect, mutants, twiggy, fuzz) are
  correctly nightly/dispatch-only, not per-PR.

---

## 3. Current vs ideal gap

| Dimension | Current | Ideal (professional OSS Rust) |
| --- | --- | --- |
| Top-level entry workflows | ~73 (all flat) | 5-7 (pr, ci/merge, nightly, release, security, pages) |
| Reusable workflows | 0 | A handful (rust-build, conformance, release-artifact, script-gate) |
| Composite actions | 0 | 1-3 (setup-rust, setup-node, setup-toolchains) |
| Setup boilerplate | Copied across 51 files | One `setup-rust` composite, referenced everywhere |
| Concurrency cancel-in-progress | 45/73 | 100% of PR-triggered |
| Least-privilege permissions | 67/73 have a block; top-level default not set | `permissions: {}` at top, escalate per-job |
| Merge queue | None observed | `merge_group` trigger + required checks |
| Required-check surface | 25-30 separate top-level checks on a PR | One aggregate `ci-required` gate job |
| Nightly orchestration | ~18 independent scheduled workflows | 1 `nightly.yml` fan-out to reusable jobs |

The central gap is architectural: **flat sprawl with no composition layer**. The repo
has good hygiene at the leaf level (pinning, path filters) but no structural reuse, so
the file count and per-PR check count scale linearly with every new gate.

---

## 4. Proposed workflow architecture (first principles)

A professional OSS Rust project separates **entry workflows** (what triggers run)
from **reusable workflows** (what work happens) and **composite actions** (how the
environment is set up). Target layout:

```
.github/
  actions/
    setup-rust/action.yml         # checkout + toolchain + rust-cache (inputs: components, targets, cache-key)
    setup-node/action.yml         # node + npm ci (input: node-version)
  workflows/
    pr.yml                        # on: pull_request, merge_group  -> fan-out to reusable
    ci.yml                        # on: push to main               -> reusable build/test + post-merge gates
    nightly.yml                   # on: schedule + dispatch         -> fuzz/mutants/bench/formal fan-out
    release.yml                   # on: push tags / release         -> reusable per-artifact release jobs
    security.yml                  # on: schedule + dispatch + PR(paths) -> vet/deny/cve/sbom/slsa
    pages.yml                     # on: push main                   -> demo-pages + docs
    _rust-build.yml               # reusable (workflow_call): build/test/clippy/fmt matrix
    _script-gate.yml              # reusable (workflow_call): inputs script, node?, node-version, permissions
    _conformance.yml              # reusable (workflow_call): vectors-byte-stable + parity
    _release-artifact.yml         # reusable (workflow_call): plan/build/publish/attest, input registry
```

Design rules applied:
1. **Entry workflows are thin**. They declare triggers, `concurrency` with
   `cancel-in-progress: true`, top-level `permissions: {}`, and call reusable workflows.
2. **One composite `setup-rust`** replaces the 51 copies of checkout+toolchain+cache.
   SHA bumps and cache policy change in one place.
3. **`_script-gate.yml` reusable** absorbs the 18 thin gates. Inputs:
   `script` (path), `needs-node` (bool), `node-version` (string), `permissions-contents`
   (string). The shape A/B/C/D differences from the README become 3-4 inputs.
4. **Path scoping is preserved** via a `paths-filter` (e.g. `dorny/paths-filter`) job in
   `pr.yml` that computes which gates are affected and conditionally dispatches the
   reusable gate. This solves the README's stated objection (a single `on:` block cannot
   express per-entry path filters) by moving path logic into a filter job, not the
   trigger.
5. **One aggregate required check.** A final `ci-required` job `needs:` all gate jobs and
   reports a single green/red. Branch protection requires only `ci-required`, so adding a
   gate never requires editing GitHub ruleset config.
6. **Merge queue.** Add `merge_group` to `pr.yml`/`ci.yml` triggers; heavy gates run once
   in the queue instead of on every push.
7. **Least privilege.** Top-level `permissions: {}`; each job opts into the minimum
   (`contents: read`, `id-token: write` only for SLSA/attestation jobs, etc.).
8. **Nightly fan-out.** `nightly.yml` calls `_rust-build`, fuzz, mutants, bench, formal,
   and conformance-staleness as reusable jobs with one `concurrency` group, eliminating
   ~18 independent scheduled cold starts.

### Rebuttal to the existing README's "keep 15 separate" rationale
The directory `README.md` declines consolidation for 4 reasons. Each is answerable
within this design without weakening fail-closed posture:
- *Per-entry path filters*: solved by a `paths-filter` job in `pr.yml`, not by the trigger.
- *Differing permissions (A/B inherit, C/D pin `contents: read`)*: make the gate's
  permission an explicit input and set every gate to `contents: read` (tightening, never
  loosening - consistent with fail-closed). No gate needs more than read.
- *Node version split (22 vs 24)*: make it an explicit `node-version` input; the split
  becomes visible and intentional in the caller, resolving the "stale drift vs deliberate"
  ambiguity the README flags.
- *Required-check name stability*: the aggregate `ci-required` job removes dependence on
  individual job names in branch protection, so renaming/restructuring gates is safe.

The README is correct that this is a behavior-bearing change requiring live Actions
verification - that caveat should carry into the migration plan, not block the design.

---

## 5. Per-workflow migration mapping

Destinations: KEEP-AS-REUSABLE (becomes/stays a `workflow_call` building block),
MERGE-INTO (folded into a named entry/reusable workflow), COMPOSITE (its setup
boilerplate moves to a composite action), NIGHTLY (moves under nightly orchestration),
KEEP (stays a distinct entry workflow). All Rust-toolchain users additionally adopt the
`setup-rust` composite.

| Current file | Destination |
| --- | --- |
| ci.yml | Becomes `ci.yml` + `_rust-build.yml` reusable (check/msrv/vet/deny/regression) |
| chio-runtime.yml | MERGE-INTO `_rust-build.yml` matrix job |
| chio-arena-determinism.yml | MERGE-INTO pr.yml as a reusable-gate call |
| chio-replay-gate.yml | KEEP as reusable `_replay-gate.yml`, called from pr.yml |
| check-registries.yml | MERGE-INTO `_script-gate.yml` |
| ttfrh.yml | MERGE-INTO pr.yml gate (in-process) + NIGHTLY (container-lane) |
| eval-receipt-bundle.yml | MERGE-INTO `_script-gate.yml` |
| chio-pheromone-relay*.yml (15) | MERGE-INTO `_script-gate.yml`, dispatched by paths-filter |
| chio-treaty-bound-provenance.yml | MERGE-INTO `_script-gate.yml` |
| chio-live-treaty-buyer-closure.yml | MERGE-INTO `_script-gate.yml` |
| chio-proof-package.yml | MERGE-INTO `_script-gate.yml` (PR) + NIGHTLY (sched) |
| apalache-safety.yml / apalache-temporal.yml | MERGE-INTO `security.yml`/NIGHTLY (formal) |
| spec-drift.yml | KEEP as reusable `_conformance.yml` job, called from pr.yml |
| schema-breaking-change.yml | MERGE-INTO pr.yml (PR-only advisory gate) |
| audit-log-schema-lint.yml | MERGE-INTO `_script-gate.yml` |
| conformance-matrix.yml | KEEP as `_conformance.yml` reusable (called PR + nightly) |
| verdict-matrix.yml | MERGE-INTO `_conformance.yml` |
| provider-conformance.yml | MERGE-INTO `_conformance.yml` |
| vectors-staleness.yml | NIGHTLY (staleness) |
| cargo-vet.yml | MERGE-INTO `security.yml` (already duplicated as a ci.yml job) |
| cve-monitor.yml | MERGE-INTO `security.yml` |
| sbom.yml | MERGE-INTO `security.yml` / release.yml |
| slsa.yml | MERGE-INTO release.yml (provenance job, id-token: write) |
| reproducible-build.yml | KEEP reusable `_reproducible-build.yml`, called by release + nightly |
| tuf-rebake.yml | NIGHTLY (scheduled rebake) |
| transitive-surface.yml | MERGE-INTO `security.yml` |
| threat-model-coverage.yml | MERGE-INTO `security.yml` / pr.yml gate |
| admin-override-audit.yml | KEEP (distinct PR-closed trigger; tighten permissions) |
| fuzz.yml | NIGHTLY (reusable `_fuzz.yml`) |
| fuzz_corpus_sync.yml | NIGHTLY |
| fuzz_crash_triage.yml | KEEP (workflow_run-triggered off fuzz) |
| cflite_pr.yml | KEEP (PR opt-in label gate) |
| cflite_batch.yml | NIGHTLY |
| mutants.yml | NIGHTLY (+ mutants-pr path may move to pr.yml gate) |
| mutants-banner.yml | NIGHTLY |
| mutants-fuzz-cocoverage.yml | NIGHTLY |
| dudect.yml | NIGHTLY |
| bench-regression.yml | NIGHTLY |
| sustained-p99-nightly.yml | NIGHTLY |
| browser-kernel-twiggy.yml | NIGHTLY |
| jvm.yml | KEEP reusable `_sdk-jvm.yml` (called from pr.yml on paths) + COMPOSITE |
| web-sdk.yml | KEEP reusable `_sdk-web.yml` (build-wasm/conformance/diff) |
| chio-cpp.yml | KEEP reusable `_sdk-cpp.yml` (6 jobs; called from pr.yml on paths) |
| sdk-parity.yml | MERGE-INTO `_conformance.yml` or `_sdk-*` umbrella |
| demo-pages.yml | MERGE-INTO `pages.yml` |
| release-binaries.yml | MERGE-INTO release.yml via `_release-artifact.yml` (binaries) |
| release-cpp.yml | MERGE-INTO release.yml via `_release-artifact.yml` (conan/vcpkg) |
| release-npm.yml | MERGE-INTO release.yml via `_release-artifact.yml` (registry=npm) |
| release-pypi.yml | MERGE-INTO release.yml via `_release-artifact.yml` (registry=pypi) |
| release-qualification.yml | MERGE-INTO release.yml (qualify gate before publish) |
| release-tagged.yml | MERGE-INTO release.yml (release-triggered compat-row append) |
| chio-tee-fips.yml | MERGE-INTO `_script-gate.yml` or `_tee.yml` reusable |
| chio-tee-image.yml | MERGE-INTO `_tee.yml` reusable |
| chio-tee-corpus-expire.yml | NIGHTLY |
| sidecar-image.yml | KEEP reusable `_image.yml` (called from release/pages) |
| nightly.yml | Becomes the `nightly.yml` orchestrator (fan-out to all NIGHTLY-mapped) |
| healthcare-pilot-pagerduty-heartbeat.yml | NIGHTLY (ops heartbeat) |

### Resulting top-level shape
After migration, the directory holds roughly:
- 6 entry workflows: `pr.yml`, `ci.yml`, `nightly.yml`, `release.yml`, `security.yml`, `pages.yml`
- ~8-10 reusable workflows: `_rust-build`, `_script-gate`, `_conformance`, `_replay-gate`,
  `_reproducible-build`, `_fuzz`, `_release-artifact`, `_sdk-jvm/_sdk-web/_sdk-cpp`, `_tee`, `_image`
- 2-3 composite actions: `setup-rust`, `setup-node`

That is roughly 18-20 files down from 73, with the per-PR required-check surface
collapsed to a single `ci-required` aggregate.

---

## 6. GitHub Actions best-practice checklist for this repo

- [x] Pin all third-party actions to 40-char SHAs (already 72/73; fix `setup-dotnet@v4`).
- [ ] Extract `setup-rust` composite action (eliminates 51 copies of toolchain setup).
- [ ] Introduce `workflow_call` reusable workflows for build, conformance, script-gate, release.
- [ ] Add `concurrency` with `cancel-in-progress: true` to all PR-triggered workflows
      (28 currently missing).
- [ ] Set top-level `permissions: {}` and escalate per-job; add blocks to the 6 missing files.
- [ ] Add `merge_group` trigger and a merge queue; require a single aggregate check.
- [ ] Replace per-entry path triggers in the gate cluster with a `paths-filter` dispatch job.
- [ ] Consolidate ~18 scheduled workflows under one `nightly.yml` fan-out.
- [ ] Keep heavy lanes (fuzz, mutants, dudect, bench, twiggy) off the PR path (already done).
- [ ] Add `id-token: write` only to provenance/attestation jobs (SLSA, SBOM, release-attest).

## 7. Caveats for whoever executes this

- The directory `README.md` documents a deliberate decision to keep the pheromone files
  separate. The migration to `_script-gate.yml` is behavior-bearing (token scope, node
  version, required-check names) and must be verified with GitHub Actions actually running
  on a branch, per the README's own guidance. Treat the 4 README objections as a
  verification checklist, not a blocker.
- Branch-protection / ruleset config lives in GitHub settings outside this repo. The
  aggregate `ci-required` strategy must be paired with a settings change, or required
  checks will break when individual job names disappear.
- `cargo-vet` runs both as a standalone workflow and as a job inside `ci.yml`; pick one
  home during consolidation to avoid double-running.
