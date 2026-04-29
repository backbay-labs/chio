# Milestone 02: Mutation Gate + Cross-SDK Verdict Differential

## Lens

Single lens: testing / quality. Two halves of one calibration question:
"are the tests we already have actually exerting the trust-boundary code,
and do the surfaces that re-implement those decisions in another language
agree on the answer?". Half A measures the dispatch-side test surface with
mutation kill rate. Half B measures the SDK-side parity with a semantic
verdict-tuple differential. Both halves protect trajectory-1's test
investment from rotting silently.

## Why this is on the trajectory

trajectory-1 M02 (`.planning/trajectory/02-fuzzing-post-pr13.md`) shipped 18
libFuzzer targets, ClusterFuzzLite, and the crash-triage automation
described under that doc's phases 1, 2, and 4. Phase 3 (the mutation lane
under "Mutation-testing approach", lines 97-108 of that file) was
explicitly deferred. Trajectory-1 M02.P3 deliberately staged the workspace
config (`.cargo/mutants.toml`), the per-crate skip-list scaffolding, and
the `mutants.yml` workflow shape, but the lane never flipped from advisory
to required and the catch-ratio was never measured against the >= 80%
target. The Quality Hawk review notes call this out as Wave-4 work that
never landed. M02 (this milestone) promotes that deferred work.

trajectory-1 M07 (`.planning/trajectory/07-provider-conformance.md`)
shipped provider-conformance fixtures at
`crates/chio-provider-conformance/fixtures/{anthropic,bedrock,openai}/`
plus the `M07.P4.T6` cross-provider verdict-equality oracle. That oracle
diffs across providers (OpenAI vs Anthropic vs Bedrock) but holds the
*kernel implementation* fixed. The cross-SDK axis (Rust vs Python vs TS
vs WASM browser kernel vs Go) is the second half this milestone closes.
The kernel logic lives in eight SDK trees under `sdks/` plus the WASM
browser kernel at `crates/chio-kernel-browser/`; today nothing CI-load-
bearing asserts that they agree on `(verdict, reason_code, scope_set)`
for the same scenario script.

## Prior-art reckoning

What trajectory-1 already shipped that overlaps with this milestone:

- **M02.P1+P2+P4 (libFuzzer + ClusterFuzzLite + crash triage)**: shipped.
  Preserved. This milestone does not touch the fuzz lane, the corpus, or
  the crash automation. The mutation lane reuses the per-crate mutants
  scaffold (`.cargo/mutants.toml`, per-crate `mutants.toml`) drafted in
  trajectory-1 M02.P3.
- **M03 (proptest invariants + 10 Kani harnesses + Apalache TLA+)**:
  shipped at `crates/chio-core-types/` and `crates/chio-kernel-core/`.
  Preserved. The Quality Hawk review on round-2 was explicit: do NOT
  widen the Kani surface. This milestone consumes Kani as backstop,
  never touches a `proofs/` directory.
- **M07.P4.T6 (cross-provider verdict equality)**: shipped. Reused.
  The `verdict_matrix` harness in Half B uses the same reason-code
  taxonomy the cross-provider oracle codified, but along an orthogonal
  axis (cross-SDK, fixed kernel) instead of (cross-provider, fixed
  kernel).
- **M01 (canonical-JSON RFC 8785 vectors)**: shipped at
  `crates/chio-conformance/tests/vectors_oracle.rs`. Reused as the
  byte-equality net underneath the new semantic-equality harness.
  trajectory-1 M01 covers byte equality of the on-wire receipt; this
  milestone covers semantic equality of the verdict tuple, which is
  weaker (allows cosmetic byte differences) and stronger (catches
  divergent reason codes that happen to canonicalize to identical
  bytes in degenerate cases).

What is *changed* (not preserved):

- The trajectory-1 M02.P3 advisory window expires. The mutation lane
  flips from advisory to required CI on PRs touching the trust-boundary
  set. Surviving mutants beyond a per-PR cap auto-file an issue.
- The trajectory-1 M02.P3 scope list (four crates: `chio-kernel-core`,
  `chio-policy`, `chio-guards`, `chio-credentials`) widens to six by
  adding `chio-attest-verify` (sigstore + manifest verify path) and
  `chio-anchor` (proof-bundle verify path). Both crates carry decisions
  that route fail-closed; both have substantial test surfaces but never
  had mutation calibration.

This milestone does NOT re-attack a v3.18-style bounded retreat. It is
straight promotion of a deferred phase plus a new orthogonal harness.

## Hard counts (measured 2026-04-29)

Reproduce with the commands in parentheses; update the date and numbers
on re-run.

- Trust-boundary crates and their existing test counts (cargo test
  binaries listed under `tests/`, exclusive of `proptest-regressions/`):
  - `crates/chio-policy/`: tests dir present, proptest regressions
    present. (`ls crates/chio-policy/tests/`)
  - `crates/chio-credentials/`: tests dir present, proptest regressions
    present.
  - `crates/chio-attest-verify/`: tests dir present, sigstore-root
    fixture present, build.rs present.
  - `crates/chio-kernel-core/`: tests dir present, proptest regressions
    present.
  - `crates/chio-guards/`: tests dir present.
  - `crates/chio-anchor/`: tests dir present.
- SDKs that drive a kernel (all under `sdks/` plus the in-tree WASM
  browser kernel): `sdks/rust/chio-guard-sdk`, `sdks/python/chio-sdk-python`,
  `sdks/typescript/packages/{ai-sdk,browser,deno,edge,elysia,express,
  fastify,node-http,workers}`, `sdks/typescript/packages/conformance`,
  `sdks/go/chio-go-http`, `sdks/go/chio-guard-sdk-go`,
  `sdks/jvm/`, `sdks/dotnet/`, `sdks/lambda/`, `sdks/k8s/`,
  `crates/chio-kernel-browser/`. The cross-SDK harness covers the
  five primary kernel implementations (Rust kernel, Python SDK,
  TypeScript node-http SDK, WASM browser kernel, Go HTTP SDK) in P5.
  (`ls sdks/`)
- Existing conformance crates:
  - `crates/chio-conformance/`: hosts the multi-language native suite
    runner; sources at `src/{lib.rs,load.rs,model.rs,native_suite.rs,
    peers.rs,report.rs,runner.rs}` plus `peers.lock.toml` and a
    `tests/conformance/{peers,scenarios}/` corpus. The verdict-matrix
    harness lives under this crate's `verdict_matrix/` subtree.
    (`ls crates/chio-conformance/`)
  - `crates/chio-provider-conformance/`: hosts the cross-provider
    fixtures the verdict differential reuses; fixtures at
    `fixtures/{anthropic,bedrock,openai}/`.
- trajectory-1 M02.P3 staged artifacts (verify with
  `git log --diff-filter=A --name-only -- '.cargo/mutants.toml'` and
  `git log --diff-filter=A --name-only -- '.github/workflows/mutants.yml'`):
  the `.cargo/mutants.toml` file and `.github/workflows/mutants.yml`
  workflow exist as advisory shells. Per-crate `mutants.toml`
  skip-list files exist under the four trajectory-1 crates. The
  comment-bot script `scripts/mutants-comment.sh` exists. None of
  these is currently load-bearing on a PR merge.

## Workspace dependency state

Pinned by trajectory-1 and reused (do not re-pin):

- `cargo-mutants` 25.x (already pinned in trajectory-1 M02.P3 install
  line: `cargo install cargo-mutants --version '~25' --locked`).

Not pinned anywhere; this milestone adds them and pins versions on the
day work opens (re-check crates.io / npm / PyPI for then-current latest
patch on Wave-1 open day):

- (Rust workspace, dev-only) `cargo-mutants` re-pin advisory, possibly
  to 26.x if 25.x reaches EOL by Wave 1 open. Re-pin lives in
  `.github/workflows/mutants.yml`, not `Cargo.toml`.
- (Python verdict-driver) `pytest`, `pyyaml`, `requests` (already in the
  Python SDK; reuse). No new pins.
- (TS verdict-driver) reuse the existing `sdks/typescript/packages/
  conformance` setup (vitest or jest already configured there). No new
  pins.
- (WASM browser kernel driver) reuse the
  `crates/chio-kernel-browser/` build and the existing `wasm-pack` /
  `wasm-bindgen` toolchain at the workspace level. No new pins.
- (Go verdict-driver) reuse `sdks/go/chio-go-http`'s existing test
  toolchain. No new pins.

## Scope

In:

- `cargo-mutants` 25.x lane required gate at >= 80% caught after one
  advisory cycle on the trust-boundary set: `chio-policy`,
  `chio-credentials`, `chio-attest-verify`, `chio-kernel-core`,
  `chio-guards`, `chio-anchor`.
- PR-comment surface listing surviving mutants. Auto-file an issue per
  surviving mutant beyond a per-PR cap (default 5).
- `mutants.toml` skip-with-rationale process for un-killable mutants
  (logging, `Display`, generated code, test-equivalent rewrites).
- Publish kill score in repo `README.md` headline ("Mutation kill: 84%,
  n=2,143"). Auto-updated by the nightly run via a maintainer-approved
  PR (no force-push to README).
- `crates/chio-conformance/verdict_matrix/` harness: scenario format
  spec, scenario corpus, Rust kernel driver, diff oracle that diffs
  `(verdict, reason_code, scope_set)` tuples cross-language, CI gate
  failing on any divergence.
- Per-SDK drivers (Python, TypeScript, WASM browser kernel, Go). Five
  drivers total (Rust kernel + four).
- Reuse trajectory-1 M01 canonical-JSON corpus and trajectory-1 M07
  fixtures from `crates/chio-provider-conformance/fixtures/` as input
  scenarios.
- Verdict-class taxonomy reuses M01 (trajectory-2) error codes; soft-dep
  reference, not blocking on M01 P0 landing first.

Out:

- Widening the Kani harness count or the Apalache TLA+ surface
  (Quality Hawk veto: do NOT widen Kani; trajectory-1 M03 covers the
  formal layer).
- Adding new libFuzzer targets (trajectory-1 M02.P1 covered the 18
  trust-boundary surfaces; this milestone is a different oracle class).
- `miri` on the kernel core, and a separate Miri + Shuttle FFI lane
  (Quality M15). Folded into the M06 perf-hardening CI as a future
  consideration; no Miri / Shuttle lane lands in M02.
- C++ peer kernel (`crates/chio-cpp-kernel-ffi`) inclusion in either
  half. Mutation lane explicitly excludes it via the trajectory-1
  `--workspace --exclude chio-cpp-kernel-ffi` config; verdict-matrix
  axis is held to the five primary kernels listed above.
- JVM, dotnet, lambda, k8s SDK drivers. Out-of-scope here per D07.
  D07 names M07 as the deferral target; the deferral is closed in
  M07.P6 (`tickets/M07/P6.yml`), which lands four deployment-shape
  drivers under
  `crates/chio-conformance/verdict_matrix/drivers/{jvm,dotnet,lambda,k8s}/`,
  registers them in the M02 P5.T6 hash-pinned manifest, and flips the
  extended workflow to required-CI. No M02 widening; the M07 P6 work
  consumes the M02 P5.T5 diff oracle without modifying it.
- Mutation-testing on adapter / edge crates (`chio-mcp-edge`,
  `chio-a2a-edge`, etc.). The trust-boundary set is the dispatch and
  verify path, not the wire layer.

## Phases

### P0: Wave-opener Cargo.lock bump and audit doc

Stage the workspace, open the audit doc, snapshot the trajectory-1
M02.P3 advisory state.

- M02.P0.T1: Open milestone audit doc and snapshot trajectory-1 M02.P3
  state.
- M02.P0.T2: Cargo.lock bump and `cargo-mutants` re-pin verification.

### P1: Mutation baseline and per-crate kill-score capture

Run `cargo-mutants` against each of the six trust-boundary crates,
record initial kill scores in `mutants-baseline.toml`, and inventory
the missed-mutant classes per crate.

- M02.P1.T1: Baseline run for `chio-policy`.
- M02.P1.T2: Baseline run for `chio-credentials`.
- M02.P1.T3: Baseline run for `chio-attest-verify`.
- M02.P1.T4: Baseline run for `chio-kernel-core`.
- M02.P1.T5: Baseline run for `chio-guards` and `chio-anchor` (combined).
- M02.P1.T6: Aggregate baseline into `mutants-baseline.toml` and the
  audit doc.

### P2: Targeted test work to raise kill rate to >= 80% per crate

One ticket per crate, each lists the targeted mutant classes pulled
from the P1 missed-mutant inventory.

- M02.P2.T1: `chio-policy` test additions to >= 80% kill.
- M02.P2.T2: `chio-credentials` test additions to >= 80% kill.
- M02.P2.T3: `chio-attest-verify` test additions to >= 80% kill.
- M02.P2.T4: `chio-kernel-core` test additions to >= 80% kill.
- M02.P2.T5: `chio-guards` test additions to >= 80% kill.
- M02.P2.T6: `chio-anchor` test additions to >= 80% kill.

### P3: Mutation gate flip, PR-comment workflow, README headline

Flip the lane from advisory to required, wire the PR comment, the
auto-issue path, and the README headline.

- M02.P3.T1: Required-CI flip in `.github/workflows/mutants.yml` for
  the six trust-boundary crates.
- M02.P3.T2: PR-comment surface listing surviving mutants.
- M02.P3.T3: Auto-file issue per surviving mutant beyond per-PR cap.
- M02.P3.T4: Skip-with-rationale process for un-killable mutants;
  per-crate `mutants.toml` rationale convention.
- M02.P3.T5: README headline kill-score banner with nightly auto-update
  PR workflow.

### P4: Verdict-matrix harness genesis (Rust kernel driver)

Land the harness scaffold, the scenario format spec, the Rust kernel
driver, and CI integration with a byte-pinned manifest.

- M02.P4.T1: `verdict_matrix/` harness scaffold and scenario format
  spec.
- M02.P4.T2: Scenario corpus genesis (capability subset, revocation
  propagation, replay verdict, redaction-determinism).
- M02.P4.T3: Rust kernel driver under `verdict_matrix/drivers/rust/`.
- M02.P4.T4: Diff oracle that diffs `(verdict, reason_code, scope_set)`
  tuples; hash-pinned `manifest.toml`.
- M02.P4.T5: CI integration; failing-on-divergence gate.

### P5: Per-SDK drivers and cross-language diff

One ticket per SDK driver plus the cross-language oracle that closes
the loop.

- M02.P5.T1: Python SDK driver under `verdict_matrix/drivers/python/`.
- M02.P5.T2: TypeScript SDK driver (node-http) under
  `verdict_matrix/drivers/typescript/`.
- M02.P5.T3: WASM browser kernel driver under
  `verdict_matrix/drivers/wasm-browser/`.
- M02.P5.T4: Go SDK driver under `verdict_matrix/drivers/go/`.
- M02.P5.T5: Cross-language diff oracle activation; required CI gate
  on any divergence.
- M02.P5.T6: Hash-pin the scenario corpus into `manifest.toml` and
  document the corpus-rotation process.

## Cross-milestone interactions

Hard deps (other trajectory-2 milestones):

- M01 (`urn:chio:error:*` registry at `spec/errors/registry.yaml`).
  The verdict-matrix oracle's `reason_code` field is a string drawn
  from that registry. The dependency is **soft** at the milestone
  level (M01 and M02 ship in Wave 1 in parallel) but **hard** at the
  ticket level for `M02.P4.T4` (diff oracle), which requires the
  registry to be queryable. Encoded in the ticket's `soft_deps` as
  a string sentence; the orchestrator gates `M02.P4.T4` on
  `M01.P1.T1`'s merged_sha via the wave-1 sync rule, not via a
  trajectory-2 `depends_on` edge.

Soft deps (trajectory-1 artifacts referenced as string sentences):

- "trajectory-1 M02.P3 staged the `.cargo/mutants.toml` and
  `.github/workflows/mutants.yml` shells; this milestone promotes them
  to required-gate status."
- "trajectory-1 M01 canonical-JSON RFC 8785 vectors at
  `crates/chio-conformance/tests/vectors_oracle.rs` are the byte-equality
  net under the new semantic-equality oracle."
- "trajectory-1 M07.P4.T6 (cross-provider verdict equality) is the
  reason-code taxonomy reference; cross-SDK axis is orthogonal."
- "trajectory-1 M07 fixtures at
  `crates/chio-provider-conformance/fixtures/{anthropic,bedrock,openai}/`
  feed the verdict-matrix scenario corpus."

Downstream consumers in trajectory-2:

- M05 (adversarial + escape + threat-model): adversarial suite cases
  must surface in the mutation kill rate (mutants survive only if
  adversarial coverage is missing) and in the verdict-matrix corpus.
- M07 (adoption beachhead): every new framework adapter (Vercel AI SDK,
  Next.js, MCP wrap) MUST pass the verdict-matrix harness as a
  pre-merge gate.
- M08 (chio-arena): the arena uses the verdict-matrix oracle as the
  referee for deterministic-replay disagreement detection.

## Risks and mitigations

- **Mutation runtime budget blowout.** `cargo-mutants` is slow (2-6
  hours per crate per full sweep on a hosted-runner-class CPU,
  trajectory-1 M02.P3 estimate). Six crates -> 12-36 CPU-hours per
  full sweep. Mitigation: PR lane uses `--in-diff` only; nightly does
  the full sweep on a dedicated scheduled runner. Per-crate timeout
  cap in `.cargo/mutants.toml`; runaway mutants kill the run, not the
  budget.
- **Flaky tests poison the mutation signal.** A test that sometimes
  passes and sometimes fails inflates the missed-mutant count.
  Mitigation: gate the lane on `cargo test` being deterministic on the
  target crate; quarantine flakes with `#[ignore]` on a tracked list;
  re-run nightly until two consecutive runs agree on the kill ratio
  before declaring a result.
- **Skip-list creep.** Easy to defeat the gate by skipping mutants
  rather than killing them. Mitigation: every line in a per-crate
  `mutants.toml` skip-list requires a one-line rationale comment;
  `scripts/check-mutants-rationale.sh` (P3.T4) fails the lane if any
  skip lacks a rationale; CODEOWNERS-gated review on `mutants.toml`
  files.
- **Cross-SDK driver toolchain drift.** Five toolchains (Rust, Python,
  TypeScript, WASM, Go) means five paths to "test environment broken".
  Mitigation: pin every driver toolchain in CI (Rust via workspace
  pin, Python via `requirements-lock.txt` in the driver dir, TS via
  `package-lock.json`, Go via `go.mod`, WASM via the existing
  workspace `wasm-pack` pin); `manifest.toml` pins the scenario corpus
  hash so a toolchain drift surfaces as scenario-decode failure, not
  silent verdict drift.
- **Verdict-tuple under-specification.** `(verdict, reason_code,
  scope_set)` may not be enough to distinguish every meaningful
  divergence; some SDKs may emit additional metadata. Mitigation:
  the diff oracle treats extra fields as *advisory* (logged, not
  failing), and the scenario format spec carries an explicit
  "asserted fields" list per scenario so the same scenario corpus
  can grow with new mandatory fields without breaking older drivers.
- **README headline race condition.** Auto-updating PRs to README
  collide with human edits. Mitigation: nightly run opens a single
  `chore(mutants): update kill-score banner` PR and reuses it (closes
  prior open PR with the same title); maintainer approves, never
  force-pushes.
- **Scenario-corpus exfil.** Scenarios may inadvertently capture real
  capability tokens or PII. Mitigation: the scenario format requires
  fixture inputs to come from the trajectory-1 M01 + M07 corpora,
  which were already reviewed for exfil; new scenarios go through the
  same `gitleaks` scan trajectory-1 M02.P2.T3 set up for fuzz corpora.
- **Diff-oracle flake on floating-point or timestamp fields.** Some
  scenarios may carry non-deterministic fields (now()-derived
  expirations). Mitigation: scenarios pin fixture clocks; the format
  spec disallows wall-clock reads inside a scenario driver; drivers
  that read wall-clock fail their own self-test.

## Success criteria

- `.cargo/mutants.toml` updated to scope the six trust-boundary crates;
  per-crate `mutants.toml` files exist with rationale-annotated skip
  lists.
- `mutants-baseline.toml` checked in at the trajectory-2 root with the
  initial kill scores per crate (date-stamped).
- Nightly `mutants-nightly` workflow reports >= 80% caught per crate
  for two consecutive runs before P3.T1 flips the gate.
- `.github/workflows/mutants.yml` `mutants-pr` job runs in required
  mode for PRs touching the six crates.
- `scripts/mutants-comment.sh` posts the per-PR comment with surviving
  mutants; auto-issue created for any surviving mutant beyond the
  per-PR cap; `.github/ISSUE_TEMPLATE/mutants_survivor.yml` exists.
- `README.md` carries a single-line kill-score banner under the
  project headline; nightly auto-update PR confirmed merging.
- `crates/chio-conformance/verdict_matrix/` exists with: scenario
  format spec at `verdict_matrix/SCENARIOS.md`, hash-pinned
  `manifest.toml`, scenario corpus under `verdict_matrix/scenarios/`,
  five drivers under `verdict_matrix/drivers/{rust,python,typescript,
  wasm-browser,go}/`, diff oracle at
  `verdict_matrix/src/diff_oracle.rs`.
- `.github/workflows/verdict-matrix.yml` runs the five drivers on
  every PR touching `crates/chio-conformance/verdict_matrix/**`,
  `crates/chio-kernel*/**`, `sdks/python/chio-sdk-python/**`,
  `sdks/typescript/packages/**`, `sdks/go/**`, or
  `crates/chio-kernel-browser/**`. Lane is required-CI on those paths.
- The audit doc at `.planning/audits/M02-mutation-and-verdict-matrix.md`
  records before/after kill scores per crate, the verdict-matrix
  scenario count, and the corpus hash; linked from this narrative on
  milestone close.
