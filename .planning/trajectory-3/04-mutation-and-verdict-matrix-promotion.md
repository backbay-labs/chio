# Milestone 04: Mutation Gate + Verdict Matrix Promotion

## Lens

Quality. Single lens: test-mass calibration. M04 promotes two
trajectory-2 advisory lanes to gating posture at the honest threshold
each will support. The mutation lane (`cargo-mutants` against the six
trust-boundary crates) and the verdict matrix (cross-language
`(verdict, reason_code, scope_set)` differential) are mechanically
distinct but share one flip mechanism: a `releases.toml` edit, a
two-consecutive-green observation streak, and a CODEOWNERS-gated PR.
M04 is the milestone that makes those flips load-bearing on PR merge.

## Why this is on the trajectory

**Release-gate anchor:** QUALIFICATION.

Trajectory-2 M02 (`.planning/trajectory-2/02-mutation-and-cross-sdk-differential.md`)
shipped both lanes as advisory: `.github/workflows/mutants.yml` runs in
advisory mode (`CHIO_MUTANTS_GATE: blocking` is set but `mutants-gate.sh`
exits 0 while `cycle_end_tag` is empty), and
`.github/workflows/verdict-matrix.yml` runs the Rust kernel reference
plus the deployment-shape smoke jobs as required while leaving Python,
Go, TypeScript-node-http, and WASM-browser drivers in advisory status.
The trajectory-2 M02 closeout aggregate of 30.7% caught
(`.planning/audits/M02-mutation-and-verdict-matrix.md`, "Mutation Kill
Scores") is misleading on inspection: the per-crate spread ranges from
0% (`chio-attest-verify`, full sweep, 57 missed of 57 evaluated) to
100% on tiny bounded shards (`chio-guards` 5 of 1298 evaluated;
`chio-anchor` 6 of 249 evaluated). The verdict treats both lanes as
load-bearing debt for QUALIFICATION because the M08 reviewer
(`08-independent-crypto-protocol-review.md` line 118) is expected to
cite the mutation-gate value in their final report. A 30.7% advisory
aggregate is not the form a crypto-protocol reviewer consumes.

The Go driver is entirely unsupported today
(`crates/chio-conformance/verdict_matrix/drivers/go/run_scenarios.go`
lines 122-146 force every scenario into `result.Unsupported++` with
diagnostic "go-http-sdk delegates matrix verdicts to a sidecar and
has no local semantic evaluator"); the Python driver emits 12 of 48
tuples (capability_subset only;
`drivers/python/run_scenarios.py` lines 188-199 fail revocation,
replay, and redaction categories with `unsupported`). Until both
drivers reach `status = "active"` with zero unsupported, the
cross-language diff is silent on three of four scenario categories
across two of five drivers.

trajectory-2 M02 closeout 30.7% aggregate is the headline number M04
is replacing.

## Prior-art reckoning

trajectory-2 M02 shipped:

- `.cargo/mutants.toml` (workspace-level mutants config; six
  trust-boundary crates registered).
- Per-crate `crates/<name>/mutants.toml` with rationale-annotated
  skip lists (`chio-policy`, `chio-credentials`, `chio-attest-verify`,
  `chio-kernel-core`, `chio-guards`, `chio-anchor`).
- `.planning/trajectory-2/mutants-baseline.toml` aggregate baseline.
- `.github/workflows/mutants.yml` (advisory mode; reads
  `scripts/mutants-gate.sh`).
- `.github/workflows/verdict-matrix.yml` (Rust kernel + deployment-
  shape smoke required; non-Rust drivers advisory).
- `crates/chio-conformance/verdict_matrix/` (48-scenario corpus,
  hash-pinned at
  `sha256:47e8d5394c807196d9567d97515e786cb1abfb0c7676e54db269ca82c735422f`,
  five drivers under `verdict_matrix/drivers/`, diff oracle, manifest).
- `releases.toml [mutants]` schema (`target_catch_ratio_percent = 80`,
  `required_consecutive_nightly_successes = 2`,
  `observed_consecutive_nightly_successes = 0`,
  `cycle_end_tag = ""`, `trust_boundary_crates = [...]`).
- `scripts/mutants-gate.sh`, `scripts/mutants-comment.sh`,
  `scripts/check-mutants-rationale.sh`,
  `scripts/update-mutants-banner.sh`,
  `scripts/mutants-autofile-issue.sh`.

What M04 changes:

- Per-crate kill-score floor moves from the trajectory-2 baseline
  (0% on `chio-attest-verify`; 33.1% on `chio-kernel-core`; 40.7% on
  `chio-credentials`; 56.0% bounded-shard on `chio-policy`; bounded
  100% on `chio-guards` and `chio-anchor` with sample sizes too small
  to be load-bearing) to whatever each crate can sustain by week 12.
  Target 80% target stays in `releases.toml [mutants].target_catch_ratio_percent`;
  the achieved threshold lands in a new
  `activation_threshold_percent_per_crate` scalar that
  `scripts/mutants-gate.sh` actually compares against.
- Mutation lane flips advisory -> required via `releases.toml` edit
  only (no workflow YAML change required; `mutants.yml` already
  threads the gate script).
- Verdict-matrix `python-sdk` and `go-http-sdk` drivers flip advisory
  -> required by adding required matrix entries to
  `.github/workflows/verdict-matrix.yml` and promoting the manifest
  entries to `status = "active"`. Two consecutive green nightly runs
  per the trajectory-2 M02.P3.T1 promotion contract.

What M04 preserves:

- The six-crate trust-boundary set per trajectory-2 D06
  (`releases.toml: trust_boundary_crates`). M04 does NOT widen to
  `chio-weights`, `chio-custody-hw`, or `chio-cross-protocol`; those
  crates exist but are not in the gated set, and `.cargo/mutants.toml`
  does not register their globs. If the M08 reviewer flags coverage
  on those crates, M04 audit doc records the out-of-scope status
  explicitly.
- The 48-scenario verdict-matrix corpus and its pinned manifest hash.
  The freeze `m02-m04-verdict-matrix-coupling`
  (`.planning/trajectory-3/freezes.yml` lines 142-153) gives M02 P2
  / P3 ownership of corpus changes; M04 consumes them.
- The fail-closed semantics in `crates/chio-conformance/verdict_matrix/src/cross_language.rs`
  (any emitting driver that disagrees with the expected tuple OR with
  any other emitting driver fails the diff). M04 makes the contract
  load-bearing on Python and Go without changing the contract itself.

## Hard counts (measured 2026-04-30)

Per-crate baselines, sourced from
`.planning/audits/M02-mutation-and-verdict-matrix.md` "Mutation Kill
Scores" and `.planning/trajectory-2/mutants-baseline.toml` (full sweeps
where listed mutants <= 100; bounded shards otherwise; reproduce with
`cargo mutants --json -p <crate> | jq` or
`scripts/mutants-baseline-kernel.sh`):

| Crate | Listed mutants | Coverage | Caught | Missed | Unviable | Timeout | Kill rate (excl. unviable) |
|-------|----------------|----------|--------|--------|----------|---------|----------------------------|
| chio-policy        | 418  | bounded shard 1/16 | 14  | 11  | 2  | 0 | 56.0% |
| chio-credentials   | 28   | full sweep         | 11  | 16  | 1  | 0 | 40.7% |
| chio-attest-verify | 72   | full sweep         | 0   | 57  | 15 | 0 | 0.0% |
| chio-kernel-core   | 304  | full sweep         | 87  | 175 | 41 | 1 | 33.1% |
| chio-guards        | 1298 | bounded shard 1/32 | 1   | 0   | 4  | 0 | 100.0% (5 evaluated) |
| chio-anchor        | 249  | bounded shard 1/32 | 2   | 0   | 4  | 0 | 100.0% (6 evaluated) |
| Aggregate          | 2369 | mixed              | 115 | 259 | 67 | 1 | 30.7% (442 evaluated) |

The 30.7% aggregate cited above is the trajectory-2 M02 closeout
headline number; M04 P0 will replace it with full-sweep per-crate
numbers. The bounded-shard reads on `chio-guards` and `chio-anchor`
are not load-bearing; their full sweeps must run before any honest
flip claim. P0.T1 captures the full-sweep numbers in
`.planning/trajectory-3/mutants-baseline.toml`.

Verdict-matrix advisory baseline today (sourced from
`crates/chio-conformance/verdict_matrix/manifest.toml` and the
five live driver entrypoints):

| Driver | Manifest status | Effective scenario coverage | Underlying primitive missing |
|--------|-----------------|------------------------------|------------------------------|
| rust-kernel        | active                                | 48 of 48 | none (reference) |
| python-sdk         | partial-capability                    | 12 of 48 (capability_subset) | revocation store, replay nonce store, guard pipeline |
| go-http-sdk        | unsupported-no-local-verdict-emitter  | 0 of 48  | local Go evaluator (SDK delegates to sidecar) |
| typescript-node-http | transport-client                    | 0 / 48 standalone (48 with sidecar) | live sidecar URL |
| wasm-browser       | partial                               | 12 of 48 (capability_subset via `evaluate_pure`) | revocation store, replay nonce store, guard pipeline (browser) |

`releases.toml [mutants]` live state:

```toml
target_catch_ratio_percent = 80
required_consecutive_nightly_successes = 2
observed_consecutive_nightly_successes = 0
cycle_end_tag = ""
activation_evidence = "pending: ..."
trust_boundary_crates = ["chio-policy", "chio-credentials", "chio-attest-verify", "chio-kernel-core", "chio-guards", "chio-anchor"]
```

Week-12 honest-threshold checkpoint date: pinned at P0 close in the
audit doc per the trajectory-3 wave-1 calendar.

## Workspace dependency state

No new workspace dependencies. Reuse trajectory-2 pins:

- `cargo-mutants` 25.x (pinned in `.github/workflows/mutants.yml`).
- Python verdict-driver runtime (`pytest`, `pyyaml`, `requests`)
  reused from `sdks/python/chio-sdk-python/`. M02 P2.T1 owns the
  Python evaluator additions; M04 P2 consumes them.
- Go verdict-driver runtime reused from `sdks/go/chio-go-http/`. M02
  P3.T1 owns the Go evaluator additions; M04 P2 consumes them.
- New optional dev-dep: `proptest` for `chio-kernel-core`. The crate
  already lists `proptest` as a dev-dependency (per existing
  `proptest-regressions/`); P1.T2 / P1.T3 add generators, no version
  bump.

## Scope

### In

- Run full `cargo-mutants` sweeps on each of the six trust-boundary
  crates and pin the per-crate full-sweep numbers in
  `.planning/trajectory-3/mutants-baseline.toml`. Aggregate dated.
- Targeted test work to raise per-crate kill rates toward the 80%
  target. Specifically:
  - `chio-credentials`: `is_supported_*_schema` predicate negative
    tests; target >= 90%.
  - `chio-kernel-core`: proptests on `NormalizedScope`,
    `NormalizedToolGrant`, `NormalizedResourceGrant`,
    `NormalizedPromptGrant`, `wildcard_matches`, `path_has_prefix`,
    `parse_domain`, `normalize_path`; target >= 65%-80% per slope.
  - `chio-attest-verify`: three new fixture families under
    `crates/chio-attest-verify/tests/fixtures/` (cert-time NotBefore
    future / NotAfter past, malformed-chain wrong-CA, oidc-mismatch
    wrong-issuer); target >= 65% (D08 honest floor for the
    long-tail crate).
  - `chio-policy`: full-sweep + boundary tests for `validate.rs`,
    `conditions.rs`, `compiler.rs`; target >= 80%.
  - `chio-guards` and `chio-anchor`: full sweeps + targeted gap
    closure to the achieved threshold.
- Verify M02-owned Python and Go verdict-matrix drivers flip from
  advisory to `status = "active"` and zero unsupported / zero
  divergence on the 48-scenario corpus. M04 P2 verifies; M02 owns
  the source authorship.
- Two-consecutive-green nightly observation captured in the M04
  audit doc.
- `releases.toml` gate-flip PR: set `cycle_end_tag`,
  `observed_consecutive_nightly_successes = 2`, write the
  `activation_evidence` YAML block, add the new
  `activation_threshold_percent_per_crate` scalar field. Update
  `scripts/mutants-gate.sh` to honor the new field with fallback to
  `target_catch_ratio_percent`.
- `.github/workflows/verdict-matrix.yml` flip: add required matrix
  entries for `python-sdk` and `go-http-sdk` asserting zero
  divergence vs the rust-kernel reference (mirror the existing
  `deployment-shape-smoke` pattern).
- M04 audit doc closure: per-crate achieved kill-rate, gap analysis,
  honest-threshold contingency record, M08 handoff artefact set.
- Two committed nightly-run JSON artefacts under
  `.planning/trajectory-3/audits/M04-mutation-gate-evidence/` so the
  activation-evidence run URLs survive the 30-day GitHub artefact
  retention.

### Out (and why)

- Widening the trust-boundary set beyond D06's six crates (`chio-policy`,
  `chio-credentials`, `chio-attest-verify`, `chio-kernel-core`,
  `chio-guards`, `chio-anchor`). The prompt's mention of
  `chio-weights`, `chio-custody-hw`, `chio-cross-protocol` does not
  match D06; those crates are out-of-scope for the M04 gate. Recorded
  explicitly in the audit doc.
- Widening the verdict-matrix corpus. `m02-m04-verdict-matrix-coupling`
  freeze gives M02 corpus ownership; M04 consumes the 48-scenario set
  unchanged. The hash check in
  `crates/chio-conformance/verdict_matrix/tests/diff_oracle_self_test.rs::manifest_hash_pins_current_scenario_index`
  catches drift.
- TypeScript-node-http and WASM-browser driver promotion. Per the
  milestone narrative the M04 driver flip is Python + Go only;
  `transport-client` and `partial` remain advisory. M02 P5.T2 / P5.T3
  closed the TS / WASM authoring; their promotion is deferred to
  trajectory-4.
- Framework wrappers (`typescript-ai-sdk-middleware`,
  `typescript-chio-next`) and the four deployment-shape drivers
  (`jvm`, `dotnet`, `lambda`, `k8s`). M07.P6 owns these per
  trajectory-2 D07.
- Aspirational thresholds beyond 80%. D08 caps the gate honestly: 80%
  target, 65% accepted floor; the gate flips at the achieved value.
- New libFuzzer targets, Kani harness widening, Apalache TLA+ surface
  changes. Different lenses; trajectory-1 M02 / M03 cover those.

## Phases

### P0: Audit doc baseline + per-crate full-sweep kill scores

Open `.planning/trajectory-3/audits/M04-mutation-gate.md` (template
already in place); fill section 2 ("Hard counts at P0") with full-sweep
per-crate numbers and section 3 ("Verdict-matrix advisory baseline").
Pin `mutants-baseline.toml` at the trajectory-3 root with the dated
full-sweep aggregate. Pin the week-12 honest-threshold checkpoint date
in the audit doc.

- M04.P0.T1: Open audit doc and capture full-sweep baseline per
  trust-boundary crate; pin `mutants-baseline.toml` at trajectory-3
  root.

### P1: Mutant survivor sweep on lagging crates

One ticket per crate (or per crate cluster), each anchored to the
missed-mutant inventory from P0. `chio-attest-verify` is the priority
gate-flip blocker (0% kill rate); P1.T4 carries the longest single-
crate effort. Tickets ordered by slope (cheapest closure first).

- M04.P1.T1: `chio-credentials` `is_supported_*_schema` negative
  tests; target >= 90%.
- M04.P1.T2: `chio-kernel-core` `normalized.rs` proptests on
  `NormalizedScope`, `NormalizedToolGrant`, `NormalizedResourceGrant`,
  `NormalizedPromptGrant`; target ~80% missed-mutant closure on the
  cluster.
- M04.P1.T3: `chio-kernel-core` `scope.rs` proptests on
  `wildcard_matches`, `path_has_prefix`, `parse_domain`,
  `normalize_path`; target additional ~50 missed-mutant closure.
- M04.P1.T4: `chio-attest-verify` fixture suite; cert-time +
  malformed-chain + oidc-mismatch families plus negative tests on
  `validate_against_fulcio`, `match_identity`,
  `read_oidc_issuer_extension`; target >= 65% (D08 floor).
- M04.P1.T5: `chio-policy` full-sweep + `validate.rs` /
  `conditions.rs` / `compiler.rs` boundary tests; target >= 80%.
- M04.P1.T6: `chio-guards` and `chio-anchor` full sweeps + targeted
  test closure to the achieved threshold; may split as T6.a / T6.b
  if the wall-time budget exceeds 2 days.

### P2: Verdict-matrix Python + Go driver verification

M02 owns the source authorship of the Python and Go verdict emitters
(M02 P2.T1 Python; M02 P3.T1 Go). M04 P2 is a verification surface:
confirm `manifest.toml` records `[drivers.python-sdk] status = "active"`
and `[drivers.go-http-sdk] status = "active"`; run each driver against
the 48-scenario corpus; assert `unsupported_count == 0`,
`failed_count == 0`, zero divergence vs the rust-kernel reference.
Capture the two-consecutive-green nightly observation in the audit
doc. The freeze `m02-m04-verdict-matrix-coupling` (P2-P3 of M02)
guarantees the source authorship lands before this phase opens.

- M04.P2.T1: Verify M02 Python driver landed at
  `status = "active"`; zero unsupported, zero divergence.
- M04.P2.T2: Verify M02 Go driver landed at `status = "active"`;
  zero unsupported, zero divergence.
- M04.P2.T3: Two-consecutive-green nightly observation captured in
  audit doc with run URLs.

### P3: Mutation lane flip to required

Edit `releases.toml`: set `cycle_end_tag`,
`observed_consecutive_nightly_successes = 2`,
`activation_evidence` YAML block per the honest-threshold playbook,
new scalar `activation_threshold_percent_per_crate`. Update
`scripts/mutants-gate.sh` to read the new field with fallback to
`target_catch_ratio_percent`. Backward-compatible. The freeze
`m04-mutation-gate-pivot` opens here and covers `.cargo/mutants.toml`,
`mutants-baseline.toml`, `.github/workflows/mutants.yml`,
`.github/workflows/verdict-matrix.yml`, and
`crates/chio-conformance/verdict_matrix/**` through P5. P3.T1 carries
the D08 floor-vs-target rule explicitly: any crate below 80% but at
or above 65% gets recorded in the activation-evidence block; the gate
uses the achieved per-crate floor. P3.T2 exercises the override
rollback recipe (`MUTANTS_GATE_OVERRIDE_REASON` env-var) under a
one-time CI run so the rollback path is proven.

- M04.P3.T1: Gate-flip PR; edit `releases.toml`; extend
  `scripts/mutants-gate.sh`; trigger README banner auto-update via
  `mutants-banner.yml`.
- M04.P3.T2: Override / rollback recipe dry-run + documentation
  update at `docs/fuzzing/mutants.md`.

### P4: Verdict-matrix Python + Go drivers flip to required

Edit `.github/workflows/verdict-matrix.yml` to add new required
matrix entries for `python-sdk` and `go-http-sdk` asserting zero
divergence vs `rust-kernel`. Mirror the existing `deployment-shape-smoke`
required job pattern. Two-consecutive-green prerequisite from
M04.P2.T3. The freeze covers the workflow file; P4 is the only
window allowed to edit it.

- M04.P4.T1: Add required matrix entries for `python-sdk` and
  `go-http-sdk` to `verdict-matrix.yml`.
- M04.P4.T2: Update `docs/conformance/verdict-matrix.md` required-
  driver list.

### P5: M04 audit doc closure + M08 handoff

Complete `.planning/trajectory-3/audits/M04-mutation-gate.md` sections
4 (honest-threshold contingency record) and 5 (closure attestations).
Cross-reference the activation-evidence YAML in `releases.toml` and
the verdict-matrix flip PR. Update `mutants-baseline.toml` in
trajectory-3 with the post-P3 per-crate kill scores and aggregate.
Commit two nightly-run JSON artefacts under
`.planning/trajectory-3/audits/M04-mutation-gate-evidence/` so the
activation-evidence run URLs survive the 30-day GitHub artefact
retention. The M04 audit doc is the artefact M08 reviewer cites.

- M04.P5.T1: Audit doc closure; achieved kill-rate per crate;
  per-driver active status; gate-flip-evidence YAML embedded
  reference.
- M04.P5.T2: Post-flip `mutants-baseline.toml` aggregate update.
- M04.P5.T3: Commit two nightly-run JSON artefacts under
  `M04-mutation-gate-evidence/`.

## Cross-milestone interactions

Hard deps inside trajectory-3:

- **M03 hosted CI**. The mutation gate runs on the hosted
  `mutants-nightly` schedule (`.github/workflows/mutants.yml`); the
  verdict-matrix gate runs on `verdict-matrix.yml`. Both depend on
  M03 closing the hosted-CI billing restoration so nightly runs
  produce green-able evidence. Without M03 hosted CI, the
  two-consecutive-green observation cannot be collected.

Hard deps from trajectory-2:

- "trajectory-2 M02.P3.T1 promotion contract: two consecutive green
  nightly runs before flip" applies to both lanes M04 promotes.
- "trajectory-2 D06 trust-boundary crate set
  (`releases.toml: trust_boundary_crates`) binds the M04 mutation
  gate; do NOT widen."
- "trajectory-2 M02.P2 (Python verdict driver) and M02.P3 (Go
  verdict driver) own the source authorship; M04.P2 verifies."
- "trajectory-2 M02.P5.T6 hash-pinned scenario manifest is the
  corpus M04 consumes; do NOT modify."

Soft deps (informational, not blocking):

- "trajectory-2 M02 closeout 30.7% aggregate is the headline number
  M04 replaces with per-crate full-sweep numbers."
- "trajectory-2 M02 audit at
  `.planning/audits/M02-mutation-and-verdict-matrix.md` is the
  source of the per-crate baseline this milestone improves."

Active freezes:

- `m04-mutation-gate-pivot` (M04 P3-P5): covers `.cargo/mutants.toml`,
  `mutants-baseline.toml`, `.github/workflows/mutation-coverage.yml`
  (file-of-record name; current path is `.github/workflows/mutants.yml`),
  `.github/workflows/verdict-matrix.yml`,
  `crates/chio-conformance/verdict_matrix/**`.
- `m04-m05-attest-verify-coupling` (M04 P3-P5): covers
  `crates/chio-attest-verify/src/**`. M04.P3.T1 (gate flip) is a
  precondition for M05 starting `dispatch_allow.rs` work in
  `m05-threat-coverage-pivot`. Practical sequence: M04.P1.T4 raises
  `chio-attest-verify` to honest threshold; M04.P3.T1 flips the
  gate; M05.P2.T1 (`dispatch_allow` placeholder eviction) opens
  AFTER M04.P5 closure so M05 source edits land under the active
  gate.
- `m02-m04-verdict-matrix-coupling` (M02 P2-P3): covers
  `crates/chio-conformance/verdict_matrix/**`. M02 P2 (Python
  driver) and M02 P3 (Go driver) MUST close before M04.P3 opens
  (i.e. before `m04-mutation-gate-pivot` activates). This is what
  guarantees Python and Go reach `status = "active"` before the
  verdict-matrix gate flips advisory -> required.

Downstream consumers:

- M05 (threat coverage): `chio-attest-verify` source edits in
  `dispatch_allow.rs` land under the M04-flipped gate. Any M05 edit
  that lowers the kill score below the activation threshold fails
  the PR.
- M08 (independent crypto-protocol review): the reviewer cites the
  M04 mutation-gate value in their final report
  (`08-independent-crypto-protocol-review.md` line 118). M04.P5
  audit doc must be in the form a vendor can quote verbatim. The
  handoff artefact set is the audit doc, the
  `releases.toml: activation_evidence` YAML, the verdict-matrix
  manifest hash + driver inventory, the two committed nightly-run
  JSONs, and the survivor inventory with skip-list rationales (per
  `scripts/check-mutants-rationale.sh`).

## Risks and mitigations

1. **80% target unreachable in 9 weeks** (D08 invokes). High
   probability for `chio-attest-verify`; medium for
   `chio-kernel-core`. Mitigation: ship at honest threshold (target
   80%, accept 65% floor). P3.T1 records the gap in
   `activation_evidence`. Do NOT slip M08; halt-trigger 15 fires
   only on >25% vendor calendar slip.
2. **`chio-attest-verify` kill rate stays below 65%**. Probability
   medium. Mitigations: (a) widen the per-crate skip-list with
   audited rationale per `scripts/check-mutants-rationale.sh` (each
   skip cites a real coverage source: integration test or fuzz
   target name); (b) accept a 50% floor as second-stage honest
   threshold and surface to user as a D08 amendment. Halt trigger:
   user notification before any second-stage downgrade.
3. **M02 fails to deliver Python or Go driver in time**. Probability
   medium. The freeze `m02-m04-verdict-matrix-coupling` enforces
   M02 P2 / P3 close before M04.P3, so a slip cascades. Mitigation:
   if only one of (Python, Go) lands, M04.P4 degrades to flipping
   the delivered driver only; the other stays advisory in the audit
   doc. Recommendation per the M04 research open question 2:
   block-on-Go (the freeze sequence implies block); decision
   recorded in P3.T1.
4. **Flipped gate fails on first nightly post-flip**. Probability
   medium-high; the activation streak is two greens but day-three
   regression is realistic. Mitigation: the P3.T1 PR carries a
   same-day rollback recipe (`cycle_end_tag = ""` PR with
   `mutants-gate-override` title, CODEOWNERS approval). P3.T2
   exercises the override path under a one-time CI run so the
   rollback is proven before the flip lands.
5. **CI runner budget regression**. The 1800-min/30-day envelope is
   shared with fuzz lanes (`scripts/check-fuzz-budget.sh`). Mutation
   full sweeps on `chio-guards` (1298 mutants) and `chio-policy`
   (418) are wall-time-heavy; the per-crate 4h nightly budget may
   not fit. Mitigation: shard the nightly sweep across runs;
   aggregate across multiple cron triggers; document if the
   activation streak is achieved via aggregated shards rather than
   single full sweeps. Audit doc records the methodology.
6. **Skip-list rationale gaming**. Tempting to skip-list
   `chio-attest-verify` mutants en masse to "achieve" 65%. M08
   reviewer audit catches this. Mitigation:
   `scripts/check-mutants-rationale.sh` requires a citation per
   skip; CODEOWNERS gate on `crates/<name>/mutants.toml` enforces
   review; each skip-list addition in M04 P1 must cite a real
   coverage source.
7. **Verdict-matrix corpus drift between M02 P3 close and M04 P4
   open**. Probability low (single-week window). Mitigation: the
   manifest hash check in
   `crates/chio-conformance/verdict_matrix/tests/diff_oracle_self_test.rs::manifest_hash_pins_current_scenario_index`
   catches any byte-level drift; the freeze
   `m02-m04-verdict-matrix-coupling` covers
   `crates/chio-conformance/verdict_matrix/**` so a between-window
   M02 hot-fix lands as a freeze-bypass PR with explicit review.

## Success criteria

- `.planning/trajectory-3/mutants-baseline.toml` carries dated
  full-sweep per-crate numbers and aggregate post-P5.
- `releases.toml [mutants]` records `cycle_end_tag` non-empty,
  `observed_consecutive_nightly_successes >= 2`,
  `activation_threshold_percent_per_crate` populated, and an
  `activation_evidence` YAML block citing two nightly run URLs and
  per-crate kill rates.
- `scripts/mutants-gate.sh` extended to read
  `activation_threshold_percent_per_crate` with fallback to
  `target_catch_ratio_percent`; backward-compatible.
- `crates/chio-conformance/verdict_matrix/manifest.toml` records
  `[drivers.python-sdk] status = "active"` and
  `[drivers.go-http-sdk] status = "active"`; both drivers report
  zero unsupported and zero divergence on the 48-scenario corpus
  for two consecutive nightly runs.
- `.github/workflows/verdict-matrix.yml` runs `python-sdk` and
  `go-http-sdk` as required matrix entries asserting zero divergence
  vs `rust-kernel`.
- `.planning/trajectory-3/audits/M04-mutation-gate.md` records:
  per-crate achieved kill-rate; per-driver active status; gate-flip-
  evidence YAML embedded reference; honest-threshold contingency
  record per D08 (any crate below 80% recorded with gap); M08
  handoff artefact set; two committed nightly-run JSONs under
  `M04-mutation-gate-evidence/`.
- The M08 reviewer cites the gate value in their final report (per
  `08-independent-crypto-protocol-review.md` line 118).
