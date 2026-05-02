# M04 Research: Mutation Gate + Verdict Matrix Promotion

Trajectory: trajectory-3
Milestone: M04
Wave: W1
Lens: Quality (single)
Release-gate anchor: QUALIFICATION
Author: RESEARCH agent
Snapshot: 2026-04-30

This document captures the IMPLEMENT-ready findings the M04 agent needs
to author tickets P0..P5. Every count and claim is sourced from a live
file in this worktree; legacy paths are listed where they are still
load-bearing. Names use Chio; ARC and Chio are synonyms.

## Mutation kill-score landscape (per-crate)

The trajectory-2 M02 closeout (`.planning/audits/M02-mutation-and-verdict-matrix.md`,
section "Mutation Kill Scores") captures the on-disk baseline. The
aggregate live in `.planning/trajectory-2/mutants-baseline.toml`. The
six trust-boundary crates per D06 are: `chio-policy`, `chio-credentials`,
`chio-attest-verify`, `chio-kernel-core`, `chio-guards`, `chio-anchor`.
Note: D06 in trajectory-3 is the FTE decision; the six-crate set is
inherited from trajectory-2 D06 of that trajectory; `releases.toml`
records the canonical list under `trust_boundary_crates`.

| Crate | Listed mutants | Coverage on disk | Caught | Missed | Unviable | Timeout | Kill rate excl. unviable |
|-------|----------------|------------------|--------|--------|----------|---------|--------------------------|
| chio-policy        | 418  | bounded shard 1/16 | 14 | 11  | 2  | 0 | 56.0% |
| chio-credentials   | 28   | full sweep         | 11 | 16  | 1  | 0 | 40.7% |
| chio-attest-verify | 72   | full sweep         | 0  | 57  | 15 | 0 | 0.0% |
| chio-kernel-core   | 304  | full sweep         | 87 | 175 | 41 | 1 | 33.1% |
| chio-guards        | 1298 | bounded shard 1/32 | 1  | 0   | 4  | 0 | 100.0% (5 evaluated) |
| chio-anchor        | 249  | bounded shard 1/32 | 2  | 0   | 4  | 0 | 100.0% (6 evaluated) |
| Aggregate          | 2369 | mixed              | 115 | 259 | 67 | 1 | 30.7% (442 evaluated) |

The 30.7% aggregate cited in the M02 audit closeout is a measured-status
average across mixed full sweeps and bounded shards. Per-crate behaviour
diverges sharply:

- `chio-attest-verify` is the most acute lagging crate. Its full sweep
  produced **zero caught mutants out of 72 listed** (15 unviable). The
  Sigstore verification surface (160 lines around `<impl AttestVerifier
  for SigstoreVerifier>::verify_bytes`, plus `parse_certificate_to_der`,
  `validate_against_fulcio`, `match_identity`, `read_oidc_issuer_extension`,
  `decode_oidc_issuer_value`, `certificate_validity`, `verify_signature_bytes`,
  `bundle_leaf_certificate_der`, `bundle_rekor_metadata`, `IssuerOnlyPolicy::verify`)
  has full-replacement and comparator-flip mutants surviving wholesale.
  Diagnosis: tests assert success paths only; there is no fault-injection
  fixture for malformed certificates, mismatched OIDC issuers, or rekor
  metadata drift. Closing this crate to >= 65% (let alone 80%) is the
  longest single-crate task in M04.
- `chio-kernel-core` (33.1%, 175 missed) shows a telltale pattern: 175
  surviving mutants concentrated in `normalized.rs` (subset checks) and
  `scope.rs` (path / pattern matching). The mutant classes table reads:
  comparison rewrite (54), boolean connective rewrite (35), boolean
  return rewrite (35), negation deletion (18), arithmetic rewrite (15),
  match arm deletion (7). Most are killable with property-based tests
  on `is_subset_of`, `wildcard_matches`, `path_has_prefix`, and the
  `*_bounded_kani` variants. The Kani harness covers the formal lane
  but does not exercise the runtime path.
- `chio-credentials` (40.7%, 16 missed) is concentrated in 16 surviving
  mutants on the `is_supported_*_schema` predicates in `lib.rs`. These
  are equality / OR rewrites that no test asserts the negative path
  for; closure is mechanical.
- `chio-policy` measured 56.0% on a 1/16 shard (27 of 418 mutants);
  full-sweep score is unmeasured. The shard's surviving mutants span
  `compiler.rs` (`tool_patterns_overlap` `==`/`!=`, `compile_velocity_rule`
  `&&`/`||`), `conditions.rs` (timezone parsing match arms, `+`/`*`
  swaps), `merge.rs` (`merge_chio` replaced with `Some(Default::default())`),
  and `validate.rs` (boundary `<` to `<=`, `>` to `>=`, `-` to `/`).
  Most are property-test-killable.
- `chio-guards` and `chio-anchor` show 100% on tiny evaluated samples
  (5 of 1298 and 6 of 249). The bounded baseline is not load-bearing;
  full sweeps will need to run before any honest claim is made.

The prompt's note about "chio-weights, chio-custody-hw, chio-cross-protocol"
does not match the D06 six-crate set. Those crates exist in the workspace
(`crates/chio-weights`, `crates/chio-custody-hw`, `crates/chio-cross-protocol`)
but `releases.toml: trust_boundary_crates` does not list them and
`.cargo/mutants.toml` does not register their globs. M04 should NOT widen
to those crates; D06 binds the gate to the six listed. If the M08
reviewer cites a kill-score gap on those non-gated crates, M04 records
the out-of-scope status explicitly in the audit doc.

## Mutant survivor analysis (sample 10)

The audit catalogues hundreds of survivors; the sample below picks 10
high-priority survivors across `chio-attest-verify`, `chio-kernel-core`,
and `chio-credentials` and classifies each by closure path.

(a) genuinely test-the-test hard cases:
1. `chio-attest-verify/src/sigstore.rs:160:16` `<` to `==` in
   `verify_bytes`: time-window comparator; killing requires a fixture
   with a not-yet-valid leaf certificate (cert NotBefore in the
   future). Doable but fixture-heavy.
2. `chio-attest-verify/src/sigstore.rs:340:5` replace
   `validate_against_fulcio` with `Ok(())`: the negative path is
   reached only via a malformed CA chain; needs a constructed fixture.
3. `chio-attest-verify/src/sigstore.rs:489:5` replace
   `verify_signature_bytes` with `Ok(())`: sig-verify happy path;
   negative requires a corrupted-signature fixture.

(b) actually killable with a property test:
4. `chio-kernel-core/src/normalized.rs:154:38` `==` to `!=` in
   `NormalizedToolGrant::is_subset_of`: a `proptest` quickcheck on
   `is_subset_of(a, b) => union(a,b) == b` kills it.
5. `chio-kernel-core/src/normalized.rs:262:17` `||` to `&&` in
   `NormalizedScope::is_subset_of`: same proptest family.
6. `chio-kernel-core/src/scope.rs:476:25` `<` to `==` in
   `wildcard_matches`: proptest over short patterns and inputs of
   varying length asserts a `<` boundary.
7. `chio-credentials/src/lib.rs:57:5` replace
   `is_supported_passport_schema` with `true`: trivially killable by
   asserting `is_supported_passport_schema("not.a.schema") == false`.
8. `chio-policy/src/validate.rs:234:26` `<` to `<=` in
   `validate_posture`: boundary test at the tipping integer.
9. `chio-policy/src/conditions.rs:178:9` delete match arm `5` in
   `day_abbreviation`: assertion that `day_abbreviation(5)` produces
   a specific string kills it.

(c) skip-listable with rationale:
10. `chio-attest-verify/src/sigstore.rs:340:5` replace
    `validate_against_fulcio` with `Ok(())` (also category (a) above).
    If the fixture cost exceeds the M04 budget, the rationale path is:
    register a per-crate `mutants.toml` skip entry citing "covered by
    integration test `tests/sigstore_negative_chain.rs::TBD` plus
    fuzz target `fuzz/fuzz_targets/sigstore_bundle.rs`". This is
    legitimate per `scripts/check-mutants-rationale.sh` if the cited
    coverage actually exists.

The realistic 9-week trajectory:

- `chio-credentials` to >= 80%: 16 missed mutants; ~3 days of test
  authoring. Achievable.
- `chio-kernel-core` to >= 65%: 175 missed mutants but ~80% are in
  the proptest-amenable cluster (`normalized.rs`, `scope.rs`). With
  a `proptest` crate addition and 4-6 generators, ~120 mutants can
  be killed in ~7-10 engineering days. Reaching 80% requires
  closing the path-normalization / domain-parse cluster too.
- `chio-attest-verify` to >= 65%: hardest. 57 missed of 57 evaluated
  caught (kill rate ZERO). Requires three new fixture families
  (cert-time, malformed chain, OIDC mismatch) and ~10-12 engineering
  days plus skip-list rationale entries for ~15 unviable mutants.
  >= 80% is a stretch; >= 65% is plausible.
- `chio-policy` to >= 80%: Full-sweep numbers unknown; the shard
  suggests 60-70% achievable with conditions / validate boundary
  tests. Needs a full sweep first to set the actual baseline.
- `chio-guards` and `chio-anchor`: full sweeps must precede any
  improvement work. Their bounded shards say nothing reliable.

Aggregate prediction: 65% per-crate floor is reachable on five of
six crates by week 12; `chio-attest-verify` is the long-tail. The
80% target is reachable on three crates (credentials, policy,
guards) and stretch on the remaining three. D08 contingency
applies.

## Honest-threshold playbook (D08)

D08 binds the gate to ship at the achieved threshold rather than
chasing 80% past week 12. The mechanics live in three files:

1. `releases.toml [mutants]`. The schema is comprehensive. Today:
   - `target_catch_ratio_percent = 80`
   - `required_consecutive_nightly_successes = 2`
   - `observed_consecutive_nightly_successes = 0`
   - `cycle_end_tag = ""` (advisory)
   - `activation_evidence = "pending: carried forward to .planning/trajectory/sweep/M02-FOLLOWUPS.md; blocker: no two consecutive mutants-nightly full sweeps at >=80 percent across all six crates"`
2. `scripts/mutants-gate.sh`. Reads only `cycle_end_tag`,
   `target_catch_ratio_percent`, `required_consecutive_nightly_successes`,
   and `observed_consecutive_nightly_successes`. Today: emit advisory
   pass when `cycle_end_tag` is empty OR observed < required.
3. `mutants-baseline.toml`. Currently lives at
   `.planning/trajectory-2/mutants-baseline.toml`. M04 should pin
   its updated aggregate at `.planning/trajectory-3/mutants-baseline.toml`
   or at the workspace root per the prompt's option, and update the
   audit doc cross-reference.

D08 honest-threshold mechanics M04 must implement:

- `target_catch_ratio_percent` stays at 80 (do NOT downgrade the
  documented target). The "shipped at" threshold is captured in a
  new field, e.g. `activation_threshold_percent_per_crate`, which
  is what `mutants-gate.sh` actually compares against. If we ship
  at 65%, that field reads 65; the target stays 80.
- `activation_evidence` is the auditable cite. Schema (proposed):
  ```
  activation_evidence = """
  cycle: <release tag>
  per_crate_kill_rate_percent:
    chio-policy: 78
    chio-credentials: 92
    chio-attest-verify: 64
    chio-kernel-core: 71
    chio-guards: 81
    chio-anchor: 73
  nightly_runs:
    - <run-url-1> (<date>)
    - <run-url-2> (<date>)
  honest_threshold_applied: 65
  d08_invocation_rationale: "chio-attest-verify reached 64% by week 12; D08 contingency applied; gap recorded in .planning/trajectory-3/audits/M04-mutation-gate.md section 4."
  """
  ```
- `mutants-gate.sh` needs a small extension: today it reads only
  `target_catch_ratio_percent`. P3.T1 should add a parallel scalar
  `activation_threshold_percent_per_crate` and prefer it when
  non-empty; absence falls back to `target_catch_ratio_percent`.
  Backward-compatible.
- `releases.toml` editing is CODEOWNERS-gated; the M04.P3 PR for
  the flip carries the activation-evidence block atomically.

The gate-flip is a `releases.toml` edit only; no `.github/workflows/mutants.yml`
change is required (the workflow already wires `CHIO_MUTANTS_GATE: blocking`
and threads the gate script).

## Verdict-matrix driver gap analysis

Source: `crates/chio-conformance/verdict_matrix/manifest.toml` and the
five live driver entrypoints under `crates/chio-conformance/verdict_matrix/drivers/`.
Corpus: 48 scenarios, four categories of 12 each
(capability_subset, revocation_propagation, replay_verdict,
redaction_determinism). Hash pinned at
`sha256:47e8d5394c807196d9567d97515e786cb1abfb0c7676e54db269ca82c735422f`.

| Driver | Manifest status | Effective scenario coverage | Underlying primitive missing |
|--------|-----------------|------------------------------|------------------------------|
| rust-kernel | active | 48 of 48 | none (reference) |
| python-sdk | partial-capability | 12 of 48 (capability_subset only) | revocation store, replay nonce store, guard pipeline |
| go-http-sdk | unsupported-no-local-verdict-emitter | 0 of 48 | no local verdict emitter; SDK delegates to a sidecar |
| typescript-node-http | transport-client | 0 of 48 without sidecar; 48 with sidecar | live sidecar URL (`CHIO_VERDICT_MATRIX_SIDECAR_URL`) |
| wasm-browser | partial | 12 of 48 (capability_subset via `evaluate_pure`) | revocation store, replay nonce store, guard pipeline (browser surface) |

Per-driver `unsupported` scenario classification:

Python (`drivers/python/run_scenarios.py`, lines 188-199):
- `script.operation != "tool.call"` -> all non-tool-call scripts
  reported `unsupported`.
- `category != "capability"` -> revocation_propagation,
  replay_verdict, redaction_determinism scenarios all
  `unsupported` because "python-sdk verdict path has no local
  <category> evaluator".
- `script.revoked == true` -> revocation_propagation scenarios
  also fail because "python-sdk mock capabilities do not expose
  revocation".
- Net effect: 12 of 48 emit tuples; 36 emit `unsupported`.

Go (`drivers/go/run_scenarios.go`, lines 122-146):
- All 48 scenarios fall into the `result.Unsupported++` branch
  with diagnostic "go-http-sdk delegates matrix verdicts to a
  sidecar and has no local semantic evaluator". The driver does
  not even attempt the capability path; it is unconditionally a
  sidecar transport client.
- Underlying primitive missing: a local Go-side evaluator. The
  Go SDK at `sdks/go/chio-go-http` is HTTP-only; the verdict
  emitter assumes a sidecar.

Path from `unsupported` -> `passing` (Python):
1. Add a Python-side capability-revocation registry that mirrors
   the Rust kernel's revocation store semantics. ~2-3 days.
2. Add a Python replay-nonce store and the deterministic-replay
   verdict path. ~3 days.
3. Add the Python redaction guard surface (input/output redaction
   verdicts emit `urn:chio:error:guard:input-redacted` /
   `output-redacted`). ~2 days.
4. Promote `[drivers.python-sdk] status` from `partial-capability`
   to `active`. Verify with `cargo test -p chio-conformance --test
   verdict_matrix_cross_language --quiet`.

Path from `unsupported` -> `passing` (Go):
1. Decision: emit verdicts locally OR keep the sidecar contract.
   The Python pattern (local) is the cheaper precedent; matches
   the existing native-test gate in `verdict_matrix.yml`.
2. Build a Go-side semantic evaluator that mirrors the four
   category surfaces. Larger scope than Python because Go has no
   existing kernel client; estimate 8-10 days.
3. Alternative path: provide a sidecar in CI (a Rust kernel
   sidecar process bound on a unix socket). Cheaper to author
   (~2 days) but adds a CI runtime moving part. Not preferred.
4. Promote `[drivers.go-http-sdk] status` from
   `unsupported-no-local-verdict-emitter` to `active`.

The TypeScript node-http and WASM browser drivers are NOT in M04
scope per the milestone narrative ("Python + Go drivers ... flip
from advisory to required"). They remain `transport-client` /
`partial`. M02 P5.T2 / P5.T3 already merged. The framework
wrappers (`typescript-ai-sdk-middleware`, `typescript-chio-next`)
and the four deployment-shape drivers (`jvm`, `dotnet`, `lambda`,
`k8s`) are also out of scope for M04; they are M07.P6 / lifted
from M02 D07.

## Verdict-matrix corpus

Source: `crates/chio-conformance/verdict_matrix/manifest.toml`,
`crates/chio-conformance/verdict_matrix/scenarios/`.

48 total scenarios, four categories:
- `capability_subset` (12): subset semantics on
  `(verdict, reason_code, scope_set)` for a capability scope vs.
  a requested tool. Reason codes hit
  `urn:chio:error:none` (allow) and
  `urn:chio:error:capability:scope-exceeded` (deny).
- `revocation_propagation` (12): the same capability is allowed
  before revocation and denied after; reason code
  `urn:chio:error:capability:revoked`.
- `replay_verdict` (12): deterministic replay of a recorded
  trace. Reason codes
  `urn:chio:error:replay:deterministic-mismatch` /
  `urn:chio:error:replay:trace-not-found`.
- `redaction_determinism` (12): input or output redaction guards
  fire with deterministic reason codes
  `urn:chio:error:guard:input-redacted` /
  `urn:chio:error:guard:output-redacted` /
  `urn:chio:error:guard:denied`.

Tuple shape: `(verdict, reason_code, scope_set)`. Reason registry:
`spec/errors/registry.yaml`. Index hash pinning is enforced by
`crates/chio-conformance/verdict_matrix/tests/diff_oracle_self_test.rs::manifest_hash_pins_current_scenario_index`,
so any unauthorised corpus drift fails CI.

M04 should NOT widen the corpus. The freeze
`m02-m04-verdict-matrix-coupling` (freezes.yml lines 142-153)
covers `crates/chio-conformance/verdict_matrix/**` for M02 P2-P3,
which means M02 owns corpus changes; M04 consumes them.

## Gate-flip mechanics in releases.toml

Live state today (worktree `releases.toml`):

```toml
[mutants]
initial_merge_tag = ""
target_catch_ratio_percent = 80
required_consecutive_nightly_successes = 2
observed_consecutive_nightly_successes = 0
activation_evidence = "pending: carried forward to .planning/trajectory/sweep/M02-FOLLOWUPS.md; blocker: no two consecutive mutants-nightly full sweeps at >=80 percent across all six crates"
cycle_end_tag = ""
pr_survivor_issue_budget = 5
nightly_wall_budget_hours_per_crate = 4
trust_boundary_crates = ["chio-policy", "chio-credentials", "chio-attest-verify", "chio-kernel-core", "chio-guards", "chio-anchor"]
```

The gate flips when `scripts/mutants-gate.sh` exits non-zero on
under-threshold survivors. Two conditions must BOTH hold:

1. `cycle_end_tag` non-empty (e.g. `v3.20.0` post-flip release tag).
2. `observed_consecutive_nightly_successes >= required_consecutive_nightly_successes`
   (i.e. >= 2).

When both hold and the cargo-mutants outcomes report a per-crate
caught ratio below `target_catch_ratio_percent`, the workflow
fails the PR. Today neither condition holds; the gate is advisory.

For the verdict-matrix:
- `verdict-matrix.yml` has TWO required jobs already:
  `rust-kernel` (Rust kernel driver + diff-oracle self-test +
  cross-language matrix) and `deployment-shape-smoke` (a smoke
  gate over the four deployment-shape SDK drivers via the Rust
  kernel reference).
- The cross-language diff (`crates/chio-conformance/verdict_matrix/src/cross_language.rs`)
  has fail-closed semantics: any driver that emits a tuple MUST
  agree with the expected tuple AND with every other emitting
  driver. Drivers in `unsupported` status emit no tuple; they do
  not contribute to the diff.
- For Python and Go to flip from advisory to required, the
  workflow must add a required job that runs each driver against
  all 48 scenarios and asserts zero divergences. This is two
  new YAML jobs (or two new matrix entries on the existing
  job) plus the source-side change that promotes
  `status = "active"` in `manifest.toml`.

Two-consecutive-green rule: from M02.P3.T1 promotion contract.
The verdict-matrix flip mirrors mutation: two consecutive nightly
runs at zero divergence per driver, recorded in the M04 audit
doc, then the M04.P4 PR adds `required: true` to the Python /
Go matrix entries.

What flipping fails-closed on:
- Mutation lane: caught-ratio-below-target on any of the six
  trust-boundary crates fails the PR. Per-crate; one crate's
  regression fails everything.
- Verdict matrix: any driver that emits a tuple disagreeing with
  the expected tuple fails the PR (already enforced for
  rust-kernel + deployment-shape; M04.P4 extends the contract to
  python-sdk + go-http-sdk).
- Verdict matrix: a driver that reports `unsupported` does NOT
  fail the gate today; M04 P2 closes the unsupported population
  to zero on Python and Go before P4 makes that contract
  load-bearing.

## Per-phase research findings (P0-P5)

### P0: Audit doc baseline + per-crate kill-score floor

P0 deliverable: open `.planning/trajectory-3/audits/M04-mutation-gate.md`
(template already in place) and fill section 2 ("Hard counts at P0")
and section 3 ("Verdict-matrix advisory baseline").

Hard counts to capture:
- Run `cargo mutants --json | jq` per crate; record per-crate
  evaluated / caught / missed / unviable / timeout. Use full
  sweeps where the listed-mutants count is small (<= 100); use
  bounded shards for `chio-policy` (418), `chio-guards` (1298),
  `chio-anchor` (249). Prior baselines used 1/16 and 1/32 shards;
  the M04 baseline should run full sweeps at least once for
  every crate so the audit has a credible per-crate full-sweep
  number to flip the gate against.
- Verdict-matrix advisory baseline: enumerate per-driver
  divergences from the diff oracle. Today divergences are zero
  for rust-kernel + wasm-browser (where wasm-browser emits
  tuples on the 12 capability scenarios it handles). Python
  emits 12 tuples; assert they agree with rust-kernel. Go emits
  zero tuples; the gap is `unsupported` count, not divergence.

Ticket P0.T1 should require commit message format
`feat(audit): open M04 mutation-gate audit doc with P0 baseline`
and the audit doc must include the literal phrase "trajectory-2
M02 closeout 30.7% aggregate" so downstream tickets can grep
for it.

P0 honest-threshold checkpoint date: pinned at week 12.
Trajectory week 1 is the first business week post merge of the
trajectory-3 README; M04 wave is W1 so P0 lands week 1, P3 flip
lands week 12. The actual calendar pin is set on the audit doc
at P0 close.

### P1: Kill-score improvement work on lagging crates

P1 ticket suggestions, ordered by slope:

- P1.T1: `chio-credentials` `is_supported_*_schema` predicate
  closure. Add `tests/schema_negative.rs` with assertions for
  unsupported schemas and OR/AND boundary cases. Target: kill
  16 missed mutants -> kill rate ~92%.
- P1.T2: `chio-kernel-core` proptest crate addition + generators
  for `NormalizedScope`, `NormalizedToolGrant`,
  `NormalizedResourceGrant`, `NormalizedPromptGrant`. Target:
  kill ~120 missed mutants concentrated in `normalized.rs`.
- P1.T3: `chio-kernel-core` `scope.rs` proptests for
  `wildcard_matches`, `path_has_prefix`, `parse_domain`,
  `normalize_path`. Target: kill ~50 missed mutants.
- P1.T4: `chio-attest-verify` fixture suite. Add three fixture
  families under `crates/chio-attest-verify/tests/fixtures/`:
  cert-time (NotBefore future, NotAfter past), malformed-chain
  (wrong CA), oidc-mismatch (wrong issuer). Author negative
  tests that exercise `validate_against_fulcio`,
  `match_identity`, `read_oidc_issuer_extension`. Target: kill
  ~25-30 missed mutants. >= 65% by week 12.
- P1.T5: `chio-policy` full sweep + boundary tests for
  `validate.rs`, `conditions.rs`, `compiler.rs`. Target: kill
  ~250 missed mutants out of ~418-(unviable).
- P1.T6: `chio-guards` and `chio-anchor` full sweeps + targeted
  test work. May be too long for one ticket; if so split per
  crate.

### P2: Verdict-matrix non-Rust driver completion (M02 surface)

Per the milestone narrative: "M04 verdict-matrix non-Rust driver
completion is gated on M02 Python / Go drivers passing." The
freeze `m02-m04-verdict-matrix-coupling` enforces M02 P2 (Python)
and P3 (Go) closing before M04 P3 opens. So M04 P2 is the
bridge: it consumes the M02 outputs and verifies them against
the corpus. M04 itself does NOT author the Python / Go verdict
emitters; M02 does. M04 P2 verifies their `status = "active"`
landing and confirms zero unsupported / zero divergence.

P2 ticket suggestion:
- P2.T1: assertion ticket. Confirm
  `crates/chio-conformance/verdict_matrix/manifest.toml` records
  `[drivers.python-sdk] status = "active"` and
  `[drivers.go-http-sdk] status = "active"`. Run each driver and
  parse `unsupported_count == 0` and `failed_count == 0`.
- P2.T2: cross-language diff confirmation. Run
  `cargo test -p chio-conformance --test verdict_matrix_cross_language --quiet`
  with all four primary drivers active (Rust, Python, Go,
  TS-via-sidecar OR with TS still transport-client). Capture the
  green run URL.
- P2.T3: two-consecutive-green nightly observation. The
  promotion contract from trajectory-2 M02.P3.T1 requires two
  consecutive nightly verdict-matrix runs at zero divergence
  before P4 flip.

If M02 fails to deliver Python / Go in time, M04 P2 falls back to
the D08 honest-threshold for verdict-matrix: ship the Python +
TypeScript pair as required, leave Go as advisory. This is NOT
in the milestone narrative; it is an open question for IMPLEMENT
(see end of doc).

### P3: Mutation lane flip to required

P3 deliverable: edit `releases.toml` to set:
- `cycle_end_tag = "<release tag>"` (e.g. `v3.20.0`)
- `observed_consecutive_nightly_successes = 2`
- `activation_evidence = "<YAML block per honest-threshold playbook>"`
- (new) `activation_threshold_percent_per_crate = <65 or 80>`

Plus update `scripts/mutants-gate.sh` to read the new field with
fallback to `target_catch_ratio_percent`. The freeze
`m04-mutation-gate-pivot` covers `.cargo/mutants.toml`,
`mutants-baseline.toml`, and the workflow files; the P3 PR is
the only PR allowed to touch them in P3-P5.

P3 also updates README mutation kill-score banner via
`.github/workflows/mutants-banner.yml` so the auto-update PR
reflects the activated thresholds.

P3.T1 carries the D08 floor-vs-target rule explicitly: if any
crate is below 80% but at or above 65%, the activation evidence
records the gap and the gate uses the achieved threshold.

### P4: Verdict-matrix non-Rust drivers flip to required

P4 deliverable: edit `.github/workflows/verdict-matrix.yml` to
add new required jobs for `python-sdk` and `go-http-sdk`. The
job runs the driver entrypoint command and asserts zero
divergence against the rust-kernel reference via
`verdict_matrix_cross_language`. Mirror the
`deployment-shape-smoke` pattern. The two-consecutive-green
prerequisite from P2.T3 is the gate for opening this ticket.

The freeze covers `.github/workflows/verdict-matrix.yml`; P4 is
the only window to edit it.

### P5: M04 audit doc records achieved threshold

P5 deliverable: complete `.planning/trajectory-3/audits/M04-mutation-gate.md`
sections 4 (honest-threshold contingency record) and 5 (closure
attestations). Cross-reference the activation_evidence YAML in
`releases.toml` and the verdict-matrix flip PR. Update
`mutants-baseline.toml` in trajectory-3 with the post-P3
per-crate kill scores and the aggregate. The M04 audit doc is
the artifact M08 reviewer cites.

## Coordination with M05 (attest-verify freeze)

`m04-m05-attest-verify-coupling` (freezes.yml lines 130-141)
covers `crates/chio-attest-verify/src/**` for M04 P3-P5. The
trust-boundary handoff: M04 P3 close (gate flip) is a
precondition for M05 starting `dispatch_allow.rs` work in
m05-threat-coverage-pivot. The mutation gate must be live BEFORE
M05 source edits begin, so any M05 edit that lowers the
chio-attest-verify kill score below the activation threshold
will fail the gate-flip PR.

Practical sequence:
1. M04 P1 (which raises chio-attest-verify) finishes.
2. M04 P3.T1 PR flips the gate. Freeze opens.
3. M05 P2.T1 (`dispatch_allow` placeholder eviction) opens
   AFTER M04.P5.T5 closes the freeze. M05 source edits land
   under the now-active gate.

If M04 P1 cannot raise chio-attest-verify to >= 65% by week 12,
the D08 honest-threshold says ship at the lower achieved value;
M05 inherits the gate at that level. M05 must NOT regress it.

## Coordination with M02 (verdict_matrix freeze)

`m02-m04-verdict-matrix-coupling` (freezes.yml lines 142-153)
covers `crates/chio-conformance/verdict_matrix/**` for M02 P2-P3.
M02 P2 (Python driver) and M02 P3 (Go driver) must close BEFORE
m04-mutation-gate-pivot opens (M04 P3). This means the verdict
matrix non-Rust drivers reach `passing` BEFORE the M04 gate flip.

Practical sequence:
1. M02 P2.T1 lands Python verdict emitter; manifest status
   becomes `active`. Freeze closes M02 P3.T5.
2. M02 P3 lands Go verdict emitter; manifest status becomes
   `active`.
3. M04 P2 verifies (no source authorship; verification only).
4. M04 P3 (gate flip) opens.
5. M04 P4 (verdict-matrix flip) lands.

If M02 cannot deliver both drivers, M04 P4 either degrades
(only Python required, Go advisory) or slips. M02 flagged this
as a P5 carry-forward in trajectory-2; the trajectory-3 M02
narrative names Anthropic / METR / Apollo as the partner
shortlist (D10) but the partner ask is independent of the
driver work.

## External-vendor handoff (M08)

M08 reviewer (NCC Group OR Trail of Bits per D12) cites the M04
mutation gate value in the final report (per `08-independent-crypto-protocol-review.md`
line 118: "M08 reviewer cites M04 mutation gate value").

The M04 -> M08 handoff artifact set:

1. Mutation kill-score memo: a one-page summary at
   `.planning/trajectory-3/audits/M04-mutation-gate.md` section
   3 (per-crate full-sweep kill rates), section 4 (honest-threshold
   record), and section 5 (closure attestations).
2. Gate-flip-evidence YAML embedded in `releases.toml: activation_evidence`.
3. Verdict-matrix corpus hash + driver inventory (manifest.toml).
4. Two consecutive nightly run URLs (linked from the
   activation_evidence block).
5. (Optional but high-value) survivor inventory: a list of
   skip-listed mutants with rationale, per `scripts/check-mutants-rationale.sh`,
   so M08 reviewer can audit whether skips are honest. M02
   already maintains per-crate `crates/<name>/mutants.toml` with
   rationales; M04 P5 should pin the SHAs of those files.

The M08 reviewer's task per the milestone narrative: cross-check
the gate value against the achieved threshold, comment on
honesty (gap vs aspirational target), and quote the value in the
report. M04 P5 audit doc must be in the form a vendor can quote
verbatim.

## Risk register

1. **80% target unreachable in 9 weeks** (D08 invokes). High
   probability for chio-attest-verify; medium for chio-kernel-core.
   Mitigation: ship at honest threshold (target 80%, accept 65%
   floor). Document gap in audit. Do NOT slip M08.
2. **chio-attest-verify kill rate stays below 65%**. Mitigation:
   (a) widen skip-list with audited rationale; (b) accept 50%
   floor as second-stage honest threshold and surface to user as
   D08 amendment. Halt trigger: notify user.
3. **Driver promotion blocks on chio-kernel-browser surface**.
   Out of scope for M04 (TS/WASM are M02 owned), but if M02
   cannot land the Python + Go drivers, M04 P4 must degrade (see
   Open Questions). Probability medium.
4. **Flipped gate fails on first nightly post-flip**. Probability
   medium-high; the activation streak is two greens but
   day-three regression is realistic. Mitigation: P3 PR must
   include a same-day rollback recipe (`cycle_end_tag = ""` PR
   with `mutants-gate-override` title; CODEOWNERS approval).
5. **CI runner budget regression**. The 1800-min/30-day envelope
   is shared with fuzz lanes (`scripts/check-fuzz-budget.sh`).
   Mutation full sweeps on chio-guards (1298 mutants) and
   chio-policy (418) are wall-time-heavy; the per-crate 4h
   nightly budget may not fit. Mitigation: shard the nightly
   sweep across runs; aggregate across multiple cron triggers;
   document if the activation streak is achieved via aggregated
   shards rather than single full sweeps.
6. **Skip-list rationale gaming**. Tempting to skip-list
   chio-attest-verify mutants en masse to "achieve" 65%. The
   M08 reviewer audit catches this. Mitigation:
   `scripts/check-mutants-rationale.sh` requires a citation per
   skip; CODEOWNERS gate enforces that. Each skip-list addition
   in M04 P1 must cite a real coverage source (integration test
   or fuzz target name).
7. **Verdict-matrix corpus drift between M02 P3 and M04 P4**.
   Mitigation: the freeze sequence enforces M02 P3 close before
   M04 P3 open, but a between-window M02 hot-fix could land.
   `m02-m04-verdict-matrix-coupling` covers
   `crates/chio-conformance/verdict_matrix/**`; the manifest
   hash check in `diff_oracle_self_test.rs` catches drift.

## Recommended ticket scaffold

P0 (1 ticket):
- T1: open M04 audit doc with P0 baseline (per-crate full-sweep
  numbers from `cargo mutants --json | jq`, verdict-matrix
  driver inventory, week-12 calendar pin). Touches
  `.planning/trajectory-3/audits/M04-mutation-gate.md` and
  `.planning/trajectory-3/mutants-baseline.toml`.

P1 (5-6 tickets):
- T1: chio-credentials closure -> >= 90%.
- T2: chio-kernel-core normalized.rs proptests -> kill ~120
  mutants.
- T3: chio-kernel-core scope.rs proptests -> kill ~50 mutants.
- T4: chio-attest-verify fixture suite + negative tests ->
  >= 65%.
- T5: chio-policy full sweep + boundary tests -> >= 80%.
- T6: chio-guards + chio-anchor full sweeps + targeted tests
  (split into T6a / T6b if budget allows).

P2 (3 tickets):
- T1: verify M02 Python driver landed at `status = "active"`;
  zero unsupported.
- T2: verify M02 Go driver landed at `status = "active"`; zero
  unsupported.
- T3: two-consecutive-green nightly observation captured in the
  audit doc.

P3 (1-2 tickets):
- T1: gate-flip PR. Edits `releases.toml` (cycle_end_tag,
  observed_consecutive_nightly_successes, activation_evidence,
  new activation_threshold_percent_per_crate). Edits
  `scripts/mutants-gate.sh` to honor new field. Edits
  `.github/workflows/mutants.yml` only if a workflow change is
  unavoidable (likely none). README banner update via
  mutants-banner.yml auto-update PR.
- T2 (optional): updates docs/fuzzing/mutants.md to reflect
  active blocking posture and document the override path.

P4 (1-2 tickets):
- T1: verdict-matrix non-Rust drivers flip in
  `.github/workflows/verdict-matrix.yml`. New required matrix
  entries for python-sdk and go-http-sdk that assert zero
  divergence vs rust-kernel.
- T2 (optional): docs/conformance/verdict-matrix.md update with
  the new required-driver list.

P5 (1-2 tickets):
- T1: M04 audit doc closure. Records achieved kill-rate per
  crate, per-driver active status, gate-flip-evidence YAML
  embedded reference, M08 handoff.
- T2 (optional): mutants-baseline.toml final post-flip
  aggregate.

Total: 11-15 tickets across 6 phases, 9-13 calendar weeks at
~5 FTE engineering.

## Open questions for IMPLEMENT phase

1. Should the mutation gate ship at a per-crate floor (each
   crate >= 65%) or an aggregate floor (sum / weighted average
   >= 65%)? The audit doc and `scripts/mutants-gate.sh` today
   imply per-crate. D08 implies per-crate ("ship gate at the
   achieved threshold") but does not name the unit.
   Recommendation: per-crate, with the audit doc carrying the
   highest per-crate gap as the headline number.

2. If M02 fails to deliver the Go driver in time, does M04 P4
   flip Python + advisory Go, or block on Go? The freeze
   sequence implies block; the D08 honest-threshold suggests
   degrade. IMPLEMENT must pick one before P4 ticket text is
   written.

3. Does the new `activation_threshold_percent_per_crate` field
   in `releases.toml` need a per-crate map (some crates flipped
   at 80, others at 65)? If yes, the field shape changes from
   scalar to table; `scripts/mutants-gate.sh` needs the
   corresponding parsing code. Recommendation: scalar (single
   floor across all crates) for simplicity, with the per-crate
   numbers captured in `activation_evidence` only.

4. The prompt mentions chio-weights, chio-custody-hw, and
   chio-cross-protocol as "highest-priority crates". These are
   NOT in the D06 six-crate set. Confirm: is the prompt asking
   M04 to widen the gate beyond the D06 set, or are these crates
   under M05 / M07 mutation surfaces? Recommendation: keep D06
   binding; do NOT widen.

5. The CI artefact retention for `mutants-nightly` is 30 days.
   The activation evidence references run URLs that may expire.
   Should P5 commit the JSON artifact to the repo for permanent
   record? Recommendation: yes, under
   `.planning/trajectory-3/audits/M04-mutation-gate-evidence/`
   with two committed JSONs (the two consecutive nightly runs).

6. Does the M04 audit doc need a section explicitly responding
   to D08 ("if 80% not reached, ship at achieved")? The
   template's section 4 is partial; IMPLEMENT may want to widen
   it.

7. The verdict-matrix flip mirrors the M02.P3.T1 promotion
   contract (two consecutive greens). Are the two green runs
   counted from the cross-language matrix, or from per-driver
   smoke tests? Recommendation: cross-language matrix, since
   that is what `verdict-matrix.yml` already runs as required.

8. The gate-flip rollback recipe (per Risk 4) needs to be
   tested. Should P3 include a dry-run of the override path
   (`MUTANTS_GATE_OVERRIDE_REASON` env-var) as part of the PR
   green checks? Recommendation: yes, add a one-time CI run
   under the P3 PR that exercises the override path so the
   rollback is proven.

## Document control

- Source-of-truth files cited: `.planning/audits/M02-mutation-and-verdict-matrix.md`,
  `.planning/trajectory-2/mutants-baseline.toml`,
  `.planning/trajectory-3/04-mutation-and-verdict-matrix-promotion.md`,
  `.planning/trajectory-3/audits/M04-mutation-gate.md`,
  `.planning/trajectory-3/decisions.yml`,
  `.planning/trajectory-3/freezes.yml`,
  `.planning/trajectory-3/tickets/M04/README.md`,
  `.cargo/mutants.toml`,
  `.github/workflows/mutants.yml`,
  `.github/workflows/verdict-matrix.yml`,
  `releases.toml`,
  `scripts/mutants-gate.sh`,
  `crates/chio-conformance/verdict_matrix/manifest.toml`,
  `crates/chio-conformance/verdict_matrix/drivers/python/run_scenarios.py`,
  `crates/chio-conformance/verdict_matrix/drivers/go/run_scenarios.go`.
- All hard counts dated 2026-04-30.
- House rules respected: no em-dashes; Chio name preferred; no
  emoji; conventional-commits style implied for tickets.
