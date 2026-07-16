# FV-E5: Lane ratchets and strict-mode honesty

Status: Implemented (2026-07-10; hosted promotion streak incomplete)
Theme: E - Verify the verification, and make lanes bite
Effort: S-M
Depends on: [FV-E3](FV-E3-pr-formal-smoke-tier.md) (the lanes must exist before their postures can ratchet)
Feeds: [FV-C5](FV-C5-proof-coverage-map.md) (gate postures join the coverage map), release qualification
Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md) (G1 and G5 posture), [FV-E1](FV-E1-spec-mutation-testing.md), [FV-B4](FV-B4-loom-registry-and-dst.md), `scripts/mutants-gate.sh`, `releases.toml`, `docs/release/RISK_REGISTER.md`

## Summary

The mutation lane retains its reviewed evidence ratchet in
`scripts/mutants-gate.sh`. Pass/fail proof and corpus lanes use fifteen
`[gates.<lane>]` entries in `releases.toml`, exact job-level GitHub Actions
history, reset boundaries, freshness limits, and release-fleet enforcement.
Proof reports record `mode = strict | metadata_only`. Release qualification
requires strict mode. Metadata-only reports run the C5 coverage preflight and
record every proof command as `not_run`.

## Motivation and evidence

Repository observations:

- The mutants ratchet pattern exists and works as designed: `scripts/mutants-gate.sh:144-153` exits advisory while `cycle_end_tag` is empty or the streak is short; `releases.toml:177-209` holds the schema (`target_catch_ratio_percent = 80`, `required_consecutive_nightly_successes = 2`, `observed_consecutive_nightly_successes = 0`, `cycle_end_tag = ""`), with a CODEOWNERS-gated lifecycle documented in its header (lines 39-79).
- But the streak field is a manually maintained repo-state counter (`observed_consecutive_nightly_successes`, updated by CODEOWNERS-reviewed PR per `releases.toml:43-49,64-79`). That is appropriate for the mutants lane, where "success" means a judged kill-rate score; it does not scale to pass/fail lanes, where the workflow conclusion IS the evidence and a hand-copied counter can only go stale.
- The registry covers ten scheduled jobs and five pull-request jobs. All
  fifteen are advisory. Six path-scoped or reliability-constrained entries
  are frozen.
- `CHIO_RUST_VERIFICATION_METADATA_ONLY=1` still supports toolchain-outage
  diagnostics. It produces a `metadata_only` report with one passed coverage
  preflight and `not_run` proof gates. Release qualification rejects that mode.
- The strict Rust verification claim rule in `docs/release/RISK_REGISTER.md` is
  enforced by the protected, adjacent report generation and structural check
  in `scripts/ci-workspace.sh`.

## Current state

- `releases.toml` carries the pass/fail lane registry alongside the unchanged `[mutants]` evidence model and remains CODEOWNERS-gated.
- `scripts/lane-gate.sh` validates section-aware TOML with `tomllib`, counts exact job display names after each lane's reset, excludes dispatch runs, and checks freshness. `--fleet` evaluates required lanes during release qualification.
- `target/formal/proof-report.json` has a required global `mode`. The checker
  verifies the exact manifest command order, status and exit-code consistency,
  current on-disk hashes, tool probes, Aeneas outputs, source locations, and
  report plus coverage commit binding.
- Nightly uploads the proof report and coverage JSON in one dynamically named
  artifact. Release qualification copies both files into its checksummed
  `formal/` evidence directory.

## Design

### Part 1: generic lane gates

`releases.toml` carries one table per lane:

```toml
[gates.kani-public-nightly]
workflow = "nightly.yml"
job = "kani-public-nightly (lanes.pr + lanes.nightly_only)"
event = "schedule"
posture = "advisory"          # advisory | required
required_streak = 7
evidence_after_run_id = 29003108285
max_age_hours = 48

[gates.formal-qualification]
workflow = "nightly.yml"
job = "formal-qualification (proof report + portable + SDK parity)"
event = "schedule"
posture = "advisory"
required_streak = 7
evidence_after_run_id = 29003108285
max_age_hours = 48
strict_mode_required = true    # a metadata_only night does not count toward the streak
strict_artifact_prefix = "formal-proof-report-strict-"

[gates.apalache-safety]
workflow = "apalache-safety.yml"
job = "apalache-subset"
event = "schedule"
posture = "advisory"
required_streak = 7
evidence_after_run_id = 29012047382
max_age_hours = 48

[gates.apalache-negative]
workflow = "apalache-safety.yml"
job = "apalache-negative"
event = "schedule"
posture = "advisory"
required_streak = 7
evidence_after_run_id = 29086573702
max_age_hours = 48

[gates.apalache-temporal]
workflow = "apalache-temporal.yml"
job = "formal-tla-liveness"
event = "schedule"
posture = "advisory"
required_streak = 7
evidence_after_run_id = 29012076489
max_age_hours = 48
frozen = true                  # header precondition: reliably green + property fixed
frozen_reason = "apalache-temporal.yml header forbids promotion until the underlying property is fixed"

# Pull-request lanes additionally name the intended base branch and an exact
# per-run, per-attempt execution-marker artifact prefix. They remain frozen
# until the workflow is run-always and uploads that marker only after real
# verification work succeeds.
```

Field semantics: `posture` drives the gate exit code; `required_streak` is the
consecutive matching-event job-success count; `evidence_after_run_id` is an
exclusive reset; and `max_age_hours` is the fleet freshness bound.
`base_branch` excludes pull requests targeting another integration branch.
`execution_artifact_prefix` names a marker ending in the exact run ID and run
attempt. `frozen = true` rejects required posture at load time. The existing
`[mutants]` table is not migrated because its judged, CODEOWNERS-attested
evidence flow is intentionally different.

Required posture also requires an inline `promotion_evidence` table. Its
`run_ids` list contains exactly `required_streak` unique IDs newer than the
reset, and `report_sha256` is the lowercase SHA-256 of the exact reviewed
`--report` output. Advisory lanes cannot carry this field.

`scripts/lane-gate.sh <lane-name>`:

- Parses its `[gates.<lane>]` table with python3 tomllib (the pattern `check-corpus-metadata.sh` uses); bash-only section-aware TOML parsing is not worth reimplementing, and every CI job here already has python3.
- Stateless streak computation at gate time via the GitHub API, no repo-state counter to maintain:

  ```bash
  gh api \
    "repos/${REPO}/actions/workflows/${WORKFLOW}/runs?event=schedule&status=completed&per_page=100&page=1"
  ```

  Fetch matching workflow runs newest-first and stop after the required streak
  or first barrier. At most ten pages are considered. Only the exact job name
  and latest attempt count. Pull-request runs must target `base_branch` and
  carry the exact unexpired execution marker. Warning mode applies only to
  positively identified rate limits, transport failures, or temporary 502,
  503, and 504 responses. Malformed JSON, 404s, corrupt timestamps, duplicate
  runs, and attempt mismatches always fail.
- Exit semantics: `posture = advisory` always exits 0 and reports the current job result without masking it; `posture = required` exits 1 when the lane's current job failed (the caller passes `LANE_EXIT`). In fleet mode, missing, stale, non-strict, or unsuccessful latest evidence for any required lane fails release qualification. Output uses stable `lane-gate:`, `lane-gate-evidence:`, and `lane-gate-barrier:` prefixes.
- Every integrated registered job has a final `if: always()` call site.
  `scripts/lane-gate.sh --fleet` runs after strict workspace qualification and
  blocks releases when a required lane is unhealthy.

### Promotion runbook (documented in the script header and docs/formal/ROADMAP.md)

1. A lane accumulates `required_streak >= 7` consecutive successes for its configured event and exact job display name (checked with `scripts/lane-gate.sh <lane> --report`). Evidence must be after the reset and fresh.
2. A posture-flip PR edits only `releases.toml`: set `posture = "required"`
   and add `promotion_evidence = { run_ids = [...], report_sha256 = "..." }`.
   Paste the exact `--report` output (run IDs, attempts, and dates) in the PR
   body so reviewers can verify its digest. CODEOWNERS review applies
   automatically since `releases.toml` is CODEOWNERS-gated. No enforcement-test
   edit is part of promotion.
3. A pull-request lane cannot be promoted while frozen. First replace the
   workflow-level path filter with a run-always aggregator, bind the registry
   entry to its intended base branch, and make the real proof job upload
   `execution_artifact_prefix + run_id + "-" + run_attempt` only after the
   verification command succeeds. A successful skip must not upload a marker.
4. After merge, adding the check to branch protection is a manual admin step
   in the ruleset UI, using the exact reported check name. A registry edit
   cannot update repository rulesets.
5. Demotion sets posture back to advisory, removes `promotion_evidence`, and
   adds an incident note. A frozen lane cannot be promoted until the same
   reviewed change resolves its reason.
6. Scheduled-only lanes are required in the fleet sense only: they gate
   releases via `--fleet`, not PR merges.

### Part 2: record the mode, close the escape hatch

Implemented behavior:

1. `scripts/generate-proof-report.sh` derives one global mode. Both modes first
   run `cargo xtask gen proof-coverage --check`. Metadata-only mode records that
   preflight as passed and every proof command as `not_run`. Strict mode runs
   the exact manifest command set and rejects a dirty worktree before or after
   execution. The trusted generator process attests the recorded gate statuses.
   The generator, checker, claim inputs, and proof sources are tracked hashes.
2. `scripts/check-proof-report.sh` loads the proof manifest and requires the
   exact unique command order. It checks every status against its exit code,
   compares every tracked and generated hash with disk, requires all strict
   tool probes and Aeneas artifacts, resolves each inventory entry to exactly
   one declaration, requires a clean strict worktree, and binds the report and
   coverage JSON to `HEAD` and `GITHUB_SHA` when present. It validates the
   generator's evidence; it does not replay proof commands.
3. `scripts/ci-workspace.sh` always generates a report and requires strict
   mode. Nightly records the mode and uploads the report plus coverage JSON as
   `formal-proof-report-<mode>-<run-id>-<run-attempt>` with missing files fatal.
4. Formal-qualification streak evidence requires the exact unexpired strict artifact name, including both run ID and latest run attempt. A strict artifact from an earlier attempt of the same run cannot satisfy a later metadata-only attempt. A metadata-only night may remain diagnostic and green, but it cannot count toward promotion.

## Implementation plan

1. [x] Phase 1 - mode recording and strict/metadata consistency tests.
2. [x] Phase 2 - unconditional report generation in workspace and nightly callers, with strict mode required for release qualification.
3. [x] Phase 3 - job-level lane gate, mocked API tests, reset and freshness policies, and advisory registry entries.
4. [x] Phase 4 - terminal call sites for all covered jobs plus release-fleet enforcement.
5. [x] Phase 5 - promotion, ruleset, reset, nightly-only, and demotion runbook.
6. [x] Phase 6 - all five pull-request jobs and ten scheduled jobs are
   registered. Future score-based or simulation lanes add their own tables
   when their workflows land.

## CI and gating changes

- Each covered job has a terminal lane-gate step. Advisory posture logs
  evidence and preserves the underlying job result. B2 adds the
  `apalache-negative` job after this isolated E5 change. Its integration must
  add `actions: read` and this terminal step to that job:

  ```yaml
  - name: Record negative Apalache lane posture
    if: always()
    env:
      GH_TOKEN: ${{ github.token }}
      LANE_EXIT: ${{ job.status == 'success' && '0' || '1' }}
      LANE_GATE_RATE_LIMIT_MODE: warn
    run: bash scripts/lane-gate.sh apalache-negative
  ```
- Release qualification enforces `check-proof-report.sh --require-strict` through `ci-workspace.sh` and then evaluates `lane-gate.sh --fleet`. Both are fail-closed.
- No branch-protection changes in this document; the runbook governs those, manually, per promotion.
- API budget: workflow history is fetched lazily in pages and stops at the
  streak threshold or first barrier. Job and artifact queries stop with it.
  Advisory call sites use warning mode only for rate limits and transport
  outages. Release qualification never enables warning mode.
- The apalache-temporal lane stays excluded from promotion by the `frozen` flag until its header's reliably-green precondition is met [v]; the flag makes the exclusion load-bearing instead of a comment.

## Acceptance criteria

- [x] `target/formal/proof-report.json` records strict or metadata-only mode,
  coverage preflight semantics, exact commands, hashes, artifacts, and commit
  binding.
- [x] Metadata-only release qualification fails at `--require-strict` with the formal claim-rule message.
- [x] A metadata-only nightly is visible in the summary and artifact name and
  cannot count toward the formal-qualification streak.
- [x] Lane reports use event-filtered, exact job-level history after a reset and
  print run IDs, attempts, and dates. Mocked dispatch exclusion and reset
  boundaries pass.
- [x] Required posture on a frozen lane fails at load time.
- [x] `releases.toml` carries fifteen advisory `[gates.*]` tables with exact
  workflow and job identities. Evidence scripts, the manifest, Apalache files,
  affected workflows, and the registry have CODEOWNERS protection.
- [x] Path-scoped PR entries remain frozen until a run-always aggregator and
  real-execution marker uploader are reviewed.
- [x] Release qualification runs `lane-gate.sh --fleet`, which rejects missing, stale, failed, or non-strict evidence for required lanes.
- [x] The promotion runbook includes manual ruleset work, PR self-skip behavior, nightly-only semantics, resets, and demotion.
- [x] `[mutants]` behavior and output are unchanged.

## Risks and mitigations

- GitHub API unavailability at gate time. Mitigation: fail closed by default.
  Advisory callers may warn only on positively identified rate limiting,
  transport failure, or temporary 502, 503, and 504 responses. Evidence
  integrity errors remain fatal.
- Streak gaming via reruns: re-running a failed scheduled run in the UI can replace the latest attempt's conclusion. Mitigation: count each run once using only its latest job attempt, and require strict proof artifacts to match that attempt. A rerun-to-green still reflects a real green at that commit; if this proves abusable, restrict evidence to first attempts in a follow-up policy change.
- A required nightly lane reds for an environmental reason and blocks a release. Mitigation: that is the designed behavior (the release claim depends on the lane); the demotion PR path plus the `MUTANTS_GATE_OVERRIDE_REASON`-style audit-logged override can be added to lane-gate if a release-train hotfix ever needs it, with the same audit-row discipline as `mutants-gate.sh:257-280`. Not included initially: fewer escape hatches is the point of this document.
- Two gate scripts (mutants-gate, lane-gate) confuse contributors. Mitigation: cross-referencing comments in both plus one paragraph in `docs/fuzzing/mutants.md`; unifying them is deliberately out of scope because the mutants evidence model is human-attested.
- Mode recording relies on callers passing the env var honestly. Mitigation:
  `generate-proof-report.sh` reads the variable itself, strict generation
  requires a clean worktree, and the report hashes the generator, checker,
  claim inputs, verification scripts, and proof sources.

## Decisions

- Freshness is load-bearing. Daily and scheduled corpus lanes use 48 hours; pull-request lanes use 168 hours. Required release-fleet checks fail on missing or stale evidence.
- Every lane starts with a seven-success threshold. Apalache safety and
  negative-test promotion use scheduled evidence only. Pull-request histories
  are scoped to `main`.
- Proof mode is global because every proof gate shares one execution policy.
  Metadata-only reports require the coverage preflight to pass and every proof
  gate to be `not_run`; any other mix fails.
- Strictness evidence uses the uploaded artifact name `formal-proof-report-<mode>-<run-id>-<run-attempt>`, and the job summary shows the same mode. Historical formal-qualification success counts only when the exact latest job attempt has an unexpired strict artifact. Artifacts from earlier attempts of the same run are rejected.
- Job history, not workflow conclusion, is authoritative. The configured display name must match exactly once in a run.
- Reset boundaries are configuration cutoffs, not hosted success claims. No
  qualifying post-reset hosted streak is recorded by this change. Promotion
  evidence remains pending for every lane.

## Manifest and registry updates

- `releases.toml`: fifteen advisory `[gates.*]` tables cover ten scheduled and
  five pull-request lanes. Six entries are frozen until their documented
  hosted preconditions are met.
- `target/formal/proof-report.json` schema: new required top-level `mode` and
  `evidenceBoundary` fields; consumers are `check-proof-report.sh` (updated
  here) and the formal-evidence bundle.
- `docs/release/RISK_REGISTER.md`: the Creusot/Kani claim rule names protected
  strict generation followed immediately by `check-proof-report.sh
  --require-strict` as its release-qualification enforcement.
- `docs/reference/CLAIM_REGISTRY.md` and `docs/formal/COVERAGE.md`: supplied by
  C5 integration. The generator requires both and fails closed when that
  integration is absent.
- `docs/formal/GAP_ANALYSIS.md`: G1 records the active posture machinery and G5 records strictness-mode enforcement.
- `.github/workflows/apalache-safety.yml`: B2 integration must append the
  documented terminal `apalache-negative` lane-gate step because that job is
  not present in the isolated E5 commit.
