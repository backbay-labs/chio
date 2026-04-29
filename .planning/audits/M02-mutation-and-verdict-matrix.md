# M02 Mutation And Verdict Matrix Audit Baseline

This audit opens trajectory-2 M02, "Mutation Gate + Cross-SDK Verdict
Differential". It is a documentation-only baseline for P0.T1. No CI,
lockfile, code, or workflow behavior is changed here.

Source-of-truth: `.planning/trajectory-2/02-mutation-and-cross-sdk-differential.md`.
Ticket: `M02.P0.T1`.
Snapshot date: 2026-04-29.

## Purpose

M02 has two quality surfaces:

- Mutation testing asks whether existing trust-boundary tests actually kill
  meaningful source-level changes.
- The verdict matrix asks whether SDK and kernel surfaces agree on the same
  `(verdict, reason_code, scope_set)` tuple for the same scenario.

This P0 audit records the starting state before M02 changes either surface.
Later M02 phases should update this file with kill scores, before and after
counts, scenario counts, and corpus hashes.

## Source References

| Reference | Baseline note |
|-----------|---------------|
| `.planning/trajectory-2/02-mutation-and-cross-sdk-differential.md` | Defines M02 scope: promote deferred trajectory-1 mutation work, widen mutation coverage to six trust-boundary crates, and add `crates/chio-conformance/verdict_matrix/`. |
| `.planning/trajectory/02-fuzzing-post-pr13.md` | Defines the original mutation-testing approach: `cargo-mutants` 25.x, four trust-boundary crates, >= 80% catch ratio, advisory for one release cycle, then blocking. |
| `.planning/trajectory/EXECUTION-STATE.json` | Records trajectory-1 M02 mutation config and advisory workflow as merged: M02.P2.T1 at `92f1b71c848db6f2bd54165195309bc4a9d22f4f`, M02.P2.T2 at `386290d26880705259d694eaf1bd3e746e9d213d`. |
| `.planning/trajectory-2/tickets/M02/P0.yml` | Defines this ticket gate: create this audit doc and include the phrase `trajectory-1 M02.P3 advisory state`. |

## trajectory-1 M02.P3 advisory state

The live repository starts M02 with trajectory-1's mutation lane present but
not yet load-bearing as a required gate.

| Surface | Live state | M02 implication |
|---------|------------|-----------------|
| `.cargo/mutants.toml` | Present as the workspace-root cargo-mutants config. It sets `additional_cargo_test_args = ["--workspace", "--exclude", "chio-cpp-kernel-ffi"]`, `timeout_multiplier = 3.0`, and `minimum_test_timeout = 60`. Its `examine_globs` cover `chio-kernel-core`, `chio-policy`, `chio-guards`, and `chio-credentials`. | P1 and P3 must widen the trust-boundary set to include `chio-attest-verify` and `chio-anchor` before the lane can satisfy trajectory-2 M02. |
| Per-crate `mutants.toml` files | None found in the live worktree with `find crates -path '*/mutants.toml' -print`. The workspace config explicitly says cargo-mutants 25.x does not auto-discover per-crate files. | Treat per-crate skip-list scaffolding as not live. P3.T4 must either create rationale-bearing skip-list files with a checker or update the process so rationale stays in the workspace config. |
| `.github/workflows/mutants.yml` | Present with `mutants-pr` and `mutants-nightly` jobs. The matrix covers the four trajectory-1 crates. The workflow installs `cargo-mutants` 25.3.1, captures PR diffs for `--in-diff`, calls `scripts/mutants-gate.sh`, posts summaries through `scripts/mutants-comment.sh`, and uploads reports. | This is an advisory shell today. M02 must extend the matrix and then flip enforcement only after kill scores are measured and stable. |
| `releases.toml` | Present with `phase3_merge_tag = ""` and `cycle_end_tag = ""`. `scripts/mutants-gate.sh` reads `cycle_end_tag`; empty means advisory pass. | The required-CI transition is not active. P3 owns the release-cycle flip and any fail-closed behavior changes around missing or malformed release state. |
| `scripts/mutants-gate.sh` | Present. With empty `cycle_end_tag`, it exits 0 regardless of the upstream cargo-mutants exit. With non-empty `cycle_end_tag`, it fails on surviving mutants unless an override reason is supplied. | Current state is intentionally advisory. Promotion must preserve auditable overrides and should avoid silent fail-open behavior after the gate is declared required. |
| `scripts/mutants-comment.sh` | Present. It posts a per-PR Markdown summary and top five missed mutants when `outcomes.json` exists, and a no-mutants one-liner otherwise. | P3.T2 owns any blocking-label wording changes. P3.T3 owns issue filing beyond the per-PR cap. |
| `docs/fuzzing/mutants.md` | Present. It documents the 25.x pin, the single workspace config, the advisory-to-blocking release-cycle model, override paths, and survivor triage. | The doc already describes future P3 mechanics, but M02 still needs live enforcement and score data before claiming required status. |
| `README.md` kill-score headline | No M02 kill-score banner is part of this P0 snapshot. | P3.T5 owns the README headline and nightly auto-update PR flow. |
| `mutants-baseline.toml` | Not present in this P0 snapshot. | P1.T6 owns the aggregate baseline file and the first measured kill-score update here. |

## Mutation Scope Delta

Trajectory-1 covered four crates:

| Crate | Current trajectory-1 status | trajectory-2 M02 target |
|-------|-----------------------------|--------------------------|
| `chio-kernel-core` | Included in `.cargo/mutants.toml` and workflow matrix. | Measure baseline, raise to >= 80%, keep required once promoted. |
| `chio-policy` | Included in `.cargo/mutants.toml` and workflow matrix. | Measure baseline, raise to >= 80%, keep required once promoted. |
| `chio-guards` | Included in `.cargo/mutants.toml` and workflow matrix. | Measure baseline, raise to >= 80%, keep required once promoted. |
| `chio-credentials` | Included in `.cargo/mutants.toml` and workflow matrix. | Measure baseline, raise to >= 80%, keep required once promoted. |

Trajectory-2 adds two crates because they carry fail-closed verification
decisions that were not mutation-calibrated in trajectory-1:

| Crate | Starting state | M02 target |
|-------|----------------|------------|
| `chio-attest-verify` | Tests and sigstore-root fixture are present, but the crate is not in the trajectory-1 mutation config or workflow matrix. | Add to mutation scope, baseline, raise to >= 80%, and include in required gating. |
| `chio-anchor` | Tests are present, but the crate is not in the trajectory-1 mutation config or workflow matrix. | Add to mutation scope, baseline, raise to >= 80%, and include in required gating. |

## Verdict Matrix Starting State

No `crates/chio-conformance/verdict_matrix/` subtree exists in this P0
snapshot. The reusable inputs are present:

| Input | Live state | M02 target |
|-------|------------|------------|
| `crates/chio-conformance/` | Existing conformance crate with native suite runner sources, peer lockfile, binaries, and tests including `tests/vectors_oracle.rs`. | Add `verdict_matrix/` with scenario spec, manifest, scenario corpus, drivers, and diff oracle. |
| `crates/chio-provider-conformance/fixtures/` | Provider fixtures exist under `anthropic`, `bedrock`, and `openai`. | Reuse fixtures as scenario inputs where they express the same kernel decision across providers. |
| `sdks/python/chio-sdk-python` | Present. | P5.T1 driver target. |
| `sdks/typescript/packages/node-http` | Present. | P5.T2 driver target. |
| `crates/chio-kernel-browser/` | Present. | P5.T3 WASM browser kernel driver target. |
| `sdks/go/chio-go-http` | Present. | P5.T4 driver target. |
| Rust kernel path | Present through in-tree kernel crates. | P4.T3 first driver target. |

M02 should keep the verdict oracle semantic, not byte-for-byte only. The
expected comparison tuple is `(verdict, reason_code, scope_set)`. Extra
driver metadata can be logged as advisory until a scenario marks a field as
asserted.

## Preserved Prior Work

- Do not touch trajectory-1 libFuzzer targets, ClusterFuzzLite, corpus
  handling, or crash triage automation.
- Do not widen Kani or Apalache proof surfaces. M02 consumes formal checks as
  backstops and leaves `proofs/` surfaces alone.
- Reuse trajectory-1 M01 canonical JSON vector coverage as byte-equality
  support under the verdict matrix.
- Reuse trajectory-1 M07 provider-conformance fixtures and reason-code
  concepts, but diff along the cross-SDK axis rather than the cross-provider
  axis.

## Open Handoffs

1. Per-crate skip-list scaffolding is a planning discrepancy. The trajectory-2
   narrative says it exists, but the live repo has consolidated the config
   into `.cargo/mutants.toml` and has no `crates/**/mutants.toml` files.
2. The mutation workflow currently covers four crates. Widening to
   `chio-attest-verify` and `chio-anchor` is required before required-CI
   claims are valid.
3. No kill scores are measured in this P0 ticket. P1 must record per-crate
   baseline counts and missed-mutant classes.
4. No verdict-matrix scenario count or corpus hash exists yet. P4 and P5 must
   add those and update this audit.
5. Promotion from advisory to blocking should be reviewed against the
   fail-closed project rule before P3 flips the gate.

## Reproduction Commands

These commands reproduce the P0 snapshot checks:

```bash
sed -n '1,260p' .planning/trajectory-2/02-mutation-and-cross-sdk-differential.md
sed -n '80,130p' .planning/trajectory/02-fuzzing-post-pr13.md
sed -n '540,572p' .planning/trajectory/EXECUTION-STATE.json
sed -n '1,220p' .cargo/mutants.toml
sed -n '1,260p' .github/workflows/mutants.yml
find crates -path '*/mutants.toml' -print | sort
rg -n "cycle_end_tag|mutants" releases.toml docs/fuzzing/mutants.md .planning/trajectory/EXECUTION-STATE.json
find crates/chio-conformance -maxdepth 4 -type f | sort
find crates/chio-provider-conformance/fixtures -maxdepth 3 -type f | sort
find sdks -maxdepth 3 -type d | sort
```

## Audit-Local Phase Tracking

- [x] P0.T1: Open this audit doc and snapshot trajectory-1 M02.P3 advisory
  state.
- [ ] P0.T2: Verify Cargo.lock bump and cargo-mutants 25.x re-pin.
- [ ] P1: Capture mutation baseline and missed-mutant classes per crate.
- [ ] P2: Raise each target crate to >= 80% kill rate.
- [ ] P3: Flip mutation gate, PR comment, issue filing, skip rationale, and
  README headline.
- [ ] P4: Add verdict-matrix harness, Rust driver, manifest, and CI.
- [ ] P5: Add Python, TypeScript, WASM browser, and Go drivers plus required
  cross-language diff.

## chio-policy Mutation Baseline

Snapshot date: 2026-04-29.

Command:

```bash
cargo mutants --config crates/chio-policy/mutants.toml --package chio-policy --shard 1/16 --jobs 4 --timeout 120 --no-shuffle --output target/mutants/chio-policy-p1-t1
```

The full candidate list contains 418 mutants. This baseline records the
completed first shard because it is enough to identify immediate survivor
classes without blocking the rest of Wave 1.

| Metric | Count |
|--------|-------|
| Shard candidates | 27 |
| Caught | 14 |
| Missed | 11 |
| Unviable | 2 |
| Timeout | 0 |
| Kill rate, excluding unviable | 56.0% |

Missed mutants:

| File | Mutation |
|------|----------|
| `crates/chio-policy/src/compiler.rs:826:24` | `==` to `!=` in `tool_patterns_overlap` |
| `crates/chio-policy/src/conditions.rs:102:69` | `+` to `*` in `evaluate_condition_depth` |
| `crates/chio-policy/src/conditions.rs:178:9` | delete match arm `5` in `day_abbreviation` |
| `crates/chio-policy/src/conditions.rs:218:9` | delete match arm `"US/Eastern" | "EST"` in `parse_timezone_offset` |
| `crates/chio-policy/src/compiler.rs:702:5` | replace `compile_output_sanitizer_config` with `Default::default()` |
| `crates/chio-policy/src/compiler.rs:776:57` | `&&` to `||` in `compile_velocity_rule` |
| `crates/chio-policy/src/conditions.rs:220:42` | `*` to `+` in `parse_timezone_offset` |
| `crates/chio-policy/src/merge.rs:421:5` | replace `merge_chio` with `Some(Default::default())` |
| `crates/chio-policy/src/validate.rs:234:26` | `<` to `<=` in `validate_posture` |
| `crates/chio-policy/src/validate.rs:465:22` | `>` to `>=` in `validate_reputation` |
| `crates/chio-policy/src/validate.rs:606:30` | `-` to `/` in `is_valid_duration` |

## chio-credentials Mutation Baseline

Snapshot date: 2026-04-29.

Command:

```bash
cargo mutants --config crates/chio-credentials/mutants.toml --package chio-credentials --jobs 4 --timeout 120 --no-shuffle --output target/mutants/chio-credentials-p1-t2
```

The full candidate list contains 28 mutants. This baseline records the
completed full sweep.

| Metric | Count |
|--------|-------|
| Listed mutants | 28 |
| Evaluated mutants | 28 |
| Caught | 11 |
| Missed | 16 |
| Unviable | 1 |
| Timeout | 0 |
| Kill rate, excluding unviable | 40.7% |

Missed mutants:

| File | Mutation |
|------|----------|
| `crates/chio-credentials/src/lib.rs:57:5` | replace `is_supported_passport_schema` with `true` |
| `crates/chio-credentials/src/lib.rs:57:41` | `==` to `!=` in `is_supported_passport_schema` |
| `crates/chio-credentials/src/lib.rs:61:5` | replace `is_supported_passport_verifier_policy_schema` with `true` |
| `crates/chio-credentials/src/lib.rs:57:31` | `||` to `&&` in `is_supported_passport_schema` |
| `crates/chio-credentials/src/lib.rs:57:12` | `==` to `!=` in `is_supported_passport_schema` |
| `crates/chio-credentials/src/lib.rs:61:57` | `==` to `!=` in `is_supported_passport_verifier_policy_schema` |
| `crates/chio-credentials/src/lib.rs:61:47` | `||` to `&&` in `is_supported_passport_verifier_policy_schema` |
| `crates/chio-credentials/src/lib.rs:61:12` | `==` to `!=` in `is_supported_passport_verifier_policy_schema` |
| `crates/chio-credentials/src/lib.rs:65:5` | replace `is_supported_passport_presentation_challenge_schema` with `true` |
| `crates/chio-credentials/src/lib.rs:65:12` | `==` to `!=` in `is_supported_passport_presentation_challenge_schema` |
| `crates/chio-credentials/src/lib.rs:66:9` | `||` to `&&` in `is_supported_passport_presentation_challenge_schema` |
| `crates/chio-credentials/src/lib.rs:66:19` | `==` to `!=` in `is_supported_passport_presentation_challenge_schema` |
| `crates/chio-credentials/src/lib.rs:71:9` | `||` to `&&` in `is_supported_passport_presentation_response_schema` |
| `crates/chio-credentials/src/lib.rs:70:5` | replace `is_supported_passport_presentation_response_schema` with `true` |
| `crates/chio-credentials/src/lib.rs:70:12` | `==` to `!=` in `is_supported_passport_presentation_response_schema` |
| `crates/chio-credentials/src/lib.rs:71:19` | `==` to `!=` in `is_supported_passport_presentation_response_schema` |
