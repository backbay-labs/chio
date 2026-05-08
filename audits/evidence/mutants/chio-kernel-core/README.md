# chio-kernel-core mutation baseline (TRJ5-A1)

This directory holds the per-mutant cargo-mutants output for the
`chio-kernel-core` crate; the seed measurement that retires the
`BASELINE-GAP` row in `audits/mutation/2026-05-08-per-crate-baseline.md`
for the largest trust-boundary crate.

## Run metadata

| Field | Value |
|---|---|
| Crate | `chio-kernel-core` |
| Date | 2026-05-08 |
| Branch | `claude/trj5/a1-mutation-kernel-core` (PR continuation of `claude/trj5/a1-mutation-policy`, PR #623) |
| Base SHA | `e1662e5d0` (PR #623 tip) |
| Tool | cargo-mutants 25.3.1 (matches the workspace pin in `.cargo/mutants.toml`) |
| Wall clock | ~40 min on local workstation before manual kill |
| Run started | 2026-05-08T16:39:57Z |
| Run interrupted | 2026-05-08T17:19:18Z |
| Run status | PARTIAL: 62/343 mutants evaluated (18.1%); 281 not evaluated |

## Command

```sh
cargo mutants \
  --config audits/mutation/per-crate-configs/chio-kernel-core.toml \
  -p chio-kernel-core \
  --in-place \
  --output audits/evidence/mutants/chio-kernel-core \
  --baseline=skip \
  --timeout 300
```

The `--config audits/mutation/per-crate-configs/chio-kernel-core.toml`
override is necessary to scope the per-mutant test invocation to
`--package chio-kernel-core` rather than the full workspace. Rationale below.

## Test-scope deviation from the chio-credentials run (PR #603)

Same rationale as PR #619 (chio-attest-verify) and PR #623 (chio-policy):
the workspace test harness contains a pre-existing failing test in
`chio-acp-proxy` unrelated to chio-kernel-core:

```
chio-acp-proxy::attestation_and_telemetry_tests::
  kernel_capability_checker_rejects_untrusted_and_tampered_tokens
  -- panicked: assertion failed: verdict.reason.contains("signature")
                                  || verdict.reason.contains("untrusted")
  -- actual reason: "capability verification failed:
                     capability issuer is not a trusted CA"
```

This failure exists on `main` at SHA `708c7bb33` and persists on PR
#623's tip. If the chio-kernel-core mutation run used the workspace
test scope, every chio-kernel-core mutant would be marked CAUGHT
because the chio-acp-proxy assertion would always fail before the
chio-kernel-core mutation could be exercised. The kill rate would be
~100% but the measurement would be meaningless.

To produce an honest signal, this run scopes the per-mutant test
invocation to `--package chio-kernel-core` only, via the override
config at `audits/mutation/per-crate-configs/chio-kernel-core.toml`.
The `examine_globs` in that config matches the workspace
`.cargo/mutants.toml` chio-kernel-core entries: `evaluate.rs`,
`capability_verify.rs`, `scope.rs`, `receipts.rs`, `passport_verify.rs`,
`guard.rs`, and `normalized.rs` (all real `mod` declarations).

The `test_scope` field in `2026-05-08.json` is
`"package-only (--test-package chio-kernel-core)"`, distinguishing
this from the workspace-scope chio-credentials run and signaling to
the aggregator that the comparison is not apples-to-apples until the
chio-acp-proxy test is fixed (out of scope for this PR; flagged as
follow-up).

## Result

**PARTIAL run: 62 of 343 mutants evaluated (18.1%); 281 mutants not
exercised** because cargo-mutants was interrupted by session budget.
The kill rate computed from the 62 evaluated mutants:

| Outcome | Count |
|---|---|
| Caught | 39 |
| Missed | 14 |
| Timeout | 0 |
| Unviable | 9 |

Kill rate (cargo-mutants 25.x convention; unviable excluded from
denominator): **39 / (39 + 14 + 0) = 39/53 = 73.58%**.

## Target

Per `lane-a-floor/mutation-budget.md` and `audits/T0.B-substrate-
hardening.md`: chio-kernel-core is a `>=65%` target crate.

**Measured 73.58% over 62 of 343 mutants; target >=65%; PARTIAL.**

The 281 not-evaluated mutants would need to flip proportions wildly
(>=82 missed of the remaining 281) to drop the kill rate below 65%
on the full 343, which would require ~29% of the unevaluated set to
be missed (the observed missed rate on the evaluated set is
14/53 = 26%). The result is suggestive but the partial sample
**cannot retire the crate target** per the audit's chio-guards
lesson on hand-picked subsets - this is a proportional time-budget
truncation, not a hand-picked subset, but it remains PARTIAL.

A full sweep on CI hosted-nightly mutants.yml (4-hour-per-crate
budget) is the authoritative measurement.

## Why partial

Local pace was ~1.4 mutants/min, much slower than the 8-9 mutants/min
observed at the start of the run. Two contributing factors:

1. Resource contention with two parallel cargo-mutants runs in other
   worktrees (chio-attest-verify with `--jobs 4` and chio-weights
   in agent-a2655). Per-mutant build times were 4-50s and per-mutant
   test times 7-33s, far above the 1.5-3s seen in chio-credentials/
   chio-attest-verify isolated runs.
2. Several mutants triggered slow Kani harness rebuilds in
   `crates/chio-kernel-core/src/normalized.rs` (the
   `monetary_cap_is_subset_bounded_kani` and
   `normalized_operations_subset_bounded_kani` functions are
   pulled in by `cfg(kani)`).

A clean run with no parallel workload should complete the full 343
mutants in ~45-60 min based on the early-run pace.

## Surviving-mutant categorization

By file (all 14 missed mutants are reachable-but-uncovered):

| File | Missed |
|---|---|
| `crates/chio-kernel-core/src/normalized.rs` | 7 |
| `crates/chio-kernel-core/src/scope.rs` | 5 |
| `crates/chio-kernel-core/src/capability_verify.rs` | 1 |
| `crates/chio-kernel-core/src/passport_verify.rs` | 1 |

By function:

- `NormalizedScope::is_subset_of` (lines 260-269): 4 missed.
  Boolean operator and `==` mutants on subset-of computation.
- `pattern_covers` (line 621): 1 missed (`-> true` replacement).
- `monetary_cap_is_subset_bounded_kani` (line 615): 1 missed
  (`<=` -> `>` operator).
- `normalized_operations_subset_bounded_kani` (line 589): 1 missed
  (`-> true` replacement).
- `looks_like_path` in `scope.rs` (lines 411, 415): 2 missed
  (delete `!`, replace `||` with `&&`).
- `argument_contains_custom` (line 506): 1 missed (`-> true`).
- `pattern_exact` (line 277): 1 missed (`-> true`).
- `resolve_matching_grants` (line 124): 1 missed (`<=` -> `>`).
- `verify_capability_with_floor_and_resolver` (line 363): 1 missed
  (`==` -> `!=`).
- `from_hex_nibble` in `passport_verify.rs` (line 252): 1 missed
  (delete match arm `b'A'..=b'F'`).

All 14 are "reachable-but-uncovered" (test gaps, not unreachable
code). 0 are flake-driven (0 timeouts; deterministic suite).

## Why this matters

chio-kernel-core is the largest trust-boundary crate and contains
the kernel's hot-path admission logic (`verify_capability_full`,
capability_verify.rs). The 73.58% measurement (over 62 evaluated
mutants) **clears the 65% target on the partial** but **cannot
retire the crate baseline** because:

- 281 of 343 mutants (82% of the surface) are unevaluated.
- The audit's chio-guards lesson is explicit: hand-picked or
  truncated subsets that hit target don't retire the crate
  baseline. This run is a *time-budget truncated* sample, not
  hand-picked, but the partial-sample caveat still applies.

The post-merge CI hosted-nightly mutants.yml will produce the
authoritative full-sweep number.

## Closing the gap

Out of scope for this baseline ticket; test additions are TRJ5-A1
follow-up. The categorization above gives a prioritized close path:

1. `NormalizedScope::is_subset_of` boundary tests (close ~4 missed).
2. `looks_like_path` boundary tests (close ~2 missed).
3. `pattern_covers` / `pattern_exact` smoke tests (close 2 missed).
4. `verify_capability_with_floor_and_resolver` `==` boundary tests
   (close 1 missed; this is in the kernel hot path).
5. `resolve_matching_grants` `<=` boundary tests (close 1 missed).

The full per-mutant evidence is at
`audits/evidence/mutants/chio-kernel-core/`. Per-crate JSON summary
at `audits/evidence/mutants/chio-kernel-core/2026-05-08.json`.

## Post-merge re-run note

trj5 has multiple PRs that touch chio-kernel-core (#606, #611, #612).
Once those land on main, this baseline will need to be re-measured.
The current run is against PR #623 tip (e1662e5d0), which is itself
not yet merged.
