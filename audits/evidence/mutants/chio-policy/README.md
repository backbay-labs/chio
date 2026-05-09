# chio-policy mutation baseline (mutation evidence item)

This directory holds the per-mutant cargo-mutants output for the
`chio-policy` crate; the seed measurement that retires the
`BASELINE-GAP` row in `audits/mutation/2026-05-08-per-crate-baseline.md`.

## Run metadata

| Field | Value |
|---|---|
| Crate | `chio-policy` |
| Date | 2026-05-08 |
| Evidence scope | local evidence run |
| Base SHA | `7bc9fd0764f374ae252bf09bd873bbdf3192eb46` |
| Tool | cargo-mutants 25.3.1 (matches the workspace pin in `.cargo/mutants.toml`) |
| Wall clock | ~3h 12m wall (interrupted by session budget) |
| Run started | 2026-05-08T11:43:40Z |
| Run interrupted | 2026-05-08T14:55:31Z |
| Run status | PARTIAL: 314/418 mutants evaluated (75.1%); 104 not evaluated |

## Command

```sh
cargo mutants \
  --config audits/mutation/per-crate-configs/chio-policy.toml \
  -p chio-policy \
  --in-place \
  --output audits/evidence/mutants/chio-policy \
  --baseline=skip
```

The `--config audits/mutation/per-crate-configs/chio-policy.toml`
override is necessary to scope the per-mutant test invocation to
`--package chio-policy` rather than the full workspace. Rationale below.

## Test-scope deviation from the chio-credentials run

Same rationale as the chio-attest-verify package run: the workspace test
harness contains a pre-existing failing test in `chio-acp-proxy`
unrelated to chio-policy:

```
chio-acp-proxy::attestation_and_telemetry_tests::
  kernel_capability_checker_rejects_untrusted_and_tampered_tokens
  -- panicked: assertion failed: verdict.reason.contains("signature")
                                  || verdict.reason.contains("untrusted")
  -- actual reason: "capability verification failed:
                     capability issuer is not a trusted CA"
```

This failure exists on `main` at SHA `708c7bb33` and persists on the
evidence base. If the chio-policy mutation run used the workspace test
scope, every chio-policy mutant would be marked CAUGHT because the
chio-acp-proxy assertion would always fail before the chio-policy
mutation could be exercised. The kill rate would be ~100% but the
measurement would be meaningless.

To produce an honest signal, this run scopes the per-mutant test
invocation to `--package chio-policy` only, via the override config at
`audits/mutation/per-crate-configs/chio-policy.toml`. The
`examine_globs` in that config matches the workspace
`.cargo/mutants.toml` chio-policy entries (lines 99-108): the umbrella
`evaluate.rs` (which `include!`s context/engine/matchers/outcomes/tests
sub-files per the workspace header) plus compiler.rs, conditions.rs,
detection.rs, merge.rs, resolve.rs, validate.rs, regex_safety.rs, and
receipt.rs as real `mod`s.

The `test_scope` field in `2026-05-08.json` is
`"package-only (--test-package chio-policy)"`, distinguishing this
from the workspace-scope chio-credentials run and signaling to the
aggregator that the comparison is not apples-to-apples until the
chio-acp-proxy test is fixed (out of scope for this PR; flagged as
follow-up).

## Result

**PARTIAL run: 314 of 418 mutants evaluated (75.1%); 104 mutants not
exercised** because cargo-mutants was interrupted by session budget.
The kill rate computed from the 314 evaluated mutants:

| Outcome | Count |
|---|---|
| Caught | 227 |
| Missed | 56 |
| Timeout | 0 |
| Unviable | 31 |

Kill rate (cargo-mutants 25.x convention; unviable excluded from
denominator): **227 / (227 + 56 + 0) = 227/283 = 80.21%**.

## Target

Per `releases.toml [mutants]`, the configured catch-ratio target is
80% and the activation floor is 65%. The 65% value is a floor for
early activation posture, not the per-crate target.

**Measured 80.21% over 314 of 418 mutants; configured target 80%;
crate-level target NOT satisfied by this run.** The dated JSON summary
is the authoritative machine-readable result and records
`target_met: false` with `result_label: "PARTIAL"`. The 104
not-evaluated mutants leave the full-crate kill rate unknown, so this
partial run cannot retire the chio-policy baseline even though the
evaluated subset clears both numeric values.

## Surviving-mutant categorization

All 56 missed mutants by file:

| File | Missed | % of file's evaluated mutants |
|---|---|---|
| `crates/chio-policy/src/conditions.rs` | 32 | 32/122 = 26% |
| `crates/chio-policy/src/compiler.rs` | 11 | 11/62 = 18% |
| `crates/chio-policy/src/regex_safety.rs` | 5 | 5/15 = 33% |
| `crates/chio-policy/src/validate.rs` | 4 | 4/61 = 7% |
| `crates/chio-policy/src/detection.rs` | 3 | 3/22 = 14% |
| `crates/chio-policy/src/receipt.rs` | 1 | 1/4 = 25% |

Top-5 surviving mutants by file:line frequency:

| File:line | Function | Count | Note |
|---|---|---|---|
| `conditions.rs:219-227` | `parse_timezone_offset` | 16+ | Timezone-string match arms (US/Central, US/Mountain, US/Pacific, GB, Japan/JST, CET, EET, PRC) and arithmetic (`*`, `-`, `+`); not exercised by the existing chio-policy test surface. |
| `conditions.rs:173-177` | `day_abbreviation` | 3 | Day-of-week lookup match arms (0, 3, 4); no test asserts day name resolution. |
| `conditions.rs:131-154` | `check_time_window` | 5 | Time-window comparison operators (`>`, `<`, `>=`, `<=`, `==`); boundary tests do not stress these. |
| `conditions.rs:73,283,311` | `evaluate_condition_depth`, `resolve_context_value`, `values_equal` | 3 | Depth-bound and value-equality comparisons. |
| `compiler.rs:776,822` | `compile_velocity_rule`, `tool_patterns_overlap` | 3 | Boolean operator (`&&` vs `||`) mutants on rule compilation. |

Other concentrations:
- `compiler.rs` glob/wildcard matchers (`glob_matches` lines 860-861;
  `contains_wildcards` line 837; `tool_access_can_safely_widen_to_wildcard`
  line 712) - 4 missed.
- `regex_safety.rs` complexity scoring (`policy_regex_complexity` lines
  94, 96; `validate_policy_regex_count` line 79; `policy_regex_is_match`
  line 63; `<<` shift on line 9) - 5 missed.
- `validate.rs` pattern-db match guard (line 353; both branches) and
  `validate_runtime_assurance` `!` deletion (line 566) - 4 missed.
- `detection.rs` Detector trait `name -> &str` returns - 3 missed.
- `receipt.rs` `compute_policy_hash -> "xyzzy".into()` - 1 missed.

The full list is at `2026-05-08.json` field `missed_mutants`.

## Categorization (test gaps vs unreachable vs reachable-but-uncovered)

All 56 missed mutants are in the **"reachable-but-uncovered"** category.
None are flake-driven (0 timeouts; deterministic test suite). The
test-gap pattern:

1. **Timezone parser (`parse_timezone_offset`)** -- 16 missed mutants
   are concentrated on the timezone-name match arms and arithmetic
   in lines 219-227. The crate has no negative-test for non-default
   timezone abbreviations beyond UTC. Adding a parametrized test that
   asserts `parse_timezone_offset("US/Central") == Some(-6*3600)` etc.
   would close 12+ of these.
2. **Day-of-week / time-window helpers** -- 8 missed in
   `day_abbreviation` and `check_time_window`. Boundary tests
   (Monday-edge, time-window-edge `start == end`) would close most.
3. **Compiler boolean ops** -- 5 missed in `compile_velocity_rule` /
   `tool_patterns_overlap` / `compile_scope`. Tests do not exercise
   the both-branch path for these `&&` / `||` operators.
4. **Glob / wildcard matchers** -- 4 missed in `glob_matches` /
   `contains_wildcards` / `tool_access_can_safely_widen_to_wildcard`.
5. **Regex safety** -- 5 missed in `regex_safety.rs`; the complexity
   scoring branches and shift operators are not asserted by
   `policy_regex_validate_*` tests.
6. **Detector trait `name`** -- 3 missed (RegexInjectionDetector,
   RegexJailbreakDetector, RegexExfiltrationDetector). No test
   asserts the `name()` getter return value.
7. **`receipt::compute_policy_hash`** -- 1 missed; the function
   returning a constant `"xyzzy"` is not caught because no test
   asserts the hash content beyond non-emptiness.
8. **`validate.rs` pattern-db guard** -- 2 missed on the
   `match guard pattern_db.trim().is_empty()` branches, plus 2
   misc.

These are concrete test-addition opportunities; closing the timezone-
parser cluster alone (deferred to mutation evidence item follow-up) would push the
kill rate to ~85% without touching the un-evaluated 104 mutants.

## Why partial run

The local workstation experienced sustained cargo-mutants pace of
~1.5-3 mutants/min (highly variable; some mutants required 50s+ build
times due to `--in-place` mode and a competing rustc on the system).
At 75% completion the wall clock was already 3h 12m -- continuing to
100% would require an estimated ~2 additional hours and exceeded the
session budget for the agent. The honest call: stop, capture the
314/418 evaluated set, document the gap, and let CI hosted-nightly
mutants.yml (4-hour-per-crate budget) produce the authoritative full
sweep. The 80.21% kill rate measured over 314 mutants spans every
trust-boundary file in the chio-policy `examine_globs` set -- it is
not a lopsided sample.

## What's NOT in this PR

- Test additions to close the 56 missed mutants (deferred to a
  mutation evidence item follow-up task; the categorization above gives a
  prioritized close path).
- Re-run to evaluate the remaining 104 mutants (deferred to CI
  hosted-nightly).
- The chio-acp-proxy unrelated test fix; that is its own concern.
- A workspace-scope re-run; once chio-acp-proxy is fixed, the CI
  hosted-nightly mutants lane will produce the authoritative
  workspace-scope number.
- `releases.toml [per_crate_kill_rate_percent]` update (a partial
  3-of-6 update would weaken audit signal; will land once all six
  trust-boundary crates have measured baselines).

## Files in this directory

- `2026-05-08.json` -- per-crate JSON summary (the authoritative
  machine-readable result; consumed by `audits/mutation/aggregate.sh`).
  Includes `run_status: "PARTIAL"`, `result_label: "PARTIAL"`,
  `target_met: false`, and `evaluated: 314, total_discovered: 418`.
- `mutants.out/caught.txt` -- 227 lines, one per caught mutant.
- `mutants.out/missed.txt` -- 56 lines, one per missed mutant.
- `mutants.out/timeout.txt` -- 0 lines.
- `mutants.out/unviable.txt` -- 31 lines.
- `mutants.out/mutants.json` -- 418-entry mutant catalogue (full
  enumeration; not all evaluated).
- `mutants.out/outcomes.json` -- per-mutant outcome record (314
  entries). Intentionally not committed; regenerate locally when
  argv-level replay evidence is needed.
- `mutants.out/lock.json` -- run start time + tool version.
  Intentionally not committed because cargo-mutants records operator
  local process metadata in this file.
- `mutants.out/diff/*.diff` -- per-mutant source diff (one per
  evaluated mutant; 314 files).

The `mutants.out/log/` and `mutants.out/debug.log` are NOT committed
per `audits/evidence/mutants/.gitignore` (large; contain absolute
paths).

## Reproducibility

`mutants.out/lock.json` and `mutants.out/outcomes.json` are intentionally
omitted by `audits/evidence/mutants/.gitignore`: cargo-mutants records
local process metadata and per-mutant console transcripts in those files. The committed evidence is
the dated JSON summary plus `caught.txt`, `missed.txt`, `timeout.txt`,
`unviable.txt`, `mutants.json`, and per-mutant `diff/` patches.

To regenerate the omitted files locally, rerun:

```sh
cargo mutants \
  --config audits/mutation/per-crate-configs/chio-policy.toml \
  -p chio-policy \
  --in-place \
  --output audits/evidence/mutants/chio-policy \
  --baseline=skip
```

Then compare the regenerated counts against
`audits/evidence/mutants/chio-policy/2026-05-08.json`; do not commit
the regenerated `lock.json`, `outcomes.json`, `log/`, or `debug.log`.
