# chio-guards mutation baseline

Status: **PARTIAL-SUBSET (9.2% surface)**.

This directory holds the per-mutant cargo-mutants output for the
`chio-guards` crate. **The 78.2% kill rate measured here is on a
hand-picked subset of 119 of 1291 historical-config mutants (8 of 27
files, 9.2% historical surface). It is NOT a crate-level kill rate and
does NOT retire the configured target or the activation floor.** Target
satisfaction at the crate level requires EITHER a full run OR a
pre-registered statistically defensible sampling scheme. See the
"Config correction note" section below.

The prior config excluded `text_utils.rs` and `embedding_anomaly.rs` as
"advisory/helper". Both files are decision-capable and have been
re-included in the chio-guards examine_globs by the config correction
commit. **The 119-mutant subset measured here is INVALID for those
two files** (they were not mutated). The next mutation run after the
config update will re-measure the corrected surface; this README's
78.2% number stands only for the 8 files in the prior subset, not
the 10-file corrected surface.

## Run metadata

| Field | Value |
|---|---|
| Crate | `chio-guards` |
| Date | 2026-05-08 |
| Evidence scope | local evidence run |
| Base SHA | `708c7bb33df43594f5e76542b05fca7a56d9689e` (main tip) |
| Tool | cargo-mutants 25.3.1 (matches the workspace pin in `.cargo/mutants.toml`) |
| Wall clock | 58m 5s |
| Run started | 2026-05-08T11:59:56Z |
| Run finished | 2026-05-08T12:58:01Z |

## Command

```sh
cargo mutants \
  --config audits/mutation/per-crate-configs/chio-guards-2026-05-08-subset.toml \
  -p chio-guards \
  --in-place \
  --output audits/evidence/mutants/chio-guards
```

The historical replay command intentionally uses
`audits/mutation/per-crate-configs/chio-guards-2026-05-08-subset.toml`.
That file preserves the exact 8-file surface measured in this evidence
directory. The corrected local rerun config is
`audits/mutation/per-crate-configs/chio-guards.toml`; it adds
`text_utils.rs` and `embedding_anomaly.rs` and therefore does not reproduce
the 2026-05-08 subset. The hosted nightly uses the workspace
`.cargo/mutants.toml` surface, not the per-crate replay file.

The override is necessary for two reasons:

1. **Test-scope override** (same as chio-attest-verify rationale):
   scopes the per-mutant test invocation to `--package chio-guards`
   rather than the workspace, to avoid the pre-existing
   chio-acp-proxy test failure
   (`kernel_capability_checker_rejects_untrusted_and_tampered_tokens`)
   which would otherwise mark every mutant as caught.

2. **Examine-globs subset** (chio-guards-specific; see notes below):
   the workspace `.cargo/mutants.toml` lists 27 chio-guards files
   (1291 mutants per `cargo mutants --list`). That set is too large
   for a single local session (~25 hours wall-clock at ~70s per
   mutant). The hosted nightly has a 4-hour-per-crate budget but is
   not sharded within `chio-guards`; budget exhaustion or timeout
   remains PARTIAL until a full completed sweep is recorded. The run captured here
   used a hand-picked subset of 8 files (119 mutants); this is
   **PARTIAL-SUBSET** (9.2% surface) and does NOT retire the crate
   target. The post-cleanup config now includes `text_utils.rs` and
   `embedding_anomaly.rs`, raising the post-cleanup surface to 10 files;
   the 119-mutant subset captured here did not mutate those two
   files. Subset breakdown (8-file, pre-cleanup):

   | File | Mutants | Trust-boundary role |
   |---|---|---|
   | `pipeline.rs` | 9 | Guard pipeline orchestration |
   | `forbidden_path.rs` | 15 | Filesystem read-side boundary |
   | `path_allowlist.rs` | 36 | Filesystem write-side boundary |
   | `path_normalization.rs` | 15 | Filesystem canonicalization |
   | `egress_allowlist.rs` | 10 | Network-egress boundary |
   | `secret_leak.rs` | 18 | Data-flow boundary (secret detection) |
   | `data_flow.rs` | 6 | Cumulative-exfiltration boundary |
   | `behavioral_sequence.rs` | 10 | Sequence-attack detection |
   | **Subset total** | **119** | |

   Files NOT in this subset (deferred to CI hosted-nightly):
   `shell_command` (265), `response_sanitization` (183),
   `jailbreak_detector` (101), `browser_automation` (70),
   `content_review` (66), `internal_network` (63),
   `behavioral_profile` (61), `computer_use` (48),
   `memory_governance` (46), `patch_integrity` (44),
   `code_execution` (41), `prompt_injection` (33),
   `input_injection` (33), `remote_desktop` (26),
   `mcp_tool` (22), `jailbreak` (20), `velocity` (18),
   `post_invocation` (16), `agent_velocity` (16).

   These are excluded for SESSION-SCOPE reasons (mutant volume),
   not scope-of-concern reasons. The workspace `.cargo/mutants.toml`
   surface is the hosted-nightly input for the full chio-guards
   trust-boundary set.

The `test_scope` field in `2026-05-08.json` is `"package-only
(--package chio-guards)"`, distinguishing this from the workspace-scope
workspace-scope chio-credentials run. The `examine_scope` field is
`"hand-picked-subset (8 of 27 files; 119 of 1291 total mutants in
workspace .cargo/mutants.toml; 9.2% surface)"` to flag the
session-scope override and match the JSON summary.

## Test-scope deviation from the chio-credentials run

The `chio-credentials` baseline ran with the workspace
`.cargo/mutants.toml` (which sets
`additional_cargo_test_args = ["--workspace", "--exclude", "chio-cpp-kernel-ffi"]`).
That works for `chio-credentials` because its lib.rs mutations affect
relatively few downstream packages.

For `chio-guards` (and `chio-attest-verify`), the
workspace-wide test harness contains a **pre-existing failing test**
unrelated to this crate:

```
chio-acp-proxy::attestation_and_telemetry_tests::
  kernel_capability_checker_rejects_untrusted_and_tampered_tokens
  -- panicked: assertion failed: verdict.reason.contains("signature")
                                  || verdict.reason.contains("untrusted")
  -- actual reason: "capability verification failed:
                     capability issuer is not a trusted CA"
```

This failure exists on `main` at SHA `708c7bb33`. It is a pre-existing
test/runtime drift where the runtime now returns a "trusted CA"
message instead of the "signature"/"untrusted" wording the test
expects.

If the chio-guards mutation run used the workspace test scope,
**every single mutant would be marked CAUGHT** because the
chio-acp-proxy test would always fail before any chio-guards mutation
could be exercised by the test harness. The kill rate would be ~100%
but the measurement would be meaningless.

To produce an honest signal, this run scopes the per-mutant test
invocation to `--package chio-guards` only.

## Result

119 mutants discovered, 119 evaluated.

| Outcome | Count |
|---|---|
| Caught | 86 |
| Missed | 24 |
| Timeout | 0 |
| Unviable | 9 |

Kill rate (cargo-mutants 25.x convention; unviable excluded from
denominator): **86 / (86 + 24 + 0) = 86/110 = 78.18%**.

## Target satisfaction

Per `releases.toml [mutants]`, the configured catch-ratio target is
80% and the activation floor is 65%. The 65% value is a floor for
early activation posture, not the per-crate target.

**Measured 78.18% on 119 of 1291 historical-config mutants (9.2%
historical surface; 8 of 27 files). PARTIAL-SUBSET. Crate-level
target NOT satisfied by this run.**

### Cleanup-wave note

A prior framing of this section claimed "ABOVE TARGET by 13.18
percentage points (on the boundary-enforcing core subset)". That
framing is wrong: a 9.2% hand-picked subset cannot retire a
crate-level kill-rate target, regardless of the rate observed on
the subset. Aggregate documents now record this row as
`PARTIAL-SUBSET -- 78.2% on 119/1291 mutants` and the crate-level
target as `UNRESOLVED` (not `PASS`).

Target satisfaction at the crate level requires either:

- a full mutation run of the corrected workspace surface
  (`.cargo/mutants.toml`, including `text_utils.rs` and
  `embedding_anomaly.rs`). The hosted-nightly lane can produce this
  measurement only if it completes; it is a per-crate matrix without
  intra-crate sharding, so timeout or budget exhaustion is still
  PARTIAL, OR
- a pre-registered statistically defensible sampling scheme
  (e.g. mutant categories sampled with documented stratification,
  power analysis, and confidence interval). The current subset is
  hand-picked by file and does not meet that bar.

The pass-through caveat in the per-crate budget framework is a
methodology hedge for categorizing surviving mutants; it does NOT
cover claiming target met on a partial run.

### Config correction note (text_utils + embedding_anomaly)

The prior config excluded `text_utils.rs` and `embedding_anomaly.rs` as
"advisory/helper". Both files are decision-capable per
`audits/evidence/mutation exclusion audit/exclude-audit.md`:

- `text_utils.rs::canonicalize` is the canonical-form input to
  prompt-injection and jailbreak guards. Mutations that stop
  stripping zero-width characters or folding homoglyphs can let
  obfuscated payloads evade the trust-boundary guards.

- `embedding_anomaly.rs::EmbeddingAnomalyGuard` returns `Verdict::Deny` for
  dimension mismatch (line 290), non-finite embeddings (line 293),
  high similarity scores, and ambiguous-deny policy (line 299).
  The file's module-level doc-comment lists three explicit
  `Verdict::Deny` paths (lines 10-28). It is NOT advisory.

The config correction re-included both files in the corrected local
rerun config, `audits/mutation/per-crate-configs/chio-guards.toml`,
and in the workspace `.cargo/mutants.toml` surface used by the
hosted-nightly lane. The historical replay config for this evidence
row does not include them. The 119-mutant subset committed here did
NOT mutate either file; the next corrected mutation run is required
to re-measure the corrected surface. The JSON evidence at
`audits/evidence/mutants/chio-guards/2026-05-08.json` carries
`"subset_invalidated_for_files": [...]` flagging this re-measure
requirement.

The kill rate **is** observed (not extrapolated) on the 8-file subset,
but it is NOT the crate-level kill rate. A future completed
hosted-nightly or manual full sweep is responsible for the
workspace-scope number; this baseline measures the prior 8-file subset
and reports that subset's kill rate honestly with the PARTIAL-SUBSET
label.

## Surviving-mutant categorization

All 24 missed mutants and the file/function distribution:

```
9 of 24 missed mutants are in crates/chio-guards/src/path_allowlist.rs
7 of 24 missed mutants are in crates/chio-guards/src/pipeline.rs
4 of 24 missed mutants are in crates/chio-guards/src/secret_leak.rs
4 of 24 missed mutants are in crates/chio-guards/src/forbidden_path.rs
```

By function:

### path_allowlist.rs (9 missed; 36 total)

| Surface | Missed | Note |
|---|---|---|
| `matches_allowlist` boundary checks (lines 93, 102, 103) | 3 | `!=` -> `==` and `\|\|` -> `&&` operators on allowlist match path |
| `matches_session_roots` boundary checks (lines 134, 135, 145, 146) | 4 | `!=` -> `==` and `\|\|` -> `&&` operators on session-root traversal check |
| `<impl Guard for PathAllowlistGuard>::evaluate` arm deletion (lines 203, 205) | 2 | `ToolAction::FileAccess` and `ToolAction::Patch` arms not asserted by negative-test cases |

### pipeline.rs (7 missed; 9 total)

| Surface | Missed | Note |
|---|---|---|
| `GuardPipeline::is_empty` (line 33) | 2 | Replace -> true and -> false; no test asserts `is_empty()` on a populated pipeline |
| `GuardPipeline::len` (line 29) | 2 | Replace -> 0 and -> 1; no test asserts `len()` on a populated pipeline |
| `<impl Guard for GuardPipeline>::name` (line 59) | 2 | Replace name string with `""` and `"xyzzy"`; no test asserts pipeline name |
| `GuardPipeline::default_pipeline -> Self` -> `Default::default()` (line 39) | 1 | Default-vs-default-pipeline distinction not asserted |

### secret_leak.rs (4 missed; 18 total)

| Surface | Missed | Note |
|---|---|---|
| `mask_value` arithmetic (line 129) | 1 | `+` -> `*` on masking-window byte arithmetic; output mask string not asserted |
| `<impl Guard for SecretLeakGuard>::evaluate` arm deletion (line 307) | 1 | `ToolAction::Patch` arm not exercised by patch-side negative test |
| `<impl Guard for SecretLeakGuard>::name` (line 295) | 2 | Replace name string with `""` and `"xyzzy"`; no test asserts guard name |

### forbidden_path.rs (4 missed; 15 total)

| Surface | Missed | Note |
|---|---|---|
| `is_forbidden` operator boundaries (lines 100, 101, 106, 114) | 4 | `!=` -> `==` and `\|\|` -> `&&` mutants on the path-prefix and exception-arm tests; positive-side covered, negative-side gaps |

The full list is at `2026-05-08.json` field `missed_mutants`.

## Categorization (test gaps vs unreachable vs reachable-but-uncovered)

All 24 missed are in the **"reachable-but-uncovered"** category. None
are flagged "unreachable code" by cargo-mutants (cargo-mutants would
have marked them unviable). None are flake-driven; the test suite is
deterministic and the run produced 0 timeouts.

The 9 unviable mutants are uniformly the
`<impl Guard for X>::evaluate -> Result<Verdict, KernelError> with
Ok(Default::default())` mutant in 6 different files plus 3 other
`Default::default()` substitutions. These don't compile because
`Verdict` (in `chio_kernel`) is not `Default`. cargo-mutants marks
these unviable correctly; they are NOT counted in the kill-rate
denominator per cargo-mutants 25.x convention.

The pattern across the 24 missed is:
1. **Boundary-operator mutants** (`==`/`!=`, `||`/`&&`) on path
   prefix/equality checks (path_allowlist, forbidden_path) survive
   when the test exercises one branch but not the other.
2. **Accessor-name mutants** (`name -> ""`, `name -> "xyzzy"`,
   `len -> 0`, `is_empty -> true/false`) survive because no test
   asserts the guard's display name or the pipeline's introspection
   methods on a populated pipeline.
3. **Arm-deletion mutants** in `evaluate` survive when the
   `ToolAction` variant is not exercised by a negative-test fixture
   that explicitly invokes that variant.
4. **Arithmetic mutants** in helpers like `mask_value` survive when
   the test asserts the masked-string presence but not its byte
   composition.

## Closing the gap

Out of scope for this baseline; the test additions are a follow-up.
Per the categorization above, the test additions that would close
the 24 missed:

1. **Boundary-pair tests** in `path_allowlist::matches_allowlist`
   and `matches_session_roots` (lines 93, 102, 103, 134, 135, 145,
   146) - assert pass/fail on path strictly inside, equal to, and
   strictly outside each session-root boundary. Closes 7 mutants.
2. **Pipeline-introspection smoke tests** for
   `GuardPipeline::{is_empty, len, name, default_pipeline}` -
   assert non-zero length, non-empty, fixed name string, and
   `default_pipeline()` is not `Default::default()` (the latter
   has no guards). Closes 7 mutants.
3. **Forbidden-path operator tests** at the boundary of the
   forbidden-prefix list and the exception arm. Closes 4 mutants.
4. **secret_leak-arm tests** for the `ToolAction::Patch` variant
   (line 307) and a `mask_value` byte-content assertion. Closes 3
   mutants.
5. **secret_leak::name assertion** (line 295). Closes 2 mutants.
6. **path_allowlist evaluate-arm tests** for `ToolAction::Patch`
   and `ToolAction::FileAccess` (lines 203, 205) with explicit
   verdict assertions. Closes 2 mutants (overlap with #1; net 1).

Total potential closure: ~24 of 24 missed (the boundary-operator
mutants would be closed by basic boundary tests; the accessor and
arm-deletion mutants would be closed by explicit assertions on the
affected accessors/arms).

This work is **deferred to a follow-up**. The 78.2% baseline is only
an observed subset score. It does not satisfy the crate-level target or
the activation floor because the run is PARTIAL-SUBSET and the
corrected surface has not been measured.

## What's NOT in this PR

- Test additions to close the 24 missed mutants (deferred).
- The chio-acp-proxy unrelated test fix; that is its own concern
  and is filed as a follow-up.
- A workspace-scope re-run; once chio-acp-proxy is fixed, the
  hosted-nightly mutants lane (`mutants.yml`, 4-hour-per-crate
  budget, per-crate matrix without intra-crate sharding) can produce
  the authoritative workspace-scope number only if it completes.
- The remaining chio-guards files NOT in the historical 8-file
  subset; these require a completed corrected-surface rerun.
- `releases.toml [per_crate_kill_rate_percent]` update; a partial
  3-of-6 update would weaken release signal; will land once all six
  trust-boundary crates have measured baselines.

## Files in this directory

- `2026-05-08.json` - per-crate JSON summary (the authoritative
  machine-readable result; consumed by `audits/mutation/aggregate.sh`).
- `mutants.out/caught.txt` - 86 lines, one per caught mutant.
- `mutants.out/missed.txt` - 24 lines, one per missed mutant.
- `mutants.out/timeout.txt` - 0 lines.
- `mutants.out/unviable.txt` - 9 lines.
- `mutants.out/outcomes.json` - per-mutant outcome record. Intentionally
  not committed; regenerate locally when argv-level replay evidence is
  needed.
- `mutants.out/lock.json` - run start time + tool version. Intentionally
  not committed because cargo-mutants records local process metadata in this file.
- `mutants.out/diff/*.diff` and `mutants.out/mutants.json` - per-mutant
  source diffs and mutant catalogue. These are produced per-run and
  published as release artifacts rather than committed to the repository.

The `mutants.out/log/` and `mutants.out/debug.log` are NOT committed
per `audits/evidence/mutants/.gitignore` (29MB+ per crate, contain
absolute paths).

## Reproducibility

`mutants.out/lock.json` and `mutants.out/outcomes.json` are intentionally
omitted by `audits/evidence/mutants/.gitignore`: cargo-mutants records
local process metadata and per-mutant console transcripts in those files. The committed evidence is
the dated JSON summary plus `caught.txt`, `missed.txt`, `timeout.txt`,
`unviable.txt`. The per-mutant `diff/` patches and `mutants.json` catalogue
are produced per-run and published as release artifacts rather than
committed to the repository.

To regenerate the omitted files locally, rerun:

```sh
cargo mutants \
  --config audits/mutation/per-crate-configs/chio-guards-2026-05-08-subset.toml \
  -p chio-guards \
  --in-place \
  --output audits/evidence/mutants/chio-guards
```

Then compare the regenerated counts against
`audits/evidence/mutants/chio-guards/2026-05-08.json`; do not commit
the regenerated `lock.json`, `outcomes.json`, `log/`, `debug.log`,
`diff/`, or `mutants.json`.
