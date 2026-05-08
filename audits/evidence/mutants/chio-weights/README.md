# chio-weights mutation baseline (TRJ5-A1)

This directory holds the per-mutant cargo-mutants output for the
`chio-weights` crate (the M10 phase 4 model-card surface: signed
weights cards, cosign bundle helper, kernel binding refusal,
`arc bind --card`). The seed measurement closes the chio-weights
BASELINE-GAP row.

## Run metadata

| Field | Value |
|---|---|
| Crate | `chio-weights` |
| Date | 2026-05-08 |
| Branch | `claude/trj5/a1-mutation-weights` |
| Base SHA | `708c7bb33df43594f5e76542b05fca7a56d9689e` (current main) |
| Tool | cargo-mutants 25.3.1 (matches the workspace pin in `.cargo/mutants.toml`) |
| Wall clock | 6m 41s (per cargo-mutants stdout summary line) |
| Run started | 2026-05-08T16:21:25Z |
| Run finished | 2026-05-08T16:28:14Z |
| Run status | FULL: 66/66 mutants evaluated; cargo-mutants returned exit 2 (mutants missed; expected) |

## Command

```sh
cargo mutants \
  --config audits/mutation/per-crate-configs/chio-weights.toml \
  -p chio-weights \
  --in-place \
  --baseline=skip \
  --output audits/evidence/mutants/chio-weights
```

The `--config audits/mutation/per-crate-configs/chio-weights.toml`
override scopes the per-mutant test invocation to
`--package chio-weights` rather than the full workspace. Rationale
below.

## Test-scope deviation rationale

Same rationale as PR #619 (chio-attest-verify) and PR #623
(chio-policy): the workspace test harness contains a pre-existing
failing test in `chio-acp-proxy` unrelated to chio-weights:

```
chio-acp-proxy::attestation_and_telemetry_tests::
  kernel_capability_checker_rejects_untrusted_and_tampered_tokens
  -- panicked: assertion failed: verdict.reason.contains("signature")
                                  || verdict.reason.contains("untrusted")
  -- actual reason: "capability verification failed:
                     capability issuer is not a trusted CA"
```

This failure exists on `main` at SHA `708c7bb33`. If the chio-weights
mutation run used the workspace test scope, every chio-weights mutant
would be marked CAUGHT because the chio-acp-proxy assertion would
always fail before the chio-weights mutation could be exercised. The
kill rate would be ~100% but the measurement would be meaningless.

To produce an honest signal, this run scopes the per-mutant test
invocation to `--package chio-weights` only via the override config at
`audits/mutation/per-crate-configs/chio-weights.toml`. The
`test_scope` field in `2026-05-08.json` is
`"package-only (cargo test --verbose --package=chio-weights@0.1.0 --package chio-weights)"`,
verified empirically during the run by inspecting cargo-mutants'
debug log, which recorded the actual test invocation as
`cargo test --verbose --package=chio-weights@0.1.0 --package chio-weights`
(no `--workspace`). The full `debug.log` is not committed (see
"Files in this directory" below); this matches the reference layout
in PR #619 / #622 / #623.

## Examine-globs surface

The override config covers all four logic-bearing source files of the
crate:

```
crates/chio-weights/src/bundle.rs
crates/chio-weights/src/card.rs
crates/chio-weights/src/error.rs
crates/chio-weights/src/lineage.rs
```

`lib.rs` is omitted because it is a re-export-only umbrella (lines
38-48: `pub mod bundle / card / error / lineage` plus `pub use`
re-exports) with no logic to mutate.

This avoids the chio-guards (PR #621) "hand-picked subset"
anti-pattern: every `pub mod` containing logic is included, so the
measurement is a true crate-level baseline rather than a partial
sample.

## Result

**FULL run: 66 of 66 mutants evaluated.** Per-status counts:

| Status | Count |
|---|---|
| caught | 43 |
| missed | 20 |
| timeout | 0 |
| unviable | 3 |

**Kill rate**: caught / (caught + missed + timeout) = 43 / (43+20+0)
= 43/63 = **68.25%** (excluding 3 unviable per cargo-mutants 25.x
convention).

**Target satisfaction**: per
`.planning/trajectory-5/lane-a-floor/mutation-budget.md`, the
non-`chio-attest-verify` per-crate target is `>= 65%`. chio-weights
is not enumerated in that table (the table covers the canonical six
trust-boundary crates per `releases.toml [trust_boundary_crates]`),
but the >=65% bucket applies because the crate is a model-card
trust-boundary surface. **Observed 68.25% on a FULL 66/66 run; target
met.**

### Per-file breakdown

| File | Caught | Missed | Timeout | Unviable | Kill rate |
|---|---|---|---|---|---|
| `bundle.rs` | 1 | 0 | 0 | 1 | 100.0% |
| `card.rs` | 25 | 14 | 0 | 1 | 64.10% |
| `error.rs` | 2 | 0 | 0 | 0 | 100.0% |
| `lineage.rs` | 15 | 6 | 0 | 1 | 71.43% |

The crate-aggregate 68.25% kill rate clears the >=65% target;
`card.rs` alone is at 64.10% (just under the bar). The 14 missed
mutants in `card.rs` cluster on `StringSet` pure-getter methods and
two boundary `<` comparisons (see categorisation below).

## Surviving mutants (top 5 by file-line)

The full list of 20 missed mutants is enumerated in `2026-05-08.json`
under `missed_mutants`. The top 5 (chosen as one representative per
distinct survival pattern):

1. `crates/chio-weights/src/card.rs:237:16: replace < with <= in ModelCard::require_live`
   - boundary condition: `now < self.expires_at`. Replacing with `<=`
     allows now == expires_at to pass. No test fixture lands on the
     boundary.
2. `crates/chio-weights/src/card.rs:226:28: replace < with <= in ModelCard::validate`
   - boundary condition: `not_before < expires_at`. Replacing with
     `<=` allows zero-duration cards to validate. No test fixture has
     `not_before == expires_at`.
3. `crates/chio-weights/src/card.rs:123:9: replace StringSet::as_set -> &BTreeSet<String> with Box::leak(Box::new(BTreeSet::new()))`
   - pure getter with no dedicated unit test asserting the returned
     set's contents.
4. `crates/chio-weights/src/lineage.rs:124:5: replace anchor_projection_bytes -> Result<Vec<u8>, WeightsError> with Ok(vec![])`
   - pinned through both sides of the round-trip (anchor produces,
     verifier recomputes through same helper); needs a golden-bytes
     test fixture that locks against a constant.
5. `crates/chio-weights/src/lineage.rs:146:5: replace sha256_hex -> String with String::new()`
   - same round-trip pinning as #4; needs a published RFC 6234 / FIPS
     180-4 vector test fixture.

## Surviving-mutant categories and follow-up plan

(Full categorisation in `2026-05-08.json` under
`missed_mutant_categories`.)

| Category | Count | Estimated test additions to close |
|---|---|---|
| `StringSet` getter, no dedicated test | 11 | ~6-8 short tests in card.rs |
| `<` -> `<=` boundary condition | 2 | 2 short tests with exact-equal timestamps |
| `anchor_projection_bytes` constant return | 3 | 1 golden-bytes round-trip test in lineage.rs |
| `sha256_hex` constant return | 2 | 1 RFC 6234 / FIPS 180-4 vector test in lineage.rs |
| `verify_model_card_anchor` negation delete | 1 | 1 branch-coverage test in lineage.rs |

Closing the gap would push the kill rate from 68.25% toward 100% on
this surface. **Follow-up is a separate PR** (TRJ5-A1.8 style); this
PR scope is the BASELINE measurement only.

## Unviable mutants

Three mutants were unviable (cargo-mutants could not compile them):

```
crates/chio-weights/src/bundle.rs:78:5:  replace verify_model_card_bundle -> Result<VerifiedModelCard, WeightsError> with Ok(Default::default())
crates/chio-weights/src/card.rs:257:9:   replace ModelCard::from_canonical_json -> Result<Self, WeightsError> with Ok(Default::default())
crates/chio-weights/src/lineage.rs:168:5: replace anchor_model_card -> Result<ModelCardLineageAnchor, WeightsError> with Ok(Default::default())
```

These are unviable because `VerifiedModelCard`, `ModelCard`, and
`ModelCardLineageAnchor` do not implement `Default`, so the constant
substitution does not type-check. Per cargo-mutants 25.x convention,
unviable mutants are excluded from the kill-rate denominator.

## Post-#613 rerun note

PR #613 (chio-weights Kani harness) is open against main and not yet
merged. The mutation run here is against current main (`708c7bb33`).
Once #613 lands, the Kani harness exercises additional invariants
(notably the kernel binding refusal contract) and a re-run is expected
to score higher than 68.25% on the same `examine_globs` surface. The
CI hosted-nightly `mutants.yml` lane (4-hour-per-crate budget) is the
authoritative re-baseline after #613 merges.

## Files in this directory

- `2026-05-08.json`: machine-readable per-crate summary (counts,
  kill rate, missed-mutant categorisation, follow-up plan).
- `README.md`: this file.
- `mutants.out/`: per-mutant output captured by cargo-mutants
  (`caught.txt`, `missed.txt`, `timeout.txt`, `unviable.txt`,
  `mutants.json`, `outcomes.json`, `lock.json`, and per-mutant
  `diff/` patches). The per-mutant `log/` directory and `debug.log`
  produced by cargo-mutants are NOT committed (they are large and
  redundant with the per-mutant diffs and outcomes.json); this
  matches the chio-attest-verify (PR #619), chio-anchor (PR #622),
  and chio-policy (PR #623) reference layouts.
