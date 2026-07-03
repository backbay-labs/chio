# chio-weights mutation baseline

This directory holds the per-mutant cargo-mutants output for the
`chio-weights` crate (the model-card trust-boundary surface: signed
weights cards, cosign bundle helper, kernel binding refusal,
`chio bind --card`). The seed measurement closes the chio-weights
BASELINE-GAP row.

## Run metadata

| Field | Value |
|---|---|
| Crate | `chio-weights` |
| Date | 2026-05-08 |
| Evidence scope | local evidence run |
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

Same package-only rationale as the chio-attest-verify and chio-policy
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
used by the other per-crate mutation baselines.

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

This avoids the chio-guards "hand-picked subset"
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

**Target satisfaction**: per `releases.toml [mutants]`, the configured
catch-ratio target is 80% and the activation floor is 65%. The 65%
value is a floor for early activation posture, not the per-crate
target. chio-weights is not currently enumerated in the canonical six
crate mutation matrix, but this evidence treats it as a model-card
trust-boundary surface. **Observed 68.25% on a FULL 66/66 run; the
activation floor is cleared, but the configured 80% target is not met.**

### Per-file breakdown

| File | Caught | Missed | Timeout | Unviable | Kill rate |
|---|---|---|---|---|---|
| `bundle.rs` | 1 | 0 | 0 | 1 | 100.0% |
| `card.rs` | 25 | 14 | 0 | 1 | 64.10% |
| `error.rs` | 2 | 0 | 0 | 0 | 100.0% |
| `lineage.rs` | 15 | 6 | 0 | 1 | 71.43% |

The crate-aggregate 68.25% kill rate clears the 65% activation floor
but remains below the configured 80% target; `card.rs` alone is at
64.10% (below even the activation floor). The 14 missed
mutants in `card.rs` cluster on `StringSet` pure-getter methods and
two boundary `<` comparisons (see categorisation below).

## Surviving mutants (top 5 by file-line)

The full list of 20 missed mutants is enumerated in `2026-05-08.json`
under `missed_mutants`. The top 5 (chosen as one representative per
distinct survival pattern):

1. `crates/chio-weights/src/card.rs:237:16: replace < with <= in ModelCard::require_live`
   - boundary condition: `now < self.expires_at` (production-correct
     polarity: `<` means a card whose `expires_at` exactly equals
     `now` is treated as expired). Replacing `<` with `<=` would
     accept `now == expires_at` as still live. The current strict-`<`
     semantics deliberately reject the boundary; no test fixture
     pins this by asserting `WeightsError::Expired` when
     `now == expires_at`, so the mutation survives silently.
2. `crates/chio-weights/src/card.rs:226:28: replace < with <= in ModelCard::validate`
   - boundary condition: `self.expires_at < self.issued_at`
     (production-correct polarity: `<` means a zero-duration card
     where `expires_at == issued_at` is currently *accepted*; only
     `expires_at` strictly before `issued_at` is rejected). Replacing
     `<` with `<=` would start *rejecting* zero-duration cards
     (`expires_at == issued_at`), making validation stricter than
     today's semantics. No test fixture pins
     `expires_at == issued_at` to the current accept-as-Ok outcome,
     so the mutation survives silently.
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
| `<` -> `<=` boundary condition | 2 | 2 short tests pinning today's polarity: `validate` Ok when `expires_at == issued_at`; `require_live` Err(Expired) when `now == expires_at` |
| `anchor_projection_bytes` constant return | 3 | 1 golden-bytes round-trip test in lineage.rs |
| `sha256_hex` constant return | 2 | 1 RFC 6234 / FIPS 180-4 vector test in lineage.rs |
| `verify_model_card_anchor` negation delete | 1 | 1 branch-coverage test in lineage.rs |

Closing the gap would push the kill rate from 68.25% toward 100% on
this surface. **Follow-up is a separate PR** (mutation evidence item style); this
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

## Post-Kani rerun note

The chio-weights Kani harness is not yet in this evidence set. The mutation
run here is against current main (`708c7bb33`). Once that harness lands,
it exercises additional invariants
(notably the kernel binding refusal contract) and a re-run is expected
to score higher than 68.25% on the same `examine_globs` surface.
`chio-weights` is not in the current `.github/workflows/mutants.yml`
PR or nightly matrix, so the next authoritative re-baseline is a
local/manual `cargo mutants` run unless that workflow is extended
to include `chio-weights`.

## Files in this directory

- `2026-05-08.json`: machine-readable per-crate summary (counts,
  kill rate, missed-mutant categorisation, follow-up plan).
- `README.md`: this file.
- `mutants.out/`: per-mutant output captured by cargo-mutants
  (`caught.txt`, `missed.txt`, `timeout.txt`, `unviable.txt`).
  The per-mutant `diff/` patches and `mutants.json` catalogue are
  produced per-run and published as release artifacts rather than
  committed to the repository. The `log/` directory, `debug.log`,
  `outcomes.json`, and `lock.json` are also NOT committed; they contain
  large transcripts and local process metadata.

## Reproducibility

`mutants.out/lock.json` and `mutants.out/outcomes.json` are intentionally
omitted by `audits/evidence/mutants/.gitignore`: cargo-mutants records
local process metadata and per-mutant console transcripts in those files. The committed evidence is
the dated JSON summary plus `caught.txt`, `missed.txt`, `timeout.txt`,
`unviable.txt`. The per-mutant `diff/` patches and `mutants.json` catalogue
are produced per-run and published as release artifacts rather than
committed to the repository.

To regenerate locally, rerun:

```sh
cargo mutants \
  --config audits/mutation/per-crate-configs/chio-weights.toml \
  -p chio-weights \
  --in-place \
  --baseline=skip \
  --output audits/evidence/mutants/chio-weights
```

Then compare the regenerated counts against
`audits/evidence/mutants/chio-weights/2026-05-08.json`; do not commit
the regenerated `lock.json`, `outcomes.json`, `log/`, `debug.log`,
`diff/`, or `mutants.json`.
