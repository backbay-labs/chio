# chio-credentials mutation baseline

Date: 2026-05-08.
Status: **PARTIAL -- major decision code outside mutation surface**.

## Headline

- 28 mutants discovered; 20 caught, 0 missed, 7 timeout, 1 unviable.
- Kill rate (caught / (caught + missed + timeout)): **74.1%** on the
  measured surface (`lib.rs` umbrella + `trust_tier.rs`).
- **Crate-level target satisfaction: NOT established.** The kill rate
  applies only to the small portion of the crate cargo-mutants could
  see; the 13 `include!()`d files containing credential
  verification/validation logic are NOT mutated by this run.

## Why PARTIAL

`crates/chio-credentials/src/lib.rs` uses `include!()` to fold 13
production source files into the umbrella file:

- `artifact.rs`
- `passport.rs`
- `cross_issuer.rs`
- `portable_sd_jwt.rs`
- `portable_jwt_vc.rs`
- `challenge.rs`
- `registry.rs`
- `presentation.rs`
- `policy.rs`
- `oid4vci.rs`
- `oid4vp.rs`
- `discovery.rs`
- `portable_reputation.rs`

cargo-mutants 25.x discovers source files via `mod` declarations only;
it does not see `include!()`d files as separate compilation units.
The 28 mutants therefore cover only `lib.rs` (the umbrella, top-level
functions) and `trust_tier.rs`. Credential verification/validation
logic in the 13 listed files sits OUTSIDE the mutation surface for
this run.

## Surface caveat

This baseline does not support a "target satisfied at crate level"
claim. Two options were considered:

- (a) Convert `include!()`d files to proper modules so cargo-mutants
  can scan them. Right long-term fix, deferred.
- (b) Add a machine-readable `examine_scope` caveat to the JSON and
  mark the README as PARTIAL. Selected here.

`audits/evidence/mutants/chio-credentials/2026-05-08.json` now
includes:

```json
"examine_scope": "exclude-13-included-files",
"uncovered_files": [...13 entries...],
"result_label": "PARTIAL",
"result_label_reason": "major decision code outside mutation surface (13 include!()d files)"
```

Aggregate documents (`audits/mutation/2026-05-08-per-crate-baseline.md`
where present) reflect the PARTIAL label.

## Run details

- Wall clock: ~75 minutes on a local workstation.
- Run started: 2026-05-08 04:28:52 UTC.
- Run finished: 2026-05-08 05:44:24 UTC.
- Test scope: workspace (`--workspace --exclude chio-cpp-kernel-ffi`).
- Tool: cargo-mutants 25.3.1.
- Per-crate JSON: `audits/evidence/mutants/chio-credentials/2026-05-08.json`.
- Per-mutant log: `audits/evidence/mutants/chio-credentials/mutants.out/`.

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
  -p chio-credentials \
  --in-place \
  --output audits/evidence/mutants/chio-credentials
```

Then compare the regenerated counts against
`audits/evidence/mutants/chio-credentials/2026-05-08.json`; do not
commit the regenerated `lock.json`, `outcomes.json`, `log/`, or
`debug.log`.

## Follow-up

- Convert `include!()` files to `mod` declarations; re-run.
- Until that lands, the chio-credentials row reads PARTIAL across all
  aggregate docs. The crate is NOT eligible for `target met` claims
  on this surface.
