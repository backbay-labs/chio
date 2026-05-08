# chio-attest-verify Kani harness run evidence (Kani harness evidence)

**Date**: 2026-05-08
**PR**: #605 (PR branch)
**Audit refs**: review item (THIRD-ROUND-CODE-SECURITY-AUDIT-2026-05-08)
**Status**: DEFERRED-PARTIAL (run-evidence not committed in this PR)

## Required posture per audit review item

The audit states the proof surface must EITHER:
1. Commit a Kani run transcript for each PR-tier harness, OR
2. Label the proof surface as partial/nightly-only in ship-bar truth.

This evidence file selects option (2): the chio-attest-verify proof
surface is labeled **MODEL-PARTIAL** for release work; transcripts are deferred
to the trj6 follow-up that wires the multi-crate Kani CI workflow
(PR #607) into a passing pipeline. Until then, the source-only enrollment
is honest about its scope and the manifest pins exactly which harnesses
the post-merge CI will iterate.

## Enrolled harnesses (from `.kani/harnesses.toml`)

| # | Harness                                                          | Lane | Posture     |
|---|------------------------------------------------------------------|------|-------------|
| 1 | `public_expect_report_data_determinism_under_input_change`       | pr   | DIRECT      |
| 2 | `public_nitro_verify_quote_rejects_report_data_mismatch`         | pr   | MODEL-ONLY  |
| 3 | `public_sev_snp_verify_quote_rejects_unacceptable_tcb`           | pr   | MODEL-ONLY  |
| 4 | `public_tdx_verify_quote_rejects_algorithm_mismatch`             | pr   | MODEL-ONLY  |

DIRECT = the harness body invokes the production `pub fn` directly.
MODEL-ONLY = the harness proves an algebraic surrogate
(`model_verify_quote`) over the post-fix production order
`TCB -> algorithm -> report_data`. Live-runtime regression for the
MODEL-ONLY harnesses is asserted by the per-backend unit tests cited
in the manifest `notes` for each entry (audit P0-018).

## Why the run transcripts are deferred

1. cargo-kani 0.67.0 PR-tier runs for the chio-attest-verify backend
   harnesses depend on cryptographic-verification call paths
   (`Ed25519`, `X.509`, `COSE/CBOR`) that the audit P0-018 deferral
   classifies as out-of-symbex-budget for synchronous PR runs without
   the algebraic surrogate. The MODEL-ONLY harnesses execute the
   surrogate; the DIRECT harness on `expect_report_data` is a pure
   function and is tractable, but committing only one of four
   transcripts is more confusing than committing none.
2. The multi-crate Kani CI runner (`scripts/run-kani-manifest.sh`)
   ships in PR #607, not this PR. The transcript cadence is intended
   to come from the merged-main CI iteration, not from a hand-run on
   one PR branch.
3. Local cargo-kani availability (verified: `cargo kani --version`
   reports `cargo-kani 0.67.0`) does not change the audit's
   "either-or" requirement. Picking the labeling option keeps the
   ship-bar honest while the CI hook lands.

## Ship-bar truth

`scripts/check-release work-ship-bar.sh` does NOT (yet) gate on Kani run
transcripts. The Bar 1 mutation kill-rate / Bar 2 negative-conformance
fixtures / Bar 3 demo-receipt rows it does gate on are unaffected by
this deferral. The chio-attest-verify Kani enrollment is recorded as
**source-only PARTIAL** in the release notes (PR #618).

## Next steps (trj6)

1. PR #607 multi-crate runner merges; CI iterates the manifest.
2. CI-produced transcripts are committed under
   `audits/evidence/kani/<crate>-<harness>-<date>.txt` per the
   per-harness convention used by the chio-anchor / chio-weights
   evidence file (`2026-05-08-anchor-weights-runs.md`).
3. The MODEL-ONLY harnesses are upgraded to direct-impl harnesses
   only after the algebraic surrogate is replaced by the
   `pub(crate) fn classify_quote_outcome(...)` extraction the
   audit P0-018 calls for.

## Honesty note

This evidence file documents **why no transcripts are committed** rather
than presenting the absence as completion. The Kani enrollment is real;
the run-evidence is deferred. PR #605 ships harness source plus manifest
entries; transcripts arrive from the CI iteration in trj6.
