# chio-attest-verify mutation evidence (post-gap-closure, PR #625)

This directory holds the post-test-uplift mutation evidence for
`chio-attest-verify`. The PR #619 baseline established a 44.12% kill
rate on 68 viable mutants (86 discovered, 18 unviable). PR #625 adds
29 sigstore negative-path tests targeting surviving mutants from that
baseline.

## R2 status (full-crate rerun requirement + full-crate rerun requirement)

`2026-05-08-post-gap-closure.json` is **PENDING-RERUN**. The 97.9%
"closed gap" claim in the PR description is based on a focused-line
local rerun (mutants on lines the PR touched only); it is NOT a
crate-level baseline. The integrator MUST commit a fresh full-crate
`cargo mutants -p chio-attest-verify` run on this branch before
`audits/mutation/2026-05-08-per-crate-baseline.md` and
`.planning/trajectory-5/baselines/BAR-1-MUTATION.md` may record an
updated kill-rate row.

Until that rerun lands, the aggregate continues to use the PR #619
baseline (44.12%).

## How to capture evidence

```bash
# from the workspace root
cargo mutants -p chio-attest-verify \
  --output audits/evidence/mutants/chio-attest-verify

# regenerate the summary (uses the durable-key whitelist from
# annotation preservation rule - hand-curated annotations like target_kill_rate
# survive but stale release-truth keys are wiped):
bash audits/mutation/summary.sh chio-attest-verify
```

After the run completes, replace `2026-05-08-post-gap-closure.json`'s
`PENDING-RERUN` block with `target_met`, `result_label`, `evaluated`,
and `total_discovered` populated from the new `mutants.out/`.
