# chio-attest-verify mutation evidence (post-gap-closure)

This file records the post-test-uplift mutation evidence state for
`chio-attest-verify`. The prior baseline established a 44.12% kill rate
on 68 viable mutants (86 discovered, 18 unviable). This evidence set adds 29
sigstore negative-path tests targeting surviving mutants from that baseline.

## Rerun Status

`2026-05-08-post-gap-closure.json` is **PENDING-RERUN**. The 97.9%
"closed gap" claim in the PR description is based on a focused-line
local rerun (mutants on lines the PR touched only); it is NOT a
crate-level baseline. The integrator MUST commit a fresh full-crate
`cargo mutants -p chio-attest-verify` run against this evidence set before
`audits/mutation/2026-05-08-per-crate-baseline.md` and
the audit-owned mutation baseline may record an
updated kill-rate row.

Until that rerun lands, the aggregate continues to use the prior baseline
(44.12%).

## How to Capture Evidence

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
