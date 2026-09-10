# Native proof run interruption and bounded resume prerequisite

The metadata-only full release attempt at abfd3b56111e2838ae648a4a82c5059eda16e210 was interrupted during Lean/mathlib compilation after shared machine load exceeded 240. SIGINT was sent only to verified owned Lake PID 71524. The enclosing qualification returned 130, and no owned Lean child remained afterward. Proof caches and raw logs remain in /tmp/chio-kernel-release-clean-20260909. This is an incomplete run, not proof failure or release success.

The owner then directed that this native full run not restart merely to reach the known Linux-only formal toolchain requirement. Continue exact-source full qualification through the checked-in Ubuntu workflow, with its pinned toolchains and all downstream gates.

Exact Lean 4.28 tool help and pinned upstream source were inspected for future bounded execution. Lean CLI supports `-j` / `--threads`; Lake help has no direct jobs option. `src/runtime/object.cpp` at the v4.28.0 tag reads LEAN_NUM_THREADS for its runtime task manager (lines 1014-1029). The installed Lean Shell also defaults its frontend thread count to hardware concurrency, so this review does not assert that LEAN_NUM_THREADS alone caps every compiler subprocess. No unverified concurrency override was used to claim a passing gate. A future local restart must confirm both scheduler and child compiler limits first.

Pinned upstream source inspected: https://github.com/leanprover/lean4/blob/v4.28.0/src/runtime/object.cpp. The retrieved source files in this directory are provenance for this control inspection, not altered proof tooling.
