# Replay Proptest Regressions

This directory is the checked-in archive root for minimized failures from
`crates/chio-kernel/tests/replay_proptest.rs`.

The replay proptest suite uses `FileFailurePersistence::Direct` and writes
its failure database to:

```text
tests/replay/proptest-regressions/replay_proptest.txt
```

The `chio-replay-gate` workflow uploads this directory as the
`proptest-regressions` artifact whenever the `proptest` job fails. The CI
job compiles the release test target first, then enforces the Phase 5
runtime budget with `timeout 30s` around the
`cargo test -p chio-kernel --test replay_proptest --release -- --nocapture`
harness invocation.

To promote a real regression into the archive:

1. Reproduce the failing case locally with the artifact contents copied into
   this directory.
2. Confirm `cargo test -p chio-kernel --test replay_proptest -- --nocapture`
   replays the failure from `replay_proptest.txt`.
3. Commit the minimized `replay_proptest.txt` alongside the fix or the
   intentional behavior-change review.

Do not add M02 libfuzzer seed glue here. `crates/chio-kernel/fuzz/seeds/`
is owned by the M02 fuzzing lane; this directory is only the replay
proptest failure archive consumed by M04 CI.
