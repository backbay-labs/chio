# Chio pheromone storage commit failure reporting

## Objective

Make per-frame receive reporting distinguish post-validation storage commit
failures from policy or frame validation failures. Storage failures must return
frame code `storage_commit_failed` and leave the batch report rejected or
partial without exposing low-level store codes as admission semantics.

## Plan

1. Add a failing runtime receiver test with a store that rejects `admit_deposit`
   using a simulated SQLite commit failure.
2. Map storage-layer errors returned from `admit_deposit` to frame code
   `storage_commit_failed`.
3. Preserve existing validation error codes such as `batch_recipient_mismatch`,
   `workflow_context_mismatch`, `replay_window_exceeded`, and scarcity failures.
4. Run focused runtime tests, clippy, formatting, schema gate, whitespace, dash
   scan, and status.

## Verification

- [x] `cargo test -p chio-pheromone-runtime storage_commit_failure_is_reported_without_accepting_frame --test runtime_receiver` fails before implementation.
- [x] `cargo test -p chio-pheromone-runtime storage_commit_failure_is_reported_without_accepting_frame --test runtime_receiver`
- [x] `cargo test -p chio-pheromone-runtime --test runtime_receiver`
- [x] `cargo clippy -p chio-pheromone-runtime --all-targets -- -D warnings`
- [x] `bash scripts/check-chio-pheromone-runtime.sh --schema-only`
- [x] `cargo fmt --all -- --check`
- [x] `git diff --check`
- [x] Unicode dash scan over changed files.
