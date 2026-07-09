# SP-2 Design: Storage hot path (RFC-0006)

- Date: 2026-07-07
- Source spec: `docs/architecture/reliability/RFC-0006-storage-hot-path.md` (the technical source of truth; this document records the implementation-cycle decisions only)
- Program: reliability criticals, track B stage 1 (blocks SP-3 / RFC-0007)
- Closes: F22 (high), F28 (high), F29 (high), F07 (medium)
- Branch: `chio/rfc-0006-storage` off `main`, one PR

## Goal

Make per-append receipt-store work independent of total history, move
checkpoint construction off the request path, and route every write through
the single writer actor. Today every append re-validates the entire history
(~2N Ed25519 verifications at N receipts) inside the kernel-global write
lock, and seven write paths bypass the writer actor through the reader pool.

## In scope (the RFC's four rollout stages, in order)

1. **True single writer (F29).** Generic `Write(WriterClosure)` actor command
   plus `WriterHandle::run_write`; rewrite the NINE bypass writers
   (session anchors, request lineage, receipt-lineage statements, child
   receipts, consuming-authorization appends, manual checkpoint creation,
   IOU store, plus the two lazy-lineage writers found by the 2026-07-07
   verify pass: `list_receipt_lineage_statement_links` and
   `receipt_lineage_verification`) onto it; fold the receipt+lineage insert
   into one transaction in `append_chio_receipt_returning_seq` (using the
   real `canonical_json_bytes` pattern; `canonical_receipt_json_string` does
   not exist). Correctness-preserving; ships as the first commit(s).
2. **Verified-head cache (F22).** `VerifiedHead` owned by the actor thread,
   seeded once at open by the existing full verification;
   `verify_head_against_latest_checkpoint` (one indexed row, deserializing
   only `KernelCheckpointBody` so no Ed25519 verify returns to the append
   path) and the delta-aggregate projection cross-check
   (`claim_log_delta_count_and_max_seq_tx`, an O(batch) indexed range scan
   over `entry_seq > head.claim_log_max_seq`) replace the two O(N) calls on
   the append path. Head-resync rule: after every `Write` closure the actor
   re-runs the delta aggregate plus one latest-checkpoint row read so
   writer-routed inserts cannot cause false Conflicts. Behind
   `incremental_verification: bool` (default `true`; `false` keeps today's
   full per-append verification for A/B on a suspect database). The flag is
   read-only after open. KEPT per program decision 2026-07-07.
3. **`chio receipt audit` CLI.** Promote the existing full verification
   (extend `cmd_receipt_checkpoint_verify` in
   `crates/products/chio-cli/src/cli/trust/receipt/health.rs`) to
   `audit` / `audit --repair`, which re-runs
   `validate_claim_receipt_log_entries` plus
   `verify_checkpoint_chain_integrity` and re-seeds the head.
4. **Background checkpoints (F28, F07).** `BackgroundCheckpointSigner`
   delivered via a new `InstallSigner` actor-command variant
   (`enable_background_checkpoints` sends it); `maybe_build_checkpoint` on
   the actor thread using the cached head as predecessor;
   `insert_checkpoint_incremental` replaces the triple-verify
   `store_kernel_checkpoint_tx` path; kernel drops request-path checkpoint
   construction from `record_chio_receipt` and `record_child_receipts` and
   retires the 8-round retry loop. `flush_report` switches to the head
   snapshot; `receipt_checkpoint_status` deliberately stays on full
   verification as an operator surface (with `chio receipt audit`).
   `audit --repair` re-seeds the head via a writer command that reruns
   `seed_verified_head`.

## Plan-stage refinements (2026-07-07, recorded from plan grounding)

The implementation plan diverges from the RFC text in five grounded ways;
the plan is authoritative where they conflict:

- Twelve bypass sites, not nine: plan grounding found three more reader-pool
  write paths (`store_checkpoint` trait/inherent,
  `record_checkpoint_publication_trust_anchor_binding`, and the trait
  `append_chio_receipt_canonical` separate lineage transaction). All twelve
  route through the writer.
- The lineage fold preserves ADR-0013 group commit: lineage is folded into
  the group-commit batch transaction (an `ensure_lineage` flag), not a
  per-receipt `run_write` round trip. Trait-append serialization stays
  `serde_json::to_string` to preserve duplicate byte-identity with existing
  rows.
- `verify_head_against_latest_checkpoint` does bounded forward catch-up
  (verify only NEW checkpoints, O(delta), fail-closed on mutation or
  regression) instead of strict conflict-on-any-mismatch, which would break
  the existing two-stores-one-file kernel tests and the CLI
  checkpoint-create flow.
- `maybe_build_checkpoint` derives the next range from the cached head; the
  RFC's sketch called `next_checkpoint_range_for_connection`, which is O(N).
- `WriterClosure` receives `Result<&mut Connection, _>` so the actor can
  fail jobs closed (pool error, poisoned head) without executing them.

## Out of scope (explicit cuts)

- `soak_flat_append_latency_10m` and `chaos_no_busy_under_multiwriter`
  (belong to `PLAN-load-soak-chaos-program.md`). The PR keeps the microbench
  (append cost within a constant factor across N in {1e3, 1e5, 1e6}) as its
  scale proof.
- Retention/rotation work of any kind (SP-3 / RFC-0007).
- Converting `receipt_store_write_lock` to an async mutex (rejected in the
  RFC).

## Interfaces produced (consumed by SP-3)

- `WriterHandle::run_write<T, F>(&self, job: F) -> Result<T, ReceiptStoreError>`
- `ReceiptCommitCommand::Write(WriterClosure)` and
  `ReceiptCommitCommand::InstallSigner(BackgroundCheckpointSigner)`
  (SP-3 adds `Rotate` beside them)
- `VerifiedHead` (actor-private) with `checkpoint_seq()` /
  `checkpointed_entry_seq()`
- `SqliteReceiptStore::enable_background_checkpoints(BackgroundCheckpointSigner)`
- `chio receipt audit [--repair]`
- Writer-drain semantics: the actor commits any pending append batch before
  executing a `Write` job (SP-3 reuses this for `Rotate` and `VACUUM`)

No wire, schema, or receipt changes. The verified head is in-memory only.
No new `ReceiptStoreError` variants (mapping onto `Conflict` / `Pool` per the
RFC's error taxonomy).

## Tests (PR gate)

Unit (head update, tampered-checkpoint rejection, one-checkpoint-per-threshold
with predecessor linkage), `prop_incremental_head_matches_full_audit`,
`append_denies_when_head_diverges` (tamper, fail-closed),
`receipt_and_lineage_commit_atomically`, loom over {Append, Write, Flush}
(single-writer serialization, no lost inflight accounting), the reader-pool
never-writes assertion, the append microbench, and the unchanged ADR-0013
durability tests.

## Acceptance criteria

RFC-0006 acceptance criteria verbatim. Headline proof: append microbench at
N = 1e6 within 2x of N = 1e3, and no full-verification call left on the
append or checkpoint hot path. Workspace gate: the standard one-liner.

## Risks carried from the RFC

- O(1) count/max cross-check is weaker than full set-equality (intended
  trade; ingest-time signature check + predecessor digest bound substitution,
  `chio receipt audit` is the periodic deep check).
- Fail-closed head poisoning stalls appends until `audit --repair` (health
  surfaces it via `last_error`).
- A crash can defer the newest batch's Merkle commitment (already true under
  ADR-0008; receipt durability unaffected).
