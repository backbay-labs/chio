# SP-3 Design: Retention without bricking (RFC-0007)

- Date: 2026-07-07
- Source spec: `docs/architecture/reliability/RFC-0007-retention-without-bricking.md` (the technical source of truth; this document records the implementation-cycle decisions only)
- Program: reliability criticals, track B stage 2
- Blocked by: SP-2 (RFC-0006). The implementation plan for this sub-project
  is written AFTER SP-2 lands, because rotation runs on the writer actor
  SP-2 introduces and the file/line anchors in the RFC move under that
  refactor.
- Closes: F23 (high, the store-bricking finding), F24 (high), F30 (medium)
- Branch: `chio/rfc-0007-retention` off `main` (after SP-2 merges), one PR

## Goal

Retention that preserves the append invariant: archival co-archives and
deletes the `claim_receipt_log_entries` projection rows together with the
source rows, atomically, along checkpoint boundaries, so the first rotation
no longer permanently bricks the store (every write and reopen failing with
"claim receipt log entry set drift detected"). Wire retention into the
kernel so the database stops growing without bound, and fix size accounting
so rotation converges.

## In scope (full RFC, per program decision 2026-07-07)

1. **Checkpoint-aligned watermark.** `W` computed in the `entry_seq` domain
   (largest checkpoint `batch_end_seq` whose covered prefix has fully aged);
   no-op when `W == 0`.
2. **Co-archive-and-delete.** Archive schema gains
   `claim_receipt_log_entries` (with `entry_seq` preserved),
   `settlement_reconciliations`, `metered_billing_reconciliations`,
   `chio_authorization_receipt_consumptions`; copy-then-verify-then-delete
   with the delete plus trigger drop/recreate plus watermark insert in one
   `BEGIN IMMEDIATE` transaction on the writer connection; then
   `incremental_vacuum` + `wal_checkpoint(TRUNCATE)`.
3. **Validator hardening.** The empty-projection backfill refuses to
   regenerate a checkpointed or archived range
   (`ArchivedRangeProjection`, fail-closed).
3a. **Watermark-aware checkpoint chain verification** (added by the
   2026-07-07 verify pass, which found a second independent brick):
   `verify_checkpoint_chain_integrity` loads `W` from
   `receipt_retention_watermark` and skips only
   `validate_checkpoint_against_claim_log` for checkpoints with
   `batch_end_seq <= W`; signed body, signature, and predecessor linkage
   remain verified, and archived checkpoints are never deleted from
   `kernel_checkpoints`. Lands together with co-archive-and-delete.
3b. **Tenant-scoped archival rejection.** Tenant-scoped archival cannot be
   expressed as a prefix watermark; rotation with
   `RetentionConfig.tenant_id = Some(..)` fails closed with the new
   `RetentionTenantScopeUnsupported` error variant.
4. **Writer-actor integration.** `ReceiptCommitCommand::Rotate`; public API
   moves to `&self` and dispatches to the actor; retention no longer writes
   through the reader pool.
5. **Kernel wiring (F24).** `RetentionConfig.check_interval_secs` (default
   3600); kernel maintenance task calling `rotate_if_needed`; health reports
   `db_size_bytes` and `retention_watermark_entry_seq` even when retention is
   disabled; `auto_vacuum = INCREMENTAL` for new stores plus the one-time
   migration for existing stores.
6. **Size accounting.** `live_db_size_bytes` ((page_count - freelist) *
   page_size) drives the rotation trigger so it converges.
7. **Recovery.** `chio receipt retention repair --archive <path>` for stores
   bricked under the pre-fix code, fail-closed per the RFC's five steps; the
   repaired watermark is checkpoint-aligned (smallest `batch_end_seq >=
   max(extra.entry_seq)`) so no checkpoint straddles it.
8. New error variants: `RetentionArchiveIncomplete`,
   `RetentionWatermarkRegression`, `ArchivedRangeProjection`,
   `RetentionTenantScopeUnsupported`.
9. New table: `receipt_retention_watermark` (append-only ledger; effective
   watermark is MAX; regressions rejected).

## Out of scope (explicit cuts)

- `soak_rotation_under_continuous_append` (belongs to
  `PLAN-load-soak-chaos-program.md`).
- Pre-fix archives remain unverifiable by design (reader detects the missing
  archive claim-log table and refuses; operators re-archive from a restored
  live store). No attempt to retrofit them.

## Interfaces consumed (from SP-2)

`WriterHandle::run_write`, `ReceiptCommitCommand` extension point,
writer-drain semantics, `chio receipt audit` (full set-equality lives there
after SP-2 demotes it off the append path).

## Tests (PR gate)

`prop_retention_preserves_append_invariant` (the state-machine proptest that
would have caught F23, F30, and the reopen brick),
`retention_then_append_and_reopen_succeeds` (the headline regression),
`bricked_store_repair_restores_append`,
`size_rotation_converges_below_threshold`,
`settlement_and_metered_rows_are_archived_not_cascaded`,
`backfill_refuses_regeneration_over_checkpointed_range`,
`checkpoint_chain_watermark_exemption` (post-rotation checkpoint creation,
status, audit, and reopen succeed; tamper above the watermark still fails;
a forged watermark is caught by audit against the archive),
`tenant_scoped_rotation_rejected`,
loom over concurrent `Append` + `Rotate`, and the reader-pool-never-rotates
assertion.

## Acceptance criteria

RFC-0007 acceptance criteria verbatim. Workspace gate: the standard
one-liner. Rollout inside the PR mirrors the RFC: co-archive-and-delete with
retention defaulting to `None` first, kernel wiring and `auto_vacuum`
migration last.

## Risks carried from the RFC

- Rotation briefly pauses appends on the writer actor (bounded by
  checkpoint-aligned prefix size; hourly default).
- Cross-database WAL atomicity is avoided structurally
  (idempotent copy completes before any delete; delete confined to `main`).
- Inclusion proofs for archived receipts are served from the archive file,
  not the live store (intended trade).
