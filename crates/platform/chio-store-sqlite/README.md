# chio-store-sqlite

SQLite-backed persistence for the Chio protocol kernel. This crate is the
concrete backend for the kernel's receipt log and every other durable store
trait the kernel depends on: budgets, human approvals, capability revocation,
execution-nonce replay guards, signing-key custody, encrypted blobs, memory
provenance, IOU envelopes, and dead letters. The store traits themselves are
defined in `chio-kernel` (and, for a few economic types, `chio-credit` and
`chio-settle`); this crate implements them against SQLite and owns no
protocol-level behavior of its own.

Reader-heavy receipt queries run against an 8-connection reader pool
(`DEFAULT_READER_POOL_MAX_SIZE`); writes serialize through a single
group-commit actor onto one writer connection (`DEFAULT_WRITER_POOL_MAX_SIZE
= 1`).

## Responsibilities

- **Receipt store** (`receipt_store`, `SqliteReceiptStore`): implements
  `chio_kernel::ReceiptStore`. Appends receipts through a group-commit writer
  actor, maintains an incrementally verified head, builds and validates
  signed checkpoints, enforces checkpoint-aligned evidence retention, and
  persists capability, session, request, and receipt lineage.
- **Receipt query** (`receipt_query`): `SqliteReceiptStore::query_receipts`,
  multi-filter, cursor-paginated tool-receipt search.
- **Operator reports** (`receipt_store/reports/*`): ten report families on
  `SqliteReceiptStore` - analytics, authorization, behavioral, billing,
  compliance, cost attribution, economic, reconciliation, settlement, and
  shared evidence.
- **Liability and underwriting persistence**
  (`receipt_store::{liability_claims, liability_market, underwriting_credit}`):
  the claim lifecycle (claim, response, dispute, adjudication, payout,
  settlement), the provider/quote/placement market, and underwriting
  decisions, appeals, credit facilities, credit bonds, and credit-loss
  lifecycle events.
- **Evidence export and federation** (`evidence_export`,
  `receipt_store::bootstrap::federated`): assembles self-contained,
  Merkle-proof-backed evidence bundles, and imports and queries signed
  evidence shares from partner Chio instances.
- **Budget store** (`budget_store`, `SqliteBudgetStore`): implements
  `chio_kernel::BudgetStore`. Per-grant invocation and cost limits with a
  two-phase authorize-then-settle model, plus replication sequencing and
  ack-head bookkeeping for multi-node budget sync.
- **Approval stores** (`approval_store`, `batch_approval_store`): implement
  `chio_kernel::ApprovalStore` and `BatchApprovalStore`. Durable
  human-in-the-loop approval requests and resolutions, and standing batch
  approvals matched by pattern, call count, and spend cap.
- **Revocation, nonce, and authority** (`revocation_store`,
  `execution_nonce_store`, `authority`): implement
  `chio_kernel::RevocationStore`, `ExecutionNonceStore`, and
  `CapabilityAuthority`. A monotonic capability revocation list, one-time
  execution-nonce reservation, and kernel signing-key custody with rotation
  and cluster-leader fencing.
- **Encrypted blobs and memory provenance** (`encrypted_blob`,
  `memory_provenance_store`): tenant-scoped ChaCha20-Poly1305 blob storage,
  and a hash-chained audit trail of agent-memory writes.
- **Settlement support** (`iou_store`, `dead_letters`): persists
  `chio_credit::IouEnvelope`s and permanently failed settlement receipts
  (`chio_settle::DeadLetterRecord`).
- **Schema governance** (`schema_version`): a shared open-path gate every
  store above calls, refusing a foreign, mismatched, or too-new database file
  before any write.

## Public API

Re-exported at the crate root (`chio_store_sqlite::*`):

| Item | Implements / provides |
|------|------------------------|
| `SqliteReceiptStore`, `BackgroundCheckpointSigner` | `chio_kernel::ReceiptStore`; background checkpoint signing |
| `SqliteBudgetStore` | `chio_kernel::BudgetStore` |
| `SqliteApprovalStore` | `chio_kernel::ApprovalStore` |
| `SqliteBatchApprovalStore` | `chio_kernel::BatchApprovalStore` |
| `SqliteRevocationStore` | `chio_kernel::RevocationStore` |
| `SqliteExecutionNonceStore`, `SqliteExecutionNonceStoreError` | `chio_kernel::ExecutionNonceStore` |
| `SqliteCapabilityAuthority` | `chio_kernel::CapabilityAuthority` |
| `SqliteMemoryProvenanceStore`, `SqliteMemoryProvenanceStoreError` | `chio_kernel::MemoryProvenanceStore` |
| `SqliteIouEnvelopeStore`, `IOU_ENVELOPE_MIGRATION` | `chio_credit::IouEnvelopeStore` |
| `SqliteEncryptedBlobStore`, `BlobHandle`, `EncryptedBlob`, `TenantId`, `TenantKey`, `encrypt_blob`, `decrypt_blob`, `BlobStoreError`, `EncryptError`, `DecryptError` | tenant-scoped encrypted-blob storage |
| `check_schema_version`, `stamp_schema_version`, `SchemaVersionError`, `CHIO_SQLITE_APPLICATION_ID` | shared schema/anchor-table gate |
| `SqlitePoolConfig`, `SqliteStoreOptions`, `DEFAULT_READER_POOL_MAX_SIZE`, `DEFAULT_WRITER_POOL_MAX_SIZE`, `is_in_memory_sqlite_path` | pool sizing and in-memory-path detection |

`SqliteReceiptStore`'s method surface is larger than `receipt_store.rs`
itself: capability lineage (`src/capability_lineage.rs`), evidence export
(`src/evidence_export.rs`), liability and underwriting persistence, and the
ten report families all add inherent methods to the same struct from
separate files under `src/receipt_store/`.

Not re-exported at the crate root:

- `dead_letters::SqliteDeadLetterStore` - opened with `open_with_pool` or
  `open_alongside(&SqliteReceiptStore)`; there is no standalone `open(path)`.
- `lineage_cte::{forward_receipt_lineage, reverse_receipt_lineage}` -
  recursive-CTE lineage walks, behind the `lineage` feature.

## Feature flags

| Flag | Effect |
|------|--------|
| `pq` | Forwards to the aliased `chio-core` (`chio-core-types`) and `chio-kernel` `pq` features (post-quantum signing support). |
| `lineage` | Enables `lineage_cte`, recursive-CTE forward/reverse walks over `receipt_lineage_statements`. Off by default; the receipt store's own delegation-chain and lineage-statement paths work without it. |

## Testing

```
cargo test -p chio-store-sqlite
cargo test -p chio-store-sqlite --features lineage
RUSTFLAGS="--cfg chio_store_sqlite_loom" cargo test -p chio-store-sqlite --test loom_receipt_writer --release
cargo bench -p chio-store-sqlite --bench store_receipt_write_throughput
```

The loom test models the receipt-commit actor's channel accounting (pre-send
inflight increment, unconditional dequeue decrement, bounded fail-closed
queue), since loom cannot execute SQLite directly.

## See also

- `chio-kernel` - defines the store traits this crate implements (`ReceiptStore`, `BudgetStore`, `ApprovalStore`, `RevocationStore`, `ExecutionNonceStore`, `CapabilityAuthority`, `MemoryProvenanceStore`).
- `chio-core-types` - protocol types persisted here (receipts, capabilities, sessions); depended on as `chio-core` in this crate's `Cargo.toml`.
- `chio-credit`, `chio-settle` - the IOU envelope store trait and dead-letter record type this crate persists.
- `chio-supervisor` - the supervised-thread runtime the receipt-commit writer actor runs under.
