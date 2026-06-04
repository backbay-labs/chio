# chio-store-sqlite Architecture Notes

## Module Boundaries

`receipt_store` owns receipt persistence, query support, report generation,
checkpoint projection, and evidence-retention helpers. `budget_store.rs` owns
durable grant usage, authorization holds, mutation events, replication sequence
allocation, and idempotent replay handling. The smaller store modules own
approval state, batch approval state, revocations, execution nonces,
encrypted blobs, IOU envelopes, dead letters, memory provenance, and evidence
export.

## Pain Points

`budget_store.rs` is a high-authority persistence boundary. Several SQLite row
decoders read persisted integer fields with `.max(0)` and then cast them into
unsigned Rust counters. That masks corrupt or manually edited negative
`invocation_count`, cost, sequence, hold, or mutation fields as zero. A bad row
can therefore continue through budget decisions, replication snapshots, and
idempotent retry checks as if it were a valid empty budget state.

The budget decoder cleanup does not cover the capability-lineage table.
`capability_lineage.rs` still normalizes negative persisted `issued_at`,
`expires_at`, `delegation_depth`, and replication sequence values to zero.
Those snapshots feed audit queries, call-chain validation, and cluster
lineage replication, so a corrupt row must fail closed instead of becoming a
synthetic root or epoch-zero capability.

## Security and API Constraints

Budget state must fail closed. Negative persisted values for unsigned budget
fields are storage corruption, not recoverable business data. Existing public
types and traits should remain source-compatible. Valid rows must keep the same
query and mutation behavior, mutation event ids must remain idempotent, and
replication sequence ordering must stay stable.

Capability lineage has the same rule: timestamps, delegation depth, and local
replication sequence are unsigned domain values. Public lineage APIs and
serialized snapshot shapes stay source-compatible, but corrupt rows must return
the existing storage error path before they can affect audit, call-chain, or
replication decisions.

## Affected Dependents

No transitive crate edits are expected. Callers still use `SqliteBudgetStore`
through the existing concrete methods and `BudgetStore` trait, and capability
lineage callers still use the existing `SqliteReceiptStore` concrete methods.
The behavioral change is limited to corrupt negative SQLite rows, which now
surface as the existing store error types instead of being normalized into
unsigned values.

## Planned Material Improvement

Introduce budget-store row decoding helpers that reject negative integers for
unsigned budget fields. Use them in the central usage, hold, mutation-event,
and hot-path budget state decoders so corrupted durable counters fail closed
before they can influence authorization or replication.

Extend the same storage invariant to capability lineage by using a shared
non-negative SQLite integer decoder for lineage snapshots, parent-depth lookup,
and replication rows. This keeps valid lineage byte-stable while rejecting
corrupt rows before audit or replication code can consume them.

## Encrypted Blob Tenant Boundary Slice

### Current Boundary

`encrypted_blob.rs` stores tenant-scoped encrypted payloads. The tenant id is
used as the SQLite lookup scope and is also bound into the ChaCha20-Poly1305
associated data with the blob id and creation timestamp.

### Pain Point

The encrypted blob store rejects whitespace-only tenant ids, but it accepts
padded or control-bearing tenant ids. Those values become durable tenant scope
keys and AEAD metadata. A caller can therefore persist a blob under
` tenant-a ` or `tenant-a\n`, creating ambiguous storage scope strings that
look like tenant `tenant-a` to humans but decrypt only under a different AAD.

### Security and API Constraints

Preserve valid tenant ids, generated blob ids, ciphertext format, nonce
format, and AAD layout for accepted writes. Reject malformed tenant ids before
encryption and before SQLite insertion. Public type names remain compatible.

### Affected Dependents

No transitive source changes are expected. Existing callers using exact tenant
ids keep the same behavior. Callers passing padded or control-bearing tenant
ids now receive `BlobStoreError` before any encrypted row is written.

### Completed Material Improvement

Strengthen encrypted blob tenant validation from whitespace-only rejection to
non-empty, unpadded, control-free validation, with a regression proving
malformed tenant ids fail before persistence.

## Verification Focus

Tests should cover receipt query pagination, checkpoint projection, budget
usage and hold replay idempotence, rejection of negative unsigned row fields,
capability-lineage corruption rejection, encrypted blob tenant validation,
memory provenance isolation, revocation persistence, and dead-letter retention
without leaking encrypted payload material.
