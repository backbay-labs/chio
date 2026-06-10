# chio-store-sqlite Architecture Notes

## Module Boundaries

`receipt_store` owns receipt persistence, query support, report generation,
checkpoint projection, and evidence-retention helpers. `budget_store` owns
durable grant usage, authorization holds, mutation events, replication sequence
allocation, and idempotent replay handling. The smaller store modules own
approval state, batch approval state, revocations, execution nonces,
encrypted blobs, IOU envelopes, dead letters, memory provenance, and evidence
export.

`budget_store.rs` is the API root for `SqliteBudgetStore` and module wiring.
`budget_store/store.rs` contains concrete store methods, `trait_impl.rs`
implements `BudgetStore`, `model.rs` defines the internal hold model, `rows.rs`
owns fail-closed row decoding and error mapping, `schema.rs` owns migration
helpers, `replication.rs` owns sequence allocation, and `tests.rs` keeps the
budget-store unit coverage.

## Security and API Constraints

Budget state fails closed. Negative persisted values for unsigned budget fields
are storage corruption, not recoverable business data: the row decoders in
`rows.rs` reject negative `invocation_count`, cost, sequence, hold, and
mutation fields and surface the existing store error types instead of
normalizing them. Valid rows keep the same query and mutation behavior,
mutation event ids stay idempotent, and replication sequence ordering stays
stable.

Capability lineage follows the same rule: timestamps, delegation depth, and
local replication sequence are unsigned domain values. `capability_lineage.rs`
decodes them through a shared non-negative SQLite integer decoder, so a corrupt
row returns the storage error path before it can become a synthetic root or
epoch-zero capability in audit, call-chain, or replication decisions.

Encrypted blobs in `encrypted_blob.rs` bind the tenant id into the
ChaCha20-Poly1305 associated data alongside the blob id and creation timestamp,
and use it as the SQLite lookup scope. Tenant ids are validated as non-empty,
unpadded, and control-free before encryption and SQLite insertion, so an
ambiguous scope string such as ` tenant-a ` or `tenant-a\n` is rejected with
`BlobStoreError` rather than persisted. Valid tenant ids, generated blob ids,
ciphertext format, nonce format, and AAD layout are preserved for accepted
writes.

## Verification Focus

Tests should cover receipt query pagination, checkpoint projection, budget
usage and hold replay idempotence, rejection of negative unsigned row fields,
capability-lineage corruption rejection, encrypted blob tenant validation,
memory provenance isolation, revocation persistence, and dead-letter retention
without leaking encrypted payload material.
