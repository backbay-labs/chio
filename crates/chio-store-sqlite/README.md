# chio-store-sqlite

`chio-store-sqlite` is the SQLite-backed persistence, query, and report layer
for Chio. It implements the receipt store and query path, budget and approval
stores, capability-lineage and revocation stores, an execution-nonce store, an
encrypted-blob store, IOU and dead-letter stores, and evidence-export queries.
Reader-heavy receipt queries use a connection pool (eight readers by default).

Use this crate when you need a concrete persistent backend for the kernel's
receipt log and supporting state. The store traits it implements are defined by
`chio-kernel` and `chio-core`.
