# chio-reputation

`chio-reputation` provides deterministic local reputation scoring for Chio
agents. It is intentionally pure and storage-agnostic: it scores an agent from
a caller-provided local corpus assembled from persisted receipts,
capability-lineage snapshots, and budget-usage records. It does not depend on
`chio-kernel`, which keeps the scoring model reusable and avoids a dependency
cycle if kernel-side issuance hooks later consume it.

Use this crate to compute a reproducible reputation score from local Chio
evidence.
