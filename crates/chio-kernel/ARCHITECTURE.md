# chio-kernel Architecture Notes

## Boundary

`chio-kernel` is the hosted enforcement layer. It validates capabilities,
matches tool grants, applies budget and governed-admission checks, runs guards,
performs runtime admission, dispatches registered tools, reconciles budget
holds, signs receipts, and persists receipt evidence. Portable verifier logic
lives in `chio-kernel-core`; durable storage implementations live in storage
crates such as `chio-store-sqlite`.

## Current Pain Point

The `chio-kernel` retention gate verifies that archived child-request receipts
remain queryable and that tenant-scoped archival moves only the child receipts
bound to archived parent receipts. That owning-crate gate currently fails
before archive logic runs: `SqliteReceiptStore::append_child_receipt` persists
the signed child receipt, then tries to backfill request-lineage evidence by
passing the child receipt JSON through the request-lineage schema validator.
`ChildRequestReceipt` is a signed receipt shape, not a
`RequestLineageRecord`, so the store rejects valid child receipts with
`missing field schema`.

The kernel owns the retention behavior and the security invariant, while the
bad serializer sits in the SQLite store implementation used by the gate. This
is a necessary transitive storage fix, not an invitation to broaden the slice
into storage cleanup.

## Security And API Constraints

- Signed child receipt bytes and signature verification must remain unchanged.
- Request-lineage rows must be schema-tagged `RequestLineageRecord` values, not
  ad hoc projections or receipt JSON.
- Archival must remain tenant-scoped: child receipts move only when their
  parent receipt is in the archived tenant/cutoff set.
- Receipt and lineage readers must continue to fail closed on malformed JSON or
  unsupported schema identifiers.
- Public kernel and receipt-store APIs should remain unchanged.

## Affected Dependents

`chio-store-sqlite` requires a scoped transitive patch because its child receipt
append path creates the malformed lineage backfill. The change should stay on
that path only. Kernel, evidence-export, and operator-report callers observe the
result through existing receipt-store methods and should see valid child
receipt listings plus valid request-lineage rows.

## Improvement In This Slice

Create the child-receipt request-lineage backfill as a typed
`RequestLineageRecord` derived from the child receipt fields before passing it
to the SQLite lineage persistence boundary. Add/restore focused retention
coverage for child receipt archival and tenant-scoped child receipt archival,
then run the full retention test target before broader `chio-kernel` gates.
