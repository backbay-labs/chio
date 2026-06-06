# chio-kernel Architecture Notes

## Boundary

`chio-kernel` is the hosted enforcement layer. It validates capabilities,
matches tool grants, applies budget and governed-admission checks, runs guards,
performs runtime admission, dispatches registered tools, reconciles budget
holds, signs receipts, and persists receipt evidence. Portable verifier logic
lives in `chio-kernel-core`; durable storage implementations live in storage
crates such as `chio-store-sqlite`.

## Module Layout

- `kernel/validation.rs` owns capability issuance and revocation, tool-server
  event drains, portable verdict evaluation, and budget charge/reconcile
  helpers.
- `kernel/governed_validation.rs` owns governed transaction admission:
  approval token trust checks, runtime assurance, metered billing, call-chain
  proof checks, autonomy bond checks, and governed call-chain receipt evidence.
- `kernel/dispatch.rs` owns guard evaluation, runtime admission, and tool
  dispatch.
- `budget_store.rs` owns the budget trait, request/decision records, and
  budget commit metadata. `budget_store/in_memory.rs` owns the in-memory
  backend, hold state, idempotent mutation events, and concrete `BudgetStore`
  implementation.

## Security And API Constraints

- Capability validation, governed-admission checks, and budget reconciliation
  must continue to fail closed.
- Approval tokens, runtime-attestation records, call-chain proofs, autonomy
  bonds, and receipt evidence must preserve canonical bytes and verification
  semantics.
- Public kernel and receipt-store APIs should remain unchanged.

## Improvement In This Slice

Split governed-admission validators out of `kernel/validation.rs` into
`kernel/governed_validation.rs` without changing method visibility or call
sites. The remaining validation module now stays focused on capability,
portable verdict, and budget validation.
