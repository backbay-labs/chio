# Chiodos 7.8 Tickets

- C7.8-001 Integrator And Gap Ledger: active planning docs, baseline, gates, and
  7.9 dashboard shadow.
- C7.8-002 Treaty Runtime Store: persist verifier-owned treaty and buyer
  evidence with same-hash idempotency and different-hash rejection.
- C7.8-003 Admission Hook Wiring: load treaty refs from runtime state and deny
  before dispatch on missing, stale, forged, downgraded, replayed, or unverified
  evidence.
- C7.8-004 Live Cross-Kernel Hero Runner: deterministic Buyer, Vendor A, Vendor B
  execution through `ChioKernel` with actual parent and child receipts.
- C7.8-005 Strict Treaty DSSE: extend strict Chiodos DSSE with treaty binding
  refs and reject compatibility-only buyer evidence.
- C7.8-006 Lineage Graph Closure: verify bounded receipt-lineage bundles for no
  cycles, no missing receipts, correct audience, and verified required edges.
- C7.8-007 Runtime Proof Regeneration: remove static package copying from the
  happy path and accept only verifier-accepted regenerated proof packages.
- C7.8-008 Buyer Review Package V2: hydrate and semantically verify buyer-facing
  review packages offline.
- C7.8-009 Executable Negative Corpus: run negative fixtures and detect wrong
  expected codes.
- C7.8-010 Docs And Closeout: claim only local live buyer-verifiable
  cross-vendor attestation, run gates, and close review threads.
