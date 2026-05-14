# Chiodos 7.6 And 7.7 Carry-Forward Gap Ledger

This ledger maps incomplete 7.6 and 7.7 work into the 7.8 closure lane.

## Status Terms

`Implemented` means the named gate proves the ticket against verifier-owned or
live runtime evidence. `Partially implemented` means a local path, schema, CLI,
or static fixture path exists, but the proving gate does not yet establish the
true Chiodos closure claim. `Blocked` means the ticket cannot honestly close
until the blocker and gate are resolved.

When prose, code comments, or worker notes disagree with a gate, the gate wins.

## Carry-Forward Gaps

| Prior ticket | Gap | 7.8 owner ticket | Done condition |
| --- | --- | --- | --- |
| C7.6-002, C7.6-003 | Treaty and ladder artifacts existed but were not fully enforced in live admission. | C7.8-002, C7.8-003 | Runtime admission loads pinned treaty and ladder records from store and denies before dispatch on missing or mismatched evidence. |
| C7.6-004 | Continuation and lineage were too close to single-edge fixtures. | C7.8-006 | Buyer verification rejects missing receipts, cycles, wrong audience, stale continuation, and asserted-only required edges. |
| C7.6-006 | Bilateral evidence could be hash-bound without treaty-specific strict predicate fields. | C7.8-005 | Strict Chiodos DSSE includes treaty binding refs and buyer verification rejects compatibility-only predicates. |
| C7.6-007 | Buyer packet verification was too hash-only. | C7.8-008 | Buyer review hydrates artifacts and reports `strict_verified`, `hash_only`, `fixture_only`, `rejected`, or `unsupported_claim`. |
| C7.6-008 | Three-party fixture did not prove live receipt capture. | C7.8-004, C7.8-007 | Happy path receipts originate from kernel execution and proof regeneration uses those runtime outputs. |
| C7.7-003 | Kernel admission did not fail closed on verifier-owned treaty-store evidence. | C7.8-003 | Missing or mismatched treaty refs deny before tool provider or cosigner invocation. |
| C7.7-004 | Strict bilateral DSSE did not bind treaty refs required for buyer verification. | C7.8-005 | Treaty mode carries treaty id, scope hash, intersection hash, request and outcome hashes, receipt hashes, lease refs, governance refs, and signer kernel ids. |
| C7.7-004, C7.7-006 | Proof regeneration could still rely on static or synthetic packages. | C7.8-007 | `accepted=true` is possible only after existing `chio-chiodos` verification accepts the regenerated package. |
| C7.7-006 | Negative corpus was too manifest-like. | C7.8-009 | Gate executes negatives and fails on wrong expected code. |

## Honest Closure Matrix

| Ticket | Status | Honest closure claim | Gate that proves it |
| --- | --- | --- | --- |
| C7.6-001 Integrator | Implemented | 7.6 planning scope, ownership, and final gates were recorded. | `.planning/trajectory-7.6/TICKETS.md` plus `.planning/trajectory-7.6/FINAL_GATES.md` review. |
| C7.6-002 Ladder And Treaty Contracts | Implemented | Ladder and treaty contracts are represented as bounded signed data. | `bash scripts/check-chiodos-treaty-bound-provenance.sh --schema-only` and `cargo test -p chio-chiodos-runtime treaty_ --test runtime_admission`. |
| C7.6-003 Cross-Boundary Admission | Partially implemented | Local treaty-bound admission evidence exists, but live verifier-owned pre-dispatch closure is a 7.8 target. | `bash scripts/check-chiodos-treaty-bound-provenance.sh` proves the artifact path. `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --runtime-only` must prove live closure. |
| C7.6-004 Continuation And Lineage | Partially implemented | Continuation and lineage statements exist, but full graph closure over live receipts remains 7.8 work. | `cargo test -p chio-chiodos-runtime buyer_attestation --test runtime_admission` proves the bounded 7.6 path. `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --lineage-only` proves closure. |
| C7.6-005 Buyer Attestation Packet | Partially implemented | Buyer packets bind hashes and budget refs, but hash-only self-attestation is not enough for 7.8 closure. | `cargo test -p chio-chiodos-runtime buyer_attestation --test runtime_admission` plus `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --buyer-only`. |
| C7.6-006 CLI And Schemas | Implemented | 7.6 CLI and schema surfaces exist for bounded treaty provenance. | `cargo check -p chio-cli --bin chio` and `bash scripts/check-chiodos-treaty-bound-provenance.sh --schema-only`. |
| C7.6-007 Negatives And Gate | Partially implemented | Negative coverage exists for 7.6 claims, but 7.8 must add replay, forged provenance, stale fixture, and downgrade cases. | `bash scripts/check-chiodos-treaty-bound-provenance.sh --negative-only` proves 7.6 negatives. `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --negative-only` proves the expanded corpus. |
| C7.6-008 Review And Closeout | Blocked | 7.6 cannot honestly close while its cross-boundary and buyer claims are carried by 7.8. | Full `bash scripts/check-chiodos-live-treaty-buyer-closure.sh` plus review of this ledger. |
| C7.7-001 Integrator | Implemented | 7.7 narrowed the hero loop and recorded final gates on top of 7.6. | `.planning/trajectory-7.7/TICKETS.md` plus `.planning/trajectory-7.7/FINAL_GATES.md` review. |
| C7.7-002 Buyer Review Contracts | Implemented | Buyer review packages bind required artifacts by role, path, byte count, and SHA-256. | `cargo test -p chio-chiodos-runtime buyer_review --test runtime_admission` and `cargo test -p chio-spec-validate`. |
| C7.7-003 Hydrated Buyer Verification | Partially implemented | Artifact hydration exists, but acceptance still needs live runtime and strict proof semantics to avoid package-carried trust roots. | `cargo test -p chio-chiodos-runtime buyer_review --test runtime_admission` proves hydration. `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --buyer-only` proves closure. |
| C7.7-004 Lineage Closure | Partially implemented | Missing asserted lineage can be rejected, but live graph closure over receipts is not fully proven. | `bash scripts/check-chiodos-treaty-buyer-hero-loop.sh --negative-only` plus `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --lineage-only`. |
| C7.7-005 Buyer CLI | Implemented | Buyer package, verify, and explain commands exist for the hero loop. | `cargo test -p chio-cli --bin chio chiodos_buyer` and `bash scripts/check-chiodos-treaty-buyer-hero-loop.sh`. |
| C7.7-006 Negatives And Gate | Partially implemented | 7.7 negatives cover the hero loop, but the adversarial corpus is not yet broad enough for 7.8 assurance. | `bash scripts/check-chiodos-treaty-buyer-hero-loop.sh --negative-only` plus `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --negative-only`. |
| C7.7-007 Docs And Closeout | Partially implemented | Docs exist, but 7.7 closeout depends on the 7.8 closure matrix and final gates. | Full `bash scripts/check-chiodos-live-treaty-buyer-closure.sh` plus this ledger showing no blocked 7.6 or 7.7 carry-forward claims. |
| C7.8-001 Integrator And Gap Ledger | Implemented | 7.8 has an explicit gap ledger, status terms, and closure matrix for 7.6, 7.7, and 7.8. | `rg -n "Honest Closure Matrix|Status Terms|Completion Criteria" .planning/trajectory-7.8` plus diff review. |
| C7.8-002 Treaty Runtime Store | Implemented | Treaty runtime artifacts can be stored and replayed from verifier-owned state with idempotent identity. | `cargo test -p chio-chiodos-runtime treaty_runtime` and `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --runtime-only`. |
| C7.8-003 Admission Hook Wiring | Partially implemented | Missing treaty-store evidence can fail closed, but full pre-dispatch and federation cosign coverage must still pass the runtime gate. | `cargo test -p chio-kernel chiodos_runtime` and `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --runtime-only`. |
| C7.8-004 Live Cross-Kernel Hero Runner | Blocked | Full live cross-kernel receipt capture is not honestly closed yet. | `cargo test -p chio-kernel chiodos_runtime`, `cargo test -p chiodos-three-vendor-example`, and full `bash scripts/check-chiodos-live-treaty-buyer-closure.sh`. |
| C7.8-005 Strict Treaty DSSE | Implemented | Strict Chiodos bilateral DSSE binds treaty refs, roles, and real receipt hashes, and compatibility predicates are non-authoritative. | `cargo test -p chio-federation chiodos` and `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --dsse-only`. |
| C7.8-006 Lineage Graph Closure | Partially implemented | Lineage closure logic exists, but it must prove complete request, outcome, continuation, and predecessor receipt coverage. | `cargo test -p chio-chiodos-runtime buyer_review` and `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --lineage-only`. |
| C7.8-007 Runtime Proof Regeneration | Blocked | Full semantic proof regeneration is not honestly closed until regenerated packages pass the existing verifier and stale copied packages fail. | `cargo test -p chio-chiodos` and `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --proof-only`. |
| C7.8-008 Buyer Review Package V2 | Partially implemented | Buyer review packages hydrate required artifacts, but final acceptance still depends on live DSSE, lineage, and proof gates. | `cargo test -p chio-chiodos-runtime buyer_review`, `cargo test -p chio-cli --bin chio chiodos_buyer`, and `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --buyer-only`. |
| C7.8-009 Executable Negative Corpus | Partially implemented | Negative lanes are named, but closure requires executable replay, forged provenance, stale fixture, downgrade, and predicate-boundary cases with exact rejection codes. | `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --negative-only`. |
| C7.8-010 Docs And Closeout | Blocked | Closeout is blocked until every required gate passes and this matrix has no blocked tickets except explicitly deferred non-goals. | Full `bash scripts/check-chiodos-live-treaty-buyer-closure.sh`, final gate review, and no blocked rows in this matrix. |

Current implementation note: this branch has store idempotency, strict treaty
DSSE binding, strict DSSE buyer role checks, and admission denial for missing
treaty-store evidence. Full live cross-kernel receipt capture and full semantic
proof regeneration remain the hardest open work until their gates pass.
