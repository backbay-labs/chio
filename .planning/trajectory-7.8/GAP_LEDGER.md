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
| C7.7-006 | Negative corpus was too manifest-like. | C7.8-009 | Gate executes live runtime negatives plus the Rust buyer-review adversarial corpus. |

## Honest Closure Matrix

| Ticket | Status | Honest closure claim | Gate that proves it |
| --- | --- | --- | --- |
| C7.6-001 Integrator | Implemented | 7.6 planning scope, ownership, and final gates were recorded. | `.planning/trajectory-7.6/TICKETS.md` plus `.planning/trajectory-7.6/FINAL_GATES.md` review. |
| C7.6-002 Ladder And Treaty Contracts | Implemented | Ladder and treaty contracts are represented as bounded signed data. | `bash scripts/check-chiodos-treaty-bound-provenance.sh --schema-only` and `cargo test -p chio-chiodos-runtime treaty_ --test runtime_admission`. |
| C7.6-003 Cross-Boundary Admission | Implemented | Treaty-bound admission is enforced before dispatch against verifier-owned runtime evidence. | `cargo test -p chio-kernel chiodos_runtime` and `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --runtime-only`. |
| C7.6-004 Continuation And Lineage | Implemented | Continuation and lineage closure are proven against runtime receipt evidence and reject asserted-only required edges. | `cargo test -p chio-chiodos-runtime buyer_review` and `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --lineage-only`. |
| C7.6-005 Buyer Attestation Packet | Implemented | Buyer packets bind verified lineage and runtime proof artifacts rather than hash-only self-attestation. | `cargo test -p chio-chiodos-runtime buyer_review` and `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --buyer-only`. |
| C7.6-006 CLI And Schemas | Implemented | 7.6 CLI and schema surfaces exist for bounded treaty provenance. | `cargo check -p chio-cli --bin chio` and `bash scripts/check-chiodos-treaty-bound-provenance.sh --schema-only`. |
| C7.6-007 Negatives And Gate | Implemented | Negative coverage includes replay, request mismatch, forged provenance, stale treaty, downgrade, non-strict DSSE, and strict DSSE tamper cases. | `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --negative-only`. |
| C7.6-008 Review And Closeout | Implemented | 7.6 carry-forward cross-boundary and buyer claims are closed by the 7.8 runtime-to-buyer gate. | Full `bash scripts/check-chiodos-live-treaty-buyer-closure.sh` plus council review. |
| C7.7-001 Integrator | Implemented | 7.7 narrowed the hero loop and recorded final gates on top of 7.6. | `.planning/trajectory-7.7/TICKETS.md` plus `.planning/trajectory-7.7/FINAL_GATES.md` review. |
| C7.7-002 Buyer Review Contracts | Implemented | Buyer review packages bind required artifacts by role, path, byte count, and SHA-256. | `cargo test -p chio-chiodos-runtime buyer_review --test runtime_admission` and `cargo test -p chio-spec-validate`. |
| C7.7-003 Hydrated Buyer Verification | Implemented | Buyer verification hydrates artifacts by role, path, byte count, and hash, then requires live runtime and strict proof semantics. | `cargo test -p chio-chiodos-runtime buyer_review --test runtime_admission` and `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --buyer-only`. |
| C7.7-004 Lineage Closure | Implemented | Buyer lineage closure is proven over live receipt graph evidence and rejects asserted-only required edges. | `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --lineage-only` and `cargo test -p chio-chiodos-runtime buyer_review`. |
| C7.7-005 Buyer CLI | Implemented | Buyer package, verify, and explain commands exist for the hero loop. | `cargo test -p chio-cli --bin chio chiodos_buyer` and `bash scripts/check-chiodos-treaty-buyer-hero-loop.sh`. |
| C7.7-006 Negatives And Gate | Implemented | The buyer hero loop is covered by the expanded 7.8 adversarial corpus. | `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --negative-only`. |
| C7.7-007 Docs And Closeout | Implemented | 7.7 closeout is grounded in this no-blocked-row closure matrix and final gates. | Full `bash scripts/check-chiodos-live-treaty-buyer-closure.sh` plus this ledger. |
| C7.8-001 Integrator And Gap Ledger | Implemented | 7.8 has an explicit gap ledger, status terms, and closure matrix for 7.6, 7.7, and 7.8. | `rg -n "Honest Closure Matrix|Status Terms|Completion Criteria" .planning/trajectory-7.8` plus diff review. |
| C7.8-002 Treaty Runtime Store | Implemented | Treaty runtime artifacts can be stored and replayed from verifier-owned state with idempotent identity. | `cargo test -p chio-chiodos-runtime treaty_runtime` and `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --runtime-only`. |
| C7.8-003 Admission Hook Wiring | Implemented | Runtime admission denies before dispatch and federation co-signing on missing, stale, forged, replayed, smuggled, or unverified treaty evidence. | `cargo test -p chio-kernel chiodos_runtime` and `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --runtime-only`. |
| C7.8-004 Live Cross-Kernel Hero Runner | Implemented | The local live cross-kernel runner captures package-valid runtime receipts and produces buyer-verifiable closure artifacts. | `cargo test -p chio-kernel chiodos_runtime`, `cargo test -p chiodos-three-vendor-example`, and full `bash scripts/check-chiodos-live-treaty-buyer-closure.sh`. |
| C7.8-005 Strict Treaty DSSE | Implemented | Strict Chiodos bilateral DSSE binds treaty refs, roles, and real receipt hashes, and compatibility predicates are non-authoritative. | `cargo test -p chio-federation chiodos` and `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --dsse-only`. |
| C7.8-006 Lineage Graph Closure | Implemented | Lineage closure proves request, outcome, continuation, and predecessor receipt coverage and rejects unverified required edges. | `cargo test -p chio-chiodos-runtime buyer_review` and `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --lineage-only`. |
| C7.8-007 Runtime Proof Regeneration | Implemented | Runtime proof regeneration is accepted only when the regenerated package passes the existing verifier and binds runtime proof inputs, manifests, reports, and source records. | `cargo test -p chio-chiodos` and `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --proof-only`. |
| C7.8-008 Buyer Review Package V2 | Implemented | Buyer review package V2 hydrates required artifacts and accepts only when live strict DSSE, lineage, runtime reports, and proof verifier evidence all bind together. | `cargo test -p chio-chiodos-runtime buyer_review`, `cargo test -p chio-cli --bin chio chiodos_buyer`, and `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --buyer-only`. |
| C7.8-009 Executable Negative Corpus | Implemented | Executable negative lanes cover live replay and request-binding denial, forged and stale treaty evidence, non-strict predicates, strict DSSE signer and signature failures, runtime proof drift, and verifier/report substitution. | `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --negative-only`. |
| C7.8-010 Docs And Closeout | Implemented | Closeout has no blocked matrix rows outside explicitly deferred non-goals and is backed by final gates. | Full `bash scripts/check-chiodos-live-treaty-buyer-closure.sh`, exact final-gate cargo tests, final gate review, and council review. |

Closure note: this branch now has store idempotency, strict treaty DSSE binding,
strict DSSE buyer role checks, admission denial for missing treaty-store
evidence, live runtime receipt capture, runtime proof regeneration accepted by
the existing verifier, and buyer review closure over the regenerated proof
package.
