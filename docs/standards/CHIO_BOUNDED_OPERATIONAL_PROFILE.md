# Chio Bounded Operational Profile

**Profile ID:** `chio-bounded-release-profile-v1`  
**Version:** `2026-04-15`  
**Status:** current bounded Chio ship profile

This profile defines the strongest honest operational contract for the current
bounded Chio release. Anything stronger stays out of the ship-facing claim.

## Guarantee Classes

| Surface | Guarantee class | Shipped truth | Explicit non-claim |
| --- | --- | --- | --- |
| Governed `call_chain` | `compatibility-only` | preserved caller context inside the approval-bound intent, with versioned provenance artifacts defined for future observed/verified upgrades | no authenticated recursive upstream provenance claim on outward surfaces until backed by observed or verified lineage artifacts |
| Authorization-context / reviewer-pack | `informational-only` | derived projection over signed receipt metadata | does not upgrade asserted call-chain fields into verified upstream truth |
| Trust-control writes | `leader-local` | deterministic leader selection, single-writer local truth, eventual repair | no consensus, quorum commit, or stale-leader fencing claim |
| Trust-control reads | `leader-local` | bounded clustered visibility over local SQLite-backed state | no globally linearizable control-plane view |
| Monetary budgets | `local-only` | single-node atomic budget enforcement on one SQLite store | no distributed-linearizable budget truth |
| Clustered monetary budgets | `leader-local` | bounded provisional authorized exposure with documented overrun bound | no actual realized-spend `<=` budget guarantee under split brain |
| Receipt and checkpoint plane | `local-only` | signed local audit evidence, immutable local checkpoints, local continuity summaries, and inclusion proofs over checkpointed claim-log batches that may contain tool and child receipts | no public transparency-log, cross-node append-only coverage, or strong non-repudiation semantics |
| Discovery / certify transparency | `informational-only` | signed snapshot/feed visibility metadata for review | no automatic trust activation or transparency-log semantics |
| Hosted auth with `cnf` and dedicated sessions | `local-only` | bounded request-time authorization and protected-resource admission | no cross-node auth-code failover or restart-safe replay guarantee |
| Static bearer / non-`cnf` / `shared_hosted_owner` | `compatibility-only` | supported interoperability and migration path | not part of the recommended bounded security profile |
| Cognition-market verified-fix wedge | `local-only` | one operator publishes and searches Findings, verifies digest-bound purchase and reveal, runs challenge and outbox-backed retraction, rejects portable retraction proofs, and quarantines governed memory under the named qualified profile | no cross-org escrow or fair-exchange claim; status-feed completeness and seller effects outside Chio remain audited assumptions |
| Cognition-market ClaimSet and passport | `local-only` | four registered `claim.finding.*` rows bind through a signed Finding-verifier report to exact content-addressed recipe and status attachments | no unsigned attachment is promoted to authority evidence; `status_fresh` does not imply external insertion completeness |

## Recommended Bounded Hosted/Auth Profile

- dedicated-per-session hosting
- explicit sender-constrained access tokens with `cnf`
- explicit `resource` binding
- request-time `authorization_details` plus `chio_transaction_context`
- stable subject derivation only when `--identity-federation-seed-file` is
  configured

## Bounded Receipt And Provenance Semantics

- signed receipts and checkpoints are the authoritative Chio evidence layer
- authorization-context and reviewer-pack exports are derived views over signed
  receipt metadata
- `chio.session_anchor.v1`, `chio.request_lineage_record.v1`,
  `chio.receipt_lineage_statement.v1`, and `chio.call_chain_continuation.v1`
  define Chio's normative provenance substrate
- session anchors and request-lineage records now provide local provenance
  continuity; receipt-lineage statements and continuation tokens strengthen that
  claim only when present and validated
- delegated `call_chain` fields remain `asserted` on outward surfaces unless
  Chio can back them with observed local lineage or verified signed provenance
  artifacts
- no report or export surface may collapse `asserted` lineage into `verified`
  truth
- checkpoint continuity records support local audit and
  `transparency_preview` claims only; current checkpoints are built over the
  local claim log, so child receipts with persisted canonical bytes can be
  covered without turning the local log into public transparency
- child receipt inclusion-proof export remains deferred unless an evidence
  package explicitly exports child receipt proof rows

## Non-Claims

This profile explicitly excludes:

- consensus-grade HA
- distributed-linearizable budget enforcement
- authenticated recursive upstream provenance beyond the observed or explicitly
  verified lineage artifacts Chio actually validates
- public transparency-log semantics
- full receipt-family append-only sequencing or strong non-repudiation
- first-principles theorem-prover completion for concrete crypto, platform, or
  external-service behavior beyond the audited assumption registry
