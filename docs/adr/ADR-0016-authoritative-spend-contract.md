# ADR-0016: Authoritative Spend Contract (execution nonce + atomic hold + mediated-spend profile)

- Status: Proposed
- Decision owner: kernel and spend control-plane lane
- Related invariant: fail-closed enforcement; "authoritative" is a structural conjunction over the kernel signature, not a label
- Consumed by: the comptroller surface-report contract (`chio.comptroller.surface-report.v1`) and the settlement receipt

## Context

The kernel already contains an atomic, fail-closed spend pipeline (`budget_store.rs`
`authorize_budget_hold`, `execution_nonce.rs`, `validation.rs` reconcile). The
surface real agents use (the `chio-api-protect` sidecar direct tool-call route)
routed around it and emitted an advisory receipt that admits, in its own
metadata, that it is not authorization. `TrustLevel::Mediated` is a stamp
(`receipt_persistence.rs`), not proof that budget was held and guards ran. This
ADR declares the enforcement contract normative so downstream consumers can pin
to a stable shape.

Two code-only realities are hereby reconciled with the docs: the
`chio.execution_nonce.v1` schema (`execution_nonce.rs`) and the
`BudgetGuaranteeLevel` taxonomy (`budget_store.rs`) were previously absent from
`spec/` and every ADR.

## Decision

1. `chio.execution_nonce.v1` is a signed body of
   `{schema, nonce_id, issued_at, expires_at, bound_to{subject_id, request_id,
   capability_id, tool_server, tool_name, parameter_hash}}` plus an Ed25519
   `signature`. A missing or empty `request_id` is rejected fail-closed.
2. The atomic hold lifecycle (authorize worst-case exposure, reconcile down to
   realized spend, reverse on deny) is normative. `BudgetGuaranteeLevel`
   (`single_node_atomic`, `ha_linearizable`, `partition_escrowed`,
   `advisory_posthoc`) is normative and must be truthful: a store never claims a
   level above its real backing (no `ha_linearizable` without a quorum store).
3. `chio.mediated_spend.v1` predicate: a receipt is authoritative iff it satisfies
   the structural conjunction (a) mediated_decision + prevent + observation_outcome
   absent + trust_level mediated + decision Allow; (b) a reconciled
   `BudgetAuthorityReceiptRef` whose exposure moved against the agent's
   cost-bearing capability; (c) a kernel-signed execution nonce bound to the same
   capability/server/tool/parameter_hash; (d) the receipt records the nonce id
   (hold <-> nonce cross-bound); (e) the signer is an admitted kernel key; (f)
   fail-closed on any missing or invalid element. Implemented by
   `chio_core_types::receipt::authoritative_spend::is_authoritative_spend_receipt`.
4. Prepay authority (owned by the kernel enforcement lane, threaded to the
   comptroller surface-report projection and the settlement receipt): authorize
   the worst case (`quote.quoted_cost` when a quote is present, else
   `max_cost_per_invocation`) and reconcile down to realized `cost_charged`. The
   authoritative number the comptroller surface-report projection reports and the
   settlement receipt gate charges is this authorize-then-reconcile pair, not
   either endpoint alone.
5. Reserved linkage slots (populate as `Option::None` until a v2 schema revision
   so no governance-gated schema v2 is forced): the comptroller surface-report
   contract `chio.comptroller.surface-report.v1` MUST carry
   `execution_nonce_ref: Option<String>` and `hold_ref: Option<String>`; the
   settlement receipt MUST carry the same two slots.

## Consequences

Supersedes the "monotonic, no-refund" text of ADR-0006 (the code already refunds
via reverse/reconcile). Advisory-only consumption becomes a machine-visible
conformance failure, enforced by the golden conformance gate in the chio-conformance
crate. The comptroller surface-report and settlement receipt pin to this shape once
the authoritative-spend conformance gates pass.
