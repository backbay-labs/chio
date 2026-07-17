# chio-ag-ui-proxy

Capability-gated proxy for AG-UI (agent-to-UI) event streams. It sits between
an agent and a UI client, classifies each event, checks it against a
capability token using Chio's capability and delegation-budget model, and
signs an audit receipt for the decision. It does not implement SSE or
WebSocket transport itself; the caller owns the connection and reports
delivery through `Transport`.

## Responsibilities

- Re-derive each event's `EventClassification` from its `EventType`
  server-side and block on any mismatch with the classification the caller
  supplied.
- Gate restricted classifications (`Mutate`, `Navigate`, `Create`, `Destroy`,
  `Submit` by default) behind a capability token; allow tokenless `Display`
  events only when `allow_display_without_capability` is set.
- Run every capability-bearing event through `verify_capability_full` (issuer
  trust, signature, time bounds, crypto floor, chain binding) and scope-grant
  matching against a synthetic `ag-ui` tool server.
- Bind matched grants to the event's real `event_id`, `session_id`, and
  target component, so a grant scoped to one session or component cannot be
  satisfied by a differently-labeled payload.
- Enforce sibling-sum delegation budgets across events for the life of the
  proxy, seeded from `ParentBudgetSnapshot`s or registered at runtime.
- Sign an `AgUiReceipt` for every evaluated event, forwarded or blocked, and
  update `Transport`'s forwarded/blocked counters.

## Public API

- `AgUiProxy` - `new`, `try_new`, `evaluate`, `register_parent_budget`,
  `register_admitted_child_budget`, `config`.
- `AgUiProxyConfig`, `proxy::ParentBudgetSnapshot`, `proxy::AdmittedChildBudget` -
  restricted classifications, trusted issuers, revoked capability IDs, peer
  capability profile, chain-binding trust roots, delegation budget seeding.
- `ProxyDecision`, `proxy::AgUiProxyError` - the forward/block outcome and the
  error type `evaluate` returns.
- `AgUiEvent`, `EventClassification`, `TargetComponent`, `event::EventType` -
  the wire event, its raw type, and its policy classification.
- `AgUiReceipt`, `AgUiReceiptBody`, `AgUiReceiptVerification` - the signed
  audit record, its unsigned body, and the trusted-key verification result.
- `Transport`, `TransportKind` - connection metadata and forwarded/blocked
  counters.

## Testing

`cargo test -p chio-ag-ui-proxy`

## See also

- `chio-core` - capability, crypto, and error types this crate builds on.
- `chio-kernel-core` - `verify_capability_full`, scope matching, and the
  budget-registry primitives this crate calls directly.
