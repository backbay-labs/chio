# chio-ag-ui-proxy Architecture Notes

## Module Boundaries

`event.rs` owns the AG-UI event wire model: event identity, type,
classification, target component, and opaque payload. `proxy.rs` owns policy
evaluation, capability verification, budget admission, event classification,
transport accounting, and receipt construction. `receipt.rs` owns canonical
payload hashing plus AG-UI receipt signing and verification. `transport.rs`
owns connection metadata and forwarded or blocked counters. `lib.rs` exposes
the public facade without hiding those modules.

## Completed Event Identity Boundary Slice

`proxy.rs` is the dominant file and combines boundary validation, policy
derivation, capability scope matching, budget accounting, and tests. The
highest-risk issue is not line count alone: `AgUiProxy::evaluate` currently
used to trust caller-supplied event identifiers before using them in receipt
ids, payload-scope arguments, audit metadata, and transport decisions. Empty
`event_id`, `agent_id`, session ids, or target component fields could therefore
reach receipt construction or scope comparison as if they were meaningful
protocol identities.

## Security and API Constraints

AG-UI receipts are observational and must never imply Chio authorization.
Restricted events must continue to require trusted capability issuers, valid
chain binding, scope containment, and sibling-sum budget admission. Public type
names and module exports should remain source-compatible. Canonical payload
hashing and signature verification must stay byte-stable. Invalid event
identity data should fail closed before the proxy signs a receipt whose
correlation fields are unusable.

## Affected Dependents

No transitive crate edits are expected. `chio-ag-ui-proxy` is consumed as a
public facade by tests and potential product code through `AgUiProxy`,
`AgUiEvent`, `TargetComponent`, `ProxyDecision`, `AgUiReceipt`, `Transport`,
and `TransportKind`. Tightening event-boundary validation should preserve those
types while changing malformed-event behavior from receipt-producing decisions
to `AgUiProxyError::InvalidEvent`.

## Completed Material Improvement

Move event identity validation into `event.rs` and have `AgUiProxy::evaluate`
invoke it before classification, capability checks, transport counters, or
receipt signing. Require non-empty `event_id` and `agent_id`; require optional
`session_id`, `target.component_type`, and `target.component_id` values to be
non-empty when present. This makes AG-UI event identity a real protocol
boundary invariant instead of an implicit assumption inside receipt and scope
logic.

## Capability-Present Display Boundary Slice

### Current Boundary

`AgUiProxy::evaluate` derives a server-side classification, then delegates to
`decide`. Restricted classifications already route through
`verify_capability_full`, issuer trust, scope matching, chain-binding checks,
and sibling-sum budget admission. Display events can be configured to forward
without a token, but the default config still requires some capability material.

### Pain Point

The non-restricted branch treats any supplied capability as sufficient. Under
the default config, a display event with a self-signed, expired, revoked,
untrusted, or out-of-scope token can forward and produce a receipt carrying that
capability id without the hot path ever validating the token. That contradicts
the crate's capability-validated proxy contract and the kernel-core expectation
that AG-UI uses full capability verification on the hot path.

### Security and API Constraints

Public type names and module exports must remain source-compatible. Operators
that intentionally allow display-only traffic without capability can keep using
`allow_display_without_capability`. Whenever a token is supplied or required,
it must be validated with the same issuer, revocation, scope, chain-binding, and
budget semantics already used for restricted events. AG-UI receipts remain
observational and must not imply authorization.

### Affected Dependents

No transitive crate edits are expected. The only behavior change is inside this
owning crate: display events that rely on an invalid or out-of-scope token now
produce a blocked AG-UI receipt instead of forwarding.

### Completed Material Improvement

Route every capability-present event through the existing full capability
verification and scope-matching path. Keep tokenless display forwarding only
when `allow_display_without_capability` is enabled; otherwise require a valid
capability grant for the server-derived event classification.

## Event Identity Normalization Boundary Slice

### Current Boundary

`AgUiEvent::validate_boundary` is the only protocol identity gate before
`AgUiProxy::evaluate` derives classification, resolves capability scopes,
updates transport counters, and signs an `AgUiReceipt`.

### Pain Point

The completed event identity slice made empty identities fail closed, but it
still accepted padded or control-bearing identifiers. That leaves ambiguous
`event_id`, `agent_id`, `session_id`, `target.component_type`, and
`target.component_id` values eligible for receipt IDs, scope arguments, audit
metadata, and transport decisions.

### Security and API Constraints

Public AG-UI event and proxy types must remain source-compatible. Empty-field
error text should stay stable for existing callers. Canonical payload hashing,
receipt signatures, server-derived classification, and capability scope
matching must stay unchanged for valid events.

### Affected Dependents

No downstream crate edits are expected. The behavior change is limited to
malformed AG-UI event identity data, which now fails before receipt
construction and before transport counters move.

### Completed Material Improvement

Reject padded or control-bearing AG-UI identity fields at the event boundary
while preserving the existing empty-field rejection. Add coverage proving these
malformed identities cannot produce receipts or transport accounting changes.
