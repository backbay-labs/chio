# chio-ag-ui-proxy Architecture Notes

## Module Boundaries

`event.rs` owns the AG-UI event wire model: event identity, type,
classification, target component, opaque payload, and the event identity
boundary gate. `proxy.rs` owns policy evaluation, capability verification,
budget admission, event classification, transport accounting, and receipt
construction. `receipt.rs` owns canonical payload hashing plus AG-UI receipt
signing and verification. `transport.rs` owns connection metadata and forwarded
or blocked counters. `lib.rs` exposes the public facade without hiding those
modules.

## Event Identity Boundary

`AgUiProxy::evaluate` consumes caller-supplied event identifiers in receipt ids,
payload-scope arguments, audit metadata, and transport decisions. It invokes
`AgUiEvent::validate_boundary` before classification, capability checks,
transport counters, or receipt signing. `event_id` and `agent_id` must be
non-empty; `session_id`, `target.component_type`, and `target.component_id` must
be non-empty when present. All identity fields must be unpadded and free of
control characters. Malformed identity data fails closed with
`AgUiProxyError::InvalidEvent` before a receipt whose correlation fields are
unusable can be signed and before transport counters move.

## Capability Verification

`AgUiProxy::evaluate` derives a server-side classification, then delegates to
`decide`. Restricted classifications route through `verify_capability_full`:
issuer trust, scope matching, chain-binding checks, and sibling-sum budget
admission. Every capability-present event, restricted or not, also routes
through that full verification and scope-matching path, so a self-signed,
expired, revoked, untrusted, or out-of-scope token produces a blocked AG-UI
receipt instead of forwarding. Tokenless display forwarding is allowed only when
`allow_display_without_capability` is enabled.

## Security and API Constraints

AG-UI receipts are observational and must never imply Chio authorization.
Restricted events continue to require trusted capability issuers, valid chain
binding, scope containment, and sibling-sum budget admission. Public type names
and module exports stay source-compatible. Canonical payload hashing and
signature verification stay byte-stable.

## Affected Dependents

No transitive crate edits are expected. `chio-ag-ui-proxy` is consumed as a
public facade by tests and potential product code through `AgUiProxy`,
`AgUiEvent`, `TargetComponent`, `ProxyDecision`, `AgUiReceipt`, `Transport`,
and `TransportKind`.
