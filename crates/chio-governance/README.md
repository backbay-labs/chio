# chio-governance

`chio-governance` defines Chio's generic governance charters and case
evaluation. It provides the capability-lease artifacts and action classes
(scoped observation, delegated action, narrow destructive), governance-receipt
artifacts, and verification helpers such as `verify_capability_lease`,
`verify_destructive_authorization`, and `verify_step_governance_boundary`. It
builds on the listing surface in `chio-listing`.

Use this crate to author and evaluate governance charters and to authorize
governed actions against a signed lease.
