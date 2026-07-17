# chio-governance

`chio-governance` defines and verifies Chio's governance authorization
artifacts: capability leases, destructive-action governance receipts, and
generic governance charters and cases (dispute, freeze, sanction, appeal) that
attach to a `chio-listing` identity. It builds on `chio-listing` for listing
and trust-activation identity, and is re-exported by `chio-core` and
`chio-open-market` as `governance`.

Callers construct and sign artifacts themselves; this crate owns validation,
signature verification, and the fail-closed evaluation logic, not artifact
custody or persistence.

## Responsibilities

- Define capability lease artifacts and action classes (`ScopedObservation`,
  `DelegatedAction`, `NarrowDestructive`), and verify a signed lease's schema,
  signature, validity window, and scope digest.
- Define destructive-action governance receipts, and verify them against an
  expected lease id, workflow id, and step hash before a destructive step is
  allowed to proceed.
- Define generic governance charters and cases scoped to a namespace and
  governing operator, with builders that mint unsigned charter/case bodies
  from an issue request.
- Evaluate a signed governance case against its charter, listing, and optional
  trust activation into an effective state (clear, disputed, frozen,
  sanctioned, appealed) and an admission-blocking decision.
- Re-export `chio-listing` as `listing`, since every artifact here references
  a listing or trust-activation identity defined there.

## Public API

Re-exported from `chio_core_types`: `canonical_json_bytes`, `crypto`,
`receipt`.

Re-exported from `chio_listing` as `listing`: `SignedGenericListing`,
`SignedGenericTrustActivation`, `GenericRegistryPublisher`,
`GenericListingActorKind`, `normalize_namespace`, and the rest of the listing
surface.

Owned in this crate:

- `lease::{CapabilityLeaseArtifact, CapabilityLeaseActionClass,
  SignedCapabilityLease, verify_capability_lease,
  CAPABILITY_LEASE_SCHEMA_V1}`
- `authorization::{GovernanceReceiptArtifact, GovernanceReceiptCaseKind,
  SignedGovernanceReceipt, verify_destructive_authorization,
  verify_step_governance_boundary, GOVERNANCE_RECEIPT_SCHEMA_V1}`
- `generic::{GenericGovernanceCharterArtifact, GenericGovernanceCaseArtifact,
  GenericGovernanceAuthorityScope, GenericGovernanceCaseKind,
  GenericGovernanceCaseState, GenericGovernanceEffectiveState,
  GenericGovernanceEvidenceReference, GenericGovernanceFinding,
  GenericGovernanceFindingCode, GenericGovernanceCharterIssueRequest,
  GenericGovernanceCaseIssueRequest, GenericGovernanceCaseEvaluationRequest,
  GenericGovernanceCaseEvaluation, SignedGenericGovernanceCharter,
  SignedGenericGovernanceCase, build_generic_governance_charter_artifact,
  build_generic_governance_case_artifact}`
- `evaluation::evaluate_generic_governance_case` - the case-evaluation entry
  point.
- `error::GovernanceAuthorizationError` - shared error for lease and receipt
  verification.

## Testing

`cargo test -p chio-governance`

## See also

- `chio-listing` - listing and trust-activation identity referenced by
  governance charters and cases.
- `chio-core` - re-exports this crate as `governance`.
- `chio-open-market` - also re-exports this crate as `governance`.
- `chio-federation-authority` - issues the governance-authority keys this
  crate's receipts and leases verify against.
