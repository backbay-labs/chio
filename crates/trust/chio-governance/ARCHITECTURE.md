# chio-governance architecture

## Overview

`chio-governance` defines and verifies Chio's governance authorization
artifacts: capability leases, destructive-action governance receipts, and
generic governance charters and cases that attach to a `chio-listing`
identity. It is a pure verification and data-modeling library: no I/O, no
runtime state, `#![forbid(unsafe_code)]`, and every public function either
verifies an artifact the caller already holds or builds an unsigned artifact
body for the caller to sign. It sits in the trust layer below the crates that
consume it directly (`chio-attest-buyer-core`, `chio-federation-authority`)
and is re-exported wholesale by `chio-core` and `chio-open-market` as
`governance`; it does not mint capability tokens, run kernel guard pipelines,
persist receipts, or resolve registry data from the network.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Crate root. Re-exports `chio-core-types` (`canonical_json_bytes`, `crypto`, `receipt`) and `chio-listing` (as `listing`); declares the five public modules. |
| `src/lease.rs` | `CapabilityLeaseArtifact`, `CapabilityLeaseActionClass`, `SignedCapabilityLease`, `verify_capability_lease`. |
| `src/authorization.rs` | `GovernanceReceiptArtifact`, `SignedGovernanceReceipt`, `verify_destructive_authorization`, `verify_step_governance_boundary`. |
| `src/generic.rs` | Generic governance charter and case data model (authority scope, evidence references, findings), issue requests, schema constants, and the charter/case builders. |
| `src/evaluation.rs` | `evaluate_generic_governance_case` and the case-state-to-effective-state mapping. |
| `src/error.rs` | `GovernanceAuthorizationError`. |
| `src/validation.rs` | Crate-private non-empty and SHA-256-hex field validators shared by `lease.rs`, `authorization.rs`, and `generic.rs`. |

## Verification order

Lease and receipt checks (`verify_capability_lease`,
`verify_destructive_authorization`, `verify_step_governance_boundary`) all
validate schema and shape, verify the signature, and enforce the
issuance/expiry window before checking identity bindings: an exact
`scope_digest` match for leases, and lease id / workflow id / step hash
matches for receipts. `verify_step_governance_boundary` requires a valid,
unexpired receipt for any step marked `destructive` and requires none
otherwise.

Generic case evaluation (`evaluate_generic_governance_case`) is a strict
pipeline; the first failure short-circuits the rest and resolves to a
`GenericGovernanceFinding` rather than an `Err`:

1. Validate the listing body and `current_publisher` shape (a hard `Err`, not
   a finding).
2. Verify the signature and body of the listing, charter, case, and, if
   present, the activation and prior case.
3. If present, the activation's `local_operator_id` must equal the charter's
   `governing_operator_id`.
4. Charter, case, and listing must agree on governing operator, charter id,
   and namespace; charter and case must not be expired as of `evaluated_at`.
5. The charter must allow the case's kind and, where scoped, admit the
   current publisher and listing subject.
6. `Freeze`/`Sanction` cases require a matching trust activation; superseding
   and appeal cases require a matching `prior_case`.
7. `effective_state_for_case` maps case state and kind to an effective state
   (clear, disputed, frozen, sanctioned, appealed) and an admission-blocking
   flag: only an `Enforced` `Freeze` or `Sanction` case blocks admission.

## Invariants and failure modes

- Every artifact checks its schema constant before anything else and fails
  closed on mismatch.
- Signature verification always runs before body values are trusted for an
  authorization decision; an unverifiable signature never falls through to a
  pass.
- Expiry is exclusive at the boundary: `expires_at_unix_ms <= now` is
  rejected, not just `<`.
- Generic case evaluation never panics on malformed or adversarial input:
  shape and signature failures resolve to an `Ok` evaluation carrying a
  finding; only an internal crypto or canonicalization error surfaces as
  `Err(String)`.
- The crate does not mint capability tokens, run kernel guard pipelines,
  persist receipts, settle payments, or fetch registry data from the network.

## Dependencies

Internal: `chio-core-types` supplies canonical JSON (`canonical_json_bytes`),
hashing (`sha256_hex`), `Keypair` and signature verification, and
`SignedExportEnvelope<T>`, the generic signed-artifact wrapper that
`SignedCapabilityLease`, `SignedGovernanceReceipt`,
`SignedGenericGovernanceCharter`, and `SignedGenericGovernanceCase` all alias.
`chio-listing` supplies the listing and trust-activation types
(`SignedGenericListing`, `SignedGenericTrustActivation`,
`GenericRegistryPublisher`, `normalize_namespace`) that case evaluation checks
against; re-exported here as `listing`. External: `serde` for artifact
(de)serialization and `thiserror` for `GovernanceAuthorizationError`.
