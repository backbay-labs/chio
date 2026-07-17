# chio-attest-buyer-core

Offline verifier for Chio buyer/auditor proof packages. Given a proof package,
a verifier trust bundle, and a verification context, it replays every
cryptographic and policy check a buyer needs to accept a workflow's proof of
execution, with no network access. It is the hardened verification core behind
the public boundary crate `chio-attest-buyer`; most callers should depend on
that crate instead of this one directly.

## Responsibilities

- Parse, canonically hash, and (de)serialize proof packages, verifier trust
  bundles, verification contexts, trusted-issuer registries, and revocation
  checkpoints (`proof_package`, `trust_bundle`, `context`, `issuer`,
  `revocation`).
- Replay a proof package end to end: workflow kernel signature and vendor
  cosignatures, step-to-DSSE-to-receipt linkage, lease scope bindings and
  capability leases, governance receipts and destructive-step authorization,
  bilateral DSSE envelopes, and BBS selective-disclosure proofs (`report`).
- Enforce revocation: verify a signed revocation checkpoint and reject any
  peer, vendor, lease authority, governance authority, or BBS issuer key that
  checkpoint revokes (`revocation`, `trust_bundle`).
- Validate BBS disclosure policy and bind proof nonces to the verifier context
  (`disclosure`, `context`).
- Produce a `VerifierReport` that records which checks passed, or a stable
  failure code and phase on rejection (`report`).

## Public API

- `proof_package::{ChioProofPackage, proof_package_from_json, package_json, package_sha256}`
- `trust_bundle::{ChioVerifierTrustBundle, ChioVerifierTrustBundleDocument, verifier_trust_bundle_from_json, verifier_trust_bundle_json, verifier_trust_bundle_document_sha256}`
- `context::{ChioVerificationContext, verification_context_from_json, verification_context_json, verification_context_sha256}`
- `report::{VerifierReport, verify_package, verify_package_report, report_json, verifier_report_from_json}` - `verify_package` returns `Err` on the first failed check; `verify_package_report` always returns a report.
- `issuer::{TrustedIssuerRegistry, TrustedIssuerRegistryDocument, trusted_issuer_registry_from_json, trusted_issuer_registry_json}`
- `revocation::{ChioRevocationCheckpoint, ChioPinnedRevocationEpoch, ChioRevocationMaterial, SignedChioRevocationCheckpoint}`
- `claims::{ChioProofClaims, PeerLadderBinding, VendorKeyBinding, WorkflowIntersectionArtifact, LeaseScopeBindingArtifact}`
- `error::ChioPackageError`

## Usage

```rust
use chio_attest_buyer_core::context::verification_context_from_json;
use chio_attest_buyer_core::proof_package::proof_package_from_json;
use chio_attest_buyer_core::report::verify_package_report;
use chio_attest_buyer_core::trust_bundle::verifier_trust_bundle_from_json;

let package = proof_package_from_json(&package_json)?;
let trust_bundle = verifier_trust_bundle_from_json(&trust_bundle_json)?;
let context = verification_context_from_json(&context_json)?;

let report = verify_package_report(&package, &trust_bundle, &context);
assert!(report.accepted);
```

## Testing

`cargo test -p chio-attest-buyer-core`

Tests load fixtures from `examples/chio-3vendor/fixtures/` via `include_str!`
(proof package, verifier trust bundle, verification context), so those files
must stay in sync with this crate's schemas.

## See also

- `chio-attest-buyer` - the public boundary crate; most callers should depend
  on it instead of this crate directly.
- `chio-runtime-core`, `chio-runtime-harness` - kernel-side and test-harness
  callers that invoke this verifier directly for proof assembly and parity
  checks.
- `chio-selective-disclosure` - supplies the BBS+ projection, signing, and
  proof primitives this crate verifies against.
- `chio-cli` - uses these types and JSON codecs directly to build and inspect
  trust-bundle and checkpoint documents.
