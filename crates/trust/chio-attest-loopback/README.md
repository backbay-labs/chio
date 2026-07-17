# chio-attest-loopback

`chio-attest-loopback` is a deterministic loopback proof-package and runtime harness for the Chio buyer/auditor attestation path. For a fixed three-vendor refund workflow it builds a complete `ChioProofPackage`, either entirely from fixture seeds or by admitting externally supplied (runtime-collected) receipts and DSSE envelopes into the same package shape after fail-closed validation. Verification of the resulting package happens in `chio-attest-buyer-core`; this crate builds packages and the trust documents needed to check them, it does not verify.

`chio-runtime-harness` (and the `chio-cli` binary built on it) depend on this crate directly, not only in dev-dependencies, for the static fixture baseline used in live proof-parity checks. It is not test-only scaffolding.

## Responsibilities

- Own the deterministic three-vendor refund workflow fixture: buyer plus `vendor-a` (`read_refund_case`), `vendor-b` (`verify_customer`), and `vendor-c` (`stage_refund`, destructive), all keyed from fixed seeds so every build is reproducible.
- Assemble a full `ChioProofPackage` from fixture data (`fresh_proof_package`), externally supplied tool receipts (`proof_package_from_runtime_receipts`), or externally supplied receipts plus DSSE envelopes and workflow steps (`proof_package_from_runtime_artifacts`).
- Validate runtime-supplied material fail-closed against the fixture vendor slot, the issued lease and governance receipt, the parent-hash chain, and the consistency anchor before it is admitted into a package.
- Build the trust-side documents a verifier checks a package against: authority profile, signing keys, issuance request, verifier trust bundle, peer pins, revocation checkpoint.
- Load the committed `fixtures/*.json` package and verifier report, and regenerate the five tampered negative-case fixture sets used by tamper-detection tests.

## Public API

Package construction:

- `fresh_proof_package() -> Result<ChioProofPackage, ChioPackageError>` - full fixture package with a freshly derived BBS disclosure proof.
- `build_proof_package(proof: chio_selective_disclosure::SelectiveDisclosureProof) -> Result<ChioProofPackage, ChioPackageError>` - fixture package using a caller-supplied disclosure proof.
- `proof_package_from_runtime_receipts(receipts: Vec<ChioReceipt>) -> Result<ChioProofPackage, ChioPackageError>` - binds externally signed tool receipts into the fixture package shape.
- `proof_package_from_runtime_artifacts(artifacts: Vec<RuntimeProofArtifact>) -> Result<ChioProofPackage, ChioPackageError>` - binds externally supplied receipts, DSSE envelopes, and workflow steps.
- `fixture_proof_package()`, `fixture_verifier_report()` - load the committed fixtures.
- `write_signed_negative_case_inputs(out_dir: &Path)` - regenerate the five tampered negative-case fixture sets.

`RuntimeProofArtifact { tool_receipt, bilateral_envelope, workflow_step }` fields are typed `chio_core_types::receipt::body::ChioReceipt`, `chio_federation::bilateral_dsse::DsseEnvelope`, and `chio_workflow::receipt::StepRecord`; none of the three are re-exported here.

Trust documents and runtime identity:

- `authority_profile_document`, `authority_signing_keys_document`, `authority_issuance_request`, `authority_issuance_request_for_package`
- `verifier_trust_bundle`, `verifier_trust_bundle_document`, `verifier_trust_bundle_document_for_package`, `peer_pins_document_for_package`
- `verification_context`, `disclosure_policy`, `revocation_publication_request`
- `runtime_vendor_keypair(step_index)`, `runtime_buyer_keypair()`, `runtime_vendor_binding(step_index) -> (kernel_id, server_id, tool_name)` - deterministic identity for the three fixture vendor slots.
- `WORKFLOW_ID`, `GENERATED_AT_UNIX_MS`.

Re-exported: proof, trust, and disclosure types from `chio-attest-buyer-core` (`ChioProofPackage`, `VerifierReport`, `ChioVerifierTrustBundle`, `ChioDisclosurePolicy`, `ChioPackageError`, `verify_package`, ...) and issuance types from `chio-federation-authority` (`issue_authority_bundle`, `AuthorityProfileDocument`, `ChioIssuanceRequest`, ...), so callers do not need either crate as a direct dependency.

## Usage

```rust
let package = chio_attest_loopback::fresh_proof_package()?;
let trust_bundle = chio_attest_loopback::verifier_trust_bundle()?;
let context = chio_attest_loopback::verification_context();
let report = chio_attest_loopback::verify_package(&package, &trust_bundle, &context)?;
assert!(report.accepted);
```

## Testing

`cargo test -p chio-attest-loopback`

`committed_fixtures_verify` pins `fixtures/*.json` to the current `verify_package` output; changing the fixture workflow, vendor set, or verifier semantics requires regenerating those files together.

## See also

- `chio-attest-buyer-core` - the offline verifier (`verify_package`) this crate builds packages to satisfy.
- `chio-attest-buyer` - the public buyer verification boundary that wraps `chio-attest-buyer-core`.
- `chio-federation-authority` - issues the capability leases, lease scope bindings, and governance receipts this crate binds into each package.
- `chio-runtime-harness` - the live runtime harness that uses this crate's fixture baseline for proof-parity checks.
- `examples/chio-3vendor` - a CLI example that drives this crate's fixture-to-verification loop end to end.
