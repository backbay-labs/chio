# chio-attest-loopback architecture

## Overview

`chio-attest-loopback` is a fixture and harness library, not a verifier. It sits next to the verification boundary: it produces `ChioProofPackage`s and their supporting trust documents, and validates individual pieces of runtime-supplied material fail-closed, but the cryptographic decision on a whole package is delegated to `chio_attest_buyer_core::verify_package` (re-exported here). The crate runs the same construction path in two modes: entirely synthetic, from fixed seeds, or partially runtime-supplied, admitting externally produced receipts and DSSE envelopes into the identical package shape after validation, so both paths can be checked against the same offline verifier and the same committed fixtures.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Public API: fixture identity and constants, package-construction entry points, authority/trust document builders, runtime key and binding accessors, fixture loaders, negative-case fixture writer. Re-exports `chio-attest-buyer-core` and `chio-federation-authority` types. |
| `src/package.rs` | `build_proof_package_unchecked` - assembles a `ChioProofPackage` from fixture or runtime input: issues leases and governance receipts via `chio-federation-authority`, builds or validates bilateral DSSE envelopes and workflow steps, signs the workflow receipt, builds the workflow intersection artifact. |
| `src/runtime_validation.rs` | Fail-closed checks for runtime-supplied receipts (`validate_runtime_receipt_for_vendor`) and runtime-supplied artifacts against issued lease, governance, and DSSE material (`validate_runtime_artifact_for_issued_material`), plus the disclosure-subject binding check (`ensure_disclosure_subject_matches_workflow`). |
| `src/tests.rs` | Regression tests: determinism, fail-closed tamper coverage across package fields, receipt-bound BBS disclosure, and `committed_fixtures_verify`, which pins `fixtures/*.json` to the current `verify_package` output. |
| `fixtures/*.json` | Committed `ChioProofPackage`, `ChioVerificationContext`, `VerifierReport`, and `ChioVerifierTrustBundleDocument` for the fixture workflow, loaded via `include_str!`. |

## Package construction

Ordered steps inside `package::build_proof_package_unchecked`:

1. Check the input variant's length against the fixed three-vendor list. `ProofPackageInput::Fixture` needs no input; `RuntimeReceipts` and `RuntimeArtifacts` must supply exactly one item per vendor or the call fails before any signing happens.
2. For each vendor, obtain a signed tool receipt (fixture-signed, or the caller's receipt after `validate_runtime_receipt_for_vendor`), derive its issuance-step request, and stage a peer ladder binding and vendor key binding.
3. Call `chio_federation_authority::issue_authority_bundle` once for all vendors together, producing the capability leases, lease scope bindings, and governance receipts (destructive vendors only), keyed by lease id.
4. For each vendor again, pair its issued lease and governance receipt with either a fixture-generated bilateral DSSE envelope and `StepRecord`, or the caller's supplied envelope and step after `validate_runtime_artifact_for_issued_material` checks them against the receipt, the issued lease, the issued governance receipt, and the running parent-hash chain.
5. Sign the assembled `WorkflowReceiptBody` with the buyer key, add each vendor's co-signature, and build the `WorkflowIntersectionArtifact` over the final steps.
6. The `lib.rs` entry points then attach the selective disclosure proof: `build_proof_package` passes one through directly, while `fresh_proof_package` and the runtime variants pass an empty placeholder into step construction and overwrite it afterward with a proof derived over the signed workflow body, then confirm the subject hash matches via `ensure_disclosure_subject_matches_workflow`.

## Invariants and failure modes

- Runtime input length must equal the fixed vendor count (3); a mismatch fails closed immediately.
- A runtime-supplied receipt must match its fixture vendor slot's server id, tool name, lease id, decision (`Allow`), action payload (`workflowId`, `caseRef`, `tool`), and metadata (`workflow_id`, `vendor_id`); its action-parameter hash and its own signature must verify against the expected vendor key.
- A runtime-supplied artifact's DSSE envelope must decode to `PREDICATE_TYPE_CHIO_BILATERAL_INVOCATION`, and its predicate's invocation id, tool name, peer kernel id, args hash, consistency anchor, and capability lease reference must match the receipt and the lease issued in step 3; its governance receipt reference must match the issued governance receipt, or both must be absent.
- Each workflow step's parent-hash chain, output hash, and consistency anchor (`chio:consistency:{WORKFLOW_ID}:{index}`) must match the previous step and the receipt exactly.
- The selective disclosure proof's subject hash must match the signed workflow body's projection before any package-building function returns.
- Destructive vendors (`vendor-c`) always carry a governance receipt and a signed step hash; non-destructive vendors never do, and `issuance_step_request` fails closed if a destructive vendor is missing its step hash.

## Dependencies

- `chio-attest-buyer-core` - the offline verifier (`verify_package`) and the proof, trust, and disclosure-policy types this crate builds packages to satisfy.
- `chio-federation-authority` - issues the capability leases, lease scope bindings, and governance receipts bound into each package, and assembles the verifier trust bundle and revocation checkpoint.
- `chio-federation` - bilateral DSSE envelope signing and decoding (`DsseEnvelope`), ladder manifest references.
- `chio-governance` - lease action-class and governance receipt types.
- `chio-selective-disclosure` (`bbs` feature) - BBS keypair generation, workflow-body projection, and selective disclosure proof derivation.
- `chio-workflow` - `WorkflowReceipt`, `StepRecord`, and workflow receipt signing.
- `chio-core-types` - canonical JSON, hashing, `Keypair`, and receipt body types (`ChioReceipt`).

No dependency is aliased via `package = ...` in `Cargo.toml`.
