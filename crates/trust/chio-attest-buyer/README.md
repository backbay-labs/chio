# chio-attest-buyer

Public Chio buyer attestation verification boundary. Defines the Chio-owned
packet, review-package, lineage, continuation, and report types so callers
depend on Chio shapes, not on either verification backend directly.

Packet- and review-level verification delegates to `chio-runtime-core`, which
owns the live admission algorithms. Full proof replay (DSSE, trust bundle,
selective disclosure) delegates to `chio-attest-buyer-core`, the hardened
offline proof-package verifier; that path keeps strict treaty-bound DSSE
semantics and leaves hash-only DSSE unresolved until replayed.

## Responsibilities

- Own the Chio-facing attestation types (`BuyerAttestationPacket`,
  `BuyerAttestationReviewPackage`, lineage, continuation, admission, and
  report shapes) and their schema-id constants, kept local rather than
  re-exported from `chio-runtime-core`.
- Validate every `*_from_json` constructor before returning a trusted struct:
  schema id, required identifiers, sha256-hex hash fields, and, for review
  packages, safe relative artifact paths with no duplicate role or path.
- Convert between Chio types and `chio_runtime_core` types (`conversions.rs`)
  and rewrite the backend's internal error and check-code namespace into
  `chio_attest_buyer.*` so no backend naming leaks through the public API.
- Provide the optional full proof-replay path that re-verifies a bundled
  proof package through `chio-attest-buyer-core` and can downgrade an
  already-accepted review report to rejected.

## Public API

- `types::{BuyerAttestationPacket, BuyerAttestationReviewPackage,
  BuyerAttestationReviewSource, ReceiptLineageStatement, ReceiptLineageBundle,
  CrossKernelContinuation, CrossBoundaryAdmissionReport, BilateralInvocation}`
  - Chio-owned request artifacts.
- `types::{BuyerAttestationVerificationReport, BuyerAttestationReviewReport,
  BuyerAttestationReviewCheck, ChioProofVerificationReport,
  RuntimeEvidenceManifest}` - Chio-owned report artifacts.
- `buyer_attestation_packet_from_json`,
  `buyer_attestation_review_package_from_json`,
  `runtime_evidence_manifest_from_json` - validating JSON constructors.
- `verify_buyer_attestation_packet`, `verify_buyer_attestation_review_package`,
  `verify_buyer_attestation_review_package_with_trust`,
  `verify_receipt_lineage_bundle` - verification against `chio-runtime-core`.
- `verify_proof_package_json`,
  `verify_buyer_attestation_review_package_with_proof_replay_json` - full DSSE
  proof replay against `chio-attest-buyer-core`.
- `buyer_attestation_packet_sha256`, `receipt_lineage_statement_sha256`,
  `bilateral_invocation_binding_sha256` - canonical artifact hashing.
- `buyer_attestation_verification_report_json`,
  `buyer_attestation_review_report_json` - canonical JSON rendering of
  reports.
- `error::BuyerAttestationError` - public error type (`code()`, `Display`,
  `std::error::Error`).
- `schemas::CHIO_*` - the nine schema-id constants this crate's types declare.

## Testing

`cargo test -p chio-attest-buyer`

## See also

- `chio-attest-buyer-core` - offline proof-package verifier this crate calls
  for full DSSE replay.
- `chio-runtime-core` - owns the live packet and review verification
  algorithms this crate wraps.
- `chio-cli` - depends on this crate for its buyer attestation command
  surface.
