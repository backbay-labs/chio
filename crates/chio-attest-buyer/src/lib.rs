//! Chio buyer attestation verification boundary.
//!
//! This crate owns the public Chio buyer proof verification API. Callers
//! depend on Chio-owned shapes, not on the proof verifier core. The
//! boundary delegates full proof replay to the hardened verifier core so
//! hash-only DSSE remains unresolved and full review keeps strict
//! treaty-bound DSSE semantics.

#![forbid(unsafe_code)]
#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

pub mod api;
pub mod error;
pub mod schemas;
pub mod types;

mod conversions;
mod runtime_manifest;
mod validation;

pub use api::{
    bilateral_invocation_binding_sha256, buyer_attestation_packet_from_json,
    buyer_attestation_packet_sha256, buyer_attestation_review_package_from_json,
    buyer_attestation_review_report_json, buyer_attestation_verification_report_json,
    receipt_lineage_statement_sha256, verify_buyer_attestation_packet,
    verify_buyer_attestation_review_package,
    verify_buyer_attestation_review_package_with_proof_replay_json,
    verify_buyer_attestation_review_package_with_trust, verify_proof_package_json,
    verify_receipt_lineage_bundle,
};
pub use error::BuyerAttestationError;
pub use runtime_manifest::runtime_evidence_manifest_from_json;
pub use schemas::{
    CHIO_ATTEST_BUYER_ATTESTATION_EXPLANATION_SCHEMA, CHIO_ATTEST_BUYER_ATTESTATION_PACKET_SCHEMA,
    CHIO_ATTEST_BUYER_ATTESTATION_REVIEW_PACKAGE_SCHEMA,
    CHIO_ATTEST_BUYER_ATTESTATION_REVIEW_REPORT_SCHEMA,
    CHIO_ATTEST_BUYER_ATTESTATION_VERIFICATION_REPORT_SCHEMA,
    CHIO_FEDERATION_BILATERAL_INVOCATION_SCHEMA, CHIO_FEDERATION_CROSS_KERNEL_CONTINUATION_SCHEMA,
    CHIO_FEDERATION_RECEIPT_LINEAGE_BUNDLE_SCHEMA,
    CHIO_FEDERATION_RECEIPT_LINEAGE_STATEMENT_SCHEMA,
};
pub use types::{
    BilateralInvocation, BuyerAttestationPacket, BuyerAttestationReviewArtifactRef,
    BuyerAttestationReviewCheck, BuyerAttestationReviewPackage, BuyerAttestationReviewReport,
    BuyerAttestationReviewSource, BuyerAttestationReviewTrustContext,
    BuyerAttestationVerificationReport, ChioProofVerificationReport, CrossBoundaryAdmissionReport,
    CrossBoundaryEvidenceRef, CrossKernelContinuation, ReceiptLineageBundle,
    ReceiptLineageStatement, RuntimeEvidenceManifest, RuntimeEvidenceManifestEntry,
};
