mod cognition_market;
mod error;
mod evidence_graph;
mod ids;
mod minimal;
mod runtime_security;
mod types;
mod validation;
mod verifier_policy;

pub use cognition_market::{
    verify_cognition_market_passport_artifacts, CognitionMarketProofTrust,
    CognitionMarketStatusObservation, CognitionMarketStatusTrustStore, COGNITION_MARKET_CLAIMS,
};
pub use error::TransactionPassportError;
pub use evidence_graph::validate_transaction_evidence_graph;
pub use ids::{
    RUNTIME_EXECUTION_LEASE_SCHEMA_ID, RUNTIME_REVOCATION_FRESHNESS_PROOF_SCHEMA_ID,
    RUNTIME_SANDBOX_ATTESTATION_SCHEMA_ID, RUNTIME_TOOL_SERVER_ACK_SCHEMA_ID,
    TRANSACTION_EVIDENCE_GRAPH_SCHEMA_ID, TRANSACTION_PASSPORT_SCHEMA_ID,
    TRANSACTION_RUNTIME_SECURITY_REPORT_SCHEMA_ID, TRANSACTION_VERIFIER_POLICY_SCHEMA_ID,
    TRANSACTION_VERIFIER_REPORT_SCHEMA_ID,
};
pub use minimal::{
    sign_transaction_passport, transaction_evidence_graph_transparency_state,
    transaction_evidence_graph_transparency_state_with_anchors, verify_minimal_passport_artifacts,
    verify_minimal_passport_schema, verify_minimal_passport_schema_at,
    verify_passport_root_and_claim_set_artifacts,
    verify_passport_root_and_claim_set_artifacts_unchecked_signature_with_external_claims,
    verify_passport_root_and_claim_set_artifacts_with_external_claims,
    verify_passport_root_and_claim_set_artifacts_with_transparency_anchors,
    verify_standalone_minimal_passport_artifacts,
    verify_standalone_minimal_passport_artifacts_unchecked_signature,
    verify_standalone_minimal_passport_artifacts_with_transparency_anchors,
    verify_transaction_passport_signature,
    verify_transaction_passport_signature_with_evidence_graph, TransactionTrustAnchors,
};
pub use runtime_security::{
    verify_runtime_security_claims, verify_runtime_security_claims_with_trust,
    RuntimeSecurityBundle, RuntimeSecurityReport, RuntimeSecurityTrust,
};
pub use types::{TransactionOmissionPolicyEntry, TransactionPassport, TransactionVerifierReport};
pub use verifier_policy::validate_verifier_policy_artifact;

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    hex::encode(Sha256::digest(bytes))
}
