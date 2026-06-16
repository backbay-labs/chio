mod error;
mod evidence_graph;
mod ids;
mod minimal;
mod runtime_security;
mod types;
mod validation;
mod verifier_policy;

pub use error::TransactionPassportError;
pub use ids::{
    RUNTIME_EXECUTION_LEASE_SCHEMA_ID, RUNTIME_REVOCATION_FRESHNESS_PROOF_SCHEMA_ID,
    RUNTIME_SANDBOX_ATTESTATION_SCHEMA_ID, RUNTIME_TOOL_SERVER_ACK_SCHEMA_ID,
    TRANSACTION_EVIDENCE_GRAPH_SCHEMA_ID, TRANSACTION_PASSPORT_SCHEMA_ID,
    TRANSACTION_RUNTIME_SECURITY_REPORT_SCHEMA_ID, TRANSACTION_VERIFIER_POLICY_SCHEMA_ID,
    TRANSACTION_VERIFIER_REPORT_SCHEMA_ID,
};
pub use minimal::{
    verify_minimal_passport_artifacts, verify_minimal_passport_schema,
    verify_standalone_minimal_passport_artifacts,
};
pub use runtime_security::{
    verify_runtime_security_claims, RuntimeSecurityBundle, RuntimeSecurityReport,
};
pub use types::{TransactionPassport, TransactionVerifierReport};

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    hex::encode(Sha256::digest(bytes))
}
