use serde::{Deserialize, Serialize};

use super::ids::TRANSACTION_VERIFIER_REPORT_SCHEMA_ID;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransactionPassport {
    pub schema: String,
    pub id: String,
    pub issued_at: String,
    pub evidence_graph_sha256: String,
    pub evidence_graph_path: String,
    pub verifier_policy_sha256: String,
    pub verifier_policy_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransactionVerifierReport {
    pub schema: String,
    pub id: String,
    pub issued_at: String,
    pub verdict: String,
    pub passport_id: String,
    pub passport_path: String,
    pub evidence_graph_sha256: String,
    pub evidence_graph_path: String,
    pub verifier_policy_sha256: String,
    pub verifier_policy_path: String,
}

impl TransactionVerifierReport {
    #[must_use]
    pub fn verified(passport: &TransactionPassport, passport_path: String) -> Self {
        Self {
            schema: TRANSACTION_VERIFIER_REPORT_SCHEMA_ID.to_string(),
            id: format!("verifier-report-{}", passport.id),
            issued_at: passport.issued_at.clone(),
            verdict: "verified".to_string(),
            passport_id: passport.id.clone(),
            passport_path,
            evidence_graph_sha256: passport.evidence_graph_sha256.clone(),
            evidence_graph_path: passport.evidence_graph_path.clone(),
            verifier_policy_sha256: passport.verifier_policy_sha256.clone(),
            verifier_policy_path: passport.verifier_policy_path.clone(),
        }
    }
}
