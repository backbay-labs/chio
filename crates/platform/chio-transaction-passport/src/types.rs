use serde::{Deserialize, Serialize};

use super::ids::TRANSACTION_VERIFIER_REPORT_SCHEMA_ID;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransactionPassport {
    pub schema: String,
    pub id: String,
    pub issued_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    pub issuer: String,
    pub evidence_graph_sha256: String,
    pub evidence_graph_path: String,
    pub claim_set_sha256: String,
    pub claim_set_path: String,
    pub verifier_policy_sha256: String,
    pub verifier_policy_path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub omission_policy: Vec<TransactionOmissionPolicyEntry>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransactionOmissionPolicyEntry {
    pub claim_id: String,
    pub status: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransactionVerifierReport {
    pub schema: String,
    pub id: String,
    pub issued_at: String,
    pub verdict: String,
    pub accepted: bool,
    pub state: String,
    #[serde(
        default,
        rename = "failureCode",
        skip_serializing_if = "Option::is_none"
    )]
    pub failure_code: Option<String>,
    pub passport_id: String,
    pub passport_path: String,
    pub evidence_graph_sha256: String,
    pub evidence_graph_path: String,
    pub claim_set_sha256: String,
    pub claim_set_path: String,
    pub verifier_policy_sha256: String,
    pub verifier_policy_path: String,
    #[serde(default = "default_transparency_state", rename = "transparencyState")]
    pub transparency_state: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verified_claims: Vec<String>,
    #[serde(rename = "claimResults")]
    pub claim_results: Vec<TransactionClaimResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransactionClaimResult {
    pub claim_id: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_evidence: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    pub verifier_module: String,
}

impl TransactionVerifierReport {
    #[must_use]
    pub fn verified(passport: &TransactionPassport, passport_path: String) -> Self {
        Self {
            schema: TRANSACTION_VERIFIER_REPORT_SCHEMA_ID.to_string(),
            id: format!("verifier-report-{}", passport.id),
            issued_at: passport.issued_at.clone(),
            verdict: "verified".to_string(),
            accepted: true,
            state: "verified".to_string(),
            failure_code: None,
            passport_id: passport.id.clone(),
            passport_path,
            evidence_graph_sha256: passport.evidence_graph_sha256.clone(),
            evidence_graph_path: passport.evidence_graph_path.clone(),
            claim_set_sha256: passport.claim_set_sha256.clone(),
            claim_set_path: passport.claim_set_path.clone(),
            verifier_policy_sha256: passport.verifier_policy_sha256.clone(),
            verifier_policy_path: passport.verifier_policy_path.clone(),
            transparency_state: default_transparency_state(),
            verified_claims: Vec::new(),
            claim_results: Vec::new(),
        }
    }

    #[must_use]
    pub fn failed(
        passport: &TransactionPassport,
        passport_path: String,
        failure_code: String,
        failure_reason: String,
    ) -> Self {
        Self {
            schema: TRANSACTION_VERIFIER_REPORT_SCHEMA_ID.to_string(),
            id: format!("verifier-report-{}", passport.id),
            issued_at: passport.issued_at.clone(),
            verdict: "failed".to_string(),
            accepted: false,
            state: "failed".to_string(),
            failure_code: Some(failure_code),
            passport_id: passport.id.clone(),
            passport_path,
            evidence_graph_sha256: passport.evidence_graph_sha256.clone(),
            evidence_graph_path: passport.evidence_graph_path.clone(),
            claim_set_sha256: passport.claim_set_sha256.clone(),
            claim_set_path: passport.claim_set_path.clone(),
            verifier_policy_sha256: passport.verifier_policy_sha256.clone(),
            verifier_policy_path: passport.verifier_policy_path.clone(),
            transparency_state: "unknown".to_string(),
            verified_claims: Vec::new(),
            claim_results: vec![TransactionClaimResult {
                claim_id: "claim.transaction.passport_root_verified".to_string(),
                status: "failed".to_string(),
                required_evidence: Vec::new(),
                evidence_refs: vec![
                    passport.evidence_graph_path.clone(),
                    passport.claim_set_path.clone(),
                    passport.verifier_policy_path.clone(),
                ],
                failure_reason: Some(failure_reason),
                verifier_module: "chio.transaction-passport".to_string(),
            }],
        }
    }

    #[must_use]
    pub fn with_transparency_state(mut self, transparency_state: impl Into<String>) -> Self {
        self.transparency_state = transparency_state.into();
        self
    }

    #[must_use]
    pub fn with_claim_results(mut self, claim_results: Vec<TransactionClaimResult>) -> Self {
        let mut verified_claims = Vec::new();
        for result in &claim_results {
            if result.status == "verified" && !verified_claims.contains(&result.claim_id) {
                verified_claims.push(result.claim_id.clone());
            }
        }
        self.verified_claims = verified_claims;
        self.claim_results = claim_results;
        self
    }
}

fn default_transparency_state() -> String {
    "not_present".to_string()
}
