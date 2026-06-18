use serde::{Deserialize, Serialize};

pub const DISCLOSURE_CRYPTO_CONTEXT_REPORT_SCHEMA_V1: &str =
    "chio.disclosure.crypto-context-report.v1";
pub const DISCLOSURE_CAPSULE_SCHEMA_V1: &str = "chio.disclosure.capsule.v1";
pub const LINEAGE_SIGNED_SUBGRAPH_SCHEMA_V1: &str = "chio.lineage.signed-subgraph.v1";
pub const DISCLOSURE_LEAKAGE_LEDGER_SCHEMA_V1: &str = "chio.disclosure.leakage-ledger.v1";
pub const DISCLOSURE_LINEAGE_VERIFIER_REPORT_SCHEMA_V1: &str =
    "chio.disclosure.lineage-verifier-report.v1";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DisclosureLineageError {
    #[error("invalid disclosure lineage artifact: {0}")]
    InvalidArtifact(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureContextVerdict {
    Verified,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DisclosureContextCheck {
    pub code: String,
    pub message: String,
}

impl DisclosureContextCheck {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DisclosureCryptoContextReport {
    pub schema: String,
    pub id: String,
    pub context_id: String,
    pub artifact_ref: String,
    pub verdict: DisclosureContextVerdict,
    pub evidence_class: String,
    pub cryptographic_proof_verified: bool,
    pub verified_claims: Vec<String>,
    pub rejected_checks: Vec<DisclosureContextCheck>,
    pub disclosed_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DisclosureCapsule {
    pub schema: String,
    pub id: String,
    pub transaction_passport_ref: String,
    pub crypto_context_report_ref: String,
    pub privacy_profile_ref: String,
    pub lineage_subgraph_ref: String,
    pub leakage_ledger_ref: String,
    pub disclosed_fields: Vec<String>,
    pub hidden_predicates: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedLineageSubgraph {
    pub schema: String,
    pub id: String,
    pub transaction_passport_ref: String,
    pub root_receipt_ids: Vec<String>,
    pub nodes: Vec<DisclosureSignedLineageNode>,
    pub edges: Vec<DisclosureSignedLineageEdge>,
    pub redactions: Vec<DisclosureSignedLineageRedaction>,
    pub subgraph_sha256: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DisclosureSignedLineageNode {
    pub id: String,
    pub receipt_ref: String,
    pub disclosure_state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DisclosureSignedLineageEdge {
    pub from: String,
    pub to: String,
    pub relation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DisclosureSignedLineageRedaction {
    pub node_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DisclosureLeakageLedger {
    pub schema: String,
    pub id: String,
    pub transaction_passport_ref: String,
    pub privacy_profile_ref: String,
    pub entries: Vec<DisclosureLeakageLedgerEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DisclosureLeakageLedgerEntry {
    pub field: String,
    pub leakage_kind: String,
    pub allowed_by_profile: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub residual_inference_note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DisclosureLineageBundle {
    pub capsule: DisclosureCapsule,
    pub lineage: SignedLineageSubgraph,
    pub leakage_ledger: DisclosureLeakageLedger,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crypto_context_report: Option<DisclosureCryptoContextReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DisclosureLineageVerifierReport {
    pub schema: String,
    pub id: String,
    pub verdict: String,
    pub capsule_id: String,
    pub transaction_passport_ref: String,
    pub lineage_subgraph_ref: String,
    pub leakage_ledger_ref: String,
    pub disclosed_field_count: usize,
    pub hidden_predicate_count: usize,
    pub verified_claims: Vec<String>,
}
