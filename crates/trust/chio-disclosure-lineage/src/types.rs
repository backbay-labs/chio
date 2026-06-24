use serde::{Deserialize, Serialize};

pub const DISCLOSURE_CRYPTO_CONTEXT_REPORT_SCHEMA_V1: &str =
    "chio.disclosure.crypto-context-report.v1";
pub const DISCLOSURE_CAPSULE_SCHEMA_V1: &str = "chio.disclosure.capsule.v1";
pub const LINEAGE_SIGNED_SUBGRAPH_SCHEMA_V1: &str = "chio.lineage.signed-subgraph.v1";
pub const DISCLOSURE_LEAKAGE_LEDGER_SCHEMA_V1: &str = "chio.disclosure.leakage-ledger.v1";
pub const DISCLOSURE_LINEAGE_VERIFIER_REPORT_SCHEMA_V1: &str =
    "chio.disclosure.lineage-verifier-report.v1";
pub const DISCLOSURE_VERIFIER_PRIVACY_PROFILE_SCHEMA_V1: &str =
    "chio.disclosure.verifier-privacy-profile.v1";

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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TransparencyState {
    None,
    Preview,
    Anchored,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DisclosureVerifierPrivacyProfile {
    pub schema: String,
    pub profile_id: String,
    pub allowed_proof_mechanisms: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_holder_binding: Option<String>,
    pub transaction_passport_ref: String,
    pub leakage_budget: DisclosureProfileLeakageBudget,
    pub sensitivity_classes: Vec<DisclosureSensitivityClass>,
    pub allowed_issuer_keys: Vec<String>,
    pub required_key_epoch_min: u64,
    pub forbidden_key_epochs: Vec<u64>,
    pub required_status_freshness_seconds: u64,
    pub required_audience: String,
    pub nonce_policy: String,
    pub allowed_algorithms: Vec<String>,
    pub forbidden_algorithms: Vec<String>,
    pub required_transparency_state: TransparencyState,
    pub max_presentation_age_seconds: u64,
    pub allowed_disclosed_fields: Vec<String>,
    pub forbidden_disclosed_fields: Vec<String>,
    pub allowed_hidden_predicates: Vec<String>,
    pub forbidden_hidden_predicates: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DisclosureProfileLeakageBudget {
    pub max_disclosed_fields: u32,
    pub max_hidden_predicates: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DisclosureSensitivityClass {
    pub class_id: String,
    pub fields: Vec<String>,
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
    pub projection_manifest_ref: String,
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
    pub projection_manifest_ref: String,
    pub privacy_profile_ref: String,
    pub lineage_subgraph_ref: String,
    pub leakage_ledger_ref: String,
    pub disclosed_fields: Vec<String>,
    pub hidden_predicates: Vec<DisclosureHiddenPredicate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DisclosureHiddenPredicate {
    pub predicate_id: String,
    pub kind: String,
    pub field: String,
    pub operator: String,
    pub operand: String,
    pub unit: String,
    pub result: bool,
    pub proof_ref: String,
    pub projection_slot: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedLineageSubgraph {
    pub schema: String,
    pub id: String,
    pub transaction_passport_ref: String,
    pub policy_profile_id: String,
    pub generated_at: String,
    pub audience: String,
    pub challenge_nonce: String,
    pub frontier_sha256: String,
    pub checkpoint_ref: String,
    pub checkpoint_inclusion_sha256: String,
    pub max_depth: u32,
    pub required_evidence_class: String,
    pub lineage_anchor_ref: String,
    pub redaction_map_sha256: String,
    pub leakage_ledger_sha256: String,
    pub projection_manifest_sha256: String,
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
    pub kind: String,
    pub receipt_ref: String,
    pub artifact_sha256: String,
    pub artifact_schema: String,
    pub evidence_class: String,
    pub tenant_hash: String,
    pub source_table: String,
    pub source_id_hash: String,
    pub depth: u32,
    pub parent_ids: Vec<String>,
    pub disclosure_state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DisclosureSignedLineageEdge {
    pub edge_id: String,
    pub from: String,
    pub to: String,
    pub relation: String,
    pub kind: String,
    pub evidence_class: String,
    pub source_artifact_sha256: String,
    pub statement_sha256: String,
    pub disclosure_state: String,
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
    pub policy_profile_id: String,
    pub subject_artifact_sha256: String,
    pub generated_at: String,
    pub audience: String,
    pub total_leakage_score: u32,
    pub max_allowed_leakage_score: u32,
    pub tenant_leakage_notice_ref: String,
    pub accepted: bool,
    pub entries: Vec<DisclosureLeakageLedgerEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DisclosureLeakageLedgerEntry {
    pub entry_id: String,
    pub source: String,
    pub field: String,
    pub leakage_kind: String,
    pub disclosure_kind: String,
    pub sensitivity_class: String,
    pub value_class: String,
    pub reason: String,
    pub policy_rule: String,
    pub derived_inferences: Vec<String>,
    pub cross_tenant_risk: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mitigation: Option<String>,
    pub score: u32,
    pub allowed_by_profile: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub residual_inference_note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DisclosureLineageBundle {
    pub capsule: DisclosureCapsule,
    pub privacy_profile: DisclosureVerifierPrivacyProfile,
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
    pub crypto_verified: bool,
    pub privacy_profile_verified: bool,
    pub disclosed_field_count: usize,
    pub hidden_predicate_count: usize,
    pub verified_claims: Vec<String>,
}
