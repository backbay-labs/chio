#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use chio_core_types::{
    capability::{governance::ProvenanceEvidenceClass, scope::MonetaryAmount},
    crypto::PublicKey,
    receipt::lineage::SignedExportEnvelope,
};
use serde::{Deserialize, Serialize};

pub const MAX_I_JSON_SAFE_INTEGER: u64 = (1 << 53) - 1;
pub const FINANCIAL_CREDENTIAL_SCHEMA_CREDIT_SCORECARD_V1: &str =
    "chio.fincred.credit-scorecard.v1";
pub const FINANCIAL_CREDENTIAL_SCHEMA_EXPOSURE_HISTORY_V1: &str =
    "chio.fincred.exposure-history.v1";
pub const FINANCIAL_CREDENTIAL_SCHEMA_SETTLEMENT_RELIABILITY_V1: &str =
    "chio.fincred.settlement-reliability.v1";
pub const FINANCIAL_CREDENTIAL_SCHEMA_PREMIUM_HISTORY_V1: &str = "chio.fincred.premium-history.v1";
pub const FINANCIAL_CREDENTIAL_SCHEMA_LOSS_HISTORY_V1: &str = "chio.fincred.loss-history.v1";
pub const FINANCIAL_SOURCE_COMPLETENESS_ATTESTATION_SCHEMA_V1: &str =
    "chio.fincred.source-completeness-attestation.v1";
pub const FINANCIAL_SOURCE_CHECKPOINT_SCHEMA_V1: &str = "chio.fincred.source-checkpoint.v1";
pub const FINANCIAL_SOURCE_MEMBER_SCHEMA_V1: &str = "chio.fincred.source-member.v1";
pub const FINANCIAL_VERIFIER_POLICY_SCHEMA_V1: &str = "chio.fincred.verifier-policy.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FinancialCredentialFamilyV1 {
    CreditScorecard,
    ExposureHistory,
    SettlementReliability,
    PremiumHistory,
    LossHistory,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinancialVerifierThresholdsV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_credit_score: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_open_exposure_ratio_bps: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_settlement_reliability_bps: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_loss_event_count: Option<u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub max_premium_units_by_currency: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinancialVerifierPolicyV1 {
    pub schema: String,
    pub policy_id: String,
    pub tenant: String,
    pub verifier: String,
    pub accepted_issuers: BTreeSet<String>,
    pub accepted_families: BTreeSet<FinancialCredentialFamilyV1>,
    pub thresholds: FinancialVerifierThresholdsV1,
    pub max_credential_age_seconds: u64,
    pub not_before: u64,
    pub expires_at: u64,
    pub configuration_generation: u64,
    pub body_digest: String,
}

impl FinancialCredentialFamilyV1 {
    #[must_use]
    pub const fn schema(self) -> &'static str {
        match self {
            Self::CreditScorecard => FINANCIAL_CREDENTIAL_SCHEMA_CREDIT_SCORECARD_V1,
            Self::ExposureHistory => FINANCIAL_CREDENTIAL_SCHEMA_EXPOSURE_HISTORY_V1,
            Self::SettlementReliability => FINANCIAL_CREDENTIAL_SCHEMA_SETTLEMENT_RELIABILITY_V1,
            Self::PremiumHistory => FINANCIAL_CREDENTIAL_SCHEMA_PREMIUM_HISTORY_V1,
            Self::LossHistory => FINANCIAL_CREDENTIAL_SCHEMA_LOSS_HISTORY_V1,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::CreditScorecard => "credit_scorecard",
            Self::ExposureHistory => "exposure_history",
            Self::SettlementReliability => "settlement_reliability",
            Self::PremiumHistory => "premium_history",
            Self::LossHistory => "loss_history",
        }
    }

    #[must_use]
    pub const fn credential_type(self) -> &'static str {
        match self {
            Self::CreditScorecard => "ChioCreditScorecardCredential",
            Self::ExposureHistory => "ChioExposureHistoryCredential",
            Self::SettlementReliability => "ChioSettlementReliabilityCredential",
            Self::PremiumHistory => "ChioPremiumHistoryCredential",
            Self::LossHistory => "ChioLossHistoryCredential",
        }
    }

    #[must_use]
    pub fn from_schema(schema: &str) -> Option<Self> {
        match schema {
            FINANCIAL_CREDENTIAL_SCHEMA_CREDIT_SCORECARD_V1 => Some(Self::CreditScorecard),
            FINANCIAL_CREDENTIAL_SCHEMA_EXPOSURE_HISTORY_V1 => Some(Self::ExposureHistory),
            FINANCIAL_CREDENTIAL_SCHEMA_SETTLEMENT_RELIABILITY_V1 => {
                Some(Self::SettlementReliability)
            }
            FINANCIAL_CREDENTIAL_SCHEMA_PREMIUM_HISTORY_V1 => Some(Self::PremiumHistory),
            FINANCIAL_CREDENTIAL_SCHEMA_LOSS_HISTORY_V1 => Some(Self::LossHistory),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditScorecardRiskBandV1 {
    Prime,
    Standard,
    Guarded,
    Probationary,
    Restricted,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditScorecardConfidenceV1 {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreditScorecardImportedSignalContextV1 {
    pub imported_signal_count: u64,
    pub accepted_imported_signal_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreditScorecardCredentialSubjectV1 {
    pub id: String,
    pub band: CreditScorecardRiskBandV1,
    pub confidence: CreditScorecardConfidenceV1,
    pub overall_score: f64,
    pub probationary: bool,
    pub imported_signals: CreditScorecardImportedSignalContextV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExposureHistoryPositionV1 {
    pub governed_max: MonetaryAmount,
    pub reserved: MonetaryAmount,
    pub settled: MonetaryAmount,
    pub pending: MonetaryAmount,
    pub failed: MonetaryAmount,
    pub provisional_loss: MonetaryAmount,
    pub recovered: MonetaryAmount,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExposureHistoryCredentialSubjectV1 {
    pub id: String,
    pub positions: Vec<ExposureHistoryPositionV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettlementReliabilityCredentialSubjectV1 {
    pub id: String,
    pub on_time_count: u64,
    pub obligation_count: u64,
    pub on_time_ratio_bps: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PremiumHistoryCredentialSubjectV1 {
    pub id: String,
    pub quoted_count: u64,
    pub quoted_amounts: Vec<MonetaryAmount>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LossHistoryCredentialSubjectV1 {
    pub id: String,
    pub delinquency_count: u64,
    pub recovery_count: u64,
    pub reserve_release_count: u64,
    pub reserve_slash_count: u64,
    pub write_off_count: u64,
    pub outstanding_amounts: Vec<MonetaryAmount>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(
    tag = "family",
    content = "claims",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum FinancialCredentialSubjectV1 {
    CreditScorecard(CreditScorecardCredentialSubjectV1),
    ExposureHistory(ExposureHistoryCredentialSubjectV1),
    SettlementReliability(SettlementReliabilityCredentialSubjectV1),
    PremiumHistory(PremiumHistoryCredentialSubjectV1),
    LossHistory(LossHistoryCredentialSubjectV1),
}

impl FinancialCredentialSubjectV1 {
    #[must_use]
    pub const fn family(&self) -> FinancialCredentialFamilyV1 {
        match self {
            Self::CreditScorecard(_) => FinancialCredentialFamilyV1::CreditScorecard,
            Self::ExposureHistory(_) => FinancialCredentialFamilyV1::ExposureHistory,
            Self::SettlementReliability(_) => FinancialCredentialFamilyV1::SettlementReliability,
            Self::PremiumHistory(_) => FinancialCredentialFamilyV1::PremiumHistory,
            Self::LossHistory(_) => FinancialCredentialFamilyV1::LossHistory,
        }
    }

    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::CreditScorecard(subject) => &subject.id,
            Self::ExposureHistory(subject) => &subject.id,
            Self::SettlementReliability(subject) => &subject.id,
            Self::PremiumHistory(subject) => &subject.id,
            Self::LossHistory(subject) => &subject.id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinancialCredentialWindowV1 {
    pub starts_at: u64,
    pub ends_at: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FinancialSourceArtifactRoleV1 {
    Claim,
    Member,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinancialSourceBundleArtifactV1 {
    pub role: FinancialSourceArtifactRoleV1,
    pub artifact_schema: String,
    pub artifact_digest: String,
    pub canonical_artifact: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinancialSourceArtifactReferenceV1 {
    pub role: FinancialSourceArtifactRoleV1,
    pub artifact_schema: String,
    pub artifact_id: String,
    pub artifact_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum FinancialSourceDisclosureV1 {
    Bundled {
        artifacts: Vec<FinancialSourceBundleArtifactV1>,
    },
    Resolver {
        resolver_id: String,
        references: Vec<FinancialSourceArtifactReferenceV1>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinancialSourceMerkleProofV1 {
    pub tree_size: u64,
    pub leaf_index: u64,
    pub audit_path: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinancialSourceQueryKeyV1 {
    pub source_family: FinancialCredentialFamilyV1,
    pub subject: String,
    pub occurred_at: u64,
    pub artifact_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinancialSourceMemberBodyV1 {
    pub schema: String,
    pub query_key: FinancialSourceQueryKeyV1,
    pub artifact_schema: String,
    pub canonical_artifact: String,
}

pub type SignedFinancialSourceMemberV1 = SignedExportEnvelope<FinancialSourceMemberBodyV1>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinancialSourceCommittedLeafV1 {
    pub index: u64,
    pub query_key: FinancialSourceQueryKeyV1,
    pub source_artifact_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinancialSourceCommittedLeafProofV1 {
    pub leaf: FinancialSourceCommittedLeafV1,
    pub index_proof: FinancialSourceMerkleProofV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum FinancialSourceCompletenessBoundaryV1 {
    SourceEdge,
    Adjacent {
        leaf_proof: FinancialSourceCommittedLeafProofV1,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinancialSourceCheckpointBodyV1 {
    pub schema: String,
    pub source_id: String,
    pub checkpoint_authority_epoch: u64,
    pub checkpoint_authority_key: PublicKey,
    pub store_generation: u64,
    pub checkpoint_sequence: u64,
    pub cutoff: u64,
    pub window: FinancialCredentialWindowV1,
    pub index_size: u64,
    pub range_root: String,
    pub index_root: String,
    pub lower_boundary: FinancialSourceCompletenessBoundaryV1,
    pub upper_boundary: FinancialSourceCompletenessBoundaryV1,
    pub issued_at: u64,
    pub expires_at: u64,
}

pub type SignedFinancialSourceCheckpointV1 = SignedExportEnvelope<FinancialSourceCheckpointBodyV1>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinancialSourceCompletenessAttestationBodyV1 {
    pub schema: String,
    pub source_id: String,
    pub source_family: FinancialCredentialFamilyV1,
    pub subject: String,
    pub source_signer_key: PublicKey,
    pub checkpoint_authority_epoch: u64,
    pub checkpoint_authority_key: PublicKey,
    pub store_generation: u64,
    pub checkpoint_sequence: u64,
    pub checkpoint_digest: String,
    pub cutoff: u64,
    pub window: FinancialCredentialWindowV1,
    pub committed_leaves: Vec<FinancialSourceCommittedLeafProofV1>,
    pub range_root: String,
    pub index_root: String,
    pub lower_boundary: FinancialSourceCompletenessBoundaryV1,
    pub upper_boundary: FinancialSourceCompletenessBoundaryV1,
    pub source_artifact_digests: Vec<String>,
    pub disclosure_digest: String,
    pub attestation_reference: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub source_evidence_class: ProvenanceEvidenceClass,
}

pub type SignedFinancialSourceCompletenessAttestationV1 =
    SignedExportEnvelope<FinancialSourceCompletenessAttestationBodyV1>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinancialCredentialEvidenceV1 {
    pub window: FinancialCredentialWindowV1,
    pub source_disclosure: FinancialSourceDisclosureV1,
    pub source_completeness_attestations: Vec<SignedFinancialSourceCompletenessAttestationV1>,
}
