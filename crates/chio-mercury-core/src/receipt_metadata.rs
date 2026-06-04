use chio_core::receipt::ChioReceipt;
use serde::{Deserialize, Serialize};

use crate::validation::{ensure_non_empty, ensure_optional_non_empty};

pub const MERCURY_RECEIPT_METADATA_SCHEMA: &str = "chio.mercury.receipt_metadata.v1";

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum MercuryContractError {
    #[error("invalid MERCURY schema `{actual}` (expected `{expected}`)")]
    InvalidSchema {
        expected: &'static str,
        actual: String,
    },
    #[error("missing required field `{0}`")]
    MissingField(&'static str),
    #[error("field `{0}` must not be empty")]
    EmptyField(&'static str),
    #[error("field `{0}` must not have surrounding whitespace")]
    PaddedField(&'static str),
    #[error("receipt metadata must be a JSON object")]
    ReceiptMetadataNotObject,
    #[error("validation error: {0}")]
    Validation(String),
    #[error("json error: {0}")]
    Json(String),
}

impl From<serde_json::Error> for MercuryContractError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct MercuryWorkflowIdentifiers {
    pub workflow_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desk_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exception_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inquiry_id: Option<String>,
}

impl MercuryWorkflowIdentifiers {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        ensure_non_empty("business_ids.workflow_id", &self.workflow_id)?;
        ensure_optional_non_empty("business_ids.account_id", self.account_id.as_deref())?;
        ensure_optional_non_empty("business_ids.desk_id", self.desk_id.as_deref())?;
        ensure_optional_non_empty("business_ids.strategy_id", self.strategy_id.as_deref())?;
        ensure_optional_non_empty("business_ids.release_id", self.release_id.as_deref())?;
        ensure_optional_non_empty("business_ids.rollback_id", self.rollback_id.as_deref())?;
        ensure_optional_non_empty("business_ids.exception_id", self.exception_id.as_deref())?;
        ensure_optional_non_empty("business_ids.inquiry_id", self.inquiry_id.as_deref())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MercuryDecisionType {
    #[default]
    Propose,
    Approve,
    Deny,
    Release,
    Rollback,
    Exception,
    Inquiry,
    Simulate,
    Observe,
}

impl MercuryDecisionType {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Propose => "propose",
            Self::Approve => "approve",
            Self::Deny => "deny",
            Self::Release => "release",
            Self::Rollback => "rollback",
            Self::Exception => "exception",
            Self::Inquiry => "inquiry",
            Self::Simulate => "simulate",
            Self::Observe => "observe",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct MercuryDecisionContext {
    pub decision_type: MercuryDecisionType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MercuryChronologyStage {
    #[default]
    Proposal,
    Approval,
    Release,
    Rollback,
    ExceptionReview,
    Inquiry,
    Observation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct MercuryChronology {
    pub event_id: String,
    pub stage: MercuryChronologyStage,
    pub ingested_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_timestamp: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub causal_parent_event_ids: Vec<String>,
}

impl MercuryChronology {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        ensure_non_empty("chronology.event_id", &self.event_id)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct MercuryProvenance {
    pub source_system: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_record_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosting_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependency_digest: Option<String>,
}

impl MercuryProvenance {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        ensure_non_empty("provenance.source_system", &self.source_system)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MercurySensitivityClass {
    #[default]
    Internal,
    Confidential,
    Restricted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct MercurySensitivity {
    pub classification: MercurySensitivityClass,
    #[serde(default)]
    pub contains_customer_data: bool,
    #[serde(default)]
    pub contains_market_data: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_class: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct MercuryDisclosurePolicy {
    pub policy: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redaction_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(default)]
    pub verifier_equivalent: bool,
    #[serde(default)]
    pub reviewed_export_approved: bool,
}

impl MercuryDisclosurePolicy {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        ensure_non_empty("disclosure.policy", &self.policy)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MercuryApprovalStatus {
    #[default]
    Pending,
    Approved,
    Denied,
    RolledBack,
    InquiryOpen,
    NotRequired,
}

impl MercuryApprovalStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::RolledBack => "rolled_back",
            Self::InquiryOpen => "inquiry_open",
            Self::NotRequired => "not_required",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct MercuryApprovalState {
    pub state: MercuryApprovalStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approver_subjects: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_ticket_id: Option<String>,
}

use crate::bundle::MercuryBundleReference;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct MercuryReceiptMetadata {
    pub schema: String,
    pub business_ids: MercuryWorkflowIdentifiers,
    pub decision_context: MercuryDecisionContext,
    pub chronology: MercuryChronology,
    pub provenance: MercuryProvenance,
    pub sensitivity: MercurySensitivity,
    pub disclosure: MercuryDisclosurePolicy,
    pub approval_state: MercuryApprovalState,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bundle_refs: Vec<MercuryBundleReference>,
}

impl MercuryReceiptMetadata {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_RECEIPT_METADATA_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_RECEIPT_METADATA_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        self.business_ids.validate()?;
        self.chronology.validate()?;
        self.provenance.validate()?;
        self.disclosure.validate()?;
        for bundle_ref in &self.bundle_refs {
            bundle_ref.validate()?;
        }
        Ok(())
    }

    pub fn into_receipt_metadata_value(&self) -> Result<serde_json::Value, MercuryContractError> {
        self.validate()?;
        Ok(serde_json::json!({ "mercury": self }))
    }

    pub fn merge_into_receipt_metadata(
        &self,
        existing: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, MercuryContractError> {
        self.validate()?;
        match existing {
            None => self.into_receipt_metadata_value(),
            Some(serde_json::Value::Object(mut map)) => {
                map.insert("mercury".to_string(), serde_json::to_value(self)?);
                Ok(serde_json::Value::Object(map))
            }
            Some(_) => Err(MercuryContractError::ReceiptMetadataNotObject),
        }
    }

    pub fn from_receipt(receipt: &ChioReceipt) -> Result<Option<Self>, MercuryContractError> {
        Self::from_metadata_value(receipt.metadata.as_ref())
    }

    pub fn from_metadata_value(
        metadata: Option<&serde_json::Value>,
    ) -> Result<Option<Self>, MercuryContractError> {
        let Some(metadata) = metadata else {
            return Ok(None);
        };
        let Some(mercury) = metadata.get("mercury") else {
            return Ok(None);
        };
        let parsed: Self = serde_json::from_value(mercury.clone())?;
        parsed.validate()?;
        Ok(Some(parsed))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::fixtures::sample_mercury_receipt_metadata;

    #[test]
    fn receipt_metadata_wraps_under_mercury_key() {
        let metadata = sample_mercury_receipt_metadata();
        let value = metadata
            .into_receipt_metadata_value()
            .expect("metadata value");
        let restored =
            MercuryReceiptMetadata::from_metadata_value(Some(&value)).expect("restore metadata");
        assert_eq!(restored.expect("present"), metadata);
    }

    #[test]
    fn receipt_metadata_requires_schema() {
        let mut metadata = sample_mercury_receipt_metadata();
        metadata.schema = "wrong".to_string();
        let error = metadata.validate().expect_err("schema should fail");
        assert!(matches!(error, MercuryContractError::InvalidSchema { .. }));
    }

    #[test]
    fn receipt_metadata_rejects_padded_workflow_id() {
        let mut metadata = sample_mercury_receipt_metadata();
        metadata.business_ids.workflow_id = " workflow-release-control ".to_string();

        let error = metadata.validate().expect_err("padded workflow id");

        assert!(matches!(
            error,
            MercuryContractError::PaddedField("business_ids.workflow_id")
        ));
    }

    #[test]
    fn receipt_metadata_rejects_empty_optional_business_ids() {
        let mut metadata = sample_mercury_receipt_metadata();
        metadata.business_ids.account_id = Some(" ".to_string());

        let error = metadata.validate().expect_err("empty optional account id");

        assert!(matches!(
            error,
            MercuryContractError::EmptyField("business_ids.account_id")
        ));
    }

    #[test]
    fn receipt_metadata_rejects_padded_optional_business_ids() {
        let mut metadata = sample_mercury_receipt_metadata();
        metadata.business_ids.inquiry_id = Some(" inquiry-2026-04-02 ".to_string());

        let error = metadata.validate().expect_err("padded optional inquiry id");

        assert!(matches!(
            error,
            MercuryContractError::PaddedField("business_ids.inquiry_id")
        ));
    }
}
