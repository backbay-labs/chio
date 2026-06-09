use serde::{Deserialize, Serialize};

use crate::receipt_metadata::{MercuryApprovalStatus, MercuryDecisionType, MercuryReceiptMetadata};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct MercuryReceiptQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_id: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_state: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MercuryReceiptIndexRecord {
    pub receipt_id: String,
    pub workflow_id: Option<String>,
    pub account_id: Option<String>,
    pub desk_id: Option<String>,
    pub strategy_id: Option<String>,
    pub release_id: Option<String>,
    pub rollback_id: Option<String>,
    pub exception_id: Option<String>,
    pub inquiry_id: Option<String>,
    pub decision_type: String,
    pub approval_state: String,
}

impl MercuryReceiptIndexRecord {
    #[must_use]
    pub fn from_metadata(receipt_id: impl Into<String>, metadata: &MercuryReceiptMetadata) -> Self {
        Self {
            receipt_id: receipt_id.into(),
            workflow_id: Some(metadata.business_ids.workflow_id.clone()),
            account_id: metadata.business_ids.account_id.clone(),
            desk_id: metadata.business_ids.desk_id.clone(),
            strategy_id: metadata.business_ids.strategy_id.clone(),
            release_id: metadata.business_ids.release_id.clone(),
            rollback_id: metadata.business_ids.rollback_id.clone(),
            exception_id: metadata.business_ids.exception_id.clone(),
            inquiry_id: metadata.business_ids.inquiry_id.clone(),
            decision_type: metadata.decision_context.decision_type.as_str().to_string(),
            approval_state: metadata.approval_state.state.as_str().to_string(),
        }
    }

    #[must_use]
    pub fn decision_type_enum(&self) -> Option<MercuryDecisionType> {
        match self.decision_type.as_str() {
            "propose" => Some(MercuryDecisionType::Propose),
            "approve" => Some(MercuryDecisionType::Approve),
            "deny" => Some(MercuryDecisionType::Deny),
            "release" => Some(MercuryDecisionType::Release),
            "rollback" => Some(MercuryDecisionType::Rollback),
            "exception" => Some(MercuryDecisionType::Exception),
            "inquiry" => Some(MercuryDecisionType::Inquiry),
            "simulate" => Some(MercuryDecisionType::Simulate),
            "observe" => Some(MercuryDecisionType::Observe),
            _ => None,
        }
    }

    #[must_use]
    pub fn approval_state_enum(&self) -> Option<MercuryApprovalStatus> {
        match self.approval_state.as_str() {
            "pending" => Some(MercuryApprovalStatus::Pending),
            "approved" => Some(MercuryApprovalStatus::Approved),
            "denied" => Some(MercuryApprovalStatus::Denied),
            "rolled_back" => Some(MercuryApprovalStatus::RolledBack),
            "inquiry_open" => Some(MercuryApprovalStatus::InquiryOpen),
            "not_required" => Some(MercuryApprovalStatus::NotRequired),
            _ => None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::fixtures::sample_mercury_receipt_metadata;

    #[test]
    fn index_record_captures_primary_mercury_filters() {
        let metadata = sample_mercury_receipt_metadata();
        let record = MercuryReceiptIndexRecord::from_metadata("receipt-1", &metadata);
        assert_eq!(
            record.workflow_id.as_deref(),
            Some("workflow-release-control")
        );
        assert_eq!(record.release_id.as_deref(), Some("release-2026-04-02"));
        assert_eq!(record.decision_type, "release");
        assert_eq!(record.approval_state, "approved");
    }
}
