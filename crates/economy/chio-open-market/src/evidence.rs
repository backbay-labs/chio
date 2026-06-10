use serde::{Deserialize, Serialize};

use crate::validation::{is_sha256_hex, validate_non_empty};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OpenMarketEvidenceKind {
    GovernanceCase,
    TrustActivation,
    Listing,
    PortableNegativeEvent,
    External,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OpenMarketFindingCode {
    ListingUnverifiable,
    FeeScheduleUnverifiable,
    FeeScheduleExpired,
    FeeScheduleScopeMismatch,
    ActivationUnverifiable,
    ActivationMissing,
    ActivationMismatch,
    GovernanceCaseAuthorityInvalid,
    GovernanceCaseExpired,
    GovernanceCaseKindInvalid,
    PenaltyUnverifiable,
    PenaltyExpired,
    BondRequirementMissing,
    BondRequirementNotSlashable,
    PenaltyCurrencyMismatch,
    PenaltyAmountExceedsBond,
    PriorPenaltyMissing,
    PriorPenaltyInvalid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenMarketEvidenceReference {
    pub kind: OpenMarketEvidenceKind,
    pub reference_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

impl OpenMarketEvidenceReference {
    pub fn validate(&self, field: &str) -> Result<(), String> {
        validate_non_empty(&self.reference_id, &format!("{field}.reference_id"))?;
        if let Some(uri) = self.uri.as_deref() {
            validate_non_empty(uri, &format!("{field}.uri"))?;
        }
        if let Some(sha256) = self.sha256.as_deref() {
            let sha256_field = format!("{field}.sha256");
            if !is_sha256_hex(sha256) {
                return Err(format!(
                    "{sha256_field} must be a 64-character SHA-256 hex digest"
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenMarketFinding {
    pub code: OpenMarketFindingCode,
    pub message: String,
}
