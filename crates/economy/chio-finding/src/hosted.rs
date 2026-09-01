//! Signed hosted-market transition artifacts.
//!
//! These artifacts close the persistence boundary between the cognition
//! market state machines and a hosted event store. They contain commitments
//! and terminal facts only. Secrets and revealed payload bytes never enter
//! the event journal.

use std::collections::BTreeSet;

use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::PublicKey;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::{Deserialize, Serialize};

use crate::envelope::require_ed25519;
use crate::validate::{
    require_bounded_id, require_bounded_text, require_currency, require_hex64, require_i_json_u64,
    require_max_items, require_nonzero, FindingError,
};

pub const FINDING_CLAIM_ALLOCATION_SCHEMA_V1: &str =
    chio_core_types::CHIO_FINDING_CLAIM_ALLOCATION_V1_SCHEMA;
pub const FINDING_PURCHASE_RESULT_SCHEMA_V1: &str =
    chio_core_types::CHIO_FINDING_PURCHASE_RESULT_V1_SCHEMA;
pub const FINDING_VERIFIED_FIX_SUBMISSION_SCHEMA_V1: &str =
    chio_core_types::CHIO_FINDING_VERIFIED_FIX_SUBMISSION_V1_SCHEMA;
pub const FINDING_VOLUNTARY_RETRACTION_SCHEMA_V1: &str =
    chio_core_types::CHIO_FINDING_VOLUNTARY_RETRACTION_V1_SCHEMA;
pub const FINDING_LIABILITY_SCHEMA_V1: &str = chio_core_types::CHIO_FINDING_LIABILITY_V1_SCHEMA;

const MAX_ALLOCATION_ENTRIES: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FindingClaimBeneficiaryKind {
    Buyer,
    CommunityFund,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingClaimAllocationEntry {
    pub beneficiary_kind: FindingClaimBeneficiaryKind,
    pub destination: String,
    pub amount_units: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingClaimAllocation {
    pub schema: String,
    pub allocation_id: String,
    pub liability_key: String,
    pub purchase_snapshot_sha256: String,
    pub deterministic_allocation_sha256: String,
    pub cutoff_slot: u64,
    pub total_realized_spend_units: u64,
    pub slash: MonetaryAmount,
    pub buyer_pool_units: u64,
    pub community_fund_units: u64,
    pub entries: Vec<FindingClaimAllocationEntry>,
    pub recorded_at: u64,
}

pub type SignedFindingClaimAllocation = SignedExportEnvelope<FindingClaimAllocation>;

impl FindingClaimAllocation {
    pub fn validate(&self) -> Result<(), FindingError> {
        if self.schema != FINDING_CLAIM_ALLOCATION_SCHEMA_V1 {
            return Err(FindingError::UnsupportedSchema(self.schema.clone()));
        }
        require_hex64(&self.allocation_id, "allocation_id")?;
        require_hex64(&self.liability_key, "liability_key")?;
        require_hex64(&self.purchase_snapshot_sha256, "purchase_snapshot_sha256")?;
        require_hex64(
            &self.deterministic_allocation_sha256,
            "deterministic_allocation_sha256",
        )?;
        if self.allocation_id != self.deterministic_allocation_sha256 {
            return Err(FindingError::ArtifactIdMismatch("allocation_id"));
        }
        require_nonzero(self.cutoff_slot, "cutoff_slot")?;
        require_i_json_u64(
            self.total_realized_spend_units,
            "total_realized_spend_units",
        )?;
        require_nonzero(self.slash.units, "slash.units")?;
        require_currency(&self.slash.currency, "slash.currency")?;
        require_i_json_u64(self.buyer_pool_units, "buyer_pool_units")?;
        require_i_json_u64(self.community_fund_units, "community_fund_units")?;
        require_nonzero(self.recorded_at, "recorded_at")?;
        if self.entries.is_empty() {
            return Err(FindingError::MissingEntry("entries"));
        }
        require_max_items(self.entries.len(), "entries", MAX_ALLOCATION_ENTRIES)?;

        let mut destinations = BTreeSet::new();
        let mut buyer_total = 0_u64;
        let mut community_total = 0_u64;
        for entry in &self.entries {
            require_bounded_id(&entry.destination, "entry.destination")?;
            require_nonzero(entry.amount_units, "entry.amount_units")?;
            if !destinations.insert(&entry.destination) {
                return Err(FindingError::DuplicateEntry("entry.destination"));
            }
            let total = match entry.beneficiary_kind {
                FindingClaimBeneficiaryKind::Buyer => &mut buyer_total,
                FindingClaimBeneficiaryKind::CommunityFund => &mut community_total,
            };
            *total = total
                .checked_add(entry.amount_units)
                .ok_or(FindingError::AmountOverflow("entries"))?;
        }
        if buyer_total != self.buyer_pool_units
            || community_total != self.community_fund_units
            || buyer_total
                .checked_add(community_total)
                .ok_or(FindingError::AmountOverflow("allocation"))?
                != self.slash.units
        {
            return Err(FindingError::InvalidField("allocation totals"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingHostedPurchaseVerdict {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingHostedSettlementTerminal {
    Captured,
    Released,
}

/// Secret-free commitment to a complete purchase terminal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingPurchaseResult {
    pub schema: String,
    pub result_id: String,
    pub request_id: String,
    pub finding_id: String,
    pub payer: PublicKey,
    pub reservation_id: String,
    pub purchase_intent_id: String,
    pub authoritative_payment_operation_id: String,
    pub verdict: FindingHostedPurchaseVerdict,
    pub settlement: FindingHostedSettlementTerminal,
    pub accepted_price: MonetaryAmount,
    pub realized_spend: MonetaryAmount,
    pub delivery_receipt_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purchase_record_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_delivery_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_sha256: Option<String>,
    pub recorded_at: u64,
}

pub type SignedFindingPurchaseResult = SignedExportEnvelope<FindingPurchaseResult>;

impl FindingPurchaseResult {
    pub fn validate(&self) -> Result<(), FindingError> {
        if self.schema != FINDING_PURCHASE_RESULT_SCHEMA_V1 {
            return Err(FindingError::UnsupportedSchema(self.schema.clone()));
        }
        require_hex64(&self.result_id, "result_id")?;
        require_hex64(&self.request_id, "request_id")?;
        if self.result_id != self.request_id {
            return Err(FindingError::ArtifactIdMismatch("result_id"));
        }
        require_hex64(&self.finding_id, "finding_id")?;
        require_ed25519(&self.payer, "payer")?;
        require_bounded_id(&self.reservation_id, "reservation_id")?;
        require_bounded_id(&self.purchase_intent_id, "purchase_intent_id")?;
        require_bounded_id(
            &self.authoritative_payment_operation_id,
            "authoritative_payment_operation_id",
        )?;
        require_nonzero(self.accepted_price.units, "accepted_price.units")?;
        require_currency(&self.accepted_price.currency, "accepted_price.currency")?;
        require_i_json_u64(self.realized_spend.units, "realized_spend.units")?;
        require_currency(&self.realized_spend.currency, "realized_spend.currency")?;
        if self.accepted_price.currency != self.realized_spend.currency {
            return Err(FindingError::CurrencyMismatch("purchase_result"));
        }
        if self.realized_spend.units > self.accepted_price.units {
            return Err(FindingError::InvalidField("realized_spend"));
        }
        require_hex64(&self.delivery_receipt_sha256, "delivery_receipt_sha256")?;
        for (value, field) in [
            (
                self.purchase_record_sha256.as_deref(),
                "purchase_record_sha256",
            ),
            (
                self.failed_delivery_sha256.as_deref(),
                "failed_delivery_sha256",
            ),
            (self.output_sha256.as_deref(), "output_sha256"),
        ] {
            if let Some(value) = value {
                require_hex64(value, field)?;
            }
        }
        require_nonzero(self.recorded_at, "recorded_at")?;
        match (self.verdict, self.settlement) {
            (FindingHostedPurchaseVerdict::Allow, FindingHostedSettlementTerminal::Captured)
                if self.realized_spend.units > 0
                    && self.purchase_record_sha256.is_some()
                    && self.failed_delivery_sha256.is_none()
                    && self.output_sha256.is_some() =>
            {
                Ok(())
            }
            (FindingHostedPurchaseVerdict::Deny, FindingHostedSettlementTerminal::Released)
                if self.realized_spend.units == 0
                    && self.purchase_record_sha256.is_none()
                    && self.failed_delivery_sha256.is_some()
                    && self.output_sha256.is_none() =>
            {
                Ok(())
            }
            _ => Err(FindingError::InvalidField("purchase terminal")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingVerifiedFixSubmission {
    pub schema: String,
    pub submission_id: String,
    pub seller: PublicKey,
    pub finding_id: String,
    pub proof_bundle_sha256: String,
    pub activation_sha256: String,
    pub submitted_at: u64,
}

pub type SignedFindingVerifiedFixSubmission = SignedExportEnvelope<FindingVerifiedFixSubmission>;

impl FindingVerifiedFixSubmission {
    pub fn validate(&self) -> Result<(), FindingError> {
        if self.schema != FINDING_VERIFIED_FIX_SUBMISSION_SCHEMA_V1 {
            return Err(FindingError::UnsupportedSchema(self.schema.clone()));
        }
        require_hex64(&self.submission_id, "submission_id")?;
        require_ed25519(&self.seller, "seller")?;
        require_hex64(&self.finding_id, "finding_id")?;
        require_hex64(&self.proof_bundle_sha256, "proof_bundle_sha256")?;
        require_hex64(&self.activation_sha256, "activation_sha256")?;
        require_nonzero(self.submitted_at, "submitted_at")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingVoluntaryRetractionReason {
    SellerVoluntaryRetraction,
    SellerVerifiedFixSupersession,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingVoluntaryRetraction {
    pub schema: String,
    pub intent_id: String,
    pub finding_id: String,
    pub seller: PublicKey,
    pub status_feed_ref: String,
    pub reason: FindingVoluntaryRetractionReason,
    pub issued_at: u64,
    pub inclusion_deadline: u64,
}

pub type SignedFindingVoluntaryRetraction = SignedExportEnvelope<FindingVoluntaryRetraction>;

impl FindingVoluntaryRetraction {
    pub fn validate(&self) -> Result<(), FindingError> {
        if self.schema != FINDING_VOLUNTARY_RETRACTION_SCHEMA_V1 {
            return Err(FindingError::UnsupportedSchema(self.schema.clone()));
        }
        require_hex64(&self.intent_id, "intent_id")?;
        require_hex64(&self.finding_id, "finding_id")?;
        require_ed25519(&self.seller, "seller")?;
        require_bounded_id(&self.status_feed_ref, "status_feed_ref")?;
        require_nonzero(self.issued_at, "issued_at")?;
        require_i_json_u64(self.inclusion_deadline, "inclusion_deadline")?;
        if self.inclusion_deadline <= self.issued_at {
            return Err(FindingError::InvalidValidityWindow);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingLiabilityLifecycleState {
    Open,
    UpheldPendingClaims,
    PendingAppeal,
    Finalizing,
    Settled,
    Quarantined,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingLiability {
    pub schema: String,
    pub liability_key: String,
    pub defect_key: String,
    pub finding_id: String,
    pub listing_id: String,
    pub backing_allocation_id: String,
    pub seller: PublicKey,
    pub venue_id: String,
    pub chain_id: String,
    pub vault_contract: String,
    pub vault_id: String,
    pub state: FindingLiabilityLifecycleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upheld_challenge_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purchase_snapshot_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deterministic_allocation_sha256: Option<String>,
    pub opened_at: u64,
    pub updated_at: u64,
}

pub type SignedFindingLiability = SignedExportEnvelope<FindingLiability>;

impl FindingLiability {
    pub fn validate(&self) -> Result<(), FindingError> {
        if self.schema != FINDING_LIABILITY_SCHEMA_V1 {
            return Err(FindingError::UnsupportedSchema(self.schema.clone()));
        }
        require_hex64(&self.liability_key, "liability_key")?;
        require_hex64(&self.defect_key, "defect_key")?;
        require_hex64(&self.finding_id, "finding_id")?;
        require_bounded_id(&self.listing_id, "listing_id")?;
        require_bounded_id(&self.backing_allocation_id, "backing_allocation_id")?;
        require_ed25519(&self.seller, "seller")?;
        require_bounded_id(&self.venue_id, "venue_id")?;
        require_bounded_id(&self.chain_id, "chain_id")?;
        require_bounded_text(&self.vault_contract, "vault_contract")?;
        require_bounded_id(&self.vault_id, "vault_id")?;
        require_nonzero(self.opened_at, "opened_at")?;
        require_nonzero(self.updated_at, "updated_at")?;
        if self.updated_at < self.opened_at {
            return Err(FindingError::InvalidField("updated_at"));
        }
        for (value, field) in [
            (self.upheld_challenge_id.as_deref(), "upheld_challenge_id"),
            (
                self.purchase_snapshot_sha256.as_deref(),
                "purchase_snapshot_sha256",
            ),
            (
                self.deterministic_allocation_sha256.as_deref(),
                "deterministic_allocation_sha256",
            ),
        ] {
            if let Some(value) = value {
                require_hex64(value, field)?;
            }
        }
        let has_upheld = self.upheld_challenge_id.is_some();
        let has_snapshot = self.purchase_snapshot_sha256.is_some();
        let has_allocation = self.deterministic_allocation_sha256.is_some();
        match self.state {
            FindingLiabilityLifecycleState::Open
                if !has_upheld && !has_snapshot && !has_allocation =>
            {
                Ok(())
            }
            FindingLiabilityLifecycleState::UpheldPendingClaims
                if has_upheld && !has_snapshot && !has_allocation =>
            {
                Ok(())
            }
            FindingLiabilityLifecycleState::PendingAppeal
            | FindingLiabilityLifecycleState::Finalizing
            | FindingLiabilityLifecycleState::Settled
                if has_upheld && has_snapshot && has_allocation =>
            {
                Ok(())
            }
            FindingLiabilityLifecycleState::Quarantined if has_upheld => Ok(()),
            _ => Err(FindingError::InvalidField("liability state evidence")),
        }
    }
}
