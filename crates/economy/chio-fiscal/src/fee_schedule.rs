use chio_core_types::canonical_json_bytes;
use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::sha256_hex;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_listing::{normalize_namespace, GenericListingActorKind, GenericTrustAdmissionClass};
use serde::{Deserialize, Serialize};

pub const OPEN_MARKET_FEE_SCHEDULE_ARTIFACT_SCHEMA: &str = "chio.registry.market-fee-schedule.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OpenMarketBondClass {
    Publication,
    Listing,
    Dispute,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OpenMarketCollateralReferenceKind {
    CreditBond,
    ExternalReference,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenMarketEconomicsScope {
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_listing_operator_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_actor_kinds: Vec<GenericListingActorKind>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_admission_classes: Vec<GenericTrustAdmissionClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_reference: Option<String>,
}

impl OpenMarketEconomicsScope {
    pub fn validate(&self) -> Result<(), String> {
        validate_non_empty(&self.namespace, "scope.namespace")?;
        for (index, operator_id) in self.allowed_listing_operator_ids.iter().enumerate() {
            validate_non_empty(
                operator_id,
                &format!("scope.allowed_listing_operator_ids[{index}]"),
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenMarketBondRequirement {
    pub bond_class: OpenMarketBondClass,
    pub required_amount: MonetaryAmount,
    pub collateral_reference_kind: OpenMarketCollateralReferenceKind,
    pub slashable: bool,
}

impl OpenMarketBondRequirement {
    pub fn validate(&self, field: &str) -> Result<(), String> {
        validate_monetary_amount(&self.required_amount, &format!("{field}.required_amount"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenMarketFeeScheduleArtifact {
    pub schema: String,
    pub fee_schedule_id: String,
    pub namespace: String,
    pub governing_operator_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governing_operator_name: Option<String>,
    pub scope: OpenMarketEconomicsScope,
    pub publication_fee: MonetaryAmount,
    pub dispute_fee: MonetaryAmount,
    pub market_participation_fee: MonetaryAmount,
    pub bond_requirements: Vec<OpenMarketBondRequirement>,
    pub issued_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub issued_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl OpenMarketFeeScheduleArtifact {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != OPEN_MARKET_FEE_SCHEDULE_ARTIFACT_SCHEMA {
            return Err(format!(
                "unsupported open-market fee schedule schema: {}",
                self.schema
            ));
        }
        validate_non_empty(&self.fee_schedule_id, "fee_schedule_id")?;
        validate_non_empty(&self.namespace, "namespace")?;
        validate_non_empty(&self.governing_operator_id, "governing_operator_id")?;
        validate_non_empty(&self.issued_by, "issued_by")?;
        self.scope.validate()?;
        if normalize_namespace(&self.namespace) != normalize_namespace(&self.scope.namespace) {
            return Err("fee schedule namespace must match scope namespace".to_string());
        }
        validate_monetary_amount(&self.publication_fee, "publication_fee")?;
        validate_monetary_amount(&self.dispute_fee, "dispute_fee")?;
        validate_monetary_amount(&self.market_participation_fee, "market_participation_fee")?;
        if self.bond_requirements.is_empty() {
            return Err("bond_requirements must not be empty".to_string());
        }
        for (index, requirement) in self.bond_requirements.iter().enumerate() {
            requirement.validate(&format!("bond_requirements[{index}]"))?;
        }
        if let Some(expires_at) = self.expires_at {
            if expires_at <= self.issued_at {
                return Err("expires_at must be greater than issued_at".to_string());
            }
        }
        Ok(())
    }
}

pub type SignedOpenMarketFeeSchedule = SignedExportEnvelope<OpenMarketFeeScheduleArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenMarketFeeScheduleIssueRequest {
    pub scope: OpenMarketEconomicsScope,
    pub publication_fee: MonetaryAmount,
    pub dispute_fee: MonetaryAmount,
    pub market_participation_fee: MonetaryAmount,
    pub bond_requirements: Vec<OpenMarketBondRequirement>,
    pub issued_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl OpenMarketFeeScheduleIssueRequest {
    pub fn validate(&self) -> Result<(), String> {
        self.scope.validate()?;
        validate_non_empty(&self.issued_by, "issued_by")?;
        validate_monetary_amount(&self.publication_fee, "publication_fee")?;
        validate_monetary_amount(&self.dispute_fee, "dispute_fee")?;
        validate_monetary_amount(&self.market_participation_fee, "market_participation_fee")?;
        if self.bond_requirements.is_empty() {
            return Err("bond_requirements must not be empty".to_string());
        }
        for (index, requirement) in self.bond_requirements.iter().enumerate() {
            requirement.validate(&format!("bond_requirements[{index}]"))?;
        }
        Ok(())
    }
}

pub fn build_open_market_fee_schedule_artifact(
    local_operator_id: &str,
    local_operator_name: Option<String>,
    request: &OpenMarketFeeScheduleIssueRequest,
    issued_at: u64,
) -> Result<OpenMarketFeeScheduleArtifact, String> {
    request.validate()?;
    validate_non_empty(local_operator_id, "local_operator_id")?;
    let issued_at = request.issued_at.unwrap_or(issued_at);
    let fee_schedule_id = format!(
        "market-fee-schedule-{}",
        sha256_hex(
            &canonical_json_bytes(&(
                local_operator_id,
                normalize_namespace(&request.scope.namespace),
                &request.publication_fee,
                &request.dispute_fee,
                &request.market_participation_fee,
                &request.bond_requirements,
                issued_at,
            ))
            .map_err(|error| error.to_string())?
        )
    );
    let artifact = OpenMarketFeeScheduleArtifact {
        schema: OPEN_MARKET_FEE_SCHEDULE_ARTIFACT_SCHEMA.to_string(),
        fee_schedule_id,
        namespace: request.scope.namespace.clone(),
        governing_operator_id: local_operator_id.to_string(),
        governing_operator_name: local_operator_name,
        scope: request.scope.clone(),
        publication_fee: request.publication_fee.clone(),
        dispute_fee: request.dispute_fee.clone(),
        market_participation_fee: request.market_participation_fee.clone(),
        bond_requirements: request.bond_requirements.clone(),
        issued_at,
        expires_at: request.expires_at,
        issued_by: request.issued_by.clone(),
        note: request.note.clone(),
    };
    artifact.validate()?;
    Ok(artifact)
}

fn validate_monetary_amount(value: &MonetaryAmount, field: &str) -> Result<(), String> {
    if value.units == 0 {
        return Err(format!("{field}.units must be greater than zero"));
    }
    validate_non_empty(&value.currency, &format!("{field}.currency"))
}

fn validate_non_empty(value: &str, field: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{field} must not be empty"))
    } else {
        Ok(())
    }
}
