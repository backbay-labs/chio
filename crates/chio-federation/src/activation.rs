use serde::{Deserialize, Serialize};

use crate::artifacts::{
    FederationArtifactKind, FederationArtifactReference, FederationDelegationControl,
    FederationImportControl, FederationTrustScope,
};
use crate::error::FederationContractError;
use crate::receipt::lineage::SignedExportEnvelope;
use crate::validation::{
    ensure_non_empty, validate_delegation_control, validate_federation_artifact_reference,
    validate_federation_scope, validate_import_control,
};

pub const CHIO_FEDERATION_ACTIVATION_EXCHANGE_SCHEMA: &str =
    "chio.federation-activation-exchange.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationActivationExchangeArtifact {
    pub schema: String,
    pub exchange_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub source_operator_id: String,
    pub target_operator_id: String,
    pub listing_id: String,
    pub activation_ref: FederationArtifactReference,
    pub listing_ref: FederationArtifactReference,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governing_charter_ref: Option<FederationArtifactReference>,
    pub scope: FederationTrustScope,
    pub delegation_control: FederationDelegationControl,
    pub import_control: FederationImportControl,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub type SignedFederationActivationExchange =
    SignedExportEnvelope<FederationActivationExchangeArtifact>;

pub fn validate_federation_activation_exchange(
    exchange: &FederationActivationExchangeArtifact,
) -> Result<(), FederationContractError> {
    if exchange.schema != CHIO_FEDERATION_ACTIVATION_EXCHANGE_SCHEMA {
        return Err(FederationContractError::UnsupportedSchema(
            exchange.schema.clone(),
        ));
    }
    ensure_non_empty(&exchange.exchange_id, "federation_exchange.exchange_id")?;
    ensure_non_empty(
        &exchange.source_operator_id,
        "federation_exchange.source_operator_id",
    )?;
    ensure_non_empty(
        &exchange.target_operator_id,
        "federation_exchange.target_operator_id",
    )?;
    ensure_non_empty(&exchange.listing_id, "federation_exchange.listing_id")?;
    if exchange.source_operator_id == exchange.target_operator_id {
        return Err(FederationContractError::InvalidExchange(
            "source_operator_id and target_operator_id must differ".to_string(),
        ));
    }
    if exchange.expires_at <= exchange.issued_at {
        return Err(FederationContractError::InvalidExchange(
            "expires_at must be greater than issued_at".to_string(),
        ));
    }
    validate_federation_artifact_reference(
        &exchange.activation_ref,
        "federation_exchange.activation_ref",
    )?;
    validate_federation_artifact_reference(
        &exchange.listing_ref,
        "federation_exchange.listing_ref",
    )?;
    if exchange.activation_ref.kind != FederationArtifactKind::TrustActivation {
        return Err(FederationContractError::InvalidExchange(
            "activation_ref must reference a trust activation artifact".to_string(),
        ));
    }
    if exchange.listing_ref.kind != FederationArtifactKind::Listing {
        return Err(FederationContractError::InvalidExchange(
            "listing_ref must reference a listing artifact".to_string(),
        ));
    }
    if let Some(charter_ref) = exchange.governing_charter_ref.as_ref() {
        validate_federation_artifact_reference(
            charter_ref,
            "federation_exchange.governing_charter_ref",
        )?;
        if charter_ref.kind != FederationArtifactKind::GovernanceCharter {
            return Err(FederationContractError::InvalidExchange(
                "governing_charter_ref must reference a governance charter".to_string(),
            ));
        }
    }
    validate_federation_scope(&exchange.scope)?;
    validate_delegation_control(&exchange.delegation_control)?;
    validate_import_control(&exchange.import_control)?;
    if exchange.delegation_control.delegator_operator_id != exchange.source_operator_id {
        return Err(FederationContractError::InvalidExchange(
            "delegation_control.delegator_operator_id must match source_operator_id".to_string(),
        ));
    }
    if exchange.delegation_control.delegate_operator_id != exchange.target_operator_id {
        return Err(FederationContractError::InvalidExchange(
            "delegation_control.delegate_operator_id must match target_operator_id".to_string(),
        ));
    }
    Ok(())
}
