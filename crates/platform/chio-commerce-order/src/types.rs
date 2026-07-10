use serde::{Deserialize, Serialize};

use super::error::CommerceOrderError;
use super::ids::COMMERCE_ORDER_CONTEXT_SCHEMA_ID;
use super::validation::{
    require_non_empty, validate_bundle_relative_path, validate_money, validate_sha256_hex,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommerceCoverageRequirement {
    pub required: bool,
    pub coverage_id: String,
    pub risk_comptroller_report_ref: String,
    pub risk_comptroller_report_sha256: String,
    pub risk_comptroller_report_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommerceTrustMarketRequirement {
    pub required: bool,
    pub provider_discovery_snapshot_ref: String,
    pub provider_selection_report_ref: String,
    pub trust_scorecard_ref: String,
    pub reputation_import_ref: String,
    pub sla_commitment_ref: String,
    pub collateral_position_ref: String,
    pub guarantee_decision_ref: String,
    pub adjudication_jurisdiction_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommerceVerifiedTrustMarketContext {
    pub provider_discovery_snapshot_ref: String,
    pub provider_selection_report_ref: String,
    pub trust_scorecard_ref: String,
    pub reputation_import_ref: String,
    pub sla_commitment_ref: String,
    pub risk_comptroller_report_ref: String,
    pub collateral_position_ref: String,
    pub guarantee_decision_ref: String,
    pub adjudication_jurisdiction_ref: String,
    pub selected_provider_subject: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommerceOrderContext {
    pub schema: String,
    pub id: String,
    pub issued_at: String,
    pub order_id: String,
    pub buyer_subject: String,
    pub agent_subject: String,
    pub merchant_subject: String,
    pub intent_ref: String,
    pub provider_admission_ref: String,
    pub provider_passport_ref: String,
    pub reputation_snapshot_ref: String,
    pub federation_trust_bundle_ref: String,
    pub quote_id: String,
    pub quote_amount_minor: u64,
    pub quote_currency: String,
    pub quote_sha256: String,
    pub settlement_packet_ref: String,
    pub reconciliation_ref: String,
    pub event_log_sha256: String,
    pub event_log_path: String,
    pub payment_lifecycle_sha256: String,
    pub payment_lifecycle_path: String,
    pub mandate_ledger_sha256: String,
    pub mandate_ledger_path: String,
    pub provider_passport_sha256: String,
    pub provider_passport_path: String,
    pub reputation_snapshot_sha256: String,
    pub reputation_snapshot_path: String,
    pub federation_trust_bundle_sha256: String,
    pub federation_trust_bundle_path: String,
    pub settlement_packet_sha256: String,
    pub settlement_packet_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_requirement: Option<CommerceCoverageRequirement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_market_requirement: Option<CommerceTrustMarketRequirement>,
    pub current_state: String,
}

impl CommerceOrderContext {
    pub fn validate_shape(&self) -> Result<(), CommerceOrderError> {
        if self.schema != COMMERCE_ORDER_CONTEXT_SCHEMA_ID {
            return Err(CommerceOrderError::UnsupportedSchema {
                field: "order context",
                schema: self.schema.clone(),
            });
        }
        for (field, value) in [
            ("id", &self.id),
            ("issued_at", &self.issued_at),
            ("order_id", &self.order_id),
            ("buyer_subject", &self.buyer_subject),
            ("agent_subject", &self.agent_subject),
            ("merchant_subject", &self.merchant_subject),
            ("intent_ref", &self.intent_ref),
            ("provider_admission_ref", &self.provider_admission_ref),
            ("provider_passport_ref", &self.provider_passport_ref),
            ("reputation_snapshot_ref", &self.reputation_snapshot_ref),
            (
                "federation_trust_bundle_ref",
                &self.federation_trust_bundle_ref,
            ),
            ("quote_id", &self.quote_id),
            ("quote_currency", &self.quote_currency),
            ("quote_sha256", &self.quote_sha256),
            ("settlement_packet_ref", &self.settlement_packet_ref),
            ("reconciliation_ref", &self.reconciliation_ref),
            ("current_state", &self.current_state),
        ] {
            require_non_empty(value, field).map_err(|message| {
                CommerceOrderError::InvalidArtifact {
                    field: "order context",
                    message,
                }
            })?;
        }
        validate_money(
            self.quote_amount_minor,
            &self.quote_currency,
            "quote amount",
        )
        .map_err(|message| CommerceOrderError::InvalidArtifact {
            field: "order context",
            message,
        })?;
        for (field, digest) in [
            ("event_log_sha256", &self.event_log_sha256),
            ("quote_sha256", &self.quote_sha256),
            ("payment_lifecycle_sha256", &self.payment_lifecycle_sha256),
            ("mandate_ledger_sha256", &self.mandate_ledger_sha256),
            ("provider_passport_sha256", &self.provider_passport_sha256),
            (
                "reputation_snapshot_sha256",
                &self.reputation_snapshot_sha256,
            ),
            (
                "federation_trust_bundle_sha256",
                &self.federation_trust_bundle_sha256,
            ),
            ("settlement_packet_sha256", &self.settlement_packet_sha256),
        ] {
            validate_sha256_hex(digest).map_err(|_| CommerceOrderError::InvalidArtifact {
                field: "order context",
                message: format!("invalid {field}: {digest}"),
            })?;
        }
        for (field, path) in [
            ("event_log_path", &self.event_log_path),
            ("payment_lifecycle_path", &self.payment_lifecycle_path),
            ("mandate_ledger_path", &self.mandate_ledger_path),
            ("provider_passport_path", &self.provider_passport_path),
            ("reputation_snapshot_path", &self.reputation_snapshot_path),
            (
                "federation_trust_bundle_path",
                &self.federation_trust_bundle_path,
            ),
            ("settlement_packet_path", &self.settlement_packet_path),
        ] {
            validate_bundle_relative_path(path).map_err(|_| {
                CommerceOrderError::InvalidArtifact {
                    field: "order context",
                    message: format!("unsafe {field}: {path}"),
                }
            })?;
        }
        if let Some(requirement) = &self.coverage_requirement {
            if requirement.required {
                validate_coverage_requirement_shape(requirement)?;
            }
        }
        if let Some(requirement) = &self.trust_market_requirement {
            if requirement.required {
                validate_trust_market_requirement_shape(requirement)?;
            } else if trust_market_requirement_has_refs(requirement) {
                return Err(CommerceOrderError::InvalidArtifact {
                    field: "order context trust market requirement",
                    message: "trust-market refs cannot disable verifier".to_string(),
                });
            }
        }
        Ok(())
    }
}

fn validate_coverage_requirement_shape(
    requirement: &CommerceCoverageRequirement,
) -> Result<(), CommerceOrderError> {
    for (field, value) in [
        ("coverage_id", &requirement.coverage_id),
        (
            "risk_comptroller_report_ref",
            &requirement.risk_comptroller_report_ref,
        ),
    ] {
        require_non_empty(value, field).map_err(|message| CommerceOrderError::InvalidArtifact {
            field: "order context coverage requirement",
            message,
        })?;
    }
    validate_sha256_hex(&requirement.risk_comptroller_report_sha256).map_err(|_| {
        CommerceOrderError::InvalidArtifact {
            field: "order context coverage requirement",
            message: format!(
                "invalid risk_comptroller_report_sha256: {}",
                requirement.risk_comptroller_report_sha256
            ),
        }
    })?;
    validate_bundle_relative_path(&requirement.risk_comptroller_report_path).map_err(|_| {
        CommerceOrderError::InvalidArtifact {
            field: "order context coverage requirement",
            message: format!(
                "unsafe risk_comptroller_report_path: {}",
                requirement.risk_comptroller_report_path
            ),
        }
    })
}

fn validate_trust_market_requirement_shape(
    requirement: &CommerceTrustMarketRequirement,
) -> Result<(), CommerceOrderError> {
    for (field, value) in [
        (
            "provider_discovery_snapshot_ref",
            &requirement.provider_discovery_snapshot_ref,
        ),
        (
            "provider_selection_report_ref",
            &requirement.provider_selection_report_ref,
        ),
        ("trust_scorecard_ref", &requirement.trust_scorecard_ref),
        ("reputation_import_ref", &requirement.reputation_import_ref),
        ("sla_commitment_ref", &requirement.sla_commitment_ref),
        (
            "collateral_position_ref",
            &requirement.collateral_position_ref,
        ),
        (
            "guarantee_decision_ref",
            &requirement.guarantee_decision_ref,
        ),
        (
            "adjudication_jurisdiction_ref",
            &requirement.adjudication_jurisdiction_ref,
        ),
    ] {
        require_non_empty(value, field).map_err(|message| CommerceOrderError::InvalidArtifact {
            field: "order context trust-market requirement",
            message,
        })?;
    }
    Ok(())
}

fn trust_market_requirement_has_refs(requirement: &CommerceTrustMarketRequirement) -> bool {
    [
        requirement.provider_discovery_snapshot_ref.as_str(),
        requirement.provider_selection_report_ref.as_str(),
        requirement.trust_scorecard_ref.as_str(),
        requirement.reputation_import_ref.as_str(),
        requirement.sla_commitment_ref.as_str(),
        requirement.collateral_position_ref.as_str(),
        requirement.guarantee_decision_ref.as_str(),
        requirement.adjudication_jurisdiction_ref.as_str(),
    ]
    .iter()
    .any(|value| !value.is_empty())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommerceOrderVerificationBundle {
    pub order_context: CommerceOrderContext,
    pub event_log_bytes: Vec<u8>,
    pub event_authority_receipts: Vec<CommerceEventAuthorityReceiptArtifact>,
    pub payment_lifecycle_bytes: Vec<u8>,
    pub mandate_ledger_bytes: Vec<u8>,
    pub provider_passport_bytes: Vec<u8>,
    pub reputation_snapshot_bytes: Vec<u8>,
    pub federation_trust_bundle_bytes: Vec<u8>,
    pub settlement_packet_bytes: Vec<u8>,
    pub mandate_protocol_payloads: Vec<CommerceMandateProtocolPayload>,
    pub risk_comptroller_report_bytes: Option<Vec<u8>>,
    pub verified_trust_market_context: Option<CommerceVerifiedTrustMarketContext>,
    pub trusted_event_authority_receipt_kernel_keys: Vec<chio_core_types::crypto::PublicKey>,
    pub trusted_payment_signer_keys: Vec<chio_core_types::crypto::PublicKey>,
    pub trusted_provider_trust_signer_keys: Vec<chio_core_types::crypto::PublicKey>,
    pub trusted_risk_comptroller_signer_keys: Vec<chio_core_types::crypto::PublicKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommerceEventAuthorityReceiptArtifact {
    pub receipt_ref: String,
    pub receipt_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommerceMandateProtocolPayload {
    pub protocol: String,
    pub purpose: String,
    pub payload_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommerceOrderPassportReport {
    pub schema: String,
    pub id: String,
    pub issued_at: String,
    pub verdict: String,
    pub order_id: String,
    pub current_state: String,
    pub artifact_digests: CommerceOrderPassportArtifactDigests,
    pub selective_disclosure_policy: CommerceOrderDisclosurePolicy,
    pub verified_claims: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommerceOrderPassportArtifactDigests {
    pub order_context_sha256: String,
    pub event_log_sha256: String,
    pub payment_lifecycle_sha256: String,
    pub mandate_ledger_sha256: String,
    pub provider_passport_sha256: String,
    pub reputation_snapshot_sha256: String,
    pub federation_trust_bundle_sha256: String,
    pub settlement_packet_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_comptroller_report_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommerceOrderDisclosurePolicy {
    pub policy_id: String,
    pub disclosed_fields: Vec<String>,
    pub redacted_fields: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct CommercePaymentLifecycle {
    pub(super) schema: String,
    pub(super) id: String,
    pub(super) issued_at: String,
    pub(super) issuer: Option<String>,
    pub(super) order_id: String,
    pub(super) merchant_subject: String,
    pub(super) psp: String,
    pub(super) payment_intent_id: String,
    pub(super) authorization_ref: Option<String>,
    pub(super) capture_ref: Option<String>,
    pub(super) charge_ref: Option<String>,
    pub(super) balance_transaction_ref: Option<String>,
    pub(super) amount_minor: u64,
    pub(super) currency: String,
    pub(super) quote_sha256: String,
    pub(super) payment_status: String,
    pub(super) capture_mode: String,
    pub(super) capture_before: String,
    pub(super) captured_at: String,
    pub(super) transfer_group: String,
    pub(super) fraud_outcome: String,
    pub(super) dispute_status: String,
    pub(super) refund_status: String,
    pub(super) chargeback_status: String,
    pub(super) transfer_reversal_status: String,
    pub(super) signature: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct CommerceSettlementPacket {
    pub(super) schema: String,
    pub(super) id: String,
    pub(super) issued_at: String,
    pub(super) order_id: String,
    pub(super) merchant_subject: String,
    pub(super) psp: String,
    pub(super) payment_intent_id: String,
    pub(super) amount_minor: u64,
    pub(super) currency: String,
    pub(super) quote_sha256: String,
    pub(super) settlement_rail: String,
    pub(super) settlement_account_ref: String,
    pub(super) dispatch_receipt_ref: String,
    pub(super) reconciliation_ref: String,
    pub(super) status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct CommerceProviderPassport {
    pub(super) schema: String,
    pub(super) id: String,
    pub(super) issued_at: String,
    pub(super) provider_subject: String,
    pub(super) status: String,
    pub(super) service_families: Vec<String>,
    pub(super) signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct CommerceReputationSnapshot {
    pub(super) schema: String,
    pub(super) id: String,
    pub(super) issued_at: String,
    pub(super) provider_subject: String,
    pub(super) status: String,
    pub(super) score_bps: u16,
    pub(super) signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct CommerceFederationTrustBundle {
    pub(super) schema: String,
    pub(super) id: String,
    pub(super) issued_at: String,
    pub(super) provider_subject: String,
    pub(super) trust_domain: String,
    pub(super) status: String,
    pub(super) trust_root_ref: String,
    pub(super) signature: String,
}
