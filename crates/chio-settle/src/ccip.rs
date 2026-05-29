use std::collections::HashSet;

use chio_core::hashing::sha256;
use chio_core::web3::Web3SettlementExecutionReceiptArtifact;
use serde::{Deserialize, Serialize};

use crate::SettlementError;

pub const CHIO_CCIP_SETTLEMENT_MESSAGE_SCHEMA: &str = "chio.ccip-settlement-message.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CcipMessageStatus {
    Prepared,
    Reconciled,
    DuplicateSuppressed,
    Delayed,
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CcipLaneConfig {
    pub source_chain_id: String,
    pub destination_chain_id: String,
    pub router_address: String,
    pub max_payload_bytes: usize,
    pub max_execution_gas: u64,
    pub expected_latency_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CcipSettlementPayload {
    pub dispatch_id: String,
    pub execution_receipt_id: String,
    pub settlement_reference: String,
    pub lifecycle_state: String,
    pub settled_amount_units: u64,
    pub settled_amount_currency: String,
    pub beneficiary_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CcipSettlementMessage {
    pub schema: String,
    pub message_id: String,
    pub lane: CcipLaneConfig,
    pub payload: CcipSettlementPayload,
    pub payload_sha256: String,
    pub prepared_at: u64,
    pub expires_at: u64,
    pub min_validity_secs: u64,
    pub status: CcipMessageStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CcipDeliveryObservation {
    pub message_id: String,
    pub destination_chain_id: String,
    pub delivered_at: u64,
    pub payload_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CcipReconciliationOutcome {
    pub message_id: String,
    pub status: CcipMessageStatus,
    pub canonical_receipt_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub fn prepare_ccip_settlement_message(
    lane: CcipLaneConfig,
    receipt: &Web3SettlementExecutionReceiptArtifact,
    prepared_at: u64,
    expires_at: u64,
) -> Result<CcipSettlementMessage, SettlementError> {
    if lane.source_chain_id.trim().is_empty()
        || lane.destination_chain_id.trim().is_empty()
        || lane.router_address.trim().is_empty()
    {
        return Err(SettlementError::InvalidInput(
            "CCIP lane requires source chain, destination chain, and router address".to_string(),
        ));
    }
    if lane.source_chain_id == lane.destination_chain_id {
        return Err(SettlementError::InvalidInput(
            "CCIP transport requires distinct source and destination chains".to_string(),
        ));
    }
    if lane.max_payload_bytes == 0 || lane.max_execution_gas == 0 || lane.expected_latency_secs == 0
    {
        return Err(SettlementError::InvalidInput(
            "CCIP lane limits must be non-zero".to_string(),
        ));
    }
    if expires_at <= prepared_at {
        return Err(SettlementError::InvalidInput(
            "CCIP message expiry must be after preparation".to_string(),
        ));
    }
    let min_validity_secs = lane.expected_latency_secs.saturating_mul(2);
    if expires_at.saturating_sub(prepared_at) < min_validity_secs {
        return Err(SettlementError::InvalidInput(format!(
            "CCIP message validity {} is below required minimum {}",
            expires_at.saturating_sub(prepared_at),
            min_validity_secs
        )));
    }

    let payload = CcipSettlementPayload {
        dispatch_id: receipt.dispatch.dispatch_id.clone(),
        execution_receipt_id: receipt.execution_receipt_id.clone(),
        settlement_reference: receipt.settlement_reference.clone(),
        lifecycle_state: serde_json::to_string(&receipt.lifecycle_state)
            .map_err(|error| SettlementError::Serialization(error.to_string()))?
            .trim_matches('"')
            .to_string(),
        settled_amount_units: receipt.settled_amount.units,
        settled_amount_currency: receipt.settled_amount.currency.clone(),
        beneficiary_address: receipt.dispatch.beneficiary_address.clone(),
    };
    let payload_bytes = serde_json::to_vec(&payload)
        .map_err(|error| SettlementError::Serialization(error.to_string()))?;
    if payload_bytes.len() > lane.max_payload_bytes {
        return Err(SettlementError::InvalidInput(format!(
            "CCIP payload size {} exceeds bounded maximum {}",
            payload_bytes.len(),
            lane.max_payload_bytes
        )));
    }
    let payload_sha256 = sha256(&payload_bytes).to_hex_prefixed();
    let message_id = format!(
        "chio-ccip-{}-{}",
        lane.destination_chain_id.replace(':', "-"),
        &payload_sha256[2..18]
    );

    Ok(CcipSettlementMessage {
        schema: CHIO_CCIP_SETTLEMENT_MESSAGE_SCHEMA.to_string(),
        message_id,
        lane,
        payload,
        payload_sha256,
        prepared_at,
        expires_at,
        min_validity_secs,
        status: CcipMessageStatus::Prepared,
    })
}

pub fn reconcile_ccip_delivery(
    message: &CcipSettlementMessage,
    observation: &CcipDeliveryObservation,
    seen_messages: &mut HashSet<String>,
) -> Result<CcipReconciliationOutcome, SettlementError> {
    if message.message_id != observation.message_id {
        return Err(SettlementError::Verification(format!(
            "CCIP delivery {} does not match prepared message {}",
            observation.message_id, message.message_id
        )));
    }
    if observation.destination_chain_id != message.lane.destination_chain_id {
        return Ok(CcipReconciliationOutcome {
            message_id: message.message_id.clone(),
            status: CcipMessageStatus::Unsupported,
            canonical_receipt_id: message.payload.execution_receipt_id.clone(),
            note: Some("delivery arrived on an unsupported destination chain".to_string()),
        });
    }
    if observation.payload_sha256 != message.payload_sha256 {
        return Ok(CcipReconciliationOutcome {
            message_id: message.message_id.clone(),
            status: CcipMessageStatus::Unsupported,
            canonical_receipt_id: message.payload.execution_receipt_id.clone(),
            note: Some(
                "delivery payload hash does not match the prepared CCIP message".to_string(),
            ),
        });
    }
    if !seen_messages.insert(message.message_id.clone()) {
        return Ok(CcipReconciliationOutcome {
            message_id: message.message_id.clone(),
            status: CcipMessageStatus::DuplicateSuppressed,
            canonical_receipt_id: message.payload.execution_receipt_id.clone(),
            note: Some("duplicate CCIP delivery suppressed fail closed".to_string()),
        });
    }
    if observation.delivered_at > message.expires_at {
        return Ok(CcipReconciliationOutcome {
            message_id: message.message_id.clone(),
            status: CcipMessageStatus::Delayed,
            canonical_receipt_id: message.payload.execution_receipt_id.clone(),
            note: Some("delivery arrived after the bounded validity window".to_string()),
        });
    }
    Ok(CcipReconciliationOutcome {
        message_id: message.message_id.clone(),
        status: CcipMessageStatus::Reconciled,
        canonical_receipt_id: message.payload.execution_receipt_id.clone(),
        note: Some(
            "cross-chain coordination reconciled back to the canonical Chio execution receipt"
                .to_string(),
        ),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use chio_core::web3::Web3SettlementExecutionReceiptArtifact;

    use super::{
        prepare_ccip_settlement_message, reconcile_ccip_delivery, CcipDeliveryObservation,
        CcipLaneConfig, CcipMessageStatus,
    };

    use chio_test_support::prelude::*;

    fn sample_receipt() -> Web3SettlementExecutionReceiptArtifact {
        serde_json::from_str(include_str!(
            "../../../docs/standards/CHIO_WEB3_SETTLEMENT_RECEIPT_EXAMPLE.json"
        ))
        .test_unwrap()
    }

    fn sample_lane() -> CcipLaneConfig {
        CcipLaneConfig {
            source_chain_id: "eip155:8453".to_string(),
            destination_chain_id: "eip155:42161".to_string(),
            router_address: "0x1000000000000000000000000000000000000010".to_string(),
            max_payload_bytes: 30_000,
            max_execution_gas: 3_000_000,
            expected_latency_secs: 900,
        }
    }

    #[test]
    fn prepares_bounded_ccip_message() {
        let message = prepare_ccip_settlement_message(
            sample_lane(),
            &sample_receipt(),
            1_744_000_000,
            1_744_001_900,
        )
        .test_unwrap();

        assert_eq!(message.status, CcipMessageStatus::Prepared);
        assert_eq!(message.min_validity_secs, 1_800);
    }

    #[test]
    fn rejects_under_validity_window() {
        let error = prepare_ccip_settlement_message(
            sample_lane(),
            &sample_receipt(),
            1_744_000_000,
            1_744_000_100,
        )
        .test_unwrap_err();
        assert!(error.to_string().contains("below required minimum"));
    }

    #[test]
    fn reconciles_duplicate_and_delayed_delivery() {
        let message = prepare_ccip_settlement_message(
            sample_lane(),
            &sample_receipt(),
            1_744_000_000,
            1_744_001_900,
        )
        .test_unwrap();
        let mut seen = HashSet::new();

        let first = reconcile_ccip_delivery(
            &message,
            &CcipDeliveryObservation {
                message_id: message.message_id.clone(),
                destination_chain_id: message.lane.destination_chain_id.clone(),
                delivered_at: 1_744_000_600,
                payload_sha256: message.payload_sha256.clone(),
            },
            &mut seen,
        )
        .test_unwrap();
        assert_eq!(first.status, CcipMessageStatus::Reconciled);

        let duplicate = reconcile_ccip_delivery(
            &message,
            &CcipDeliveryObservation {
                message_id: message.message_id.clone(),
                destination_chain_id: message.lane.destination_chain_id.clone(),
                delivered_at: 1_744_000_900,
                payload_sha256: message.payload_sha256.clone(),
            },
            &mut seen,
        )
        .test_unwrap();
        assert_eq!(duplicate.status, CcipMessageStatus::DuplicateSuppressed);

        let delayed_message = prepare_ccip_settlement_message(
            sample_lane(),
            &sample_receipt(),
            1_744_000_000,
            1_744_001_900,
        )
        .test_unwrap();
        let delayed = reconcile_ccip_delivery(
            &delayed_message,
            &CcipDeliveryObservation {
                message_id: delayed_message.message_id.clone(),
                destination_chain_id: delayed_message.lane.destination_chain_id.clone(),
                delivered_at: 1_744_002_000,
                payload_sha256: delayed_message.payload_sha256.clone(),
            },
            &mut HashSet::new(),
        )
        .test_unwrap();
        assert_eq!(delayed.status, CcipMessageStatus::Delayed);
    }
}
