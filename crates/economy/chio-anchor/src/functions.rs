use chio_core::canonical::canonical_json_bytes;
use chio_core::hashing::{sha256, Hash};
use chio_core::merkle::MerkleTree;
use chio_core::receipt::body::ChioReceipt;
use serde::{Deserialize, Serialize};

use crate::AnchorError;

pub const CHIO_FUNCTIONS_ED25519_SOURCE: &str = r#"import * as ed from "https://esm.sh/@noble/ed25519";

const receipts = JSON.parse(args[0]);
for (const item of receipts) {
  const valid = await ed.verifyAsync(
    item.signature,
    item.body,
    item.publicKey,
  );
  if (!valid) {
    return Functions.encodeUint256(0);
  }
}

return Functions.encodeUint256(1);
"#;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FunctionsVerificationPurpose {
    AnchorAuditBatch,
    ReceiptSpotCheck,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FunctionsFallbackStatus {
    Verified,
    Rejected,
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FunctionsVerificationPolicy {
    pub max_batch_receipts: usize,
    pub max_request_size_bytes: usize,
    pub max_callback_gas_limit: u64,
    pub max_return_bytes: usize,
    pub max_notional_value_usd_cents: u64,
    pub allow_direct_fund_release: bool,
    pub require_receipt_event_log: bool,
    pub challenge_window_secs: u64,
}

impl Default for FunctionsVerificationPolicy {
    fn default() -> Self {
        Self {
            max_batch_receipts: 25,
            max_request_size_bytes: 30_000,
            max_callback_gas_limit: 300_000,
            max_return_bytes: 256,
            max_notional_value_usd_cents: 1_000_000,
            allow_direct_fund_release: false,
            require_receipt_event_log: true,
            challenge_window_secs: 3_600,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChainlinkFunctionsTarget {
    pub chain_id: String,
    pub router_address: String,
    pub consumer_address: String,
    pub don_id: String,
    pub subscription_id: u64,
    pub callback_gas_limit: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FunctionsBatchItem {
    pub receipt_id: String,
    pub receipt_body_hex: String,
    pub receipt_body_sha256: Hash,
    pub receipt_leaf_hash: Hash,
    pub signature_hex: String,
    pub public_key_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedFunctionsVerificationRequest {
    pub request_id: String,
    pub target: ChainlinkFunctionsTarget,
    pub purpose: FunctionsVerificationPurpose,
    pub receipt_count: usize,
    pub request_size_bytes: usize,
    pub source_code_sha256: Hash,
    pub receipt_batch_root: Hash,
    pub batch_items: Vec<FunctionsBatchItem>,
    pub request_payload_sha256: Hash,
    pub max_notional_value_usd_cents: u64,
    pub policy: FunctionsVerificationPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FunctionsVerificationResponse {
    pub request_id: String,
    pub target_chain_id: String,
    pub status: FunctionsFallbackStatus,
    pub verified_receipt_count: usize,
    pub returned_bytes: usize,
    pub receipt_batch_root: Hash,
    pub result_payload_sha256: Hash,
    pub executed_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FunctionsFallbackAssessment {
    pub request_id: String,
    pub accepted: bool,
    pub status: FunctionsFallbackStatus,
    pub receipt_batch_root: Hash,
    pub challenge_window_secs: u64,
    pub direct_fund_release_allowed: bool,
    pub receipt_event_log_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<String>,
}

pub fn prepare_functions_batch_verification(
    target: ChainlinkFunctionsTarget,
    purpose: FunctionsVerificationPurpose,
    receipts: &[ChioReceipt],
    max_notional_value_usd_cents: u64,
    policy: FunctionsVerificationPolicy,
    note: Option<String>,
) -> Result<PreparedFunctionsVerificationRequest, AnchorError> {
    if receipts.is_empty() {
        return Err(AnchorError::InvalidInput(
            "functions verification requires at least one receipt".to_string(),
        ));
    }
    if receipts.len() > policy.max_batch_receipts {
        return Err(AnchorError::InvalidInput(format!(
            "functions verification batch {} exceeds maximum {}",
            receipts.len(),
            policy.max_batch_receipts
        )));
    }
    if policy.allow_direct_fund_release {
        return Err(AnchorError::InvalidInput(
            "Functions fallback must not be configured as a direct fund-release gate".to_string(),
        ));
    }
    if target.callback_gas_limit == 0 || target.callback_gas_limit > policy.max_callback_gas_limit {
        return Err(AnchorError::InvalidInput(format!(
            "callback gas limit {} exceeds bounded maximum {}",
            target.callback_gas_limit, policy.max_callback_gas_limit
        )));
    }
    if max_notional_value_usd_cents > policy.max_notional_value_usd_cents {
        return Err(AnchorError::InvalidInput(format!(
            "Functions fallback notional value {} exceeds bounded maximum {}",
            max_notional_value_usd_cents, policy.max_notional_value_usd_cents
        )));
    }

    let mut items = Vec::with_capacity(receipts.len());
    let mut leaf_hashes = Vec::with_capacity(receipts.len());
    let mut request_size_bytes = 0usize;
    for receipt in receipts {
        let verified = receipt
            .verify_signature()
            .map_err(|error| AnchorError::Verification(error.to_string()))?;
        if !verified {
            return Err(AnchorError::Verification(format!(
                "receipt {} signature verification failed before Functions submission",
                receipt.id
            )));
        }

        let body_bytes = canonical_json_bytes(&receipt.body())
            .map_err(|error| AnchorError::Serialization(error.to_string()))?;
        let body_hex = hex::encode(&body_bytes);
        request_size_bytes = request_size_bytes
            .checked_add(body_bytes.len())
            .ok_or_else(|| {
                AnchorError::Serialization("functions request size overflowed".to_string())
            })?;

        let receipt_body_sha256 = sha256(&body_bytes);
        let receipt_leaf_hash = chio_core::merkle::leaf_hash(&body_bytes);
        leaf_hashes.push(receipt_leaf_hash);
        items.push(FunctionsBatchItem {
            receipt_id: receipt.id.clone(),
            receipt_body_hex: body_hex,
            receipt_body_sha256,
            receipt_leaf_hash,
            signature_hex: receipt.signature.to_hex(),
            public_key_hex: receipt.kernel_key.to_hex(),
        });
    }

    let payload_json = serde_json::to_vec(&items)
        .map_err(|error| AnchorError::Serialization(error.to_string()))?;
    if payload_json.len() > policy.max_request_size_bytes
        || request_size_bytes > policy.max_request_size_bytes
    {
        return Err(AnchorError::InvalidInput(format!(
            "functions request size {} exceeds maximum {}",
            payload_json.len().max(request_size_bytes),
            policy.max_request_size_bytes
        )));
    }

    let tree = MerkleTree::from_hashes(leaf_hashes)
        .map_err(|error| AnchorError::Verification(error.to_string()))?;
    let receipt_batch_root = tree.root();
    let source_code_sha256 = sha256(CHIO_FUNCTIONS_ED25519_SOURCE.as_bytes());
    let request_payload_sha256 = sha256(&payload_json);
    let request_id = format!(
        "chio.functions.{}.{}",
        target.chain_id.replace(':', "-"),
        &receipt_batch_root.to_hex()[..16]
    );

    Ok(PreparedFunctionsVerificationRequest {
        request_id,
        target,
        purpose,
        receipt_count: items.len(),
        request_size_bytes: payload_json.len(),
        source_code_sha256,
        receipt_batch_root,
        batch_items: items,
        request_payload_sha256,
        max_notional_value_usd_cents,
        policy,
        note,
    })
}

pub fn assess_functions_verification(
    request: &PreparedFunctionsVerificationRequest,
    response: &FunctionsVerificationResponse,
) -> Result<FunctionsFallbackAssessment, AnchorError> {
    if request.request_id != response.request_id {
        return Err(AnchorError::Verification(format!(
            "Functions response {} does not match request {}",
            response.request_id, request.request_id
        )));
    }
    if request.target.chain_id != response.target_chain_id {
        return Err(AnchorError::Verification(format!(
            "Functions response chain {} does not match request chain {}",
            response.target_chain_id, request.target.chain_id
        )));
    }
    if response.returned_bytes > request.policy.max_return_bytes {
        return Err(AnchorError::Verification(format!(
            "Functions response size {} exceeds maximum {}",
            response.returned_bytes, request.policy.max_return_bytes
        )));
    }
    if response.receipt_batch_root != request.receipt_batch_root {
        return Err(AnchorError::Verification(
            "Functions response batch root does not match prepared request".to_string(),
        ));
    }
    if response.status == FunctionsFallbackStatus::Verified
        && response.verified_receipt_count != request.receipt_count
    {
        return Err(AnchorError::Verification(format!(
            "Functions response verified {} receipts but request expected {}",
            response.verified_receipt_count, request.receipt_count
        )));
    }

    let accepted = matches!(response.status, FunctionsFallbackStatus::Verified);
    let rejection_reason = if accepted {
        None
    } else {
        Some(match response.status {
            FunctionsFallbackStatus::Rejected => {
                "DON result rejected the receipt batch".to_string()
            }
            FunctionsFallbackStatus::Unsupported => {
                "requested verification mode remains outside the bounded Functions surface"
                    .to_string()
            }
            FunctionsFallbackStatus::Verified => {
                unreachable!("accepted == false implies status != Verified")
            }
        })
    };

    Ok(FunctionsFallbackAssessment {
        request_id: request.request_id.clone(),
        accepted,
        status: response.status,
        receipt_batch_root: request.receipt_batch_root,
        challenge_window_secs: request.policy.challenge_window_secs,
        direct_fund_release_allowed: request.policy.allow_direct_fund_release,
        receipt_event_log_required: request.policy.require_receipt_event_log,
        rejection_reason,
    })
}

#[cfg(test)]
mod tests {
    use chio_core::crypto::Keypair;
    use chio_core::hashing::Hash;
    use chio_core::receipt::{
        body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
        metadata::GuardEvidence,
    };

    use super::{
        assess_functions_verification, prepare_functions_batch_verification,
        ChainlinkFunctionsTarget, FunctionsFallbackStatus, FunctionsVerificationPolicy,
        FunctionsVerificationPurpose, FunctionsVerificationResponse,
    };

    use chio_test_support::prelude::*;

    fn sample_receipt(id: &str, timestamp: u64) -> ChioReceipt {
        let keypair = Keypair::generate();
        let body = ChioReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: "cap-web3".to_string(),
            tool_server: "srv-web3".to_string(),
            tool_name: "settle".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({
                "chain_id": "eip155:8453",
                "method": "release"
            }))
            .test_unwrap(),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: chio_core::crypto::sha256_hex(br#"{"released":true}"#),
            policy_hash: "abc123".to_string(),
            evidence: vec![GuardEvidence {
                guard_name: "BudgetGuard".to_string(),
                verdict: true,
                details: Some("bounded".to_string()),
            }],
            metadata: Some(serde_json::json!({
                "financial": { "units": 42, "currency": "USD" }
            })),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        };
        ChioReceipt::sign(body, &keypair).test_unwrap()
    }

    fn sample_target() -> ChainlinkFunctionsTarget {
        ChainlinkFunctionsTarget {
            chain_id: "eip155:8453".to_string(),
            router_address: "0x1000000000000000000000000000000000000001".to_string(),
            consumer_address: "0x1000000000000000000000000000000000000002".to_string(),
            don_id: "fun-base-mainnet".to_string(),
            subscription_id: 42,
            callback_gas_limit: 250_000,
        }
    }

    #[test]
    fn prepares_bounded_functions_batch_request() {
        let receipts = vec![
            sample_receipt("rcpt-001", 1_744_000_000),
            sample_receipt("rcpt-002", 1_744_000_030),
        ];
        let request = prepare_functions_batch_verification(
            sample_target(),
            FunctionsVerificationPurpose::AnchorAuditBatch,
            &receipts,
            50_000,
            FunctionsVerificationPolicy::default(),
            Some("batch anchor audit".to_string()),
        )
        .test_unwrap();

        assert_eq!(request.receipt_count, 2);
        assert!(!request.policy.allow_direct_fund_release);
        assert!(request.request_size_bytes > 0);
        assert!(request
            .request_id
            .starts_with("chio.functions.eip155-8453."));
    }

    #[test]
    fn rejects_unbounded_notional_value() {
        let receipts = vec![sample_receipt("rcpt-001", 1_744_000_000)];
        let error = prepare_functions_batch_verification(
            sample_target(),
            FunctionsVerificationPurpose::AnchorAuditBatch,
            &receipts,
            1_000_001,
            FunctionsVerificationPolicy::default(),
            None,
        )
        .test_unwrap_err();

        assert!(error.to_string().contains("exceeds bounded maximum"));
    }

    #[test]
    fn assesses_verified_response() {
        let receipts = vec![sample_receipt("rcpt-001", 1_744_000_000)];
        let request = prepare_functions_batch_verification(
            sample_target(),
            FunctionsVerificationPurpose::AnchorAuditBatch,
            &receipts,
            1_000,
            FunctionsVerificationPolicy::default(),
            None,
        )
        .test_unwrap();

        let response = FunctionsVerificationResponse {
            request_id: request.request_id.clone(),
            target_chain_id: request.target.chain_id.clone(),
            status: FunctionsFallbackStatus::Verified,
            verified_receipt_count: 1,
            returned_bytes: 32,
            receipt_batch_root: request.receipt_batch_root,
            result_payload_sha256: request.request_payload_sha256,
            executed_at: 1_744_000_120,
            note: Some("OCR consensus: verified".to_string()),
        };
        let assessment = assess_functions_verification(&request, &response).test_unwrap();

        assert!(assessment.accepted);
        assert_eq!(assessment.status, FunctionsFallbackStatus::Verified);
        assert!(!assessment.direct_fund_release_allowed);
        assert!(assessment.receipt_event_log_required);
    }

    #[test]
    fn rejects_mismatched_response_root() {
        let receipts = vec![sample_receipt("rcpt-001", 1_744_000_000)];
        let request = prepare_functions_batch_verification(
            sample_target(),
            FunctionsVerificationPurpose::AnchorAuditBatch,
            &receipts,
            1_000,
            FunctionsVerificationPolicy::default(),
            None,
        )
        .test_unwrap();

        let response = FunctionsVerificationResponse {
            request_id: request.request_id.clone(),
            target_chain_id: request.target.chain_id.clone(),
            status: FunctionsFallbackStatus::Rejected,
            verified_receipt_count: 0,
            returned_bytes: 32,
            receipt_batch_root: Hash::zero(),
            result_payload_sha256: request.request_payload_sha256,
            executed_at: 1_744_000_120,
            note: None,
        };

        let error = assess_functions_verification(&request, &response).test_unwrap_err();
        assert!(error.to_string().contains("batch root does not match"));
    }
}
