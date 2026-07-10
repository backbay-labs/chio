use chio_core::web3::anchors::{AnchorInclusionProof, OracleConversionEvidence};
use chio_core::web3::settlement::{
    validate_web3_settlement_execution_receipt, Web3SettlementDispatchArtifact,
    Web3SettlementExecutionReceiptArtifact, Web3SettlementIdentityRegistryEvidence,
    Web3SettlementIdentityRegistryEvidenceBinding, Web3SettlementLifecycleState,
    CHIO_WEB3_SETTLEMENT_RECEIPT_SCHEMA,
};
use chio_egress_contract::{client_builder_with_contract, send_with_contract};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::evm::{
    confirm_transaction, read_bond_snapshot, read_escrow_snapshot,
    scale_token_minor_units_to_chio_amount, EscrowSnapshot, EvmBondSnapshot, EvmTransactionReceipt,
};
use crate::{SettlementChainConfig, SettlementError};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EscrowLifecycleStatus {
    Locked,
    PartiallyReleased,
    Released,
    Refunded,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BondLifecycleStatus {
    Active,
    Released,
    Impaired,
    Expired,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SettlementFinalityStatus {
    AwaitingConfirmations,
    AwaitingDisputeWindow,
    Finalized,
    Reorged,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SettlementRecoveryAction {
    WaitForConfirmations,
    WaitForDisputeWindow,
    RetrySubmission,
    ResubmitAfterReorg,
    ExecuteRefund,
    ManualReview,
    ExpireBond,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SettlementFinalityAssessment {
    pub chain_id: String,
    pub required_confirmations: u32,
    pub current_confirmations: u32,
    pub dispute_window_secs: u64,
    pub dispute_window_closes_at: u64,
    pub status: SettlementFinalityStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EscrowExecutionProjection {
    pub receipt: Web3SettlementExecutionReceiptArtifact,
    pub finality: SettlementFinalityAssessment,
    pub escrow_snapshot: EscrowSnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_action: Option<SettlementRecoveryAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BondLifecycleObservation {
    pub chain_id: String,
    pub vault_id: String,
    pub snapshot: EvmBondSnapshot,
    pub status: BondLifecycleStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_action: Option<SettlementRecoveryAction>,
}

#[derive(Debug, Clone)]
pub struct ExecutionProjectionInput<'a> {
    pub dispatch: &'a Web3SettlementDispatchArtifact,
    pub tx_hash: &'a str,
    pub execution_receipt_id: String,
    pub settlement_reference: String,
    pub observed_at: Option<u64>,
    pub observed_amount: chio_core::capability::scope::MonetaryAmount,
    pub anchor_proof: Option<&'a AnchorInclusionProof>,
    pub identity_registry_evidence: Option<Web3SettlementIdentityRegistryEvidence>,
    pub identity_registry_evidence_binding: Option<Web3SettlementIdentityRegistryEvidenceBinding>,
    pub oracle_evidence: Option<&'a OracleConversionEvidence>,
    pub failure_reason: Option<String>,
    pub reversal_of: Option<String>,
    pub note: Option<String>,
}

pub async fn inspect_finality(
    config: &SettlementChainConfig,
    tx_hash: &str,
    amount_units: u64,
    now_override: Option<u64>,
) -> Result<(EvmTransactionReceipt, SettlementFinalityAssessment), SettlementError> {
    let receipt = confirm_transaction(config, tx_hash).await?;
    let assessment =
        inspect_finality_for_receipt(config, &receipt, amount_units, now_override).await?;
    Ok((receipt, assessment))
}

pub async fn inspect_finality_for_receipt(
    config: &SettlementChainConfig,
    receipt: &EvmTransactionReceipt,
    amount_units: u64,
    now_override: Option<u64>,
) -> Result<SettlementFinalityAssessment, SettlementError> {
    let latest_block_number = latest_block_number(config).await?;
    let current_confirmations = latest_block_number
        .saturating_sub(receipt.block_number)
        .saturating_add(1) as u32;
    let current_hash = block_hash_at_number_optional(config, receipt.block_number).await?;
    let tier = config.policy.tier_for_amount(amount_units);
    let dispute_window_closes_at = receipt.observed_at.saturating_add(tier.dispute_window_secs);
    let status = if current_hash.as_deref() != Some(receipt.block_hash.as_str()) {
        SettlementFinalityStatus::Reorged
    } else if current_confirmations < tier.min_confirmations {
        SettlementFinalityStatus::AwaitingConfirmations
    } else if now_override
        .unwrap_or(receipt.observed_at)
        .lt(&dispute_window_closes_at)
    {
        SettlementFinalityStatus::AwaitingDisputeWindow
    } else {
        SettlementFinalityStatus::Finalized
    };
    Ok(SettlementFinalityAssessment {
        chain_id: config.chain_id.clone(),
        required_confirmations: tier.min_confirmations,
        current_confirmations,
        dispute_window_secs: tier.dispute_window_secs,
        dispute_window_closes_at,
        status,
    })
}

pub async fn project_escrow_execution_receipt(
    config: &SettlementChainConfig,
    input: ExecutionProjectionInput<'_>,
) -> Result<EscrowExecutionProjection, SettlementError> {
    let escrow_snapshot = read_escrow_snapshot(config, &input.dispatch.escrow_id).await?;
    let (_, finality) = inspect_finality(
        config,
        input.tx_hash,
        input.dispatch.settlement_amount.units,
        input.observed_at,
    )
    .await?;

    let lifecycle_state = lifecycle_state_for_projection(finality.status, &escrow_snapshot);

    let failure_reason = match lifecycle_state {
        Web3SettlementLifecycleState::TimedOut => Some(
            input
                .failure_reason
                .clone()
                .unwrap_or_else(|| "escrow refunded after deadline".to_string()),
        ),
        Web3SettlementLifecycleState::Failed => {
            Some(input.failure_reason.clone().unwrap_or_else(|| {
                "settlement submission failed before a durable on-chain release".to_string()
            }))
        }
        Web3SettlementLifecycleState::Reorged => {
            Some(input.failure_reason.clone().unwrap_or_else(|| {
                "transaction receipt disappeared from the canonical chain".to_string()
            }))
        }
        _ => input.failure_reason.clone(),
    };

    let settled_amount = if lifecycle_state == Web3SettlementLifecycleState::TimedOut {
        scale_token_minor_units_to_chio_amount(
            escrow_snapshot.remaining_minor_units,
            &input.dispatch.settlement_amount.currency,
            config,
        )?
    } else if lifecycle_state == Web3SettlementLifecycleState::EscrowLocked {
        chio_core::capability::scope::MonetaryAmount {
            units: 0,
            currency: input.dispatch.settlement_amount.currency.clone(),
        }
    } else {
        input.observed_amount.clone()
    };

    let observed_execution = chio_core::credit::CapitalExecutionObservation {
        observed_at: input.observed_at.unwrap_or_else(|| {
            finality
                .dispute_window_closes_at
                .saturating_sub(finality.dispute_window_secs)
        }),
        external_reference_id: input.tx_hash.to_string(),
        amount: settled_amount.clone(),
    };

    let receipt = Web3SettlementExecutionReceiptArtifact {
        schema: CHIO_WEB3_SETTLEMENT_RECEIPT_SCHEMA.to_string(),
        execution_receipt_id: input.execution_receipt_id,
        issued_at: observed_execution.observed_at,
        dispatch: input.dispatch.clone(),
        observed_execution,
        lifecycle_state,
        settlement_reference: input.settlement_reference,
        reconciled_anchor_proof: input.anchor_proof.cloned(),
        identity_registry_evidence: input.identity_registry_evidence,
        identity_registry_evidence_binding: input.identity_registry_evidence_binding,
        oracle_evidence: input.oracle_evidence.cloned(),
        settled_amount,
        reversal_of: input.reversal_of.clone(),
        failure_reason,
        note: input.note.clone(),
    };
    validate_web3_settlement_execution_receipt(&receipt)
        .map_err(|error| SettlementError::Verification(error.to_string()))?;

    let recovery_action = recovery_action_for_projection(finality.status, lifecycle_state);

    Ok(EscrowExecutionProjection {
        receipt,
        finality,
        escrow_snapshot,
        recovery_action,
    })
}

pub async fn observe_bond(
    config: &SettlementChainConfig,
    vault_id: &str,
) -> Result<BondLifecycleObservation, SettlementError> {
    let snapshot = read_bond_snapshot(config, vault_id).await?;
    let time_expired = snapshot.observed_at > snapshot.expires_at;
    let status = if snapshot.expired || time_expired {
        BondLifecycleStatus::Expired
    } else if snapshot.released {
        BondLifecycleStatus::Released
    } else if snapshot.slashed_minor_units > 0 {
        BondLifecycleStatus::Impaired
    } else {
        BondLifecycleStatus::Active
    };
    let recovery_action = if time_expired && !snapshot.expired {
        Some(SettlementRecoveryAction::ExpireBond)
    } else if matches!(
        status,
        BondLifecycleStatus::Active | BondLifecycleStatus::Expired
    ) {
        None
    } else {
        Some(SettlementRecoveryAction::ManualReview)
    };
    Ok(BondLifecycleObservation {
        chain_id: config.chain_id.clone(),
        vault_id: vault_id.to_string(),
        snapshot,
        status,
        recovery_action,
    })
}

async fn latest_block_number(config: &SettlementChainConfig) -> Result<u64, SettlementError> {
    let result =
        settlement_rpc_call(config, "eth_getBlockByNumber", json!(["latest", false])).await?;
    parse_hex_u64(
        result
            .get("number")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| SettlementError::Rpc("latest block missing number".to_string()))?,
    )
}

async fn block_hash_at_number_optional(
    config: &SettlementChainConfig,
    block_number: u64,
) -> Result<Option<String>, SettlementError> {
    let result = settlement_rpc_call(
        config,
        "eth_getBlockByNumber",
        json!([format!("0x{block_number:x}"), false]),
    )
    .await?;
    if result.is_null() {
        return Ok(None);
    }
    Ok(result
        .get("hash")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string))
}

#[derive(Debug, Deserialize)]
struct JsonRpcEnvelope {
    #[serde(rename = "jsonrpc")]
    _jsonrpc: String,
    #[serde(rename = "id")]
    _id: u64,
    #[serde(default)]
    result: Value,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

async fn settlement_rpc_call(
    config: &SettlementChainConfig,
    method: &str,
    params: Value,
) -> Result<Value, SettlementError> {
    config.validate_rpc_egress_contract()?;
    let contract = &config.egress_contract;
    let client = client_builder_with_contract(contract)
        .build()
        .map_err(|error| SettlementError::Rpc(format!("reqwest build: {error}")))?;
    let request = client
        .post(&config.rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1u64,
            "method": method,
            "params": params,
        }))
        .build()
        .map_err(|error| SettlementError::Rpc(format!("reqwest build request: {error}")))?;
    let response = send_with_contract(contract, &client, request)
        .await
        .map_err(|error| {
            SettlementError::Rpc(format!(
                "HttpEgressContract rejects settlement observer RPC dispatch: {error}"
            ))
        })?;
    let envelope: JsonRpcEnvelope = response
        .json()
        .await
        .map_err(|error| SettlementError::Rpc(error.to_string()))?;
    if let Some(error) = envelope.error {
        return Err(SettlementError::Rpc(format!(
            "{} (code {})",
            error.message, error.code
        )));
    }
    Ok(envelope.result)
}

fn parse_hex_u64(value: &str) -> Result<u64, SettlementError> {
    u64::from_str_radix(value.trim_start_matches("0x"), 16)
        .map_err(|error| SettlementError::Rpc(error.to_string()))
}

fn recovery_action_for_projection(
    finality_status: SettlementFinalityStatus,
    lifecycle_state: Web3SettlementLifecycleState,
) -> Option<SettlementRecoveryAction> {
    match finality_status {
        SettlementFinalityStatus::AwaitingConfirmations => {
            Some(SettlementRecoveryAction::WaitForConfirmations)
        }
        SettlementFinalityStatus::AwaitingDisputeWindow => {
            Some(SettlementRecoveryAction::WaitForDisputeWindow)
        }
        SettlementFinalityStatus::Reorged => Some(SettlementRecoveryAction::ResubmitAfterReorg),
        SettlementFinalityStatus::Finalized => match lifecycle_state {
            Web3SettlementLifecycleState::Failed => Some(SettlementRecoveryAction::RetrySubmission),
            Web3SettlementLifecycleState::TimedOut => Some(SettlementRecoveryAction::ExecuteRefund),
            _ => None,
        },
    }
}

fn lifecycle_state_for_projection(
    finality_status: SettlementFinalityStatus,
    escrow_snapshot: &EscrowSnapshot,
) -> Web3SettlementLifecycleState {
    if finality_status == SettlementFinalityStatus::Reorged {
        return Web3SettlementLifecycleState::Reorged;
    }
    if finality_status != SettlementFinalityStatus::Finalized {
        return Web3SettlementLifecycleState::EscrowLocked;
    }
    if escrow_snapshot.refunded {
        return Web3SettlementLifecycleState::TimedOut;
    }
    if escrow_snapshot.released_minor_units == 0 {
        Web3SettlementLifecycleState::Failed
    } else if escrow_snapshot.released_minor_units < escrow_snapshot.deposited_minor_units {
        Web3SettlementLifecycleState::PartiallySettled
    } else {
        Web3SettlementLifecycleState::Settled
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use alloy_primitives::{Address, B256, U256};
    use alloy_sol_types::SolCall;
    use chio_core::web3::settlement::{
        Web3SettlementDispatchArtifact, Web3SettlementLifecycleState,
    };
    use chio_core::web3::trust_profile::{Web3FinalityMode, Web3SettlementPath};
    use chio_web3_bindings::{IChioBondVault, IChioEscrow};
    use serde_json::{json, Value};

    use super::*;

    use chio_test_support::prelude::*;

    struct MockJsonRpcServer {
        base_url: String,
        requests: Arc<Mutex<Vec<Value>>>,
        handle: thread::JoinHandle<()>,
    }

    struct MockRawHttpServer {
        base_url: String,
        handle: thread::JoinHandle<()>,
    }

    impl MockJsonRpcServer {
        fn spawn(envelopes: Vec<Value>) -> Self {
            let listener =
                TcpListener::bind("127.0.0.1:0").test_expect("bind mock JSON-RPC listener");
            let address = listener.local_addr().test_expect("listener address");
            let base_url = format!("http://127.0.0.1:{}", address.port());
            let requests = Arc::new(Mutex::new(Vec::new()));
            let requests_for_thread = Arc::clone(&requests);

            let handle = thread::spawn(move || {
                for envelope in envelopes {
                    let (mut stream, _) = listener.accept().test_expect("accept mock request");
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .test_expect("set read timeout");
                    let request = read_http_request(&mut stream);
                    requests_for_thread
                        .lock()
                        .test_expect("lock request log")
                        .push(parse_json_request(&request));
                    write_http_json_response(&mut stream, 200, &envelope);
                    stream.flush().test_expect("flush mock response");
                }
            });

            Self {
                base_url,
                requests,
                handle,
            }
        }

        fn base_url(&self) -> &str {
            &self.base_url
        }

        fn requests(&self) -> Vec<Value> {
            self.requests.lock().test_expect("lock request log").clone()
        }

        fn join(self) {
            self.handle.join().test_expect("join mock JSON-RPC server");
        }
    }

    impl MockRawHttpServer {
        fn spawn(response: String) -> Self {
            let listener =
                TcpListener::bind("127.0.0.1:0").test_expect("bind mock raw HTTP listener");
            let address = listener.local_addr().test_expect("listener address");
            let base_url = format!("http://127.0.0.1:{}", address.port());

            let handle = thread::spawn(move || {
                let (mut stream, _) = listener.accept().test_expect("accept mock request");
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .test_expect("set read timeout");
                let _request = read_http_request(&mut stream);
                stream
                    .write_all(response.as_bytes())
                    .test_expect("write mock response");
                stream.flush().test_expect("flush mock response");
            });

            Self { base_url, handle }
        }

        fn base_url(&self) -> &str {
            &self.base_url
        }

        fn join(self) {
            self.handle.join().test_expect("join mock raw server");
        }
    }

    fn sample_config(rpc_url: &str) -> SettlementChainConfig {
        SettlementChainConfig {
            chain_id: "eip155:31337".to_string(),
            network_name: "Ganache".to_string(),
            rpc_url: rpc_url.to_string(),
            egress_contract: crate::settlement_devnet_rpc_egress_contract(rpc_url)
                .test_expect("devnet egress contract"),
            escrow_contract: "0x69011eD3D9792Ea93595EeBd919EE621764B19e0".to_string(),
            bond_vault_contract: "0x621c302d6EC93b7186bEF18dF5D6436C6ea30125".to_string(),
            identity_registry_contract: "0x0eAFb60DD4F4b3863eb5490752238aC37A625dc6".to_string(),
            root_registry_contract: "0x3a167ACFC3348a8f8df11BF383aF3cA86a8A2B42".to_string(),
            operator_address: "0x8d6d63c22D114C18C2a0dA6Db0A8972Ed9C40343".to_string(),
            settlement_token_symbol: "mUSDC".to_string(),
            settlement_token_address: "0x735F1Ba389D9D350501dB8FBbB5b52477DcaddA8".to_string(),
            oracle: crate::SettlementOracleConfig::default(),
            evidence_substrate: crate::SettlementEvidenceConfig::default(),
            policy: crate::SettlementPolicyConfig {
                chio_minor_unit_decimals: 2,
                token_minor_unit_decimals: 6,
                tiers: vec![
                    crate::SettlementAmountTier {
                        upper_bound_units: 1_000,
                        dispute_window_secs: 0,
                        min_confirmations: 1,
                        finality_mode: Web3FinalityMode::OptimisticL2,
                    },
                    crate::SettlementAmountTier {
                        upper_bound_units: 100_000,
                        dispute_window_secs: 3_600,
                        min_confirmations: 1,
                        finality_mode: Web3FinalityMode::OptimisticL2,
                    },
                    crate::SettlementAmountTier {
                        upper_bound_units: 1_000_000,
                        dispute_window_secs: 14_400,
                        min_confirmations: 12,
                        finality_mode: Web3FinalityMode::L1Finalized,
                    },
                    crate::SettlementAmountTier {
                        upper_bound_units: u64::MAX,
                        dispute_window_secs: 86_400,
                        min_confirmations: 64,
                        finality_mode: Web3FinalityMode::L1Finalized,
                    },
                ],
            },
        }
    }

    fn hostname_rpc_contract(authority: &str) -> chio_egress_contract::HttpEgressContract {
        chio_egress_contract::HttpEgressContract {
            tenant_egress_namespace: "chio-settle-observer-unit-rpc".to_string(),
            allowed_schemes: std::collections::BTreeSet::from(["https".to_string()]),
            allowed_authority_set: std::collections::BTreeSet::from([authority.to_string()]),
            deny_loopback: true,
            deny_link_local: true,
            deny_ipv6_ula: true,
            max_redirect_chain: 0,
            max_response_bytes: 64 * 1024 * 1024,
        }
    }

    fn sample_receipt(
        block_number: u64,
        block_hash: &str,
        observed_at: u64,
    ) -> EvmTransactionReceipt {
        EvmTransactionReceipt {
            tx_hash: "0xabc".to_string(),
            block_number,
            block_hash: block_hash.to_string(),
            status: true,
            from_address: "0x1000000000000000000000000000000000000001".to_string(),
            to_address: "0x1000000000000000000000000000000000000002".to_string(),
            gas_used: 21_000,
            observed_at,
            logs: Vec::new(),
        }
    }

    fn sample_dispatch() -> Web3SettlementDispatchArtifact {
        let mut dispatch: Web3SettlementDispatchArtifact = serde_json::from_str(include_str!(
            "../../../../docs/standards/CHIO_WEB3_SETTLEMENT_DISPATCH_EXAMPLE.json"
        ))
        .test_expect("dispatch example should parse");
        dispatch.escrow_id =
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        dispatch.settlement_path = Web3SettlementPath::DualSignature;
        dispatch.support_boundary.anchor_proof_required = false;
        dispatch.support_boundary.oracle_evidence_required_for_fx = false;
        dispatch
    }

    fn sample_identity_registry_evidence(
        dispatch: &Web3SettlementDispatchArtifact,
        config: &SettlementChainConfig,
    ) -> Web3SettlementIdentityRegistryEvidence {
        Web3SettlementIdentityRegistryEvidence {
            chain_id: dispatch.chain_id.clone(),
            identity_registry_contract: config.identity_registry_contract.clone(),
            operator_address: config.operator_address.clone(),
            block_number: 120,
            block_hash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_string(),
            observed_at: 1_743_292_850,
            operator_key_hash: dispatch.operator_key_hash.clone(),
            settlement_key: dispatch.beneficiary_address.clone(),
            registered_at: 1_743_292_700,
            operator_epoch: 1,
            active: true,
        }
    }

    fn sample_identity_registry_evidence_binding(
        dispatch: &Web3SettlementDispatchArtifact,
        config: &SettlementChainConfig,
    ) -> Web3SettlementIdentityRegistryEvidenceBinding {
        Web3SettlementIdentityRegistryEvidenceBinding {
            identity_registry_contract: config.identity_registry_contract.clone(),
            operator_address: config.operator_address.clone(),
            settlement_key: dispatch.beneficiary_address.clone(),
        }
    }

    fn escrow_result(released_minor_units: u64) -> Value {
        rpc_result(json!(encode_hex(
            IChioEscrow::getEscrowCall::abi_encode_returns(&IChioEscrow::getEscrowReturn {
                terms: IChioEscrow::EscrowTerms {
                    capabilityId: B256::from([0x99; 32]),
                    depositor: Address::from_str("0x1000000000000000000000000000000000000001",)
                        .test_unwrap(),
                    beneficiary: Address::from_str("0x1000000000000000000000000000000000000002",)
                        .test_unwrap(),
                    token: Address::from_str("0x1000000000000000000000000000000000000003",)
                        .test_unwrap(),
                    maxAmount: U256::from(1_500_000_u64),
                    deadline: U256::from(1_700_050_000_u64),
                    operator: Address::from_str("0x1000000000000000000000000000000000000004",)
                        .test_unwrap(),
                    operatorKeyHash: B256::from([0xaa; 32]),
                },
                deposited: U256::from(1_500_000_u64),
                released: U256::from(released_minor_units),
                refunded: false,
            })
        )))
    }

    fn rpc_result(result: Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": result,
        })
    }

    fn rpc_error(code: i64, message: &str) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": code,
                "message": message,
            }
        })
    }

    fn encode_hex(data: Vec<u8>) -> String {
        format!("0x{}", hex::encode(data))
    }

    fn read_http_request<R: Read>(stream: &mut R) -> String {
        let mut request = Vec::new();
        let mut chunk = [0_u8; 1024];
        let mut header_end = None;
        let mut content_length = 0_usize;

        loop {
            let read = stream.read(&mut chunk).test_expect("read request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            if header_end.is_none() {
                header_end = find_header_end(&request);
                if let Some(end) = header_end {
                    content_length = parse_content_length(&request[..end]);
                }
            }
            if let Some(end) = header_end {
                if request.len() >= end + content_length {
                    break;
                }
            }
        }

        String::from_utf8(request).test_expect("request should be valid UTF-8")
    }

    fn find_header_end(request: &[u8]) -> Option<usize> {
        request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
    }

    fn parse_content_length(headers: &[u8]) -> usize {
        String::from_utf8_lossy(headers)
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0)
    }

    fn parse_json_request(request: &str) -> Value {
        let body = request
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .unwrap_or_default();
        serde_json::from_str(body).test_expect("request body should be JSON")
    }

    fn write_http_json_response<W: Write>(stream: &mut W, status: u16, body: &Value) {
        let body_text = body.to_string();
        let response = format!(
            "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            http_status_text(status),
            body_text.len(),
            body_text
        );
        stream
            .write_all(response.as_bytes())
            .test_expect("write mock response");
    }

    fn http_status_text(status: u16) -> &'static str {
        match status {
            200 => "OK",
            500 => "Internal Server Error",
            _ => "Unknown",
        }
    }

    #[test]
    fn parse_hex_u64_accepts_and_rejects_expected_values() {
        assert_eq!(parse_hex_u64("0x2a").test_expect("hex should parse"), 42);
        let error = parse_hex_u64("nope").test_expect_err("bad hex should fail");
        assert!(matches!(error, SettlementError::Rpc(_)));
    }

    #[test]
    fn recovery_action_mapping_covers_terminal_states() {
        assert_eq!(
            recovery_action_for_projection(
                SettlementFinalityStatus::AwaitingConfirmations,
                Web3SettlementLifecycleState::Settled,
            ),
            Some(SettlementRecoveryAction::WaitForConfirmations)
        );
        assert_eq!(
            recovery_action_for_projection(
                SettlementFinalityStatus::AwaitingDisputeWindow,
                Web3SettlementLifecycleState::Settled,
            ),
            Some(SettlementRecoveryAction::WaitForDisputeWindow)
        );
        assert_eq!(
            recovery_action_for_projection(
                SettlementFinalityStatus::Reorged,
                Web3SettlementLifecycleState::Settled,
            ),
            Some(SettlementRecoveryAction::ResubmitAfterReorg)
        );
        assert_eq!(
            recovery_action_for_projection(
                SettlementFinalityStatus::Finalized,
                Web3SettlementLifecycleState::Failed,
            ),
            Some(SettlementRecoveryAction::RetrySubmission)
        );
        assert_eq!(
            recovery_action_for_projection(
                SettlementFinalityStatus::Finalized,
                Web3SettlementLifecycleState::TimedOut,
            ),
            Some(SettlementRecoveryAction::ExecuteRefund)
        );
        assert_eq!(
            recovery_action_for_projection(
                SettlementFinalityStatus::Finalized,
                Web3SettlementLifecycleState::Settled,
            ),
            None
        );
    }

    #[tokio::test]
    async fn inspect_finality_for_receipt_awaits_confirmations() {
        let server = MockJsonRpcServer::spawn(vec![
            rpc_result(json!({ "number": "0x69" })),
            rpc_result(json!({ "hash": "0xaaa" })),
        ]);
        let config = sample_config(server.base_url());
        let receipt = sample_receipt(100, "0xaaa", 1_700_000_000);

        let assessment = inspect_finality_for_receipt(&config, &receipt, 500_000, None)
            .await
            .test_expect("assessment should succeed");

        let requests = server.requests();
        server.join();

        assert_eq!(
            assessment.status,
            SettlementFinalityStatus::AwaitingConfirmations
        );
        assert_eq!(assessment.required_confirmations, 12);
        assert_eq!(assessment.current_confirmations, 6);
        assert_eq!(assessment.dispute_window_secs, 14_400);
        assert_eq!(requests[0]["method"], "eth_getBlockByNumber");
        assert_eq!(requests[1]["method"], "eth_getBlockByNumber");
    }

    #[tokio::test]
    async fn inspect_finality_for_receipt_awaits_dispute_window() {
        let server = MockJsonRpcServer::spawn(vec![
            rpc_result(json!({ "number": "0x78" })),
            rpc_result(json!({ "hash": "0xaaa" })),
        ]);
        let config = sample_config(server.base_url());
        let receipt = sample_receipt(100, "0xaaa", 1_700_000_000);

        let assessment =
            inspect_finality_for_receipt(&config, &receipt, 500_000, Some(1_700_010_000))
                .await
                .test_expect("assessment should succeed");

        server.join();

        assert_eq!(
            assessment.status,
            SettlementFinalityStatus::AwaitingDisputeWindow
        );
        assert_eq!(assessment.current_confirmations, 21);
        assert_eq!(assessment.dispute_window_closes_at, 1_700_014_400);
    }

    #[tokio::test]
    async fn inspect_finality_for_receipt_finalizes_after_dispute_window() {
        let server = MockJsonRpcServer::spawn(vec![
            rpc_result(json!({ "number": "0x78" })),
            rpc_result(json!({ "hash": "0xaaa" })),
        ]);
        let mut config = sample_config(server.base_url());
        config.policy.tiers[0].dispute_window_secs = 3_600;
        let receipt = sample_receipt(100, "0xaaa", 1_700_000_000);

        let assessment =
            inspect_finality_for_receipt(&config, &receipt, 500_000, Some(1_700_020_000))
                .await
                .test_expect("assessment should succeed");

        server.join();

        assert_eq!(assessment.status, SettlementFinalityStatus::Finalized);
    }

    #[tokio::test]
    async fn inspect_finality_for_receipt_marks_reorgs_for_hash_mismatch_or_missing_block() {
        let mismatch_server = MockJsonRpcServer::spawn(vec![
            rpc_result(json!({ "number": "0x78" })),
            rpc_result(json!({ "hash": "0xbbb" })),
        ]);
        let mismatch_config = sample_config(mismatch_server.base_url());
        let receipt = sample_receipt(100, "0xaaa", 1_700_000_000);

        let mismatch =
            inspect_finality_for_receipt(&mismatch_config, &receipt, 500_000, Some(1_700_020_000))
                .await
                .test_expect("assessment should succeed");
        mismatch_server.join();
        assert_eq!(mismatch.status, SettlementFinalityStatus::Reorged);

        let missing_server = MockJsonRpcServer::spawn(vec![
            rpc_result(json!({ "number": "0x78" })),
            rpc_result(Value::Null),
        ]);
        let missing_config = sample_config(missing_server.base_url());
        let missing =
            inspect_finality_for_receipt(&missing_config, &receipt, 500_000, Some(1_700_020_000))
                .await
                .test_expect("assessment should succeed");
        missing_server.join();
        assert_eq!(missing.status, SettlementFinalityStatus::Reorged);
    }

    #[tokio::test]
    async fn inspect_finality_fetches_receipt_and_timestamp() {
        let server = MockJsonRpcServer::spawn(vec![
            rpc_result(json!({
                "blockHash": "0xabc",
                "blockNumber": "0x64",
                "status": "0x1",
                "gasUsed": "0x5208",
                "from": "0x1000000000000000000000000000000000000001",
                "to": "0x1000000000000000000000000000000000000002",
                "logs": []
            })),
            rpc_result(json!({
                "timestamp": "0x6553f100"
            })),
            rpc_result(json!({ "number": "0x64" })),
            rpc_result(json!({ "hash": "0xabc" })),
        ]);
        let config = sample_config(server.base_url());

        let (receipt, assessment) =
            inspect_finality(&config, "0xdeadbeef", 50_000, Some(1_700_004_000))
                .await
                .test_expect("finality inspection should succeed");

        let requests = server.requests();
        server.join();

        assert_eq!(receipt.tx_hash, "0xdeadbeef");
        assert_eq!(receipt.block_number, 100);
        assert_eq!(receipt.block_hash, "0xabc");
        assert_eq!(receipt.gas_used, 21_000);
        assert_eq!(receipt.observed_at, 1_700_000_000);
        assert_eq!(assessment.status, SettlementFinalityStatus::Finalized);
        assert_eq!(assessment.required_confirmations, 1);
        assert_eq!(requests[0]["method"], "eth_getTransactionReceipt");
        assert_eq!(requests[1]["method"], "eth_getBlockByHash");
        assert_eq!(requests[2]["method"], "eth_getBlockByNumber");
        assert_eq!(requests[3]["method"], "eth_getBlockByNumber");
    }

    #[tokio::test]
    async fn inspect_finality_for_receipt_surfaces_rpc_errors_and_missing_fields() {
        let error_server = MockJsonRpcServer::spawn(vec![rpc_error(-32000, "boom")]);
        let error_config = sample_config(error_server.base_url());
        let receipt = sample_receipt(100, "0xaaa", 1_700_000_000);
        let error = inspect_finality_for_receipt(&error_config, &receipt, 500_000, None)
            .await
            .test_expect_err("RPC error should fail");
        error_server.join();
        assert!(matches!(error, SettlementError::Rpc(_)));

        let missing_field_server =
            MockJsonRpcServer::spawn(vec![rpc_result(json!({ "hash": "0xaaa" }))]);
        let missing_field_config = sample_config(missing_field_server.base_url());
        let error = inspect_finality_for_receipt(&missing_field_config, &receipt, 500_000, None)
            .await
            .test_expect_err("missing block number should fail");
        missing_field_server.join();
        assert!(error.to_string().contains("latest block missing number"));
    }

    #[test]
    fn observer_config_accepts_hostname_rpc_url_with_pinned_resolver() {
        let mut config = sample_config("http://127.0.0.1:8545");
        config.rpc_url = "https://mainnet-rpc.example.com".to_string();
        config.egress_contract = hostname_rpc_contract("mainnet-rpc.example.com");

        config
            .validate_rpc_egress_contract()
            .test_expect("hostname observer RPC dispatch is resolver-enforced");
    }

    #[tokio::test]
    async fn observer_rpc_rejects_redirects() {
        let server = MockRawHttpServer::spawn(
            "HTTP/1.1 302 Found\r\nLocation: /redirected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_string(),
        );
        let config = sample_config(server.base_url());
        let receipt = sample_receipt(100, "0xaaa", 1_700_000_000);

        let error = inspect_finality_for_receipt(&config, &receipt, 50_000, None)
            .await
            .test_expect_err("observer RPC redirect should fail");
        let message = error.to_string();

        server.join();
        assert!(
            message.contains("HttpEgressContract") && message.contains("redirect chain length"),
            "unexpected observer RPC redirect denial: {message}"
        );
    }

    #[tokio::test]
    async fn observer_rpc_rejects_oversized_responses() {
        let server = MockRawHttpServer::spawn(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 67108865\r\nConnection: close\r\n\r\n"
                .to_string(),
        );
        let config = sample_config(server.base_url());
        let receipt = sample_receipt(100, "0xaaa", 1_700_000_000);

        let error = inspect_finality_for_receipt(&config, &receipt, 50_000, None)
            .await
            .test_expect_err("oversized observer RPC response should fail");
        let message = error.to_string();

        server.join();
        assert!(
            message.contains("HttpEgressContract") && message.contains("response size"),
            "unexpected observer RPC response-size denial: {message}"
        );
    }

    #[tokio::test]
    async fn project_escrow_execution_receipt_projects_timed_out_refund() {
        let dispatch = sample_dispatch();
        let server = MockJsonRpcServer::spawn(vec![
            rpc_result(json!(encode_hex(
                IChioEscrow::getEscrowCall::abi_encode_returns(&IChioEscrow::getEscrowReturn {
                    terms: IChioEscrow::EscrowTerms {
                        capabilityId: B256::from([0x11; 32]),
                        depositor: Address::from_str("0x1000000000000000000000000000000000000001",)
                            .test_unwrap(),
                        beneficiary: Address::from_str(
                            "0x1000000000000000000000000000000000000002",
                        )
                        .test_unwrap(),
                        token: Address::from_str("0x1000000000000000000000000000000000000003",)
                            .test_unwrap(),
                        maxAmount: U256::from(1_500_000_u64),
                        deadline: U256::from(1_700_003_000_u64),
                        operator: Address::from_str("0x1000000000000000000000000000000000000004",)
                            .test_unwrap(),
                        operatorKeyHash: B256::from([0x22; 32]),
                    },
                    deposited: U256::from(1_500_000_u64),
                    released: U256::from(250_000_u64),
                    refunded: true,
                })
            ))),
            rpc_result(json!({
                "blockHash": "0xabc",
                "blockNumber": "0x64",
                "status": "0x1",
                "gasUsed": "0x5208",
                "from": "0x1000000000000000000000000000000000000001",
                "to": "0x1000000000000000000000000000000000000002",
                "logs": []
            })),
            rpc_result(json!({
                "timestamp": "0x6553f100"
            })),
            rpc_result(json!({ "number": "0x64" })),
            rpc_result(json!({ "hash": "0xabc" })),
        ]);
        let config = sample_config(server.base_url());

        let projection = project_escrow_execution_receipt(
            &config,
            ExecutionProjectionInput {
                dispatch: &dispatch,
                tx_hash: "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                execution_receipt_id: "exec-1".to_string(),
                settlement_reference: "settlement-1".to_string(),
                observed_at: Some(1_743_292_900),
                observed_amount: dispatch.settlement_amount.clone(),
                anchor_proof: None,
                identity_registry_evidence: None,
                identity_registry_evidence_binding: None,
                oracle_evidence: None,
                failure_reason: None,
                reversal_of: None,
                note: Some("timed out".to_string()),
            },
        )
        .await
        .test_expect("projection should succeed");

        server.join();

        assert_eq!(
            projection.receipt.lifecycle_state,
            Web3SettlementLifecycleState::TimedOut
        );
        assert_eq!(
            projection.receipt.failure_reason.as_deref(),
            Some("escrow refunded after deadline")
        );
        assert_eq!(projection.receipt.settled_amount.units, 125);
        assert_eq!(
            projection.recovery_action,
            Some(SettlementRecoveryAction::ExecuteRefund)
        );
        assert!(projection.escrow_snapshot.refunded);
    }

    #[tokio::test]
    async fn project_escrow_execution_receipt_projects_partial_settlement() {
        let dispatch = sample_dispatch();
        let server = MockJsonRpcServer::spawn(vec![
            rpc_result(json!(encode_hex(
                IChioEscrow::getEscrowCall::abi_encode_returns(&IChioEscrow::getEscrowReturn {
                    terms: IChioEscrow::EscrowTerms {
                        capabilityId: B256::from([0x33; 32]),
                        depositor: Address::from_str("0x1000000000000000000000000000000000000001",)
                            .test_unwrap(),
                        beneficiary: Address::from_str(
                            "0x1000000000000000000000000000000000000002",
                        )
                        .test_unwrap(),
                        token: Address::from_str("0x1000000000000000000000000000000000000003",)
                            .test_unwrap(),
                        maxAmount: U256::from(1_500_000_u64),
                        deadline: U256::from(1_700_050_000_u64),
                        operator: Address::from_str("0x1000000000000000000000000000000000000004",)
                            .test_unwrap(),
                        operatorKeyHash: B256::from([0x44; 32]),
                    },
                    deposited: U256::from(1_500_000_u64),
                    released: U256::from(750_000_u64),
                    refunded: false,
                })
            ))),
            rpc_result(json!({
                "blockHash": "0xabc",
                "blockNumber": "0x64",
                "status": "0x1",
                "gasUsed": "0x5208",
                "from": "0x1000000000000000000000000000000000000001",
                "to": "0x1000000000000000000000000000000000000002",
                "logs": []
            })),
            rpc_result(json!({
                "timestamp": "0x6553f100"
            })),
            rpc_result(json!({ "number": "0x78" })),
            rpc_result(json!({ "hash": "0xabc" })),
        ]);
        let config = sample_config(server.base_url());

        let projection = project_escrow_execution_receipt(
            &config,
            ExecutionProjectionInput {
                dispatch: &dispatch,
                tx_hash: "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                execution_receipt_id: "exec-2".to_string(),
                settlement_reference: "settlement-2".to_string(),
                observed_at: Some(1_743_292_900),
                observed_amount: chio_core::capability::scope::MonetaryAmount {
                    units: dispatch.settlement_amount.units / 2,
                    currency: dispatch.settlement_amount.currency.clone(),
                },
                anchor_proof: None,
                identity_registry_evidence: Some(sample_identity_registry_evidence(
                    &dispatch, &config,
                )),
                identity_registry_evidence_binding: Some(
                    sample_identity_registry_evidence_binding(&dispatch, &config),
                ),
                oracle_evidence: None,
                failure_reason: Some("partial release".to_string()),
                reversal_of: None,
                note: None,
            },
        )
        .await
        .test_expect("projection should succeed");

        server.join();

        assert_eq!(
            projection.receipt.lifecycle_state,
            Web3SettlementLifecycleState::PartiallySettled
        );
        assert_eq!(
            projection.receipt.failure_reason.as_deref(),
            Some("partial release")
        );
        assert_eq!(
            projection.finality.status,
            SettlementFinalityStatus::Finalized
        );
        assert_eq!(projection.recovery_action, None);
        assert!(!projection.escrow_snapshot.refunded);
    }

    #[tokio::test]
    async fn project_escrow_execution_receipt_waits_for_finality_before_settled_state() {
        let dispatch = sample_dispatch();
        let server = MockJsonRpcServer::spawn(vec![
            rpc_result(json!(encode_hex(
                IChioEscrow::getEscrowCall::abi_encode_returns(&IChioEscrow::getEscrowReturn {
                    terms: IChioEscrow::EscrowTerms {
                        capabilityId: B256::from([0x77; 32]),
                        depositor: Address::from_str("0x1000000000000000000000000000000000000001",)
                            .test_unwrap(),
                        beneficiary: Address::from_str(
                            "0x1000000000000000000000000000000000000002",
                        )
                        .test_unwrap(),
                        token: Address::from_str("0x1000000000000000000000000000000000000003",)
                            .test_unwrap(),
                        maxAmount: U256::from(1_500_000_u64),
                        deadline: U256::from(1_700_050_000_u64),
                        operator: Address::from_str("0x1000000000000000000000000000000000000004",)
                            .test_unwrap(),
                        operatorKeyHash: B256::from([0x88; 32]),
                    },
                    deposited: U256::from(1_500_000_u64),
                    released: U256::from(750_000_u64),
                    refunded: false,
                })
            ))),
            rpc_result(json!({
                "blockHash": "0xabc",
                "blockNumber": "0x64",
                "status": "0x1",
                "gasUsed": "0x5208",
                "from": "0x1000000000000000000000000000000000000001",
                "to": "0x1000000000000000000000000000000000000002",
                "logs": []
            })),
            rpc_result(json!({
                "timestamp": "0x67e88660"
            })),
            rpc_result(json!({ "number": "0x78" })),
            rpc_result(json!({ "hash": "0xabc" })),
        ]);
        let mut config = sample_config(server.base_url());
        config.policy.tiers[0].dispute_window_secs = 3_600;

        let projection = project_escrow_execution_receipt(
            &config,
            ExecutionProjectionInput {
                dispatch: &dispatch,
                tx_hash: "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                execution_receipt_id: "exec-pending".to_string(),
                settlement_reference: "settlement-pending".to_string(),
                observed_at: Some(1_743_292_900),
                observed_amount: chio_core::capability::scope::MonetaryAmount {
                    units: dispatch.settlement_amount.units / 2,
                    currency: dispatch.settlement_amount.currency.clone(),
                },
                anchor_proof: None,
                identity_registry_evidence: Some(sample_identity_registry_evidence(
                    &dispatch, &config,
                )),
                identity_registry_evidence_binding: Some(
                    sample_identity_registry_evidence_binding(&dispatch, &config),
                ),
                oracle_evidence: None,
                failure_reason: None,
                reversal_of: None,
                note: None,
            },
        )
        .await
        .test_expect("projection should succeed");

        server.join();

        assert_eq!(
            projection.finality.status,
            SettlementFinalityStatus::AwaitingDisputeWindow
        );
        assert_eq!(
            projection.receipt.lifecycle_state,
            Web3SettlementLifecycleState::EscrowLocked
        );
        assert_eq!(
            projection.recovery_action,
            Some(SettlementRecoveryAction::WaitForDisputeWindow)
        );
        assert_eq!(projection.receipt.settled_amount.units, 0);
        assert_eq!(projection.receipt.observed_execution.amount.units, 0);
        assert_eq!(projection.receipt.failure_reason, None);
    }

    #[tokio::test]
    async fn project_escrow_execution_receipt_waits_for_confirmations_without_release() {
        let dispatch = sample_dispatch();
        let server = MockJsonRpcServer::spawn(vec![
            escrow_result(0),
            rpc_result(json!({
                "blockHash": "0xabc",
                "blockNumber": "0x64",
                "status": "0x1",
                "gasUsed": "0x5208",
                "from": "0x1000000000000000000000000000000000000001",
                "to": "0x1000000000000000000000000000000000000002",
                "logs": []
            })),
            rpc_result(json!({
                "timestamp": "0x6553f100"
            })),
            rpc_result(json!({ "number": "0x64" })),
            rpc_result(json!({ "hash": "0xabc" })),
        ]);
        let mut config = sample_config(server.base_url());
        config.policy.tiers[0].min_confirmations = 2;

        let projection = project_escrow_execution_receipt(
            &config,
            ExecutionProjectionInput {
                dispatch: &dispatch,
                tx_hash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                execution_receipt_id: "exec-pending-zero".to_string(),
                settlement_reference: "settlement-pending-zero".to_string(),
                observed_at: Some(1_743_292_900),
                observed_amount: dispatch.settlement_amount.clone(),
                anchor_proof: None,
                identity_registry_evidence: Some(sample_identity_registry_evidence(
                    &dispatch, &config,
                )),
                identity_registry_evidence_binding: Some(
                    sample_identity_registry_evidence_binding(&dispatch, &config),
                ),
                oracle_evidence: None,
                failure_reason: None,
                reversal_of: None,
                note: None,
            },
        )
        .await
        .test_expect("pending zero-release projection should still return a wait action");

        server.join();

        assert_eq!(
            projection.finality.status,
            SettlementFinalityStatus::AwaitingConfirmations
        );
        assert_eq!(
            projection.receipt.lifecycle_state,
            Web3SettlementLifecycleState::EscrowLocked
        );
        assert_eq!(
            projection.recovery_action,
            Some(SettlementRecoveryAction::WaitForConfirmations)
        );
        assert_eq!(projection.receipt.settled_amount.units, 0);
        assert_eq!(projection.receipt.observed_execution.amount.units, 0);
        assert_eq!(projection.receipt.failure_reason, None);
    }

    #[tokio::test]
    async fn observe_bond_classifies_statuses_and_recovery_actions() {
        let cases = [
            (
                false,
                false,
                0_u64,
                1_700_000_000_u64,
                BondLifecycleStatus::Active,
                None,
            ),
            (
                true,
                false,
                0_u64,
                1_700_000_000_u64,
                BondLifecycleStatus::Released,
                Some(SettlementRecoveryAction::ManualReview),
            ),
            (
                false,
                false,
                5_u64,
                1_700_000_000_u64,
                BondLifecycleStatus::Impaired,
                Some(SettlementRecoveryAction::ManualReview),
            ),
            (
                false,
                false,
                0_u64,
                1_700_100_001_u64,
                BondLifecycleStatus::Expired,
                Some(SettlementRecoveryAction::ExpireBond),
            ),
            (
                false,
                true,
                0_u64,
                1_700_100_001_u64,
                BondLifecycleStatus::Expired,
                None,
            ),
        ];

        for (
            released,
            expired,
            slashed_minor_units,
            observed_at,
            expected_status,
            expected_recovery,
        ) in cases
        {
            let server = MockJsonRpcServer::spawn(vec![
                rpc_result(json!({
                    "number": "0x65",
                    "hash": "0xabababababababababababababababababababababababababababababababab",
                    "timestamp": format!("0x{observed_at:x}")
                })),
                rpc_result(json!(encode_hex(
                    IChioBondVault::getBondCall::abi_encode_returns(
                        &IChioBondVault::getBondReturn {
                            terms: IChioBondVault::BondTerms {
                                bondId: B256::from([0x55; 32]),
                                facilityId: B256::from([0x66; 32]),
                                principal: Address::from_str(
                                    "0x1000000000000000000000000000000000000001",
                                )
                                .test_unwrap(),
                                token: Address::from_str(
                                    "0x1000000000000000000000000000000000000002",
                                )
                                .test_unwrap(),
                                collateralAmount: U256::from(1_000_u64),
                                reserveRequirementAmount: U256::from(250_u64),
                                expiresAt: U256::from(1_700_100_000_u64),
                                reserveRequirementRatioBps: 2_500_u16,
                                operator: Address::from_str(
                                    "0x1000000000000000000000000000000000000003",
                                )
                                .test_unwrap(),
                                operatorKeyHash: B256::from([0x77; 32]),
                            },
                            lockedAmount: U256::from(1_000_u64),
                            slashedAmount: U256::from(slashed_minor_units),
                            released,
                            expired,
                        }
                    )
                ))),
            ]);
            let config = sample_config(server.base_url());

            let observation = observe_bond(
                &config,
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )
            .await
            .test_expect("bond observation should succeed");

            server.join();

            assert_eq!(observation.status, expected_status);
            assert_eq!(observation.recovery_action, expected_recovery);
        }
    }
}
