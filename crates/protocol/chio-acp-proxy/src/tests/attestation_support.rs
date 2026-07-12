use super::*;
use std::collections::VecDeque;
use std::fs;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::capability::{scope::{ChioScope, Constraint, Operation, ToolGrant}, token::{CapabilityToken, CapabilityTokenBody}};
use chio_core::crypto::Keypair;
use chio_core::receipt::{
    lineage::ChildRequestReceipt, body::ChioReceipt, body::ChioReceiptBody, decision::Decision, metadata::GuardEvidence, decision::ToolCallAction,
};
use chio_kernel::receipt_store::{
    ReceiptCheckpointCreateReport, ReceiptStore, ReceiptStoreError,
};
use chio_kernel::{
    mint_execution_nonce, ChioKernel, ExecutionNonceConfig, InMemoryExecutionNonceStore,
    KernelConfig, NonceBinding, DEFAULT_CHECKPOINT_BATCH_SIZE,
    DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use serde_json::json;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn make_capability_token(
    issuer: &Keypair,
    subject: &Keypair,
    server_id: &str,
    tool_name: &str,
    constraints: Vec<Constraint>,
    issued_at: u64,
    expires_at: u64,
) -> CapabilityToken {
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: format!("cap-{tool_name}-{issued_at}"),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: server_id.to_string(),
                    tool_name: tool_name.to_string(),
                    operations: vec![Operation::Invoke],
                    constraints,
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                resource_grants: Vec::new(),
                prompt_grants: Vec::new(),
            },
            issued_at,
            expires_at,
            delegation_chain: Vec::new(),
        },
        issuer,
    )
    .expect("capability token should sign")
}

fn test_kernel_config(issuer: &Keypair) -> KernelConfig {
    KernelConfig {
        ca_public_keys: vec![issuer.public_key()],
        keypair: issuer.clone(),
        max_delegation_depth: 8,
        policy_hash: "policy-acp-proxy-test".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    }
}

fn make_receipt(
    signer: &Keypair,
    id: &str,
    timestamp: u64,
    tool_name: &str,
    decision: Decision,
    evidence: Vec<GuardEvidence>,
) -> ChioReceipt {
    make_receipt_with_metadata(signer, None, id, timestamp, tool_name, decision, evidence)
}

fn make_receipt_for_session(
    signer: &Keypair,
    session_id: &str,
    id: &str,
    timestamp: u64,
    tool_name: &str,
    decision: Decision,
    evidence: Vec<GuardEvidence>,
) -> ChioReceipt {
    make_receipt_with_metadata(
        signer,
        Some(json!({
            "receipt_context": {
                "session_id": session_id,
            }
        })),
        id,
        timestamp,
        tool_name,
        decision,
        evidence,
    )
}

fn make_receipt_with_metadata(
    signer: &Keypair,
    metadata: Option<serde_json::Value>,
    id: &str,
    timestamp: u64,
    tool_name: &str,
    decision: Decision,
    evidence: Vec<GuardEvidence>,
) -> ChioReceipt {
    let action = ToolCallAction::from_parameters(json!({
        "tool": tool_name,
        "receipt_id": id,
    }))
    .expect("hash receipt parameters");
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: "capability-1".to_string(),
            tool_server: "acp-proxy".to_string(),
            tool_name: tool_name.to_string(),
            action,
            decision: Some(decision),
            receipt_kind: chio_core::receipt::kinds::ReceiptKind::MediatedDecision,
            boundary_class: chio_core::receipt::kinds::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core::receipt::kinds::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core::receipt::kinds::RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: format!("content-hash-{id}"),
            policy_hash: "policy-hash".to_string(),
            evidence,
            metadata,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            kernel_key: signer.public_key(),
            bbs_projection_version: None,
            tenant_id: None,
        },
        signer,
    )
    .expect("receipt should sign")
}

fn make_authorization_receipt(
    signer: &Keypair,
    capability_id: &str,
    request_id: &str,
    session_id: &str,
    tool_call_id: &str,
    tool_name: &str,
) -> ChioReceipt {
    make_authorization_receipt_with_semantics(
        signer,
        capability_id,
        request_id,
        session_id,
        tool_call_id,
        tool_name,
        Decision::Allow,
        chio_core::receipt::kinds::TrustLevel::Mediated,
        chio_core::receipt::metadata::ReceiptSemanticFields::mediated_prevent(),
    )
}

#[allow(clippy::too_many_arguments)]
fn make_authorization_receipt_with_semantics(
    signer: &Keypair,
    capability_id: &str,
    request_id: &str,
    session_id: &str,
    tool_call_id: &str,
    tool_name: &str,
    decision: Decision,
    trust_level: chio_core::receipt::kinds::TrustLevel,
    semantics: chio_core::receipt::metadata::ReceiptSemanticFields,
) -> ChioReceipt {
    let operation_payload = test_authorization_operation_payload();
    let authorization_parameter_hash = test_authorization_parameter_hash();
    let action = ToolCallAction::from_parameters(json!({
        "tool": tool_name,
        "authorization_parameter_hash": authorization_parameter_hash,
        "operation_payload": operation_payload,
    }))
        .expect("hash receipt parameters");
    let decision = if semantics.receipt_kind == chio_core::receipt::kinds::ReceiptKind::MediatedDecision {
        Some(decision)
    } else {
        None
    };
    ChioReceipt::sign(
        ChioReceiptBody {
            id: "ignored-auth-id".to_string(),
            timestamp: now_secs(),
            capability_id: capability_id.to_string(),
            tool_server: "proxy-server".to_string(),
            tool_name: tool_name.to_string(),
            action,
            decision,
            receipt_kind: semantics.receipt_kind,
            boundary_class: semantics.boundary_class,
            observation_outcome: semantics.observation_outcome,
            tool_origin: semantics.tool_origin,
            redaction_mode: semantics.redaction_mode,
            actor_chain: semantics.actor_chain,
            content_hash: "authorization-content-hash".to_string(),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: Some(json!({
                "receipt_context": {
                    "request_id": request_id,
                    "session_id": session_id,
                    "tool_call_id": tool_call_id,
                    "authorization_correlation_id": test_authorization_correlation_id(
                        session_id,
                        tool_call_id,
                    ),
                    "tool_call_id": tool_call_id,
                    "operation": test_authorization_operation(tool_name),
                    "resource": test_authorization_resource(tool_call_id),
                    "authorization_parameter_hash": test_authorization_parameter_hash(),
                }
            })),
            trust_level,
            kernel_key: signer.public_key(),
            bbs_projection_version: None,
            tenant_id: None,
        },
        signer,
    )
    .expect("authorization receipt should sign")
}

fn make_authorization_receipt_with_tenant(
    signer: &Keypair,
    capability_id: &str,
    request_id: &str,
    session_id: &str,
    tool_call_id: &str,
    tool_name: &str,
    tenant_id: Option<&str>,
) -> ChioReceipt {
    let mut receipt = make_authorization_receipt(
        signer,
        capability_id,
        request_id,
        session_id,
        tool_call_id,
        tool_name,
    );
    if let Some(tenant_id) = tenant_id {
        let body = ChioReceiptBody {
            id: receipt.id.clone(),
            timestamp: receipt.timestamp,
            capability_id: receipt.capability_id.clone(),
            tool_server: receipt.tool_server.clone(),
            tool_name: receipt.tool_name.clone(),
            action: receipt.action.clone(),
            decision: receipt.decision.clone(),
            receipt_kind: receipt.receipt_kind,
            boundary_class: receipt.boundary_class,
            observation_outcome: receipt.observation_outcome,
            tool_origin: receipt.tool_origin,
            redaction_mode: receipt.redaction_mode,
            actor_chain: receipt.actor_chain.clone(),
            content_hash: receipt.content_hash.clone(),
            policy_hash: receipt.policy_hash.clone(),
            evidence: receipt.evidence.clone(),
            metadata: receipt.metadata.clone(),
            trust_level: receipt.trust_level,
            tenant_id: Some(tenant_id.to_string()),
            kernel_key: signer.public_key(),
            bbs_projection_version: None,
        };
        receipt = ChioReceipt::sign(body, signer).expect("authorization receipt signs");
    }
    receipt
}

fn make_audit_entry(tool_call_id: &str, session_id: &str) -> AcpToolCallAuditEntry {
    AcpToolCallAuditEntry {
        tool_call_id: tool_call_id.to_string(),
        title: "Test tool".to_string(),
        kind: Some("execute".to_string()),
        status: "completed".to_string(),
        session_id: session_id.to_string(),
        timestamp: now_secs().to_string(),
        server_id: "acp-proxy".to_string(),
        content_hash: format!("hash-{tool_call_id}"),
        capability_id: None,
        authorization_receipt_id: None,
        authorization_request_id: None,
        authorization_tool_call_id: None,
        authorization_correlation_id: None,
        authorization_operation: None,
        authorization_resource: None,
        authorization_parameter_hash: None,
        enforcement_mode: Some(AcpEnforcementMode::AuditOnly),
    }
}

fn mark_entry_cryptographically_enforced(
    entry: &mut AcpToolCallAuditEntry,
    capability_id: &str,
    authorization_receipt_id: &str,
    authorization_request_id: &str,
    tool_name: &str,
) {
    entry.capability_id = Some(capability_id.to_string());
    entry.authorization_receipt_id = Some(authorization_receipt_id.to_string());
    entry.authorization_request_id = Some(authorization_request_id.to_string());
    entry.authorization_tool_call_id = Some(entry.tool_call_id.clone());
    entry.authorization_correlation_id = Some(test_authorization_correlation_id(
        &entry.session_id,
        &entry.tool_call_id,
    ));
    entry.authorization_operation = Some(test_authorization_operation(tool_name));
    entry.authorization_resource = Some(test_authorization_resource(&entry.tool_call_id));
    entry.authorization_parameter_hash = Some(test_authorization_parameter_hash());
    entry.enforcement_mode = Some(AcpEnforcementMode::CryptographicallyEnforced);
}

fn test_authorization_correlation_id(session_id: &str, tool_call_id: &str) -> String {
    format!("auth-correlation:{session_id}:{tool_call_id}")
}

fn test_authorization_operation(tool_name: &str) -> String {
    match tool_name {
        "fs/read_text_file" => "fs_read",
        "fs/write_text_file" => "fs_write",
        "terminal/create" => "terminal",
        other => other,
    }
    .to_string()
}

fn test_authorization_resource(tool_call_id: &str) -> String {
    format!("resource:{tool_call_id}")
}

fn test_authorization_operation_payload() -> serde_json::Value {
    json!({
        "sessionId": "test-session",
        "toolCallId": "test-tool-call",
        "path": "resource:test-tool-call",
        "capabilityToken": "test-token"
    })
}

fn test_authorization_parameter_hash() -> String {
    let bytes = chio_core::canonical::canonical_json_bytes(
        &test_authorization_operation_payload(),
    )
    .expect("test authorization payload should canonicalize");
    chio_core::sha256_hex(&bytes)
}

#[derive(Default)]
struct MockStoreState {
    appended_receipts: Vec<ChioReceipt>,
    canonical_ranges: Vec<(u64, u64)>,
    checkpoints: Vec<ReceiptCheckpointCreateReport>,
    consumed_authorization_receipts: std::collections::BTreeMap<String, String>,
    return_empty_bytes: bool,
}

struct MockReceiptStore {
    state: Arc<Mutex<MockStoreState>>,
    supports_checkpoints: bool,
}

impl ReceiptStore for MockReceiptStore {
    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        assert!(receipt.action.verify_hash().unwrap());
        let mut state = self.state.lock().expect("mock store lock should hold");
        state.appended_receipts.push(receipt.clone());
        Ok(())
    }

    fn append_chio_receipt_consuming_authorization(
        &self,
        receipt: &ChioReceipt,
        consumption: &AuthorizationReceiptConsumption,
    ) -> Result<(), ReceiptStoreError> {
        assert_eq!(receipt.id, consumption.consumer_receipt_id);
        let mut state = self.state.lock().expect("mock store lock should hold");
        if state
            .consumed_authorization_receipts
            .insert(
                consumption.authorization_receipt_id.clone(),
                consumption.consumer_receipt_id.clone(),
            )
            .is_some()
        {
            return Err(ReceiptStoreError::Conflict(
                "authorization receipt already consumed".to_string(),
            ));
        }
        state.appended_receipts.push(receipt.clone());
        Ok(())
    }

    fn load_chio_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        let state = self.state.lock().expect("mock store lock should hold");
        Ok(state
            .appended_receipts
            .iter()
            .find(|receipt| receipt.id == receipt_id)
            .cloned())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn receipts_canonical_bytes_range(
        &self,
        start_seq: u64,
        end_seq: u64,
    ) -> Result<Vec<(u64, Vec<u8>)>, ReceiptStoreError> {
        let mut state = self.state.lock().expect("mock store lock should hold");
        state.canonical_ranges.push((start_seq, end_seq));
        if state.return_empty_bytes {
            return Ok(Vec::new());
        }

        Ok(state
            .appended_receipts
            .iter()
            .enumerate()
            .filter_map(|(idx, receipt)| {
                let seq = idx as u64 + 1;
                ((start_seq..=end_seq).contains(&seq))
                    .then(|| (seq, receipt.id.as_bytes().to_vec()))
            })
            .collect())
    }

    fn latest_committed_entry_seq(&self) -> Result<u64, ReceiptStoreError> {
        let state = self.state.lock().expect("mock store lock should hold");
        Ok(state.appended_receipts.len() as u64)
    }

    fn latest_checkpointed_entry_seq(&self) -> Result<u64, ReceiptStoreError> {
        let state = self.state.lock().expect("mock store lock should hold");
        Ok(state
            .checkpoints
            .last()
            .map_or(0, |checkpoint| checkpoint.latest_checkpointed_entry_seq))
    }

    fn create_next_receipt_checkpoint(
        &self,
        max_batch: u64,
        _keypair: &Keypair,
    ) -> Result<ReceiptCheckpointCreateReport, ReceiptStoreError> {
        if max_batch == 0 {
            return Err(ReceiptStoreError::Conflict(
                "checkpoint max_batch must be greater than zero".to_string(),
            ));
        }
        if !self.supports_checkpoints {
            return Err(ReceiptStoreError::Conflict(
                "receipt checkpoint creation is not supported by this receipt store"
                    .to_string(),
            ));
        }
        let mut state = self.state.lock().expect("mock store lock should hold");
        if state.return_empty_bytes {
            return Err(ReceiptStoreError::Conflict(
                "checkpoint canonical bytes are missing".to_string(),
            ));
        }
        let latest_committed_entry_seq = state.appended_receipts.len() as u64;
        let next_start = state
            .checkpoints
            .last()
            .and_then(|checkpoint| checkpoint.batch_end_seq)
            .map_or(1, |seq| seq.saturating_add(1));
        if latest_committed_entry_seq < next_start {
            return Ok(ReceiptCheckpointCreateReport {
                created: false,
                checkpoint_seq: None,
                batch_start_seq: None,
                batch_end_seq: None,
                latest_committed_entry_seq,
                latest_checkpointed_entry_seq: latest_committed_entry_seq,
            });
        }
        let batch_end_seq = latest_committed_entry_seq.min(
            next_start.saturating_add(max_batch.saturating_sub(1)),
        );
        let report = ReceiptCheckpointCreateReport {
            created: true,
            checkpoint_seq: Some(state.checkpoints.len() as u64 + 1),
            batch_start_seq: Some(next_start),
            batch_end_seq: Some(batch_end_seq),
            latest_committed_entry_seq,
            latest_checkpointed_entry_seq: batch_end_seq,
        };
        state.checkpoints.push(report.clone());
        Ok(report)
    }
}

struct UnsupportedDurableConsumptionStore {
    authorization_receipt: ChioReceipt,
}

impl ReceiptStore for UnsupportedDurableConsumptionStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn load_chio_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        Ok((self.authorization_receipt.id == receipt_id)
            .then(|| self.authorization_receipt.clone()))
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
}

struct DummySigner(Keypair);

impl ReceiptSigner for DummySigner {
    fn sign_acp_receipt(
        &self,
        request: &AcpReceiptRequest,
    ) -> Result<ChioReceipt, ReceiptSignError> {
        Ok(make_receipt(
            &self.0,
            &format!("signed-{}", request.audit_entry.tool_call_id),
            now_secs(),
            &request.tool_name,
            Decision::Allow,
            Vec::new(),
        ))
    }
}

struct FailingSigner;

impl ReceiptSigner for FailingSigner {
    fn sign_acp_receipt(
        &self,
        _request: &AcpReceiptRequest,
    ) -> Result<ChioReceipt, ReceiptSignError> {
        Err(ReceiptSignError::SigningFailed(
            "test signer unavailable".to_string(),
        ))
    }
}

struct DummyChecker;

impl CapabilityChecker for DummyChecker {
    fn check_access(
        &self,
        request: &AcpCapabilityRequest,
    ) -> Result<AcpVerdict, CapabilityCheckError> {
        Ok(AcpVerdict {
            allowed: true,
            capability_id: Some(format!("cap:{}", request.session_id)),
            receipt_id: None,
            receipt_request_id: None,
            execution_nonce: None,
            reason: "dummy allow".to_string(),
        })
    }
}

struct RecordingChecker {
    requests: Arc<Mutex<Vec<AcpCapabilityRequest>>>,
    verdict: AcpVerdict,
}

impl RecordingChecker {
    fn allow(requests: Arc<Mutex<Vec<AcpCapabilityRequest>>>, capability_id: &str) -> Self {
        Self {
            requests,
            verdict: AcpVerdict {
                allowed: true,
                capability_id: Some(capability_id.to_string()),
                receipt_id: None,
                receipt_request_id: None,
                execution_nonce: None,
                reason: "recorded allow".to_string(),
            },
        }
    }

    fn allow_with_receipt(
        requests: Arc<Mutex<Vec<AcpCapabilityRequest>>>,
        capability_id: &str,
        receipt_id: &str,
        receipt_request_id: &str,
    ) -> Self {
        Self {
            requests,
            verdict: AcpVerdict {
                allowed: true,
                capability_id: Some(capability_id.to_string()),
                receipt_id: Some(receipt_id.to_string()),
                receipt_request_id: Some(receipt_request_id.to_string()),
                execution_nonce: None,
                reason: "recorded signed allow".to_string(),
            },
        }
    }

    fn deny(requests: Arc<Mutex<Vec<AcpCapabilityRequest>>>, reason: &str) -> Self {
        Self {
            requests,
            verdict: AcpVerdict {
                allowed: false,
                capability_id: Some("cap-denied".to_string()),
                receipt_id: None,
                receipt_request_id: None,
                execution_nonce: None,
                reason: reason.to_string(),
            },
        }
    }
}

impl CapabilityChecker for RecordingChecker {
    fn check_access(
        &self,
        request: &AcpCapabilityRequest,
    ) -> Result<AcpVerdict, CapabilityCheckError> {
        self.requests
            .lock()
            .expect("recording checker lock should succeed")
            .push(request.clone());
        Ok(self.verdict.clone())
    }
}

struct SequencedChecker {
    requests: Arc<Mutex<Vec<AcpCapabilityRequest>>>,
    verdicts: Arc<Mutex<VecDeque<AcpVerdict>>>,
}

impl SequencedChecker {
    fn new(requests: Arc<Mutex<Vec<AcpCapabilityRequest>>>, verdicts: Vec<AcpVerdict>) -> Self {
        Self {
            requests,
            verdicts: Arc::new(Mutex::new(VecDeque::from(verdicts))),
        }
    }
}

impl CapabilityChecker for SequencedChecker {
    fn check_access(
        &self,
        request: &AcpCapabilityRequest,
    ) -> Result<AcpVerdict, CapabilityCheckError> {
        self.requests
            .lock()
            .expect("sequenced checker request lock should succeed")
            .push(request.clone());
        self.verdicts
            .lock()
            .expect("sequenced checker verdict lock should succeed")
            .pop_front()
            .ok_or_else(|| CapabilityCheckError::Internal("no verdict queued".to_string()))
    }
}

struct ErrorChecker;

impl CapabilityChecker for ErrorChecker {
    fn check_access(
        &self,
        _request: &AcpCapabilityRequest,
    ) -> Result<AcpVerdict, CapabilityCheckError> {
        Err(CapabilityCheckError::Internal(
            "checker backend unavailable".to_string(),
        ))
    }
}
