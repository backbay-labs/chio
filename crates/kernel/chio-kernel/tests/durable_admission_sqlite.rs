use std::error::Error;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::{
    scope::{ChioScope, Constraint, MonetaryAmount, Operation, ToolGrant},
    token::CapabilityToken,
};
use chio_core::crypto::{sha256_hex, Keypair};
use chio_core::receipt::metadata::{
    DeliveryContract, DeliveryResult, DELIVERY_CONTRACT_METADATA_KEY, DELIVERY_CONTRACT_SCHEMA,
};
use chio_kernel::admission_operation::{
    AdmissionOperationState, AdmissionOperationStore, AdmissionReceiptMetadataV1,
    AdmissionRecoveryLease, StoreMutationFence, ADMISSION_RECEIPT_METADATA_KEY,
};
use chio_kernel::tool_outcome::{
    CanonicalInvocationBlobV1, CanonicalResolvedOutputBlobV1, PostReturnEvaluationRecordV1,
    QualifiedToolOutcomeStore, RawInvocationOutcomeV1, ToolOutcomeInsertResultV1,
    ToolOutcomeRecordV1, ToolOutcomeStore, ToolOutcomeStoreError,
};
use chio_kernel::{
    BudgetStore, ChioKernel, KernelConfig, KernelError, NestedFlowBridge, PaymentAdapter,
    PaymentAuthorization, PaymentAuthorizationState, PaymentAuthorizeRequest, PaymentError,
    PaymentJournalState, PaymentRailMode, PaymentReleaseAuthorityKind, PaymentResult,
    PaymentSettleAction, RailSettlementStatus, ReceiptStore, ToolCallChunk, ToolCallRequest,
    ToolCallResponse, ToolCallStream, ToolInvocationCost, ToolServerConnection,
    ToolServerStreamResult, Verdict, DEFAULT_CHECKPOINT_BATCH_SIZE,
    DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_store_sqlite::{SqliteAuthorityStore, SqliteToolOutcomeStore};

fn secure_directory(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn create_private_directory(path: &std::path::Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    secure_directory(path)
}

struct MutationServer {
    invocations: Arc<AtomicU64>,
}

struct ZeroCostMutationServer {
    invocations: Arc<AtomicU64>,
}

struct PaidMutationServer {
    invocations: Arc<AtomicU64>,
}

#[derive(Default)]
struct ReversiblePaymentAdapter {
    calls: Option<Arc<PaymentCalls>>,
}

#[derive(Default)]
struct PaymentCalls {
    authorizations: AtomicU64,
    captures: AtomicU64,
    releases: AtomicU64,
    refunds: AtomicU64,
    fail_next_capture: AtomicBool,
    fail_next_release: AtomicBool,
}

struct FailOnceOutcomeStore {
    inner: SqliteToolOutcomeStore,
    fail_record: AtomicBool,
}

#[async_trait::async_trait]
impl ToolServerConnection for MutationServer {
    fn server_id(&self) -> &str {
        "sqlite-durable-server"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["mutate".to_owned()]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({
            "tool": tool_name,
            "echo": arguments,
        }))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for ZeroCostMutationServer {
    fn server_id(&self) -> &str {
        "sqlite-durable-zero-server"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["mutate".to_owned()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"result": "no charge"}))
    }

    async fn invoke_with_cost(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        let output = self.invoke(tool_name, arguments, bridge).await?;
        Ok((
            output,
            Some(ToolInvocationCost {
                units: 0,
                currency: "USD".to_owned(),
                breakdown: None,
            }),
        ))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for PaidMutationServer {
    fn server_id(&self) -> &str {
        "sqlite-durable-paid-server"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["mutate".to_owned()]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({
            "tool": tool_name,
            "echo": arguments,
        }))
    }

    async fn invoke_with_cost(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        let output = self.invoke(tool_name, arguments, bridge).await?;
        Ok((
            output,
            Some(ToolInvocationCost {
                units: 5,
                currency: "USD".to_owned(),
                breakdown: None,
            }),
        ))
    }
}

struct StreamingPaidMutationServer {
    invocations: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl ToolServerConnection for StreamingPaidMutationServer {
    fn server_id(&self) -> &str {
        "sqlite-durable-stream-server"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["mutate".to_owned()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::Internal(
            "the streaming server must be dispatched through invoke_stream".to_owned(),
        ))
    }

    async fn invoke_stream(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(Some(ToolServerStreamResult::Complete(ToolCallStream {
            chunks: vec![
                ToolCallChunk {
                    data: serde_json::json!({"chunk": 1}),
                },
                ToolCallChunk {
                    data: serde_json::json!({"chunk": 2}),
                },
            ],
        })))
    }
}

impl PaymentAdapter for ReversiblePaymentAdapter {
    fn rail_id(&self) -> &'static str {
        "sqlite-test-reversible"
    }

    fn rail_mode(&self) -> Option<PaymentRailMode> {
        Some(PaymentRailMode::ReversibleHold)
    }

    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        if let Some(calls) = &self.calls {
            calls.authorizations.fetch_add(1, Ordering::SeqCst);
        }
        Ok(PaymentAuthorization {
            authorization_id: format!("authorization:{}", request.reference),
            state: PaymentAuthorizationState::Held,
            metadata: serde_json::json!({}),
        })
    }

    fn capture(
        &self,
        authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        if let Some(calls) = &self.calls {
            calls.captures.fetch_add(1, Ordering::SeqCst);
            if calls.fail_next_capture.swap(false, Ordering::SeqCst) {
                return Err(PaymentError::Unavailable(
                    "injected capture interruption".to_owned(),
                ));
            }
        }
        Ok(PaymentResult {
            transaction_id: authorization_id.to_owned(),
            settlement_status: RailSettlementStatus::Settled,
            metadata: serde_json::json!({}),
        })
    }

    fn release(
        &self,
        authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        if let Some(calls) = &self.calls {
            calls.releases.fetch_add(1, Ordering::SeqCst);
            if calls.fail_next_release.swap(false, Ordering::SeqCst) {
                return Err(PaymentError::Unavailable(
                    "injected release interruption".to_owned(),
                ));
            }
        }
        Ok(PaymentResult {
            transaction_id: format!("release:{authorization_id}"),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::json!({}),
        })
    }

    fn refund(
        &self,
        transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        if let Some(calls) = &self.calls {
            calls.refunds.fetch_add(1, Ordering::SeqCst);
        }
        Ok(PaymentResult {
            transaction_id: transaction_id.to_owned(),
            settlement_status: RailSettlementStatus::Refunded,
            metadata: serde_json::json!({}),
        })
    }
}

/// A final-settlement rail. A delivery-digest grant cannot be honored here:
/// the compare only runs after the tool returns, which is past the prepay
/// point on this rail, so the kernel must reject the request before dispatch.
struct PrepaidFinalPaymentAdapter {
    calls: Arc<PaymentCalls>,
}

impl PaymentAdapter for PrepaidFinalPaymentAdapter {
    fn rail_id(&self) -> &'static str {
        "sqlite-test-prepaid-final"
    }

    fn rail_mode(&self) -> Option<PaymentRailMode> {
        Some(PaymentRailMode::PrepaidFinal)
    }

    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.calls.authorizations.fetch_add(1, Ordering::SeqCst);
        Ok(PaymentAuthorization {
            authorization_id: format!("prepaid:{}", request.reference),
            state: PaymentAuthorizationState::PrepaidFinal,
            metadata: serde_json::json!({}),
        })
    }

    fn capture(
        &self,
        authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.calls.captures.fetch_add(1, Ordering::SeqCst);
        Ok(PaymentResult {
            transaction_id: authorization_id.to_owned(),
            settlement_status: RailSettlementStatus::Settled,
            metadata: serde_json::json!({}),
        })
    }

    fn release(
        &self,
        authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.calls.releases.fetch_add(1, Ordering::SeqCst);
        Ok(PaymentResult {
            transaction_id: format!("release:{authorization_id}"),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::json!({}),
        })
    }

    fn refund(
        &self,
        transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.calls.refunds.fetch_add(1, Ordering::SeqCst);
        Ok(PaymentResult {
            transaction_id: transaction_id.to_owned(),
            settlement_status: RailSettlementStatus::Refunded,
            metadata: serde_json::json!({}),
        })
    }
}

impl ToolOutcomeStore for FailOnceOutcomeStore {
    fn record_tool_returned(
        &self,
        operation: &chio_kernel::admission_operation::AdmissionOperationV1,
        recovery_lease: &AdmissionRecoveryLease,
        blob: &CanonicalInvocationBlobV1,
        record: &ToolOutcomeRecordV1,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<ToolOutcomeInsertResultV1, ToolOutcomeStoreError> {
        if self.fail_record.swap(false, Ordering::SeqCst) {
            return Err(ToolOutcomeStoreError::Unavailable(
                "injected tool outcome write failure".to_owned(),
            ));
        }
        self.inner.record_tool_returned(
            operation,
            recovery_lease,
            blob,
            record,
            active_fence,
            trusted_now_unix_ms,
        )
    }

    fn lookup_by_operation(
        &self,
        operation_id: &chio_kernel::admission_operation::AdmissionOperationId,
    ) -> Result<Option<ToolOutcomeRecordV1>, ToolOutcomeStoreError> {
        self.inner.lookup_by_operation(operation_id)
    }

    fn load_raw_invocation_by_operation(
        &self,
        operation_id: &chio_kernel::admission_operation::AdmissionOperationId,
    ) -> Result<Option<RawInvocationOutcomeV1>, ToolOutcomeStoreError> {
        self.inner.load_raw_invocation_by_operation(operation_id)
    }

    fn lookup_post_return_evaluation(
        &self,
        operation_id: &chio_kernel::admission_operation::AdmissionOperationId,
    ) -> Result<Option<PostReturnEvaluationRecordV1>, ToolOutcomeStoreError> {
        self.inner.lookup_post_return_evaluation(operation_id)
    }

    fn begin_post_return_evaluation(
        &self,
        recovery_lease: &AdmissionRecoveryLease,
        record: &PostReturnEvaluationRecordV1,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<PostReturnEvaluationRecordV1, ToolOutcomeStoreError> {
        self.inner.begin_post_return_evaluation(
            recovery_lease,
            record,
            active_fence,
            trusted_now_unix_ms,
        )
    }

    fn stage_post_return_evaluation(
        &self,
        operation_id: &chio_kernel::admission_operation::AdmissionOperationId,
        expected_version: u64,
        recovery_lease: &AdmissionRecoveryLease,
        next: &PostReturnEvaluationRecordV1,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<PostReturnEvaluationRecordV1, ToolOutcomeStoreError> {
        self.inner.stage_post_return_evaluation(
            operation_id,
            expected_version,
            recovery_lease,
            next,
            active_fence,
            trusted_now_unix_ms,
        )
    }

    fn finalize_post_return(
        &self,
        operation_id: &chio_kernel::admission_operation::AdmissionOperationId,
        expected_evaluation_version: u64,
        recovery_lease: &AdmissionRecoveryLease,
        terminal_evaluation: &PostReturnEvaluationRecordV1,
        expected_outcome_version: u64,
        terminal_outcome: &ToolOutcomeRecordV1,
        resolved_output: Option<&CanonicalResolvedOutputBlobV1>,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<(PostReturnEvaluationRecordV1, ToolOutcomeRecordV1), ToolOutcomeStoreError> {
        self.inner.finalize_post_return(
            operation_id,
            expected_evaluation_version,
            recovery_lease,
            terminal_evaluation,
            expected_outcome_version,
            terminal_outcome,
            resolved_output,
            active_fence,
            trusted_now_unix_ms,
        )
    }

    fn load_resolved_output_by_operation(
        &self,
        operation_id: &chio_kernel::admission_operation::AdmissionOperationId,
    ) -> Result<Option<CanonicalResolvedOutputBlobV1>, ToolOutcomeStoreError> {
        self.inner.load_resolved_output_by_operation(operation_id)
    }
}

impl QualifiedToolOutcomeStore for FailOnceOutcomeStore {}

fn kernel_config(keypair: Keypair) -> KernelConfig {
    KernelConfig {
        keypair,
        ca_public_keys: Vec::new(),
        max_delegation_depth: 5,
        policy_hash: sha256_hex(b"sqlite-durable-admission-test-policy"),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    }
}

fn scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "sqlite-durable-server".to_owned(),
            tool_name: "mutate".to_owned(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    }
}

fn zero_charge_scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "sqlite-durable-zero-server".to_owned(),
            tool_name: "mutate".to_owned(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 10,
                currency: "USD".to_owned(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 100,
                currency: "USD".to_owned(),
            }),
            dpop_required: None,
        }],
        ..ChioScope::default()
    }
}

fn paid_scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "sqlite-durable-paid-server".to_owned(),
            tool_name: "mutate".to_owned(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 10,
                currency: "USD".to_owned(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 100,
                currency: "USD".to_owned(),
            }),
            dpop_required: None,
        }],
        ..ChioScope::default()
    }
}

fn request(capability: &CapabilityToken) -> ToolCallRequest {
    ToolCallRequest {
        request_id: "sqlite-durable-terminal".to_owned(),
        capability: capability.clone(),
        tool_name: "mutate".to_owned(),
        server_id: "sqlite-durable-server".to_owned(),
        agent_id: capability.subject.to_hex(),
        arguments: serde_json::json!({"record": "ledger-11", "value": "committed"}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    }
}

fn zero_charge_request(capability: &CapabilityToken) -> ToolCallRequest {
    ToolCallRequest {
        request_id: "sqlite-durable-zero-terminal".to_owned(),
        capability: capability.clone(),
        tool_name: "mutate".to_owned(),
        server_id: "sqlite-durable-zero-server".to_owned(),
        agent_id: capability.subject.to_hex(),
        arguments: serde_json::json!({"record": "ledger-zero"}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    }
}

fn paid_request(capability: &CapabilityToken) -> ToolCallRequest {
    ToolCallRequest {
        request_id: "sqlite-durable-unknown-outcome".to_owned(),
        capability: capability.clone(),
        tool_name: "mutate".to_owned(),
        server_id: "sqlite-durable-paid-server".to_owned(),
        agent_id: capability.subject.to_hex(),
        arguments: serde_json::json!({"record": "ledger-unknown", "value": "committed"}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    }
}

fn paid_scope_with_digests(digests: &[&str]) -> ChioScope {
    let mut scope = paid_scope();
    if let Some(grant) = scope.grants.first_mut() {
        grant.constraints = digests
            .iter()
            .map(|digest| Constraint::OutputDigestSha256((*digest).to_owned()))
            .collect();
    }
    scope
}

/// A digest-marked paid grant followed by an unconstrained sibling for the
/// same tool with roomier ceilings. The marked grant's per-invocation
/// exposure exceeds its total budget, so budget authorization denies it and
/// grant selection falls through to the sibling.
fn paid_scope_with_marked_grant_and_unmarked_sibling(digest: &str) -> ChioScope {
    let mut scope = paid_scope();
    if let Some(grant) = scope.grants.first_mut() {
        grant.constraints = vec![Constraint::OutputDigestSha256(digest.to_owned())];
        grant.max_cost_per_invocation = Some(MonetaryAmount {
            units: 5,
            currency: "USD".to_owned(),
        });
        grant.max_total_cost = Some(MonetaryAmount {
            units: 3,
            currency: "USD".to_owned(),
        });
    }
    let mut sibling = paid_scope();
    scope.grants.append(&mut sibling.grants);
    scope
}

fn delivery_block(response: &ToolCallResponse) -> Result<DeliveryContract, Box<dyn Error>> {
    let value = response
        .receipt
        .metadata
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .and_then(|metadata| metadata.get(DELIVERY_CONTRACT_METADATA_KEY))
        .cloned()
        .ok_or_else(|| std::io::Error::other("delivery contract block is absent"))?;
    let block: DeliveryContract = serde_json::from_value(value)?;
    block.validate()?;
    Ok(block)
}

fn now_unix_ms() -> Result<u64, Box<dyn Error>> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

#[test]
fn sqlite_restart_terminalizes_an_unrecorded_dispatch_without_moving_funds(
) -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    secure_directory(temp.path())?;
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    create_private_directory(&lock_root)?;
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let kernel_keypair = Keypair::generate();
    let invocations = Arc::new(AtomicU64::new(0));
    let payment_calls = Arc::new(PaymentCalls::default());

    let (operation_id, capability_id, usage_before) = {
        let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        let fence = authority.mutation_fence();
        let operations = Arc::new(authority.admission_operation_store());
        let outcomes = authority.tool_outcome_store();
        let budget = Arc::new(authority.budget_store());
        let mut kernel = ChioKernel::new(kernel_config(kernel_keypair.clone()));
        kernel.set_durable_admission_store(
            operations.clone(),
            Arc::new(FailOnceOutcomeStore {
                inner: outcomes,
                fail_record: AtomicBool::new(true),
            }),
            fence.clone(),
        )?;
        kernel.set_budget_store_handle(budget.clone());
        kernel.set_payment_adapter(Box::new(ReversiblePaymentAdapter {
            calls: Some(payment_calls.clone()),
        }));
        kernel.register_tool_server(Box::new(PaidMutationServer {
            invocations: invocations.clone(),
        }));
        let agent = Keypair::generate();
        let capability = kernel.issue_capability(&agent.public_key(), paid_scope(), 300)?;
        let request = paid_request(&capability);
        let error = kernel
            .evaluate_tool_call_blocking(&request)
            .err()
            .ok_or_else(|| std::io::Error::other("the injected outcome write must fail"))?;
        assert!(matches!(
            error,
            KernelError::DurableAdmission(ref reason)
                if reason.contains("injected tool outcome write failure")
        ));
        let recoverable = operations.list_recoverable(now_unix_ms()? + 120_000, 10)?;
        assert_eq!(recoverable.len(), 1);
        let operation = &recoverable[0];
        assert_eq!(
            operation.state(),
            AdmissionOperationState::DispatchCommitted
        );
        let journal = operations
            .load_payment_journal(operation.binding().operation_id().as_str(), &fence)?
            .ok_or_else(|| std::io::Error::other("payment journal is absent"))?;
        assert_eq!(journal.state, PaymentJournalState::Authorized);
        let usage = budget
            .get_usage(&capability.id, 0)?
            .ok_or_else(|| std::io::Error::other("budget usage is absent"))?;
        assert_eq!(usage.total_cost_exposed, 10);
        (
            operation.binding().operation_id().clone(),
            capability.id,
            usage,
        )
    };

    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let fence = authority.mutation_fence();
    let operations = Arc::new(authority.admission_operation_store());
    let outcomes = Arc::new(authority.tool_outcome_store());
    let budget = Arc::new(authority.budget_store());
    let mut recovered_kernel = ChioKernel::new(kernel_config(kernel_keypair));
    recovered_kernel.set_durable_admission_store(operations.clone(), outcomes, fence.clone())?;
    recovered_kernel.set_budget_store_handle(budget.clone());
    recovered_kernel.set_payment_adapter(Box::new(ReversiblePaymentAdapter {
        calls: Some(payment_calls.clone()),
    }));
    recovered_kernel.register_tool_server(Box::new(PaidMutationServer {
        invocations: invocations.clone(),
    }));

    assert_eq!(recovered_kernel.reconcile_durable_admission_startup()?, 1);
    assert_eq!(recovered_kernel.reconcile_recoverable_admissions()?, 0);
    let retained = operations
        .load_by_operation_id(&operation_id)?
        .ok_or_else(|| std::io::Error::other("recovered operation is absent"))?;
    assert_eq!(
        retained.state(),
        AdmissionOperationState::OutcomeUnknownAfterDispatch
    );
    let replay = retained
        .terminal_replay()
        .ok_or_else(|| std::io::Error::other("incident replay is absent"))?;
    let stored_replay = operations
        .load_terminal_replay(&retained.replay_key())?
        .ok_or_else(|| std::io::Error::other("stored incident replay is absent"))?;
    assert_eq!(&stored_replay, replay);
    let journal = operations
        .load_payment_journal(operation_id.as_str(), &fence)?
        .ok_or_else(|| std::io::Error::other("recovered payment journal is absent"))?;
    assert_eq!(journal.state, PaymentJournalState::Authorized);
    assert_eq!(
        budget
            .get_usage(&capability_id, 0)?
            .ok_or_else(|| std::io::Error::other("recovered budget usage is absent"))?,
        usage_before
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(payment_calls.authorizations.load(Ordering::SeqCst), 1);
    assert_eq!(payment_calls.captures.load(Ordering::SeqCst), 0);
    assert_eq!(payment_calls.releases.load(Ordering::SeqCst), 0);
    assert_eq!(payment_calls.refunds.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn sqlite_restart_completes_a_committed_capture_without_request_replay(
) -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    secure_directory(temp.path())?;
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    create_private_directory(&lock_root)?;
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let kernel_keypair = Keypair::generate();
    let invocations = Arc::new(AtomicU64::new(0));
    let payment_calls = Arc::new(PaymentCalls::default());
    payment_calls
        .fail_next_capture
        .store(true, Ordering::SeqCst);

    let (request, operation_id) = {
        let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        let fence = authority.mutation_fence();
        let operations = Arc::new(authority.admission_operation_store());
        let outcomes = Arc::new(authority.tool_outcome_store());
        let budget = Arc::new(authority.budget_store());
        let mut kernel = ChioKernel::new(kernel_config(kernel_keypair.clone()));
        kernel.set_durable_admission_store(operations.clone(), outcomes, fence.clone())?;
        kernel.set_budget_store_handle(budget);
        kernel.set_payment_adapter(Box::new(ReversiblePaymentAdapter {
            calls: Some(payment_calls.clone()),
        }));
        kernel.register_tool_server(Box::new(PaidMutationServer {
            invocations: invocations.clone(),
        }));
        let agent = Keypair::generate();
        let capability = kernel.issue_capability(&agent.public_key(), paid_scope(), 300)?;
        let request = paid_request(&capability);
        let error = kernel
            .evaluate_tool_call_blocking(&request)
            .err()
            .ok_or_else(|| std::io::Error::other("the injected capture must fail"))?;
        assert!(matches!(
            error,
            KernelError::DurableAdmission(ref reason)
                if reason.contains("injected capture interruption")
        ));
        let recoverable = operations.list_recoverable(now_unix_ms()? + 120_000, 10)?;
        assert_eq!(recoverable.len(), 1);
        let operation = &recoverable[0];
        assert_eq!(operation.state(), AdmissionOperationState::Finalizing);
        let journal = operations
            .load_payment_journal(operation.binding().operation_id().as_str(), &fence)?
            .ok_or_else(|| std::io::Error::other("payment journal is absent"))?;
        assert_eq!(journal.state, PaymentJournalState::Settling);
        (request, operation.binding().operation_id().clone())
    };

    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let fence = authority.mutation_fence();
    let operations = Arc::new(authority.admission_operation_store());
    let outcomes = Arc::new(authority.tool_outcome_store());
    let budget = Arc::new(authority.budget_store());
    let mut recovered_kernel = ChioKernel::new(kernel_config(kernel_keypair));
    recovered_kernel.set_durable_admission_store(operations.clone(), outcomes, fence.clone())?;
    recovered_kernel.set_budget_store_handle(budget);
    recovered_kernel.set_payment_adapter(Box::new(ReversiblePaymentAdapter {
        calls: Some(payment_calls.clone()),
    }));
    recovered_kernel.register_tool_server(Box::new(PaidMutationServer {
        invocations: invocations.clone(),
    }));

    assert_eq!(recovered_kernel.reconcile_durable_admission_startup()?, 1);
    let journal = operations
        .load_payment_journal(operation_id.as_str(), &fence)?
        .ok_or_else(|| std::io::Error::other("recovered payment journal is absent"))?;
    assert_eq!(journal.state, PaymentJournalState::Settled);
    assert_eq!(journal.settle_action, Some(PaymentSettleAction::Capture));
    assert_eq!(payment_calls.captures.load(Ordering::SeqCst), 2);
    let completed = operations
        .load_by_operation_id(&operation_id)?
        .ok_or_else(|| std::io::Error::other("completed operation is absent"))?;
    assert_eq!(completed.state(), AdmissionOperationState::Completed);

    let response = recovered_kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(payment_calls.captures.load(Ordering::SeqCst), 2);
    Ok(())
}

#[test]
fn sqlite_restart_completes_a_committed_release_without_request_replay(
) -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    secure_directory(temp.path())?;
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    create_private_directory(&lock_root)?;
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let kernel_keypair = Keypair::generate();
    let invocations = Arc::new(AtomicU64::new(0));
    let payment_calls = Arc::new(PaymentCalls::default());
    payment_calls
        .fail_next_release
        .store(true, Ordering::SeqCst);

    let (request, operation_id) = {
        let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        let fence = authority.mutation_fence();
        let operations = Arc::new(authority.admission_operation_store());
        let outcomes = Arc::new(authority.tool_outcome_store());
        let budget = Arc::new(authority.budget_store());
        let mut kernel = ChioKernel::new(kernel_config(kernel_keypair.clone()));
        kernel.set_durable_admission_store(operations.clone(), outcomes, fence.clone())?;
        kernel.set_budget_store_handle(budget);
        kernel.set_payment_adapter(Box::new(ReversiblePaymentAdapter {
            calls: Some(payment_calls.clone()),
        }));
        kernel.register_tool_server(Box::new(ZeroCostMutationServer {
            invocations: invocations.clone(),
        }));
        let agent = Keypair::generate();
        let capability = kernel.issue_capability(&agent.public_key(), zero_charge_scope(), 300)?;
        let request = zero_charge_request(&capability);
        let error = kernel
            .evaluate_tool_call_blocking(&request)
            .err()
            .ok_or_else(|| std::io::Error::other("the injected release must fail"))?;
        assert!(matches!(
            error,
            KernelError::DurableAdmission(ref reason)
                if reason.contains("injected release interruption")
        ));
        let recoverable = operations.list_recoverable(now_unix_ms()? + 120_000, 10)?;
        assert_eq!(recoverable.len(), 1);
        let operation = &recoverable[0];
        assert_eq!(operation.state(), AdmissionOperationState::Finalizing);
        let journal = operations
            .load_payment_journal(operation.binding().operation_id().as_str(), &fence)?
            .ok_or_else(|| std::io::Error::other("payment journal is absent"))?;
        assert_eq!(journal.state, PaymentJournalState::Settling);
        assert_eq!(journal.settle_action, Some(PaymentSettleAction::Release));
        assert_eq!(
            journal
                .release_authority
                .as_ref()
                .map(|authority| authority.kind),
            Some(PaymentReleaseAuthorityKind::ContractualZeroCharge)
        );
        (request, operation.binding().operation_id().clone())
    };

    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let fence = authority.mutation_fence();
    let operations = Arc::new(authority.admission_operation_store());
    let outcomes = Arc::new(authority.tool_outcome_store());
    let budget = Arc::new(authority.budget_store());
    let mut recovered_kernel = ChioKernel::new(kernel_config(kernel_keypair));
    recovered_kernel.set_durable_admission_store(operations.clone(), outcomes, fence.clone())?;
    recovered_kernel.set_budget_store_handle(budget);
    recovered_kernel.set_payment_adapter(Box::new(ReversiblePaymentAdapter {
        calls: Some(payment_calls.clone()),
    }));
    recovered_kernel.register_tool_server(Box::new(ZeroCostMutationServer {
        invocations: invocations.clone(),
    }));

    assert_eq!(recovered_kernel.reconcile_durable_admission_startup()?, 1);
    let journal = operations
        .load_payment_journal(operation_id.as_str(), &fence)?
        .ok_or_else(|| std::io::Error::other("recovered payment journal is absent"))?;
    assert_eq!(journal.state, PaymentJournalState::Settled);
    assert_eq!(journal.settle_action, Some(PaymentSettleAction::Release));
    assert_eq!(payment_calls.releases.load(Ordering::SeqCst), 2);
    let completed = operations
        .load_by_operation_id(&operation_id)?
        .ok_or_else(|| std::io::Error::other("completed operation is absent"))?;
    assert_eq!(completed.state(), AdmissionOperationState::Completed);

    let response = recovered_kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(payment_calls.releases.load(Ordering::SeqCst), 2);
    Ok(())
}

#[test]
fn sqlite_durable_admission_atomically_publishes_receipt_and_terminal_outcome(
) -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    secure_directory(temp.path())?;
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    create_private_directory(&lock_root)?;
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let kernel_keypair = Keypair::generate();
    let invocations = Arc::new(AtomicU64::new(0));
    let (request, response, first_owner_epoch) = {
        let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        let fence = authority.mutation_fence();
        let first_owner_epoch = fence.owner_epoch;
        let operations = Arc::new(authority.admission_operation_store());
        let outcomes = Arc::new(authority.tool_outcome_store());
        let mut kernel = ChioKernel::new(kernel_config(kernel_keypair.clone()));
        kernel.set_durable_admission_store(operations.clone(), outcomes.clone(), fence)?;
        kernel.register_tool_server(Box::new(MutationServer {
            invocations: invocations.clone(),
        }));
        let agent = Keypair::generate();
        let capability = kernel.issue_capability(&agent.public_key(), scope(), 300)?;
        let request = request(&capability);
        let response = kernel.evaluate_tool_call_blocking(&request)?;
        assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
        let metadata: AdmissionReceiptMetadataV1 = serde_json::from_value(
            response
                .receipt
                .metadata
                .as_ref()
                .and_then(serde_json::Value::as_object)
                .and_then(|metadata| metadata.get(ADMISSION_RECEIPT_METADATA_KEY))
                .cloned()
                .ok_or_else(|| std::io::Error::other("admission receipt metadata is absent"))?,
        )?;
        let operation = operations
            .load_by_operation_id(&metadata.operation_id)?
            .ok_or_else(|| std::io::Error::other("completed admission operation is absent"))?;

        assert_eq!(operation.state(), AdmissionOperationState::Completed);
        assert_eq!(invocations.load(Ordering::SeqCst), 1);
        let stored_receipt = operations
            .load_chio_receipt(&response.receipt.id)?
            .ok_or_else(|| std::io::Error::other("projected receipt is absent"))?;
        assert_eq!(
            canonical_json_bytes(&stored_receipt)?,
            canonical_json_bytes(&response.receipt)?
        );
        let resolved = outcomes
            .load_resolved_output_by_operation(&metadata.operation_id)?
            .ok_or_else(|| std::io::Error::other("resolved output blob is absent"))?;
        assert_eq!(sha256_hex(resolved.bytes()), response.receipt.content_hash);
        (request, response, first_owner_epoch)
    };

    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let fence = authority.mutation_fence();
    assert!(fence.owner_epoch > first_owner_epoch);
    let operations = Arc::new(authority.admission_operation_store());
    let outcomes = Arc::new(authority.tool_outcome_store());
    let mut recovered_kernel = ChioKernel::new(kernel_config(kernel_keypair));
    recovered_kernel.set_durable_admission_store(operations, outcomes, fence)?;
    recovered_kernel.register_tool_server(Box::new(MutationServer {
        invocations: invocations.clone(),
    }));

    let replay = recovered_kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(replay.verdict, Verdict::Allow, "{:?}", replay.reason);
    assert_eq!(replay.receipt.id, response.receipt.id);
    assert_eq!(replay.output, response.output);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn sqlite_durable_zero_charge_persists_release_evidence_and_reopens_cleanly(
) -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    secure_directory(temp.path())?;
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    create_private_directory(&lock_root)?;
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let kernel_keypair = Keypair::generate();

    let operation_id = {
        let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        let fence = authority.mutation_fence();
        let operations = Arc::new(authority.admission_operation_store());
        let outcomes = Arc::new(authority.tool_outcome_store());
        let budget = Arc::new(authority.budget_store());
        let mut kernel = ChioKernel::new(kernel_config(kernel_keypair));
        kernel.set_durable_admission_store(operations.clone(), outcomes, fence.clone())?;
        kernel.set_budget_store_handle(budget);
        kernel.set_payment_adapter(Box::new(ReversiblePaymentAdapter::default()));
        kernel.register_tool_server(Box::new(ZeroCostMutationServer {
            invocations: Arc::new(AtomicU64::new(0)),
        }));
        let agent = Keypair::generate();
        let capability = kernel.issue_capability(&agent.public_key(), zero_charge_scope(), 300)?;
        let response = kernel.evaluate_tool_call_blocking(&zero_charge_request(&capability))?;
        let metadata: AdmissionReceiptMetadataV1 = serde_json::from_value(
            response
                .receipt
                .metadata
                .as_ref()
                .and_then(serde_json::Value::as_object)
                .and_then(|metadata| metadata.get(ADMISSION_RECEIPT_METADATA_KEY))
                .cloned()
                .ok_or_else(|| std::io::Error::other("admission receipt metadata is absent"))?,
        )?;
        let journal = operations
            .load_payment_journal(metadata.operation_id.as_str(), &fence)?
            .ok_or_else(|| std::io::Error::other("payment journal is absent"))?;

        assert_eq!(response.verdict, Verdict::Allow);
        assert_eq!(journal.state, PaymentJournalState::Settled);
        assert_eq!(journal.settle_action, Some(PaymentSettleAction::Release));
        assert_eq!(
            journal
                .release_authority
                .as_ref()
                .map(|authority| authority.kind),
            Some(PaymentReleaseAuthorityKind::ContractualZeroCharge)
        );
        assert_eq!(
            response
                .receipt
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.get("financial"))
                .and_then(|financial| financial.get("cost_charged"))
                .and_then(serde_json::Value::as_u64),
            Some(0)
        );
        metadata.operation_id
    };

    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let fence = authority.mutation_fence();
    let operations = authority.admission_operation_store();
    let reopened = operations
        .load_payment_journal(operation_id.as_str(), &fence)?
        .ok_or_else(|| std::io::Error::other("reopened payment journal is absent"))?;
    assert_eq!(reopened.state, PaymentJournalState::Settled);
    assert_eq!(reopened.settle_action, Some(PaymentSettleAction::Release));
    Ok(())
}

// A grant that fixes an expected output digest is honored end to end: a
// delivered output that does not hash to it is denied with a signed
// zero-charge receipt, a matching delivery captures normally, and both
// outcomes survive a restart without redispatching the tool or moving money
// a second time. A rail that cannot support the deferred compare is rejected
// before the tool ever runs.
#[test]
fn output_digest_delivery_contract_enforces_every_lane() -> Result<(), Box<dyn Error>> {
    let wrong_digest = sha256_hex(b"a digest the delivered output cannot match");
    let true_digest = sha256_hex(&canonical_json_bytes(&serde_json::json!({
        "tool": "mutate",
        "echo": {"record": "ledger-unknown", "value": "committed"},
    }))?);

    // Lane 1: a mismatch denies, charges nothing, and recovers to the same
    // persisted Deny after a restart.
    {
        let temp = tempfile::tempdir()?;
        let database = temp.path().join("authority.db");
        let lock_root = temp.path().join("locks");
        std::fs::create_dir(&lock_root)?;
        SqliteAuthorityStore::provision(&database, &lock_root)?;
        let kernel_keypair = Keypair::generate();
        let invocations = Arc::new(AtomicU64::new(0));
        let payment_calls = Arc::new(PaymentCalls::default());

        let (request, response, operation_id) = {
            let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
            let fence = authority.mutation_fence();
            let operations = Arc::new(authority.admission_operation_store());
            let outcomes = Arc::new(authority.tool_outcome_store());
            let budget = Arc::new(authority.budget_store());
            let mut kernel = ChioKernel::new(kernel_config(kernel_keypair.clone()));
            kernel.set_durable_admission_store(operations.clone(), outcomes, fence.clone())?;
            kernel.set_budget_store_handle(budget);
            kernel.set_payment_adapter(Box::new(ReversiblePaymentAdapter {
                calls: Some(payment_calls.clone()),
            }));
            kernel.register_tool_server(Box::new(PaidMutationServer {
                invocations: invocations.clone(),
            }));
            let agent = Keypair::generate();
            let capability = kernel.issue_capability(
                &agent.public_key(),
                paid_scope_with_digests(&[wrong_digest.as_str()]),
                300,
            )?;
            let request = paid_request(&capability);
            let response = kernel.evaluate_tool_call_blocking(&request)?;

            assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
            assert!(
                response
                    .reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("committed output digest")),
                "{:?}",
                response.reason
            );
            // The denial discloses both digests and withholds the bytes:
            // the caller is not paying for this output and must not
            // receive it.
            assert!(
                response.output.is_none(),
                "a denied delivery must not disclose the payload"
            );
            let block = delivery_block(&response)?;
            assert_eq!(block.schema, DELIVERY_CONTRACT_SCHEMA);
            assert_eq!(block.result, DeliveryResult::Mismatched);
            assert_eq!(block.expected_digest, wrong_digest);
            assert_eq!(block.observed_digest, response.receipt.content_hash);
            assert_ne!(block.observed_digest, block.expected_digest);
            assert_eq!(invocations.load(Ordering::SeqCst), 1);
            // The paid grant was worth five units, yet the mismatch releases
            // the hold instead of capturing it.
            assert_eq!(payment_calls.captures.load(Ordering::SeqCst), 0);
            assert_eq!(payment_calls.releases.load(Ordering::SeqCst), 1);

            let metadata: AdmissionReceiptMetadataV1 = serde_json::from_value(
                response
                    .receipt
                    .metadata
                    .as_ref()
                    .and_then(serde_json::Value::as_object)
                    .and_then(|metadata| metadata.get(ADMISSION_RECEIPT_METADATA_KEY))
                    .cloned()
                    .ok_or_else(|| std::io::Error::other("admission receipt metadata is absent"))?,
            )?;
            let operation = operations
                .load_by_operation_id(&metadata.operation_id)?
                .ok_or_else(|| std::io::Error::other("denied admission operation is absent"))?;
            assert_eq!(
                operation.state(),
                AdmissionOperationState::DeniedAfterDelivery
            );
            let journal = operations
                .load_payment_journal(metadata.operation_id.as_str(), &fence)?
                .ok_or_else(|| std::io::Error::other("payment journal is absent"))?;
            assert_eq!(journal.state, PaymentJournalState::Settled);
            assert_eq!(journal.settle_action, Some(PaymentSettleAction::Release));
            assert_eq!(
                journal
                    .release_authority
                    .as_ref()
                    .map(|authority| authority.kind),
                Some(PaymentReleaseAuthorityKind::ContractualZeroCharge)
            );
            assert_eq!(
                response
                    .receipt
                    .metadata
                    .as_ref()
                    .and_then(|metadata| metadata.get("financial"))
                    .and_then(|financial| financial.get("cost_charged"))
                    .and_then(serde_json::Value::as_u64),
                Some(0)
            );
            (request, response, metadata.operation_id)
        };

        // Restart: re-entering the denied operation returns the persisted
        // Deny without redispatching the tool or moving funds.
        let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        let fence = authority.mutation_fence();
        let operations = Arc::new(authority.admission_operation_store());
        let outcomes = Arc::new(authority.tool_outcome_store());
        let budget = Arc::new(authority.budget_store());
        let mut recovered = ChioKernel::new(kernel_config(kernel_keypair));
        recovered.set_durable_admission_store(operations.clone(), outcomes, fence)?;
        recovered.set_budget_store_handle(budget);
        recovered.set_payment_adapter(Box::new(ReversiblePaymentAdapter {
            calls: Some(payment_calls.clone()),
        }));
        recovered.register_tool_server(Box::new(PaidMutationServer {
            invocations: invocations.clone(),
        }));

        let replay = recovered.evaluate_tool_call_blocking(&request)?;
        assert_eq!(replay.verdict, Verdict::Deny, "{:?}", replay.reason);
        assert_eq!(replay.receipt.id, response.receipt.id);
        assert_eq!(
            canonical_json_bytes(&replay.receipt)?,
            canonical_json_bytes(&response.receipt)?
        );
        assert_eq!(delivery_block(&replay)?.result, DeliveryResult::Mismatched);
        assert!(
            replay.output.is_none(),
            "a replayed denial must not disclose the payload either"
        );
        assert_eq!(invocations.load(Ordering::SeqCst), 1);
        assert_eq!(payment_calls.captures.load(Ordering::SeqCst), 0);
        let operation = operations
            .load_by_operation_id(&operation_id)?
            .ok_or_else(|| std::io::Error::other("denied admission operation is absent"))?;
        assert_eq!(
            operation.state(),
            AdmissionOperationState::DeniedAfterDelivery
        );

        assert_ne!(
            response.receipt.content_hash, true_digest,
            "a mismatch receipt exposes only the redacted delivery commitment"
        );
    }

    // Lane 2: a matching digest allows, captures, and replays the same Allow
    // after a restart without a second capture.
    {
        let temp = tempfile::tempdir()?;
        let database = temp.path().join("authority.db");
        let lock_root = temp.path().join("locks");
        std::fs::create_dir(&lock_root)?;
        SqliteAuthorityStore::provision(&database, &lock_root)?;
        let kernel_keypair = Keypair::generate();
        let invocations = Arc::new(AtomicU64::new(0));
        let payment_calls = Arc::new(PaymentCalls::default());

        let (request, response) = {
            let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
            let fence = authority.mutation_fence();
            let operations = Arc::new(authority.admission_operation_store());
            let outcomes = Arc::new(authority.tool_outcome_store());
            let budget = Arc::new(authority.budget_store());
            let mut kernel = ChioKernel::new(kernel_config(kernel_keypair.clone()));
            kernel.set_durable_admission_store(operations.clone(), outcomes, fence.clone())?;
            kernel.set_budget_store_handle(budget);
            kernel.set_payment_adapter(Box::new(ReversiblePaymentAdapter {
                calls: Some(payment_calls.clone()),
            }));
            kernel.register_tool_server(Box::new(PaidMutationServer {
                invocations: invocations.clone(),
            }));
            let agent = Keypair::generate();
            let capability = kernel.issue_capability(
                &agent.public_key(),
                paid_scope_with_digests(&[true_digest.as_str()]),
                300,
            )?;
            let request = paid_request(&capability);
            let response = kernel.evaluate_tool_call_blocking(&request)?;

            assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
            let block = delivery_block(&response)?;
            assert_eq!(block.result, DeliveryResult::Matched);
            assert_eq!(block.expected_digest, true_digest);
            assert_eq!(block.observed_digest, true_digest);
            assert_eq!(block.observed_digest, response.receipt.content_hash);
            assert_eq!(invocations.load(Ordering::SeqCst), 1);
            assert_eq!(payment_calls.captures.load(Ordering::SeqCst), 1);

            let metadata: AdmissionReceiptMetadataV1 = serde_json::from_value(
                response
                    .receipt
                    .metadata
                    .as_ref()
                    .and_then(serde_json::Value::as_object)
                    .and_then(|metadata| metadata.get(ADMISSION_RECEIPT_METADATA_KEY))
                    .cloned()
                    .ok_or_else(|| std::io::Error::other("admission receipt metadata is absent"))?,
            )?;
            let operation = operations
                .load_by_operation_id(&metadata.operation_id)?
                .ok_or_else(|| std::io::Error::other("completed admission operation is absent"))?;
            assert_eq!(operation.state(), AdmissionOperationState::Completed);
            (request, response)
        };

        let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        let fence = authority.mutation_fence();
        let operations = Arc::new(authority.admission_operation_store());
        let outcomes = Arc::new(authority.tool_outcome_store());
        let budget = Arc::new(authority.budget_store());
        let mut recovered = ChioKernel::new(kernel_config(kernel_keypair));
        recovered.set_durable_admission_store(operations, outcomes, fence)?;
        recovered.set_budget_store_handle(budget);
        recovered.set_payment_adapter(Box::new(ReversiblePaymentAdapter {
            calls: Some(payment_calls.clone()),
        }));
        recovered.register_tool_server(Box::new(PaidMutationServer {
            invocations: invocations.clone(),
        }));

        let replay = recovered.evaluate_tool_call_blocking(&request)?;
        assert_eq!(replay.verdict, Verdict::Allow, "{:?}", replay.reason);
        assert_eq!(replay.receipt.id, response.receipt.id);
        assert_eq!(replay.output, response.output);
        assert_eq!(delivery_block(&replay)?.result, DeliveryResult::Matched);
        assert_eq!(invocations.load(Ordering::SeqCst), 1);
        assert_eq!(payment_calls.captures.load(Ordering::SeqCst), 1);
    }

    // Lane 3: a final-settlement rail cannot arbitrate the deferred compare,
    // so a digest-constrained request is denied before dispatch with no
    // execution and no money touched.
    {
        let temp = tempfile::tempdir()?;
        let database = temp.path().join("authority.db");
        let lock_root = temp.path().join("locks");
        std::fs::create_dir(&lock_root)?;
        SqliteAuthorityStore::provision(&database, &lock_root)?;
        let invocations = Arc::new(AtomicU64::new(0));
        let payment_calls = Arc::new(PaymentCalls::default());
        let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        let fence = authority.mutation_fence();
        let operations = Arc::new(authority.admission_operation_store());
        let outcomes = Arc::new(authority.tool_outcome_store());
        let budget = Arc::new(authority.budget_store());
        let mut kernel = ChioKernel::new(kernel_config(Keypair::generate()));
        kernel.set_durable_admission_store(operations, outcomes, fence)?;
        kernel.set_budget_store_handle(budget);
        kernel.set_payment_adapter(Box::new(PrepaidFinalPaymentAdapter {
            calls: payment_calls.clone(),
        }));
        kernel.register_tool_server(Box::new(PaidMutationServer {
            invocations: invocations.clone(),
        }));
        let agent = Keypair::generate();
        let capability = kernel.issue_capability(
            &agent.public_key(),
            paid_scope_with_digests(&[true_digest.as_str()]),
            300,
        )?;
        let response = kernel.evaluate_tool_call_blocking(&paid_request(&capability))?;

        assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
        assert!(
            response
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("reversible-hold")),
            "{:?}",
            response.reason
        );
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
        assert_eq!(payment_calls.authorizations.load(Ordering::SeqCst), 0);
        assert_eq!(payment_calls.captures.load(Ordering::SeqCst), 0);
    }

    Ok(())
}

// A committed output digest is admitted only in the shape the terminal can
// honor and the registered receipt schema can express: exactly one carrier
// on the selected grant, canonical lowercase 64-hex, and never the digest
// of the canonical null output. Every malformed shape denies before the
// tool runs and before any payment hold exists, because past that point a
// malformed commitment either signs a schema-violating receipt or wedges
// the operation in finalization with its hold open.
#[test]
fn malformed_delivery_digests_are_rejected_before_dispatch() -> Result<(), Box<dyn Error>> {
    let valid = sha256_hex(b"a well-formed committed delivery");
    let null_output = sha256_hex(b"null");
    let shapes: [(&[&str], &str); 3] = [
        (&["zz"], "canonical"),
        (&[valid.as_str(), null_output.as_str()], "at most one"),
        (&[null_output.as_str()], "no-output"),
    ];
    for (digests, expected_fragment) in shapes {
        let temp = tempfile::tempdir()?;
        let database = temp.path().join("authority.db");
        let lock_root = temp.path().join("locks");
        std::fs::create_dir(&lock_root)?;
        SqliteAuthorityStore::provision(&database, &lock_root)?;
        let invocations = Arc::new(AtomicU64::new(0));
        let payment_calls = Arc::new(PaymentCalls::default());
        let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        let fence = authority.mutation_fence();
        let operations = Arc::new(authority.admission_operation_store());
        let outcomes = Arc::new(authority.tool_outcome_store());
        let budget = Arc::new(authority.budget_store());
        let mut kernel = ChioKernel::new(kernel_config(Keypair::generate()));
        kernel.set_durable_admission_store(operations, outcomes, fence)?;
        kernel.set_budget_store_handle(budget);
        kernel.set_payment_adapter(Box::new(ReversiblePaymentAdapter {
            calls: Some(payment_calls.clone()),
        }));
        kernel.register_tool_server(Box::new(PaidMutationServer {
            invocations: invocations.clone(),
        }));
        let agent = Keypair::generate();
        let capability =
            kernel.issue_capability(&agent.public_key(), paid_scope_with_digests(digests), 300)?;
        let response = kernel.evaluate_tool_call_blocking(&paid_request(&capability))?;

        assert_eq!(
            response.verdict,
            Verdict::Deny,
            "{digests:?}: {:?}",
            response.reason
        );
        assert!(
            response
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains(expected_fragment)),
            "{digests:?}: {:?}",
            response.reason
        );
        assert_eq!(invocations.load(Ordering::SeqCst), 0, "{digests:?}");
        assert_eq!(
            payment_calls.authorizations.load(Ordering::SeqCst),
            0,
            "{digests:?}"
        );
        assert_eq!(
            payment_calls.captures.load(Ordering::SeqCst),
            0,
            "{digests:?}"
        );
    }
    Ok(())
}

// Grant selection skips candidates whose budget authorization denies and
// tries the next. A delivery-marked candidate must never be skippable: an
// unconstrained sibling selected in its place would dispatch with full
// capture, full payload, and no delivery gate. The call denies instead.
#[test]
fn delivery_marked_grant_cannot_fall_through_to_an_unmarked_sibling() -> Result<(), Box<dyn Error>>
{
    let temp = tempfile::tempdir()?;
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    std::fs::create_dir(&lock_root)?;
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let invocations = Arc::new(AtomicU64::new(0));
    let payment_calls = Arc::new(PaymentCalls::default());
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let fence = authority.mutation_fence();
    let operations = Arc::new(authority.admission_operation_store());
    let outcomes = Arc::new(authority.tool_outcome_store());
    let budget = Arc::new(authority.budget_store());
    let mut kernel = ChioKernel::new(kernel_config(Keypair::generate()));
    kernel.set_durable_admission_store(operations, outcomes, fence)?;
    kernel.set_budget_store_handle(budget);
    kernel.set_payment_adapter(Box::new(ReversiblePaymentAdapter {
        calls: Some(payment_calls.clone()),
    }));
    kernel.register_tool_server(Box::new(PaidMutationServer {
        invocations: invocations.clone(),
    }));
    let agent = Keypair::generate();
    let digest = sha256_hex(b"the committed delivery only the marked grant honors");
    let capability = kernel.issue_capability(
        &agent.public_key(),
        paid_scope_with_marked_grant_and_unmarked_sibling(&digest),
        300,
    )?;
    let response = kernel.evaluate_tool_call_blocking(&paid_request(&capability))?;

    assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
    assert!(
        response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("sibling")),
        "{:?}",
        response.reason
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_eq!(payment_calls.authorizations.load(Ordering::SeqCst), 0);
    assert_eq!(payment_calls.captures.load(Ordering::SeqCst), 0);
    Ok(())
}

// A delivery commitment is validated at admission, before the tool runs and
// before any hold is placed. A malformed digest would otherwise be signed
// into a receipt whose registered schema pins canonical lowercase hex; a
// duplicated digest would run the tool and then strand the operation in
// finalization with its hold open; the fixed no-output content hash can
// never name a real delivery.
#[test]
fn output_digest_admission_rejects_malformed_commitments() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    std::fs::create_dir(&lock_root)?;
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let invocations = Arc::new(AtomicU64::new(0));
    let payment_calls = Arc::new(PaymentCalls::default());
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let fence = authority.mutation_fence();
    let operations = Arc::new(authority.admission_operation_store());
    let outcomes = Arc::new(authority.tool_outcome_store());
    let budget = Arc::new(authority.budget_store());
    let mut kernel = ChioKernel::new(kernel_config(Keypair::generate()));
    kernel.set_durable_admission_store(operations, outcomes, fence)?;
    kernel.set_budget_store_handle(budget);
    kernel.set_payment_adapter(Box::new(ReversiblePaymentAdapter {
        calls: Some(payment_calls.clone()),
    }));
    kernel.register_tool_server(Box::new(PaidMutationServer {
        invocations: invocations.clone(),
    }));
    let agent = Keypair::generate();

    let valid_a = sha256_hex(b"one committed delivery");
    let valid_b = sha256_hex(b"another committed delivery");
    let uppercase = valid_a.to_ascii_uppercase();
    let null_hash = sha256_hex(b"null");
    let cases: [(&[&str], &str); 4] = [
        (&["zz"], "canonical lowercase"),
        (&[uppercase.as_str()], "canonical lowercase"),
        (&[valid_a.as_str(), valid_b.as_str()], "at most one"),
        (&[null_hash.as_str()], "no-output content hash"),
    ];
    for (case, (digests, expected_reason)) in cases.into_iter().enumerate() {
        let capability =
            kernel.issue_capability(&agent.public_key(), paid_scope_with_digests(digests), 300)?;
        let mut request = paid_request(&capability);
        request.request_id = format!("sqlite-durable-malformed-commitment-{case}");
        let response = kernel.evaluate_tool_call_blocking(&request)?;
        assert_eq!(response.verdict, Verdict::Deny, "{digests:?}");
        assert!(
            response
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains(expected_reason)),
            "{digests:?} -> {:?}",
            response.reason
        );
    }
    assert_eq!(
        invocations.load(Ordering::SeqCst),
        0,
        "a malformed commitment must never reach the tool"
    );
    assert_eq!(payment_calls.captures.load(Ordering::SeqCst), 0);
    assert_eq!(payment_calls.releases.load(Ordering::SeqCst), 0);
    Ok(())
}

// A committed output digest is a commitment over canonical value bytes. A
// stream's content hash is derived from provider-authored chunk digests, so
// a seller who commits the stream-form hash and then streams the chunks
// would otherwise be paid for a delivery that never produced the committed
// value. The delivery denies, releases the hold, and replays the same Deny.
#[test]
fn stream_delivery_cannot_satisfy_a_committed_output_digest() -> Result<(), Box<dyn Error>> {
    let stream_scope = |constraints: Vec<Constraint>| ChioScope {
        grants: vec![ToolGrant {
            server_id: "sqlite-durable-stream-server".to_owned(),
            tool_name: "mutate".to_owned(),
            operations: vec![Operation::Invoke],
            constraints,
            max_invocations: None,
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 10,
                currency: "USD".to_owned(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 100,
                currency: "USD".to_owned(),
            }),
            dpop_required: None,
        }],
        ..ChioScope::default()
    };
    let stream_request = |capability: &CapabilityToken, request_id: &str| ToolCallRequest {
        request_id: request_id.to_owned(),
        capability: capability.clone(),
        tool_name: "mutate".to_owned(),
        server_id: "sqlite-durable-stream-server".to_owned(),
        agent_id: capability.subject.to_hex(),
        arguments: serde_json::json!({"record": "ledger-stream"}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };

    // Learn the stream-form content hash from an unconstrained delivery.
    let stream_hash = {
        let temp = tempfile::tempdir()?;
        let database = temp.path().join("authority.db");
        let lock_root = temp.path().join("locks");
        std::fs::create_dir(&lock_root)?;
        SqliteAuthorityStore::provision(&database, &lock_root)?;
        let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        let invocations = Arc::new(AtomicU64::new(0));
        let mut kernel = ChioKernel::new(kernel_config(Keypair::generate()));
        kernel.set_durable_admission_store(
            Arc::new(authority.admission_operation_store()),
            Arc::new(authority.tool_outcome_store()),
            authority.mutation_fence(),
        )?;
        kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
        kernel.set_payment_adapter(Box::new(ReversiblePaymentAdapter { calls: None }));
        kernel.register_tool_server(Box::new(StreamingPaidMutationServer {
            invocations: invocations.clone(),
        }));
        let agent = Keypair::generate();
        let capability =
            kernel.issue_capability(&agent.public_key(), stream_scope(Vec::new()), 300)?;
        let response =
            kernel.evaluate_tool_call_blocking(&stream_request(&capability, "stream-probe"))?;
        assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
        response.receipt.content_hash
    };

    // Commit that exact hash as the output digest: the streamed delivery
    // must still deny with a zero-charge release, not capture.
    let temp = tempfile::tempdir()?;
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    std::fs::create_dir(&lock_root)?;
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let invocations = Arc::new(AtomicU64::new(0));
    let payment_calls = Arc::new(PaymentCalls::default());
    let operations = Arc::new(authority.admission_operation_store());
    let mut kernel = ChioKernel::new(kernel_config(Keypair::generate()));
    kernel.set_durable_admission_store(
        operations.clone(),
        Arc::new(authority.tool_outcome_store()),
        authority.mutation_fence(),
    )?;
    kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
    kernel.set_payment_adapter(Box::new(ReversiblePaymentAdapter {
        calls: Some(payment_calls.clone()),
    }));
    kernel.register_tool_server(Box::new(StreamingPaidMutationServer {
        invocations: invocations.clone(),
    }));
    let agent = Keypair::generate();
    let capability = kernel.issue_capability(
        &agent.public_key(),
        stream_scope(vec![Constraint::OutputDigestSha256(stream_hash.clone())]),
        300,
    )?;
    let request = stream_request(&capability, "stream-committed");
    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
    assert!(
        response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("single value delivery")),
        "{:?}",
        response.reason
    );
    assert!(response.output.is_none());
    let block = delivery_block(&response)?;
    assert_eq!(block.result, DeliveryResult::Mismatched);
    assert_eq!(block.expected_digest, stream_hash);
    assert_eq!(
        block.observed_digest, stream_hash,
        "the colliding stream hash is exactly what the denial must resist"
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(payment_calls.captures.load(Ordering::SeqCst), 0);
    assert_eq!(payment_calls.releases.load(Ordering::SeqCst), 1);
    let metadata: AdmissionReceiptMetadataV1 = serde_json::from_value(
        response
            .receipt
            .metadata
            .as_ref()
            .and_then(serde_json::Value::as_object)
            .and_then(|metadata| metadata.get(ADMISSION_RECEIPT_METADATA_KEY))
            .cloned()
            .ok_or_else(|| std::io::Error::other("admission receipt metadata is absent"))?,
    )?;
    let operation = operations
        .load_by_operation_id(&metadata.operation_id)?
        .ok_or_else(|| std::io::Error::other("denied admission operation is absent"))?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::DeniedAfterDelivery
    );

    // Re-entry replays the persisted Deny without redispatching the tool.
    let replay = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(replay.verdict, Verdict::Deny);
    assert_eq!(replay.receipt.id, response.receipt.id);
    assert_eq!(
        canonical_json_bytes(&replay.receipt)?,
        canonical_json_bytes(&response.receipt)?
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}
