// The settlement-observer outcome is routed into the retry/dead-letter
// machinery, never dropped: a retryable outcome persists a bounded attempt
// row, an accepted outcome clears it, and a permanent outcome lands exactly
// one dead-letter row.

#[derive(Default)]
struct RecordingRetryStore {
    attempts: std::sync::Mutex<
        std::collections::HashMap<String, crate::settlement_retry::SettleAttemptRecord>,
    >,
    dead_letters: std::sync::Mutex<Vec<chio_settle::DeadLetterRecord>>,
}

impl RecordingRetryStore {
    fn attempt(&self, receipt_id: &str) -> Option<crate::settlement_retry::SettleAttemptRecord> {
        self.attempts.lock().unwrap().get(receipt_id).cloned()
    }

    fn dead_letter_count(&self) -> usize {
        self.dead_letters.lock().unwrap().len()
    }
}

impl crate::settlement_retry::SettlementRetryStore for RecordingRetryStore {
    fn load_attempt(
        &self,
        receipt_id: &str,
    ) -> Result<
        Option<crate::settlement_retry::SettleAttemptRecord>,
        crate::settlement_retry::SettlementRetryError,
    > {
        Ok(self.attempt(receipt_id))
    }

    fn upsert_attempt(
        &self,
        record: &crate::settlement_retry::SettleAttemptRecord,
    ) -> Result<(), crate::settlement_retry::SettlementRetryError> {
        self.attempts
            .lock()
            .unwrap()
            .insert(record.receipt_id.clone(), record.clone());
        Ok(())
    }

    fn clear_attempt(
        &self,
        receipt_id: &str,
    ) -> Result<(), crate::settlement_retry::SettlementRetryError> {
        self.attempts.lock().unwrap().remove(receipt_id);
        Ok(())
    }

    fn insert_dead_letter(
        &self,
        record: &chio_settle::DeadLetterRecord,
    ) -> Result<bool, crate::settlement_retry::SettlementRetryError> {
        let mut letters = self.dead_letters.lock().unwrap();
        if letters
            .iter()
            .any(|existing| existing.receipt_id == record.receipt_id)
        {
            return Ok(false);
        }
        letters.push(record.clone());
        Ok(true)
    }

    fn due_attempts(
        &self,
        now_unix_secs: u64,
        limit: usize,
    ) -> Result<
        Vec<crate::settlement_retry::SettleAttemptRecord>,
        crate::settlement_retry::SettlementRetryError,
    > {
        let mut due: Vec<_> = self
            .attempts
            .lock()
            .unwrap()
            .values()
            .filter(|record| record.next_visible_at <= now_unix_secs)
            .cloned()
            .collect();
        due.sort_by_key(|record| record.next_visible_at);
        due.truncate(limit);
        Ok(due)
    }
}

struct RetryableSettlementHook;

impl chio_settle::SettlementHook for RetryableSettlementHook {
    fn observe(
        &self,
        _observation: &chio_settle::SettlementObservation,
    ) -> Result<chio_settle::SettlementOutcome, chio_settle::SettlementHookError> {
        Ok(chio_settle::SettlementOutcome::retryable(
            "rail temporarily unavailable",
        ))
    }
}

struct FailingSettlementHook;

impl chio_settle::SettlementHook for FailingSettlementHook {
    fn observe(
        &self,
        _observation: &chio_settle::SettlementObservation,
    ) -> Result<chio_settle::SettlementOutcome, chio_settle::SettlementHookError> {
        Err(chio_settle::SettlementHookError::Transient(
            "settlement rpc endpoint unreachable".to_string(),
        ))
    }
}

fn monetary_kernel_with_retry_store() -> (
    ChioKernel,
    std::sync::Arc<RecordingRetryStore>,
    CapabilityToken,
    Keypair,
) {
    let mut kernel = make_kernel(make_monetary_config());
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let retry_store = std::sync::Arc::new(RecordingRetryStore::default());
    kernel.set_settlement_retry_store(retry_store.clone());
    kernel
        .set_settlement_observer(std::sync::Arc::new(RetryableSettlementHook))
        .expect("observer install succeeds once the retry store is present");

    let agent_kp = Keypair::generate();
    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    (kernel, retry_store, cap, agent_kp)
}

fn priced_request(request_id: &str, cap: &CapabilityToken, agent: &Keypair) -> ToolCallRequest {
    ToolCallRequest {
        request_id: request_id.to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    }
}

#[test]
fn observer_install_without_a_retry_store_is_rejected() {
    let mut kernel = make_kernel(make_monetary_config());

    let error = kernel
        .set_settlement_observer(std::sync::Arc::new(RetryableSettlementHook))
        .expect_err("an observer without a durable retry store must be rejected at wiring time");
    assert!(
        matches!(error, KernelBuildError::MissingSettlementRetryStore),
        "the rejection must name the missing retry store: {error}"
    );
    assert!(
        error.to_string().contains("set_settlement_retry_store"),
        "the error must tell the embedder which call is missing: {error}"
    );
    assert!(
        kernel.settlement_observer().is_none(),
        "a rejected install must leave no observer wired"
    );

    // The same install succeeds once the durable sink is present.
    kernel.set_settlement_retry_store(std::sync::Arc::new(RecordingRetryStore::default()));
    kernel
        .set_settlement_observer(std::sync::Arc::new(RetryableSettlementHook))
        .expect("observer install succeeds once the retry store is present");
    assert!(kernel.settlement_observer().is_some());
}

#[test]
fn retryable_outcome_persists_a_bounded_attempt_row() {
    let (kernel, retry_store, cap, agent_kp) = monetary_kernel_with_retry_store();

    let response = kernel
        .evaluate_tool_call_blocking(&priced_request("req-settle-retry", &cap, &agent_kp))
        .unwrap();
    assert_eq!(response.verdict, Verdict::Allow);

    let attempt = retry_store
        .attempt(&response.receipt.id)
        .expect("retryable outcome must persist an attempt row");
    assert_eq!(attempt.attempts, 1);
    assert!(
        attempt.next_visible_at > attempt.finalized_at,
        "backoff must push visibility past finalization"
    );
    assert_eq!(retry_store.dead_letter_count(), 0);
}

#[test]
fn hook_failure_persists_a_bounded_attempt_row() {
    let mut kernel = make_kernel(make_monetary_config());
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let retry_store = std::sync::Arc::new(RecordingRetryStore::default());
    kernel.set_settlement_retry_store(retry_store.clone());
    kernel
        .set_settlement_observer(std::sync::Arc::new(FailingSettlementHook))
        .expect("observer install succeeds once the retry store is present");

    let agent_kp = Keypair::generate();
    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let response = kernel
        .evaluate_tool_call_blocking(&priced_request("req-settle-hook-err", &cap, &agent_kp))
        .unwrap();
    assert_eq!(response.verdict, Verdict::Allow);

    // The hook error consumed the same bounded envelope as a Retryable
    // outcome: a durable attempt row `chio settle drive` picks up, instead
    // of a warn-only log nothing ever retries.
    let attempt = retry_store
        .attempt(&response.receipt.id)
        .expect("a hook failure must persist a settle_attempts row");
    assert_eq!(attempt.attempts, 1);
    assert!(
        attempt.next_visible_at > attempt.finalized_at,
        "backoff must push visibility past finalization"
    );
    assert_eq!(retry_store.dead_letter_count(), 0);
}

#[test]
fn accepted_outcome_clears_the_attempt_row() {
    let (kernel, retry_store, cap, agent_kp) = monetary_kernel_with_retry_store();

    let response = kernel
        .evaluate_tool_call_blocking(&priced_request("req-settle-clear", &cap, &agent_kp))
        .unwrap();
    assert_eq!(response.verdict, Verdict::Allow);
    assert!(retry_store.attempt(&response.receipt.id).is_some());

    kernel
        .classify_and_persist(
            &response.receipt,
            &chio_settle::SettlementOutcome::accepted("ts-clear"),
        )
        .expect("accepted outcome resolves");
    assert!(
        retry_store.attempt(&response.receipt.id).is_none(),
        "accepted outcome must clear the bounded envelope"
    );
}

#[test]
fn permanent_outcome_dead_letters_exactly_once() {
    let (kernel, retry_store, cap, agent_kp) = monetary_kernel_with_retry_store();

    let response = kernel
        .evaluate_tool_call_blocking(&priced_request("req-settle-dl", &cap, &agent_kp))
        .unwrap();
    assert_eq!(response.verdict, Verdict::Allow);

    let outcome = chio_settle::SettlementOutcome::permanent("payee unresolvable");
    kernel
        .classify_and_persist(&response.receipt, &outcome)
        .expect("permanent outcome dead-letters");
    kernel
        .classify_and_persist(&response.receipt, &outcome)
        .expect("replayed dead-letter stays idempotent");

    assert_eq!(retry_store.dead_letter_count(), 1);
    assert!(
        retry_store.attempt(&response.receipt.id).is_none(),
        "dead-lettered receipts leave no live attempt row"
    );
}
