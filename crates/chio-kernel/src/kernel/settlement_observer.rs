//! Settlement observer slot wired into the kernel evaluator.
//!
//! Plugs `chio-settle::SettlementHook` into the kernel's post-dispatch
//! observer surface. The observer is consulted only after a receipt has
//! been fully signed and durably stored: settlement is observer-only
//! relative to the receipt bytes, and a hook failure NEVER blocks the
//! dispatch path.
//!
//! The kernel field [`ChioKernel::settlement_observer`] holds an
//! optional handle; deployments that do not wire a settlement runtime
//! see byte-identical receipts (an integration test enforces this
//! invariant explicitly).

use std::sync::Arc;

use chio_core::crypto::PublicKey;
use chio_core::receipt::ChioReceipt;
use chio_settle::{SettlementHook, SettlementHookError, SettlementObservation, SettlementOutcome};

/// Schema string emitted on the wire for settlement-observer status frames.
/// Public so external observers can pin against the same identifier the
/// kernel records.
#[allow(dead_code)]
pub const SETTLEMENT_OBSERVER_STATUS_SCHEMA: &str = "chio.settle.observer-status.v1";

/// Status the kernel records for each settlement observer invocation.
///
/// Settlement runs post-dispatch: regardless of which variant lands,
/// the receipt has already been signed and persisted. The variants
/// document only what the observer slot did with the hook's return,
/// not whether the receipt committed (it always committed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettlementObserverStatus {
    /// No settlement hook is registered on this kernel; the observation
    /// was not produced.
    NotRegistered,
    /// The receipt was either zero-priced or otherwise outside the
    /// marketplace surface; the kernel produced no observation. This
    /// is the steady-state for non-economic deployments.
    Skipped { reason: String },
    /// The hook accepted the observation and returned an outcome
    /// classification. The downstream lifecycle is then driven by the
    /// retry policy and dead-letter machinery.
    Observed { outcome: SettlementOutcome },
    /// The hook surfaced an error. Settlement runs on the post-dispatch
    /// task, so this is recorded but never propagated back to the
    /// dispatch path. The error is routed through retry/dead-letter
    /// classification.
    HookFailed { error: String },
}

impl SettlementObserverStatus {
    /// Construct a `Skipped` status with a documented reason string.
    #[must_use]
    pub fn skipped(reason: impl Into<String>) -> Self {
        Self::Skipped {
            reason: reason.into(),
        }
    }

    /// Construct a `HookFailed` status from a [`SettlementHookError`].
    #[must_use]
    pub fn hook_failed(err: &SettlementHookError) -> Self {
        Self::HookFailed {
            error: err.to_string(),
        }
    }
}

/// Build a [`SettlementObservation`] for a freshly signed receipt.
///
/// Returns `None` when the receipt does not warrant an observation
/// (currently: missing manifest pricing context, zero-priced
/// invocations, or non-allow decisions). The kernel observer slot
/// invokes a registered hook only when this returns `Some`.
///
/// The receipt's financial metadata is the `FinancialReceiptMetadata`
/// shape (`cost_charged`, `currency`, `attempted_cost`) under
/// `metadata.financial.*`.
#[must_use]
fn build_observation_unchecked(receipt: &ChioReceipt) -> Option<SettlementObservation> {
    if !receipt.verify_signature().ok()? {
        return None;
    }
    if !receipt.action.verify_hash().ok()? {
        return None;
    }
    if !receipt.is_allowed() {
        return None;
    }

    let financial = receipt.metadata.as_ref().and_then(|metadata| {
        metadata
            .get("financial")
            .and_then(|value| value.as_object())
    })?;

    // Financial metadata uses the `FinancialReceiptMetadata` shape.
    let monetary = financial.get("cost_charged").and_then(|cc| {
        let units = cc.as_u64()?;
        let currency = financial.get("currency")?.as_str()?.to_string();
        Some(chio_core::capability::MonetaryAmount { currency, units })
    })?;

    if monetary.units == 0 {
        return None;
    }

    let observation = SettlementObservation::new(
        receipt.id.clone(),
        receipt.timestamp,
        receipt.tool_server.clone(),
        receipt.tool_name.clone(),
        receipt.capability_id.clone(),
        monetary,
        receipt.content_hash.clone(),
        receipt.policy_hash.clone(),
    );

    Some(if let Some(tenant_id) = receipt.tenant_id.clone() {
        observation.with_tenant(tenant_id)
    } else {
        observation
    })
}

/// Build an observation only when the receipt signer is explicitly trusted.
#[must_use]
pub fn build_observation(
    receipt: &ChioReceipt,
    trusted_kernel_keys: &[PublicKey],
) -> Option<SettlementObservation> {
    if trusted_kernel_keys.is_empty()
        || !trusted_kernel_keys
            .iter()
            .any(|trusted| trusted == &receipt.kernel_key)
    {
        return None;
    }
    build_observation_unchecked(receipt)
}

/// Build an observation only when the receipt signer is explicitly trusted.
#[must_use]
pub fn build_observation_with_trusted_signers(
    receipt: &ChioReceipt,
    trusted_kernel_keys: &[PublicKey],
) -> Option<SettlementObservation> {
    build_observation(receipt, trusted_kernel_keys)
}

/// Run the registered settlement hook against a freshly signed receipt.
///
/// Settlement is observer-only relative to receipt bytes: the receipt
/// has already been signed and persisted before this function runs,
/// and the returned status NEVER feeds back into the dispatch path.
/// The function is plumbed through the kernel struct in
/// [`super::ChioKernel::run_settlement_observer`] so callers only
/// need the kernel handle.
#[must_use]
pub fn run_observer(
    hook: Option<&Arc<dyn SettlementHook>>,
    receipt: &ChioReceipt,
    trusted_kernel_keys: &[PublicKey],
) -> SettlementObserverStatus {
    let Some(hook) = hook else {
        return SettlementObserverStatus::NotRegistered;
    };

    let Some(observation) = build_observation_with_trusted_signers(receipt, trusted_kernel_keys)
    else {
        return SettlementObserverStatus::skipped("receipt outside marketplace surface");
    };

    match hook.observe(&observation) {
        Ok(outcome) => SettlementObserverStatus::Observed { outcome },
        Err(error) => SettlementObserverStatus::hook_failed(&error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chio_core::capability::MonetaryAmount;
    use chio_core::crypto::Keypair;
    use chio_core::receipt::{
        ChioReceiptBody, Decision, GuardEvidence, ToolCallAction, TrustLevel,
    };

    fn sign_with(body_metadata: serde_json::Value, decision: Decision) -> ChioReceipt {
        let action = ToolCallAction::from_parameters(serde_json::json!({}))
            .expect("test tool-call action constructs");
        sign_with_action(body_metadata, decision, action)
    }

    fn sign_with_action(
        body_metadata: serde_json::Value,
        decision: Decision,
        action: ToolCallAction,
    ) -> ChioReceipt {
        let kp = Keypair::generate();
        let body = ChioReceiptBody {
            id: "rcpt-test".to_string(),
            timestamp: 100,
            capability_id: "cap-1".to_string(),
            tool_server: "srv-1".to_string(),
            tool_name: "tool-1".to_string(),
            action,
            decision: Some(decision),
            receipt_kind: chio_core::ReceiptKind::MediatedDecision,
            boundary_class: chio_core::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core::RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: "ch-1".to_string(),
            policy_hash: "ph-1".to_string(),
            evidence: vec![GuardEvidence {
                guard_name: "G".to_string(),
                verdict: true,
                details: None,
            }],
            metadata: Some(body_metadata),
            trust_level: TrustLevel::default(),
            tenant_id: None,
            kernel_key: kp.public_key(),
        };
        ChioReceipt::sign(body, &kp).expect("test receipt signs")
    }

    struct AcceptingHook;
    impl SettlementHook for AcceptingHook {
        fn observe(
            &self,
            observation: &SettlementObservation,
        ) -> Result<SettlementOutcome, SettlementHookError> {
            Ok(SettlementOutcome::accepted(format!(
                "ts-{}",
                observation.receipt_id
            )))
        }
    }

    struct FailingHook;
    impl SettlementHook for FailingHook {
        fn observe(
            &self,
            _observation: &SettlementObservation,
        ) -> Result<SettlementOutcome, SettlementHookError> {
            Err(SettlementHookError::Transient("rpc lag".to_string()))
        }
    }

    #[test]
    fn build_observation_skips_non_allow_decisions() {
        let receipt = sign_with(
            serde_json::json!({
                "financial": {"cost_charged": 100, "currency": "USD"}
            }),
            Decision::Deny {
                reason: "denied".to_string(),
                guard: "G".to_string(),
            },
        );
        assert!(build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key)).is_none());
    }

    #[test]
    fn build_observation_skips_zero_priced_receipts() {
        let receipt = sign_with(
            serde_json::json!({
                "financial": {"cost_charged": 0, "currency": "USD"}
            }),
            Decision::Allow,
        );
        assert!(build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key)).is_none());
    }

    #[test]
    fn build_observation_skips_when_metadata_missing_financial_section() {
        let receipt = sign_with(serde_json::json!({}), Decision::Allow);
        assert!(build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key)).is_none());
    }

    #[test]
    fn build_observation_skips_invalid_signature() {
        let mut receipt = sign_with(
            serde_json::json!({
                "financial": {"cost_charged": 250, "currency": "USD"}
            }),
            Decision::Allow,
        );
        receipt.tool_name = "tampered".to_string();
        assert!(build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key)).is_none());
    }

    #[test]
    fn build_observation_skips_mismatched_action_hash() {
        let mut action = ToolCallAction::from_parameters(serde_json::json!({"path": "/tmp/a"}))
            .expect("test tool-call action constructs");
        action.parameters = serde_json::json!({"path": "/tmp/b"});
        let receipt = sign_with_action(
            serde_json::json!({
                "financial": {"cost_charged": 250, "currency": "USD"}
            }),
            Decision::Allow,
            action,
        );
        assert!(build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key)).is_none());
    }

    #[test]
    fn build_observation_constructs_priced_frame() {
        let receipt = sign_with(
            serde_json::json!({
                "financial": {"cost_charged": 250, "currency": "USD"}
            }),
            Decision::Allow,
        );
        let observation = build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key))
            .expect("priced receipt yields observation");
        assert_eq!(observation.receipt_id, receipt.id);
        assert_eq!(observation.finalized_at, 100);
        assert_eq!(
            observation.amount,
            MonetaryAmount {
                currency: "USD".to_string(),
                units: 250,
            }
        );
        assert_eq!(observation.content_hash, "ch-1");
    }

    #[test]
    fn build_observation_rejects_untrusted_signer() {
        let receipt = sign_with(
            serde_json::json!({
                "financial": {"cost_charged": 250, "currency": "USD"}
            }),
            Decision::Allow,
        );
        assert!(build_observation(&receipt, &[]).is_none());
    }

    #[test]
    fn run_observer_returns_not_registered_without_hook() {
        let receipt = sign_with(
            serde_json::json!({
                "financial": {"cost_charged": 250, "currency": "USD"}
            }),
            Decision::Allow,
        );
        let status = run_observer(None, &receipt, std::slice::from_ref(&receipt.kernel_key));
        assert!(matches!(status, SettlementObserverStatus::NotRegistered));
    }

    #[test]
    fn run_observer_records_hook_outcome() {
        let receipt = sign_with(
            serde_json::json!({
                "financial": {"cost_charged": 250, "currency": "USD"}
            }),
            Decision::Allow,
        );
        let hook: Arc<dyn SettlementHook> = Arc::new(AcceptingHook);
        let status = run_observer(
            Some(&hook),
            &receipt,
            std::slice::from_ref(&receipt.kernel_key),
        );
        match status {
            SettlementObserverStatus::Observed {
                outcome: SettlementOutcome::Accepted { transcript_id, .. },
            } => assert_eq!(transcript_id, format!("ts-{}", receipt.id)),
            other => panic!("expected accepted outcome, got {other:?}"),
        }
    }

    #[test]
    fn run_observer_skips_zero_price_without_invoking_hook() {
        let receipt = sign_with(
            serde_json::json!({
                "financial": {"cost_charged": 0, "currency": "USD"}
            }),
            Decision::Allow,
        );
        let hook: Arc<dyn SettlementHook> = Arc::new(FailingHook);
        let status = run_observer(
            Some(&hook),
            &receipt,
            std::slice::from_ref(&receipt.kernel_key),
        );
        assert!(matches!(status, SettlementObserverStatus::Skipped { .. }));
    }

    #[test]
    fn build_observation_reads_canonical_financial_metadata() {
        // The kernel canonical financial-metadata shape is
        // `FinancialReceiptMetadata` (`cost_charged`, `currency`,
        // `attempted_cost`). Receipts emitted by the kernel's normal
        // finalize path use this shape, so the settlement observer
        // MUST recognize it.
        let receipt = sign_with(
            serde_json::json!({
                "financial": {
                    "grant_index": 0,
                    "cost_charged": 250,
                    "currency": "USD",
                    "budget_remaining": 750,
                    "budget_total": 1000,
                    "delegation_depth": 1,
                    "root_budget_holder": "tenant-a",
                    "settlement_status": "pending"
                }
            }),
            Decision::Allow,
        );
        let observation = build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key))
            .expect("canonical FinancialReceiptMetadata shape yields observation");
        assert_eq!(observation.amount.units, 250);
        assert_eq!(observation.amount.currency, "USD");
    }

    #[test]
    fn build_observation_skips_zero_cost_charged() {
        let receipt = sign_with(
            serde_json::json!({
                "financial": {
                    "cost_charged": 0,
                    "currency": "USD"
                }
            }),
            Decision::Allow,
        );
        assert!(build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key)).is_none());
    }

    #[test]
    fn run_observer_records_hook_failures_without_panicking() {
        let receipt = sign_with(
            serde_json::json!({
                "financial": {"cost_charged": 250, "currency": "USD"}
            }),
            Decision::Allow,
        );
        let hook: Arc<dyn SettlementHook> = Arc::new(FailingHook);
        let status = run_observer(
            Some(&hook),
            &receipt,
            std::slice::from_ref(&receipt.kernel_key),
        );
        assert!(matches!(
            status,
            SettlementObserverStatus::HookFailed { .. }
        ));
    }
}
