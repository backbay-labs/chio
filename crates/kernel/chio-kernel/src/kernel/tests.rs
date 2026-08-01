#![allow(deprecated)]

use crate::budget_store::{
    BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest,
    BudgetCancelCapturedBeforeDispatchRequest, BudgetCaptureInvocationRequest,
    BudgetCapturedBeforeDispatchCancellationDecision, BudgetInvocationCaptureDecision,
    BudgetMutationKind, BudgetReconcileHoldRequest, BudgetReleaseHoldRequest,
    BudgetReverseHoldRequest,
};

include!("tests/support.rs");
include!("tests/support_delegation_plain.rs");
include!("tests/support_budget_store_impls.rs");
include!("tests/support_monetary.rs");
include!("tests/settlement_routing.rs");
include!("tests/capability_validation.rs");
include!("tests/guard_pipeline.rs");
include!("tests/hot_path_deadlines.rs");
include!("tests/receipts.rs");
include!("tests/session.rs");
include!("tests/budget.rs");
include!("tests/budget_governed_fallback.rs");
include!("tests/budget_governed_call_chain.rs");
include!("tests/budget_governed_assurance.rs");
include!("tests/emergency.rs");
include!("tests/constraint_variants.rs");
include!("tests/plan_evaluation.rs");
include!("tests/approval_flow.rs");
include!("tests/execution_nonce_support.rs");
include!("tests/execution_nonce.rs");
include!("tests/session_nonce_binding.rs");
include!("tests/compliance_score.rs");
include!("tests/multi_tenant_receipt.rs");
include!("tests/memory_provenance.rs");
include!("tests/federation_cosign.rs");
include!("tests/revocation_durability.rs");
include!("tests/durable_admission.rs");
include!("tests/chio_runtime.rs");
include!("tests/drop_guard_proptest.rs");
include!("tests/formal_closure.rs");
include!("tests/sim_payment.rs");
