//! Property tests for IOU minting invariants.
//!
//! Asserts the core invariant that every finalized
//! `ChioReceipt` produces exactly one `IouEnvelope` (priced allow)
//! or zero (deny / cancelled / incomplete / zero-price / missing
//! financial metadata). No partial state.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_credit::crypto::{sha256_hex, Ed25519Backend, Keypair};
use chio_credit::receipt::{
    ChioReceipt, ChioReceiptBody, Decision, FinancialReceiptMetadata, GuardEvidence,
    SettlementStatus, ToolCallAction, TrustLevel,
};
use chio_credit::{CreditEvaluatorHook, LocalCreditAccount};
use proptest::prelude::*;

#[derive(Debug, Clone, Copy)]
enum DecisionShape {
    Allow,
    Deny,
    Cancelled,
    Incomplete,
}

#[derive(Debug, Clone)]
struct ReceiptScenario {
    receipt_id: String,
    timestamp: u64,
    cost_charged: u64,
    currency: String,
    has_financial_metadata: bool,
    decision: DecisionShape,
    tenant_id: Option<String>,
}

fn arb_decision() -> impl Strategy<Value = DecisionShape> {
    prop_oneof![
        Just(DecisionShape::Allow),
        Just(DecisionShape::Deny),
        Just(DecisionShape::Cancelled),
        Just(DecisionShape::Incomplete),
    ]
}

fn arb_scenario() -> impl Strategy<Value = ReceiptScenario> {
    (
        "[a-z]{4,12}",
        1_700_000_000_u64..1_800_000_000_u64,
        0_u64..10_000_u64,
        prop_oneof!["USD", "EUR", "GBP"],
        any::<bool>(),
        arb_decision(),
        proptest::option::of("[a-z]{3,8}"),
    )
        .prop_map(
            |(id_part, ts, cost, currency, has_meta, decision, tenant)| ReceiptScenario {
                receipt_id: format!("rcpt-{id_part}"),
                timestamp: ts,
                cost_charged: cost,
                currency: currency.to_string(),
                has_financial_metadata: has_meta,
                decision,
                tenant_id: tenant,
            },
        )
}

fn build_signed_receipt(scenario: &ReceiptScenario, kp: &Keypair) -> ChioReceipt {
    let decision = match scenario.decision {
        DecisionShape::Allow => Decision::Allow,
        DecisionShape::Deny => Decision::Deny {
            reason: "denied".to_string(),
            guard: "G".to_string(),
        },
        DecisionShape::Cancelled => Decision::Cancelled {
            reason: "cancelled".to_string(),
        },
        DecisionShape::Incomplete => Decision::Incomplete {
            reason: "incomplete".to_string(),
        },
    };
    let metadata = if scenario.has_financial_metadata {
        let financial = FinancialReceiptMetadata {
            grant_index: 0,
            cost_charged: scenario.cost_charged,
            currency: scenario.currency.clone(),
            budget_remaining: 1_000_000,
            budget_total: 1_000_000,
            delegation_depth: 1,
            root_budget_holder: scenario
                .tenant_id
                .clone()
                .unwrap_or_else(|| "root".to_string()),
            payment_reference: None,
            settlement_status: SettlementStatus::Pending,
            cost_breakdown: None,
            oracle_evidence: None,
            attempted_cost: None,
        };
        Some(serde_json::json!({"financial": financial}))
    } else {
        None
    };
    let body = ChioReceiptBody {
        id: scenario.receipt_id.clone(),
        timestamp: scenario.timestamp,
        capability_id: "cap".to_string(),
        tool_server: "srv".to_string(),
        tool_name: "tool".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({})).unwrap(),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        decision: Some(decision),
        content_hash: sha256_hex(b"{}"),
        policy_hash: "policy".to_string(),
        evidence: vec![GuardEvidence {
            guard_name: "G".to_string(),
            verdict: true,
            details: None,
        }],
        metadata,
        trust_level: TrustLevel::default(),
        tenant_id: scenario.tenant_id.clone(),
        kernel_key: kp.public_key(),
    };
    ChioReceipt::sign(body, kp).unwrap()
}

/// Byte-stability guard: evaluating the same receipt multiple times must not
/// mutate or re-serialize the receipt. Canonical bytes before and after must
/// be identical.
#[test]
fn hook_does_not_mutate_receipt_bytes() {
    use chio_credit::crypto::canonical_json_bytes;
    let kp = Keypair::generate();
    let account = LocalCreditAccount::new_with_trusted_kernel_keys(
        Ed25519Backend::new(kp.clone()),
        [kp.public_key()],
    );
    // A receipt without financial metadata: evaluates to None every round.
    let body = ChioReceiptBody {
        id: "rcpt-stability".to_string(),
        timestamp: 1_700_000_000,
        capability_id: "cap".to_string(),
        tool_server: "srv".to_string(),
        tool_name: "tool".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"k": "v"})).unwrap(),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        decision: Some(Decision::Allow),
        content_hash: sha256_hex(b"{}"),
        policy_hash: "policy".to_string(),
        evidence: vec![GuardEvidence {
            guard_name: "G".to_string(),
            verdict: true,
            details: None,
        }],
        metadata: None,
        trust_level: TrustLevel::default(),
        tenant_id: None,
        kernel_key: kp.public_key(),
    };
    let receipt = ChioReceipt::sign(body, &kp).unwrap();
    let baseline = canonical_json_bytes(&receipt).unwrap();
    for _ in 0..5 {
        assert!(account.evaluate(&receipt).unwrap().is_none());
    }
    assert_eq!(
        baseline,
        canonical_json_bytes(&receipt).unwrap(),
        "receipt canonical bytes must be unchanged after repeated hook evaluation"
    );
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    /// Every finalized receipt mints exactly one IOU (when the
    /// scenario has Allow decision plus non-zero financial metadata)
    /// or zero (in every other case). Never two; never a malformed
    /// envelope.
    #[test]
    fn one_receipt_mints_zero_or_one_iou(scenario in arb_scenario()) {
        let kp = Keypair::generate();
        let account = LocalCreditAccount::new_with_trusted_kernel_keys(Ed25519Backend::new(kp.clone()), [kp.public_key()]);
        let receipt = build_signed_receipt(&scenario, &kp);

        let outcome = account.evaluate(&receipt).unwrap();

        let expects_iou = matches!(scenario.decision, DecisionShape::Allow)
            && scenario.has_financial_metadata
            && scenario.cost_charged > 0;

        if expects_iou {
            let envelope = outcome.expect("priced allow receipt mints exactly one IOU");
            prop_assert_eq!(envelope.body.amount_units, scenario.cost_charged);
            prop_assert_eq!(&envelope.body.currency, &scenario.currency);
            prop_assert_eq!(&envelope.body.receipt_id, &receipt.id);
            prop_assert_eq!(envelope.body.receipt_timestamp, scenario.timestamp);
            prop_assert_eq!(envelope.body.tenant_id.clone(), scenario.tenant_id.clone());
            prop_assert!(envelope.verify_signature().unwrap());

            // Re-evaluation is idempotent: same envelope, same id.
            let again = account.evaluate(&receipt).unwrap().unwrap();
            prop_assert_eq!(again, envelope);
        } else {
            prop_assert!(outcome.is_none(), "non-priced or non-allow receipt must mint zero IOUs");
        }
    }

    /// Tampering with a signed receipt must produce zero IOUs and a
    /// SignatureInvalid error. The receipt input itself is never
    /// mutated by the hook.
    #[test]
    fn tampered_receipt_mints_zero_iou(scenario in arb_scenario()) {
        let kp = Keypair::generate();
        let account = LocalCreditAccount::new_with_trusted_kernel_keys(Ed25519Backend::new(kp.clone()), [kp.public_key()]);
        let mut receipt = build_signed_receipt(&scenario, &kp);
        // Mutate a signed field to invalidate the signature.
        receipt.tool_name = format!("{}-tampered", receipt.tool_name);

        let result = account.evaluate(&receipt);
        prop_assert!(result.is_err(), "tampered receipt must fail closed");
    }
}
