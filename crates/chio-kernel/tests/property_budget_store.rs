#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core::{
    crypto::Keypair,
    receipt::{
        ChioReceipt, ChioReceiptBody, FinancialBudgetAuthorityReceiptMetadata,
        FinancialBudgetAuthorizeReceiptMetadata, FinancialBudgetHoldAuthorityMetadata,
        FinancialBudgetTerminalReceiptMetadata, FinancialReceiptMetadata, SettlementStatus,
        ToolCallAction,
    },
};
use chio_kernel::{BudgetStore, BudgetStoreError, InMemoryBudgetStore};
use proptest::prelude::*;
use proptest::test_runner::Config as ProptestConfig;

const CAPABILITY_ID: &str = "cap-property";
const GRANT_INDEX: usize = 0;
const MAX_INVOCATIONS: Option<u32> = Some(8);
const MAX_COST_PER_INVOCATION: Option<u64> = Some(32);
const MAX_TOTAL_COST: Option<u64> = Some(128);

#[derive(Debug, Clone)]
enum BudgetOp {
    Charge(u16),
    Reduce(u16),
    Reverse(u16),
}

#[derive(Debug, Clone, Default)]
struct BudgetModel {
    present: bool,
    invocation_count: u32,
    committed_cost_units: u64,
    seq: u64,
    next_seq: u64,
}

impl BudgetModel {
    fn allocate_event_seq(&mut self) -> u64 {
        let event_seq = self.next_seq.saturating_add(1);
        self.next_seq = event_seq;
        event_seq
    }

    fn try_charge_cost(
        &mut self,
        cost_units: u64,
        max_invocations: Option<u32>,
        max_cost_per_invocation: Option<u64>,
        max_total_cost: Option<u64>,
    ) -> Result<bool, &'static str> {
        if let Some(max) = max_invocations {
            if self.invocation_count >= max {
                self.allocate_event_seq();
                return Ok(false);
            }
        }

        if let Some(max) = max_cost_per_invocation {
            if cost_units > max {
                self.allocate_event_seq();
                return Ok(false);
            }
        }

        let new_total = self
            .committed_cost_units
            .checked_add(cost_units)
            .ok_or("overflow")?;
        if let Some(max_total) = max_total_cost {
            if new_total > max_total {
                self.allocate_event_seq();
                return Ok(false);
            }
        }

        self.invocation_count = self.invocation_count.saturating_add(1);
        self.committed_cost_units = new_total;
        self.present = true;
        self.seq = self.allocate_event_seq();
        Ok(true)
    }

    fn reverse_charge_cost(&mut self, cost_units: u64) -> Result<(), &'static str> {
        if !self.present {
            return Err("invariant");
        }
        if self.invocation_count == 0 {
            return Err("invariant");
        }
        if self.committed_cost_units < cost_units {
            return Err("invariant");
        }

        self.invocation_count -= 1;
        self.committed_cost_units -= cost_units;
        self.seq = self.allocate_event_seq();
        Ok(())
    }

    fn reduce_charge_cost(&mut self, cost_units: u64) -> Result<(), &'static str> {
        if !self.present {
            return Err("invariant");
        }
        if self.committed_cost_units < cost_units {
            return Err("invariant");
        }

        self.committed_cost_units -= cost_units;
        self.seq = self.allocate_event_seq();
        Ok(())
    }
}

fn budget_op_strategy() -> impl Strategy<Value = BudgetOp> {
    prop_oneof![
        (0u16..64).prop_map(BudgetOp::Charge),
        (0u16..64).prop_map(BudgetOp::Reduce),
        (0u16..64).prop_map(BudgetOp::Reverse),
    ]
}

fn error_kind(error: &BudgetStoreError) -> &'static str {
    match error {
        BudgetStoreError::Overflow(_) => "overflow",
        BudgetStoreError::Invariant(_) => "invariant",
        BudgetStoreError::Sqlite(_) => "sqlite",
        BudgetStoreError::Io(_) => "io",
    }
}

fn assert_charge_result_matches(
    actual: Result<bool, BudgetStoreError>,
    expected: Result<bool, &'static str>,
) {
    match (actual, expected) {
        (Ok(actual), Ok(expected)) => assert_eq!(actual, expected),
        (Err(actual), Err(expected)) => assert_eq!(error_kind(&actual), expected),
        (actual, expected) => {
            panic!("charge result mismatch: actual={actual:?}, expected={expected:?}")
        }
    }
}

fn assert_unit_result_matches(
    actual: Result<(), BudgetStoreError>,
    expected: Result<(), &'static str>,
) {
    match (actual, expected) {
        (Ok(actual), Ok(expected)) => assert_eq!(actual, expected),
        (Err(actual), Err(expected)) => assert_eq!(error_kind(&actual), expected),
        (actual, expected) => {
            panic!("mutation result mismatch: actual={actual:?}, expected={expected:?}")
        }
    }
}

fn assert_store_matches_model(store: &InMemoryBudgetStore, model: &BudgetModel) {
    let usage = store.get_usage(CAPABILITY_ID, GRANT_INDEX).unwrap();
    if !model.present {
        assert!(usage.is_none());
        return;
    }

    let usage = usage.expect("budget row should exist");
    assert_eq!(usage.capability_id, CAPABILITY_ID);
    assert_eq!(usage.grant_index, GRANT_INDEX as u32);
    assert_eq!(usage.invocation_count, model.invocation_count);
    assert_eq!(
        usage.committed_cost_units().unwrap(),
        model.committed_cost_units
    );
    assert_eq!(usage.seq, model.seq);
}

#[test]
fn financial_receipt_carries_hold_lineage_and_guarantee_level() {
    let keypair = Keypair::generate();
    let financial = FinancialReceiptMetadata {
        grant_index: 0,
        cost_charged: 75,
        currency: "USD".to_string(),
        budget_remaining: 925,
        budget_total: 1_000,
        delegation_depth: 1,
        root_budget_holder: "agent-root-001".to_string(),
        payment_reference: None,
        settlement_status: SettlementStatus::Settled,
        cost_breakdown: None,
        oracle_evidence: None,
        attempted_cost: None,
    };
    let budget_authority = FinancialBudgetAuthorityReceiptMetadata {
        guarantee_level: "ha_quorum_commit".to_string(),
        authority_profile: "authoritative_hold_event".to_string(),
        metering_profile: "max_cost_preauthorize_then_reconcile_actual".to_string(),
        hold_id: "budget-hold:req-1:cap-property:0".to_string(),
        budget_term: Some("http://leader-a:7".to_string()),
        authority: Some(FinancialBudgetHoldAuthorityMetadata {
            authority_id: "http://leader-a".to_string(),
            lease_id: "http://leader-a#term-7".to_string(),
            lease_epoch: 7,
        }),
        authorize: FinancialBudgetAuthorizeReceiptMetadata {
            event_id: Some("budget-hold:req-1:cap-property:0:authorize".to_string()),
            budget_commit_index: Some(41),
            exposure_units: 120,
            committed_cost_units_after: 120,
        },
        terminal: Some(FinancialBudgetTerminalReceiptMetadata {
            disposition: "reconciled".to_string(),
            event_id: Some("budget-hold:req-1:cap-property:0:reconcile".to_string()),
            budget_commit_index: Some(42),
            exposure_units: 120,
            realized_spend_units: 75,
            committed_cost_units_after: 75,
        }),
    };
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "rcpt-budget-lineage-1".to_string(),
            timestamp: 1_710_000_000,
            capability_id: CAPABILITY_ID.to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({"command": "true"}))
                .expect("build action"),
            decision: chio_core::receipt::Decision::Allow,
            content_hash: "content-hash-1".to_string(),
            policy_hash: "policy-hash-1".to_string(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "financial": financial.clone(),
                "budget_authority": budget_authority.clone(),
            })),
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .expect("sign receipt");

    let extracted_financial = receipt
        .financial_metadata()
        .expect("extract financial metadata");
    assert_eq!(extracted_financial.grant_index, financial.grant_index);
    assert_eq!(extracted_financial.cost_charged, financial.cost_charged);
    assert_eq!(extracted_financial.currency, financial.currency);
    assert_eq!(
        extracted_financial.budget_remaining,
        financial.budget_remaining
    );
    assert_eq!(extracted_financial.budget_total, financial.budget_total);
    assert_eq!(
        extracted_financial.root_budget_holder,
        financial.root_budget_holder
    );
    let extracted = receipt
        .financial_budget_authority_metadata()
        .expect("extract budget authority");
    assert_eq!(extracted.guarantee_level, "ha_quorum_commit");
    assert_eq!(extracted.hold_id, "budget-hold:req-1:cap-property:0");
    assert_eq!(extracted.budget_term.as_deref(), Some("http://leader-a:7"));
    assert_eq!(
        extracted
            .authority
            .as_ref()
            .map(|authority| authority.authority_id.as_str()),
        Some("http://leader-a")
    );
    assert_eq!(
        extracted.authorize.event_id.as_deref(),
        Some("budget-hold:req-1:cap-property:0:authorize")
    );
    assert_eq!(
        extracted
            .terminal
            .as_ref()
            .and_then(|terminal| terminal.event_id.as_deref()),
        Some("budget-hold:req-1:cap-property:0:reconcile")
    );
}

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: None,
        .. ProptestConfig::default()
    })]

    #[test]
    fn budget_store_matches_reference_model_under_random_operation_sequences(
        operations in proptest::collection::vec(budget_op_strategy(), 1..64),
    ) {
        let store = InMemoryBudgetStore::new();
        let mut model = BudgetModel::default();

        for operation in operations {
            match operation {
                BudgetOp::Charge(cost_units) => {
                    let actual = store.try_charge_cost(
                        CAPABILITY_ID,
                        GRANT_INDEX,
                        MAX_INVOCATIONS,
                        u64::from(cost_units),
                        MAX_COST_PER_INVOCATION,
                        MAX_TOTAL_COST,
                    );
                    let expected = model.try_charge_cost(
                        u64::from(cost_units),
                        MAX_INVOCATIONS,
                        MAX_COST_PER_INVOCATION,
                        MAX_TOTAL_COST,
                    );
                    assert_charge_result_matches(actual, expected);
                }
                BudgetOp::Reduce(cost_units) => {
                    let actual = store.reduce_charge_cost(
                        CAPABILITY_ID,
                        GRANT_INDEX,
                        u64::from(cost_units),
                    );
                    let expected = model.reduce_charge_cost(u64::from(cost_units));
                    assert_unit_result_matches(actual, expected);
                }
                BudgetOp::Reverse(cost_units) => {
                    let actual = store.reverse_charge_cost(
                        CAPABILITY_ID,
                        GRANT_INDEX,
                        u64::from(cost_units),
                    );
                    let expected = model.reverse_charge_cost(u64::from(cost_units));
                    assert_unit_result_matches(actual, expected);
                }
            }

            assert_store_matches_model(&store, &model);
        }
    }

    #[test]
    fn total_cost_overflow_is_reported_before_state_wraps(
        slack in 0u16..=1024,
        overflow_by in 1u16..=1024,
    ) {
        let store = InMemoryBudgetStore::new();
        let first_charge = u64::MAX - u64::from(slack);
        let second_charge = u64::from(slack) + u64::from(overflow_by);

        let accepted = store.try_charge_cost(
            CAPABILITY_ID,
            GRANT_INDEX,
            Some(4),
            first_charge,
            None,
            Some(u64::MAX),
        ).unwrap();
        prop_assert!(accepted);

        let overflow = store.try_charge_cost(
            CAPABILITY_ID,
            GRANT_INDEX,
            Some(4),
            second_charge,
            None,
            Some(u64::MAX),
        );
        prop_assert!(matches!(overflow, Err(BudgetStoreError::Overflow(_))));

        let usage = store.get_usage(CAPABILITY_ID, GRANT_INDEX).unwrap().unwrap();
        prop_assert_eq!(usage.invocation_count, 1);
        prop_assert_eq!(usage.committed_cost_units().unwrap(), first_charge);
        prop_assert_eq!(usage.seq, 1);
    }
}
