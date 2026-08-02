use std::sync::{Arc, Mutex};

use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::Keypair;

use super::*;
use crate::{
    HotPathDeadlineConfig, KernelConfig, MemoryBudgetConfig, DEFAULT_CHECKPOINT_BATCH_SIZE,
    DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
};

#[derive(Default)]
struct RecordingLedger {
    decisions: Mutex<Vec<FindingPoolTerminalDecision>>,
}

impl FindingPoolLedger for RecordingLedger {
    fn contains_purchase(&self, _purchase_id: &str) -> Result<bool, FindingPoolLedgerError> {
        Ok(true)
    }

    fn debit(
        &self,
        _debit: &AuthorizedFindingPoolDebit,
    ) -> Result<FindingPoolDebitReceipt, FindingPoolLedgerError> {
        Err(FindingPoolLedgerError::Storage(
            "unexpected test debit".to_owned(),
        ))
    }

    fn settle(
        &self,
        terminal: &AuthorizedFindingPoolTerminal,
    ) -> Result<FindingPoolDebitReceipt, FindingPoolLedgerError> {
        let Ok(mut decisions) = self.decisions.lock() else {
            return Err(FindingPoolLedgerError::Storage(
                "test decision lock was poisoned".to_owned(),
            ));
        };
        decisions.push(terminal.decision());
        Ok(FindingPoolDebitReceipt {
            purchase_id: terminal.purchase_id().to_owned(),
            allocation_id: "allocation:test".to_owned(),
            allocation_envelope_sha256: "a".repeat(64),
            amount_units: terminal.amount_units(),
            currency: terminal.currency().to_owned(),
            state: match terminal.decision() {
                FindingPoolTerminalDecision::Finalize => FindingPoolDebitState::Finalized,
                FindingPoolTerminalDecision::Release => FindingPoolDebitState::Released,
            },
            reserved_after_units: 0,
            spent_after_units: terminal.amount_units(),
            remaining_after_units: 0,
            replayed: false,
        })
    }
}

impl QualifiedFindingPoolLedger for RecordingLedger {}

fn kernel_with_ledger(ledger: Arc<RecordingLedger>) -> ChioKernel {
    let mut kernel = ChioKernel::new(KernelConfig {
        keypair: Keypair::from_seed(&[91_u8; 32]),
        ca_public_keys: Vec::new(),
        max_delegation_depth: 1,
        policy_hash: "finding-pool-terminal-test".to_owned(),
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
        memory_budget: MemoryBudgetConfig::defaults(),
        deadlines: HotPathDeadlineConfig::default(),
    });
    assert!(kernel.set_finding_pool_ledger(ledger).is_ok());
    kernel
}

fn purchase() -> crate::finding_purchase::VerifiedFindingPurchase {
    crate::finding_purchase::VerifiedFindingPurchase {
        finding_id: "b".repeat(64),
        listing_id: "listing:test".to_owned(),
        payload_sha256: "c".repeat(64),
        payload_media_type: "application/json".to_owned(),
        accepted_price: MonetaryAmount {
            units: 25,
            currency: "USD".to_owned(),
        },
        payer_key_hex: "d".repeat(64),
        reservation_id: "reservation:test".to_owned(),
        purchase_intent_id: "purchase:test".to_owned(),
        authoritative_payment_operation_id: "payment:test".to_owned(),
        accepted_bid_envelope_sha256: "e".repeat(64),
        venue_admission_envelope_sha256: "f".repeat(64),
        status_proof: None,
    }
}

#[test]
fn delivery_capture_finalizes_the_configured_pool_reservation() {
    let ledger = Arc::new(RecordingLedger::default());
    let kernel = kernel_with_ledger(Arc::clone(&ledger));
    let result = kernel.settle_finding_pool_delivery(
        &purchase(),
        &crate::tool_outcome::SettlementDispositionV1::Capture {
            amount: MonetaryAmount {
                units: 25,
                currency: "USD".to_owned(),
            },
        },
    );
    assert!(result.is_ok());
    let Ok(decisions) = ledger.decisions.lock() else {
        panic!("test decision lock was poisoned");
    };
    assert_eq!(
        decisions.as_slice(),
        &[FindingPoolTerminalDecision::Finalize]
    );
}

#[test]
fn delivery_zero_charge_releases_the_configured_pool_reservation() {
    let ledger = Arc::new(RecordingLedger::default());
    let kernel = kernel_with_ledger(Arc::clone(&ledger));
    let result = kernel.settle_finding_pool_delivery(
        &purchase(),
        &crate::tool_outcome::SettlementDispositionV1::ContractualZeroCharge {
            currency: "USD".to_owned(),
        },
    );
    assert!(result.is_ok());
    let Ok(decisions) = ledger.decisions.lock() else {
        panic!("test decision lock was poisoned");
    };
    assert_eq!(
        decisions.as_slice(),
        &[FindingPoolTerminalDecision::Release]
    );
}

#[test]
fn pool_terminal_rejects_a_divergent_settlement_amount() {
    let ledger = Arc::new(RecordingLedger::default());
    let kernel = kernel_with_ledger(Arc::clone(&ledger));
    let result = kernel.settle_finding_pool_delivery(
        &purchase(),
        &crate::tool_outcome::SettlementDispositionV1::Capture {
            amount: MonetaryAmount {
                units: 24,
                currency: "USD".to_owned(),
            },
        },
    );
    assert_eq!(result, Err(FindingPoolLedgerError::TerminalConflict));
    let Ok(decisions) = ledger.decisions.lock() else {
        panic!("test decision lock was poisoned");
    };
    assert!(decisions.is_empty());
}
