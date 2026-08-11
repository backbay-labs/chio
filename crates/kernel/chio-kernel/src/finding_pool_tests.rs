use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};

use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::Keypair;
use chio_core::receipt::lineage::ChildRequestReceipt;

use super::*;
use crate::receipt_store::{ReceiptStore, ReceiptStoreError};
use crate::{
    HotPathDeadlineConfig, KernelConfig, MemoryBudgetConfig, DEFAULT_CHECKPOINT_BATCH_SIZE,
    DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
};

#[derive(Default)]
pub(crate) struct RecordingLedger {
    decisions: Mutex<Vec<FindingPoolTerminalDecision>>,
    claims: Mutex<Vec<(String, u64)>>,
    active_claim_operations: Mutex<Vec<String>>,
    recovery_releases: Mutex<Vec<String>>,
    unknown_dispatch_finalizations: Mutex<Vec<String>>,
    outbox: Mutex<Vec<ChioReceipt>>,
    acknowledged: Mutex<Vec<String>>,
    delivery_claims: Mutex<Vec<(String, String, u64)>>,
    receipt_authority: Mutex<Option<chio_core::crypto::PublicKey>>,
    delay_pending_reads: AtomicBool,
    active_pending_reads: AtomicUsize,
    max_active_pending_reads: AtomicUsize,
}

impl RecordingLedger {
    pub(crate) fn unknown_dispatch_finalizations(&self) -> Vec<String> {
        self.unknown_dispatch_finalizations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn pending_mutation_receipts(&self) -> Result<Vec<ChioReceipt>, FindingPoolLedgerError> {
        let outbox = self.outbox.lock().map_err(|_| {
            FindingPoolLedgerError::Storage("test outbox lock was poisoned".to_owned())
        })?;
        let acknowledged = self.acknowledged.lock().map_err(|_| {
            FindingPoolLedgerError::Storage("test ack lock was poisoned".to_owned())
        })?;
        Ok(outbox
            .iter()
            .filter(|receipt| !acknowledged.contains(&receipt.id))
            .cloned()
            .collect())
    }

    fn store_attestation(
        &self,
        mutation: FindingPoolMutation,
        attestor: &FindingPoolMutationAttestor<'_>,
    ) -> Result<(), FindingPoolLedgerError> {
        let receipt = attestor(&mutation)?;
        let Ok(mut receipt_authority) = self.receipt_authority.lock() else {
            return Err(FindingPoolLedgerError::Storage(
                "test receipt authority lock was poisoned".to_owned(),
            ));
        };
        match receipt_authority.as_ref() {
            Some(authority) if authority != &receipt.kernel_key => {
                return Err(FindingPoolLedgerError::Receipt(
                    "finding pool mutation receipt authority changed".to_owned(),
                ));
            }
            Some(_) => {}
            None => *receipt_authority = Some(receipt.kernel_key.clone()),
        }
        drop(receipt_authority);
        let Ok(mut outbox) = self.outbox.lock() else {
            return Err(FindingPoolLedgerError::Storage(
                "test outbox lock was poisoned".to_owned(),
            ));
        };
        outbox.push(receipt);
        Ok(())
    }
}

impl FindingPoolLedger for RecordingLedger {
    fn contains_purchase(&self, _purchase_id: &str) -> Result<bool, FindingPoolLedgerError> {
        Ok(true)
    }

    fn replay_debit(
        &self,
        _replay: &AuthorizedFindingPoolDebitReplay,
    ) -> Result<FindingPoolDebitReceipt, FindingPoolLedgerError> {
        Err(FindingPoolLedgerError::ReplayConflict)
    }

    fn list_claimed_admission_operations(
        &self,
        after_operation_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<String>, FindingPoolLedgerError> {
        let mut operations = self
            .active_claim_operations
            .lock()
            .map_err(|_| {
                FindingPoolLedgerError::Storage("test active claim lock was poisoned".to_owned())
            })?
            .clone();
        operations.sort();
        operations.dedup();
        Ok(operations
            .into_iter()
            .filter(|operation_id| {
                after_operation_id.is_none_or(|after| operation_id.as_str() > after)
            })
            .take(limit)
            .collect())
    }

    fn debit(
        &self,
        _debit: &AuthorizedFindingPoolDebit,
        _attestor: &FindingPoolMutationAttestor<'_>,
    ) -> Result<FindingPoolDebitReceipt, FindingPoolLedgerError> {
        Err(FindingPoolLedgerError::Storage(
            "unexpected test debit".to_owned(),
        ))
    }

    fn claim(
        &self,
        claim: &AuthorizedFindingPoolClaim,
        attestor: &FindingPoolMutationAttestor<'_>,
    ) -> Result<(), FindingPoolLedgerError> {
        let Ok(mut claims) = self.claims.lock() else {
            return Err(FindingPoolLedgerError::Storage(
                "test claim lock was poisoned".to_owned(),
            ));
        };
        claims.push((claim.purchase_id().to_owned(), claim.claimed_at_unix_ms()));
        drop(claims);
        let mut active_claim_operations = self.active_claim_operations.lock().map_err(|_| {
            FindingPoolLedgerError::Storage("test active claim lock was poisoned".to_owned())
        })?;
        if !active_claim_operations
            .iter()
            .any(|operation_id| operation_id == claim.durable_admission_operation_id())
        {
            active_claim_operations.push(claim.durable_admission_operation_id().to_owned());
        }
        drop(active_claim_operations);
        self.store_attestation(
            FindingPoolMutation {
                schema: FINDING_POOL_MUTATION_SCHEMA_V1.to_owned(),
                kind: FindingPoolMutationKind::Claim,
                purchase_id: claim.purchase_id().to_owned(),
                allocation_id: "allocation:test".to_owned(),
                allocation_envelope_sha256: "a".repeat(64),
                amount_units: claim.amount_units().to_string(),
                currency: claim.currency().to_owned(),
                state: FindingPoolDebitState::Reserved,
                reserved_after_units: claim.amount_units().to_string(),
                spent_after_units: "0".to_owned(),
                remaining_after_units: "75".to_owned(),
                occurred_at_unix_ms: claim.claimed_at_unix_ms().to_string(),
                durable_admission_operation_id: Some(
                    claim.durable_admission_operation_id().to_owned(),
                ),
            },
            attestor,
        )?;
        Ok(())
    }

    fn release_claimed_before_dispatch(
        &self,
        release: &AuthorizedFindingPoolRecoveryRelease,
        attestor: &FindingPoolMutationAttestor<'_>,
    ) -> Result<(), FindingPoolLedgerError> {
        self.active_claim_operations
            .lock()
            .map_err(|_| {
                FindingPoolLedgerError::Storage("test active claim lock was poisoned".to_owned())
            })?
            .retain(|operation_id| operation_id != release.durable_admission_operation_id());
        self.recovery_releases
            .lock()
            .map_err(|_| {
                FindingPoolLedgerError::Storage(
                    "test recovery release lock was poisoned".to_owned(),
                )
            })?
            .push(release.durable_admission_operation_id().to_owned());
        self.store_attestation(
            FindingPoolMutation {
                schema: FINDING_POOL_MUTATION_SCHEMA_V1.to_owned(),
                kind: FindingPoolMutationKind::Release,
                purchase_id: "purchase:test".to_owned(),
                allocation_id: "allocation:test".to_owned(),
                allocation_envelope_sha256: "a".repeat(64),
                amount_units: "25".to_owned(),
                currency: "USD".to_owned(),
                state: FindingPoolDebitState::Released,
                reserved_after_units: "0".to_owned(),
                spent_after_units: "0".to_owned(),
                remaining_after_units: "100".to_owned(),
                occurred_at_unix_ms: release.released_at_unix_ms().to_string(),
                durable_admission_operation_id: Some(
                    release.durable_admission_operation_id().to_owned(),
                ),
            },
            attestor,
        )
    }

    fn release_claimed_after_verified_no_effect(
        &self,
        release: &AuthorizedFindingPoolRecoveryRelease,
        attestor: &FindingPoolMutationAttestor<'_>,
    ) -> Result<(), FindingPoolLedgerError> {
        self.release_claimed_before_dispatch(release, attestor)
    }

    fn finalize_claimed_after_unknown_dispatch(
        &self,
        terminal: &AuthorizedFindingPoolUnknownDispatchTerminal,
        attestor: &FindingPoolMutationAttestor<'_>,
    ) -> Result<(), FindingPoolLedgerError> {
        self.active_claim_operations
            .lock()
            .map_err(|_| {
                FindingPoolLedgerError::Storage("test active claim lock was poisoned".to_owned())
            })?
            .retain(|operation_id| operation_id != terminal.durable_admission_operation_id());
        self.unknown_dispatch_finalizations
            .lock()
            .map_err(|_| {
                FindingPoolLedgerError::Storage(
                    "test unknown-dispatch finalization lock was poisoned".to_owned(),
                )
            })?
            .push(terminal.durable_admission_operation_id().to_owned());
        self.store_attestation(
            FindingPoolMutation {
                schema: FINDING_POOL_MUTATION_SCHEMA_V1.to_owned(),
                kind: FindingPoolMutationKind::Finalize,
                purchase_id: "purchase:test".to_owned(),
                allocation_id: "allocation:test".to_owned(),
                allocation_envelope_sha256: "a".repeat(64),
                amount_units: "25".to_owned(),
                currency: "USD".to_owned(),
                state: FindingPoolDebitState::Finalized,
                reserved_after_units: "0".to_owned(),
                spent_after_units: "25".to_owned(),
                remaining_after_units: "75".to_owned(),
                occurred_at_unix_ms: terminal.finalized_at_unix_ms().to_string(),
                durable_admission_operation_id: Some(
                    terminal.durable_admission_operation_id().to_owned(),
                ),
            },
            attestor,
        )
    }

    fn settle(
        &self,
        terminal: &AuthorizedFindingPoolTerminal,
        attestor: &FindingPoolMutationAttestor<'_>,
    ) -> Result<FindingPoolDebitReceipt, FindingPoolLedgerError> {
        let Ok(mut decisions) = self.decisions.lock() else {
            return Err(FindingPoolLedgerError::Storage(
                "test decision lock was poisoned".to_owned(),
            ));
        };
        decisions.push(terminal.decision());
        drop(decisions);
        let (kind, state, spent_after, remaining_after) = match terminal.decision() {
            FindingPoolTerminalDecision::Finalize => (
                FindingPoolMutationKind::Finalize,
                FindingPoolDebitState::Finalized,
                terminal.amount_units(),
                75,
            ),
            FindingPoolTerminalDecision::Release => (
                FindingPoolMutationKind::Release,
                FindingPoolDebitState::Released,
                0,
                100,
            ),
        };
        self.store_attestation(
            FindingPoolMutation {
                schema: FINDING_POOL_MUTATION_SCHEMA_V1.to_owned(),
                kind,
                purchase_id: terminal.purchase_id().to_owned(),
                allocation_id: "allocation:test".to_owned(),
                allocation_envelope_sha256: "a".repeat(64),
                amount_units: terminal.amount_units().to_string(),
                currency: terminal.currency().to_owned(),
                state,
                reserved_after_units: "0".to_owned(),
                spent_after_units: spent_after.to_string(),
                remaining_after_units: remaining_after.to_string(),
                occurred_at_unix_ms: terminal.occurred_at_unix_ms().to_string(),
                durable_admission_operation_id: None,
            },
            attestor,
        )?;
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

    fn claim_pending_mutation_receipts(
        &self,
        claimant_id: &str,
        claimed_at_unix_ms: u64,
        lease_ms: u64,
        limit: usize,
    ) -> Result<Vec<ChioReceipt>, FindingPoolLedgerError> {
        let mut claims = self.delivery_claims.lock().map_err(|_| {
            FindingPoolLedgerError::Storage("test delivery claim lock was poisoned".to_owned())
        })?;
        let active = self.active_pending_reads.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_active_pending_reads
            .fetch_max(active, Ordering::SeqCst);
        if self.delay_pending_reads.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let outbox = self.outbox.lock().map_err(|_| {
            FindingPoolLedgerError::Storage("test outbox lock was poisoned".to_owned())
        })?;
        let acknowledged = self.acknowledged.lock().map_err(|_| {
            FindingPoolLedgerError::Storage("test ack lock was poisoned".to_owned())
        })?;
        let pending = outbox
            .iter()
            .filter(|receipt| {
                !acknowledged.contains(&receipt.id)
                    && !claims.iter().any(|(receipt_id, _, expires_at)| {
                        receipt_id == &receipt.id && *expires_at > claimed_at_unix_ms
                    })
            })
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        let claim_expires_at = claimed_at_unix_ms
            .checked_add(lease_ms)
            .ok_or_else(|| FindingPoolLedgerError::Receipt("test claim overflowed".to_owned()))?;
        for receipt in &pending {
            claims.retain(|(receipt_id, _, _)| receipt_id != &receipt.id);
            claims.push((receipt.id.clone(), claimant_id.to_owned(), claim_expires_at));
        }
        self.active_pending_reads.fetch_sub(1, Ordering::SeqCst);
        Ok(pending)
    }

    fn acknowledge_mutation_receipt(
        &self,
        receipt_id: &str,
        claimant_id: &str,
        _acknowledged_at_unix_ms: u64,
    ) -> Result<(), FindingPoolLedgerError> {
        let outbox = self.outbox.lock().map_err(|_| {
            FindingPoolLedgerError::Storage("test outbox lock was poisoned".to_owned())
        })?;
        if !outbox.iter().any(|receipt| receipt.id == receipt_id) {
            return Err(FindingPoolLedgerError::Receipt(
                "test tried to acknowledge an unknown receipt".to_owned(),
            ));
        }
        drop(outbox);
        let claims = self.delivery_claims.lock().map_err(|_| {
            FindingPoolLedgerError::Storage("test delivery claim lock was poisoned".to_owned())
        })?;
        if !claims.iter().any(|(claimed_receipt_id, owner, _)| {
            claimed_receipt_id == receipt_id && owner == claimant_id
        }) {
            return Err(FindingPoolLedgerError::Receipt(
                "test tried to acknowledge another worker's claim".to_owned(),
            ));
        }
        drop(claims);
        let mut acknowledged = self.acknowledged.lock().map_err(|_| {
            FindingPoolLedgerError::Storage("test ack lock was poisoned".to_owned())
        })?;
        if !acknowledged.iter().any(|existing| existing == receipt_id) {
            acknowledged.push(receipt_id.to_owned());
        }
        Ok(())
    }
}

impl QualifiedFindingPoolLedger for RecordingLedger {
    fn ledger_domain(&self) -> &str {
        "ledger:test-recording"
    }
}

#[derive(Default)]
struct RecordingReceiptStore {
    receipts: Mutex<Vec<ChioReceipt>>,
}

impl ReceiptStore for RecordingReceiptStore {
    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        self.receipts
            .lock()
            .map_err(|_| ReceiptStoreError::Conflict("test receipt lock was poisoned".to_owned()))?
            .push(receipt.clone());
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
}

fn kernel_with_ledger(ledger: Arc<RecordingLedger>) -> ChioKernel {
    kernel_with_keys(ledger, 91, 92)
}

fn kernel_with_keys(
    ledger: Arc<RecordingLedger>,
    kernel_key_seed: u8,
    pool_authority_seed: u8,
) -> ChioKernel {
    let mut kernel = kernel_without_receipt_store(kernel_key_seed, pool_authority_seed);
    assert!(kernel
        .set_receipt_store(Box::<RecordingReceiptStore>::default())
        .is_ok());
    assert!(kernel.set_finding_pool_ledger(ledger).is_ok());
    kernel
}

fn kernel_without_receipt_store(kernel_key_seed: u8, pool_authority_seed: u8) -> ChioKernel {
    let mut kernel = ChioKernel::new(KernelConfig {
        keypair: Keypair::from_seed(&[kernel_key_seed; 32]),
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
    assert!(kernel
        .set_finding_pool_receipt_authority(Keypair::from_seed(&[pool_authority_seed; 32]))
        .is_ok());
    kernel
}

fn purchase() -> crate::finding_purchase::VerifiedFindingPurchase {
    crate::finding_purchase::VerifiedFindingPurchase {
        finding_id: "b".repeat(64),
        listing_id: "listing:test".to_owned(),
        payload_sha256: "c".repeat(64),
        payload_media_type: "application/json".to_owned(),
        expected_status_feed_id: "status-feed/test".to_owned(),
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

fn pool_mutation_from_receipt(receipt: &ChioReceipt) -> FindingPoolMutation {
    assert!(matches!(receipt.verify_signature(), Ok(true)));
    serde_json::from_value(
        receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("finding_pool_mutation"))
            .cloned()
            .unwrap_or(serde_json::Value::Null),
    )
    .unwrap_or_else(|error| panic!("signed pool mutation metadata must decode: {error}"))
}

fn recorded_pool_mutation(kernel: &ChioKernel) -> FindingPoolMutation {
    let receipts = kernel.receipt_log().receipts();
    assert_eq!(receipts.len(), 1);
    pool_mutation_from_receipt(&receipts[0])
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
    assert_eq!(
        recorded_pool_mutation(&kernel).kind,
        FindingPoolMutationKind::Finalize
    );
}

#[test]
fn dispatch_claims_the_configured_pool_reservation() {
    let ledger = Arc::new(RecordingLedger::default());
    let kernel = kernel_with_ledger(Arc::clone(&ledger));
    assert!(kernel
        .claim_finding_pool_delivery(&purchase(), 12_345, Some("operation:test"))
        .is_ok());
    let Ok(claims) = ledger.claims.lock() else {
        panic!("test claim lock was poisoned");
    };
    assert_eq!(claims.as_slice(), &[("purchase:test".to_owned(), 12_345)]);
    drop(claims);
    let pending = ledger
        .pending_mutation_receipts()
        .unwrap_or_else(|error| panic!("signed claim outbox must be readable: {error}"));
    assert_eq!(pending.len(), 1);
    assert_eq!(
        pool_mutation_from_receipt(&pending[0]).kind,
        FindingPoolMutationKind::Claim
    );
    assert!(kernel.receipt_log().is_empty());
}

#[test]
fn pre_dispatch_recovery_releases_the_bound_pool_claim() {
    let ledger = Arc::new(RecordingLedger::default());
    let kernel = kernel_with_ledger(Arc::clone(&ledger));
    assert!(kernel
        .claim_finding_pool_delivery(&purchase(), 12_345, Some("operation:test"))
        .is_ok());
    assert!(kernel
        .release_finding_pool_claim_before_dispatch("operation:test", 12_346)
        .is_ok());
    let Ok(releases) = ledger.recovery_releases.lock() else {
        panic!("test recovery release lock was poisoned");
    };
    assert_eq!(releases.as_slice(), &["operation:test".to_owned()]);
    drop(releases);
    assert_eq!(kernel.receipt_log().receipts().len(), 2);
    assert!(ledger
        .pending_mutation_receipts()
        .is_ok_and(|receipts| receipts.is_empty()));
}

#[test]
fn verified_post_commit_no_effect_releases_the_bound_pool_claim() {
    let ledger = Arc::new(RecordingLedger::default());
    let kernel = kernel_with_ledger(Arc::clone(&ledger));
    assert!(kernel
        .claim_finding_pool_delivery(&purchase(), 12_345, Some("operation:test"))
        .is_ok());
    assert!(kernel
        .release_finding_pool_claim_after_verified_no_effect("operation:test", 12_346)
        .is_ok());
    let Ok(releases) = ledger.recovery_releases.lock() else {
        panic!("test recovery release lock was poisoned");
    };
    assert_eq!(releases.as_slice(), &["operation:test".to_owned()]);
    drop(releases);
    assert_eq!(kernel.receipt_log().receipts().len(), 2);
    assert!(ledger
        .pending_mutation_receipts()
        .is_ok_and(|receipts| receipts.is_empty()));
}

#[test]
fn unknown_dispatch_recovery_finalizes_the_bound_pool_claim() {
    let ledger = Arc::new(RecordingLedger::default());
    let kernel = kernel_with_ledger(Arc::clone(&ledger));
    assert!(kernel
        .claim_finding_pool_delivery(&purchase(), 12_345, Some("operation:test"))
        .is_ok());
    assert!(kernel
        .finalize_finding_pool_claim_after_unknown_dispatch("operation:test", 12_346)
        .is_ok());
    let Ok(finalizations) = ledger.unknown_dispatch_finalizations.lock() else {
        panic!("test unknown-dispatch finalization lock was poisoned");
    };
    assert_eq!(finalizations.as_slice(), &["operation:test".to_owned()]);
    drop(finalizations);
    assert_eq!(kernel.receipt_log().receipts().len(), 2);
    assert!(ledger
        .pending_mutation_receipts()
        .is_ok_and(|receipts| receipts.is_empty()));
}

#[test]
fn dispatch_rejects_a_pool_reservation_without_durable_admission() {
    let ledger = Arc::new(RecordingLedger::default());
    let kernel = kernel_with_ledger(Arc::clone(&ledger));

    assert_eq!(
        kernel.claim_finding_pool_delivery(&purchase(), 12_345, None),
        Err(FindingPoolLedgerError::DurableAdmissionRequired)
    );
    assert!(ledger
        .claims
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .is_empty());
    assert!(ledger
        .outbox
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .is_empty());
}

#[test]
fn pool_ledger_requires_a_durable_ordinary_receipt_store_at_configuration() {
    let ledger = Arc::new(RecordingLedger::default());
    let mut kernel = kernel_without_receipt_store(91, 92);

    assert_eq!(
        kernel.set_finding_pool_ledger(ledger.clone()),
        Err(FindingPoolLedgerError::DurableReceiptStoreMissing)
    );
    assert!(ledger
        .claims
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .is_empty());
    assert!(ledger
        .acknowledged
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .is_empty());
}

#[test]
fn configured_pool_ledger_freezes_the_ordinary_receipt_store() {
    let ledger = Arc::new(RecordingLedger::default());
    let mut kernel = kernel_with_ledger(ledger);

    let error = kernel
        .set_receipt_store(Box::<RecordingReceiptStore>::default())
        .expect_err("pool receipt history must remain on one durable store");
    assert!(error
        .to_string()
        .contains("cannot be replaced after the finding pool ledger"));
}

#[test]
fn emergency_stop_blocks_the_public_pool_debit_gate() {
    let ledger = Arc::new(RecordingLedger::default());
    let kernel = kernel_with_ledger(ledger);
    kernel
        .emergency_stop("finding pool containment")
        .expect("engage emergency stop");

    assert_eq!(
        kernel.require_finding_pool_debit_active(),
        Err(FindingPoolDebitError::EmergencyStopped)
    );
}

#[test]
fn pending_pool_receipt_is_not_acknowledged_without_a_durable_store() {
    let ledger = Arc::new(RecordingLedger::default());
    let first_kernel = kernel_with_ledger(Arc::clone(&ledger));
    assert!(first_kernel
        .claim_finding_pool_delivery(&purchase(), 12_345, Some("operation:test"))
        .is_ok());
    assert_eq!(
        ledger
            .pending_mutation_receipts()
            .unwrap_or_else(|error| panic!("test outbox must be readable: {error}"))
            .len(),
        1
    );

    let mut restarted = kernel_without_receipt_store(93, 92);
    assert_eq!(
        restarted.set_finding_pool_ledger(ledger.clone()),
        Err(FindingPoolLedgerError::DurableReceiptStoreMissing)
    );
    assert!(ledger
        .acknowledged
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .is_empty());
    assert!(ledger
        .decisions
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .is_empty());
}

#[test]
fn concurrent_pool_outbox_flushers_project_each_receipt_once() {
    let ledger = Arc::new(RecordingLedger::default());
    let producer = kernel_with_ledger(Arc::clone(&ledger));
    assert!(producer
        .claim_finding_pool_delivery(&purchase(), 12_345, Some("operation:test"))
        .is_ok());
    ledger.delay_pending_reads.store(true, Ordering::SeqCst);
    let barrier = Arc::new(Barrier::new(5));
    let mut handles = Vec::new();
    let mut kernels = Vec::new();
    for seed in 93..97 {
        let kernel = Arc::new(kernel_with_keys(Arc::clone(&ledger), seed, 92));
        kernels.push(Arc::clone(&kernel));
        let ledger = Arc::clone(&ledger);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            kernel.flush_finding_pool_mutation_receipts(ledger.as_ref())
        }));
    }
    barrier.wait();
    for handle in handles {
        assert!(handle.join().is_ok_and(|result| result.is_ok()));
    }
    assert_eq!(ledger.max_active_pending_reads.load(Ordering::SeqCst), 1);
    assert_eq!(
        kernels
            .iter()
            .map(|kernel| kernel.receipt_log().receipts().len())
            .sum::<usize>(),
        1
    );
    assert!(ledger
        .pending_mutation_receipts()
        .is_ok_and(|receipts| receipts.is_empty()));
}

#[test]
fn stable_pool_receipt_authority_survives_ordinary_kernel_key_rotation() {
    let ledger = Arc::new(RecordingLedger::default());
    let first_kernel = kernel_with_keys(Arc::clone(&ledger), 91, 92);
    assert!(first_kernel
        .claim_finding_pool_delivery(&purchase(), 12_345, Some("operation:test"))
        .is_ok());

    let rotated_kernel = kernel_with_keys(Arc::clone(&ledger), 93, 92);
    assert!(rotated_kernel
        .settle_finding_pool_delivery(
            &purchase(),
            &crate::tool_outcome::SettlementDispositionV1::Capture {
                amount: MonetaryAmount {
                    units: 25,
                    currency: "USD".to_owned(),
                },
            },
        )
        .is_ok());

    let stable_key = Keypair::from_seed(&[92_u8; 32]).public_key();
    let ordinary_rotated_key = Keypair::from_seed(&[93_u8; 32]).public_key();
    let outbox = ledger
        .outbox
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert_eq!(outbox.len(), 2);
    assert!(outbox
        .iter()
        .all(|receipt| receipt.kernel_key == stable_key));
    assert!(outbox
        .iter()
        .all(|receipt| receipt.kernel_key != ordinary_rotated_key));
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
    assert_eq!(
        recorded_pool_mutation(&kernel).kind,
        FindingPoolMutationKind::Release
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

#[test]
fn pool_terminal_preflight_rejects_partial_capture_without_mutation() {
    let ledger = Arc::new(RecordingLedger::default());
    let kernel = kernel_with_ledger(Arc::clone(&ledger));
    let result = kernel.require_finding_pool_delivery_disposition(
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
    assert!(kernel.receipt_log().receipts().is_empty());
}
