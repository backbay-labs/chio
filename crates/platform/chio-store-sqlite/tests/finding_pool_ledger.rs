#![cfg(feature = "cognition-market-experimental")]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;

use chio_core::capability::scope::{
    ChioScope, FindingPurchaseMarkerV1, FindingSettlementSelector, MonetaryAmount,
};
use chio_core::capability::token::{CapabilityToken, CHIO_CAPABILITY_SCHEMA};
use chio_core::crypto::{sha256_hex, Keypair};
use chio_kernel::finding_pool::{
    FindingPoolDebitError, FindingPoolDebitRequest, FindingPoolDebitState, FindingPoolLedgerError,
};
use chio_kernel::finding_purchase::{
    FindingPurchaseContextView, FindingPurchaseVerifier, FindingStatusProofContextView,
    FindingStatusProofVerifier, VerifiedFindingPurchase, VerifiedFindingStatusProof,
};
use chio_kernel::{
    ChioKernel, HotPathDeadlineConfig, KernelConfig, MemoryBudgetConfig,
    DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_store_sqlite::finding_pool_ledger::SqliteFindingPoolLedger;
use chio_swarm_authority::finding_pool::{
    finding_pool_allocation_envelope_sha256, sign_finding_pool_allocation,
    swarm_budget_pool_sha256, FindingPoolAllocation, SignedFindingPoolAllocation,
    FINDING_POOL_ALLOCATION_SCHEMA_V1, FINDING_POOL_PURPOSE_V1,
};
use chio_swarm_authority::{SwarmBudgetPool, CHIO_SWARM_BUDGET_POOL_SCHEMA};
use chio_test_support::prelude::*;

#[derive(Clone)]
struct PoolFixture {
    pool: SwarmBudgetPool,
    allocation: SignedFindingPoolAllocation,
    envelope_sha256: String,
    authority: Keypair,
    purchaser: Keypair,
}

fn fixture(amount_units: u64) -> PoolFixture {
    let authority = Keypair::from_seed(&[71_u8; 32]);
    let purchaser = Keypair::from_seed(&[72_u8; 32]);
    let pool = SwarmBudgetPool {
        schema: CHIO_SWARM_BUDGET_POOL_SCHEMA.to_string(),
        pool_id: "pool:cognition-market:buyer-1".to_string(),
        graph_id: "graph:cognition-market:buyer-1".to_string(),
        currency: "USD".to_string(),
        total_units: amount_units,
        allocations: Vec::new(),
    };
    let allocation = sign_finding_pool_allocation(
        FindingPoolAllocation {
            schema: FINDING_POOL_ALLOCATION_SCHEMA_V1.to_string(),
            allocation_id: String::new(),
            pool_id: pool.pool_id.clone(),
            pool_sha256: swarm_budget_pool_sha256(&pool).test_expect("hash pool"),
            graph_id: pool.graph_id.clone(),
            purpose: FINDING_POOL_PURPOSE_V1.to_string(),
            purchaser_id: "buyer-agent-1".to_string(),
            purchaser_key: purchaser.public_key(),
            currency: "USD".to_string(),
            amount_units,
            nonce: "pool-allocation-nonce-1".to_string(),
            authority: authority.public_key(),
            issued_at_unix_ms: 1_000,
            expires_at_unix_ms: 10_000,
        },
        &authority,
    )
    .test_expect("sign pool allocation");
    let envelope_sha256 = finding_pool_allocation_envelope_sha256(&allocation)
        .test_expect("hash pool allocation envelope");
    PoolFixture {
        pool,
        allocation,
        envelope_sha256,
        authority,
        purchaser,
    }
}

fn debit(
    ledger: &SqliteFindingPoolLedger,
    fixture: &PoolFixture,
    purchase_id: &str,
    amount_units: u64,
) -> Result<chio_kernel::finding_pool::FindingPoolDebitReceipt, FindingPoolDebitError> {
    debit_at(ledger, fixture, purchase_id, amount_units, 2_000)
}

#[derive(Clone)]
struct StaticPurchaseVerifier {
    purchase: VerifiedFindingPurchase,
}

impl FindingPurchaseVerifier for StaticPurchaseVerifier {
    fn verify_purchase(
        &self,
        _view: &FindingPurchaseContextView<'_>,
    ) -> Result<VerifiedFindingPurchase, String> {
        Ok(self.purchase.clone())
    }

    fn verify_purchase_admission(
        &self,
        _view: &FindingPurchaseContextView<'_>,
        _verified: &VerifiedFindingPurchase,
        _now_unix_secs: u64,
    ) -> Result<(), String> {
        Ok(())
    }
}

fn debit_at(
    ledger: &SqliteFindingPoolLedger,
    fixture: &PoolFixture,
    purchase_id: &str,
    amount_units: u64,
    now_unix_ms: u64,
) -> Result<chio_kernel::finding_pool::FindingPoolDebitReceipt, FindingPoolDebitError> {
    debit_at_with_status(
        ledger,
        fixture,
        purchase_id,
        amount_units,
        now_unix_ms,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn debit_at_with_status(
    ledger: &SqliteFindingPoolLedger,
    fixture: &PoolFixture,
    purchase_id: &str,
    amount_units: u64,
    now_unix_ms: u64,
    status_verifier: Option<Arc<dyn FindingStatusProofVerifier>>,
    status_proof_b64: Option<&str>,
) -> Result<chio_kernel::finding_pool::FindingPoolDebitReceipt, FindingPoolDebitError> {
    let verified_purchase = VerifiedFindingPurchase {
        finding_id: "a".repeat(64),
        listing_id: "listing:cognition-market:1".to_string(),
        payload_sha256: "c".repeat(64),
        payload_media_type: "application/json".to_string(),
        accepted_price: MonetaryAmount {
            units: amount_units,
            currency: "USD".to_string(),
        },
        payer_key_hex: fixture.purchaser.public_key().to_hex(),
        reservation_id: format!("reservation:{purchase_id}"),
        purchase_intent_id: purchase_id.to_string(),
        authoritative_payment_operation_id: format!("payment:{purchase_id}"),
        accepted_bid_envelope_sha256: sha256_hex(purchase_id.as_bytes()),
        venue_admission_envelope_sha256: "d".repeat(64),
        status_proof: None,
    };
    let verifier = StaticPurchaseVerifier {
        purchase: verified_purchase,
    };
    let mut kernel = ChioKernel::new(KernelConfig {
        keypair: fixture.authority.clone(),
        ca_public_keys: Vec::new(),
        max_delegation_depth: 1,
        policy_hash: "finding-pool-ledger-test".to_string(),
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
    kernel.set_finding_purchase_verifier(Arc::new(verifier));
    kernel.set_finding_pool_allocation_authority(fixture.authority.public_key());
    kernel
        .set_finding_pool_ledger(Arc::new(ledger.clone()))
        .test_expect("configure qualified pool ledger");
    if let Some(status_verifier) = status_verifier {
        kernel.set_finding_status_proof_verifier(status_verifier);
    }
    let marker = FindingPurchaseMarkerV1 {
        finding_id: "a".repeat(64),
        listing_id: "listing:cognition-market:1".to_string(),
        settlement: FindingSettlementSelector::LocalReversibleHold,
    };
    let capability = CapabilityToken {
        schema: CHIO_CAPABILITY_SCHEMA.to_string(),
        id: format!("capability:{purchase_id}"),
        issuer: fixture.authority.public_key(),
        subject: fixture.purchaser.public_key(),
        scope: ChioScope::default(),
        issued_at: 1,
        expires_at: u64::MAX,
        delegation_chain: Vec::new(),
        aggregate_invocation_budget: None,
        algorithm: None,
        caveats: Vec::new(),
        scope_attenuations: None,
        attenuation_proof: None,
        budget_share_bps: None,
        signature: fixture.authority.sign(purchase_id.as_bytes()),
    };
    let arguments = serde_json::Value::Null;
    let _runtime = chio_kernel::scope_fixed_runtime_for_current_thread(
        now_unix_ms / 1_000,
        std::iter::empty::<String>(),
    );
    kernel.debit_finding_pool_purchase(FindingPoolDebitRequest {
        allocation: &fixture.allocation,
        pool: &fixture.pool,
        expected_allocation_envelope_sha256: &fixture.envelope_sha256,
        purchaser_id: &fixture.allocation.body.purchaser_id,
        purchase_context: FindingPurchaseContextView {
            marker: &marker,
            context_b64: "test-purchase-context",
            capability: &capability,
            server_id: "finding-server",
            tool_name: "read_finding",
            arguments: &arguments,
            expected_output_digest: &"c".repeat(64),
        },
        status_proof_b64,
    })
}

#[derive(Clone)]
struct StaticStatusVerifier {
    admissions: Arc<AtomicU64>,
}

impl FindingStatusProofVerifier for StaticStatusVerifier {
    fn verify_status_proof(
        &self,
        view: &FindingStatusProofContextView<'_>,
    ) -> Result<VerifiedFindingStatusProof, String> {
        if view.proof_b64 != "live-status-proof" || view.expected_finding_id != "a".repeat(64) {
            return Err("status proof mismatch".to_owned());
        }
        Ok(VerifiedFindingStatusProof {
            feed_id: "status-feed/test".to_owned(),
            key_domain_nonce: 1,
            map_epoch: 1,
            status_epoch_id: "b".repeat(64),
            status_epoch_artifact_sha256: "c".repeat(64),
            proof_sha256: "d".repeat(64),
            root_hash: "e".repeat(64),
            non_inclusion_checked_at: 2,
        })
    }

    fn verify_status_admission(
        &self,
        _view: &FindingStatusProofContextView<'_>,
        _verified: &VerifiedFindingStatusProof,
        _now_unix_secs: u64,
    ) -> Result<(), String> {
        self.admissions.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[test]
fn cognition_market_authenticated_pool_restart_never_exceeds_signed_amount() {
    let directory = tempfile::tempdir().test_expect("create ledger directory");
    let database = directory.path().join("finding-pool.sqlite3");
    let ledger = Arc::new(
        SqliteFindingPoolLedger::open_qualified(&database).test_expect("open qualified ledger"),
    );
    let fixture = Arc::new(fixture(100));

    let mut handles = Vec::new();
    for index in 0..20_u64 {
        let ledger = Arc::clone(&ledger);
        let fixture = Arc::clone(&fixture);
        handles.push(thread::spawn(move || {
            debit(
                &ledger,
                &fixture,
                &format!("purchase:concurrent:{index}"),
                10,
            )
        }));
    }

    let mut successful = 0_u64;
    let mut exhausted = 0_u64;
    let mut successful_purchase_id = None;
    for handle in handles {
        match handle.join().test_expect("join debit thread") {
            Ok(receipt) => {
                successful += 1;
                successful_purchase_id.get_or_insert(receipt.purchase_id.clone());
                assert_eq!(receipt.state, FindingPoolDebitState::Reserved);
                assert!(receipt.reserved_after_units <= 100);
            }
            Err(FindingPoolDebitError::Ledger(FindingPoolLedgerError::AmountExceeded)) => {
                exhausted += 1;
            }
            Err(error) => panic!("unexpected pool debit result: {error}"),
        }
    }
    assert_eq!(successful, 10);
    assert_eq!(exhausted, 10);
    assert_eq!(
        ledger
            .reserved_units(&fixture.envelope_sha256)
            .test_expect("read reserved units"),
        Some(100)
    );
    assert_eq!(
        ledger
            .spent_units(&fixture.envelope_sha256)
            .test_expect("read spent units"),
        Some(0)
    );

    drop(ledger);
    let restarted =
        SqliteFindingPoolLedger::open_qualified(&database).test_expect("restart ledger");
    assert_eq!(
        restarted
            .reserved_units(&fixture.envelope_sha256)
            .test_expect("read restarted reservations"),
        Some(100)
    );
    let replay_purchase_id = successful_purchase_id
        .as_deref()
        .test_expect("at least one successful purchase id");
    let replay = debit(&restarted, &fixture, replay_purchase_id, 10)
        .test_expect("exact replay after restart");
    assert!(replay.replayed);
    assert_eq!(replay.state, FindingPoolDebitState::Reserved);
    assert!(replay.reserved_after_units <= 100);
    assert_eq!(
        restarted
            .reserved_units(&fixture.envelope_sha256)
            .test_expect("read reservations after replay"),
        Some(100)
    );

    assert!(matches!(
        debit(&restarted, &fixture, replay_purchase_id, 11),
        Err(FindingPoolDebitError::Ledger(
            FindingPoolLedgerError::ReplayConflict
        ))
    ));
}

#[test]
fn qualified_pool_rejects_percent_decoded_nul_uris() {
    for path in ["file:%00", "file::memory:%00", "file:pool?mode=memory%00"] {
        assert!(
            matches!(
                SqliteFindingPoolLedger::open_qualified(path),
                Err(FindingPoolLedgerError::Storage(_))
            ),
            "{path} must be rejected before SQLite opens it"
        );
    }
}

#[test]
fn cognition_market_pool_rejects_authority_purchaser_digest_and_pool_substitution() {
    let directory = tempfile::tempdir().test_expect("create ledger directory");
    let ledger = SqliteFindingPoolLedger::open_qualified(directory.path().join("pool.sqlite3"))
        .test_expect("open qualified ledger");
    let fixture = fixture(100);

    let mut wrong_digest = fixture.clone();
    wrong_digest.envelope_sha256 = "0".repeat(64);
    assert_eq!(
        debit(&ledger, &wrong_digest, "purchase:wrong-digest", 10),
        Err(FindingPoolDebitError::EnvelopeDigestMismatch)
    );

    let mut wrong_authority = fixture.clone();
    wrong_authority.authority = Keypair::from_seed(&[73_u8; 32]);
    assert!(matches!(
        debit(&ledger, &wrong_authority, "purchase:wrong-authority", 10),
        Err(FindingPoolDebitError::Allocation(_))
    ));

    let mut wrong_purchaser = fixture.clone();
    wrong_purchaser.purchaser = Keypair::from_seed(&[74_u8; 32]);
    assert_eq!(
        debit(&ledger, &wrong_purchaser, "purchase:wrong-purchaser", 10),
        Err(FindingPoolDebitError::PurchaserMismatch)
    );

    let mut wrong_pool = fixture.clone();
    wrong_pool.pool.total_units = 101;
    assert!(matches!(
        debit(&ledger, &wrong_pool, "purchase:wrong-pool", 10),
        Err(FindingPoolDebitError::Allocation(_))
    ));
}

#[test]
fn cognition_market_pool_binds_one_purchaser_allocation_per_pool() {
    let directory = tempfile::tempdir().test_expect("create ledger directory");
    let ledger = SqliteFindingPoolLedger::open_qualified(directory.path().join("pool.sqlite3"))
        .test_expect("open qualified ledger");
    let first = fixture(100);
    debit(&ledger, &first, "purchase:first", 10).test_expect("first pool debit");

    let mut second = fixture(100);
    second.purchaser = Keypair::from_seed(&[75_u8; 32]);
    let mut body = second.allocation.body.clone();
    body.purchaser_id = "buyer-agent-2".to_string();
    body.purchaser_key = second.purchaser.public_key();
    body.nonce = "pool-allocation-nonce-2".to_string();
    second.allocation = sign_finding_pool_allocation(body, &second.authority)
        .test_expect("sign second pool allocation");
    second.envelope_sha256 = finding_pool_allocation_envelope_sha256(&second.allocation)
        .test_expect("hash second allocation");

    let error = debit(&ledger, &second, "purchase:second", 10);
    assert!(matches!(
        error,
        Err(FindingPoolDebitError::Ledger(
            FindingPoolLedgerError::PoolBindingConflict
        ))
    ));
}

#[test]
fn cognition_market_pool_replays_after_expiry_but_rejects_new_spend() {
    let directory = tempfile::tempdir().test_expect("create ledger directory");
    let ledger = SqliteFindingPoolLedger::open_qualified(directory.path().join("pool.sqlite3"))
        .test_expect("open qualified ledger");
    let fixture = fixture(100);
    debit_at(&ledger, &fixture, "purchase:committed", 10, 9_999)
        .test_expect("commit before allocation expiry");

    let replay = debit_at(&ledger, &fixture, "purchase:committed", 10, 10_000)
        .test_expect("replay committed debit after expiry");
    assert!(replay.replayed);
    assert!(matches!(
        debit_at(&ledger, &fixture, "purchase:new", 10, 10_000),
        Err(FindingPoolDebitError::Ledger(
            FindingPoolLedgerError::AllocationNotLive
        ))
    ));
}

#[test]
fn cognition_market_pool_requires_live_status_before_new_debit_but_replays() {
    let directory = tempfile::tempdir().test_expect("create ledger directory");
    let ledger = SqliteFindingPoolLedger::open_qualified(directory.path().join("pool.sqlite3"))
        .test_expect("open qualified ledger");
    let fixture = fixture(100);
    let admissions = Arc::new(AtomicU64::new(0));
    let verifier = Arc::new(StaticStatusVerifier {
        admissions: Arc::clone(&admissions),
    });

    assert!(matches!(
        debit_at_with_status(
            &ledger,
            &fixture,
            "purchase:status",
            10,
            2_000,
            Some(verifier.clone()),
            None,
        ),
        Err(FindingPoolDebitError::Allocation(_))
    ));
    assert_eq!(admissions.load(Ordering::SeqCst), 0);
    let committed = debit_at_with_status(
        &ledger,
        &fixture,
        "purchase:status",
        10,
        2_000,
        Some(verifier.clone()),
        Some("live-status-proof"),
    )
    .test_expect("live status admits new pool debit");
    assert!(!committed.replayed);
    assert_eq!(admissions.load(Ordering::SeqCst), 1);

    let replay = debit_at_with_status(
        &ledger,
        &fixture,
        "purchase:status",
        10,
        2_000,
        Some(verifier.clone()),
        None,
    )
    .test_expect("committed pool debit replays without a fresh status proof");
    assert!(replay.replayed);
    assert_eq!(admissions.load(Ordering::SeqCst), 1);
    assert!(matches!(
        debit_at_with_status(
            &ledger,
            &fixture,
            "purchase:new-without-status",
            10,
            2_000,
            Some(verifier),
            None,
        ),
        Err(FindingPoolDebitError::Allocation(_))
    ));
    assert_eq!(
        ledger
            .reserved_units(&fixture.envelope_sha256)
            .test_expect("read status-qualified reservation"),
        Some(10)
    );
}

#[test]
fn cognition_market_kernel_refuses_pool_ledger_replacement() {
    let first_directory = tempfile::tempdir().test_expect("create first ledger directory");
    let second_directory = tempfile::tempdir().test_expect("create second ledger directory");
    let first =
        SqliteFindingPoolLedger::open_qualified(first_directory.path().join("pool.sqlite3"))
            .test_expect("open first qualified ledger");
    let second =
        SqliteFindingPoolLedger::open_qualified(second_directory.path().join("pool.sqlite3"))
            .test_expect("open second qualified ledger");
    let fixture = fixture(100);
    let mut kernel = ChioKernel::new(KernelConfig {
        keypair: fixture.authority,
        ca_public_keys: Vec::new(),
        max_delegation_depth: 1,
        policy_hash: "finding-pool-ledger-pinning-test".to_string(),
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
    kernel
        .set_finding_pool_ledger(Arc::new(first))
        .test_expect("pin first ledger");
    assert_eq!(
        kernel.set_finding_pool_ledger(Arc::new(second)),
        Err(FindingPoolLedgerError::AlreadyConfigured)
    );
}

#[test]
fn cognition_market_qualified_pool_refuses_in_memory_storage() {
    for path in [
        ":memory:",
        "",
        "file:",
        "file:?mode=rwc",
        "file:pool?vfs=memdb",
        "file:pool?mode%3Dmemory",
        "file:pool?mode=%6demory",
        "file:%3Amemory%3A",
        "file::memory:#fragment",
        "file:pool?mode=memory#fragment",
        "file:pool?vfs=memdb#fragment",
    ] {
        assert!(
            matches!(
                SqliteFindingPoolLedger::open_qualified(path),
                Err(FindingPoolLedgerError::Storage(_))
            ),
            "temporary SQLite path {path:?} must not qualify"
        );
    }
}
