#![cfg(feature = "cognition-market-experimental")]

use std::sync::Arc;
use std::thread;

use chio_core::capability::scope::{
    ChioScope, FindingPurchaseMarkerV1, FindingSettlementSelector, MonetaryAmount,
};
use chio_core::capability::token::{CapabilityToken, CHIO_CAPABILITY_SCHEMA};
use chio_core::crypto::{sha256_hex, Keypair};
use chio_kernel::finding_pool::{
    debit_finding_pool_purchase, FindingPoolDebitError, FindingPoolDebitRequest,
    FindingPoolLedgerError,
};
use chio_kernel::finding_purchase::{
    FindingPurchaseContextView, FindingPurchaseVerifier, VerifiedFindingPurchase,
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
    debit_finding_pool_purchase(
        ledger,
        FindingPoolDebitRequest {
            allocation: &fixture.allocation,
            pool: &fixture.pool,
            pinned_authority: &fixture.authority.public_key(),
            expected_allocation_envelope_sha256: &fixture.envelope_sha256,
            purchaser_id: &fixture.allocation.body.purchaser_id,
            kernel: &kernel,
            purchase_context: FindingPurchaseContextView {
                marker: &marker,
                context_b64: "test-purchase-context",
                capability: &capability,
                server_id: "finding-server",
                tool_name: "read_finding",
                arguments: &arguments,
                expected_output_digest: &"c".repeat(64),
            },
            now_unix_ms,
        },
    )
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
                assert!(receipt.spent_after_units <= 100);
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
            .spent_units(&fixture.envelope_sha256)
            .test_expect("read spent units"),
        Some(100)
    );

    drop(ledger);
    let restarted =
        SqliteFindingPoolLedger::open_qualified(&database).test_expect("restart ledger");
    assert_eq!(
        restarted
            .spent_units(&fixture.envelope_sha256)
            .test_expect("read restarted spend"),
        Some(100)
    );
    let replay_purchase_id = successful_purchase_id
        .as_deref()
        .test_expect("at least one successful purchase id");
    let replay = debit(&restarted, &fixture, replay_purchase_id, 10)
        .test_expect("exact replay after restart");
    assert!(replay.replayed);
    assert!(replay.spent_after_units <= 100);
    assert_eq!(
        restarted
            .spent_units(&fixture.envelope_sha256)
            .test_expect("read spend after replay"),
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
fn cognition_market_qualified_pool_refuses_in_memory_storage() {
    for path in [":memory:", "", "file:", "file:?mode=rwc"] {
        assert!(
            matches!(
                SqliteFindingPoolLedger::open_qualified(path),
                Err(FindingPoolLedgerError::Storage(_))
            ),
            "temporary SQLite path {path:?} must not qualify"
        );
    }
}
